"""Completeness-review PR 2: authority is re-checked during a run (PM-003), and every refused
decision reaches a durable CLOSED checkpoint (PM-004).

PM-003: permit expiry was read once, at admission. A slow provider, a long step, or an approval wait
could carry an admitted run past the end of its authority and still launch a tool, redeem an approval,
or emit a migration. Every boundary that ACTS now re-reads the trusted clock.

PM-004: `_apply_decision` ran outside every failure boundary, so a decision that failed host
authorization raised out of `run()` and left the admitted checkpoint open at `running` -- resumable,
and claiming the agent was still working.
"""

import contextlib
import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from portmark import _clock
from portmark.factory import make_demo_envelope, make_host
from dataclasses import asdict

from portmark.models import ProviderDecision, ResourceBudget, ToolGrant
from portmark.providers import ModelProvider
from portmark.security import ApprovalAuthority, HostPolicy, PermitExpiredError, SecurityError
from portmark.storage import SQLiteRuntimeStore
from test_section12_capacity_clock import FakeTime


class ScriptedProvider(ModelProvider):
    """Returns the given decisions in order, and may move the fake clock before answering."""

    def __init__(self, *decisions, fake=None, jump=0.0):
        self.decisions = list(decisions)
        self.fake = fake
        self.jump = jump
        self.calls = 0

    def decide(self, state, available_tools, grants=()):
        self.calls += 1
        if self.fake is not None and self.jump:
            self.fake.advance(self.jump)  # real time passing, not a clock jump
        return self.decisions[min(self.calls - 1, len(self.decisions) - 1)]


class PayingProvider(ModelProvider):
    """Proposes the approval-gated tool until it has its result, then completes (like a real one)."""

    def __init__(self, tool="payments.reserve"):
        self.tool = tool

    def decide(self, state, available_tools, grants=()):
        if self.tool not in state.tool_results:
            return ProviderDecision("tool", self.tool, {"amount": 50, "currency": "USD"})
        return ProviderDecision("complete", content={"done": True})


class ReviewLifecycleTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)

    def _store(self) -> SQLiteRuntimeStore:
        return SQLiteRuntimeStore(self.root / "runtime.sqlite")

    def _host(self, provider, store=None):
        return make_host(
            store=store, allow_ephemeral_signing_key=True, providers={"scripted": provider}
        )

    def _envelope(self, host, goal):
        envelope = make_demo_envelope(host, goal, "scripted")
        host.signer.seal(envelope)
        # A pristine copy of the SAME sealed envelope: run() mutates the state it is given, so a
        # replay must use the admitted copy, not the mutated one (its signature would not verify).
        return envelope, copy.deepcopy(envelope)

    def _events(self, task_id):
        with contextlib.closing(sqlite3.connect(str(self.root / "runtime.sqlite"))) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT event, details_json FROM audit_events WHERE task_id = ? ORDER BY sequence", (str(task_id),)
            ).fetchall()
        return [{"event": row["event"], "details": json.loads(row["details_json"])} for row in rows]

    def _closed_failed(self, store, host, probe, event):
        task_id = probe.state.task_id
        checkpoint = store.load_checkpoint(task_id)
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["status"], "failed")  # durable terminal, never left `running`
        self.assertTrue(store.verify_audit_chain(task_id))
        self.assertIn(event, [entry["event"] for entry in self._events(task_id)])
        # Closed in the durable row, so the lineage cannot be resumed at this host again.
        with contextlib.closing(sqlite3.connect(str(self.root / "runtime.sqlite"))) as connection:
            closed = connection.execute("SELECT closed FROM checkpoints WHERE task_id = ?", (str(task_id),)).fetchone()
        self.assertEqual(closed[0], 1)

    # ---- PM-003: authority is re-checked while the run is in flight -------------------------

    def test_a_permit_that_expires_during_the_provider_call_launches_no_tool(self):
        fake = FakeTime(2_000_000_000)
        store = self._store()
        with patch.object(_clock, "_default_clock", fake.clock()):
            provider = ScriptedProvider(
                ProviderDecision("tool", "catalog.search", {"query": "telescript"}), fake=fake, jump=3_601
            )
            host = self._host(provider, store)
            envelope, probe = self._envelope(host, "slow provider")
            self.assertEqual(envelope.permit.expires_at, 2_000_000_000 + 3600)
            with patch.object(host.tools, "invoke", side_effect=AssertionError("tool must not run")):
                with self.assertRaises(PermitExpiredError):
                    host.run(envelope)
            self._closed_failed(store, host, probe, "permit.expired")

    def test_a_permit_that_expires_during_the_provider_call_completes_nothing(self):
        # Isolates the FIRST boundary. `complete` has no later check of its own, so only the check at
        # the top of _apply_decision can refuse it: a run must not write a final result under
        # authority that ended while the provider was thinking.
        fake = FakeTime(2_000_000_000)
        store = self._store()
        with patch.object(_clock, "_default_clock", fake.clock()):
            provider = ScriptedProvider(ProviderDecision("complete", content={"done": True}), fake=fake, jump=3_601)
            host = self._host(provider, store)
            envelope, probe = self._envelope(host, "late completion")
            with self.assertRaises(PermitExpiredError):
                host.run(envelope)
            self._closed_failed(store, host, probe, "permit.expired")
            self.assertNotEqual(store.load_checkpoint(probe.state.task_id)["status"], "completed")

    def test_a_permit_that_expires_before_the_launch_records_no_effect_and_no_launch(self):
        # The second boundary, isolated: the check at the top of _apply_decision passed, the approval
        # gate returned, and time ran out during the pre-launch cancellation read. The tool must not
        # run AND -- auditor round 1 -- the effect ledger must record NOTHING: a `started` row for an
        # effect that never launched would later settle `unknown` and need reconciling by hand.
        fake = FakeTime(2_000_000_000)
        store = self._store()
        authority = ApprovalAuthority.generate()
        launched = []
        with patch.object(_clock, "_default_clock", fake.clock()):
            host = self._host(PayingProvider(), store)
            host.policy = HostPolicy(
                "host:local-demo",
                (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}, ("reserved",)),),
                ResourceBudget(), "policy-v1", "policy-hash", {"payments.reserve": "external-payment"},
                (authority.trusted_approver(),),
            )
            host.tools.is_side_effecting = lambda name: True
            host.tools.is_isolated = lambda name: True
            envelope, probe = self._envelope(host, "expiry before the ledger")
            object.__setattr__(
                envelope.permit, "grants", (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}),)
            )
            host.signer.seal(envelope)
            first = host.run(envelope)
            self.assertEqual(first.status, "awaiting_input")
            token = authority.issue(
                "payments.reserve", envelope.permit.subject, envelope.permit.audience, envelope.state.task_id,
                envelope.permit.nonce, {"amount": 50, "currency": "USD"}, "policy-hash",
                int(fake.wall) + 3_600, checkpoint_generation=first.checkpoint["checkpoint_generation"],
            )
            envelope.state.memory["approvals"] = {"payments.reserve": asdict(token)}
            host.signer.seal(envelope)

            def slow_cancellation_read(task_id):
                fake.advance(3_601)  # the permit ends after the approval, before the ledger write
                return False

            with patch.object(host.store, "is_task_cancelled", side_effect=slow_cancellation_read):
                with patch.object(host.tools, "invoke", side_effect=lambda *a, **k: launched.append(1)):
                    with self.assertRaises(PermitExpiredError):
                        host.run(envelope)
            self.assertEqual(launched, [])
            with contextlib.closing(sqlite3.connect(str(self.root / "runtime.sqlite"))) as connection:
                effects = connection.execute("SELECT COUNT(*) FROM tool_effects").fetchone()[0]
            self.assertEqual(effects, 0)  # nothing was written under expired authority

    def test_a_permit_that_expires_during_the_started_transition_reverts_the_row(self):
        # Auditor round 3: `prepared` -> `started` is itself a store round trip that can block, so a
        # check placed before it can go stale. The last check sits immediately before the call, where
        # the host KNOWS nothing ran, and settles the row back to `prepared` -- truthful, and
        # re-runnable without an operator reconcile.
        fake = FakeTime(2_000_000_000)
        store = self._store()
        launched = []
        with patch.object(_clock, "_default_clock", fake.clock()):
            host = self._host(ScriptedProvider(ProviderDecision("tool", "catalog.search", {"query": "t"})), store)
            host.tools.is_side_effecting = lambda name: True
            host.tools.is_isolated = lambda name: True
            envelope, probe = self._envelope(host, "expiry during the started transition")
            real_started = host.store.mark_effect_started

            def slow_started(*args, **kwargs):
                real_started(*args, **kwargs)
                fake.advance(3_601)  # the permit ends while the row is being advanced

            with patch.object(host.store, "mark_effect_started", side_effect=slow_started):
                with patch.object(host.tools, "invoke", side_effect=lambda *a, **k: launched.append(1)):
                    with self.assertRaises(PermitExpiredError):
                        host.run(envelope)
            self.assertEqual(launched, [])
            with contextlib.closing(sqlite3.connect(str(self.root / "runtime.sqlite"))) as connection:
                rows = connection.execute("SELECT state, reason FROM tool_effects").fetchall()
            self.assertEqual([row[0] for row in rows], ["prepared"])  # not `started`: nothing ran
            self.assertIn("nothing ran", rows[0][1])

    def test_an_expired_permit_emits_no_migration(self):
        fake = FakeTime(2_000_000_000)
        store = self._store()
        with patch.object(_clock, "_default_clock", fake.clock()):
            provider = ScriptedProvider(
                ProviderDecision("migrate", destination="host:elsewhere"), fake=fake, jump=3_601
            )
            host = self._host(provider, store)
            envelope, probe = self._envelope(host, "late migration")
            with self.assertRaises(PermitExpiredError):
                host.run(envelope)
            self.assertNotIn("migration", envelope.state.memory)
            self._closed_failed(store, host, probe, "permit.expired")

    def test_a_permit_that_expires_during_the_approval_check_burns_no_approval(self):
        # The fourth boundary. The check at the top of _apply_decision passed, and the permit ended
        # while the approval token was being verified. The approval must NOT be consumed durably and
        # the side-effecting tool must not run: an approval is one-use, so burning it here would
        # destroy it for a later, properly authorized run.
        fake = FakeTime(2_000_000_000)
        store = self._store()
        authority = ApprovalAuthority.generate()
        with patch.object(_clock, "_default_clock", fake.clock()):
            host = self._host(PayingProvider(), store)
            host.policy = HostPolicy(
                "host:local-demo",
                (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}, ("reserved",)),),
                ResourceBudget(),
                "policy-v1",
                "policy-hash",
                {"payments.reserve": "external-payment"},
                (authority.trusted_approver(),),
            )
            envelope, _probe = self._envelope(host, "approval then expiry")
            object.__setattr__(
                envelope.permit, "grants", (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}),)
            )
            host.signer.seal(envelope)
            first = host.run(envelope)
            self.assertEqual(first.status, "awaiting_input")

            token = authority.issue(
                "payments.reserve", envelope.permit.subject, envelope.permit.audience, envelope.state.task_id,
                envelope.permit.nonce, {"amount": 50, "currency": "USD"}, "policy-hash",
                int(fake.wall) + 60, checkpoint_generation=first.checkpoint["checkpoint_generation"],
            )
            envelope.state.memory["approvals"] = {"payments.reserve": asdict(token)}
            host.signer.seal(envelope)

            real_verify = host.policy.verify_approval

            def slow_verify(*args, **kwargs):
                outcome = real_verify(*args, **kwargs)
                fake.advance(3_601)  # the permit ends while the approval is being checked
                return outcome

            with patch.object(host.policy, "verify_approval", side_effect=slow_verify):
                with patch.object(host.tools, "invoke", side_effect=AssertionError("tool must not run")):
                    with self.assertRaises(PermitExpiredError):
                        host.run(envelope)

            with contextlib.closing(sqlite3.connect(str(self.root / "runtime.sqlite"))) as connection:
                burned = connection.execute(
                    "SELECT COUNT(*) FROM consumed_nonces WHERE nonce LIKE ?", (f"approval:{envelope.state.task_id}:%",)
                ).fetchone()[0]
            self.assertEqual(burned, 0)  # the one-use approval survives for a properly timed run

    def test_a_permit_that_expires_before_a_plain_tool_launch_stops_it(self):
        # The path with NO ledger row (a tool that is not side-effecting): its last check sits
        # immediately before the launch, with nothing after it. Time passes here while the registry
        # is asked whether the tool is side-effecting.
        fake = FakeTime(2_000_000_000)
        store = self._store()
        launched = []
        with patch.object(_clock, "_default_clock", fake.clock()):
            host = self._host(ScriptedProvider(ProviderDecision("tool", "catalog.search", {"query": "t"})), store)
            envelope, probe = self._envelope(host, "expiry before a plain launch")

            def slow_lookup(name):
                fake.advance(3_601)  # the permit ends after the ledger-write check, before the launch
                return False

            host.tools.is_side_effecting = slow_lookup
            with patch.object(host.tools, "invoke", side_effect=lambda *a, **k: launched.append(1)):
                with self.assertRaises(PermitExpiredError):
                    host.run(envelope)
            self.assertEqual(launched, [])
            with contextlib.closing(sqlite3.connect(str(self.root / "runtime.sqlite"))) as connection:
                effects = connection.execute("SELECT COUNT(*) FROM tool_effects").fetchone()[0]
            self.assertEqual(effects, 0)
            self._closed_failed(store, host, probe, "permit.expired")

    def test_the_boundaries_that_re_read_the_clock_are_named(self):
        # The guard is one call; this pins WHERE it is called, so removing a call site is visible.
        import inspect

        from portmark import host as host_module

        source = inspect.getsource(host_module)
        for where in (
            '"after the provider decision"',
            '"before the ledger write"',
            '"before the tool launch"',
            '"before the approval redemption"',
        ):
            with self.subTest(where=where):
                self.assertIn(where, source)

    # ---- PM-004: a refused decision ends the task durably -----------------------------------

    def test_an_invalid_provider_result_closes_the_task(self):
        # Auditor round 1: READING the decision was outside every boundary, so a provider that
        # returns something that is not a ProviderDecision raised on attribute access and left the
        # checkpoint at `running` -- the same class PM-004 closes.
        store = self._store()

        class BrokenProvider(ModelProvider):
            def decide(self, state, available_tools, grants=()):
                return "not a decision"

        host = self._host(BrokenProvider(), store)
        envelope, probe = self._envelope(host, "invalid provider result")
        with self.assertRaises(Exception):
            host.run(envelope)
        self._closed_failed(store, host, probe, "decision.refused")

    def test_a_decision_whose_fields_explode_closes_the_task(self):
        # Auditor round 2: a field that RAISES on access breaks a handler that reads it with a plain
        # getattr, so the refusal record itself would strand the task it exists to close.
        store = self._store()

        class Exploding:
            kind = "tool"

            @property
            def tool(self):
                raise RuntimeError("boom on read")

            arguments: dict = {}
            content = None
            destination = None

        class BoobyTrappedProvider(ModelProvider):
            def decide(self, state, available_tools, grants=()):
                return Exploding()

        host = self._host(BoobyTrappedProvider(), store)
        envelope, probe = self._envelope(host, "exploding decision field")
        with self.assertRaises(Exception):
            host.run(envelope)
        self._closed_failed(store, host, probe, "decision.refused")

    def test_a_decision_with_unrecordable_fields_closes_the_task(self):
        # Auditor round 2: a field that is not JSON-encodable makes audit.append raise while it
        # hashes the record. Inside the refusal handler that would strand the task, so the handler
        # records only values it can prove are recordable.
        store = self._store()

        class Weird:
            kind = object()
            tool = {"not": "a string"}
            arguments: dict = {}
            content = None
            destination = None

        class WeirdProvider(ModelProvider):
            def decide(self, state, available_tools, grants=()):
                return Weird()

        host = self._host(WeirdProvider(), store)
        envelope, probe = self._envelope(host, "unrecordable decision field")
        with self.assertRaises(Exception):
            host.run(envelope)
        self._closed_failed(store, host, probe, "decision.refused")
        # And the record that was written is plain, readable evidence.
        refusal = [entry for entry in self._events(probe.state.task_id) if entry["event"] == "decision.refused"][0]
        self.assertIsNone(refusal["details"]["kind"])
        self.assertIsNone(refusal["details"]["tool"])

    def test_a_permit_that_expires_during_the_ledger_write_leaves_the_effect_prepared(self):
        # Auditor round 2: the ledger write sits between the last check and the launch, and it can
        # block on a database lock. The tool must not run, and the ledger row must stay `prepared`
        # ("intent recorded, never launched") -- not `started`, which means "this may have landed"
        # and forces a reconcile of an effect that never happened.
        fake = FakeTime(2_000_000_000)
        store = self._store()
        launched = []
        with patch.object(_clock, "_default_clock", fake.clock()):
            host = self._host(ScriptedProvider(ProviderDecision("tool", "catalog.search", {"query": "t"})), store)
            host.tools.is_side_effecting = lambda name: True
            host.tools.is_isolated = lambda name: True
            envelope, probe = self._envelope(host, "expiry during the ledger write")
            real_prepared = host.store.record_effect_prepared

            def slow_prepared(*args, **kwargs):
                real_prepared(*args, **kwargs)
                fake.advance(3_601)  # the permit ends while the ledger row is being written

            with patch.object(host.store, "record_effect_prepared", side_effect=slow_prepared):
                with patch.object(host.tools, "invoke", side_effect=lambda *a, **k: launched.append(1)):
                    with self.assertRaises(PermitExpiredError):
                        host.run(envelope)
            self.assertEqual(launched, [])
            with contextlib.closing(sqlite3.connect(str(self.root / "runtime.sqlite"))) as connection:
                states = [row[0] for row in connection.execute("SELECT state FROM tool_effects").fetchall()]
            self.assertEqual(states, ["prepared"])  # truthful: recorded, never launched

    def test_a_tool_name_that_is_not_a_string_is_refused_before_it_reaches_the_state(self):
        # Auditor round 2, the side door: a tool that is NOT a string but compares equal to a granted
        # name passes the grant check, and then becomes a KEY in state.memory["tool_results"]. The
        # checkpoint's canonical encoding then raises in _persist -- outside every handler -- and
        # strands the task at `running`. The shape check refuses it before any of that.
        store = self._store()

        class SneakyName:
            """Equal to a granted tool name, hashable, and not a string."""

            def __eq__(self, other):
                return other == "catalog.search"

            def __hash__(self):
                return hash("catalog.search")

        class SneakyProvider(ModelProvider):
            def decide(self, state, available_tools, grants=()):
                return ProviderDecision("tool", SneakyName(), {"query": "t"})

        host = self._host(SneakyProvider(), store)
        envelope, probe = self._envelope(host, "sneaky tool name")
        with self.assertRaisesRegex(SecurityError, "tool must be a string"):
            host.run(envelope)
        self._closed_failed(store, host, probe, "decision.refused")

    def test_arguments_that_cannot_be_recorded_are_refused(self):
        # The same shape: the first attempt to encode the arguments depends on which path the run
        # takes, so the raise could land in a place that strands the task. Refuse once, up front.
        store = self._store()

        class UnrecordableProvider(ModelProvider):
            def decide(self, state, available_tools, grants=()):
                # A float NaN passes a type constraint (it IS a number) but canonical_json refuses
                # it (allow_nan=False), so without this check the raise lands wherever that value is
                # first encoded -- which depends on the path, and can be outside the boundary.
                return ProviderDecision("tool", "catalog.search", {"query": float("nan")})

        host = self._host(UnrecordableProvider(), store)
        # A grant with NO argument constraints, so the constraint check cannot catch this first and
        # the encodability rule is the only thing standing in the way.
        host.policy = HostPolicy("host:local-demo", (ToolGrant("catalog.search"),), ResourceBudget())
        envelope, probe = self._envelope(host, "unrecordable arguments")
        object.__setattr__(envelope.permit, "grants", (ToolGrant("catalog.search"),))
        host.signer.seal(envelope)
        with self.assertRaisesRegex(SecurityError, "arguments cannot be recorded"):
            host.run(envelope)
        self._closed_failed(store, host, probe, "decision.refused")

    def test_a_decision_shape_refusal_never_reaches_the_tool_or_the_ledger(self):
        # A refused shape must not run anything or write an effect row.
        store = self._store()
        launched = []

        class BadKindProvider(ModelProvider):
            def decide(self, state, available_tools, grants=()):
                return ProviderDecision(42, "catalog.search", {"query": "t"})

        host = self._host(BadKindProvider(), store)
        host.tools.is_side_effecting = lambda name: True
        host.tools.is_isolated = lambda name: True
        envelope, probe = self._envelope(host, "bad decision kind")
        with patch.object(host.tools, "invoke", side_effect=lambda *a, **k: launched.append(1)):
            with self.assertRaisesRegex(SecurityError, "kind must be a string"):
                host.run(envelope)
        self.assertEqual(launched, [])
        with contextlib.closing(sqlite3.connect(str(self.root / "runtime.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM tool_effects").fetchone()[0], 0)
        self._closed_failed(store, host, probe, "decision.refused")

    def test_a_tool_with_no_grant_closes_the_task_instead_of_stranding_it(self):
        store = self._store()
        provider = ScriptedProvider(ProviderDecision("tool", "not-granted", {}))
        host = self._host(provider, store)
        envelope, probe = self._envelope(host, "ungranted tool")
        with self.assertRaises(SecurityError):
            host.run(envelope)
        self._closed_failed(store, host, probe, "decision.refused")

    def test_an_exhausted_tool_budget_closes_the_task(self):
        store = self._store()
        provider = ScriptedProvider(ProviderDecision("tool", "catalog.search", {"query": "t"}))
        host = self._host(provider, store)
        envelope, probe = self._envelope(host, "budget")
        object.__setattr__(envelope.permit.budget, "max_tool_calls", 0)
        host.signer.seal(envelope)
        with self.assertRaisesRegex(SecurityError, "tool-call budget exhausted"):
            host.run(envelope)
        self._closed_failed(store, host, probe, "decision.refused")

    def test_a_migration_without_a_destination_closes_the_task(self):
        store = self._store()
        provider = ScriptedProvider(ProviderDecision("migrate", destination=""))
        host = self._host(provider, store)
        envelope, probe = self._envelope(host, "no destination")
        with self.assertRaisesRegex(SecurityError, "lacks a destination"):
            host.run(envelope)
        self._closed_failed(store, host, probe, "decision.refused")

    def test_an_unexpected_tool_error_closes_the_task_and_keeps_the_effect_unsettled(self):
        # The dangerous case: an effect may already be in flight. The task must close, and the EFFECT
        # ledger must stay the authority -- the row is not settled `confirmed` by this closure.
        store = self._store()
        provider = ScriptedProvider(ProviderDecision("tool", "catalog.search", {"query": "t"}))
        host = self._host(provider, store)
        envelope, probe = self._envelope(host, "tool explodes")
        host.tools.is_side_effecting = lambda name: True
        host.tools.is_isolated = lambda name: True
        with patch.object(host.tools, "invoke", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                host.run(envelope)
        self._closed_failed(store, host, probe, "decision.refused")
        with contextlib.closing(sqlite3.connect(str(self.root / "runtime.sqlite"))) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute("SELECT state FROM tool_effects WHERE task_id = ?", (envelope.state.task_id,)).fetchall()
        self.assertTrue(rows)  # an effect WAS recorded before the launch
        for row in rows:
            self.assertNotEqual(row["state"], "confirmed")  # the ledger stays the authority

    def test_the_refusal_record_carries_no_arguments_or_state(self):
        store = self._store()
        marker = "swordfish-not-in-the-audit"  # a value that must never be copied into evidence
        provider = ScriptedProvider(ProviderDecision("tool", "not-granted", {"password": marker}))
        host = self._host(provider, store)
        envelope, probe = self._envelope(host, "no secrets in the record")
        with self.assertRaises(SecurityError):
            host.run(envelope)
        blob = repr(self._events(envelope.state.task_id)) + repr(store.load_checkpoint(envelope.state.task_id))
        self.assertNotIn(marker, blob)


if __name__ == "__main__":
    unittest.main()

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

    def test_a_permit_that_expires_before_the_launch_stops_the_launch(self):
        # The second boundary: the check at the top of _apply_decision passed, and time then ran out
        # during the pre-launch ledger step. The tool must still not run.
        fake = FakeTime(2_000_000_000)
        store = self._store()
        launched = []
        with patch.object(_clock, "_default_clock", fake.clock()):
            provider = ScriptedProvider(ProviderDecision("tool", "catalog.search", {"query": "t"}))
            host = self._host(provider, store)
            envelope, probe = self._envelope(host, "expiry before launch")
            host.tools.is_side_effecting = lambda name: True
            host.tools.is_isolated = lambda name: True
            host._effect_pre_launch = lambda *args, **kwargs: (fake.advance(3_601), ("launch", None))[1]
            with patch.object(host.tools, "invoke", side_effect=lambda *a, **k: launched.append(1)):
                with self.assertRaises(PermitExpiredError):
                    host.run(envelope)
            self.assertEqual(launched, [])
            self._closed_failed(store, host, probe, "permit.expired")

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

    def test_the_boundaries_that_re_read_the_clock_are_named(self):
        # The guard is one call; this pins WHERE it is called, so removing a call site is visible.
        import inspect

        from portmark import host as host_module

        source = inspect.getsource(host_module)
        for where in (
            '"after the provider decision"',
            '"before the tool launch"',
            '"before the approval redemption"',
        ):
            with self.subTest(where=where):
                self.assertIn(where, source)

    # ---- PM-004: a refused decision ends the task durably -----------------------------------

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

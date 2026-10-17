"""Cancelling a task stops it, not only its approval path.

`cancel_task` wrote a cancellation row that only the approval gate and the pre-launch re-check read.
A cancelled task resumed and ran tools, and a running one ran to completion. Now every store refuses a
NON-closing checkpoint save, and a migration enqueue, for a cancelled task, inside the save
transaction. The host turns that refusal into a durable CLOSED, failed checkpoint with an
`agent.cancelled` audit event. A closing save stays allowed, so a cancelled task can always be closed.

Known limit (asserted below, not fixed): a tool already chosen in the current step can still run; the
task stops at its next save.
"""

from __future__ import annotations

import contextlib
import copy
import os
import tempfile
import unittest
from pathlib import Path

from portmark.factory import make_demo_envelope, make_host
from portmark.models import AgentState, ProviderDecision
from portmark.providers import ModelProvider
from portmark.security import MigrationPolicy, SecurityError
from portmark.storage import InMemoryRuntimeStore, PostgresRuntimeStore, SQLiteRuntimeStore
import test_audit_export
import test_runtime


@contextlib.contextmanager
def _sqlite():
    with tempfile.TemporaryDirectory() as directory:
        yield SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")


@contextlib.contextmanager
def _memory():
    yield InMemoryRuntimeStore()


def _store_cases():
    cases = [("memory", _memory), ("sqlite", _sqlite)]
    if os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available():
        def _postgres():
            return _postgres_store()
        cases.append(("postgres", _postgres))
    return cases


@contextlib.contextmanager
def _postgres_store():
    with test_runtime.RuntimeTests()._postgres_store_case() as (_, store):
        yield store


class _AwaitThenSearch(ModelProvider):
    """Step 0 asks for input; after a resume it searches once, then completes."""

    def __init__(self) -> None:
        self.calls = 0

    def decide(self, view, tools, grants=()):
        self.calls += 1
        if view.step == 0:
            return ProviderDecision("await_input", content="need input")
        if not view.tool_results.get("catalog.search"):
            return ProviderDecision("tool", "catalog.search", {"query": "w", "limit": 1})
        return ProviderDecision("complete", content="done")


class _CancelsThenSearches(ModelProvider):
    """Cancels its own task during its first decision (an operator cancel landing mid-run), then keeps going."""

    def __init__(self, store) -> None:
        self.store, self.calls, self.task_id = store, 0, None

    def decide(self, view, tools, grants=()):
        self.calls += 1
        if self.calls == 1:
            self.store.cancel_task(self.task_id)
        if not view.tool_results.get("catalog.search"):
            return ProviderDecision("tool", "catalog.search", {"query": "w", "limit": 1})
        return ProviderDecision("complete", content="done")


class _CancelsThenMigrates(ModelProvider):
    def __init__(self, store, destination) -> None:
        self.store, self.destination, self.task_id = store, destination, None

    def decide(self, view, tools, grants=()):
        self.store.cancel_task(self.task_id)
        return ProviderDecision("migrate", destination=self.destination)


def _events(result) -> list[str]:
    return [record["event"] for record in result.audit]


def _resume_envelope(host, envelope, result):
    resumed = copy.deepcopy(envelope)
    resumed.state.checkpoint_generation = result.checkpoint["checkpoint_generation"]
    resumed.state.status = "awaiting_input"
    resumed.signature = ""
    return host.signer.seal(resumed)


class CancelStopsTaskTests(unittest.TestCase):
    def host(self, store, provider):
        host = make_host(store=store, allow_ephemeral_signing_key=True)
        host.providers["p"] = provider
        return host

    def test_a_cancelled_task_cannot_resume_and_is_closed(self):
        # a_checks.py A1: cancel a waiting task, then resume it. It used to complete with tool_calls=1.
        for backend, store_case in _store_cases():
            with self.subTest(backend=backend), store_case() as store:
                provider = _AwaitThenSearch()
                host = self.host(store, provider)
                envelope = make_demo_envelope(host, "wait", "p")
                first = host.run(copy.deepcopy(envelope))
                self.assertEqual(first.status, "awaiting_input")
                host.cancel_task(envelope.state.task_id)

                result = host.run(_resume_envelope(host, envelope, first))

                self.assertEqual(result.status, "failed")
                self.assertIn("agent.cancelled", _events(result))
                self.assertEqual(provider.calls, 1)  # the provider was never asked again
                checkpoint = store.load_checkpoint(envelope.state.task_id)
                self.assertEqual((checkpoint["status"], checkpoint["tool_calls"]), ("failed", 0))
                with self.assertRaisesRegex(SecurityError, "closed"):
                    host.run(_resume_envelope(host, envelope, first))  # durably closed, not just refused once

    def test_control_an_uncancelled_resume_still_completes(self):
        for backend, store_case in _store_cases():
            with self.subTest(backend=backend), store_case() as store:
                host = self.host(store, _AwaitThenSearch())
                envelope = make_demo_envelope(host, "wait", "p")
                first = host.run(copy.deepcopy(envelope))
                result = host.run(_resume_envelope(host, envelope, first))
                self.assertEqual(result.status, "completed")
                self.assertNotIn("agent.cancelled", _events(result))

    def test_a_cancel_during_a_run_stops_it_at_the_next_save(self):
        for backend, store_case in _store_cases():
            with self.subTest(backend=backend), store_case() as store:
                provider = _CancelsThenSearches(store)
                host = self.host(store, provider)
                envelope = make_demo_envelope(host, "run", "p")
                provider.task_id = envelope.state.task_id

                result = host.run(envelope)

                self.assertEqual(result.status, "failed")
                self.assertIn("agent.cancelled", _events(result))
                self.assertEqual(provider.calls, 1)  # stopped before the next provider call
                # Known limit: the tool chosen in the step the cancel landed in still ran.
                self.assertIn("tool.executed", _events(result))
                checkpoint = store.load_checkpoint(envelope.state.task_id)
                self.assertEqual(checkpoint["status"], "failed")

    def test_a_cancelled_task_cannot_escape_by_migrating(self):
        for backend, store_case in _store_cases():
            with self.subTest(backend=backend), store_case() as store:
                host = make_host(host_id="host:source", store=store, allow_ephemeral_signing_key=True)
                host.policy.migration = MigrationPolicy(allowed=True, destinations=("host:destination",))
                provider = _CancelsThenMigrates(store, "host:destination")
                host.providers["p"] = provider
                envelope = make_demo_envelope(host, "migrate away", "p")
                object.__setattr__(envelope.permit, "delegation_allowed", True)
                host.signer.seal(envelope)
                provider.task_id = envelope.state.task_id

                result = host.run(envelope)

                self.assertEqual(result.status, "failed")
                self.assertIsNone(result.migration_envelope)
                self.assertIn("agent.cancelled", _events(result))
                self.assertEqual(store.claim_migrations("worker", 30, limit=10), [])  # nothing left in the outbox
                self.assertEqual(store.load_checkpoint(envelope.state.task_id)["status"], "failed")

    def test_a_pre_cancelled_task_id_is_never_admitted(self):
        for backend, store_case in _store_cases():
            with self.subTest(backend=backend), store_case() as store:
                host = self.host(store, _AwaitThenSearch())
                envelope = make_demo_envelope(host, "never", "p")
                host.cancel_task(envelope.state.task_id)
                with self.assertRaisesRegex(SecurityError, "cancelled"):
                    host.run(envelope)
                self.assertIsNone(store.load_checkpoint(envelope.state.task_id))


class ApprovalGateCancelTests(unittest.TestCase):
    """Tier 1 at the host: a cancel that lands MID-RUN, after admission and before redemption, is caught
    inside the redemption transaction, so the approval is not burned. (A cancel before the resume is now
    closed at admission and never reaches the gate, so this path needs its own test.)"""

    def test_a_cancel_between_admission_and_redemption_burns_no_approval(self):
        from dataclasses import asdict

        from store_probes import nonce_is_consumed

        helpers = test_runtime.RuntimeTests()
        host, authority = helpers._approval_gated_host()
        envelope, first = helpers._suspend_payment_envelope(host, "cancel mid-run")
        self.assertEqual(first.status, "awaiting_input")
        token = helpers._mint_payment_approval(authority, envelope, first.checkpoint["checkpoint_generation"])
        envelope.state.memory["approvals"] = {"payments.reserve": asdict(token)}
        host.signer.seal(envelope)
        task_id = envelope.state.task_id

        class CancelsThenPays(test_runtime.PaymentProvider):
            def decide(self, state, available_tools, grants=()):
                host.cancel_task(task_id)  # lands after the resume's admission save
                return super().decide(state, available_tools, grants)

        host.providers["payer"] = CancelsThenPays()
        result = host.run(envelope)

        events = [record["event"] for record in result.audit]
        denials = [record for record in result.audit if record["event"] == "approval.denied"]
        self.assertEqual([denial["details"]["reason"] for denial in denials], ["cancelled"])
        self.assertNotIn("approval.approved", events)
        self.assertNotIn("tool.executed", events)
        # The gate's in-transaction check rolled the redemption back: the approval is not burned.
        self.assertFalse(nonce_is_consumed(host.store, f"approval:{task_id}:{token.approval_id}"))
        self.assertEqual(result.status, "failed")


class CancelledTaskExportTests(test_audit_export.ExportCase):
    """agent.cancelled is a new audit event kind: it exports, verifies at both levels, and maps to OCSF."""

    def test_a_cancelled_task_exports_and_verifies(self):
        from portmark.ocsf import to_ocsf

        provider = _CancelsThenSearches(self.store)
        self.host.providers["p"] = provider
        envelope = make_demo_envelope(self.host, "cancel me", "p")
        provider.task_id = envelope.state.task_id
        self.assertEqual(self.host.run(envelope).status, "failed")

        report, data = self.export()
        self.assertTrue(report.ok, report.integrity_failures)
        records = test_audit_export.lines_of(data)
        cancelled = next(record for record in records if record.get("event") == "agent.cancelled")
        self.assertEqual(cancelled["details"], {"task_id": envelope.state.task_id})
        level2 = self.verify(data, level2=True)
        self.assertEqual((level2.status, level2.level), ("valid", 2), level2.reasons)
        ocsf = to_ocsf(cancelled, product_version="", now_seconds=0)
        self.assertEqual((ocsf["status"], ocsf["severity"]), ("Failure", "Medium"))


class StoreRefusalTests(unittest.TestCase):
    """The rule itself, per store: inside the save transaction, closing saves allowed."""

    def test_non_closing_save_refused_closing_save_allowed(self):
        for backend, store_case in _store_cases():
            with self.subTest(backend=backend), store_case() as store:
                state = AgentState("task-1", "goal")
                with store.transaction() as txn:
                    generation = txn.save_checkpoint("task-1", state, 0)
                store.cancel_task("task-1")
                with self.assertRaisesRegex(SecurityError, "cancelled"):
                    with store.transaction() as txn:
                        txn.save_checkpoint("task-1", state, generation)
                with self.assertRaisesRegex(SecurityError, "cancelled"):
                    with store.transaction() as txn:
                        txn.enqueue_migration("task-1", "host:destination", "{}")
                state.status = "failed"
                with store.transaction() as txn:
                    txn.save_checkpoint("task-1", state, generation, closed=True)
                self.assertEqual(store.load_checkpoint("task-1")["status"], "failed")


if __name__ == "__main__":
    unittest.main()

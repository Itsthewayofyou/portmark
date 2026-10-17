"""Fix 1 (1A): a fresh admission is refused when the task already has audit history.

The insider replay: someone with write access to the store deletes a finished task's checkpoint row and
its consumed-nonce row, then resends the ORIGINAL signed envelope. The admission looked fresh (no
checkpoint, nonce unused), and `_audit_start` quietly continued the existing audit chain, so the agent and
its tools ran a second time and `verify-audit` still reported the chain valid. A fresh, non-migration
admission can never have audit history (its first save writes its first events), so it is now refused,
before any work and again inside the admission transaction.
"""

from __future__ import annotations

import contextlib
import copy
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from portmark.factory import make_demo_envelope, make_host
from portmark.security import SecurityError
from portmark.storage import InMemoryRuntimeStore, PostgresRuntimeStore, SQLiteRuntimeStore
import test_runtime
from test_audit_floor import HOST, host_signer


@contextlib.contextmanager
def _memory():
    yield InMemoryRuntimeStore()


@contextlib.contextmanager
def _sqlite():
    with tempfile.TemporaryDirectory() as directory:
        yield SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")


@contextlib.contextmanager
def _postgres():
    with test_runtime.RuntimeTests()._postgres_store_case() as (_, store):
        yield store


def _store_cases():
    cases = [("memory", _memory), ("sqlite", _sqlite)]
    if os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available():
        cases.append(("postgres", _postgres))
    return cases


def _insider_deletes_checkpoint_and_nonce(store, task_id: str, nonce: str) -> None:
    """What an insider with store write access does: remove exactly the two rows that make a task look new."""
    if isinstance(store, InMemoryRuntimeStore):
        with store._lock:
            del store._checkpoints[task_id]
            del store._nonces[nonce]
        return
    if isinstance(store, SQLiteRuntimeStore):
        with contextlib.closing(sqlite3.connect(str(store.path))) as connection:
            connection.execute("DELETE FROM checkpoints WHERE task_id = ?", (task_id,))
            connection.execute("DELETE FROM consumed_nonces WHERE task_id = ?", (task_id,))
            connection.commit()
        return
    with store._connect() as connection:
        connection.execute("DELETE FROM checkpoints WHERE task_id = %s", (task_id,))
        connection.execute("DELETE FROM consumed_nonces WHERE task_id = %s", (task_id,))


class InsiderReplayTests(unittest.TestCase):
    def test_a_replay_after_deleting_checkpoint_and_nonce_is_refused(self):
        for backend, store_case in _store_cases():
            with self.subTest(backend=backend), store_case() as store:
                host = make_host(store=store, allow_ephemeral_signing_key=True)
                envelope = make_demo_envelope(host, "find portable agent references")
                original = copy.deepcopy(envelope)
                task_id = envelope.state.task_id

                first = host.run(copy.deepcopy(original))
                self.assertEqual(first.status, "completed")
                head_before = store.audit_head(task_id)

                _insider_deletes_checkpoint_and_nonce(store, task_id, original.permit.nonce)
                self.assertIsNone(store.load_checkpoint(task_id))  # the tamper landed

                with self.assertRaisesRegex(SecurityError, "already has audit history"):
                    host.run(copy.deepcopy(original))
                # Nothing ran and nothing was appended: the chain is exactly as the first run left it.
                self.assertEqual(store.audit_head(task_id), head_before)
                self.assertIsNone(store.load_checkpoint(task_id))
                self.assertTrue(store.verify_audit_chain_status(task_id).valid)

    def test_a_new_host_process_refuses_it_too(self):
        # d1_replay.py replays through a NEW host object over the same database.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            # Fixed key bytes: a durable store requires a signing key that is stable across processes.
            host = make_host(host_id=HOST, store=SQLiteRuntimeStore(path), signer=host_signer())
            original = copy.deepcopy(make_demo_envelope(host, "replay me"))
            host.run(copy.deepcopy(original))
            store = SQLiteRuntimeStore(path)
            _insider_deletes_checkpoint_and_nonce(store, original.state.task_id, original.permit.nonce)
            with self.assertRaisesRegex(SecurityError, "already has audit history"):
                make_host(host_id=HOST, store=store, signer=host_signer()).run(copy.deepcopy(original))

    def test_control_plain_replay_without_tampering_is_still_refused_as_before(self):
        for backend, store_case in _store_cases():
            with self.subTest(backend=backend), store_case() as store:
                host = make_host(store=store, allow_ephemeral_signing_key=True)
                original = copy.deepcopy(make_demo_envelope(host, "once"))
                host.run(copy.deepcopy(original))
                with self.assertRaises(SecurityError):
                    host.run(copy.deepcopy(original))

    def test_control_fresh_tasks_and_resumes_still_run(self):
        for backend, store_case in _store_cases():
            with self.subTest(backend=backend), store_case() as store:
                host, authority = test_runtime.RuntimeTests()._approval_gated_host(store=store)
                helpers = test_runtime.RuntimeTests()
                envelope, first = helpers._suspend_payment_envelope(host, f"pay {backend}")
                self.assertEqual(first.status, "awaiting_input")  # a fresh admission
                token = helpers._mint_payment_approval(authority, envelope, first.checkpoint["checkpoint_generation"])
                from dataclasses import asdict

                envelope.state.memory["approvals"] = {"payments.reserve": asdict(token)}
                host.signer.seal(envelope)
                resumed = host.run(envelope)  # a resume continues the SAME chain
                self.assertEqual(resumed.status, "completed")
                self.assertTrue(store.verify_audit_chain_status(envelope.state.task_id).valid)


class MigrationReplayTests(unittest.TestCase):
    """A migration admission is exempt from the 1A check; its own rule must still refuse a re-delivery."""

    def test_a_redelivered_migration_after_deleting_destination_rows_runs_nothing(self):
        helpers = test_runtime.RuntimeTests()
        source_signer, destination_signer = helpers._migration_signers("fix1-redeliver")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_store = SQLiteRuntimeStore(root / "source.sqlite", source_signer)
            destination_store = SQLiteRuntimeStore(root / "destination.sqlite", destination_signer)
            _, migrated, second = helpers._migrate_once(
                "sqlite", source_store, destination_store, source_signer, destination_signer
            )
            destination_task = second.task_id
            head_before = destination_store.audit_head(destination_task)
            self.assertIsNotNone(head_before)

            _insider_deletes_checkpoint_and_nonce(destination_store, destination_task, migrated.permit.nonce)
            self.assertIsNone(destination_store.load_checkpoint(destination_task))  # the tamper landed
            destination = make_host(
                host_id="host:destination", signer=destination_signer, store=destination_store,
                allow_ephemeral_signing_key=True,
            )
            destination.providers["migrator"] = test_runtime.MigrateThenCompleteProvider("host:destination")
            # Either outcome is acceptable: a refusal, or the stored receipt handed back. Running again is not.
            try:
                destination.run(copy.deepcopy(migrated))
            except SecurityError:
                pass
            self.assertEqual(destination_store.audit_head(destination_task), head_before)


if __name__ == "__main__":
    unittest.main()

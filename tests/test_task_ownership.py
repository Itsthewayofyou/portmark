"""PM-001: a task belongs to the sender that started it (owner decision A: permit issuer + subject).

The resume path found a checkpoint by caller-supplied task id alone and adopted its counters. The
envelope signature proves the sender is *a* trusted identity; it said nothing about this task. So any
trusted sender that learned or guessed an open task's id and generation could resume, drive, and
close another sender's task. The owner is now recorded on the admission checkpoint and compared on
every later save, inside the same transaction as the generation compare-and-swap.
"""

import contextlib
import copy
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from portmark.factory import make_host
from portmark.models import AgentEnvelope, AgentManifest, AgentState, Permit, ProviderDecision, ResourceBudget, ToolGrant
from portmark.providers import ModelProvider
from portmark.security import EnvelopeSigner, SecurityError
from portmark.storage import InMemoryRuntimeStore, PostgresRuntimeStore, SQLiteRuntimeStore
from test_section11_migrations import build_at_version

HOST = "host:local-demo"
PG_DSN = os.environ.get("PORTMARK_TEST_POSTGRES_DSN")
try:
    import psycopg  # noqa: F401

    HAVE_PSYCOPG = True
except ImportError:
    HAVE_PSYCOPG = False


class SuspendProvider(ModelProvider):
    """Suspends every time, so the task stays open and resumable -- the state PM-001 is about."""

    def decide(self, state, available_tools, grants=()):
        return ProviderDecision("await_input", None, {"need": "more input"})


def _envelope(signer, issuer, subject="agent:demo", task_id="task-owned"):
    manifest = AgentManifest(subject, "1.0.0", "suspender", ("catalog.search",), "python:reference-agent-v1")
    permit = Permit(
        issuer=issuer, subject=subject, audience=HOST, expires_at=2_000_000_000 + 3600,
        nonce=f"nonce-{issuer}-{task_id}-{os.urandom(4).hex()}",
        grants=(ToolGrant("catalog.search", {"max_limit": 3, "arguments": {"query": {"type": "string"}}}, ("id",)),),
        budget=ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=32_768),
    )
    return signer.seal(AgentEnvelope(manifest, permit, AgentState(task_id, "research Telescript")))


class TaskOwnershipTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        self.path = self.root / "runtime.sqlite"
        # The host signs its own audit heads; its issuer must be the host id.
        self.host_signer = EnvelopeSigner.generate("host-key", HOST, (HOST,))
        # Two senders the host trusts EQUALLY -- the whole point: signature verification cannot tell
        # them apart, so only stored ownership can.
        self.alice = EnvelopeSigner.generate("alice-key", "user:alice", (HOST,), registry=self.host_signer.registry)
        self.bob = EnvelopeSigner.generate("bob-key", "user:bob", (HOST,), registry=self.host_signer.registry)

    def _host(self):
        return make_host(
            host_id=HOST, signer=self.host_signer, store=SQLiteRuntimeStore(self.path),
            providers={"suspender": SuspendProvider()}, allow_ephemeral_signing_key=True,
        )

    def _suspended_task(self, host):
        envelope = _envelope(self.alice, "user:alice")
        result = host.run(envelope)
        self.assertEqual(result.status, "awaiting_input")
        return envelope, result

    def _row(self):
        with contextlib.closing(sqlite3.connect(str(self.path))) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT status, generation, closed, owner_issuer, owner_subject FROM checkpoints"
            ).fetchone()
        return dict(row)

    def test_the_admission_records_the_owner(self):
        host = self._host()
        self._suspended_task(host)
        row = self._row()
        self.assertEqual((row["owner_issuer"], row["owner_subject"]), ("user:alice", "agent:demo"))

    def test_another_trusted_sender_cannot_resume_the_task(self):
        host = self._host()
        envelope, first = self._suspended_task(host)
        before = self._row()

        # Bob signs his own valid envelope, with Alice's task id AND the correct stored generation.
        stolen = _envelope(self.bob, "user:bob")
        stolen.state.checkpoint_generation = first.checkpoint["checkpoint_generation"]
        self.bob.seal(stolen)
        with self.assertRaisesRegex(SecurityError, "different owner"):
            host.run(stolen)

        # Alice's task is untouched: same generation, still open, still hers.
        self.assertEqual(self._row(), before)
        # And Alice can still resume it.
        resumed = copy.deepcopy(envelope)
        resumed.state.checkpoint_generation = first.checkpoint["checkpoint_generation"]
        self.alice.seal(resumed)
        self.assertEqual(host.run(resumed).status, "awaiting_input")

    def test_the_same_issuer_with_another_subject_cannot_resume_the_task(self):
        host = self._host()
        envelope, first = self._suspended_task(host)
        other = _envelope(self.alice, "user:alice", subject="agent:other")
        other.state.checkpoint_generation = first.checkpoint["checkpoint_generation"]
        self.alice.seal(other)
        with self.assertRaisesRegex(SecurityError, "different owner"):
            host.run(other)

    def test_the_owner_may_rotate_its_signing_key(self):
        # Ownership binds (issuer, subject), not the key id, so a routine key rotation does not lock
        # an owner out of its own open task.
        host = self._host()
        envelope, first = self._suspended_task(host)
        rotated = EnvelopeSigner.generate("alice-key-2", "user:alice", (HOST,), registry=self.host_signer.registry)
        resumed = _envelope(rotated, "user:alice")
        resumed.state.checkpoint_generation = first.checkpoint["checkpoint_generation"]
        rotated.seal(resumed)
        self.assertEqual(host.run(resumed).status, "awaiting_input")
        self.assertEqual(self._row()["owner_issuer"], "user:alice")  # unchanged by the resume

    def test_an_open_task_from_before_the_upgrade_refuses_to_resume(self):
        # A row written before the owner column cannot have its owner reconstructed (the audit trail
        # records the agent, never the issuer). Refuse rather than let the first caller claim it.
        host = self._host()
        envelope, first = self._suspended_task(host)
        with contextlib.closing(sqlite3.connect(str(self.path))) as connection:
            connection.execute("UPDATE checkpoints SET owner_issuer = NULL, owner_subject = NULL")
            connection.commit()
        resumed = copy.deepcopy(envelope)
        resumed.state.checkpoint_generation = first.checkpoint["checkpoint_generation"]
        self.alice.seal(resumed)
        with self.assertRaisesRegex(SecurityError, "legacy checkpoint has no stored owner"):
            host.run(resumed)

    def test_a_closed_task_from_before_the_upgrade_stays_readable(self):
        # Only ownerless RESUME fails closed. A closed legacy task is evidence, and stays verifiable.
        store = SQLiteRuntimeStore(self.path)
        host = make_host(
            host_id=HOST, signer=self.host_signer, store=store,
            providers={"suspender": SuspendProvider()}, allow_ephemeral_signing_key=True,
        )
        envelope = _envelope(self.alice, "user:alice", task_id="task-closed")
        host.run(envelope)  # suspends
        with contextlib.closing(sqlite3.connect(str(self.path))) as connection:
            connection.execute("UPDATE checkpoints SET owner_issuer = NULL, owner_subject = NULL, closed = 1")
            connection.commit()
        self.assertIsNotNone(store.load_checkpoint("task-closed"))
        self.assertTrue(store.verify_audit_chain("task-closed"))

    def test_an_upgraded_database_leaves_its_rows_ownerless(self):
        # The v13 -> v14 step adds the columns; it must NOT invent an owner for existing rows.
        path = self.root / "legacy.sqlite"
        build_at_version(path, 13)
        with contextlib.closing(sqlite3.connect(str(path))) as connection:
            connection.execute(
                "INSERT INTO checkpoints (task_id, status, checkpoint_json, updated_at, generation, closed) "
                "VALUES ('old-task', 'awaiting_input', '{}', 1, 1, 0)"
            )
            connection.commit()
        store = SQLiteRuntimeStore(path)  # upgrades through v14 (owner columns) to v15 (EV-013) on open
        self.assertEqual(store.checkpoint_owner("old-task"), (None, None))
        with contextlib.closing(sqlite3.connect(str(path))) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(version, 15)


class OwnershipStoreContractTests(unittest.TestCase):
    """The durable gate: every store refuses a foreign owner inside the CAS transaction."""

    def _state(self, generation=0):
        state = AgentState("contract-task", "goal")
        state.checkpoint_generation = generation
        return state

    def _check(self, store):
        with store.transaction() as transaction:
            self.assertEqual(transaction.save_checkpoint("contract-task", self._state(), 0, owner=("user:alice", "agent:demo")), 1)
        self.assertEqual(store.checkpoint_owner("contract-task"), ("user:alice", "agent:demo"))
        with self.assertRaisesRegex(SecurityError, "different owner"):
            with store.transaction() as transaction:
                transaction.save_checkpoint("contract-task", self._state(1), 1, owner=("user:bob", "agent:demo"))
        with self.assertRaisesRegex(SecurityError, "different owner"):  # a caller asserting nothing is not a key
            with store.transaction() as transaction:
                transaction.save_checkpoint("contract-task", self._state(1), 1)
        with store.transaction() as transaction:  # the owner advances its own task
            self.assertEqual(transaction.save_checkpoint("contract-task", self._state(1), 1, owner=("user:alice", "agent:demo")), 2)

        # A row with NO stored owner (written before the column existed) is not claimable: a caller
        # that asserts an owner is refused with the upgrade message, not adopted as the owner.
        with store.transaction() as transaction:
            self.assertEqual(transaction.save_checkpoint("legacy-task", self._state(), 0), 1)
        self.assertEqual(store.checkpoint_owner("legacy-task"), (None, None))
        with self.assertRaisesRegex(SecurityError, "legacy checkpoint has no stored owner"):
            with store.transaction() as transaction:
                transaction.save_checkpoint("legacy-task", self._state(1), 1, owner=("user:mallory", "agent:demo"))

    def test_in_memory_store(self):
        self._check(InMemoryRuntimeStore())

    def test_sqlite_store(self):
        with tempfile.TemporaryDirectory() as directory:
            self._check(SQLiteRuntimeStore(Path(directory) / "runtime.sqlite"))

    @unittest.skipUnless(PG_DSN and HAVE_PSYCOPG, "live PostgreSQL required")
    def test_postgres_store(self):
        store = PostgresRuntimeStore(PG_DSN, schema=f"pm001_{os.urandom(4).hex()}")
        self._check(store)


if __name__ == "__main__":
    unittest.main()

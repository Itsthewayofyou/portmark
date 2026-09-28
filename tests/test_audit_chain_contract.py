"""Every runtime store refuses an audit event that does not extend its stored head, and writes nothing.

The in-memory store is the independent oracle; SQLite and PostgreSQL share the rule in
storage._check_audit_link. Before this test, disabling the sequence check in the SQL stores passed the
whole suite.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from portmark.security import SecurityError
from portmark.storage import InMemoryRuntimeStore, PostgresRuntimeStore, SQLiteRuntimeStore

PG_DSN = os.environ.get("PORTMARK_TEST_POSTGRES_DSN")
try:
    import psycopg  # noqa: F401

    HAVE_PSYCOPG = True
except ImportError:
    HAVE_PSYCOPG = False


def _event(sequence: int, previous: str, hash_: str) -> dict:
    return {"sequence": sequence, "event": "test.event", "details": {}, "previous": previous, "hash": hash_}


class AuditChainStoreContractTests(unittest.TestCase):
    def _append(self, store, event) -> None:
        with store.transaction() as transaction:
            transaction.append_audit_events("chain-task", "host:a", (event,))

    def _check(self, store) -> None:
        self._append(store, _event(0, "", "h0"))
        self.assertEqual(store.audit_head("chain-task"), ("h0", 1))
        cases = {
            "sequence is not contiguous": _event(2, "h0", "h2"),  # skips sequence 1
            "previous hash does not match stored head": _event(1, "not-h0", "h1"),
        }
        for message, event in cases.items():
            with self.subTest(refusal=message):
                with self.assertRaisesRegex(SecurityError, message):
                    self._append(store, event)
                self.assertEqual(store.audit_head("chain-task"), ("h0", 1))  # nothing was written
        self._append(store, _event(1, "h0", "h1"))  # the event that does extend the head is accepted
        self.assertEqual(store.audit_head("chain-task"), ("h1", 2))

    def test_in_memory_store(self):
        self._check(InMemoryRuntimeStore())

    def test_sqlite_store(self):
        with tempfile.TemporaryDirectory() as directory:
            self._check(SQLiteRuntimeStore(Path(directory) / "runtime.sqlite"))

    @unittest.skipUnless(PG_DSN and HAVE_PSYCOPG, "live PostgreSQL required")
    def test_postgres_store(self):
        self._check(PostgresRuntimeStore(PG_DSN, schema=f"chain_{os.urandom(4).hex()}"))


if __name__ == "__main__":
    unittest.main()

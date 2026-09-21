"""EV-006 / TM-005: optional authenticated encryption of stored checkpoints.

Owner decisions: D1 -- optional, reported by the `checkpoint_encryption_active` gauge; D2 -- strict
reads plus the one-time `portmark store encrypt-checkpoints` migration, with no plaintext-read flag.
Every store test runs on SQLite and, when PORTMARK_TEST_POSTGRES_DSN is set, on Postgres.
"""

import base64
import contextlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from portmark.checkpoint_crypto import (
    CHECKPOINT_KEYS_ENV,
    CHECKPOINT_KEYS_FILE_ENV,
    CheckpointCodec,
    CheckpointCryptoError,
    codec_from_environment,
    generate_key,
    parse_keyring,
)
from portmark.cli import main as cli_main
from portmark.factory import make_demo_envelope, make_host
from portmark.models import AgentState
from portmark.storage import PostgresRuntimeStore, SQLiteRuntimeStore, create_runtime_store

HOST = "host:local-demo"
PG_DSN = os.environ.get("PORTMARK_TEST_POSTGRES_DSN")
try:
    import psycopg  # noqa: F401

    HAVE_PSYCOPG = True
except ImportError:
    HAVE_PSYCOPG = False

KEY_A = base64.b64encode(bytes(range(32))).decode()
KEY_B = base64.b64encode(bytes(range(32, 64))).decode()
_NO_KEY_ENV = {CHECKPOINT_KEYS_ENV: "", CHECKPOINT_KEYS_FILE_ENV: ""}


def _ring(*entries: str) -> CheckpointCodec:
    return parse_keyring(",".join(entries))


def _save(store, task_id: str, goal: str = "secret goal text", expected: int = 0) -> int:
    with store.transaction() as transaction:
        return transaction.save_checkpoint(task_id, AgentState(task_id, goal), expected)


class _StoreCases:
    """Store-boundary cases. Subclasses provide `_open(codec)`, `_raw(task_id)` and `_sql(statement, params)`."""

    def test_sealed_row_round_trips_and_hides_the_state(self):
        store = self._open(_ring(f"a:{KEY_A}"))
        _save(store, "t1")
        raw = self._raw("t1")
        self.assertTrue(raw.startswith("pmc1:a:"))
        self.assertNotIn("secret goal text", raw)
        loaded = store.load_checkpoint("t1")
        self.assertEqual((loaded["task_id"], loaded["goal"], loaded["checkpoint_generation"]), ("t1", "secret goal text", 1))
        # The update path (generation 2) seals too, and the task continues.
        _save(store, "t1", "second", expected=1)
        self.assertEqual(store.load_checkpoint("t1")["goal"], "second")
        self.assertTrue(self._raw("t1").startswith("pmc1:a:"))

    def test_a_changed_byte_fails_closed(self):
        store = self._open(_ring(f"a:{KEY_A}"))
        _save(store, "t1")
        raw = self._raw("t1")
        middle = len(raw) // 2
        self._set_raw("t1", raw[:middle] + ("B" if raw[middle] == "A" else "A") + raw[middle + 1:])
        with self.assertRaisesRegex(CheckpointCryptoError, "failed authentication"):
            store.load_checkpoint("t1")

    def test_a_wrong_key_fails_closed(self):
        _save(self._open(_ring(f"a:{KEY_A}")), "t1")
        with self.assertRaisesRegex(CheckpointCryptoError, "failed authentication"):
            self._open(_ring(f"a:{KEY_B}")).load_checkpoint("t1")
        with self.assertRaisesRegex(CheckpointCryptoError, "not in the keyring"):
            self._open(_ring(f"b:{KEY_B}")).load_checkpoint("t1")

    def test_a_row_moved_to_another_task_or_generation_fails_closed(self):
        store = self._open(_ring(f"a:{KEY_A}"))
        _save(store, "t1")
        _save(store, "t2", "other")
        self._set_raw("t2", self._raw("t1"))
        with self.assertRaisesRegex(CheckpointCryptoError, "failed authentication"):
            store.load_checkpoint("t2")
        self._sql_generation("t1", 5)
        with self.assertRaisesRegex(CheckpointCryptoError, "failed authentication"):
            store.load_checkpoint("t1")

    def test_reads_are_strict_in_both_directions(self):
        _save(self._open(None), "plain")
        with self.assertRaisesRegex(CheckpointCryptoError, "encrypt-checkpoints"):
            self._open(_ring(f"a:{KEY_A}")).load_checkpoint("plain")
        _save(self._open(_ring(f"a:{KEY_A}")), "sealed")
        with self.assertRaisesRegex(CheckpointCryptoError, "no checkpoint keyring is configured"):
            self._open(None).load_checkpoint("sealed")

    def test_migration_dry_run_then_apply_seals_every_plaintext_row(self):
        plain = self._open(None)
        for task_id in ("p1", "p2", "p3"):
            _save(plain, task_id)
        keyed = self._open(_ring(f"a:{KEY_A}"))
        _save(keyed, "s1")
        before = {task_id: self._raw(task_id) for task_id in ("p1", "p2", "p3", "s1")}
        report = keyed.encrypt_checkpoints(apply=False)
        self.assertEqual((report["encrypted"], report["rekeyed"], report["verified"], report["applied"]), (3, 0, 1, False))
        self.assertEqual({task_id: self._raw(task_id) for task_id in before}, before)
        report = keyed.encrypt_checkpoints(apply=True)
        self.assertEqual((report["encrypted"], report["verified"], report["applied"]), (3, 1, True))
        for task_id in ("p1", "p2", "p3"):
            self.assertTrue(self._raw(task_id).startswith("pmc1:a:"))
            self.assertEqual(keyed.load_checkpoint(task_id)["goal"], "secret goal text")
        self.assertEqual(self._raw("s1"), before["s1"])
        self.assertEqual(keyed.maintenance_log(1)[0]["action"], "checkpoint-encrypt")
        # A second run finds nothing left to do.
        self.assertEqual(keyed.encrypt_checkpoints(apply=True)["encrypted"], 0)

    def test_migration_is_atomic_when_one_row_cannot_be_read(self):
        plain = self._open(None)
        _save(plain, "p1")
        _save(plain, "p2")
        keyed = self._open(_ring(f"a:{KEY_A}"))
        _save(keyed, "bad")
        raw = self._raw("bad")
        self._set_raw("bad", raw[:-4] + ("AAAA" if not raw.endswith("AAAA") else "BBBB"))
        before = {task_id: self._raw(task_id) for task_id in ("p1", "p2", "bad")}
        with self.assertRaisesRegex(CheckpointCryptoError, "'bad' cannot be migrated, nothing was changed"):
            keyed.encrypt_checkpoints(apply=True)
        self.assertEqual({task_id: self._raw(task_id) for task_id in before}, before)
        self.assertFalse(any(entry["action"] == "checkpoint-encrypt" for entry in keyed.maintenance_log(10)))

    def test_migration_rotates_rows_to_the_current_key(self):
        _save(self._open(_ring(f"a:{KEY_A}")), "t1")
        rotated = self._open(_ring(f"b:{KEY_B}", f"a:{KEY_A}"))
        self.assertEqual(rotated.load_checkpoint("t1")["goal"], "secret goal text")
        report = rotated.encrypt_checkpoints(apply=True)
        self.assertEqual((report["rekeyed"], report["key_id"]), (1, "b"))
        self.assertTrue(self._raw("t1").startswith("pmc1:b:"))
        self.assertEqual(self._open(_ring(f"b:{KEY_B}")).load_checkpoint("t1")["goal"], "secret goal text")

    def test_migration_needs_a_keyring(self):
        with self.assertRaisesRegex(ValueError, "needs a checkpoint keyring"):
            self._open(None).encrypt_checkpoints()


class SQLiteCheckpointEncryptionTests(_StoreCases, unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "runtime.sqlite"

    def _open(self, codec):
        return SQLiteRuntimeStore(self.path, checkpoint_codec=codec)

    def _query(self, statement, params=()):
        connection = sqlite3.connect(self.path)
        try:
            with connection:
                return connection.execute(statement, params).fetchone()
        finally:
            connection.close()

    def _raw(self, task_id):
        return self._query("SELECT checkpoint_json FROM checkpoints WHERE task_id = ?", (task_id,))[0]

    def _set_raw(self, task_id, value):
        self._query("UPDATE checkpoints SET checkpoint_json = ? WHERE task_id = ?", (value, task_id))

    def _sql_generation(self, task_id, generation):
        self._query("UPDATE checkpoints SET generation = ? WHERE task_id = ?", (generation, task_id))


@unittest.skipUnless(PG_DSN and HAVE_PSYCOPG, "live PostgreSQL required (PORTMARK_TEST_POSTGRES_DSN)")
class PostgresCheckpointEncryptionTests(_StoreCases, unittest.TestCase):
    def setUp(self):
        self.schema = f"ev006_{os.urandom(4).hex()}"
        self.addCleanup(self._drop_schema)

    def _open(self, codec):
        return PostgresRuntimeStore(PG_DSN, schema=self.schema, checkpoint_codec=codec)

    def _query(self, statement, params=()):
        with psycopg.connect(PG_DSN, options=f"-c search_path={self.schema}") as connection:
            cursor = connection.execute(statement, params)
            return cursor.fetchone() if cursor.description else None

    def _drop_schema(self):
        with psycopg.connect(PG_DSN) as connection:
            connection.execute(f'DROP SCHEMA IF EXISTS "{self.schema}" CASCADE')  # nosec B608 -- random test schema name

    def _raw(self, task_id):
        return self._query("SELECT checkpoint_json FROM checkpoints WHERE task_id = %s", (task_id,))[0]

    def _set_raw(self, task_id, value):
        self._query("UPDATE checkpoints SET checkpoint_json = %s WHERE task_id = %s", (value, task_id))

    def _sql_generation(self, task_id, generation):
        self._query("UPDATE checkpoints SET generation = %s WHERE task_id = %s", (generation, task_id))


class KeyringTests(unittest.TestCase):
    def test_bad_keyrings_are_refused(self):
        cases = {
            "must be written as key-id:base64-key": "just-a-key",
            "is not valid base64": "a:%%%",
            "exactly 32 bytes": f"a:{base64.b64encode(bytes(16)).decode()}",
            "appears twice": f"a:{KEY_A},a:{KEY_B}",
            "must be 1-64 characters": f"bad id:{KEY_A}",
            "at least one key": " , ",
        }
        for message, text in cases.items():
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    parse_keyring(text)

    def test_the_first_key_seals_and_urlsafe_or_standard_base64_both_parse(self):
        url_key = generate_key()
        codec = parse_keyring(f"new:{url_key}\nold:{KEY_A}")
        self.assertEqual((codec.current_key_id, codec.key_ids), ("new", ("new", "old")))

    def test_environment_sources(self):
        self.assertIsNone(codec_from_environment({}))
        self.assertEqual(codec_from_environment({CHECKPOINT_KEYS_ENV: f"a:{KEY_A}"}).current_key_id, "a")
        with self.assertRaisesRegex(ValueError, "not both"):
            codec_from_environment({CHECKPOINT_KEYS_ENV: f"a:{KEY_A}", CHECKPOINT_KEYS_FILE_ENV: "/x"})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keys"
            path.write_text(f"f:{KEY_A}\n", encoding="utf-8")
            os.chmod(path, 0o600)
            self.assertEqual(codec_from_environment({CHECKPOINT_KEYS_FILE_ENV: str(path)}).current_key_id, "f")
            with self.assertRaisesRegex(ValueError, "cannot be read"):
                codec_from_environment({CHECKPOINT_KEYS_FILE_ENV: str(path) + ".missing"})
            if os.name == "posix":
                os.chmod(path, 0o640)
                with self.assertRaisesRegex(ValueError, "must not be readable by group or others"):
                    codec_from_environment({CHECKPOINT_KEYS_FILE_ENV: str(path)})

    def test_each_seal_uses_a_fresh_nonce(self):
        codec = _ring(f"a:{KEY_A}")
        self.assertNotEqual(codec.seal("t", 1, "{}"), codec.seal("t", 1, "{}"))

    def test_create_runtime_store_loads_the_keyring_from_the_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            with patch.dict(os.environ, {CHECKPOINT_KEYS_ENV: f"a:{KEY_A}", CHECKPOINT_KEYS_FILE_ENV: ""}):
                self.assertEqual(create_runtime_store("sqlite", path).checkpoint_codec.current_key_id, "a")
            with patch.dict(os.environ, _NO_KEY_ENV):
                self.assertIsNone(create_runtime_store("sqlite", path).checkpoint_codec)
            with patch.dict(os.environ, {CHECKPOINT_KEYS_ENV: "broken", CHECKPOINT_KEYS_FILE_ENV: ""}):
                with self.assertRaises(ValueError):
                    create_runtime_store("sqlite", path)


class HostAndGaugeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "runtime.sqlite"

    def _gauge(self, host) -> str:
        return next(line for line in host.metrics.prometheus_text().splitlines() if line.startswith("portmark_checkpoint_encryption_active "))

    def test_a_host_runs_on_sealed_checkpoints_and_reports_the_gauge(self):
        store = SQLiteRuntimeStore(self.path, checkpoint_codec=_ring(f"a:{KEY_A}"))
        host = make_host(host_id=HOST, store=store, allow_ephemeral_signing_key=True)
        self.assertTrue(self._gauge(host).endswith(" 1"))
        result = host.run(make_demo_envelope(host, "research Telescript"))
        self.assertEqual(result.status, "completed")
        connection = sqlite3.connect(self.path)
        try:
            raw = connection.execute("SELECT checkpoint_json FROM checkpoints").fetchone()[0]
        finally:
            connection.close()
        self.assertTrue(raw.startswith("pmc1:a:"))
        self.assertNotIn("Telescript", raw)

    def test_the_gauge_is_0_without_a_keyring(self):
        host = make_host(host_id=HOST, store=SQLiteRuntimeStore(self.path), allow_ephemeral_signing_key=True)
        self.assertTrue(self._gauge(host).endswith(" 0"))


class EncryptCheckpointsCliTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "runtime.sqlite"
        _save(SQLiteRuntimeStore(self.path), "p1")

    def _run(self, argv, env):
        stdout, stderr = io.StringIO(), io.StringIO()
        full_env = {"PORTMARK_STORE_PATH": str(self.path), **_NO_KEY_ENV, **env}
        with patch.dict(os.environ, full_env, clear=True), patch.object(sys, "argv", ["portmark", *argv]):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                try:
                    cli_main()
                    code = 0
                except SystemExit as exit_:
                    code = exit_.code
        return code, stdout.getvalue(), stderr.getvalue()

    def _raw(self):
        connection = sqlite3.connect(self.path)
        try:
            return connection.execute("SELECT checkpoint_json FROM checkpoints WHERE task_id = 'p1'").fetchone()[0]
        finally:
            connection.close()

    def test_dry_run_then_apply(self):
        keys = {CHECKPOINT_KEYS_ENV: f"a:{KEY_A}"}
        code, out, err = self._run(["store", "encrypt-checkpoints"], keys)
        self.assertEqual((code, json.loads(out)["encrypted"]), (0, 1))
        self.assertIn("DRY RUN", err)
        self.assertFalse(self._raw().startswith("pmc1:"))
        code, out, _ = self._run(["store", "encrypt-checkpoints", "--apply"], keys)
        self.assertEqual((code, json.loads(out)["applied"]), (0, True))
        self.assertTrue(self._raw().startswith("pmc1:a:"))

    def test_refusals(self):
        code, _, err = self._run(["store", "encrypt-checkpoints", "--apply"], {})
        self.assertEqual(code, 2)
        self.assertIn("needs a checkpoint keyring", err)
        code, _, err = self._run(["store", "encrypt-checkpoints"], {CHECKPOINT_KEYS_ENV: "broken"})
        self.assertEqual(code, 2)
        self.assertIn("key-id:base64-key", err)
        connection = sqlite3.connect(self.path)
        try:
            with connection:
                connection.execute("UPDATE checkpoints SET checkpoint_json = 'pmc1:a:AAAA' WHERE task_id = 'p1'")
        finally:
            connection.close()
        code, out, _ = self._run(["store", "encrypt-checkpoints", "--apply"], {CHECKPOINT_KEYS_ENV: f"a:{KEY_A}"})
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["status"], "refused")


class CheckpointEncryptionDocsTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]

    def test_deployment_documents_the_control_and_its_limits(self):
        text = (self.ROOT / "DEPLOYMENT.md").read_text(encoding="utf-8")
        for needle in (
            "## Checkpoint Encryption",
            CHECKPOINT_KEYS_ENV,
            CHECKPOINT_KEYS_FILE_ENV,
            "store encrypt-checkpoints --apply",
            "checkpoint_encryption_active",
            "**Residual risk:**",
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()

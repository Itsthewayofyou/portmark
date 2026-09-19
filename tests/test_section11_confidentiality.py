"""Section 11 PR A: secrets never reach log output, and runtime state is owner-only at rest.

Finding #2: redaction ran only in the JSON formatter, and no pattern matched URI user-info, so a
PostgreSQL DSN password leaked in both modes. Finding #5: the SQLite store's permissions followed the
ambient umask, so a 022 umask made task data readable by every local user.
"""

import io
import json
import logging
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from portmark._durable_file import atomic_write_bytes
from portmark.logging_config import SERVER_LOGGERS, configure_logging, redact_log_value
from portmark.security import EnvelopeSigner
from portmark.storage import SQLiteRuntimeStore
from portmark.witness import LocalFloorWitness

SECRET = "super-secret-value"  # nosec B105 -- a synthetic marker the leak tests search for, not a credential
POSIX = os.name != "nt"


def _raise_nested(message):
    try:
        raise ValueError(f"inner connect failed for postgres://alice:{SECRET}@db/app")
    except ValueError as inner:
        raise RuntimeError(message) from inner


class _LoggingSandbox:
    """Capture what configure_logging writes, then restore every logger it touched."""

    def __init__(self, json_logs):
        self.json_logs = json_logs
        self.stream = io.StringIO()

    def __enter__(self):
        names = ("", *SERVER_LOGGERS)
        self._saved = {
            name: (list(logging.getLogger(name).handlers), logging.getLogger(name).level, logging.getLogger(name).propagate)
            for name in names
        }
        with redirect_stderr(self.stream):
            configure_logging("DEBUG", self.json_logs)
        return self

    def __exit__(self, *exc):
        for name, (handlers, level, propagate) in self._saved.items():
            logger = logging.getLogger(name)
            logger.handlers[:] = handlers
            logger.setLevel(level)
            logger.propagate = propagate


class LogRedactionTests(unittest.TestCase):
    def emit_everything(self, logger):
        # The auditor's reproduction, widened to every channel a record can carry a secret on.
        try:
            _raise_nested(f"PASSWORD={SECRET}")
        except RuntimeError:
            logger.exception("audit: failed Authorization: Bearer %s at postgres://alice:%s@db/app", SECRET, SECRET)
        logger.error("query was GET /x?api_key=%s&page=2", SECRET)
        logger.error("redis at redis://:%s@cache:6379/0 and https://%s@github.com/org", SECRET, SECRET)
        logger.error("libpq dsn host=db password=%s user=u", SECRET, stack_info=True)
        logger.error("args=%r", ValueError(f"token={SECRET}"))

    def test_text_logging_redacts_messages_args_tracebacks_and_uris(self):
        with _LoggingSandbox(json_logs=False) as sandbox:
            self.emit_everything(logging.getLogger("portmark.test"))
        output = sandbox.stream.getvalue()
        self.assertIn("Traceback", output)
        self.assertIn("postgres://[REDACTED]@db/app", output)
        self.assertNotIn(SECRET, output)

    def test_json_logging_redacts_dsn_userinfo_and_every_field(self):
        with _LoggingSandbox(json_logs=True) as sandbox:
            self.emit_everything(logging.getLogger("portmark.test"))
        output = sandbox.stream.getvalue()
        records = [json.loads(line) for line in output.splitlines()]
        self.assertTrue(any("exception" in record for record in records))
        self.assertTrue(any("stack" in record for record in records))
        self.assertNotIn(SECRET, output)

    def test_uvicorn_loggers_are_routed_through_the_redacting_handler(self):
        # uvicorn installs its own non-propagating handlers before it imports the app. Simulate
        # that, then prove configure_logging takes them over.
        private = io.StringIO()
        uvicorn_error = logging.getLogger("uvicorn.error")
        saved = (list(uvicorn_error.handlers), uvicorn_error.propagate)
        try:
            uvicorn_error.handlers[:] = [logging.StreamHandler(private)]
            uvicorn_error.propagate = False
            with _LoggingSandbox(json_logs=False) as sandbox:
                try:
                    _raise_nested("Exception in ASGI application")
                except RuntimeError:
                    uvicorn_error.exception("Exception in ASGI application")
        finally:
            uvicorn_error.handlers[:], uvicorn_error.propagate = saved
        self.assertEqual(private.getvalue(), "")
        self.assertIn("Exception in ASGI application", sandbox.stream.getvalue())
        self.assertNotIn(SECRET, sandbox.stream.getvalue())

    def test_ordinary_urls_and_addresses_are_not_mangled(self):
        for text in ("see https://example.com/path?page=2 ok", "http://example.com/a@b", "mailto:a@b.com"):
            self.assertEqual(redact_log_value(text), text)


@unittest.skipUnless(POSIX, "POSIX permission bits")
class SQLitePermissionTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)
        self._umask = os.umask(0o022)  # the common default the auditor used

    def tearDown(self):
        os.umask(self._umask)
        self._dir.cleanup()

    def mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    def test_new_database_and_wal_and_shm_are_owner_only_under_a_022_umask(self):
        path = self.root / "state" / "portmark.db"
        store = SQLiteRuntimeStore(path)
        # SQLite removes -wal/-shm when the last connection closes, so hold one open (as a running
        # host does) and write through the store while it is open.
        held = store._connect()
        try:
            with store.transaction() as transaction:
                transaction.consume_nonce("n1", "subject", "audience", "t1")
            for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
                self.assertTrue(candidate.exists(), candidate)
                self.assertEqual(self.mode(candidate), 0o600, candidate)
        finally:
            held.close()
        self.assertEqual(self.mode(path.parent), 0o700)

    def test_existing_group_or_world_readable_database_is_refused_with_the_chmod_fix(self):
        path = self.root / "loose db.sqlite"
        SQLiteRuntimeStore(path)
        os.chmod(path, 0o644)
        with self.assertRaises(RuntimeError) as raised:
            SQLiteRuntimeStore(path)
        self.assertIn(f"chmod 600 '{path}'", str(raised.exception))
        self.assertIn("0644", str(raised.exception))
        os.chmod(path, 0o600)
        SQLiteRuntimeStore(path)  # the printed fix is sufficient

    def test_loose_wal_or_shm_side_file_is_refused(self):
        for suffix in ("-wal", "-shm"):
            with self.subTest(suffix=suffix):
                path = self.root / f"side{suffix}.db"
                SQLiteRuntimeStore(path)
                side = Path(f"{path}{suffix}")
                side.touch()
                os.chmod(side, 0o640)
                with self.assertRaises(RuntimeError) as raised:
                    SQLiteRuntimeStore(path)
                self.assertIn(f"chmod 600 {side}", str(raised.exception))


@unittest.skipUnless(POSIX, "POSIX permission bits")
class FloorPermissionTests(unittest.TestCase):
    def test_floor_is_tightened_to_owner_only_on_every_write(self):
        with tempfile.TemporaryDirectory() as directory:
            floor_path = Path(directory) / "audit-floor.json"
            signer = EnvelopeSigner.from_private_key_bytes("floor-key", "host:perm", bytes(range(32)))
            witness = LocalFloorWitness(floor_path, "host:perm", signer, signer)
            witness.create(1, None, {}, [])
            self.assertEqual(stat.S_IMODE(os.stat(floor_path).st_mode), 0o600)
            os.chmod(floor_path, 0o644)  # e.g. restored by a tool that ignored modes
            witness.advance_head("t1", 1, "h1")
            self.assertEqual(stat.S_IMODE(os.stat(floor_path).st_mode), 0o600)

    def test_atomic_write_keeps_the_existing_mode_unless_forced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "registry.json")
            atomic_write_bytes(path, b"{}")
            os.chmod(path, 0o644)
            atomic_write_bytes(path, b"{}")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644)
            atomic_write_bytes(path, b"{}", mode=0o600)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()

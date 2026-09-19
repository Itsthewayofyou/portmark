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
import subprocess  # nosec B404 -- runs this test's own interpreter on a fixed inline script
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from portmark._durable_file import atomic_write_bytes
from portmark.logging_config import SERVER_LOGGERS, configure_logging, redact_log_value
from portmark.security import EnvelopeSigner
from portmark.storage import SQLiteRuntimeStore, _refuse_insecure_sqlite_file
from portmark.witness import LocalFloorWitness

SRC = str(Path(__file__).resolve().parent.parent / "src")

# The REAL `portmark serve` startup order (auditor round 2): CLI main -> configure_logging ->
# make_host -> serve -> uvicorn.run -> uvicorn Config (which applies its log_config) -> Server.run.
# Only Server.run is replaced: instead of listening, it logs the way a failing request would.
CLI_SERVE_SCRIPT = """
import logging, sys
import uvicorn.server

SECRET = sys.argv[1]

def fake_run(self, sockets=None):
    self.started = True  # uvicorn.run exits 3 (startup failure) if the server never started
    try:
        raise RuntimeError(f"db down postgres://u:{SECRET}@db/x")
    except RuntimeError:
        logging.getLogger("uvicorn.error").exception("Exception in ASGI application Authorization: Bearer %s", SECRET)

uvicorn.server.Server.run = fake_run
sys.argv = ["portmark", "serve", "--bind", "127.0.0.1", "--port", "8765"]
from portmark.cli import main
main()
"""

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
        logger.error("signed url /blob?sig=%s&se=2026", SECRET)  # only the query-string rule matches `sig`
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

    def test_cli_serve_startup_order_keeps_uvicorn_output_redacted(self):
        # Auditor round 2: uvicorn.run() re-applied uvicorn's default logging AFTER the CLI's
        # configure_logging, reinstalling unredacted handlers. Run the real CLI ordering.
        env = {**os.environ, "PYTHONPATH": SRC, "PYTHONDONTWRITEBYTECODE": "1"}
        for variable in ("PORTMARK_LOG_JSON", "PORTMARK_STORE_PATH", "PORTMARK_AUDIT_FLOOR_PATH"):
            env.pop(variable, None)
        result = subprocess.run(  # nosec B603 -- this interpreter, fixed inline script
            [sys.executable, "-c", CLI_SERVE_SCRIPT, SECRET], capture_output=True, text=True, env=env, timeout=120
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("Exception in ASGI application", output)  # the log line was emitted at all
        self.assertIn("Traceback", output)
        self.assertNotIn(SECRET, output)

    def test_other_credential_forms_are_redacted(self):
        # Auditor round 2, Low: header, key=value, and cookie forms outside the first patterns.
        cases = (
            f"X-API-Key: {SECRET}",
            f"API-Key: {SECRET}",
            f"x-auth-token: {SECRET}",
            f"api_key={SECRET}",
            f"access_key={SECRET}",
            f"aws_secret_access_key={SECRET}",
            f"api-key={SECRET}",
            f"Cookie: session={SECRET}; theme=dark",
            f"Set-Cookie: sid={SECRET}; HttpOnly",
            f"Authorization: Basic {SECRET}",
            f"Proxy-Authorization: Basic {SECRET}",
            f'Authorization: Digest username="bob", response="{SECRET}"',
            f"Authorization: {SECRET}",
            f"{{'x-api-key': '{SECRET}', 'cookie': 'a={SECRET}', 'proxy-authorization': 'Basic {SECRET}'}}",
        )
        for text in cases:
            with self.subTest(text=text):
                self.assertNotIn(SECRET, redact_log_value(text))
        # A Bearer value keeps its scheme and the rest of the line survives.
        self.assertEqual(
            redact_log_value(f"failed Authorization: Bearer {SECRET} request_id=7"),
            "failed Authorization: Bearer [REDACTED] request_id=7",
        )
        # A header value is redacted to the end of ITS line only.
        self.assertEqual(redact_log_value(f"a\nCookie: s={SECRET}\nnext"), "a\nCookie: [REDACTED]\nnext")

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

    # -- auditor round 2: the directory, symlinks, file type, and ownership ----------------------
    def test_group_or_world_writable_store_directory_is_refused_with_the_chmod_fix(self):
        for mode in (0o777, 0o770, 0o702):
            with self.subTest(mode=oct(mode)):
                directory = self.root / f"dir{mode:o}"
                directory.mkdir()
                SQLiteRuntimeStore(directory / "state.db")  # safe while 0700
                os.chmod(directory, mode)
                with self.assertRaises(RuntimeError) as raised:
                    SQLiteRuntimeStore(directory / "state.db")
                self.assertIn(f"chmod 700 {directory}", str(raised.exception))
                os.chmod(directory, 0o700)
                SQLiteRuntimeStore(directory / "state.db")

    def test_unsafe_directory_is_refused_before_anything_is_created_in_it(self):
        directory = self.root / "shared"
        directory.mkdir()
        os.chmod(directory, 0o777)  # nosec B103 -- the insecure state the refusal must reject, in a private temp dir
        with self.assertRaises(RuntimeError):
            SQLiteRuntimeStore(directory / "state.db")
        self.assertEqual(list(directory.iterdir()), [])

    def test_symlinked_database_is_refused(self):
        target = self.root / "elsewhere.db"
        SQLiteRuntimeStore(target)  # a real, owner-only database
        link = self.root / "state.db"
        link.symlink_to(target)
        with self.assertRaises(RuntimeError) as raised:
            SQLiteRuntimeStore(link)
        self.assertIn("symbolic link", str(raised.exception))

    def test_dangling_symlink_at_the_database_path_is_not_followed(self):
        link = self.root / "state.db"
        link.symlink_to(self.root / "attacker-chosen.db")
        with self.assertRaises(RuntimeError) as raised:
            SQLiteRuntimeStore(link)
        self.assertIn("symbolic link", str(raised.exception))
        self.assertFalse((self.root / "attacker-chosen.db").exists())

    def test_symlinked_wal_or_shm_is_refused(self):
        for suffix in ("-wal", "-shm"):
            with self.subTest(suffix=suffix):
                path = self.root / f"link{suffix}.db"
                SQLiteRuntimeStore(path)
                # An EXISTING owner-only target, so a check that followed the link would pass it.
                target = self.root / f"target{suffix}"
                target.touch(mode=0o600)
                Path(f"{path}{suffix}").symlink_to(target)
                with self.assertRaises(RuntimeError) as raised:
                    SQLiteRuntimeStore(path)
                self.assertIn("symbolic link", str(raised.exception))

    def test_non_regular_side_file_is_refused(self):
        path = self.root / "fifo.db"
        SQLiteRuntimeStore(path)
        os.mkfifo(f"{path}-shm", 0o600)
        with self.assertRaises(RuntimeError) as raised:
            SQLiteRuntimeStore(path)
        self.assertIn("not a regular file", str(raised.exception))

    def test_store_file_owned_by_another_user_is_refused(self):
        path = self.root / "owned.db"
        SQLiteRuntimeStore(path)
        other_uid = os.geteuid() + 1  # a test process cannot chown, so ask as a different user
        with self.assertRaises(RuntimeError) as raised:
            _refuse_insecure_sqlite_file(path, other_uid)
        self.assertIn(f"owned by uid {os.geteuid()}", str(raised.exception))
        _refuse_insecure_sqlite_file(path, os.geteuid())  # the real owner passes

    def test_store_directory_owned_by_another_user_is_refused(self):
        directory = self.root / "theirs"
        directory.mkdir(mode=0o700)
        with patch("portmark.storage.os.geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(RuntimeError) as raised:
                SQLiteRuntimeStore(directory / "state.db")
        self.assertIn("not by the host user", str(raised.exception))
        self.assertEqual(list(directory.iterdir()), [])

    def test_symlinked_store_directory_is_allowed_and_its_target_is_checked(self):
        real = self.root / "volume"
        real.mkdir(mode=0o700)
        link = self.root / "state-dir"
        link.symlink_to(real, target_is_directory=True)
        SQLiteRuntimeStore(link / "state.db")
        os.chmod(real, 0o777)  # nosec B103 -- the insecure state the refusal must reject, in a private temp dir
        with self.assertRaises(RuntimeError):
            SQLiteRuntimeStore(link / "state.db")


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

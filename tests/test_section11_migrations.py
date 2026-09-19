"""Section 11 PR B: SQLite schema migrations are crash-atomic and restart-idempotent.

Finding #3: migrations ran through executescript(), which COMMITs first and then runs each statement
in autocommit. A crash after `ALTER TABLE checkpoints ADD COLUMN generation` but before `closed` and
the version bump left a database that every later start refused ("duplicate column name").

The authority for "the complete schema at version N" is tests/sqlite_schema_versions.json. It was
generated from the storage code on main BEFORE this rewrite (ea42a58), so these tests check the new
runner against the old schemas instead of against itself. A future migration appends its version.
"""

import json
import os
import shutil
import sqlite3
import stat
import subprocess  # nosec B404 -- runs this test's own interpreter on a fixed inline script
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import portmark.storage as storage
from portmark.storage import SQLITE_SCHEMA_VERSION, SQLiteRuntimeStore

SRC = str(Path(__file__).resolve().parent.parent / "src")
# One cold-starting host. The import happens BEFORE the wait, so every process is ready and they all
# reach the missing directories together (importing after the signal staggers them and hides the race).
COLD_START_SCRIPT = """
import os, sys, time
from portmark.storage import SQLiteRuntimeStore
gate, path, ready = sys.argv[1], sys.argv[2], sys.argv[3]
open(ready, "w").close()
while not os.path.exists(gate):
    pass
SQLiteRuntimeStore(path)
"""

REFERENCE = {int(version): schema for version, schema in json.loads((Path(__file__).parent / "sqlite_schema_versions.json").read_text()).items()}
CAN_FORK = hasattr(os, "fork")
CRASH_EXIT = 77

LEGACY_V1_DDL = (
    "CREATE TABLE consumed_nonces (nonce TEXT PRIMARY KEY, subject TEXT NOT NULL, audience TEXT NOT NULL, "
    "task_id TEXT NOT NULL, consumed_at INTEGER NOT NULL)",
    "CREATE TABLE checkpoints (task_id TEXT PRIMARY KEY, status TEXT NOT NULL, checkpoint_json TEXT NOT NULL, "
    "updated_at INTEGER NOT NULL)",
    "CREATE TABLE audit_events (task_id TEXT NOT NULL, sequence INTEGER NOT NULL, host_id TEXT NOT NULL, "
    "event TEXT NOT NULL, details_json TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL, "
    "created_at INTEGER NOT NULL, PRIMARY KEY (task_id, sequence), UNIQUE (task_id, hash))",
    "CREATE TABLE audit_heads (task_id TEXT PRIMARY KEY, head_hash TEXT NOT NULL, sequence INTEGER NOT NULL, "
    "updated_at INTEGER NOT NULL)",
)
SEED_ROWS = {
    "consumed_nonces": [("n-1", "subject", "audience", "t-1", 100)],
    "checkpoints": [("t-1", "suspended", '{"step": 1}', 101), ("t-2", "completed", '{"step": 9}', 102)],
    "audit_events": [
        ("t-1", 0, "host:a", "task.accepted", "{}", "genesis", "h0", 103),
        ("t-1", 1, "host:a", "task.suspended", '{"k": "v"}', "h0", "h1", 104),
    ],
    "audit_heads": [("t-1", "h1", 1, 105)],
}
SEED_COLUMNS = {
    "consumed_nonces": "nonce, subject, audience, task_id, consumed_at",
    "checkpoints": "task_id, status, checkpoint_json, updated_at",
    "audit_events": "task_id, sequence, host_id, event, details_json, previous_hash, hash, created_at",
    "audit_heads": "task_id, head_hash, sequence, updated_at",
}


def schema_signature(connection):
    """The same shape as tests/sqlite_schema_versions.json: columns and indexes of every table."""
    result = {"user_version": connection.execute("PRAGMA user_version").fetchone()[0], "tables": {}}
    tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    for table in tables:
        columns = [list(row[1:]) for row in connection.execute(f'PRAGMA table_info("{table}")')]
        indexes = []
        for index in connection.execute(f'PRAGMA index_list("{table}")'):
            index_columns = [row[2] for row in connection.execute(f'PRAGMA index_info("{index[1]}")')]
            indexes.append([index[2], index[3], index_columns])
        result["tables"][table] = {"columns": columns, "indexes": sorted(indexes)}
    return result


def raw(path):
    return sqlite3.connect(path, isolation_level=None)


def seeded_rows(connection):
    return {table: sorted(connection.execute(f"SELECT {columns} FROM {table}").fetchall()) for table, columns in SEED_COLUMNS.items()}  # nosec B608 -- table and column names are this module's constants


def expected_rows():
    return {table: sorted(rows) for table, rows in SEED_ROWS.items()}


def build_legacy_v0(path):
    """A pre-versioning database (user_version 0) with the v1 tables and seeded rows."""
    connection = raw(path)
    try:
        for statement in LEGACY_V1_DDL:
            connection.execute(statement)
        for table, rows in SEED_ROWS.items():
            marks = ", ".join("?" * len(rows[0]))
            connection.executemany(f"INSERT INTO {table} ({SEED_COLUMNS[table]}) VALUES ({marks})", rows)  # nosec B608 -- table and column names are this module's constants
    finally:
        connection.close()
    os.chmod(path, 0o600)


def build_at_version(path, version):
    """A seeded legacy database, then migrated by the store itself exactly to `version`."""
    build_legacy_v0(path)
    original = storage.SQLITE_SCHEMA_VERSION
    storage.SQLITE_SCHEMA_VERSION = version
    try:
        SQLiteRuntimeStore(path)
    finally:
        storage.SQLITE_SCHEMA_VERSION = original


def copy_database(source, target):
    shutil.copyfile(source, target)
    os.chmod(target, 0o600)


class _CrashAtStatement(sqlite3.Connection):
    """Dies (os._exit, no cleanup, no rollback) when the Nth statement is about to run."""

    crash_at = 0
    count = 0

    def execute(self, sql, *args):
        type(self).count += 1
        if type(self).count == type(self).crash_at:
            os._exit(CRASH_EXIT)
        return super().execute(sql, *args)


def open_in_child_crashing_at(path, statement):
    """Fork; in the child, open the store with a crash before statement N. Returns the exit code."""
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child never returns
        try:
            _CrashAtStatement.crash_at = statement
            _CrashAtStatement.count = 0
            real_connect = sqlite3.connect

            def connect(*args, **kwargs):
                kwargs["factory"] = _CrashAtStatement
                return real_connect(*args, **kwargs)

            storage.sqlite3.connect = connect
            SQLiteRuntimeStore(path)
            os._exit(0)
        except BaseException:
            os._exit(1)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


class MigrationSchemaTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)

    def tearDown(self):
        self._dir.cleanup()

    def assert_complete_schema(self, path, version):
        connection = raw(path)
        try:
            self.assertEqual(schema_signature(connection), REFERENCE[version])
            self.assertEqual(seeded_rows(connection), expected_rows())
        finally:
            connection.close()

    def test_every_version_matches_the_pre_rewrite_reference(self):
        for version in range(1, SQLITE_SCHEMA_VERSION + 1):
            with self.subTest(version=version):
                path = self.root / f"v{version}.db"
                build_at_version(path, version)
                self.assert_complete_schema(path, version)
        self.assertEqual(sorted(REFERENCE), list(range(1, SQLITE_SCHEMA_VERSION + 1)))

    def test_legacy_v0_upgrades_to_current_with_data_and_closed_flag(self):
        path = self.root / "legacy.db"
        build_legacy_v0(path)
        SQLiteRuntimeStore(path)
        self.assert_complete_schema(path, SQLITE_SCHEMA_VERSION)
        connection = raw(path)
        try:
            closed = dict(connection.execute("SELECT task_id, closed FROM checkpoints").fetchall())
        finally:
            connection.close()
        self.assertEqual(closed, {"t-1": 0, "t-2": 1})

    def test_newer_schema_is_refused_without_changes(self):
        path = self.root / "future.db"
        build_at_version(path, SQLITE_SCHEMA_VERSION)
        connection = raw(path)
        connection.execute(f"PRAGMA user_version = {SQLITE_SCHEMA_VERSION + 1}")
        connection.close()
        with self.assertRaises(RuntimeError) as raised:
            SQLiteRuntimeStore(path)
        self.assertIn("newer than supported", str(raised.exception))

    # -- the half-applied states the OLD autocommit runner could leave behind ----------------------
    def test_auditor_repro_generation_added_but_not_closed_or_version(self):
        path = self.root / "stranded-v4.db"
        build_at_version(path, 3)
        connection = raw(path)
        connection.execute("ALTER TABLE checkpoints ADD COLUMN generation INTEGER NOT NULL DEFAULT 0")
        connection.close()
        SQLiteRuntimeStore(path)  # was: OperationalError duplicate column name: generation
        self.assert_complete_schema(path, SQLITE_SCHEMA_VERSION)

    def test_stranded_audit_events_rebuild_copy_is_discarded_and_redone(self):
        # Stopped after CREATE + INSERT of audit_events_v2, before DROP: the original is intact.
        path = self.root / "stranded-v2a.db"
        build_at_version(path, 1)
        connection = raw(path)
        connection.execute("CREATE TABLE audit_events_v2 AS SELECT * FROM audit_events WHERE sequence = 0")
        connection.close()
        SQLiteRuntimeStore(path)
        self.assert_complete_schema(path, SQLITE_SCHEMA_VERSION)

    def test_stranded_audit_events_rebuild_after_drop_is_finished_by_rename(self):
        # Stopped after DROP TABLE audit_events, before the RENAME: the copy holds every row.
        path = self.root / "stranded-v2b.db"
        build_at_version(path, 1)
        connection = raw(path)
        connection.execute(
            "CREATE TABLE audit_events_v2 (task_id TEXT NOT NULL, sequence INTEGER NOT NULL, host_id TEXT NOT NULL, "
            "event TEXT NOT NULL, details_json TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL, "
            "created_at INTEGER NOT NULL, PRIMARY KEY (task_id, sequence), UNIQUE (task_id, hash))"
        )
        connection.execute("INSERT INTO audit_events_v2 SELECT * FROM audit_events")
        connection.execute("DROP TABLE audit_events")
        connection.close()
        SQLiteRuntimeStore(path)
        self.assert_complete_schema(path, SQLITE_SCHEMA_VERSION)

    def test_stranded_partial_column_sets_continue(self):
        stranded = {
            2: ["ALTER TABLE audit_heads ADD COLUMN host_id TEXT NOT NULL DEFAULT ''"],
            6: [
                "CREATE TABLE migration_receipts (task_id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL, created_at INTEGER NOT NULL)"
            ],
            7: ["ALTER TABLE migration_outbox ADD COLUMN claimed_by TEXT", "ALTER TABLE migration_outbox ADD COLUMN lease_expires_at INTEGER"],
            10: ["ALTER TABLE tool_effects ADD COLUMN reconcile_claim_id TEXT"],
        }
        for version, statements in stranded.items():
            with self.subTest(version=version):
                path = self.root / f"stranded-from-{version}.db"
                build_at_version(path, version)
                connection = raw(path)
                for statement in statements:
                    connection.execute(statement)
                connection.close()
                SQLiteRuntimeStore(path)
                self.assert_complete_schema(path, SQLITE_SCHEMA_VERSION)

    def test_concurrent_opens_of_one_old_database_all_succeed(self):
        # Every opener re-reads the version inside BEGIN IMMEDIATE, so they queue on the write lock
        # instead of racing through the same step.
        path = self.root / "shared.db"
        build_at_version(path, 1)
        errors = []
        barrier = threading.Barrier(6)

        def open_store():
            try:
                barrier.wait()
                SQLiteRuntimeStore(path)
            except BaseException as error:  # collected and asserted below
                errors.append(repr(error))

        threads = [threading.Thread(target=open_store) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assert_complete_schema(path, SQLITE_SCHEMA_VERSION)


@unittest.skipUnless(CAN_FORK, "needs os.fork to kill a real process mid-migration")
class MigrationCrashInjectionTests(unittest.TestCase):
    """Kill the process before EVERY statement of the upgrade, reopen, and require a whole version.

    os._exit is a real crash for SQLite: no rollback, no close, uncommitted WAL frames abandoned.
    (It does not model power loss; SQLite's own fsync durability covers that.)
    """

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)

    def tearDown(self):
        self._dir.cleanup()

    def crash_everywhere(self, fixture, start_version):
        seen_versions = set()
        statement = 0
        while True:
            statement += 1
            with self.subTest(crash_before_statement=statement):
                path = self.root / f"crash-{start_version}-{statement}.db"
                copy_database(fixture, path)
                exit_code = open_in_child_crashing_at(path, statement)
                self.assertIn(exit_code, (CRASH_EXIT, 0))
                connection = raw(path)
                try:
                    signature = schema_signature(connection)
                    version = signature["user_version"]
                    # The complete OLD schema or a complete NEWER one -- never a mix.
                    if version == 0:
                        self.assertEqual(start_version, 0)
                        self.assertEqual(sorted(signature["tables"]), sorted(REFERENCE[1]["tables"]))
                    else:
                        self.assertGreaterEqual(version, max(start_version, 1))
                        self.assertEqual(signature, REFERENCE[version])
                    self.assertEqual(seeded_rows(connection), expected_rows())
                finally:
                    connection.close()
                seen_versions.add(version)
                SQLiteRuntimeStore(path)  # the next start always continues to the current version
                connection = raw(path)
                try:
                    self.assertEqual(schema_signature(connection), REFERENCE[SQLITE_SCHEMA_VERSION])
                    self.assertEqual(seeded_rows(connection), expected_rows())
                finally:
                    connection.close()
            if exit_code == 0:  # the child ran past the last statement: every crash point is covered
                break
        return statement, seen_versions

    def test_crash_before_every_statement_from_a_legacy_database(self):
        fixture = self.root / "fixture-v0.db"
        build_legacy_v0(fixture)
        statements, seen = self.crash_everywhere(fixture, 0)
        # Every intermediate version was observed as a crash outcome, so every step was exercised.
        self.assertEqual(seen, set(range(0, SQLITE_SCHEMA_VERSION + 1)))
        self.assertGreater(statements, 2 * SQLITE_SCHEMA_VERSION)

    def test_crash_before_every_statement_from_version_3(self):
        # The auditor's starting point: v3 -> v4 adds generation, then closed.
        fixture = self.root / "fixture-v3.db"
        build_at_version(fixture, 3)
        _, seen = self.crash_everywhere(fixture, 3)
        self.assertEqual(seen, set(range(3, SQLITE_SCHEMA_VERSION + 1)))


class _Rows:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class ColdStartDirectoryRaceTests(unittest.TestCase):
    """Auditor round 2 on #86: hosts cold-starting together on a store whose directories do not exist
    yet all try to create the same components; the losers failed with FileExistsError."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)

    def tearDown(self):
        self._dir.cleanup()

    def test_many_processes_cold_start_one_new_nested_store(self):
        path = self.root / "new" / "nested" / "deeper" / "state.db"
        gate = self.root / "go"
        env = {**os.environ, "PYTHONPATH": SRC, "PYTHONDONTWRITEBYTECODE": "1"}
        ready_dir = self.root / "ready"
        ready_dir.mkdir()
        hosts = [
            subprocess.Popen(  # nosec B603 -- this interpreter, fixed inline script
                [sys.executable, "-c", COLD_START_SCRIPT, str(gate), str(path), str(ready_dir / str(index))],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
            )
            for index in range(32)
        ]
        deadline = time.monotonic() + 120
        while len(list(ready_dir.iterdir())) < len(hosts):  # every host imported and is spinning
            self.assertLess(time.monotonic(), deadline, "cold-start hosts never became ready")
            time.sleep(0.01)
        gate.touch()
        failures = []
        for host in hosts:
            _, stderr = host.communicate(timeout=180)
            if host.returncode != 0:
                failures.append(stderr.strip().splitlines()[-1] if stderr.strip() else f"exit {host.returncode}")
        self.assertEqual(failures, [])
        connection = sqlite3.connect(path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], SQLITE_SCHEMA_VERSION)
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        finally:
            connection.close()
        if os.name != "nt":
            for directory in (self.root / "new", self.root / "new" / "nested", path.parent):
                self.assertEqual(stat.S_IMODE(os.stat(directory).st_mode), 0o700, directory)

    # The same cold start exposed a second race: switching a NEW database to WAL needs an exclusive
    # lock, and SQLite may answer SQLITE_BUSY at once (no busy handler) to avoid a deadlock. The
    # 32-process test above hits it only sometimes, so the retry is pinned deterministically here.
    class _FakeWalConnection:
        def __init__(self, mode, failures):
            self.mode, self.failures, self.switches = mode, list(failures), 0

        def execute(self, sql):
            if sql == "PRAGMA journal_mode":
                return _Rows((self.mode,))
            self.switches += 1
            if self.failures:
                raise self.failures.pop(0)
            self.mode = "wal"
            return _Rows(("wal",))

    @staticmethod
    def sqlite_error(code, message):
        error = sqlite3.OperationalError(message)
        error.sqlite_errorcode = code
        return error

    def test_wal_switch_retries_sqlite_busy_until_it_succeeds(self):
        busy = self.sqlite_error(sqlite3.SQLITE_BUSY, "database is locked")
        connection = self._FakeWalConnection("delete", [busy, busy, busy])
        storage._enable_wal(connection)
        self.assertEqual((connection.switches, connection.mode), (4, "wal"))

    def test_wal_switch_fails_at_once_on_any_other_error(self):
        other = self.sqlite_error(sqlite3.SQLITE_IOERR, "disk I/O error")
        connection = self._FakeWalConnection("delete", [other])
        with self.assertRaises(sqlite3.OperationalError):
            storage._enable_wal(connection)
        self.assertEqual(connection.switches, 1)

    def test_wal_switch_gives_up_at_the_busy_timeout(self):
        busy = self.sqlite_error(sqlite3.SQLITE_BUSY, "database is locked")
        connection = self._FakeWalConnection("delete", [busy] * 200)
        with patch("portmark.storage.SQLITE_BUSY_TIMEOUT_MS", 50), self.assertRaises(sqlite3.OperationalError):
            storage._enable_wal(connection)
        self.assertLess(connection.switches, 200)

    def test_wal_switch_is_skipped_when_the_database_is_already_wal(self):
        connection = self._FakeWalConnection("wal", [])
        storage._enable_wal(connection)
        self.assertEqual(connection.switches, 0)

    # Deterministic forms of the same race: "another process" creates the component just before this
    # one's mkdir. A benign winner is accepted; anything hostile it could have raced in is refused.
    def race_mkdir(self, plant):
        real_mkdir = os.mkdir

        def racing_mkdir(target, mode=0o777, *args, **kwargs):
            if not os.path.lexists(target):
                plant(Path(target), real_mkdir)
            return real_mkdir(target, mode, *args, **kwargs)

        return patch("portmark.storage.os.mkdir", racing_mkdir)

    @unittest.skipIf(os.name == "nt", "POSIX directory chain")
    def test_losing_the_mkdir_race_to_a_benign_winner_is_not_an_error(self):
        path = self.root / "a" / "b" / "state.db"
        with self.race_mkdir(lambda target, mkdir: mkdir(target, 0o700)):
            SQLiteRuntimeStore(path)
        self.assertTrue(path.exists())

    @unittest.skipIf(os.name == "nt", "POSIX directory chain")
    def test_a_symlink_raced_in_as_the_store_directory_is_refused(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir(mode=0o700)
        path = self.root / "a" / "store" / "state.db"

        def plant(target, mkdir):
            if target.name == "store":
                target.symlink_to(elsewhere, target_is_directory=True)
            else:
                mkdir(target, 0o700)

        with self.race_mkdir(plant), self.assertRaises(RuntimeError) as raised:
            SQLiteRuntimeStore(path)
        self.assertIn("symbolic link", str(raised.exception))
        self.assertEqual(list(elsewhere.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "POSIX directory chain")
    def test_a_world_writable_directory_raced_in_is_refused(self):
        path = self.root / "a" / "store" / "state.db"

        def plant(target, mkdir):
            mkdir(target, 0o700)
            if target.name == "a":
                os.chmod(target, 0o777)  # nosec B103 -- the insecure state the refusal must reject, in a private temp dir

        with self.race_mkdir(plant), self.assertRaises(RuntimeError) as raised:
            SQLiteRuntimeStore(path)
        self.assertIn("is writable by group or other users", str(raised.exception))
        self.assertFalse(path.exists())

    @unittest.skipIf(os.name == "nt", "POSIX directory chain")
    def test_a_file_raced_in_as_the_store_directory_is_refused(self):
        path = self.root / "a" / "store" / "state.db"

        def plant(target, mkdir):
            if target.name == "store":
                target.write_text("not a directory")
            else:
                mkdir(target, 0o700)

        with self.race_mkdir(plant), self.assertRaises(RuntimeError) as raised:
            SQLiteRuntimeStore(path)
        self.assertIn("is not a directory", str(raised.exception))


if __name__ == "__main__":
    unittest.main()

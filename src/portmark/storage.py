from __future__ import annotations

import json
import hashlib
import sqlite3
import threading
import time
from contextlib import AbstractContextManager
from dataclasses import asdict
from pathlib import Path
from types import TracebackType
from typing import Any, Callable, Protocol

from .models import AgentState
from .security import AuditHeadVerifier, SecurityError, audit_head_payload, canonical_json


SQLITE_SCHEMA_VERSION = 3
SQLITE_BUSY_TIMEOUT_MS = 30_000
AuditHeadSigner = Callable[[str, int], tuple[str, str]]


class RuntimeTransaction(Protocol):
    def consume_nonce(self, nonce: str, subject: str, audience: str, task_id: str) -> None:
        ...

    def append_audit_events(self, task_id: str, host_id: str, events: tuple[dict[str, Any], ...], sign_head: AuditHeadSigner | None = None) -> None:
        ...

    def save_checkpoint(self, task_id: str, state: AgentState) -> None:
        ...


class RuntimeStore(Protocol):
    def transaction(self) -> AbstractContextManager[RuntimeTransaction]:
        ...

    def consumed_nonce_exists(self, nonce: str) -> bool:
        ...

    def load_checkpoint(self, task_id: str) -> dict[str, Any] | None:
        ...

    def audit_head(self, task_id: str) -> tuple[str, int] | None:
        ...

    def verify_audit_chain(self, task_id: str) -> bool:
        ...


class InMemoryRuntimeStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._nonces: dict[str, dict[str, Any]] = {}
        self._checkpoints: dict[str, dict[str, Any]] = {}
        self._audit_events: dict[str, list[dict[str, Any]]] = {}
        self._audit_heads: dict[str, dict[str, Any]] = {}
        self._audit_head_verifier: AuditHeadVerifier | None = None

    def set_audit_head_verifier(self, verifier: AuditHeadVerifier) -> None:
        self._audit_head_verifier = verifier

    def transaction(self) -> AbstractContextManager[RuntimeTransaction]:
        return _InMemoryTransaction(self)

    def consumed_nonce_exists(self, nonce: str) -> bool:
        with self._lock:
            return nonce in self._nonces

    def load_checkpoint(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            checkpoint = self._checkpoints.get(task_id)
            return json.loads(json.dumps(checkpoint)) if checkpoint is not None else None

    def audit_head(self, task_id: str) -> tuple[str, int] | None:
        with self._lock:
            events = self._audit_events.get(task_id)
            head = self._audit_heads.get(task_id)
            if not events or head is None:
                return None
            return head["head_hash"], head["sequence"]

    def verify_audit_chain(self, task_id: str) -> bool:
        with self._lock:
            events = self._audit_events.get(task_id, [])
            head = self._audit_heads.get(task_id)
            if not events or head is None:
                return False
            previous = events[0]["previous"]
            for expected_sequence, event in enumerate(events):
                if event["sequence"] != expected_sequence or event["previous"] != previous:
                    return False
                record = {
                    "sequence": event["sequence"],
                    "event": event["event"],
                    "details": event["details"],
                    "previous": event["previous"],
                }
                if event["hash"] != _audit_hash(record):
                    return False
                previous = event["hash"]
            if head["head_hash"] != previous or head["sequence"] != len(events):
                return False
            return _verify_head_signature(self._audit_head_verifier, task_id, head)


class _InMemoryTransaction:
    def __init__(self, store: InMemoryRuntimeStore) -> None:
        self._store = store
        self._snapshots: tuple[dict[str, Any], dict[str, Any], dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]]] | None = None

    def __enter__(self) -> "_InMemoryTransaction":
        self._store._lock.acquire()
        self._snapshots = (
            dict(self._store._nonces),
            json.loads(json.dumps(self._store._checkpoints)),
            json.loads(json.dumps(self._store._audit_events)),
            json.loads(json.dumps(self._store._audit_heads)),
        )
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        if exc_type is not None and self._snapshots is not None:
            self._store._nonces, self._store._checkpoints, self._store._audit_events, self._store._audit_heads = self._snapshots
        self._store._lock.release()

    def consume_nonce(self, nonce: str, subject: str, audience: str, task_id: str) -> None:
        if nonce in self._store._nonces:
            raise SecurityError("permit nonce has already been consumed")
        self._store._nonces[nonce] = {
            "subject": subject,
            "audience": audience,
            "task_id": task_id,
            "consumed_at": int(time.time()),
        }

    def append_audit_events(self, task_id: str, host_id: str, events: tuple[dict[str, Any], ...], sign_head: AuditHeadSigner | None = None) -> None:
        current = self._store._audit_events.setdefault(task_id, [])
        hashes = {event["hash"] for event in current}
        for event in events:
            if event["sequence"] != len(current):
                raise SecurityError("audit event sequence is not contiguous")
            expected_previous = current[-1]["hash"] if current else event["previous"]
            if event["previous"] != expected_previous:
                raise SecurityError("audit event previous hash does not match stored head")
            if event["hash"] in hashes:
                raise SecurityError("audit event hash already exists")
            current.append(json.loads(json.dumps({**event, "host_id": host_id})))
            hashes.add(event["hash"])
            sequence = event["sequence"] + 1
            signature_key_id, signature = sign_head(event["hash"], sequence) if sign_head is not None else ("", "")
            self._store._audit_heads[task_id] = {
                "head_hash": event["hash"],
                "sequence": sequence,
                "host_id": host_id,
                "signature_key_id": signature_key_id,
                "signature": signature,
            }

    def save_checkpoint(self, task_id: str, state: AgentState) -> None:
        self._store._checkpoints[task_id] = asdict(state)


class SQLiteRuntimeStore:
    def __init__(self, path: str | Path, audit_head_verifier: AuditHeadVerifier | None = None) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._audit_head_verifier = audit_head_verifier
        self._initialize()

    def set_audit_head_verifier(self, verifier: AuditHeadVerifier) -> None:
        self._audit_head_verifier = verifier

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _initialize(self) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > SQLITE_SCHEMA_VERSION:
                raise RuntimeError(f"SQLite store schema version {version} is newer than supported version {SQLITE_SCHEMA_VERSION}")
            if version == 0:
                self._migrate_to_v1(connection)
                version = 1
            while version < SQLITE_SCHEMA_VERSION:
                version = self._run_migration(connection, version)

    def _run_migration(self, connection: sqlite3.Connection, version: int) -> int:
        migrations = {
            0: self._migrate_to_v1,
            1: self._migrate_to_v2,
            2: self._migrate_to_v3,
        }
        migration = migrations.get(version)
        if migration is None:
            raise RuntimeError(f"SQLite store has no migration from schema version {version}")
        migration(connection)
        return int(connection.execute("PRAGMA user_version").fetchone()[0])

    def _migrate_to_v1(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS consumed_nonces (
                nonce TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                audience TEXT NOT NULL,
                task_id TEXT NOT NULL,
                consumed_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS checkpoints (
                task_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                checkpoint_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                task_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                host_id TEXT NOT NULL,
                event TEXT NOT NULL,
                details_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (task_id, sequence),
                UNIQUE (task_id, hash)
            );
            CREATE TABLE IF NOT EXISTS audit_heads (
                task_id TEXT PRIMARY KEY,
                head_hash TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            PRAGMA user_version = 1;
            """
        )

    def _migrate_to_v2(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE audit_events_v2 (
                task_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                host_id TEXT NOT NULL,
                event TEXT NOT NULL,
                details_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (task_id, sequence),
                UNIQUE (task_id, hash)
            );
            INSERT INTO audit_events_v2
                (task_id, sequence, host_id, event, details_json, previous_hash, hash, created_at)
            SELECT task_id, sequence, host_id, event, details_json, previous_hash, hash, created_at
            FROM audit_events;
            DROP TABLE audit_events;
            ALTER TABLE audit_events_v2 RENAME TO audit_events;
            PRAGMA user_version = 2;
            """
        )

    def _migrate_to_v3(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            ALTER TABLE audit_heads ADD COLUMN host_id TEXT NOT NULL DEFAULT '';
            ALTER TABLE audit_heads ADD COLUMN signature_key_id TEXT NOT NULL DEFAULT '';
            ALTER TABLE audit_heads ADD COLUMN signature TEXT NOT NULL DEFAULT '';
            PRAGMA user_version = 3;
            """
        )

    def transaction(self) -> AbstractContextManager[RuntimeTransaction]:
        return _SQLiteTransaction(self)

    def consumed_nonce_exists(self, nonce: str) -> bool:
        with self._connect() as connection:
            row = connection.execute("SELECT 1 FROM consumed_nonces WHERE nonce = ?", (nonce,)).fetchone()
            return row is not None

    def load_checkpoint(self, task_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT checkpoint_json FROM checkpoints WHERE task_id = ?", (task_id,)).fetchone()
            return json.loads(row["checkpoint_json"]) if row is not None else None

    def audit_head(self, task_id: str) -> tuple[str, int] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT head_hash, sequence FROM audit_heads WHERE task_id = ?", (task_id,)).fetchone()
            return (row["head_hash"], int(row["sequence"])) if row is not None else None

    def verify_audit_chain(self, task_id: str) -> bool:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT sequence, event, details_json, previous_hash, hash FROM audit_events WHERE task_id = ? ORDER BY sequence",
                (task_id,),
            ).fetchall()
            head = connection.execute(
                "SELECT head_hash, sequence, host_id, signature_key_id, signature FROM audit_heads WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        if not rows or head is None:
            return False
        previous = rows[0]["previous_hash"] if rows else ""
        for expected_sequence, row in enumerate(rows):
            if row["sequence"] != expected_sequence or row["previous_hash"] != previous:
                return False
            record = {
                "sequence": row["sequence"],
                "event": row["event"],
                "details": json.loads(row["details_json"]),
                "previous": row["previous_hash"],
            }
            if row["hash"] != _audit_hash(record):
                return False
            previous = row["hash"]
        if head["head_hash"] != previous or int(head["sequence"]) != len(rows):
            return False
        return _verify_head_signature(
            self._audit_head_verifier,
            task_id,
            {
                "head_hash": head["head_hash"],
                "sequence": int(head["sequence"]),
                "host_id": head["host_id"],
                "signature_key_id": head["signature_key_id"],
                "signature": head["signature"],
            },
        )


class _SQLiteTransaction:
    def __init__(self, store: SQLiteRuntimeStore) -> None:
        self._store = store
        self._connection: sqlite3.Connection | None = None

    def __enter__(self) -> "_SQLiteTransaction":
        self._store._lock.acquire()
        self._connection = self._store._connect()
        self._connection.execute("BEGIN IMMEDIATE")
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        if self._connection is None:
            raise RuntimeError("SQLite transaction was not opened")
        try:
            if exc_type is None:
                self._connection.execute("COMMIT")
            else:
                self._connection.execute("ROLLBACK")
        finally:
            self._connection.close()
            self._store._lock.release()

    def consume_nonce(self, nonce: str, subject: str, audience: str, task_id: str) -> None:
        if self._connection is None:
            raise RuntimeError("SQLite transaction was not opened")
        try:
            self._connection.execute(
                "INSERT INTO consumed_nonces (nonce, subject, audience, task_id, consumed_at) VALUES (?, ?, ?, ?, ?)",
                (nonce, subject, audience, task_id, int(time.time())),
            )
        except sqlite3.IntegrityError as error:
            raise SecurityError("permit nonce has already been consumed") from error

    def append_audit_events(self, task_id: str, host_id: str, events: tuple[dict[str, Any], ...], sign_head: AuditHeadSigner | None = None) -> None:
        if self._connection is None:
            raise RuntimeError("SQLite transaction was not opened")
        for event in events:
            head = self._connection.execute(
                "SELECT head_hash, sequence FROM audit_heads WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            expected_sequence = int(head["sequence"]) if head is not None else 0
            expected_previous = head["head_hash"] if head is not None else event["previous"]
            if event["sequence"] != expected_sequence:
                raise SecurityError("audit event sequence is not contiguous")
            if event["previous"] != expected_previous:
                raise SecurityError("audit event previous hash does not match stored head")
            try:
                self._connection.execute(
                    """
                    INSERT INTO audit_events
                        (task_id, sequence, host_id, event, details_json, previous_hash, hash, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        task_id,
                        event["sequence"],
                        host_id,
                        event["event"],
                        json.dumps(event["details"], sort_keys=True, separators=(",", ":")),
                        event["previous"],
                        event["hash"],
                        int(time.time()),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise SecurityError("audit event already exists") from error
            sequence = event["sequence"] + 1
            signature_key_id, signature = sign_head(event["hash"], sequence) if sign_head is not None else ("", "")
            self._connection.execute(
                """
                INSERT INTO audit_heads (task_id, head_hash, sequence, host_id, signature_key_id, signature, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    head_hash = excluded.head_hash,
                    sequence = excluded.sequence,
                    host_id = excluded.host_id,
                    signature_key_id = excluded.signature_key_id,
                    signature = excluded.signature,
                    updated_at = excluded.updated_at
                """,
                (task_id, event["hash"], sequence, host_id, signature_key_id, signature, int(time.time())),
            )

    def save_checkpoint(self, task_id: str, state: AgentState) -> None:
        if self._connection is None:
            raise RuntimeError("SQLite transaction was not opened")
        self._connection.execute(
            """
            INSERT INTO checkpoints (task_id, status, checkpoint_json, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(task_id) DO UPDATE SET
                status = excluded.status,
                checkpoint_json = excluded.checkpoint_json,
                updated_at = excluded.updated_at
            """,
            (task_id, state.status, json.dumps(asdict(state), sort_keys=True, separators=(",", ":")), int(time.time())),
        )


def _audit_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(record)).hexdigest()


def _verify_head_signature(verifier: AuditHeadVerifier | None, task_id: str, head: dict[str, Any]) -> bool:
    if verifier is None or not head.get("signature_key_id") or not head.get("signature") or not head.get("host_id"):
        return False
    try:
        verifier.verify_audit_head(
            head["signature_key_id"],
            audit_head_payload(task_id, head["host_id"], head["head_hash"], int(head["sequence"])),
            head["signature"],
        )
    except SecurityError:
        return False
    return True

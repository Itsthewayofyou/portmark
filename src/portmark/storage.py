from __future__ import annotations

import json
import hashlib
import sqlite3
import threading
import time
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Callable, Literal, Protocol

from .models import AgentState
from .security import AUDIT_HASH_VERSION, AuditHeadVerifier, SecurityError, audit_event_record, audit_head_payload, canonical_json


SQLITE_SCHEMA_VERSION = 3
POSTGRES_SCHEMA_VERSION = 1
SQLITE_BUSY_TIMEOUT_MS = 30_000
AuditHeadSigner = Callable[[str, int], tuple[str, str]]
AuditVerificationStatus = Literal["valid", "invalid", "unverifiable"]


@dataclass(frozen=True)
class AuditVerificationResult:
    status: AuditVerificationStatus
    reason: str

    @property
    def valid(self) -> bool:
        return self.status == "valid"


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

    def verify_audit_chain_status(self, task_id: str) -> AuditVerificationResult:
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

    def verify_audit_chain_status(self, task_id: str) -> AuditVerificationResult:
        with self._lock:
            events = self._audit_events.get(task_id, [])
            head = self._audit_heads.get(task_id)
            if not events or head is None:
                return AuditVerificationResult("invalid", "audit chain is missing")
            previous = events[0]["previous"]
            for expected_sequence, event in enumerate(events):
                if event["sequence"] != expected_sequence or event["previous"] != previous:
                    return AuditVerificationResult("invalid", "audit chain sequence or previous hash is inconsistent")
                if not _audit_event_hash_matches(
                    event["sequence"], event["event"], event["details"], event["previous"], event.get("host_id", ""), event["hash"]
                ):
                    return AuditVerificationResult("invalid", "audit event hash is invalid")
                previous = event["hash"]
            if head["head_hash"] != previous or head["sequence"] != len(events):
                return AuditVerificationResult("invalid", "stored audit head does not match audit events")
            return _verify_head_signature(self._audit_head_verifier, task_id, head)

    def verify_audit_chain(self, task_id: str) -> bool:
        return self.verify_audit_chain_status(task_id).valid


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

    def verify_audit_chain_status(self, task_id: str) -> AuditVerificationResult:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT sequence, event, details_json, previous_hash, hash, host_id FROM audit_events WHERE task_id = ? ORDER BY sequence",
                (task_id,),
            ).fetchall()
            head = connection.execute(
                "SELECT head_hash, sequence, host_id, signature_key_id, signature FROM audit_heads WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        if not rows or head is None:
            return AuditVerificationResult("invalid", "audit chain is missing")
        previous = rows[0]["previous_hash"] if rows else ""
        for expected_sequence, row in enumerate(rows):
            if row["sequence"] != expected_sequence or row["previous_hash"] != previous:
                return AuditVerificationResult("invalid", "audit chain sequence or previous hash is inconsistent")
            try:
                details = json.loads(row["details_json"])
            except json.JSONDecodeError:
                return AuditVerificationResult("invalid", "audit event details are malformed")
            if not _audit_event_hash_matches(
                row["sequence"], row["event"], details, row["previous_hash"], row["host_id"], row["hash"]
            ):
                return AuditVerificationResult("invalid", "audit event hash is invalid")
            previous = row["hash"]
        try:
            head_sequence = int(head["sequence"])
        except (TypeError, ValueError):
            return AuditVerificationResult("invalid", "signed audit head sequence is malformed")
        if head["head_hash"] != previous or head_sequence != len(rows):
            return AuditVerificationResult("invalid", "stored audit head does not match audit events")
        return _verify_head_signature(
            self._audit_head_verifier,
            task_id,
            {
                "head_hash": head["head_hash"],
                "sequence": head_sequence,
                "host_id": head["host_id"],
                "signature_key_id": head["signature_key_id"],
                "signature": head["signature"],
            },
        )

    def verify_audit_chain(self, task_id: str) -> bool:
        return self.verify_audit_chain_status(task_id).valid


class PostgresRuntimeStore:
    def __init__(self, dsn: str, audit_head_verifier: AuditHeadVerifier | None = None, schema: str = "public") -> None:
        if not dsn:
            raise ValueError("Postgres DSN must not be empty")
        if not schema or "\x00" in schema:
            raise ValueError("Postgres schema must not be empty")
        self.dsn = dsn
        self.schema = schema
        self._audit_head_verifier = audit_head_verifier
        self._ensure_schema()
        self._initialize()

    def set_audit_head_verifier(self, verifier: AuditHeadVerifier) -> None:
        self._audit_head_verifier = verifier

    @staticmethod
    def available() -> bool:
        try:
            import psycopg  # noqa: F401
        except ImportError:
            return False
        return True

    def _ensure_schema(self) -> None:
        psycopg, _, sql, _ = _postgres_modules()
        with psycopg.connect(self.dsn, autocommit=True) as connection:
            connection.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(self.schema)))

    def _connect(self):
        psycopg, rows, sql, _ = _postgres_modules()
        connection = psycopg.connect(self.dsn, row_factory=rows.dict_row)
        connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(self.schema)))
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS portmark_schema (
                    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
                    version INTEGER NOT NULL
                )
                """
            )
            row = connection.execute("SELECT version FROM portmark_schema WHERE singleton = TRUE").fetchone()
            if row is None:
                connection.execute("INSERT INTO portmark_schema (singleton, version) VALUES (TRUE, %s)", (POSTGRES_SCHEMA_VERSION,))
                version = POSTGRES_SCHEMA_VERSION
            else:
                version = int(row["version"])
            if version > POSTGRES_SCHEMA_VERSION:
                raise RuntimeError(
                    f"Postgres store schema version {version} is newer than supported version {POSTGRES_SCHEMA_VERSION}"
                )
            self._migrate_to_v1(connection)

    def _migrate_to_v1(self, connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS consumed_nonces (
                nonce TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                audience TEXT NOT NULL,
                task_id TEXT NOT NULL,
                consumed_at BIGINT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS checkpoints (
                task_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                checkpoint_json TEXT NOT NULL,
                updated_at BIGINT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                task_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                host_id TEXT NOT NULL,
                event TEXT NOT NULL,
                details_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                hash TEXT NOT NULL,
                created_at BIGINT NOT NULL,
                PRIMARY KEY (task_id, sequence),
                UNIQUE (task_id, hash)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_heads (
                task_id TEXT PRIMARY KEY,
                head_hash TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                host_id TEXT NOT NULL DEFAULT '',
                signature_key_id TEXT NOT NULL DEFAULT '',
                signature TEXT NOT NULL DEFAULT '',
                updated_at BIGINT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO portmark_schema (singleton, version)
            VALUES (TRUE, %s)
            ON CONFLICT (singleton) DO UPDATE SET version = EXCLUDED.version
            """,
            (POSTGRES_SCHEMA_VERSION,),
        )

    def transaction(self) -> AbstractContextManager[RuntimeTransaction]:
        return _PostgresTransaction(self)

    def consumed_nonce_exists(self, nonce: str) -> bool:
        with self._connect() as connection:
            row = connection.execute("SELECT 1 FROM consumed_nonces WHERE nonce = %s", (nonce,)).fetchone()
            return row is not None

    def load_checkpoint(self, task_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT checkpoint_json FROM checkpoints WHERE task_id = %s", (task_id,)).fetchone()
            return json.loads(row["checkpoint_json"]) if row is not None else None

    def audit_head(self, task_id: str) -> tuple[str, int] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT head_hash, sequence FROM audit_heads WHERE task_id = %s", (task_id,)).fetchone()
            return (row["head_hash"], int(row["sequence"])) if row is not None else None

    def verify_audit_chain_status(self, task_id: str) -> AuditVerificationResult:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT sequence, event, details_json, previous_hash, hash, host_id FROM audit_events WHERE task_id = %s ORDER BY sequence",
                (task_id,),
            ).fetchall()
            head = connection.execute(
                "SELECT head_hash, sequence, host_id, signature_key_id, signature FROM audit_heads WHERE task_id = %s",
                (task_id,),
            ).fetchone()
        if not rows or head is None:
            return AuditVerificationResult("invalid", "audit chain is missing")
        previous = rows[0]["previous_hash"] if rows else ""
        for expected_sequence, row in enumerate(rows):
            if row["sequence"] != expected_sequence or row["previous_hash"] != previous:
                return AuditVerificationResult("invalid", "audit chain sequence or previous hash is inconsistent")
            try:
                details = json.loads(row["details_json"])
            except json.JSONDecodeError:
                return AuditVerificationResult("invalid", "audit event details are malformed")
            if not _audit_event_hash_matches(
                row["sequence"], row["event"], details, row["previous_hash"], row["host_id"], row["hash"]
            ):
                return AuditVerificationResult("invalid", "audit event hash is invalid")
            previous = row["hash"]
        try:
            head_sequence = int(head["sequence"])
        except (TypeError, ValueError):
            return AuditVerificationResult("invalid", "signed audit head sequence is malformed")
        if head["head_hash"] != previous or head_sequence != len(rows):
            return AuditVerificationResult("invalid", "stored audit head does not match audit events")
        return _verify_head_signature(
            self._audit_head_verifier,
            task_id,
            {
                "head_hash": head["head_hash"],
                "sequence": head_sequence,
                "host_id": head["host_id"],
                "signature_key_id": head["signature_key_id"],
                "signature": head["signature"],
            },
        )

    def verify_audit_chain(self, task_id: str) -> bool:
        return self.verify_audit_chain_status(task_id).valid


class _PostgresTransaction:
    def __init__(self, store: PostgresRuntimeStore) -> None:
        self._store = store
        self._connection = None

    def __enter__(self) -> "_PostgresTransaction":
        self._connection = self._store._connect()
        self._connection.execute("BEGIN")
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        if self._connection is None:
            raise RuntimeError("Postgres transaction was not opened")
        try:
            if exc_type is None:
                self._connection.commit()
            else:
                self._connection.rollback()
        finally:
            self._connection.close()

    def consume_nonce(self, nonce: str, subject: str, audience: str, task_id: str) -> None:
        if self._connection is None:
            raise RuntimeError("Postgres transaction was not opened")
        _, _, _, errors = _postgres_modules()
        try:
            self._connection.execute(
                "INSERT INTO consumed_nonces (nonce, subject, audience, task_id, consumed_at) VALUES (%s, %s, %s, %s, %s)",
                (nonce, subject, audience, task_id, int(time.time())),
            )
        except errors.UniqueViolation as error:
            raise SecurityError("permit nonce has already been consumed") from error

    def append_audit_events(self, task_id: str, host_id: str, events: tuple[dict[str, Any], ...], sign_head: AuditHeadSigner | None = None) -> None:
        if self._connection is None:
            raise RuntimeError("Postgres transaction was not opened")
        _, _, _, errors = _postgres_modules()
        self._connection.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (task_id,))
        for event in events:
            head = self._connection.execute(
                "SELECT head_hash, sequence FROM audit_heads WHERE task_id = %s FOR UPDATE",
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
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
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
            except errors.UniqueViolation as error:
                raise SecurityError("audit event already exists") from error
            sequence = event["sequence"] + 1
            signature_key_id, signature = sign_head(event["hash"], sequence) if sign_head is not None else ("", "")
            self._connection.execute(
                """
                INSERT INTO audit_heads (task_id, head_hash, sequence, host_id, signature_key_id, signature, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(task_id) DO UPDATE SET
                    head_hash = EXCLUDED.head_hash,
                    sequence = EXCLUDED.sequence,
                    host_id = EXCLUDED.host_id,
                    signature_key_id = EXCLUDED.signature_key_id,
                    signature = EXCLUDED.signature,
                    updated_at = EXCLUDED.updated_at
                """,
                (task_id, event["hash"], sequence, host_id, signature_key_id, signature, int(time.time())),
            )

    def save_checkpoint(self, task_id: str, state: AgentState) -> None:
        if self._connection is None:
            raise RuntimeError("Postgres transaction was not opened")
        self._connection.execute(
            """
            INSERT INTO checkpoints (task_id, status, checkpoint_json, updated_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT(task_id) DO UPDATE SET
                status = EXCLUDED.status,
                checkpoint_json = EXCLUDED.checkpoint_json,
                updated_at = EXCLUDED.updated_at
            """,
            (task_id, state.status, json.dumps(asdict(state), sort_keys=True, separators=(",", ":")), int(time.time())),
        )


def create_runtime_store(
    backend: str,
    location: str | Path,
    audit_head_verifier: AuditHeadVerifier | None = None,
) -> RuntimeStore:
    if backend == "sqlite":
        return SQLiteRuntimeStore(location, audit_head_verifier)
    if backend == "postgres":
        return PostgresRuntimeStore(str(location), audit_head_verifier)
    raise ValueError("store backend must be 'sqlite' or 'postgres'")


def _postgres_modules():
    try:
        import psycopg
        from psycopg import errors, rows, sql
    except ImportError as exc:
        raise RuntimeError("Postgres storage requires installing portmark[postgres]") from exc
    return psycopg, rows, sql, errors


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


# Format versions this build can verify, newest first. A stored hash is valid if it
# matches the recompute for any of them; distinct versions produce distinct digests,
# so a v2 event (host_id covered) cannot be downgraded to a different recipe. A future
# format bump adds its version here without breaking chains written under an older one.
_SUPPORTED_AUDIT_HASH_VERSIONS = (AUDIT_HASH_VERSION,)


def _audit_event_hash_matches(
    sequence: int, event: str, details: Any, previous: str, host_id: str, stored_hash: str
) -> bool:
    for version in _SUPPORTED_AUDIT_HASH_VERSIONS:
        record = audit_event_record(sequence, event, details, previous, host_id, version)
        if _audit_hash(record) == stored_hash:
            return True
    return False


def _verify_head_signature(verifier: AuditHeadVerifier | None, task_id: str, head: dict[str, Any]) -> AuditVerificationResult:
    if verifier is None:
        return AuditVerificationResult("unverifiable", "trust registry is not configured")
    if not head.get("signature_key_id") or not head.get("signature") or not head.get("host_id"):
        return AuditVerificationResult("invalid", "signed audit head is missing")
    try:
        sequence = int(head["sequence"])
    except (TypeError, ValueError):
        return AuditVerificationResult("invalid", "signed audit head sequence is malformed")
    try:
        verifier.verify_audit_head(
            head["signature_key_id"],
            audit_head_payload(task_id, head["host_id"], head["head_hash"], sequence),
            head["signature"],
        )
    except SecurityError:
        return AuditVerificationResult("invalid", "audit head signature is invalid or untrusted")
    return AuditVerificationResult("valid", "audit chain and signed head verified")

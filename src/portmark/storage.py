from __future__ import annotations

import json
import hashlib
import sqlite3
import threading
import time
from collections.abc import Generator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Callable, Literal, Protocol

from .models import AgentState
from .security import AUDIT_HASH_VERSION, AuditHeadVerifier, SecurityError, _audit_head_payload_for, audit_event_record, canonical_json


SQLITE_SCHEMA_VERSION = 8
POSTGRES_SCHEMA_VERSION = 6

# Section 4 #3: a migration lease is bounded. Zero/negative would defeat exclusivity (two workers
# could claim the same row at the same instant); an unbounded lease would let a dead worker hold a
# row effectively forever. Callers that need longer must renew, not lease past this ceiling.
MAX_MIGRATION_LEASE_SECONDS = 7 * 24 * 60 * 60  # 7 days


def _validate_claim_args(worker_id: str, lease_seconds: int, limit: int) -> None:
    # Section 4 #3: exclusivity holds only for well-formed leases, so reject the inputs that would
    # silently break it rather than trusting every caller to pass sane values. bool is an int
    # subclass, so it is rejected explicitly.
    if not isinstance(worker_id, str) or not worker_id.strip():
        raise SecurityError("claim_migrations: worker_id must be a non-empty string")
    if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int):
        raise SecurityError("claim_migrations: lease_seconds must be an int")
    if lease_seconds <= 0:
        raise SecurityError("claim_migrations: lease_seconds must be positive")
    if lease_seconds > MAX_MIGRATION_LEASE_SECONDS:
        raise SecurityError(f"claim_migrations: lease_seconds exceeds the {MAX_MIGRATION_LEASE_SECONDS}s ceiling")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise SecurityError("claim_migrations: limit must be a positive int")


def _advisory_lock_key(name: str) -> int:
    # A stable 64-bit signed key for pg_advisory_lock(bigint), derived Python-side so
    # it does not depend on a server function (hashtextextended is PG 11+); blake2b is
    # deterministic across processes and versions. Range fits a Postgres bigint.
    digest = hashlib.blake2b(name.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big", signed=True)
SQLITE_BUSY_TIMEOUT_MS = 30_000
# Readiness (/readyz) must be quick to fail, not wait the full transactional budget
# (section 2, finding #1 follow-up): a dedicated short connect + busy/statement bound.
READINESS_CONNECT_TIMEOUT_SECONDS = 2
SQLITE_READINESS_BUSY_TIMEOUT_MS = 2_000
# sign_head(head_hash, sequence) -> (signature_key_id, signature, signed_at). signed_at is
# the epoch seconds embedded in the signed v2 payload (None => a v1 head, no signing time).
AuditHeadSigner = Callable[[str, int], tuple[str, str, "int | None"]]
AuditVerificationStatus = Literal["valid", "invalid", "unverifiable"]


@dataclass(frozen=True)
class AuditVerificationResult:
    # `status` stays the coarse three-way outcome that drives CLI exit codes; `head_status`
    # carries the precise historical verdict (finding #3 four-way: valid / valid-key-expired
    # / valid-key-revoked / signed-after-revocation, plus legacy/untrusted/etc.).
    status: AuditVerificationStatus
    reason: str
    head_status: str = ""

    @property
    def valid(self) -> bool:
        return self.status == "valid"


class RuntimeTransaction(Protocol):
    def consume_nonce(self, nonce: str, subject: str, audience: str, task_id: str) -> None:
        ...

    def append_audit_events(self, task_id: str, host_id: str, events: tuple[dict[str, Any], ...], sign_head: AuditHeadSigner | None = None) -> None:
        ...

    def save_checkpoint(self, task_id: str, state: AgentState, expected_generation: int, closed: bool = False) -> int:
        """Atomically admit and persist a checkpoint, returning its new generation.

        Compare-and-swap on the store-owned generation (finding EV-008). The store
        is the authority; `expected_generation` is the caller's assertion about
        which stored generation it is advancing, never the new value:

        - no stored checkpoint + `expected_generation == 0` -> create generation 1.
        - a stored checkpoint whose generation equals `expected_generation` and is
          not closed -> advance to `expected_generation + 1`.
        - anything else (stale generation, a closed checkpoint, or a fresh create
          over an existing task) -> raise `SecurityError`.

        `closed=True` marks the checkpoint terminal (completed, failed, or migrated
        away); a closed checkpoint can never be reopened by a later resume. The
        comparison and the advance happen in the same store transaction.
        """
        ...

    def enqueue_migration(self, task_id: str, destination: str, sealed_envelope_json: str) -> None:
        """Record a sealed destination envelope for durable delivery (section 1 #2).

        Written in the same transaction that closes the source checkpoint, so the
        migration cannot vanish if the process dies before the caller delivers it.
        Idempotent per task_id: a second enqueue for the same closed source is a
        no-op (the row already exists).
        """
        ...

    def store_migration_receipt(self, task_id: str, receipt_json: str) -> None:
        """Persist the destination's signed migration receipt (section 4 #2).

        Called INSIDE the destination's admission transaction, so a crash cannot leave a
        task admitted without a receipt to prove it. Idempotent per task_id: the first
        receipt stored wins, so a duplicate delivery returns the same proof rather than a
        new one.
        """
        ...


class RuntimeStore(Protocol):
    # Whether checkpoints/audit heads survive a process restart. A durable store must
    # refuse an ephemeral (per-restart) signing key (finding #1); the store declares
    # this rather than callers inferring it from a path or env var.
    is_durable: bool

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

    def list_pending_migrations(self) -> list[dict[str, Any]]:
        """All OUTSTANDING outbox rows (status='pending'), oldest first, INCLUDING rows another
        worker currently holds under a lease. This is a VISIBILITY query, NOT a delivery queue.

        Do NOT enumerate this list and ship its rows -- that is exactly the double-dispatch bug
        section 4 #3 exists to prevent, because two dispatchers would each see and ship the same
        row. A delivery dispatcher must instead `claim_migrations(worker_id, lease_seconds, limit)`,
        which hands each row to at most one worker under a lease; ship the claimed rows, call
        `record_migration_attempt(task_id, worker_id)` per try, `dead_letter_migration` the ones it
        gives up on, and settle delivery ONLY on a verified destination receipt (section 4 #2) via
        the source's `AgentHost.settle_migration` -> `mark_migration_delivered`. Each returned row
        carries `claimed_by`/`lease_expires_at` so a caller can see the claim state. Portmark ships
        the outbox mechanism, not a dispatcher: without one a migration stays durably pending.
        """
        ...

    def get_migration_receipt(self, task_id: str) -> dict[str, Any] | None:
        """The destination-issued receipt for an admitted migration, or None (section 4 #2).

        Read on the DESTINATION side so a duplicate delivery of an already-admitted
        migration returns the same receipt instead of a replay error.
        """
        ...

    def mark_migration_delivered(self, task_id: str, receipt_json: str) -> None:
        """Settle a source outbox row against a verified destination receipt (section 4 #2).

        `receipt_json` is the receipt the source has ALREADY verified (signature + all
        bindings) before calling this; the store persists it on the row and flips the
        row to delivered. Passing an unverified receipt defeats the settlement, so the
        verification belongs at the host layer (`AgentHost.settle_migration`), not here.
        """
        ...

    def record_migration_attempt(self, task_id: str, worker_id: str | None = None, *, _now: int | None = None) -> None:
        """Count a delivery attempt. If `worker_id` is given, only the CURRENT (live-lease) holder
        counts -- a worker whose lease has expired is no longer the logical holder and cannot inflate
        the count toward dead-letter; without a worker_id the count is unscoped (legacy). `_now` is a
        private test-only clock; production uses the wall clock. Section 4 part 3a."""
        ...

    def claim_migrations(
        self, worker_id: str, lease_seconds: int, limit: int = 1, *, _now: int | None = None
    ) -> list[dict[str, Any]]:
        """Atomically claim up to `limit` deliverable rows under a `lease_seconds` lease and return
        them (section 4 #3). A row is claimable if pending AND (unclaimed OR its lease has expired),
        so a worker that dies mid-delivery has its rows reclaimed once the lease lapses. Claiming is
        race-safe: two concurrent dispatchers never receive the same row. `worker_id`, `lease_seconds`
        (0 < n <= MAX_MIGRATION_LEASE_SECONDS) and `limit` are validated -- a zero/negative lease would
        defeat exclusivity. `_now` is a private test-only clock (keyword-only); production uses the
        wall clock so a caller cannot pass a `now` that bypasses another worker's live lease."""
        ...

    def release_migration(self, task_id: str, worker_id: str, *, _now: int | None = None) -> bool:
        """Release a claim so another worker can take the row. Holder-scoped AND lease-live (uniform
        with dead_letter): returns False unless this worker still holds the row under an UNEXPIRED
        lease. An expired holder's release is therefore a no-op -- which is safe, not stranding,
        because an expired lease already makes the row reclaimable via `claim_migrations`; the caller
        need not release it. Section 4 #3."""
        ...

    def dead_letter_migration(self, task_id: str, worker_id: str, reason: str, *, _now: int | None = None) -> bool:
        """Terminalize a pending row the current holder gave up on into a 'dead' state with a reason
        (section 4 #4). Holder-scoped AND lease-live like release: an EXPIRED holder cannot dead-letter
        (its authority lapsed with the lease). Returns False if not the live holder or not pending (not
        distinguished). A verified receipt can still settle a dead row (see
        `find_migration_for_settlement`)."""
        ...

    def list_dead_migrations(self) -> list[dict[str, Any]]:
        """Dead-lettered rows for operator inspection, oldest first (section 4 #4)."""
        ...

    def requeue_migration(self, task_id: str) -> bool:
        """Operator recovery: return a dead-lettered row to the pending queue, clearing its
        dead_reason and any claim (section 4 #4). NOT lease-scoped -- the operator decides. Returns
        False if the row is not dead."""
        ...

    def find_migration_for_settlement(self, task_id: str) -> dict[str, Any] | None:
        """The outbox row for `task_id` if it is still settleable -- pending OR dead, never
        delivered (section 4 #4). Used by the source's `settle_migration` so a verified destination
        receipt settles a row even after the dispatcher dead-lettered it, keeping #4 from regressing
        the section 4 #2 lost-ack fix."""
        ...

    def check_ready(self) -> None:
        """Lightweight, bounded liveness probe for /readyz (section 2, finding #4).

        A single cheap query plus a schema-version sanity check, with a short
        database timeout -- NOT schema construction or migration. Raises on an
        unreachable store or an unsupported (newer) schema version.
        """
        ...


class InMemoryRuntimeStore:
    is_durable = False

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._nonces: dict[str, dict[str, Any]] = {}
        self._checkpoints: dict[str, dict[str, Any]] = {}
        self._audit_events: dict[str, list[dict[str, Any]]] = {}
        self._audit_heads: dict[str, dict[str, Any]] = {}
        self._outbox: dict[str, dict[str, Any]] = {}
        self._migration_receipts: dict[str, str] = {}
        self._audit_head_verifier: AuditHeadVerifier | None = None

    def set_audit_head_verifier(self, verifier: AuditHeadVerifier) -> None:
        self._audit_head_verifier = verifier

    def transaction(self) -> AbstractContextManager[RuntimeTransaction]:
        return _InMemoryTransaction(self)

    def list_pending_migrations(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = [dict(row) for row in self._outbox.values() if row["status"] == "pending"]
        rows.sort(key=lambda row: (row["created_at"], row["task_id"]))
        return rows

    def get_migration_receipt(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            stored = self._migration_receipts.get(task_id)
        return None if stored is None else json.loads(stored)

    def mark_migration_delivered(self, task_id: str, receipt_json: str) -> None:
        with self._lock:
            row = self._outbox.get(task_id)
            if row is not None:
                row["status"] = "delivered"
                row["receipt_json"] = receipt_json

    def record_migration_attempt(self, task_id: str, worker_id: str | None = None, *, _now: int | None = None) -> None:
        moment = int(time.time()) if _now is None else int(_now)
        with self._lock:
            row = self._outbox.get(task_id)
            if row is None:
                return
            # When a worker id is given, only the current LIVE-lease holder may count an attempt, so
            # neither a different worker nor an expired holder can inflate the count toward dead-letter.
            if worker_id is not None and not self._is_live_holder(row, worker_id, moment):
                return
            row["attempt_count"] = int(row["attempt_count"]) + 1

    @staticmethod
    def _is_live_holder(row: dict[str, Any], worker_id: str, moment: int) -> bool:
        return row.get("claimed_by") == worker_id and int(row.get("lease_expires_at") or 0) > moment

    def claim_migrations(
        self, worker_id: str, lease_seconds: int, limit: int = 1, *, _now: int | None = None
    ) -> list[dict[str, Any]]:
        _validate_claim_args(worker_id, lease_seconds, limit)
        moment = int(time.time()) if _now is None else int(_now)
        with self._lock:
            candidates = [
                row
                for row in self._outbox.values()
                if row["status"] == "pending"
                and (row.get("claimed_by") is None or int(row.get("lease_expires_at") or 0) <= moment)
            ]
            candidates.sort(key=lambda row: (row["created_at"], row["task_id"]))
            claimed = []
            for row in candidates[:limit]:
                row["claimed_by"] = worker_id
                row["lease_expires_at"] = moment + int(lease_seconds)
                claimed.append(dict(row))
        return claimed

    def release_migration(self, task_id: str, worker_id: str, *, _now: int | None = None) -> bool:
        # Holder-scoped AND lease-live: returns False unless this worker still holds the row under an
        # unexpired lease, so neither a different worker nor an expired holder can clear a live claim.
        moment = int(time.time()) if _now is None else int(_now)
        with self._lock:
            row = self._outbox.get(task_id)
            if row is None or not self._is_live_holder(row, worker_id, moment):
                return False
            row["claimed_by"] = None
            row["lease_expires_at"] = None
            return True

    def dead_letter_migration(self, task_id: str, worker_id: str, reason: str, *, _now: int | None = None) -> bool:
        # Holder-scoped AND lease-live like release: an expired holder's authority lapsed with the lease.
        moment = int(time.time()) if _now is None else int(_now)
        with self._lock:
            row = self._outbox.get(task_id)
            if row is None or not self._is_live_holder(row, worker_id, moment):
                return False
            if row["status"] != "pending":
                return False
            row["status"] = "dead"
            row["dead_reason"] = reason
            row["claimed_by"] = None
            row["lease_expires_at"] = None
            return True

    def list_dead_migrations(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = [dict(row) for row in self._outbox.values() if row["status"] == "dead"]
        rows.sort(key=lambda row: (row["created_at"], row["task_id"]))
        return rows

    def requeue_migration(self, task_id: str) -> bool:
        # Operator recovery of a dead-lettered row (NOT lease-scoped -- the operator, not a worker,
        # decides to retry). dead_reason is cleared; the row returns to the pending queue.
        with self._lock:
            row = self._outbox.get(task_id)
            if row is None or row["status"] != "dead":
                return False
            row["status"] = "pending"
            row["dead_reason"] = None
            row["claimed_by"] = None
            row["lease_expires_at"] = None
            return True

    def find_migration_for_settlement(self, task_id: str) -> dict[str, Any] | None:
        # A verified destination receipt settles a row even after the dispatcher gave up on it, so
        # settlement looks up pending OR dead rows (not delivered -- re-settling a delivered row is
        # Part 2b). This keeps #4 from regressing the section 4 #2 lost-ack fix.
        with self._lock:
            row = self._outbox.get(task_id)
            if row is None or row["status"] not in ("pending", "dead"):
                return None
            return dict(row)

    def check_ready(self) -> None:
        # In-memory: no external dependency to probe, always ready.
        return None

    def consumed_nonce_exists(self, nonce: str) -> bool:
        with self._lock:
            return nonce in self._nonces

    def load_checkpoint(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._checkpoints.get(task_id)
            # Stored rows are {generation, closed, state}; callers see the state blob.
            return json.loads(json.dumps(row["state"])) if row is not None else None

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
        self._snapshots: tuple[dict[str, Any], dict[str, Any], dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, str]] | None = None

    def __enter__(self) -> "_InMemoryTransaction":
        self._store._lock.acquire()
        self._snapshots = (
            dict(self._store._nonces),
            json.loads(json.dumps(self._store._checkpoints)),
            json.loads(json.dumps(self._store._audit_events)),
            json.loads(json.dumps(self._store._audit_heads)),
            json.loads(json.dumps(self._store._outbox)),
            # Shallow copy is sufficient here (unlike the deep-copied dicts above): the values are
            # immutable JSON strings, never mutated in place -- store_migration_receipt only inserts.
            dict(self._store._migration_receipts),
        )
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        if exc_type is not None and self._snapshots is not None:
            (
                self._store._nonces,
                self._store._checkpoints,
                self._store._audit_events,
                self._store._audit_heads,
                self._store._outbox,
                self._store._migration_receipts,
            ) = self._snapshots
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
            signature_key_id, signature, signed_at = sign_head(event["hash"], sequence) if sign_head is not None else ("", "", None)
            self._store._audit_heads[task_id] = {
                "head_hash": event["hash"],
                "sequence": sequence,
                "host_id": host_id,
                "signature_key_id": signature_key_id,
                "signature": signature,
                "signed_at": signed_at,
            }

    def save_checkpoint(self, task_id: str, state: AgentState, expected_generation: int, closed: bool = False) -> int:
        row = self._store._checkpoints.get(task_id)
        if row is None:
            if expected_generation != 0:
                raise SecurityError("stale checkpoint generation")
            new_generation = 1
        else:
            if row["closed"]:
                raise SecurityError("task checkpoint is closed")
            if row["generation"] != expected_generation:
                raise SecurityError("stale checkpoint generation")
            new_generation = expected_generation + 1
        blob = asdict(state)
        blob["checkpoint_generation"] = new_generation
        self._store._checkpoints[task_id] = {
            "generation": new_generation,
            "closed": bool(closed),
            "state": blob,
        }
        return new_generation

    def enqueue_migration(self, task_id: str, destination: str, sealed_envelope_json: str) -> None:
        # Section 4 #8: keep-first is only safe when the collision is an exact re-enqueue of the
        # SAME sealed envelope (an idempotent retry). A same-task-id enqueue with a DIFFERENT
        # envelope is a real collision -- silently dropping it (the old ON CONFLICT DO NOTHING)
        # hides the anomaly, so raise and let the atomic source close roll back. Cross-source-host
        # task-id collisions stay possible until #7 namespaces the key; this only makes them loud.
        existing = self._store._outbox.get(task_id)
        if existing is not None:
            if existing["sealed_envelope_json"] == sealed_envelope_json and existing["destination"] == destination:
                return
            raise SecurityError(f"migration outbox already holds a different envelope for task {task_id!r}")
        self._store._outbox[task_id] = {
            "task_id": task_id,
            "destination": destination,
            "sealed_envelope_json": sealed_envelope_json,
            "status": "pending",
            "attempt_count": 0,
            "created_at": int(time.time()),
            "claimed_by": None,
            "lease_expires_at": None,
            "dead_reason": None,
        }

    def store_migration_receipt(self, task_id: str, receipt_json: str) -> None:
        # Keep-first: the first receipt issued for an admitted migration wins, so a
        # duplicate delivery returns the same proof.
        self._store._migration_receipts.setdefault(task_id, receipt_json)


class SQLiteRuntimeStore:
    is_durable = True

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

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        # sqlite3's own `with connection` commits/rolls back but never *closes* the
        # connection. On Windows an open connection holds the database file open, so
        # temp files cannot be deleted and long-running processes leak descriptors.
        # Wrap the transactional context and close in a finally.
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
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
            3: self._migrate_to_v4,
            4: self._migrate_to_v5,
            5: self._migrate_to_v6,
            6: self._migrate_to_v7,
            7: self._migrate_to_v8,
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

    def _migrate_to_v4(self, connection: sqlite3.Connection) -> None:
        # Finding EV-008: give every stored checkpoint a store-owned monotonic
        # generation and a terminal `closed` flag, so a resume is a compare-and-swap
        # on the durable row rather than trust in caller-supplied state.
        connection.executescript(
            """
            ALTER TABLE checkpoints ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE checkpoints ADD COLUMN closed INTEGER NOT NULL DEFAULT 0;
            UPDATE checkpoints SET closed = 1 WHERE status IN ('completed', 'failed');
            PRAGMA user_version = 4;
            """
        )

    def _migrate_to_v5(self, connection: sqlite3.Connection) -> None:
        # Section 1, finding #2: durable migration delivery. The sealed destination
        # envelope is written in the SAME transaction that closes the source
        # checkpoint, so a crash after the source closes cannot lose the migration;
        # a dispatcher recovers it from this outbox. Duplicate delivery is safe
        # (destination nonce/CAS reject a replay).
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS migration_outbox (
                task_id TEXT PRIMARY KEY,
                destination TEXT NOT NULL,
                sealed_envelope_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempt_count INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            PRAGMA user_version = 5;
            """
        )

    def _migrate_to_v6(self, connection: sqlite3.Connection) -> None:
        # Finding #3 (Option B): audit heads gain a nullable signed_at so verification can be
        # judged at signing time. NULL marks a legacy v1 head (no attested signing time).
        connection.executescript(
            """
            ALTER TABLE audit_heads ADD COLUMN signed_at INTEGER;
            PRAGMA user_version = 6;
            """
        )

    def _migrate_to_v7(self, connection: sqlite3.Connection) -> None:
        # Section 4 #2: signed destination receipts for migration delivery settlement.
        # migration_receipts holds the receipt this host ISSUED as a destination (so a
        # duplicate delivery returns the same one); migration_outbox.receipt_json holds the
        # receipt this host RECEIVED as a source and verified before settling the row.
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS migration_receipts (
                task_id TEXT PRIMARY KEY,
                receipt_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            ALTER TABLE migration_outbox ADD COLUMN receipt_json TEXT;
            PRAGMA user_version = 7;
            """
        )

    def _migrate_to_v8(self, connection: sqlite3.Connection) -> None:
        # Section 4 part 3a: outbox reliability. A dispatcher CLAIMS a row under a time-bounded
        # lease (claimed_by + lease_expires_at) so two dispatchers can't ship the same migration
        # (#3); a row it gives up on moves to a terminal 'dead' state with a dead_reason instead
        # of sitting pending forever (#4). All three columns are nullable -- an unclaimed, live,
        # non-dead row has them NULL, so existing pending rows upgrade untouched.
        connection.executescript(
            """
            ALTER TABLE migration_outbox ADD COLUMN claimed_by TEXT;
            ALTER TABLE migration_outbox ADD COLUMN lease_expires_at INTEGER;
            ALTER TABLE migration_outbox ADD COLUMN dead_reason TEXT;
            PRAGMA user_version = 8;
            """
        )

    def transaction(self) -> AbstractContextManager[RuntimeTransaction]:
        return _SQLiteTransaction(self)

    def list_pending_migrations(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT task_id, destination, sealed_envelope_json, status, attempt_count, created_at, claimed_by, lease_expires_at "
                "FROM migration_outbox WHERE status = 'pending' ORDER BY created_at, task_id"
            ).fetchall()
            return [dict(row) for row in rows]

    def get_migration_receipt(self, task_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT receipt_json FROM migration_receipts WHERE task_id = ?", (task_id,)
            ).fetchone()
        return None if row is None else json.loads(row["receipt_json"])

    def mark_migration_delivered(self, task_id: str, receipt_json: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "UPDATE migration_outbox SET status = 'delivered', receipt_json = ? WHERE task_id = ?",
                (receipt_json, task_id),
            )

    def record_migration_attempt(self, task_id: str, worker_id: str | None = None, *, _now: int | None = None) -> None:
        moment = int(time.time()) if _now is None else int(_now)
        with self._connection() as connection:
            if worker_id is None:
                connection.execute("UPDATE migration_outbox SET attempt_count = attempt_count + 1 WHERE task_id = ?", (task_id,))
            else:
                # Only the current LIVE-lease holder may count an attempt: an expired holder is no
                # longer the logical owner and must not push a row toward dead-letter.
                connection.execute(
                    "UPDATE migration_outbox SET attempt_count = attempt_count + 1 "
                    "WHERE task_id = ? AND claimed_by = ? AND lease_expires_at > ?",
                    (task_id, worker_id, moment),
                )

    def claim_migrations(
        self, worker_id: str, lease_seconds: int, limit: int = 1, *, _now: int | None = None
    ) -> list[dict[str, Any]]:
        # Section 4 #3. Race-safety comes from BEGIN IMMEDIATE, which takes SQLite's single write
        # lock up front, so two concurrent claimers serialize (the second blocks until the first
        # commits) rather than both selecting and one silently losing its UPDATE. `_connect` opens
        # in autocommit (isolation_level=None), so the transaction is managed explicitly here.
        _validate_claim_args(worker_id, lease_seconds, limit)
        moment = int(time.time()) if _now is None else int(_now)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                rows = connection.execute(
                    "SELECT task_id, destination, sealed_envelope_json, status, attempt_count, created_at, "
                    "claimed_by, lease_expires_at, dead_reason "
                    "FROM migration_outbox "
                    "WHERE status = 'pending' AND (claimed_by IS NULL OR lease_expires_at <= ?) "
                    "ORDER BY created_at, task_id LIMIT ?",
                    (moment, limit),
                ).fetchall()
                expiry = moment + int(lease_seconds)
                claimed = []
                for row in rows:
                    connection.execute(
                        "UPDATE migration_outbox SET claimed_by = ?, lease_expires_at = ? WHERE task_id = ?",
                        (worker_id, expiry, row["task_id"]),
                    )
                    record = dict(row)
                    record["claimed_by"] = worker_id
                    record["lease_expires_at"] = expiry
                    claimed.append(record)
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        return claimed

    def release_migration(self, task_id: str, worker_id: str, *, _now: int | None = None) -> bool:
        # Holder-scoped AND lease-live: neither a different worker nor an EXPIRED holder can clear a
        # live claim (an expired holder's authority lapsed with the lease).
        moment = int(time.time()) if _now is None else int(_now)
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE migration_outbox SET claimed_by = NULL, lease_expires_at = NULL "
                "WHERE task_id = ? AND claimed_by = ? AND lease_expires_at > ?",
                (task_id, worker_id, moment),
            )
            return cursor.rowcount > 0

    def dead_letter_migration(self, task_id: str, worker_id: str, reason: str, *, _now: int | None = None) -> bool:
        # Holder-scoped AND lease-live terminalization of a pending row the worker gave up on (#4).
        moment = int(time.time()) if _now is None else int(_now)
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE migration_outbox SET status = 'dead', dead_reason = ?, claimed_by = NULL, "
                "lease_expires_at = NULL WHERE task_id = ? AND claimed_by = ? AND status = 'pending' "
                "AND lease_expires_at > ?",
                (reason, task_id, worker_id, moment),
            )
            return cursor.rowcount > 0

    def list_dead_migrations(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT task_id, destination, sealed_envelope_json, status, attempt_count, created_at, dead_reason "
                "FROM migration_outbox WHERE status = 'dead' ORDER BY created_at, task_id"
            ).fetchall()
            return [dict(row) for row in rows]

    def requeue_migration(self, task_id: str) -> bool:
        # Operator recovery of a dead row (NOT lease-scoped) -- clears dead_reason, returns to queue.
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE migration_outbox SET status = 'pending', dead_reason = NULL, claimed_by = NULL, "
                "lease_expires_at = NULL WHERE task_id = ? AND status = 'dead'",
                (task_id,),
            )
            return cursor.rowcount > 0

    def find_migration_for_settlement(self, task_id: str) -> dict[str, Any] | None:
        # Pending OR dead (not delivered): a verified receipt settles a row even after the
        # dispatcher dead-lettered it, so #4 does not regress the section 4 #2 lost-ack fix.
        with self._connection() as connection:
            row = connection.execute(
                "SELECT task_id, destination, sealed_envelope_json, status, attempt_count, created_at, dead_reason "
                "FROM migration_outbox WHERE task_id = ? AND status IN ('pending', 'dead')",
                (task_id,),
            ).fetchone()
        return None if row is None else dict(row)

    def check_ready(self) -> None:
        # Bounded liveness only (section 2, findings #4 + follow-ups). Two hardenings
        # beyond a cheap query: (1) open the EXISTING file read-write via a mode=rw
        # URI, so a deleted/absent database fails readiness closed instead of being
        # silently recreated empty and reported ready; (2) require the EXACT current
        # schema version -- an empty (version 0), older, or incomplete schema is NOT
        # ready. The version is set only after each migration step completes, so it is
        # the authoritative "migrated" marker. Short busy timeout, not the 30s budget.
        db_uri = Path(self.path).resolve().as_uri() + "?mode=rw"
        connection = sqlite3.connect(db_uri, uri=True, timeout=READINESS_CONNECT_TIMEOUT_SECONDS, isolation_level=None)
        try:
            connection.execute(f"PRAGMA busy_timeout = {SQLITE_READINESS_BUSY_TIMEOUT_MS}")
            connection.execute("SELECT 1").fetchone()
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        finally:
            connection.close()
        if version != SQLITE_SCHEMA_VERSION:
            raise RuntimeError(f"SQLite store schema version {version} is not the supported version {SQLITE_SCHEMA_VERSION}")

    def consumed_nonce_exists(self, nonce: str) -> bool:
        with self._connection() as connection:
            row = connection.execute("SELECT 1 FROM consumed_nonces WHERE nonce = ?", (nonce,)).fetchone()
            return row is not None

    def load_checkpoint(self, task_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute("SELECT checkpoint_json FROM checkpoints WHERE task_id = ?", (task_id,)).fetchone()
            return json.loads(row["checkpoint_json"]) if row is not None else None

    def audit_head(self, task_id: str) -> tuple[str, int] | None:
        with self._connection() as connection:
            row = connection.execute("SELECT head_hash, sequence FROM audit_heads WHERE task_id = ?", (task_id,)).fetchone()
            return (row["head_hash"], int(row["sequence"])) if row is not None else None

    def verify_audit_chain_status(self, task_id: str) -> AuditVerificationResult:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT sequence, event, details_json, previous_hash, hash, host_id FROM audit_events WHERE task_id = ? ORDER BY sequence",
                (task_id,),
            ).fetchall()
            head = connection.execute(
                "SELECT head_hash, sequence, host_id, signature_key_id, signature, signed_at FROM audit_heads WHERE task_id = ?",
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
                "signed_at": head["signed_at"],
            },
        )

    def verify_audit_chain(self, task_id: str) -> bool:
        return self.verify_audit_chain_status(task_id).valid


class PostgresRuntimeStore:
    is_durable = True

    def __init__(self, dsn: str, audit_head_verifier: AuditHeadVerifier | None = None, schema: str = "public") -> None:
        if not dsn:
            raise ValueError("Postgres DSN must not be empty")
        if not schema or "\x00" in schema:
            raise ValueError("Postgres schema must not be empty")
        self.dsn = dsn
        self.schema = schema
        self._audit_head_verifier = audit_head_verifier
        self._initialize_schema()

    def set_audit_head_verifier(self, verifier: AuditHeadVerifier) -> None:
        self._audit_head_verifier = verifier

    @staticmethod
    def available() -> bool:
        try:
            import psycopg  # noqa: F401
        except ImportError:
            return False
        return True

    def _initialize_schema(self) -> None:
        # Section 1, finding #1: concurrent cold init is not race-safe. CREATE SCHEMA
        # and CREATE TABLE IF NOT EXISTS are NOT atomic against concurrent DDL -- two
        # processes opening the same new schema race on the pg_namespace / pg_type
        # unique indexes, and one crashes with a UniqueViolation on portmark_schema's
        # rowtype. Serialize the whole DDL block behind a session-level advisory lock
        # derived from the schema name, on ONE connection, acquired BEFORE CREATE
        # SCHEMA (schema creation itself can race). The lock is released implicitly
        # when the connection closes -- we do NOT hand-roll pg_advisory_unlock: a
        # failed DDL leaves the connection in an aborted transaction where the unlock
        # would itself raise (InFailedSqlTransaction) and mask the real error.
        psycopg, rows, sql, _ = _postgres_modules()
        lock_key = _advisory_lock_key("portmark-schema:" + self.schema)
        with psycopg.connect(self.dsn, row_factory=rows.dict_row) as connection:
            connection.execute("SELECT pg_advisory_lock(%s)", (lock_key,))
            connection.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(self.schema)))
            connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(self.schema)))
            self._initialize(connection)
            connection.commit()

    def _connect(self):
        psycopg, rows, sql, _ = _postgres_modules()
        connection = psycopg.connect(self.dsn, row_factory=rows.dict_row)
        connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(self.schema)))
        return connection

    def _initialize(self, connection) -> None:
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
                generation BIGINT NOT NULL DEFAULT 0,
                closed BOOLEAN NOT NULL DEFAULT FALSE,
                updated_at BIGINT NOT NULL
            )
            """
        )
        # Finding EV-008 (schema v2): an existing deployment's checkpoints table
        # predates the generation/closed columns; CREATE TABLE IF NOT EXISTS will
        # not add them, so ALTER them in idempotently. No-op on a fresh table.
        connection.execute("ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS generation BIGINT NOT NULL DEFAULT 0")
        connection.execute("ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS closed BOOLEAN NOT NULL DEFAULT FALSE")
        # An already-terminal checkpoint from before this column existed must be
        # closed so a pre-EV-008 envelope (default generation 0) cannot re-run it.
        connection.execute("UPDATE checkpoints SET closed = TRUE WHERE closed = FALSE AND status IN ('completed', 'failed')")
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
        # Finding #3 (Option B), schema v4: nullable signed_at for verify-at-signing-time.
        # ADD COLUMN IF NOT EXISTS upgrades an existing (v3) store idempotently.
        connection.execute("ALTER TABLE audit_heads ADD COLUMN IF NOT EXISTS signed_at BIGINT")
        # Section 1, finding #2: durable migration delivery. The sealed destination
        # envelope is written here in the SAME transaction that closes the source
        # checkpoint, so a crash after the source closes cannot lose the migration --
        # a dispatcher recovers it from this outbox. Duplicate delivery is safe
        # (destination nonce/CAS reject a replay).
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS migration_outbox (
                task_id TEXT PRIMARY KEY,
                destination TEXT NOT NULL,
                sealed_envelope_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempt_count INTEGER NOT NULL DEFAULT 0,
                created_at BIGINT NOT NULL
            )
            """
        )
        # Section 4 #2, schema v5: signed destination receipts for delivery settlement.
        # migration_receipts holds receipts this host ISSUED as a destination (keep-first, so a
        # duplicate delivery returns the same one); migration_outbox.receipt_json holds the
        # receipt this host RECEIVED as a source and verified before settling the row. ADD COLUMN
        # IF NOT EXISTS upgrades a v4 store idempotently.
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS migration_receipts (
                task_id TEXT PRIMARY KEY,
                receipt_json TEXT NOT NULL,
                created_at BIGINT NOT NULL
            )
            """
        )
        connection.execute("ALTER TABLE migration_outbox ADD COLUMN IF NOT EXISTS receipt_json TEXT")
        # Section 4 part 3a (schema v6): claim/lease (#3) + dead-letter (#4). All nullable, so a v5
        # store upgrades idempotently and existing pending rows are unclaimed/live/non-dead.
        connection.execute("ALTER TABLE migration_outbox ADD COLUMN IF NOT EXISTS claimed_by TEXT")
        connection.execute("ALTER TABLE migration_outbox ADD COLUMN IF NOT EXISTS lease_expires_at BIGINT")
        connection.execute("ALTER TABLE migration_outbox ADD COLUMN IF NOT EXISTS dead_reason TEXT")
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

    def list_pending_migrations(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT task_id, destination, sealed_envelope_json, status, attempt_count, created_at, claimed_by, lease_expires_at "
                "FROM migration_outbox WHERE status = 'pending' ORDER BY created_at, task_id"
            ).fetchall()
            return [dict(row) for row in rows]

    def get_migration_receipt(self, task_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT receipt_json FROM migration_receipts WHERE task_id = %s", (task_id,)
            ).fetchone()
        return None if row is None else json.loads(row["receipt_json"])

    def mark_migration_delivered(self, task_id: str, receipt_json: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE migration_outbox SET status = 'delivered', receipt_json = %s WHERE task_id = %s",
                (receipt_json, task_id),
            )

    def record_migration_attempt(self, task_id: str, worker_id: str | None = None, *, _now: int | None = None) -> None:
        moment = int(time.time()) if _now is None else int(_now)
        with self._connect() as connection:
            if worker_id is None:
                connection.execute("UPDATE migration_outbox SET attempt_count = attempt_count + 1 WHERE task_id = %s", (task_id,))
            else:
                connection.execute(
                    "UPDATE migration_outbox SET attempt_count = attempt_count + 1 "
                    "WHERE task_id = %s AND claimed_by = %s AND lease_expires_at > %s",
                    (task_id, worker_id, moment),
                )

    def claim_migrations(
        self, worker_id: str, lease_seconds: int, limit: int = 1, *, _now: int | None = None
    ) -> list[dict[str, Any]]:
        # Section 4 #3. FOR UPDATE SKIP LOCKED is the standard Postgres queue claim: concurrent
        # claimers lock disjoint rows and skip each other's, so no row is handed to two workers and
        # claimers don't block. One statement claims and returns the rows atomically.
        _validate_claim_args(worker_id, lease_seconds, limit)
        moment = int(time.time()) if _now is None else int(_now)
        expiry = moment + int(lease_seconds)
        with self._connect() as connection:
            rows = connection.execute(
                """
                UPDATE migration_outbox SET claimed_by = %s, lease_expires_at = %s
                WHERE task_id IN (
                    SELECT task_id FROM migration_outbox
                    WHERE status = 'pending' AND (claimed_by IS NULL OR lease_expires_at <= %s)
                    ORDER BY created_at, task_id
                    FOR UPDATE SKIP LOCKED
                    LIMIT %s
                )
                RETURNING task_id, destination, sealed_envelope_json, status, attempt_count,
                          created_at, claimed_by, lease_expires_at, dead_reason
                """,
                (worker_id, expiry, moment, limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def release_migration(self, task_id: str, worker_id: str, *, _now: int | None = None) -> bool:
        moment = int(time.time()) if _now is None else int(_now)
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE migration_outbox SET claimed_by = NULL, lease_expires_at = NULL "
                "WHERE task_id = %s AND claimed_by = %s AND lease_expires_at > %s",
                (task_id, worker_id, moment),
            )
            return cursor.rowcount > 0

    def dead_letter_migration(self, task_id: str, worker_id: str, reason: str, *, _now: int | None = None) -> bool:
        moment = int(time.time()) if _now is None else int(_now)
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE migration_outbox SET status = 'dead', dead_reason = %s, claimed_by = NULL, "
                "lease_expires_at = NULL WHERE task_id = %s AND claimed_by = %s AND status = 'pending' "
                "AND lease_expires_at > %s",
                (reason, task_id, worker_id, moment),
            )
            return cursor.rowcount > 0

    def list_dead_migrations(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT task_id, destination, sealed_envelope_json, status, attempt_count, created_at, dead_reason "
                "FROM migration_outbox WHERE status = 'dead' ORDER BY created_at, task_id"
            ).fetchall()
            return [dict(row) for row in rows]

    def requeue_migration(self, task_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE migration_outbox SET status = 'pending', dead_reason = NULL, claimed_by = NULL, "
                "lease_expires_at = NULL WHERE task_id = %s AND status = 'dead'",
                (task_id,),
            )
            return cursor.rowcount > 0

    def find_migration_for_settlement(self, task_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT task_id, destination, sealed_envelope_json, status, attempt_count, created_at, dead_reason "
                "FROM migration_outbox WHERE task_id = %s AND status IN ('pending', 'dead')",
                (task_id,),
            ).fetchone()
        return None if row is None else dict(row)

    def check_ready(self) -> None:
        # Bounded liveness only (section 2, finding #4 + #1 follow-up). Two separate
        # bounds are needed: connect_timeout caps CONNECTION establishment (a
        # blackholed host, DNS stall, or dead route would otherwise hang for the OS
        # default, which statement_timeout cannot help because it only applies once
        # connected); SET LOCAL statement_timeout then caps the query (transaction-
        # scoped -- this dedicated connection is non-autocommit, so the implicit
        # transaction gives it effect; outside a transaction it is a silent no-op).
        # A cheap query plus a schema sanity check -- never schema construction.
        psycopg, rows, sql, _ = _postgres_modules()
        connection = psycopg.connect(
            self.dsn, row_factory=rows.dict_row, connect_timeout=READINESS_CONNECT_TIMEOUT_SECONDS
        )
        try:
            connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(self.schema)))
            connection.execute("SET LOCAL statement_timeout = '2000ms'")
            connection.execute("SELECT 1").fetchone()
            row = connection.execute("SELECT version FROM portmark_schema WHERE singleton = TRUE").fetchone()
            connection.commit()
        finally:
            connection.close()
        # Require the EXACT current version. A missing portmark_schema table makes the
        # SELECT raise (fails closed); an EMPTY table gives row=None -> version 0, which
        # is likewise rejected here rather than passing as "ready" (finding follow-up).
        version = int(row["version"]) if row is not None else 0
        if version != POSTGRES_SCHEMA_VERSION:
            raise RuntimeError(f"Postgres store schema version {version} is not the supported version {POSTGRES_SCHEMA_VERSION}")

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
                "SELECT head_hash, sequence, host_id, signature_key_id, signature, signed_at FROM audit_heads WHERE task_id = %s",
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
                "signed_at": head["signed_at"],
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
            signature_key_id, signature, signed_at = sign_head(event["hash"], sequence) if sign_head is not None else ("", "", None)
            self._connection.execute(
                """
                INSERT INTO audit_heads (task_id, head_hash, sequence, host_id, signature_key_id, signature, signed_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(task_id) DO UPDATE SET
                    head_hash = EXCLUDED.head_hash,
                    sequence = EXCLUDED.sequence,
                    host_id = EXCLUDED.host_id,
                    signature_key_id = EXCLUDED.signature_key_id,
                    signature = EXCLUDED.signature,
                    signed_at = EXCLUDED.signed_at,
                    updated_at = EXCLUDED.updated_at
                """,
                (task_id, event["hash"], sequence, host_id, signature_key_id, signature, signed_at, int(time.time())),
            )

    def save_checkpoint(self, task_id: str, state: AgentState, expected_generation: int, closed: bool = False) -> int:
        if self._connection is None:
            raise RuntimeError("Postgres transaction was not opened")
        row = self._connection.execute(
            "SELECT generation, closed FROM checkpoints WHERE task_id = %s", (task_id,)
        ).fetchone()
        if row is None:
            if expected_generation != 0:
                raise SecurityError("stale checkpoint generation")
            new_generation = 1
            result = self._connection.execute(
                """
                INSERT INTO checkpoints (task_id, status, checkpoint_json, generation, closed, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (task_id) DO NOTHING
                RETURNING generation
                """,
                (task_id, state.status, self._checkpoint_json(state, new_generation), new_generation, bool(closed), int(time.time())),
            ).fetchone()
            if result is None:
                raise SecurityError("stale checkpoint generation")
            return new_generation
        if row["closed"]:
            raise SecurityError("task checkpoint is closed")
        new_generation = expected_generation + 1
        result = self._connection.execute(
            """
            UPDATE checkpoints
            SET generation = %s, status = %s, checkpoint_json = %s, closed = %s, updated_at = %s
            WHERE task_id = %s AND generation = %s AND closed = FALSE
            RETURNING generation
            """,
            (new_generation, state.status, self._checkpoint_json(state, new_generation), bool(closed), int(time.time()), task_id, expected_generation),
        ).fetchone()
        if result is None:
            raise SecurityError("stale checkpoint generation")
        return new_generation

    def enqueue_migration(self, task_id: str, destination: str, sealed_envelope_json: str) -> None:
        if self._connection is None:
            raise RuntimeError("Postgres transaction was not opened")
        # Section 4 #8, made race-safe: ONE atomic conflict-validating statement, not a SELECT then a
        # separate INSERT (two concurrent first-enqueues could each SELECT no row, and the loser's
        # ON CONFLICT DO NOTHING would silently drop its different envelope). ON CONFLICT DO UPDATE
        # with a WHERE that matches only when the existing envelope EQUALS this one: a fresh insert or
        # an identical re-enqueue returns the row (keep-first); a DIFFERENT envelope fails the WHERE,
        # returns nothing, and raises -- rolling back the atomic source close. The second concurrent
        # writer blocks on the unique constraint until the first commits, then re-evaluates the WHERE
        # against the committed row, so the race is closed.
        returned = self._connection.execute(
            """
            INSERT INTO migration_outbox (task_id, destination, sealed_envelope_json, status, attempt_count, created_at)
            VALUES (%s, %s, %s, 'pending', 0, %s)
            ON CONFLICT (task_id) DO UPDATE SET destination = EXCLUDED.destination
                WHERE migration_outbox.sealed_envelope_json = EXCLUDED.sealed_envelope_json
                  AND migration_outbox.destination = EXCLUDED.destination
            RETURNING task_id
            """,
            (task_id, destination, sealed_envelope_json, int(time.time())),
        ).fetchone()
        if returned is None:
            raise SecurityError(f"migration outbox already holds a different envelope for task {task_id!r}")

    def store_migration_receipt(self, task_id: str, receipt_json: str) -> None:
        if self._connection is None:
            raise RuntimeError("Postgres transaction was not opened")
        # Keep-first: a duplicate delivery returns the same receipt (section 4 #2).
        self._connection.execute(
            """
            INSERT INTO migration_receipts (task_id, receipt_json, created_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (task_id) DO NOTHING
            """,
            (task_id, receipt_json, int(time.time())),
        )

    @staticmethod
    def _checkpoint_json(state: AgentState, generation: int) -> str:
        blob = asdict(state)
        blob["checkpoint_generation"] = generation
        return json.dumps(blob, sort_keys=True, separators=(",", ":"))


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
            signature_key_id, signature, signed_at = sign_head(event["hash"], sequence) if sign_head is not None else ("", "", None)
            self._connection.execute(
                """
                INSERT INTO audit_heads (task_id, head_hash, sequence, host_id, signature_key_id, signature, signed_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    head_hash = excluded.head_hash,
                    sequence = excluded.sequence,
                    host_id = excluded.host_id,
                    signature_key_id = excluded.signature_key_id,
                    signature = excluded.signature,
                    signed_at = excluded.signed_at,
                    updated_at = excluded.updated_at
                """,
                (task_id, event["hash"], sequence, host_id, signature_key_id, signature, signed_at, int(time.time())),
            )

    def save_checkpoint(self, task_id: str, state: AgentState, expected_generation: int, closed: bool = False) -> int:
        if self._connection is None:
            raise RuntimeError("SQLite transaction was not opened")
        row = self._connection.execute(
            "SELECT generation, closed FROM checkpoints WHERE task_id = ?", (task_id,)
        ).fetchone()
        if row is None:
            if expected_generation != 0:
                raise SecurityError("stale checkpoint generation")
            new_generation = 1
            cursor = self._connection.execute(
                """
                INSERT INTO checkpoints (task_id, status, checkpoint_json, generation, closed, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO NOTHING
                """,
                (task_id, state.status, self._checkpoint_json(state, new_generation), new_generation, 1 if closed else 0, int(time.time())),
            )
            if cursor.rowcount != 1:
                raise SecurityError("stale checkpoint generation")
            return new_generation
        if row["closed"]:
            raise SecurityError("task checkpoint is closed")
        new_generation = expected_generation + 1
        cursor = self._connection.execute(
            """
            UPDATE checkpoints
            SET generation = ?, status = ?, checkpoint_json = ?, closed = ?, updated_at = ?
            WHERE task_id = ? AND generation = ? AND closed = 0
            """,
            (new_generation, state.status, self._checkpoint_json(state, new_generation), 1 if closed else 0, int(time.time()), task_id, expected_generation),
        )
        if cursor.rowcount != 1:
            raise SecurityError("stale checkpoint generation")
        return new_generation

    def enqueue_migration(self, task_id: str, destination: str, sealed_envelope_json: str) -> None:
        if self._connection is None:
            raise RuntimeError("SQLite transaction was not opened")
        # Section 4 #8, made race-safe: ONE atomic conflict-validating statement (mirrors the Postgres
        # path), not a SELECT then a separate INSERT. ON CONFLICT DO UPDATE with a WHERE that matches
        # only an IDENTICAL envelope: a fresh insert or an identical re-enqueue changes one row
        # (keep-first); a DIFFERENT envelope fails the WHERE, changes nothing, and raises -- rolling
        # back the atomic source close. rowcount==0 is the reject signal (verified against SQLite's
        # ON CONFLICT DO UPDATE ... WHERE semantics); no RETURNING dependency on the SQLite version.
        cursor = self._connection.execute(
            """
            INSERT INTO migration_outbox (task_id, destination, sealed_envelope_json, status, attempt_count, created_at)
            VALUES (?, ?, ?, 'pending', 0, ?)
            ON CONFLICT(task_id) DO UPDATE SET destination = excluded.destination
                WHERE migration_outbox.sealed_envelope_json = excluded.sealed_envelope_json
                  AND migration_outbox.destination = excluded.destination
            """,
            (task_id, destination, sealed_envelope_json, int(time.time())),
        )
        if cursor.rowcount == 0:
            raise SecurityError(f"migration outbox already holds a different envelope for task {task_id!r}")

    def store_migration_receipt(self, task_id: str, receipt_json: str) -> None:
        if self._connection is None:
            raise RuntimeError("SQLite transaction was not opened")
        # Keep-first: a duplicate delivery returns the same receipt (section 4 #2).
        self._connection.execute(
            """
            INSERT INTO migration_receipts (task_id, receipt_json, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(task_id) DO NOTHING
            """,
            (task_id, receipt_json, int(time.time())),
        )

    @staticmethod
    def _checkpoint_json(state: AgentState, generation: int) -> str:
        blob = asdict(state)
        blob["checkpoint_generation"] = generation
        return json.dumps(blob, sort_keys=True, separators=(",", ":"))


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
        return AuditVerificationResult("unverifiable", "trust registry is not configured", head_status="unverifiable")
    if not head.get("signature_key_id") or not head.get("signature") or not head.get("host_id"):
        return AuditVerificationResult("invalid", "signed audit head is missing", head_status="incomplete")
    try:
        sequence = int(head["sequence"])
    except (TypeError, ValueError):
        return AuditVerificationResult("invalid", "signed audit head sequence is malformed", head_status="malformed")
    # Reconstruct the exact signed payload: a stored signed_at means a v2 head verified at
    # signing time (finding #3); NULL/absent means a legacy v1 head. evaluate_audit_head
    # returns a precise historical verdict; the coarse `status` (for CLI exit codes) is just
    # ok/not-ok, but the four-way outcome is preserved in `head_status`.
    signed_at = head.get("signed_at")
    payload = _audit_head_payload_for(task_id, head["host_id"], head["head_hash"], sequence, signed_at)
    try:
        evaluation = verifier.evaluate_audit_head(head["signature_key_id"], payload, head["signature"])
    except SecurityError as error:
        # A fail-closed TrustSource raises if its on-disk registry changed; report it rather
        # than crash the read path.
        return AuditVerificationResult("unverifiable", str(error), head_status="registry-unavailable")
    status: AuditVerificationStatus = "valid" if evaluation.ok else "invalid"
    return AuditVerificationResult(status, evaluation.detail, head_status=evaluation.head_status)

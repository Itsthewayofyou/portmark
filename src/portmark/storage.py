from __future__ import annotations

import json
import hashlib
import os
import shutil
import shlex
import sqlite3
import stat
import threading
import time
from collections.abc import Generator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from types import TracebackType
from typing import Any, Callable, Literal, Protocol

from .models import AgentState
from .security import (
    AUDIT_HASH_VERSION,
    AuditHeadVerifier,
    SecurityError,
    _audit_head_payload_for,
    audit_event_record,
    audit_head_payload,
    canonical_json,
)


SQLITE_SCHEMA_VERSION = 14
POSTGRES_SCHEMA_VERSION = 12

# Section 4 #3: a migration lease is bounded. Zero/negative would defeat exclusivity (two workers
# could claim the same row at the same instant); an unbounded lease would let a dead worker hold a
# row effectively forever. Callers that need longer must renew, not lease past this ceiling.
MAX_MIGRATION_LEASE_SECONDS = 7 * 24 * 60 * 60  # 7 days


_LEGACY_OWNER_REFUSAL = (
    "legacy checkpoint has no stored owner and cannot be resumed safely after upgrade. "
    "Submit it as a new task."
)


def _check_owner(stored: tuple[str | None, str | None], asserted: tuple[str, str] | None) -> None:
    """PM-001: the stored owner must be exactly the one the caller asserts.

    `(None, None)` means the row predates the owner column. It is not a wildcard: a caller that
    asserts an owner is refused, because the row's real owner cannot be reconstructed and letting
    the first caller claim it would preserve the takeover this check closes.
    """
    expected: tuple[str | None, str | None] = asserted if asserted is not None else (None, None)
    if stored == expected:
        return
    if stored == (None, None):
        raise SecurityError(_LEGACY_OWNER_REFUSAL)
    raise SecurityError("checkpoint belongs to a different owner")


def _wall_clock() -> int:
    return int(time.time())


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
    if limit > MAX_CLAIM_LIMIT:
        raise SecurityError(f"claim_migrations: limit exceeds the ceiling of {MAX_CLAIM_LIMIT} rows per claim")


# Section 12 #4: capacity. Administrative listings are paged (a stable cursor on task_id, a capped
# page), one claim takes at most MAX_CLAIM_LIMIT rows, and a prune deletes in bounded batches.
DEFAULT_ADMIN_PAGE_SIZE = 500
MAX_ADMIN_PAGE_SIZE = 1000
MAX_CLAIM_LIMIT = 100
MAX_PRUNE_BATCH = 1000
# Section 12 #6: the durable time floor advances at most once per this many seconds, so it is not
# written on every save (owner decision D3: 'avoid writing it on every clock read').
TIME_FLOOR_CADENCE_SECONDS = 60
# Owner decision D2: only these record classes may ever be pruned. Everything else -- audit events and
# heads, checkpoints, tool effects, cancellations, receipts, pending/dead migrations, and the
# maintenance log that records every prune -- is evidence and is never deleted by Portmark.
PRUNABLE_CLASSES = ("expired_nonces", "delivered_migrations")
# Timestamp columns that are wall-clock times of past events. The time floor of an upgraded database
# starts at the newest of them (never at zero), so a clock rolled back before the first start after an
# upgrade is still caught. Lease expiries are FUTURE times and are deliberately not listed.
_TIME_FLOOR_SEED_COLUMNS = (
    ("audit_events", "created_at"),
    ("audit_heads", "updated_at"),
    ("audit_heads", "signed_at"),
    ("audit_floor_markers", "updated_at"),
    ("checkpoints", "updated_at"),
    ("consumed_nonces", "consumed_at"),
    ("migration_outbox", "created_at"),
    ("migration_receipts", "created_at"),
    ("task_cancellations", "cancelled_at"),
    ("tool_effects", "created_at"),
    ("tool_effects", "updated_at"),
)
# Tables a capacity report counts (row counts are bounded labels: fixed table names only).
_CAPACITY_TABLES = (
    "audit_events", "audit_heads", "checkpoints", "consumed_nonces", "migration_outbox",
    "migration_receipts", "task_cancellations", "tool_effects", "maintenance_log",
)


def _validate_page(limit: Any, after: Any) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_ADMIN_PAGE_SIZE:
        raise ValueError(f"page limit must be an integer from 1 to {MAX_ADMIN_PAGE_SIZE}, got {limit!r}")
    if after is not None and not isinstance(after, str):
        raise ValueError("page cursor `after` must be a task id string or None")


def _validate_prune_args(nonce_cutoff: Any, migration_cutoff: Any, batch_size: Any) -> None:
    for name, value in (("nonce_cutoff", nonce_cutoff), ("migration_cutoff", migration_cutoff)):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive epoch-seconds integer, got {value!r}")
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not 1 <= batch_size <= MAX_PRUNE_BATCH:
        raise ValueError(f"batch_size must be an integer from 1 to {MAX_PRUNE_BATCH}, got {batch_size!r}")


def _empty_prune_report(nonce_cutoff: int, migration_cutoff: int, apply: bool) -> dict[str, Any]:
    return {
        "applied": apply,
        "nonce_cutoff": nonce_cutoff,
        "migration_cutoff": migration_cutoff,
        "expired_nonces": {"eligible": 0, "deleted": 0, "oldest": None, "newest": None},
        "delivered_migrations": {"eligible": 0, "deleted": 0, "oldest": None, "newest": None},
        "kept": {},
        "batches": 0,
    }


def _checked_expiry(expires_at: Any) -> int | None:
    if expires_at is None:
        return None
    if isinstance(expires_at, bool) or not isinstance(expires_at, int):
        raise ValueError(f"nonce expires_at must be epoch seconds or None, got {expires_at!r}")
    return expires_at


def _validate_floor_reset(floor_at: Any, reason: Any) -> None:
    if isinstance(floor_at, bool) or not isinstance(floor_at, int) or floor_at < 0:
        raise ValueError(f"time floor must be a non-negative epoch-seconds integer, got {floor_at!r}")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("a time-floor reset requires a non-empty reason")


def _maintenance_entry(entry_id: int, at: int, action: str, detail: dict[str, Any]) -> dict[str, Any]:
    return {"id": entry_id, "at": at, "action": action, "detail": detail}


def _prune_summary(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "nonce_cutoff": report["nonce_cutoff"],
        "migration_cutoff": report["migration_cutoff"],
        "deleted": {name: report[name]["deleted"] for name in PRUNABLE_CLASSES},
        "ranges": {name: [report[name]["oldest"], report[name]["newest"]] for name in PRUNABLE_CLASSES},
        "kept": report["kept"],
        "batches": report["batches"],
    }


# Section 12 #4: the two prunable classes as SQL. `{p}` is the backend's placeholder. The DELETE
# repeats the eligibility predicate, so a row that changed between the SELECT and the DELETE (for
# example re-delivered) is never removed on stale information.
_PRUNE_SQL = {
    "expired_nonces": {
        "table": "consumed_nonces",
        "key": "nonce",
        "stamp": "expires_at",
        "predicate": "expires_at IS NOT NULL AND expires_at < {p}",
    },
    "delivered_migrations": {
        "table": "migration_outbox",
        "key": "task_id",
        "stamp": "delivered_at",
        "predicate": "status = 'delivered' AND receipt_json IS NOT NULL AND delivered_at IS NOT NULL AND delivered_at < {p}",
    },
}
_PRUNE_KEPT_SQL = {
    "nonces_without_expiry": "SELECT COUNT(*) AS n FROM consumed_nonces WHERE expires_at IS NULL",
    "delivered_without_delivery_time": "SELECT COUNT(*) AS n FROM migration_outbox WHERE status = 'delivered' AND delivered_at IS NULL",
    "delivered_without_receipt": "SELECT COUNT(*) AS n FROM migration_outbox WHERE status = 'delivered' AND receipt_json IS NULL",
    "pending_migrations": "SELECT COUNT(*) AS n FROM migration_outbox WHERE status = 'pending'",
    "dead_migrations": "SELECT COUNT(*) AS n FROM migration_outbox WHERE status = 'dead'",
}


def _run_sql_prune(
    placeholder: str,
    read: Callable[[str, tuple[Any, ...]], list[dict[str, Any]]],
    batch_transaction: Callable[[Callable[[Callable[[str, tuple[Any, ...]], Any]], Any]], Any],
    nonce_cutoff: int,
    migration_cutoff: int,
    apply: bool,
    batch_size: int,
    now: Callable[[], int],
) -> dict[str, Any]:
    """Backend-neutral prune: `read(sql, params)` runs a read; `batch_transaction(work)` runs `work(execute)`
    in ONE write transaction, where `execute(sql, params)` returns the cursor."""
    _validate_prune_args(nonce_cutoff, migration_cutoff, batch_size)
    report = _empty_prune_report(nonce_cutoff, migration_cutoff, apply)
    cutoffs = {"expired_nonces": nonce_cutoff, "delivered_migrations": migration_cutoff}
    for name, sql in _PRUNE_SQL.items():
        predicate = sql["predicate"].format(p=placeholder)
        row = read(
            f"SELECT COUNT(*) AS n, MIN({sql['stamp']}) AS oldest, MAX({sql['stamp']}) AS newest "  # nosec B608 -- constant identifiers
            f"FROM {sql['table']} WHERE {predicate}",
            (cutoffs[name],),
        )[0]
        report[name]["eligible"] = int(row["n"])
        _merge_range(report[name], row["oldest"], row["newest"])
    report["kept"] = {name: int(read(query, ())[0]["n"]) for name, query in _PRUNE_KEPT_SQL.items()}
    if not apply:
        return report
    for name, sql in _PRUNE_SQL.items():
        predicate = sql["predicate"].format(p=placeholder)
        cursor_key = ""
        while True:
            def work(execute, name=name, sql=sql, predicate=predicate, cursor_key=cursor_key):
                rows = execute(
                    f"SELECT {sql['key']} AS k, {sql['stamp']} AS s FROM {sql['table']} "  # nosec B608 -- constant identifiers
                    f"WHERE {predicate} AND {sql['key']} > {placeholder} ORDER BY {sql['key']} LIMIT {placeholder}",
                    (cutoffs[name], cursor_key, batch_size),
                ).fetchall()
                if not rows:
                    return None
                keys = [row["k"] for row in rows]
                marks = ", ".join([placeholder] * len(keys))
                deleted = execute(
                    f"DELETE FROM {sql['table']} WHERE {sql['key']} IN ({marks}) AND {predicate}",  # nosec B608 -- constant identifiers
                    (*keys, cutoffs[name]),
                ).rowcount
                stamps = [int(row["s"]) for row in rows]
                execute(
                    f"INSERT INTO maintenance_log (at, action, detail_json) VALUES ({placeholder}, {placeholder}, {placeholder})",  # nosec B608 -- placeholders only
                    (now(), "prune-batch", json.dumps({"class": name, "deleted": deleted, "oldest": min(stamps), "newest": max(stamps), "cutoff": cutoffs[name]}, sort_keys=True)),
                )
                return keys[-1], deleted
            outcome = batch_transaction(work)
            if outcome is None:
                break
            cursor_key, deleted = outcome
            report[name]["deleted"] += deleted
            report["batches"] += 1
    batch_transaction(lambda execute: execute(
        f"INSERT INTO maintenance_log (at, action, detail_json) VALUES ({placeholder}, {placeholder}, {placeholder})",  # nosec B608 -- placeholders only
        (now(), "prune", json.dumps(_prune_summary(report), sort_keys=True)),
    ))
    return report


def _maintenance_rows(rows: list[Any]) -> list[dict[str, Any]]:
    return [_maintenance_entry(int(row["id"]), int(row["at"]), row["action"], json.loads(row["detail_json"])) for row in rows]


def _merge_range(entry: dict[str, Any], oldest: Any, newest: Any) -> None:
    if oldest is not None:
        entry["oldest"] = int(oldest) if entry["oldest"] is None else min(entry["oldest"], int(oldest))
    if newest is not None:
        entry["newest"] = int(newest) if entry["newest"] is None else max(entry["newest"], int(newest))


def _validate_reconcile_claim_args(claim_id: str, lease_seconds: int) -> None:
    # Section 7 PR 2 (round 4 hardening): a reconcile claim's exclusivity holds only for a well-formed
    # owner + lease, so the store validates its own inputs rather than trusting the caller. AgentHost
    # always passes a random claim_id + the fixed positive lease, but a zero/negative lease would make
    # the claim instantly reclaimable (defeating exclusivity) and an empty owner id would collide. bool
    # is an int subclass, so it is rejected explicitly.
    if not isinstance(claim_id, str) or not claim_id.strip():
        raise SecurityError("claim_effect_for_reconcile: claim_id must be a non-empty string")
    if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int):
        raise SecurityError("claim_effect_for_reconcile: lease_seconds must be an int")
    if lease_seconds <= 0:
        raise SecurityError("claim_effect_for_reconcile: lease_seconds must be positive")


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


# Section 12 #3: every PostgreSQL connection Portmark opens is time-bounded, whatever the operator's
# DSN says. Without these, a blackholed database or a blocked row/advisory lock holds an A2A worker
# (and graceful shutdown) indefinitely. A timeout raises, which fails the transaction and rolls it
# back exactly as any other database error does.
_POSTGRES_TIMEOUT_LIMITS = {
    # name: (default, maximum, unit, environment variable)
    "connect_seconds": (5, 300, "s", "PORTMARK_POSTGRES_CONNECT_TIMEOUT_SECONDS"),
    "statement_ms": (30_000, 3_600_000, "ms", "PORTMARK_POSTGRES_STATEMENT_TIMEOUT_MS"),
    "lock_ms": (10_000, 3_600_000, "ms", "PORTMARK_POSTGRES_LOCK_TIMEOUT_MS"),
    "idle_in_transaction_ms": (60_000, 3_600_000, "ms", "PORTMARK_POSTGRES_IDLE_IN_TRANSACTION_TIMEOUT_MS"),
}


@dataclass(frozen=True)
class PostgresTimeouts:
    """Bounds applied to every Portmark PostgreSQL connection (Section 12 #3).

    Every value must be a positive integer no larger than its maximum: zero would DISABLE the
    PostgreSQL timeout, so it is refused rather than accepted.
    """

    connect_seconds: int = _POSTGRES_TIMEOUT_LIMITS["connect_seconds"][0]
    statement_ms: int = _POSTGRES_TIMEOUT_LIMITS["statement_ms"][0]
    lock_ms: int = _POSTGRES_TIMEOUT_LIMITS["lock_ms"][0]
    idle_in_transaction_ms: int = _POSTGRES_TIMEOUT_LIMITS["idle_in_transaction_ms"][0]

    def __post_init__(self) -> None:
        for name, (_default, maximum, unit, _env) in _POSTGRES_TIMEOUT_LIMITS.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
                raise ValueError(f"Postgres timeout {name} must be an integer from 1 to {maximum} {unit}, got {value!r}")

    @classmethod
    def from_environment(cls, environ: Any = None) -> "PostgresTimeouts":
        environ = os.environ if environ is None else environ
        values = {}
        for name, (default, _maximum, _unit, env) in _POSTGRES_TIMEOUT_LIMITS.items():
            raw = environ.get(env)
            if raw is None or not raw.strip():
                values[name] = default
                continue
            try:
                values[name] = int(raw.strip())
            except ValueError as error:
                raise ValueError(f"{env} must be an integer, got {raw!r}") from error
        return cls(**values)

    def for_schema_migration(self) -> "PostgresTimeouts":
        # Schema setup may rewrite tables and waits for another process's migration behind the schema
        # advisory lock, so it gets longer (still finite) statement and lock bounds.
        return replace(self, statement_ms=max(self.statement_ms, 600_000), lock_ms=max(self.lock_ms, 300_000))


def _effective_connect_timeout(dsn: str, timeouts: PostgresTimeouts) -> int:
    """Portmark's connect bound, or the DSN's own connect_timeout when that one is SMALLER.

    A connect_timeout keyword argument replaces the DSN's value, so a DSN can never disable or widen
    the bound -- but an operator's tighter value is kept. libpq treats 0 (or a negative) as "wait
    forever", so such a DSN value is ignored.
    """
    from psycopg.conninfo import conninfo_to_dict

    raw = conninfo_to_dict(dsn).get("connect_timeout")
    try:
        from_dsn = int(str(raw)) if raw is not None else 0
    except ValueError:
        from_dsn = 0
    return min(timeouts.connect_seconds, from_dsn) if from_dsn > 0 else timeouts.connect_seconds


# Section 12 #3 (auditor, PR #97 round 1): the server-side bounds cannot help when the NETWORK goes
# silent after a query was sent -- the server may cancel the statement, but its reply never arrives.
# TCP keepalives detect a dead peer while the client waits for a reply (probe after 10 s idle, then
# every 5 s; 3 missed probes = dead, about 25 s), and tcp_user_timeout fails a send that stays
# unacknowledged for 30 s. A live server acknowledges probes at the TCP level, so a long but healthy
# statement is not affected. These are OS-level mechanisms, not an exact client deadline: libpq
# ignores tcp_user_timeout where the OS lacks TCP_USER_TIMEOUT (for example Windows).
_POSTGRES_TCP_FAILURE_DETECTION = {
    "keepalives": 1,
    "keepalives_idle": 10,
    "keepalives_interval": 5,
    "keepalives_count": 3,
    "tcp_user_timeout": 30_000,
}


def _bounded_postgres_connect(dsn: str, timeouts: PostgresTimeouts, **kwargs: Any):
    """psycopg.connect with Portmark's bounds enforced over anything the DSN sets (Section 12 #3).

    The session settings are applied with set_config(..., false) AFTER connecting and then COMMITTED:
    a session setting made inside a transaction that later rolls back would be undone. They are not
    passed as the `options` keyword, which would REPLACE the operator's own DSN options (for example
    a search_path). A later value in the session wins over the DSN's startup options.
    """
    psycopg, _rows, _sql, _ = _postgres_modules()
    connection = psycopg.connect(
        dsn, connect_timeout=_effective_connect_timeout(dsn, timeouts), **_POSTGRES_TCP_FAILURE_DETECTION, **kwargs
    )
    try:
        connection.execute(
            "SELECT set_config('statement_timeout', %s, false), set_config('lock_timeout', %s, false), "
            "set_config('idle_in_transaction_session_timeout', %s, false)",
            (f"{timeouts.statement_ms}ms", f"{timeouts.lock_ms}ms", f"{timeouts.idle_in_transaction_ms}ms"),
        )
        connection.commit()
    except BaseException:
        connection.close()
        raise
    return connection
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
    # Section 10 F2: verdict on a migration anchor in event 0 -- "none" (not a migration),
    # "verified", "legacy-anchor" (pre-Section-10 anchor without the source proof), or
    # "invalid"/"registry-unavailable". Empty when verification stopped before this check.
    anchor_status: str = ""
    # Section 10 PR B: verdict of the audit floor (verify-audit --audit-floor-path): "anchored",
    # "not-anchored", "no-floor", or a refusal code (rolled-back, forked, floor-missing, ...).
    floor_status: str = ""

    @property
    def valid(self) -> bool:
        return self.status == "valid"


class RuntimeTransaction(Protocol):
    def consume_nonce(self, nonce: str, subject: str, audience: str, task_id: str, expires_at: int | None = None) -> None:
        """Consume a one-time nonce. `expires_at` is the expiry of the authorization it belongs to,
        stored WITH the nonce (Section 12 #4, owner decision D2): it is the only fact that later
        justifies deleting the row, never a value re-derived from mutable configuration. None marks a
        row that can never be pruned."""
        ...

    def advance_time_floor(self, now: int) -> int | None:
        """Advance the durable time floor inside this transaction (Section 12 #6), at most once per
        TIME_FLOOR_CADENCE_SECONDS, never downwards. Postgres ignores `now` and uses the database clock
        (the shared authority). Never waits for another writer: a row another transaction is already
        advancing is skipped, so the floor can never fail or stall the save it rides in. Returns the new
        floor, or None when it did not advance."""
        ...

    def is_task_cancelled(self, task_id: str) -> bool:
        """Whether the task is durably cancelled, read inside this transaction (section 5 #3).

        Called after `consume_nonce` in the approval gate so the redeem and the cancel check
        commit or roll back together: a cancel that lands first is observed and rolls the redeem
        back; one that lands after is caught by a later pre-launch re-check.
        """
        ...

    def audit_head(self, task_id: str) -> tuple[str, int] | None:
        """The stored head as seen INSIDE this transaction (Section 10 PR B floor check)."""
        ...

    def audit_event_hash(self, task_id: str, sequence: int) -> str | None:
        ...

    def append_audit_events(self, task_id: str, host_id: str, events: tuple[dict[str, Any], ...], sign_head: AuditHeadSigner | None = None) -> None:
        ...

    def save_checkpoint(self, task_id: str, state: AgentState, expected_generation: int, closed: bool = False, owner: tuple[str, str] | None = None) -> int:
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

        PM-001: `owner` is `(permit issuer, permit subject)`. It is recorded on the
        CREATE and compared -- in this same transaction as the generation CAS -- on
        every later save. A different owner raises `SecurityError`, so a trusted
        sender cannot resume, drive, or close another trusted sender's open task by
        knowing its id and generation. A stored row with NO owner (written before
        this schema) refuses too: its owner cannot be reconstructed, and letting the
        first caller claim it would preserve the very takeover this closes. `owner=None`
        makes no assertion and is for store-contract tests, never the host path.
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

    def cancel_task(self, task_id: str) -> None:
        """Durably record that a task is cancelled (section 5 #3). Idempotent."""
        ...

    def is_task_cancelled(self, task_id: str) -> bool:
        """Whether a task is durably cancelled (non-transactional read for the pre-launch re-check)."""
        ...

    # Effect ledger (Section 7 PR 2): durable idempotency/reconciliation record for one side-effecting
    # tool invocation, keyed by a host-derived effect_id. Persisted BEFORE the tool launches so a
    # crash-and-resume can tell "never launched" (prepared) from "may have landed" (started).
    def get_effect(self, effect_id: str) -> dict[str, Any] | None:
        """The ledger row for effect_id, or None. Keys: effect_id, task_id, tool, state,
        arguments_json, result_json, reason, created_at, updated_at."""
        ...

    def record_effect_prepared(self, effect_id: str, task_id: str, tool: str, arguments_json: str) -> None:
        """Insert a `prepared` effect row if none exists (idempotent on effect_id). Records intent to
        run a side-effecting tool BEFORE launch; `prepared` means it has not launched yet."""
        ...

    def mark_effect_started(self, effect_id: str) -> None:
        """Transition a `prepared` effect row to `started`, durably, immediately before the tool
        launches. A crash while `started` is treated as `unknown` (the effect may have landed)."""
        ...

    def settle_effect(self, effect_id: str, state: str, result_json: str | None, reason: str | None) -> None:
        """Settle a `started` effect to a terminal-ish state: `confirmed` (success, with result_json),
        `unknown` (killed / errored / crashed while started), or `reconciled` (reconcile determined the
        effect did not land). Idempotent overwrite of state/result/reason with a fresh updated_at."""
        ...

    def claim_effect_for_reconcile(self, effect_id: str, claim_id: str, lease_seconds: int) -> bool:
        """Atomically claim an effect for reconciliation under an OWNED lease (Section 7 PR 2, round 3
        remediation, mirroring the migration-outbox lease). Moves the row to `reconciling` and stamps it
        with `claim_id` (the owner) + a lease expiry iff it is currently `unknown`, OR a `reconciling`
        row whose lease has EXPIRED (a claim from a reconciler that died). A reclaim mints a DIFFERENT
        claim_id, so the prior holder can no longer settle it. Returns True iff this caller won the
        claim. Lease expiry uses DATABASE time on Postgres (a shared central clock), the local clock on
        the embedded stores."""
        ...

    def settle_effect_from_claim(self, effect_id: str, claim_id: str, new_state: str, result_json: str | None, reason: str | None) -> bool:
        """Terminal CAS settle scoped to the claim OWNER: move a `reconciling` row to `new_state` ONLY if
        `claim_id` still holds it AND the lease is still LIVE. Returns True iff it moved. A stale/expired
        holder (or one whose claim was reclaimed under a new id) cannot overwrite the current claim."""
        ...

    def release_effect_claim(self, effect_id: str, claim_id: str) -> bool:
        """Release a reconcile claim back to `unknown` (the reconcile function failed). Requires the
        `claim_id` match but NOT a live lease -- an expired holder relinquishing is always safe (it
        cannot touch a DIFFERENT holder, whose claim_id differs), and it keeps the effect retryable
        rather than stranded `reconciling`. Returns True iff it moved."""
        ...

    def renew_effect_claim(self, effect_id: str, claim_id: str, lease_seconds: int) -> bool:
        """Re-stamp the lease on an OWNED `reconciling` claim, atomically, using the store's authoritative
        clock (DB time on Postgres). Requires the `claim_id` match (state `reconciling`); NOT a live lease
        -- if you still own it (no one has reclaimed), extending is safe; if a reclaimer already took it
        the claim_id will differ and this returns False. The host calls it immediately BEFORE running a
        reconcile so a holder that was paused past its lease cannot execute concurrently with a reclaimer:
        whichever of renew and a reclaim reaches the row first wins atomically, and neither ordering yields
        two concurrent reconcile executions. Returns True iff the lease was extended."""
        ...

    def consumed_nonce_exists(self, nonce: str) -> bool:
        ...

    def load_checkpoint(self, task_id: str) -> dict[str, Any] | None:
        ...

    def checkpoint_owner(self, task_id: str) -> tuple[str | None, str | None] | None:
        """PM-001: the stored `(issuer, subject)` of this task, or None when there is no checkpoint.

        `(None, None)` means the row predates the owner column. The host reads this to refuse a
        foreign resume BEFORE anything is written; `save_checkpoint` re-checks it durably, inside
        the transaction that does the generation CAS, so this read is a courtesy, not the gate.
        """
        ...

    def audit_head(self, task_id: str) -> tuple[str, int] | None:
        ...

    def verify_audit_chain_status(self, task_id: str, allow_legacy_anchor: bool = False) -> AuditVerificationResult:
        ...

    def verify_audit_chain(self, task_id: str) -> bool:
        ...

    def list_pending_migrations(self, limit: int = DEFAULT_ADMIN_PAGE_SIZE, after: str | None = None) -> list[dict[str, Any]]:
        """One PAGE of OUTSTANDING outbox rows (status='pending'), ordered by task_id, INCLUDING rows another
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

        Section 12 #4: paged -- at most `limit` rows (1..MAX_ADMIN_PAGE_SIZE) with task_id > `after`, so
        a large backlog is never materialized at once. Pass the last row's task_id to get the next page.
        """
        ...

    def get_migration_receipt(self, task_id: str) -> dict[str, Any] | None:
        """The destination-issued receipt for an admitted migration, or None (section 4 #2).

        Read on the DESTINATION side so a duplicate delivery of an already-admitted
        migration returns the same receipt instead of a replay error.
        """
        ...

    def replace_migration_receipt(self, task_id: str, receipt_json: str) -> None:
        """Atomically overwrite an existing migration receipt (section 4 #5, durability).

        Used ONLY to persist a receipt whose challenge attestation was regenerated on redelivery of
        the identical envelope. All admission bindings (envelope digest, permit nonce, checkpoint
        generation, audit head, admission timestamp, task/source/destination) are unchanged -- only the
        attestation and the destination signature over it differ -- so the durable receipt always
        reflects the latest valid proof and a lost acknowledgement recovers even if the attester later
        becomes unavailable. Distinct from the keep-first `store_migration_receipt` of first admission.
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

    def record_migration_attempt(self, task_id: str, worker_id: str | None = None) -> None:
        """Count a delivery attempt. If `worker_id` is given, only the CURRENT (live-lease) holder
        counts -- a worker whose lease has expired is no longer the logical holder and cannot inflate
        the count toward dead-letter; without a worker_id the count is unscoped (legacy). The lease
        clock is a store CONSTRUCTION dependency, never a per-call parameter. Section 4 part 3a."""
        ...

    def claim_migrations(
        self, worker_id: str, lease_seconds: int, limit: int = 1
    ) -> list[dict[str, Any]]:
        """Atomically claim up to `limit` deliverable rows under a `lease_seconds` lease and return
        them (section 4 #3). A row is claimable if pending AND (unclaimed OR its lease has expired),
        so a worker that dies mid-delivery has its rows reclaimed once the lease lapses. Claiming is
        race-safe: two concurrent dispatchers never receive the same row. `worker_id`, `lease_seconds`
        (0 < n <= MAX_MIGRATION_LEASE_SECONDS) and `limit` are validated -- a zero/negative lease would
        defeat exclusivity. The lease clock is injected at store CONSTRUCTION (default: wall clock), so
        a caller of this method cannot supply a `now` that bypasses another worker's live lease."""
        ...

    def release_migration(self, task_id: str, worker_id: str) -> bool:
        """Release a claim so another worker can take the row. Holder-scoped AND lease-live (uniform
        with dead_letter): returns False unless this worker still holds the row under an UNEXPIRED
        lease. An expired holder's release is therefore a no-op -- which is safe, not stranding,
        because an expired lease already makes the row reclaimable via `claim_migrations`; the caller
        need not release it. Section 4 #3."""
        ...

    def dead_letter_migration(self, task_id: str, worker_id: str, reason: str) -> bool:
        """Terminalize a pending row the current holder gave up on into a 'dead' state with a reason
        (section 4 #4). Holder-scoped AND lease-live like release: an EXPIRED holder cannot dead-letter
        (its authority lapsed with the lease). Returns False if not the live holder or not pending (not
        distinguished). A verified receipt can still settle a dead row (see
        `find_migration_for_settlement`)."""
        ...

    def list_dead_migrations(self, limit: int = DEFAULT_ADMIN_PAGE_SIZE, after: str | None = None) -> list[dict[str, Any]]:
        """One page of dead-lettered rows for operator inspection, ordered by task_id (section 4 #4;
        paged like list_pending_migrations, Section 12 #4)."""
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

    # Section 12: time floor (#6) and capacity (#4).
    def time_floor(self) -> int:
        """The durable time floor in epoch seconds (0 if none). Only ever raised by advance_time_floor;
        only an explicit operator reset (reset_time_floor) can lower it."""
        ...

    def database_now(self) -> int | None:
        """The database clock (Postgres), or None for the embedded stores (they use the host clock)."""
        ...

    def reset_time_floor(self, floor_at: int, reason: str) -> int:
        """Operator recovery: set the floor to `floor_at` (may lower it) and write a maintenance-log
        record with the reason. Returns the previous floor. Never called automatically."""
        ...

    def maintenance_log(self, limit: int = 100) -> list[dict[str, Any]]:
        """The newest maintenance records (prunes, time-floor resets), newest first."""
        ...

    def prune(self, nonce_cutoff: int, migration_cutoff: int, apply: bool = False, batch_size: int = MAX_PRUNE_BATCH) -> dict[str, Any]:
        """Delete ONLY provably-unneeded rows (owner decision D2), in bounded batches:

        - consumed nonces whose STORED authorization expiry is < nonce_cutoff (rows without an expiry are
          kept and counted);
        - delivered outbox rows with a verified receipt stored on the row and delivered_at < migration_cutoff
          (pending, dead, and legacy delivered rows without a delivery time are kept and counted).

        Dry run unless `apply`. Each applied batch selects by a stable key cursor, re-checks the predicate
        in its DELETE, and writes a maintenance_log record in the SAME transaction. Never VACUUMs.
        Returns counts plus the oldest/newest timestamp of each class."""
        ...

    def capacity_report(self) -> dict[str, Any]:
        """Row counts per table, the oldest pending migration, database size, free space, time floor."""
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

    def __init__(self, clock: Callable[[], int] | None = None) -> None:
        self._lock = threading.RLock()
        self._nonces: dict[str, dict[str, Any]] = {}
        self._checkpoints: dict[str, dict[str, Any]] = {}
        self._audit_events: dict[str, list[dict[str, Any]]] = {}
        self._audit_heads: dict[str, dict[str, Any]] = {}
        self._outbox: dict[str, dict[str, Any]] = {}
        self._migration_receipts: dict[str, str] = {}
        # Section 5 #3: durable task cancellation. Membership means cancelled. Read inside the
        # approval transaction (which holds self._lock for its whole duration, so a concurrent
        # cancel cannot interleave with a redeem) and again before the tool launches.
        self._cancelled: set[str] = set()
        self._effects: dict[str, dict[str, Any]] = {}
        self._floor_markers: dict[str, tuple[int, bool]] = {}
        # Section 12: the durable time floor (#6) and the maintenance log (#4).
        self._time_floor = 0
        self._maintenance_log: list[dict[str, Any]] = []
        self._audit_head_verifier: AuditHeadVerifier | None = None
        # Section 4 #3: the lease clock is a CONSTRUCTION dependency, never a per-call parameter --
        # so a caller of claim/release/dead_letter cannot pass a forged "now" to steal a live lease.
        # Production uses the wall clock; tests inject a controllable one at construction.
        self._clock: Callable[[], int] = clock or _wall_clock

    def set_audit_head_verifier(self, verifier: AuditHeadVerifier) -> None:
        self._audit_head_verifier = verifier

    def transaction(self) -> AbstractContextManager[RuntimeTransaction]:
        return _InMemoryTransaction(self)

    def _page(self, status: str, limit: int, after: str | None) -> list[dict[str, Any]]:
        _validate_page(limit, after)
        with self._lock:
            rows = [dict(row) for row in self._outbox.values() if row["status"] == status and (after is None or row["task_id"] > after)]
        rows.sort(key=lambda row: row["task_id"])
        return rows[:limit]

    def list_pending_migrations(self, limit: int = DEFAULT_ADMIN_PAGE_SIZE, after: str | None = None) -> list[dict[str, Any]]:
        return self._page("pending", limit, after)

    def get_migration_receipt(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            stored = self._migration_receipts.get(task_id)
        return None if stored is None else json.loads(stored)

    def replace_migration_receipt(self, task_id: str, receipt_json: str) -> None:
        with self._lock:
            self._migration_receipts[task_id] = receipt_json

    def cancel_task(self, task_id: str) -> None:
        with self._lock:
            self._cancelled.add(task_id)

    def is_task_cancelled(self, task_id: str) -> bool:
        with self._lock:
            return task_id in self._cancelled

    def get_effect(self, effect_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._effects.get(effect_id)
            return None if row is None else dict(row)

    def record_effect_prepared(self, effect_id: str, task_id: str, tool: str, arguments_json: str) -> None:
        now = int(time.time())
        with self._lock:
            if effect_id in self._effects:
                return
            self._effects[effect_id] = {
                "effect_id": effect_id, "task_id": task_id, "tool": tool, "state": "prepared",
                "arguments_json": arguments_json, "result_json": None, "reason": None,
                "created_at": now, "updated_at": now,
                "reconcile_claim_id": None, "reconcile_lease_expires_at": None,
            }

    def mark_effect_started(self, effect_id: str) -> None:
        with self._lock:
            row = self._effects.get(effect_id)
            if row is not None and row["state"] == "prepared":
                row["state"] = "started"
                row["updated_at"] = int(time.time())

    def settle_effect(self, effect_id: str, state: str, result_json: str | None, reason: str | None) -> None:
        with self._lock:
            row = self._effects.get(effect_id)
            if row is not None:
                row["state"] = state
                row["result_json"] = result_json
                row["reason"] = reason
                row["updated_at"] = int(time.time())

    def claim_effect_for_reconcile(self, effect_id: str, claim_id: str, lease_seconds: int) -> bool:
        _validate_reconcile_claim_args(claim_id, lease_seconds)
        with self._lock:
            row = self._effects.get(effect_id)
            if row is None:
                return False
            now = self._clock()
            state = row["state"]
            lease = row.get("reconcile_lease_expires_at")
            eligible = state == "unknown" or (state == "reconciling" and (lease is None or int(lease) <= now))
            if not eligible:
                return False
            row["state"] = "reconciling"
            row["reconcile_claim_id"] = claim_id
            row["reconcile_lease_expires_at"] = now + int(lease_seconds)
            row["updated_at"] = now
            return True

    def settle_effect_from_claim(self, effect_id: str, claim_id: str, new_state: str, result_json: str | None, reason: str | None) -> bool:
        with self._lock:
            row = self._effects.get(effect_id)
            now = self._clock()
            if (row is None or row["state"] != "reconciling" or row.get("reconcile_claim_id") != claim_id
                    or int(row.get("reconcile_lease_expires_at") or 0) <= now):
                return False  # terminal settle needs the owning claim AND a LIVE lease
            row["state"] = new_state
            row["result_json"] = result_json
            row["reason"] = reason
            row["reconcile_claim_id"] = None
            row["reconcile_lease_expires_at"] = None
            row["updated_at"] = now
            return True

    def release_effect_claim(self, effect_id: str, claim_id: str) -> bool:
        with self._lock:
            row = self._effects.get(effect_id)
            if row is None or row["state"] != "reconciling" or row.get("reconcile_claim_id") != claim_id:
                return False  # release needs the owning claim, but NOT a live lease (safe relinquish)
            row["state"] = "unknown"
            row["result_json"] = None
            row["reason"] = "reconcile failed; claim released"
            row["reconcile_claim_id"] = None
            row["reconcile_lease_expires_at"] = None
            row["updated_at"] = self._clock()
            return True

    def renew_effect_claim(self, effect_id: str, claim_id: str, lease_seconds: int) -> bool:
        _validate_reconcile_claim_args(claim_id, lease_seconds)
        with self._lock:
            row = self._effects.get(effect_id)
            if row is None or row["state"] != "reconciling" or row.get("reconcile_claim_id") != claim_id:
                return False  # claim match only (no live-lease requirement): still-owned -> safe to extend
            now = self._clock()
            row["reconcile_lease_expires_at"] = now + int(lease_seconds)
            row["updated_at"] = now
            return True

    def mark_migration_delivered(self, task_id: str, receipt_json: str) -> None:
        with self._lock:
            row = self._outbox.get(task_id)
            if row is not None:
                row["status"] = "delivered"
                row["receipt_json"] = receipt_json
                row["delivered_at"] = self._clock()  # Section 12 #4: the prune cutoff is measured from here

    def record_migration_attempt(self, task_id: str, worker_id: str | None = None) -> None:
        moment = self._clock()
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
        self, worker_id: str, lease_seconds: int, limit: int = 1
    ) -> list[dict[str, Any]]:
        _validate_claim_args(worker_id, lease_seconds, limit)
        moment = self._clock()
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

    def release_migration(self, task_id: str, worker_id: str) -> bool:
        # Holder-scoped AND lease-live: returns False unless this worker still holds the row under an
        # unexpired lease, so neither a different worker nor an expired holder can clear a live claim.
        moment = self._clock()
        with self._lock:
            row = self._outbox.get(task_id)
            if row is None or not self._is_live_holder(row, worker_id, moment):
                return False
            row["claimed_by"] = None
            row["lease_expires_at"] = None
            return True

    def dead_letter_migration(self, task_id: str, worker_id: str, reason: str) -> bool:
        # Holder-scoped AND lease-live like release: an expired holder's authority lapsed with the lease.
        moment = self._clock()
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

    def list_dead_migrations(self, limit: int = DEFAULT_ADMIN_PAGE_SIZE, after: str | None = None) -> list[dict[str, Any]]:
        return self._page("dead", limit, after)

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

    def time_floor(self) -> int:
        with self._lock:
            return self._time_floor

    def database_now(self) -> int | None:
        return None

    def reset_time_floor(self, floor_at: int, reason: str) -> int:
        _validate_floor_reset(floor_at, reason)
        with self._lock:
            prior = self._time_floor
            self._time_floor = floor_at
            self._maintenance_log.append(_maintenance_entry(len(self._maintenance_log) + 1, _wall_clock(), "time-floor-reset", {"prior": prior, "new": floor_at, "reason": reason}))
            return prior

    def maintenance_log(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(entry) for entry in reversed(self._maintenance_log[-limit:])]

    def prune(self, nonce_cutoff: int, migration_cutoff: int, apply: bool = False, batch_size: int = MAX_PRUNE_BATCH) -> dict[str, Any]:
        _validate_prune_args(nonce_cutoff, migration_cutoff, batch_size)
        report = _empty_prune_report(nonce_cutoff, migration_cutoff, apply)
        with self._lock:
            nonces = sorted(
                (key, row["expires_at"]) for key, row in self._nonces.items()
                if row.get("expires_at") is not None and row["expires_at"] < nonce_cutoff
            )
            delivered = sorted(
                (key, row["delivered_at"]) for key, row in self._outbox.items()
                if row["status"] == "delivered" and row.get("receipt_json") is not None
                and row.get("delivered_at") is not None and row["delivered_at"] < migration_cutoff
            )
            report["kept"] = {
                "nonces_without_expiry": sum(1 for row in self._nonces.values() if row.get("expires_at") is None),
                "delivered_without_delivery_time": sum(1 for row in self._outbox.values() if row["status"] == "delivered" and row.get("delivered_at") is None),
                "delivered_without_receipt": sum(1 for row in self._outbox.values() if row["status"] == "delivered" and row.get("receipt_json") is None),
                "pending_migrations": sum(1 for row in self._outbox.values() if row["status"] == "pending"),
                "dead_migrations": sum(1 for row in self._outbox.values() if row["status"] == "dead"),
            }
            for name, rows, table in (("expired_nonces", nonces, self._nonces), ("delivered_migrations", delivered, self._outbox)):
                entry = report[name]
                entry["eligible"] = len(rows)
                if rows:
                    _merge_range(entry, min(stamp for _, stamp in rows), max(stamp for _, stamp in rows))
                if not apply:
                    continue
                for offset in range(0, len(rows), batch_size):
                    batch = rows[offset:offset + batch_size]
                    for key, _stamp in batch:
                        del table[key]
                    entry["deleted"] += len(batch)
                    report["batches"] += 1
                    self._maintenance_log.append(_maintenance_entry(
                        len(self._maintenance_log) + 1, _wall_clock(), "prune-batch",
                        {"class": name, "deleted": len(batch), "oldest": min(stamp for _, stamp in batch),
                         "newest": max(stamp for _, stamp in batch), "cutoff": nonce_cutoff if name == "expired_nonces" else migration_cutoff},
                    ))
            if apply:
                self._maintenance_log.append(_maintenance_entry(len(self._maintenance_log) + 1, _wall_clock(), "prune", _prune_summary(report)))
        return report

    def capacity_report(self) -> dict[str, Any]:
        with self._lock:
            pending = [row["created_at"] for row in self._outbox.values() if row["status"] == "pending"]
            return {
                "backend": "memory",
                "rows": {
                    "audit_events": sum(len(events) for events in self._audit_events.values()),
                    "audit_heads": len(self._audit_heads), "checkpoints": len(self._checkpoints),
                    "consumed_nonces": len(self._nonces), "migration_outbox": len(self._outbox),
                    "migration_receipts": len(self._migration_receipts), "task_cancellations": len(self._cancelled),
                    "tool_effects": len(self._effects), "maintenance_log": len(self._maintenance_log),
                },
                "oldest_pending_migration_at": min(pending) if pending else None,
                "database_bytes": None,
                "free_bytes": None,
                "time_floor": self._time_floor,
            }

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

    def checkpoint_owner(self, task_id: str) -> tuple[str | None, str | None] | None:
        with self._lock:
            row = self._checkpoints.get(task_id)
            return None if row is None else (row.get("owner_issuer"), row.get("owner_subject"))

    def audit_head(self, task_id: str) -> tuple[str, int] | None:
        with self._lock:
            events = self._audit_events.get(task_id)
            head = self._audit_heads.get(task_id)
            if not events or head is None:
                return None
            return head["head_hash"], head["sequence"]

    def verify_audit_chain_status(self, task_id: str, allow_legacy_anchor: bool = False) -> AuditVerificationResult:
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
            head_result = _verify_head_signature(self._audit_head_verifier, task_id, head)
            return _check_migration_anchor(self._audit_head_verifier, head_result, events[0]["details"], allow_legacy_anchor)

    def verify_audit_chain(self, task_id: str) -> bool:
        return self.verify_audit_chain_status(task_id).valid

    # -- Section 10 PR B: audit-floor support (reads + the per-host marker) ------------------
    def audit_heads_for_host(self, host_id: str) -> list[tuple[str, str, int]]:
        with self._lock:
            return [(task_id, head["head_hash"], int(head["sequence"])) for task_id, head in self._audit_heads.items() if head.get("host_id") == host_id]

    def audit_event_hash(self, task_id: str, sequence: int) -> str | None:
        with self._lock:
            events = self._audit_events.get(task_id, [])
            return events[sequence]["hash"] if 0 <= sequence < len(events) else None

    def audit_floor_marker(self, host_id: str) -> tuple[int, bool] | None:
        with self._lock:
            return self._floor_markers.get(host_id)

    def set_audit_floor_marker(self, host_id: str, epoch: int, pending: bool) -> None:
        with self._lock:
            self._floor_markers[host_id] = (epoch, pending)


class _InMemoryTransaction:
    def __init__(self, store: InMemoryRuntimeStore) -> None:
        self._store = store
        self._snapshots: tuple[dict[str, Any], dict[str, Any], dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, str]] | None = None

    def __enter__(self) -> "_InMemoryTransaction":
        self._store._lock.acquire()
        self._time_floor_snapshot = self._store._time_floor
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
            self._store._time_floor = self._time_floor_snapshot
        self._store._lock.release()

    def consume_nonce(self, nonce: str, subject: str, audience: str, task_id: str, expires_at: int | None = None) -> None:
        if nonce in self._store._nonces:
            raise SecurityError("permit nonce has already been consumed")
        self._store._nonces[nonce] = {
            "subject": subject,
            "audience": audience,
            "task_id": task_id,
            "consumed_at": int(time.time()),
            "expires_at": _checked_expiry(expires_at),
        }

    def advance_time_floor(self, now: int) -> int | None:
        if now - TIME_FLOOR_CADENCE_SECONDS < self._store._time_floor:
            return None
        self._store._time_floor = int(now)
        return int(now)

    def is_task_cancelled(self, task_id: str) -> bool:
        # Read within the held transaction lock so the redeem-vs-cancel decision is atomic.
        return task_id in self._store._cancelled

    def audit_head(self, task_id: str) -> tuple[str, int] | None:
        head = self._store._audit_heads.get(task_id)
        return None if head is None else (head["head_hash"], int(head["sequence"]))

    def audit_event_hash(self, task_id: str, sequence: int) -> str | None:
        events = self._store._audit_events.get(task_id, [])
        return events[sequence]["hash"] if 0 <= sequence < len(events) else None

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

    def save_checkpoint(self, task_id: str, state: AgentState, expected_generation: int, closed: bool = False, owner: tuple[str, str] | None = None) -> int:
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
            # PM-001: ownership is compared in the same step as the generation CAS.
            _check_owner((row.get("owner_issuer"), row.get("owner_subject")), owner)
            new_generation = expected_generation + 1
        blob = asdict(state)
        blob["checkpoint_generation"] = new_generation
        self._store._checkpoints[task_id] = {
            "generation": new_generation,
            "closed": bool(closed),
            "state": blob,
            # Recorded on the CREATE and never rewritten afterwards.
            "owner_issuer": row["owner_issuer"] if row is not None else (owner[0] if owner else None),
            "owner_subject": row["owner_subject"] if row is not None else (owner[1] if owner else None),
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


# Section 11 #5: the SQLite store holds checkpoints, messages, tool arguments and results,
# migration envelopes and receipts, and audit details, so it must never be readable by other local
# users. Group/other permission bits on the database or its WAL/SHM side files are refused.
SQLITE_INSECURE_MODE_BITS = stat.S_IRWXG | stat.S_IRWXO
SQLITE_SIDE_FILE_SUFFIXES = ("-wal", "-shm")


def _refuse_insecure_sqlite_file(path: Path, owner_uid: int) -> None:
    """Refuse a store file that another local user could read, swap, or redirect.

    lstat, never stat: a symlink at the database, -wal, or -shm path would let whoever controls
    its target decide where task data is written (auditor round 2).
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"SQLite store file {path} is a symbolic link; the store and its -wal/-shm files must be regular files")
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"SQLite store file {path} is not a regular file")
    if info.st_uid != owner_uid:
        raise RuntimeError(
            f"SQLite store file {path} is owned by uid {info.st_uid}, not by the host user (uid {owner_uid}). "
            f"Fix it with: chown {owner_uid} {shlex.quote(str(path))}"
        )
    if info.st_mode & SQLITE_INSECURE_MODE_BITS:
        raise RuntimeError(
            f"SQLite store file {path} is accessible by group or other users "
            f"(mode {stat.S_IMODE(info.st_mode):04o}); it may hold task data and secrets. "
            f"Fix it with: chmod 600 {shlex.quote(str(path))}"
        )


SQLITE_MAX_SYMLINK_HOPS = 40
_GROUP_OR_OTHER_WRITE = stat.S_IWGRP | stat.S_IWOTH


def _refuse_untrusted_owner(kind: str, path: str, info: os.stat_result, owner_uid: int) -> None:
    if info.st_uid not in (owner_uid, 0):
        raise RuntimeError(
            f"SQLite store {kind} {path} is owned by uid {info.st_uid}, not by the host user "
            f"(uid {owner_uid}) or root. Fix it with: chown {owner_uid} {shlex.quote(path)}"
        )


def _refuse_unsafe_directory_chain(directory: Path, owner_uid: int, *, is_store_directory: bool) -> None:
    """Refuse a path that any untrusted local user could redirect, from / down to ``directory``.

    Section 11 #5 (auditor round 3): a 0700 store directory is not protected if ANY ancestor is
    writable by another user, because renaming a directory needs write access only to ITS parent.
    The store reconnects by pathname, so that user could swap in a replacement between connections.
    Every component is read with lstat and must be owned by the host user or root. An ancestor
    directory may be group/other-writable only when it is sticky (like /tmp): then only the owner
    of an entry, the directory owner, or root can rename or delete that entry, and every entry on
    the path is itself required to be owned by the host user or root.

    Symlinks: the store directory itself must not be a symlink (a symlink there is a
    pathname-replacement primitive). A symlink ABOVE it (macOS /var -> /private/var) is allowed only
    where the walk has already shown that no untrusted user can replace it, and its target is walked
    with the same rules. The walk runs to /, never stopping early: a root-owned directory inside a
    writable directory can still be renamed away.
    """
    lexical = directory if directory.is_absolute() else Path(os.getcwd()) / directory
    if is_store_directory and stat.S_ISLNK(os.lstat(lexical).st_mode):
        raise RuntimeError(
            f"SQLite store directory {lexical} is a symbolic link; point the store path at the real "
            f"directory (use a bind mount to place it on another volume)"
        )
    root_info = os.lstat("/")
    _refuse_untrusted_owner("directory", "/", root_info, owner_uid)
    if root_info.st_mode & _GROUP_OR_OTHER_WRITE and not root_info.st_mode & stat.S_ISVTX:
        raise RuntimeError("SQLite store path is unsafe: / is writable by group or other users")
    current = "/"
    pending = list(reversed(lexical.parts[1:]))
    hops = 0
    while pending:
        name = pending.pop()
        if name in ("", "."):
            continue
        if name == "..":
            current = os.path.dirname(current)
            continue
        candidate = os.path.join(current, name)
        info = os.lstat(candidate)
        _refuse_untrusted_owner("path component", candidate, info, owner_uid)
        if stat.S_ISLNK(info.st_mode):
            hops += 1
            if hops > SQLITE_MAX_SYMLINK_HOPS:
                raise RuntimeError(f"SQLite store path {lexical} has too many symbolic links")
            target = os.readlink(candidate)
            if os.path.isabs(target):
                current = "/"
            pending.extend(reversed(Path(target).parts[1:] if os.path.isabs(target) else Path(target).parts))
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"SQLite store path component {candidate} is not a directory")
        if is_store_directory and not pending:
            current = candidate  # the store directory itself: the stricter check below applies
            break
        if info.st_mode & _GROUP_OR_OTHER_WRITE and not info.st_mode & stat.S_ISVTX:
            raise RuntimeError(
                f"SQLite store path component {candidate} is writable by group or other users "
                f"(mode {stat.S_IMODE(info.st_mode):04o}) and not sticky; they could rename or replace "
                f"the store directory. Fix it with: chmod go-w {shlex.quote(candidate)}"
            )
        current = candidate
    if is_store_directory:
        # The store directory gets no sticky exception: nobody but its owner may write it.
        info = os.lstat(current)
        if info.st_mode & _GROUP_OR_OTHER_WRITE:
            raise RuntimeError(
                f"SQLite store directory {current} is writable by group or other users "
                f"(mode {stat.S_IMODE(info.st_mode):04o}); they could replace or delete the store. "
                f"Fix it with: chmod 700 {shlex.quote(current)}"
            )


def _prepare_sqlite_database_file(path: Path) -> None:
    """Create a new database owner-only; refuse an unsafe directory or an unsafe existing file.

    POSIX only: Windows has no mode bits here (its ACLs are documented in OPERATIONS.md).
    Order matters: the existing part of the directory chain is checked BEFORE anything is created
    in it; missing directories are then created one by one with 0700, and the whole chain is checked
    again. A new database file is then pre-created 0600 (O_EXCL, so an existing file or symlink is
    never followed) BEFORE sqlite3 opens it, because SQLite creates the -wal and -shm files with the
    database's mode.
    """
    if os.name == "nt":
        path.parent.mkdir(parents=True, exist_ok=True)
        return
    owner_uid = os.geteuid()
    store_directory = path.parent if path.parent.is_absolute() else Path(os.getcwd()) / path.parent
    existing, missing = store_directory, []
    while not os.path.lexists(existing):
        missing.append(existing.name)
        existing = existing.parent
    _refuse_unsafe_directory_chain(existing, owner_uid, is_store_directory=not missing)
    for name in reversed(missing):
        existing = existing / name
        try:
            os.mkdir(existing, 0o700)
        except FileExistsError:
            # Section 11 PR B (auditor): hosts cold-starting together all see the same missing
            # directories; losing that race is not an error. Whatever the winner created -- or
            # whatever was raced in (a symlink, a file, a wider mode, another owner) -- is judged
            # by the full re-check below, never trusted because it exists.
            pass
    if missing:
        _refuse_unsafe_directory_chain(store_directory, owner_uid, is_store_directory=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(fd)
    for candidate in (path, *(Path(f"{path}{suffix}") for suffix in SQLITE_SIDE_FILE_SUFFIXES)):
        _refuse_insecure_sqlite_file(candidate, owner_uid)


def _enable_wal(connection: sqlite3.Connection) -> None:
    """Put the database in WAL mode, tolerating the cold-start race over the switch.

    Switching a new database to WAL needs an exclusive lock, and SQLite may return SQLITE_BUSY at
    once -- without the busy handler -- to avoid a lock-escalation deadlock. With many hosts
    cold-starting on one new store, some failed startup with "database is locked" (Section 11 PR B,
    found by the real 32-process cold-start test). WAL mode persists in the file, so a host that sees
    it already set skips the switch; a host that loses the race retries SQLITE_BUSY only, bounded by
    the same busy timeout. Every other error still fails at once.
    """
    if str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal":
        return
    deadline = time.monotonic() + SQLITE_BUSY_TIMEOUT_MS / 1000
    delay = 0.005
    while True:
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            return
        except sqlite3.OperationalError as error:
            if getattr(error, "sqlite_errorcode", None) != sqlite3.SQLITE_BUSY or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 0.1)


class SQLiteRuntimeStore:
    is_durable = True

    def __init__(self, path: str | Path, audit_head_verifier: AuditHeadVerifier | None = None, clock: Callable[[], int] | None = None) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._audit_head_verifier = audit_head_verifier
        # Section 4 #3: lease clock is a construction dependency (see InMemoryRuntimeStore).
        self._clock: Callable[[], int] = clock or _wall_clock
        self._initialize()

    def set_audit_head_verifier(self, verifier: AuditHeadVerifier) -> None:
        self._audit_head_verifier = verifier

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
        try:
            _enable_wal(connection)
        except BaseException:
            connection.close()
            raise
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
        _prepare_sqlite_database_file(Path(self.path))
        connection = self._connect()
        try:
            while self._migrate_one_step(connection):
                pass
        finally:
            connection.close()

    def _migrate_one_step(self, connection: sqlite3.Connection) -> bool:
        """Apply exactly one schema step in one write transaction; return False once current.

        Section 11 #3: executescript() issues a COMMIT first and then runs every statement in
        autocommit, so a crash in the middle of a migration left a half-applied schema that the next
        start could not continue ("duplicate column name"). Each step now runs its statements with
        execute() inside ONE explicit BEGIN IMMEDIATE transaction together with its
        PRAGMA user_version bump. SQLite DDL and user_version are transactional, so a crash leaves
        the complete old version or the complete new one, never a mix.

        The version is read INSIDE the write transaction, so two processes opening the same old
        database serialize on SQLite's write lock and the second sees the first one's result instead
        of re-running a step. Every step is also restart-idempotent against the half-applied states
        the old executescript runner could leave behind (see _migrate_to_v2 and _add_column).
        """
        connection.execute("BEGIN IMMEDIATE")
        try:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > SQLITE_SCHEMA_VERSION:
                raise RuntimeError(f"SQLite store schema version {version} is newer than supported version {SQLITE_SCHEMA_VERSION}")
            if version == SQLITE_SCHEMA_VERSION:
                connection.execute("COMMIT")
                return False
            migration = self._migrations().get(version)
            if migration is None:
                raise RuntimeError(f"SQLite store has no migration from schema version {version}")
            migration(connection)
            connection.execute(f"PRAGMA user_version = {version + 1:d}")
            connection.execute("COMMIT")
            return True
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    def _migrations(self) -> dict[int, Callable[[sqlite3.Connection], None]]:
        # Keyed by the version a step upgrades FROM. Version 0 is a new or pre-versioning database.
        return {
            0: self._migrate_to_v1,
            1: self._migrate_to_v2,
            2: self._migrate_to_v3,
            3: self._migrate_to_v4,
            4: self._migrate_to_v5,
            5: self._migrate_to_v6,
            6: self._migrate_to_v7,
            7: self._migrate_to_v8,
            8: self._migrate_to_v9,
            9: self._migrate_to_v10,
            10: self._migrate_to_v11,
            11: self._migrate_to_v12,
            12: self._migrate_to_v13,
            13: self._migrate_to_v14,
        }

    @staticmethod
    def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
        return connection.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone() is not None

    @staticmethod
    def _add_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        # SQLite has no ADD COLUMN IF NOT EXISTS. Checking first makes the step restart-idempotent
        # against a column that the old autocommit runner added before crashing. `table`, `column`
        # and `definition` are literals from this module, never external input.
        existing = {row[1] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in existing:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _migrate_to_v1(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS consumed_nonces (
                nonce TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                audience TEXT NOT NULL,
                task_id TEXT NOT NULL,
                consumed_at INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS checkpoints (
                task_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                checkpoint_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
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
                created_at INTEGER NOT NULL,
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
                updated_at INTEGER NOT NULL
            )
            """
        )

    def _migrate_to_v2(self, connection: sqlite3.Connection) -> None:
        # Rebuild audit_events. The old autocommit runner could stop between any two statements:
        # - audit_events_v2 exists but audit_events is gone: it stopped after DROP, before RENAME, so
        #   the copy is complete -- finish with the rename;
        # - both exist: it stopped before DROP, so the original is intact and the copy may be
        #   partial -- discard the copy and rebuild.
        if self._table_exists(connection, "audit_events_v2"):
            if not self._table_exists(connection, "audit_events"):
                connection.execute("ALTER TABLE audit_events_v2 RENAME TO audit_events")
                return
            connection.execute("DROP TABLE audit_events_v2")
        connection.execute(
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
            )
            """
        )
        connection.execute(
            """
            INSERT INTO audit_events_v2
                (task_id, sequence, host_id, event, details_json, previous_hash, hash, created_at)
            SELECT task_id, sequence, host_id, event, details_json, previous_hash, hash, created_at
            FROM audit_events
            """
        )
        connection.execute("DROP TABLE audit_events")
        connection.execute("ALTER TABLE audit_events_v2 RENAME TO audit_events")

    def _migrate_to_v3(self, connection: sqlite3.Connection) -> None:
        self._add_column(connection, "audit_heads", "host_id", "TEXT NOT NULL DEFAULT ''")
        self._add_column(connection, "audit_heads", "signature_key_id", "TEXT NOT NULL DEFAULT ''")
        self._add_column(connection, "audit_heads", "signature", "TEXT NOT NULL DEFAULT ''")

    def _migrate_to_v4(self, connection: sqlite3.Connection) -> None:
        # Finding EV-008: give every stored checkpoint a store-owned monotonic
        # generation and a terminal `closed` flag, so a resume is a compare-and-swap
        # on the durable row rather than trust in caller-supplied state.
        self._add_column(connection, "checkpoints", "generation", "INTEGER NOT NULL DEFAULT 0")
        self._add_column(connection, "checkpoints", "closed", "INTEGER NOT NULL DEFAULT 0")
        connection.execute("UPDATE checkpoints SET closed = 1 WHERE status IN ('completed', 'failed')")

    def _migrate_to_v5(self, connection: sqlite3.Connection) -> None:
        # Section 1, finding #2: durable migration delivery. The sealed destination
        # envelope is written in the SAME transaction that closes the source
        # checkpoint, so a crash after the source closes cannot lose the migration;
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
                created_at INTEGER NOT NULL
            )
            """
        )

    def _migrate_to_v6(self, connection: sqlite3.Connection) -> None:
        # Finding #3 (Option B): audit heads gain a nullable signed_at so verification can be
        # judged at signing time. NULL marks a legacy v1 head (no attested signing time).
        self._add_column(connection, "audit_heads", "signed_at", "INTEGER")

    def _migrate_to_v7(self, connection: sqlite3.Connection) -> None:
        # Section 4 #2: signed destination receipts for migration delivery settlement.
        # migration_receipts holds the receipt this host ISSUED as a destination (so a
        # duplicate delivery returns the same one); migration_outbox.receipt_json holds the
        # receipt this host RECEIVED as a source and verified before settling the row.
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS migration_receipts (
                task_id TEXT PRIMARY KEY,
                receipt_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        self._add_column(connection, "migration_outbox", "receipt_json", "TEXT")

    def _migrate_to_v8(self, connection: sqlite3.Connection) -> None:
        # Section 4 part 3a: outbox reliability. A dispatcher CLAIMS a row under a time-bounded
        # lease (claimed_by + lease_expires_at) so two dispatchers can't ship the same migration
        # (#3); a row it gives up on moves to a terminal 'dead' state with a dead_reason instead
        # of sitting pending forever (#4). All three columns are nullable -- an unclaimed, live,
        # non-dead row has them NULL, so existing pending rows upgrade untouched.
        self._add_column(connection, "migration_outbox", "claimed_by", "TEXT")
        self._add_column(connection, "migration_outbox", "lease_expires_at", "INTEGER")
        self._add_column(connection, "migration_outbox", "dead_reason", "TEXT")

    def _migrate_to_v9(self, connection: sqlite3.Connection) -> None:
        # Section 5 #3: durable cancellation. An operator can cancel an admitted task; the
        # approval gate consults this table inside the SAME transaction that consumes the
        # approval nonce, so a cancel that lands first atomically prevents redemption, and a
        # cancel that lands after redemption is caught by the pre-launch re-check. One row per
        # cancelled task; presence means cancelled (idempotent).
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS task_cancellations (
                task_id TEXT PRIMARY KEY,
                cancelled_at INTEGER NOT NULL
            )
            """
        )

    def _migrate_to_v10(self, connection: sqlite3.Connection) -> None:
        # Section 7 PR 2: the effect ledger. One row per side-effecting tool invocation, keyed by a
        # host-derived effect_id, written BEFORE the tool launches (prepared -> started) so a
        # crash-and-resume can tell "never launched" from "may have landed". State machine:
        # prepared | started | confirmed | unknown | reconciled. arguments_json is kept so the
        # reconcile pass can re-query the external system; result_json holds a confirmed result.
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS tool_effects (
                effect_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                state TEXT NOT NULL,
                arguments_json TEXT NOT NULL,
                result_json TEXT,
                reason TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_tool_effects_task ON tool_effects (task_id)")

    def _migrate_to_v11(self, connection: sqlite3.Connection) -> None:
        # Section 7 PR 2 (round 3, remediation): give a reconcile claim an OWNER + a lease, mirroring the
        # migration-outbox lease (v8). reconcile_claim_id identifies WHO holds the current claim so a
        # stale/expired reconciler cannot settle or reset a newer holder's claim; reconcile_lease_expires_at
        # bounds it so a dead reconciler's claim is reclaimable. Both nullable -- an effect not under
        # reconciliation has them NULL, so existing rows upgrade untouched.
        self._add_column(connection, "tool_effects", "reconcile_claim_id", "TEXT")
        self._add_column(connection, "tool_effects", "reconcile_lease_expires_at", "INTEGER")

    def _migrate_to_v12(self, connection: sqlite3.Connection) -> None:
        # Section 10 PR B: the audit-floor "initialized" marker, one row per host. The floor file
        # lives OUTSIDE this database; this row records that a floor exists (and its epoch), so a
        # floor that later disappears is refused instead of silently rebuilt, and a database from
        # before the floor was created (or before an operator reset) is detected.
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_floor_markers (
                host_id TEXT PRIMARY KEY,
                epoch INTEGER NOT NULL,
                pending INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            )
            """
        )

    def _migrate_to_v14(self, connection: sqlite3.Connection) -> None:
        # PM-001: the owner of a task -- the permit issuer and subject of its FIRST admission. A
        # checkpoint was found by caller-supplied task id alone, so any trusted sender that learned
        # or guessed an open task's id and generation could resume, drive, and close another
        # sender's task. Existing rows stay NULL: their owner cannot be reconstructed (the audit
        # trail records the agent, never the issuer), so an OPEN legacy task refuses to resume
        # rather than let the first caller claim it. A closed one is unaffected -- it is evidence.
        self._add_column(connection, "checkpoints", "owner_issuer", "TEXT")
        self._add_column(connection, "checkpoints", "owner_subject", "TEXT")

    def _migrate_to_v13(self, connection: sqlite3.Connection) -> None:
        # Section 12. #4: a nonce keeps the expiry of the authorization it belongs to (the only fact that
        # justifies pruning it), a delivered migration keeps when it was delivered, and every prune or
        # time-floor reset is recorded in maintenance_log. #6: the durable time floor, seeded from the
        # newest past timestamp already stored, so an upgraded database starts protected, not at zero.
        self._add_column(connection, "consumed_nonces", "expires_at", "INTEGER")
        self._add_column(connection, "migration_outbox", "delivered_at", "INTEGER")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS maintenance_log (
                id INTEGER PRIMARY KEY,
                at INTEGER NOT NULL,
                action TEXT NOT NULL,
                detail_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS time_floor (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                floor_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        seed = 0
        for table, column in _TIME_FLOOR_SEED_COLUMNS:
            value = connection.execute(f"SELECT MAX({column}) FROM {table}").fetchone()[0]  # nosec B608 -- constant identifiers
            if value is not None:
                seed = max(seed, int(value))
        connection.execute("INSERT OR IGNORE INTO time_floor (singleton, floor_at, updated_at) VALUES (1, ?, ?)", (seed, seed))

    def transaction(self) -> AbstractContextManager[RuntimeTransaction]:
        return _SQLiteTransaction(self)

    def _page(self, status: str, columns: str, limit: int, after: str | None) -> list[dict[str, Any]]:
        _validate_page(limit, after)
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT {columns} FROM migration_outbox WHERE status = ? AND task_id > ? ORDER BY task_id LIMIT ?",  # nosec B608 -- constant columns
                (status, after or "", limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def list_pending_migrations(self, limit: int = DEFAULT_ADMIN_PAGE_SIZE, after: str | None = None) -> list[dict[str, Any]]:
        return self._page("pending", "task_id, destination, sealed_envelope_json, status, attempt_count, created_at, claimed_by, lease_expires_at", limit, after)

    def get_migration_receipt(self, task_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT receipt_json FROM migration_receipts WHERE task_id = ?", (task_id,)
            ).fetchone()
        return None if row is None else json.loads(row["receipt_json"])

    def replace_migration_receipt(self, task_id: str, receipt_json: str) -> None:
        # Overwrite only the receipt body (regenerated attestation + signature); created_at and every
        # binding stay put. A single UPDATE is atomic under the connection lock, so concurrent
        # regenerations are last-write-wins over equally-valid receipts, never a partial write.
        with self._connection() as connection:
            connection.execute(
                "UPDATE migration_receipts SET receipt_json = ? WHERE task_id = ?",
                (receipt_json, task_id),
            )

    def mark_migration_delivered(self, task_id: str, receipt_json: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "UPDATE migration_outbox SET status = 'delivered', receipt_json = ?, delivered_at = ? WHERE task_id = ?",
                (receipt_json, int(time.time()), task_id),
            )

    def cancel_task(self, task_id: str) -> None:
        # Idempotent: a repeat cancel keeps the first cancelled_at. Presence = cancelled.
        with self._connection() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO task_cancellations (task_id, cancelled_at) VALUES (?, ?)",
                (task_id, int(time.time())),
            )

    def is_task_cancelled(self, task_id: str) -> bool:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT 1 FROM task_cancellations WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        return row is not None

    def get_effect(self, effect_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT effect_id, task_id, tool, state, arguments_json, result_json, reason, "
                "created_at, updated_at, reconcile_claim_id, reconcile_lease_expires_at "
                "FROM tool_effects WHERE effect_id = ?",
                (effect_id,),
            ).fetchone()
        return None if row is None else dict(row)

    def record_effect_prepared(self, effect_id: str, task_id: str, tool: str, arguments_json: str) -> None:
        # Idempotent on effect_id: a prepared row for a call already recorded is left as-is (the
        # host checks state first). Presence of a prepared row means "intent recorded, not launched".
        now = int(time.time())
        with self._connection() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO tool_effects "
                "(effect_id, task_id, tool, state, arguments_json, result_json, reason, created_at, updated_at) "
                "VALUES (?, ?, ?, 'prepared', ?, NULL, NULL, ?, ?)",
                (effect_id, task_id, tool, arguments_json, now, now),
            )

    def mark_effect_started(self, effect_id: str) -> None:
        # Only advance a prepared row to started (durable, right before launch). A row already
        # started/settled is not moved back.
        with self._connection() as connection:
            connection.execute(
                "UPDATE tool_effects SET state = 'started', updated_at = ? "
                "WHERE effect_id = ? AND state = 'prepared'",
                (int(time.time()), effect_id),
            )

    def settle_effect(self, effect_id: str, state: str, result_json: str | None, reason: str | None) -> None:
        with self._connection() as connection:
            connection.execute(
                "UPDATE tool_effects SET state = ?, result_json = ?, reason = ?, updated_at = ? "
                "WHERE effect_id = ?",
                (state, result_json, reason, int(time.time()), effect_id),
            )

    def claim_effect_for_reconcile(self, effect_id: str, claim_id: str, lease_seconds: int) -> bool:
        # Embedded single-host store: the injected clock is authoritative (no cross-host lease comparison).
        _validate_reconcile_claim_args(claim_id, lease_seconds)
        now = self._clock()
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE tool_effects SET state = 'reconciling', reconcile_claim_id = ?, "
                "reconcile_lease_expires_at = ?, updated_at = ? "
                "WHERE effect_id = ? AND (state = 'unknown' OR (state = 'reconciling' "
                "AND (reconcile_lease_expires_at IS NULL OR reconcile_lease_expires_at <= ?)))",
                (claim_id, now + int(lease_seconds), now, effect_id, now),
            )
            return cursor.rowcount == 1

    def settle_effect_from_claim(self, effect_id: str, claim_id: str, new_state: str, result_json: str | None, reason: str | None) -> bool:
        now = self._clock()
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE tool_effects SET state = ?, result_json = ?, reason = ?, "
                "reconcile_claim_id = NULL, reconcile_lease_expires_at = NULL, updated_at = ? "
                "WHERE effect_id = ? AND state = 'reconciling' AND reconcile_claim_id = ? "
                "AND reconcile_lease_expires_at > ?",
                (new_state, result_json, reason, now, effect_id, claim_id, now),
            )
            return cursor.rowcount == 1

    def release_effect_claim(self, effect_id: str, claim_id: str) -> bool:
        # Claim match only, NOT lease-live: an expired holder relinquishing to `unknown` is safe (its
        # claim_id cannot match a DIFFERENT holder's) and keeps the effect retryable.
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE tool_effects SET state = 'unknown', result_json = NULL, "
                "reason = 'reconcile failed; claim released', reconcile_claim_id = NULL, "
                "reconcile_lease_expires_at = NULL, updated_at = ? "
                "WHERE effect_id = ? AND state = 'reconciling' AND reconcile_claim_id = ?",
                (self._clock(), effect_id, claim_id),
            )
            return cursor.rowcount == 1

    def renew_effect_claim(self, effect_id: str, claim_id: str, lease_seconds: int) -> bool:
        # Embedded single-host store: the injected clock is authoritative. Claim match only (no live-lease
        # requirement): still-owned -> safe to extend; if a reclaimer took it the claim_id differs -> no row.
        _validate_reconcile_claim_args(claim_id, lease_seconds)
        now = self._clock()
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE tool_effects SET reconcile_lease_expires_at = ?, updated_at = ? "
                "WHERE effect_id = ? AND state = 'reconciling' AND reconcile_claim_id = ?",
                (now + int(lease_seconds), now, effect_id, claim_id),
            )
            return cursor.rowcount == 1

    def record_migration_attempt(self, task_id: str, worker_id: str | None = None) -> None:
        moment = self._clock()
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
        self, worker_id: str, lease_seconds: int, limit: int = 1
    ) -> list[dict[str, Any]]:
        # Section 4 #3. Race-safety comes from BEGIN IMMEDIATE, which takes SQLite's single write
        # lock up front, so two concurrent claimers serialize (the second blocks until the first
        # commits) rather than both selecting and one silently losing its UPDATE. `_connect` opens
        # in autocommit (isolation_level=None), so the transaction is managed explicitly here.
        _validate_claim_args(worker_id, lease_seconds, limit)
        moment = self._clock()
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

    def release_migration(self, task_id: str, worker_id: str) -> bool:
        # Holder-scoped AND lease-live: neither a different worker nor an EXPIRED holder can clear a
        # live claim (an expired holder's authority lapsed with the lease).
        moment = self._clock()
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE migration_outbox SET claimed_by = NULL, lease_expires_at = NULL "
                "WHERE task_id = ? AND claimed_by = ? AND lease_expires_at > ?",
                (task_id, worker_id, moment),
            )
            return cursor.rowcount > 0

    def dead_letter_migration(self, task_id: str, worker_id: str, reason: str) -> bool:
        # Holder-scoped AND lease-live terminalization of a pending row the worker gave up on (#4).
        moment = self._clock()
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE migration_outbox SET status = 'dead', dead_reason = ?, claimed_by = NULL, "
                "lease_expires_at = NULL WHERE task_id = ? AND claimed_by = ? AND status = 'pending' "
                "AND lease_expires_at > ?",
                (reason, task_id, worker_id, moment),
            )
            return cursor.rowcount > 0

    def list_dead_migrations(self, limit: int = DEFAULT_ADMIN_PAGE_SIZE, after: str | None = None) -> list[dict[str, Any]]:
        return self._page("dead", "task_id, destination, sealed_envelope_json, status, attempt_count, created_at, dead_reason", limit, after)

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

    def time_floor(self) -> int:
        with self._connection() as connection:
            row = connection.execute("SELECT floor_at FROM time_floor WHERE singleton = 1").fetchone()
        return 0 if row is None else int(row["floor_at"])

    def database_now(self) -> int | None:
        return None

    def reset_time_floor(self, floor_at: int, reason: str) -> int:
        _validate_floor_reset(floor_at, reason)
        with self._lock, self._connection() as connection:
            row = connection.execute("SELECT floor_at FROM time_floor WHERE singleton = 1").fetchone()
            prior = 0 if row is None else int(row["floor_at"])
            now = int(time.time())
            connection.execute(
                "INSERT INTO time_floor (singleton, floor_at, updated_at) VALUES (1, ?, ?) "
                "ON CONFLICT (singleton) DO UPDATE SET floor_at = excluded.floor_at, updated_at = excluded.updated_at",
                (floor_at, now),
            )
            connection.execute(
                "INSERT INTO maintenance_log (at, action, detail_json) VALUES (?, 'time-floor-reset', ?)",
                (now, json.dumps({"prior": prior, "new": floor_at, "reason": reason}, sort_keys=True)),
            )
        return prior

    def maintenance_log(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute("SELECT id, at, action, detail_json FROM maintenance_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return _maintenance_rows(rows)

    def prune(self, nonce_cutoff: int, migration_cutoff: int, apply: bool = False, batch_size: int = MAX_PRUNE_BATCH) -> dict[str, Any]:
        def read(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
            with self._connection() as connection:
                return [dict(row) for row in connection.execute(sql, params).fetchall()]

        def batch_transaction(work):
            with self._lock:
                connection = self._connect()
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        result = work(connection.execute)
                        connection.execute("COMMIT")
                        return result
                    except BaseException:
                        connection.execute("ROLLBACK")
                        raise
                finally:
                    connection.close()

        return _run_sql_prune("?", read, batch_transaction, nonce_cutoff, migration_cutoff, apply, batch_size, _wall_clock)

    def capacity_report(self) -> dict[str, Any]:
        with self._connection() as connection:
            rows = {table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in _CAPACITY_TABLES}  # nosec B608 -- constant table names
            oldest = connection.execute("SELECT MIN(created_at) FROM migration_outbox WHERE status = 'pending'").fetchone()[0]
            floor = connection.execute("SELECT floor_at FROM time_floor WHERE singleton = 1").fetchone()
        size = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                size += os.path.getsize(str(self.path) + suffix)
            except OSError:
                pass
        try:
            free = shutil.disk_usage(os.path.dirname(os.path.abspath(str(self.path)))).free
        except OSError:
            free = None
        return {
            "backend": "sqlite",
            "rows": rows,
            "oldest_pending_migration_at": None if oldest is None else int(oldest),
            "database_bytes": size,
            "free_bytes": free,
            "time_floor": 0 if floor is None else int(floor[0]),
        }

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

    def checkpoint_owner(self, task_id: str) -> tuple[str | None, str | None] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT owner_issuer, owner_subject FROM checkpoints WHERE task_id = ?", (task_id,)
            ).fetchone()
            return None if row is None else (row["owner_issuer"], row["owner_subject"])

    def audit_head(self, task_id: str) -> tuple[str, int] | None:
        with self._connection() as connection:
            row = connection.execute("SELECT head_hash, sequence FROM audit_heads WHERE task_id = ?", (task_id,)).fetchone()
            return (row["head_hash"], int(row["sequence"])) if row is not None else None

    def verify_audit_chain_status(self, task_id: str, allow_legacy_anchor: bool = False) -> AuditVerificationResult:
        with self._connection() as connection:
            # Section 10 F3: read the events and the head from ONE snapshot. The connection is
            # autocommit (isolation_level=None), so without an explicit transaction each SELECT
            # sees its own snapshot and a writer committing between them made a healthy chain
            # report "stored audit head does not match". Under WAL a deferred read transaction
            # pins its snapshot at the first read and does not block writers. The `with
            # connection` exit ends it.
            connection.execute("BEGIN DEFERRED")
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
        first_details: Any = None
        for expected_sequence, row in enumerate(rows):
            if row["sequence"] != expected_sequence or row["previous_hash"] != previous:
                return AuditVerificationResult("invalid", "audit chain sequence or previous hash is inconsistent")
            try:
                details = json.loads(row["details_json"])
            except json.JSONDecodeError:
                return AuditVerificationResult("invalid", "audit event details are malformed")
            if expected_sequence == 0:
                first_details = details
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
        head_result = _verify_head_signature(
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
        return _check_migration_anchor(self._audit_head_verifier, head_result, first_details, allow_legacy_anchor)

    def verify_audit_chain(self, task_id: str) -> bool:
        return self.verify_audit_chain_status(task_id).valid

    # -- Section 10 PR B: audit-floor support (reads + the per-host marker) ------------------
    def audit_heads_for_host(self, host_id: str) -> list[tuple[str, str, int]]:
        with self._connection() as connection:
            rows = connection.execute("SELECT task_id, head_hash, sequence FROM audit_heads WHERE host_id = ?", (host_id,)).fetchall()
        return [(row["task_id"], row["head_hash"], int(row["sequence"])) for row in rows]

    def audit_event_hash(self, task_id: str, sequence: int) -> str | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT hash FROM audit_events WHERE task_id = ? AND sequence = ?", (task_id, sequence)
            ).fetchone()
        return None if row is None else row["hash"]

    def audit_floor_marker(self, host_id: str) -> tuple[int, bool] | None:
        with self._connection() as connection:
            row = connection.execute("SELECT epoch, pending FROM audit_floor_markers WHERE host_id = ?", (host_id,)).fetchone()
        return None if row is None else (int(row["epoch"]), bool(row["pending"]))

    def set_audit_floor_marker(self, host_id: str, epoch: int, pending: bool) -> None:
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO audit_floor_markers (host_id, epoch, pending, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT (host_id) DO UPDATE SET epoch = EXCLUDED.epoch, pending = EXCLUDED.pending, updated_at = EXCLUDED.updated_at",
                (host_id, epoch, pending, int(time.time())),
            )


class PostgresRuntimeStore:
    is_durable = True

    def __init__(
        self,
        dsn: str,
        audit_head_verifier: AuditHeadVerifier | None = None,
        schema: str = "public",
        clock: Callable[[], int] | None = None,
        timeouts: PostgresTimeouts | None = None,
    ) -> None:
        if not dsn:
            raise ValueError("Postgres DSN must not be empty")
        if not schema or "\x00" in schema:
            raise ValueError("Postgres schema must not be empty")
        self.dsn = dsn
        self.schema = schema
        # Section 12 #3: the bounds every connection below gets (see PostgresTimeouts).
        self.timeouts = timeouts if timeouts is not None else PostgresTimeouts()
        self._audit_head_verifier = audit_head_verifier
        # Section 4 #3: the lease OPERATIONS on Postgres use DATABASE time (clock_timestamp(), see the
        # lease-methods class note), NOT this clock -- so multiple dispatcher hosts with skewed clocks
        # cannot break lease exclusivity. `clock` is accepted for constructor uniformity with the
        # embedded stores and may be injected by a test, but it does NOT govern Postgres lease timing.
        self._clock: Callable[[], int] = clock or _wall_clock
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
        # Section 12 #3: bounded like every connection, with the longer schema-migration bounds, so
        # a start behind another process's migration waits a finite time for the advisory lock.
        with _bounded_postgres_connect(self.dsn, self.timeouts.for_schema_migration(), row_factory=rows.dict_row) as connection:
            connection.execute("SELECT pg_advisory_lock(%s)", (lock_key,))
            connection.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(self.schema)))
            connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(self.schema)))
            self._initialize(connection)
            connection.commit()

    def _connect(self):
        _psycopg, rows, sql, _ = _postgres_modules()
        connection = _bounded_postgres_connect(self.dsn, self.timeouts, row_factory=rows.dict_row)
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
        # PM-001 (schema v12): the owner of a task -- the permit issuer and subject of its FIRST
        # admission. Existing rows stay NULL, and an OPEN row with no owner refuses to resume: the
        # owner cannot be reconstructed (the audit trail records the agent, never the issuer), so
        # letting the first caller claim it would preserve the very takeover this closes.
        connection.execute("ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS owner_issuer TEXT")
        connection.execute("ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS owner_subject TEXT")
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
        # Section 5 #3 (schema v7): durable task cancellation. Presence of a row means the
        # task is cancelled; the approval gate reads it inside the nonce-consume transaction
        # (FOR the atomic redeem-vs-cancel race) and again just before the tool launches.
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS task_cancellations (
                task_id TEXT PRIMARY KEY,
                cancelled_at BIGINT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS tool_effects (
                effect_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                state TEXT NOT NULL,
                arguments_json TEXT NOT NULL,
                result_json TEXT,
                reason TEXT,
                created_at BIGINT NOT NULL,
                updated_at BIGINT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_tool_effects_task ON tool_effects (task_id)"
        )
        # Section 7 PR 2 (round 3, schema v9): OWNED reconcile lease -- who holds the current claim and
        # when it expires -- so a stale/expired reconciler cannot settle or reset a newer claim. Both
        # nullable; ADD COLUMN IF NOT EXISTS upgrades an existing (v8) store idempotently.
        connection.execute("ALTER TABLE tool_effects ADD COLUMN IF NOT EXISTS reconcile_claim_id TEXT")
        connection.execute("ALTER TABLE tool_effects ADD COLUMN IF NOT EXISTS reconcile_lease_expires_at BIGINT")
        # Section 10 PR B (schema v10): the audit-floor "initialized" marker, one row per host.
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_floor_markers (
                host_id TEXT PRIMARY KEY,
                epoch BIGINT NOT NULL,
                pending BOOLEAN NOT NULL DEFAULT FALSE,
                updated_at BIGINT NOT NULL
            )
            """
        )
        # Section 12 (schema v11). #4: nonce authorization expiry, delivery time, maintenance log. #6: the
        # durable time floor, seeded (once) from the newest past timestamp already stored.
        connection.execute("ALTER TABLE consumed_nonces ADD COLUMN IF NOT EXISTS expires_at BIGINT")
        connection.execute("ALTER TABLE migration_outbox ADD COLUMN IF NOT EXISTS delivered_at BIGINT")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS maintenance_log (
                id BIGSERIAL PRIMARY KEY,
                at BIGINT NOT NULL,
                action TEXT NOT NULL,
                detail_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS time_floor (
                singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
                floor_at BIGINT NOT NULL,
                updated_at BIGINT NOT NULL
            )
            """
        )
        seed_terms = ", ".join(f"(SELECT MAX({column}) FROM {table})" for table, column in _TIME_FLOOR_SEED_COLUMNS)  # nosec B608 -- constant identifiers
        connection.execute(
            f"INSERT INTO time_floor (singleton, floor_at, updated_at) "  # nosec B608 -- constant identifiers
            f"SELECT TRUE, COALESCE(GREATEST({seed_terms}), 0), COALESCE(GREATEST({seed_terms}), 0) "
            f"ON CONFLICT (singleton) DO NOTHING"
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

    def _page(self, status: str, columns: str, limit: int, after: str | None) -> list[dict[str, Any]]:
        _validate_page(limit, after)
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {columns} FROM migration_outbox WHERE status = %s AND task_id > %s ORDER BY task_id LIMIT %s",  # nosec B608 -- constant columns
                (status, after or "", limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def list_pending_migrations(self, limit: int = DEFAULT_ADMIN_PAGE_SIZE, after: str | None = None) -> list[dict[str, Any]]:
        return self._page("pending", "task_id, destination, sealed_envelope_json, status, attempt_count, created_at, claimed_by, lease_expires_at", limit, after)

    def get_migration_receipt(self, task_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT receipt_json FROM migration_receipts WHERE task_id = %s", (task_id,)
            ).fetchone()
        return None if row is None else json.loads(row["receipt_json"])

    def replace_migration_receipt(self, task_id: str, receipt_json: str) -> None:
        # Overwrite only the receipt body (regenerated attestation + signature); created_at and every
        # binding stay put. The single UPDATE takes the row lock, so concurrent regenerations are
        # last-write-wins over equally-valid receipts, never a partial write.
        with self._connect() as connection:
            connection.execute(
                "UPDATE migration_receipts SET receipt_json = %s WHERE task_id = %s",
                (receipt_json, task_id),
            )

    def mark_migration_delivered(self, task_id: str, receipt_json: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE migration_outbox SET status = 'delivered', receipt_json = %s, delivered_at = EXTRACT(EPOCH FROM clock_timestamp())::bigint WHERE task_id = %s",
                (receipt_json, task_id),
            )

    def cancel_task(self, task_id: str) -> None:
        # Idempotent: a repeat cancel keeps the first cancelled_at. Presence = cancelled. Takes the
        # per-task advisory xact lock so a cancel racing an in-flight redemption serializes with the
        # approval gate's own check (see _PostgresTransaction.is_task_cancelled) -- the two cannot
        # both succeed.
        with self._connect() as connection:
            connection.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (task_id,))
            connection.execute(
                "INSERT INTO task_cancellations (task_id, cancelled_at) VALUES (%s, %s) "
                "ON CONFLICT (task_id) DO NOTHING",
                (task_id, int(time.time())),
            )

    def is_task_cancelled(self, task_id: str) -> bool:
        # The pre-launch re-check reads under the same advisory lock, so a cancel committed by the
        # time the tool is about to launch is always observed here.
        with self._connect() as connection:
            connection.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (task_id,))
            row = connection.execute(
                "SELECT 1 FROM task_cancellations WHERE task_id = %s",
                (task_id,),
            ).fetchone()
        return row is not None

    def get_effect(self, effect_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT effect_id, task_id, tool, state, arguments_json, result_json, reason, "
                "created_at, updated_at, reconcile_claim_id, reconcile_lease_expires_at "
                "FROM tool_effects WHERE effect_id = %s",
                (effect_id,),
            ).fetchone()
        return None if row is None else dict(row)

    def record_effect_prepared(self, effect_id: str, task_id: str, tool: str, arguments_json: str) -> None:
        # Keyed by the effect_id PRIMARY KEY; idempotent on it. The host serializes effect writes per
        # task in its run loop, so no per-task advisory lock is needed (unlike cancellation, which
        # races the approval redemption).
        now = int(time.time())
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO tool_effects "
                "(effect_id, task_id, tool, state, arguments_json, result_json, reason, created_at, updated_at) "
                "VALUES (%s, %s, %s, 'prepared', %s, NULL, NULL, %s, %s) "
                "ON CONFLICT (effect_id) DO NOTHING",
                (effect_id, task_id, tool, arguments_json, now, now),
            )

    def mark_effect_started(self, effect_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE tool_effects SET state = 'started', updated_at = %s "
                "WHERE effect_id = %s AND state = 'prepared'",
                (int(time.time()), effect_id),
            )

    def settle_effect(self, effect_id: str, state: str, result_json: str | None, reason: str | None) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE tool_effects SET state = %s, result_json = %s, reason = %s, updated_at = %s "
                "WHERE effect_id = %s",
                (state, result_json, reason, int(time.time()), effect_id),
            )

    def claim_effect_for_reconcile(self, effect_id: str, claim_id: str, lease_seconds: int) -> bool:
        # Lease creation + eligibility use DATABASE time (clock_timestamp), not the app host clock, so a
        # host whose clock runs ahead cannot prematurely reclaim another host's live reconcile claim.
        _validate_reconcile_claim_args(claim_id, lease_seconds)
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE tool_effects SET state = 'reconciling', reconcile_claim_id = %s, "
                "reconcile_lease_expires_at = EXTRACT(EPOCH FROM clock_timestamp())::bigint + %s, "
                "updated_at = EXTRACT(EPOCH FROM clock_timestamp())::bigint "
                "WHERE effect_id = %s AND (state = 'unknown' OR (state = 'reconciling' "
                "AND (reconcile_lease_expires_at IS NULL "
                "OR reconcile_lease_expires_at <= EXTRACT(EPOCH FROM clock_timestamp())::bigint)))",
                (claim_id, lease_seconds, effect_id),
            )
            return cursor.rowcount == 1

    def settle_effect_from_claim(self, effect_id: str, claim_id: str, new_state: str, result_json: str | None, reason: str | None) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE tool_effects SET state = %s, result_json = %s, reason = %s, "
                "reconcile_claim_id = NULL, reconcile_lease_expires_at = NULL, "
                "updated_at = EXTRACT(EPOCH FROM clock_timestamp())::bigint "
                "WHERE effect_id = %s AND state = 'reconciling' AND reconcile_claim_id = %s "
                "AND reconcile_lease_expires_at > EXTRACT(EPOCH FROM clock_timestamp())::bigint",
                (new_state, result_json, reason, effect_id, claim_id),
            )
            return cursor.rowcount == 1

    def release_effect_claim(self, effect_id: str, claim_id: str) -> bool:
        # Claim match only, NOT lease-live (an expired holder relinquishing to `unknown` is safe).
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE tool_effects SET state = 'unknown', result_json = NULL, "
                "reason = 'reconcile failed; claim released', reconcile_claim_id = NULL, "
                "reconcile_lease_expires_at = NULL, updated_at = EXTRACT(EPOCH FROM clock_timestamp())::bigint "
                "WHERE effect_id = %s AND state = 'reconciling' AND reconcile_claim_id = %s",
                (effect_id, claim_id),
            )
            return cursor.rowcount == 1

    def renew_effect_claim(self, effect_id: str, claim_id: str, lease_seconds: int) -> bool:
        # New lease expiry uses DATABASE time (clock_timestamp), not the app host clock, so a host whose
        # clock runs fast cannot extend past what the DB will honour. Claim match only (no live-lease
        # requirement): still-owned -> safe to extend; a reclaimer's different claim_id -> no row.
        _validate_reconcile_claim_args(claim_id, lease_seconds)
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE tool_effects SET "
                "reconcile_lease_expires_at = EXTRACT(EPOCH FROM clock_timestamp())::bigint + %s, "
                "updated_at = EXTRACT(EPOCH FROM clock_timestamp())::bigint "
                "WHERE effect_id = %s AND state = 'reconciling' AND reconcile_claim_id = %s",
                (lease_seconds, effect_id, claim_id),
            )
            return cursor.rowcount == 1

    # Section 4 #3 (round 3): every lease comparison and every new-lease expiry on Postgres is
    # computed from DATABASE time -- EXTRACT(EPOCH FROM clock_timestamp())::bigint -- NOT the
    # dispatcher host's clock (self._clock, which governs only the embedded SQLite/InMemory stores).
    # With a shared central DB, judging a committed lease against a per-host clock lets a host whose
    # clock runs ahead classify a still-live lease as expired and reclaim a row another worker holds
    # (SKIP LOCKED serializes the statements but not the clock they read). Using the single DB clock
    # for eligibility, expiry, and release/dead-letter/attempt authority closes that cross-host break.
    # The SQL below is STATIC (no f-strings / formatting / user data) -- the DB-time expression is a
    # literal, and every value is a bound %s parameter -- so there is no injection surface.

    def record_migration_attempt(self, task_id: str, worker_id: str | None = None) -> None:
        with self._connect() as connection:
            if worker_id is None:
                connection.execute("UPDATE migration_outbox SET attempt_count = attempt_count + 1 WHERE task_id = %s", (task_id,))
            else:
                connection.execute(
                    "UPDATE migration_outbox SET attempt_count = attempt_count + 1 "
                    "WHERE task_id = %s AND claimed_by = %s "
                    "AND lease_expires_at > EXTRACT(EPOCH FROM clock_timestamp())::bigint",
                    (task_id, worker_id),
                )

    def claim_migrations(
        self, worker_id: str, lease_seconds: int, limit: int = 1
    ) -> list[dict[str, Any]]:
        # FOR UPDATE SKIP LOCKED is the standard Postgres queue claim: concurrent claimers lock
        # disjoint rows and skip each other's, so no row is handed to two workers and claimers don't
        # block. Eligibility and the new lease expiry are both computed from DB time (see class note).
        _validate_claim_args(worker_id, lease_seconds, limit)
        with self._connect() as connection:
            rows = connection.execute(
                """
                UPDATE migration_outbox
                SET claimed_by = %s,
                    lease_expires_at = EXTRACT(EPOCH FROM clock_timestamp())::bigint + %s
                WHERE task_id IN (
                    SELECT task_id FROM migration_outbox
                    WHERE status = 'pending'
                      AND (claimed_by IS NULL
                           OR lease_expires_at <= EXTRACT(EPOCH FROM clock_timestamp())::bigint)
                    ORDER BY created_at, task_id
                    FOR UPDATE SKIP LOCKED
                    LIMIT %s
                )
                RETURNING task_id, destination, sealed_envelope_json, status, attempt_count,
                          created_at, claimed_by, lease_expires_at, dead_reason
                """,
                (worker_id, lease_seconds, limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def release_migration(self, task_id: str, worker_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE migration_outbox SET claimed_by = NULL, lease_expires_at = NULL "
                "WHERE task_id = %s AND claimed_by = %s "
                "AND lease_expires_at > EXTRACT(EPOCH FROM clock_timestamp())::bigint",
                (task_id, worker_id),
            )
            return cursor.rowcount > 0

    def dead_letter_migration(self, task_id: str, worker_id: str, reason: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE migration_outbox SET status = 'dead', dead_reason = %s, claimed_by = NULL, "
                "lease_expires_at = NULL WHERE task_id = %s AND claimed_by = %s AND status = 'pending' "
                "AND lease_expires_at > EXTRACT(EPOCH FROM clock_timestamp())::bigint",
                (reason, task_id, worker_id),
            )
            return cursor.rowcount > 0

    def list_dead_migrations(self, limit: int = DEFAULT_ADMIN_PAGE_SIZE, after: str | None = None) -> list[dict[str, Any]]:
        return self._page("dead", "task_id, destination, sealed_envelope_json, status, attempt_count, created_at, dead_reason", limit, after)

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

    def time_floor(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT floor_at FROM time_floor WHERE singleton").fetchone()
        return 0 if row is None else int(row["floor_at"])

    def database_now(self) -> int | None:
        # Section 12 #6: the database clock is the shared authority for the Postgres time floor.
        with self._connect() as connection:
            return int(connection.execute("SELECT EXTRACT(EPOCH FROM clock_timestamp())::bigint AS now").fetchone()["now"])

    def reset_time_floor(self, floor_at: int, reason: str) -> int:
        _validate_floor_reset(floor_at, reason)
        with self._connect() as connection:
            row = connection.execute("SELECT floor_at FROM time_floor WHERE singleton FOR UPDATE").fetchone()
            prior = 0 if row is None else int(row["floor_at"])
            connection.execute(
                "INSERT INTO time_floor (singleton, floor_at, updated_at) VALUES (TRUE, %s, EXTRACT(EPOCH FROM clock_timestamp())::bigint) "
                "ON CONFLICT (singleton) DO UPDATE SET floor_at = EXCLUDED.floor_at, updated_at = EXCLUDED.updated_at",
                (floor_at,),
            )
            connection.execute(
                "INSERT INTO maintenance_log (at, action, detail_json) VALUES (EXTRACT(EPOCH FROM clock_timestamp())::bigint, 'time-floor-reset', %s)",
                (json.dumps({"prior": prior, "new": floor_at, "reason": reason}, sort_keys=True),),
            )
        return prior

    def maintenance_log(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT id, at, action, detail_json FROM maintenance_log ORDER BY id DESC LIMIT %s", (limit,)).fetchall()
        return _maintenance_rows(rows)

    def prune(self, nonce_cutoff: int, migration_cutoff: int, apply: bool = False, batch_size: int = MAX_PRUNE_BATCH) -> dict[str, Any]:
        def read(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
            with self._connect() as connection:
                return [dict(row) for row in connection.execute(sql, params).fetchall()]

        def batch_transaction(work):
            # `with connection` commits on success and rolls back on an exception (psycopg 3).
            with self._connect() as connection:
                return work(connection.execute)

        return _run_sql_prune("%s", read, batch_transaction, nonce_cutoff, migration_cutoff, apply, batch_size, self.database_now)

    def capacity_report(self) -> dict[str, Any]:
        with self._connect() as connection:
            rows = {table: int(connection.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]) for table in _CAPACITY_TABLES}  # nosec B608 -- constant table names
            oldest = connection.execute("SELECT MIN(created_at) AS oldest FROM migration_outbox WHERE status = 'pending'").fetchone()["oldest"]
            size = connection.execute(
                "SELECT COALESCE(SUM(pg_total_relation_size(c.oid)), 0) AS bytes FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = %s AND c.relkind IN ('r', 'p')",
                (self.schema,),
            ).fetchone()["bytes"]
            floor = connection.execute("SELECT floor_at FROM time_floor WHERE singleton").fetchone()
        return {
            "backend": "postgres",
            "rows": rows,
            "oldest_pending_migration_at": None if oldest is None else int(oldest),
            "database_bytes": int(size),
            # Free space belongs to the database server's filesystem; Portmark cannot see it. Monitor it
            # on the server (DEPLOYMENT.md).
            "free_bytes": None,
            "time_floor": 0 if floor is None else int(floor["floor_at"]),
        }

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

    def checkpoint_owner(self, task_id: str) -> tuple[str | None, str | None] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT owner_issuer, owner_subject FROM checkpoints WHERE task_id = %s", (task_id,)
            ).fetchone()
            return None if row is None else (row["owner_issuer"], row["owner_subject"])

    def audit_head(self, task_id: str) -> tuple[str, int] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT head_hash, sequence FROM audit_heads WHERE task_id = %s", (task_id,)).fetchone()
            return (row["head_hash"], int(row["sequence"])) if row is not None else None

    def verify_audit_chain_status(self, task_id: str, allow_legacy_anchor: bool = False) -> AuditVerificationResult:
        psycopg, _, _, _ = _postgres_modules()
        with self._connect() as connection:
            # Section 10 F3: READ COMMITTED takes a new snapshot per statement, so a writer
            # committing between the two SELECTs made a healthy chain report "stored audit head
            # does not match". End the transaction _connect opened for SET search_path (a
            # session-level setting, it survives the commit), then read both inside one
            # REPEATABLE READ, READ ONLY transaction: one snapshot for events and head.
            connection.commit()
            connection.isolation_level = psycopg.IsolationLevel.REPEATABLE_READ
            connection.read_only = True
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
        first_details: Any = None
        for expected_sequence, row in enumerate(rows):
            if row["sequence"] != expected_sequence or row["previous_hash"] != previous:
                return AuditVerificationResult("invalid", "audit chain sequence or previous hash is inconsistent")
            try:
                details = json.loads(row["details_json"])
            except json.JSONDecodeError:
                return AuditVerificationResult("invalid", "audit event details are malformed")
            if expected_sequence == 0:
                first_details = details
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
        head_result = _verify_head_signature(
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
        return _check_migration_anchor(self._audit_head_verifier, head_result, first_details, allow_legacy_anchor)

    def verify_audit_chain(self, task_id: str) -> bool:
        return self.verify_audit_chain_status(task_id).valid

    # -- Section 10 PR B: audit-floor support (reads + the per-host marker) ------------------
    def audit_heads_for_host(self, host_id: str) -> list[tuple[str, str, int]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT task_id, head_hash, sequence FROM audit_heads WHERE host_id = %s", (host_id,)).fetchall()
        return [(row["task_id"], row["head_hash"], int(row["sequence"])) for row in rows]

    def audit_event_hash(self, task_id: str, sequence: int) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT hash FROM audit_events WHERE task_id = %s AND sequence = %s", (task_id, sequence)
            ).fetchone()
        return None if row is None else row["hash"]

    def audit_floor_marker(self, host_id: str) -> tuple[int, bool] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT epoch, pending FROM audit_floor_markers WHERE host_id = %s", (host_id,)).fetchone()
        return None if row is None else (int(row["epoch"]), bool(row["pending"]))

    def set_audit_floor_marker(self, host_id: str, epoch: int, pending: bool) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO audit_floor_markers (host_id, epoch, pending, updated_at) VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (host_id) DO UPDATE SET epoch = EXCLUDED.epoch, pending = EXCLUDED.pending, updated_at = EXCLUDED.updated_at",
                (host_id, epoch, pending, int(time.time())),
            )


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

    def consume_nonce(self, nonce: str, subject: str, audience: str, task_id: str, expires_at: int | None = None) -> None:
        if self._connection is None:
            raise RuntimeError("Postgres transaction was not opened")
        _, _, _, errors = _postgres_modules()
        try:
            self._connection.execute(
                "INSERT INTO consumed_nonces (nonce, subject, audience, task_id, consumed_at, expires_at) VALUES (%s, %s, %s, %s, %s, %s)",
                (nonce, subject, audience, task_id, int(time.time()), _checked_expiry(expires_at)),
            )
        except errors.UniqueViolation as error:
            raise SecurityError("permit nonce has already been consumed") from error

    def advance_time_floor(self, now: int) -> int | None:
        # Section 12 #6: the DATABASE clock is the shared authority (`now` from the host is ignored).
        # Every host's checkpoint save rides this in its own transaction, so it must never wait on the
        # singleton row: SKIP LOCKED makes a save whose floor row another transaction is already
        # advancing skip the update instead of blocking (and failing under lock_timeout). Monotonic by
        # the WHERE clause; at most once per cadence.
        if self._connection is None:
            raise RuntimeError("Postgres transaction was not opened")
        cursor = self._connection.execute(
            "UPDATE time_floor SET floor_at = EXTRACT(EPOCH FROM clock_timestamp())::bigint, updated_at = EXTRACT(EPOCH FROM clock_timestamp())::bigint "
            "WHERE singleton AND floor_at <= EXTRACT(EPOCH FROM clock_timestamp())::bigint - %s "
            "AND singleton IN (SELECT singleton FROM time_floor WHERE singleton FOR UPDATE SKIP LOCKED) "
            "RETURNING floor_at",
            (TIME_FLOOR_CADENCE_SECONDS,),
        )
        row = cursor.fetchone()
        return None if row is None else int(row["floor_at"])

    def is_task_cancelled(self, task_id: str) -> bool:
        # Take the per-task advisory xact lock (same key cancel_task uses) so redeem and cancel
        # serialize: whichever grabs the lock first wins, and the loser observes the winner. Held
        # until this approval transaction commits or rolls back, so the check is atomic with the
        # consume_nonce above -- a cancel that wins the lock makes this return True and rolls the
        # redeem back; a redeem that wins commits first and the pre-launch re-check catches a later
        # cancel.
        if self._connection is None:
            raise RuntimeError("Postgres transaction was not opened")
        self._connection.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (task_id,))
        row = self._connection.execute(
            "SELECT 1 FROM task_cancellations WHERE task_id = %s",
            (task_id,),
        ).fetchone()
        return row is not None

    def audit_head(self, task_id: str) -> tuple[str, int] | None:
        if self._connection is None:
            raise RuntimeError("Postgres transaction was not opened")
        row = self._connection.execute("SELECT head_hash, sequence FROM audit_heads WHERE task_id = %s", (task_id,)).fetchone()
        return None if row is None else (row["head_hash"], int(row["sequence"]))

    def audit_event_hash(self, task_id: str, sequence: int) -> str | None:
        if self._connection is None:
            raise RuntimeError("Postgres transaction was not opened")
        row = self._connection.execute(
            "SELECT hash FROM audit_events WHERE task_id = %s AND sequence = %s", (task_id, sequence)
        ).fetchone()
        return None if row is None else row["hash"]

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

    def save_checkpoint(self, task_id: str, state: AgentState, expected_generation: int, closed: bool = False, owner: tuple[str, str] | None = None) -> int:
        if self._connection is None:
            raise RuntimeError("Postgres transaction was not opened")
        row = self._connection.execute(
            "SELECT generation, closed, owner_issuer, owner_subject FROM checkpoints WHERE task_id = %s", (task_id,)
        ).fetchone()
        if row is None:
            if expected_generation != 0:
                raise SecurityError("stale checkpoint generation")
            new_generation = 1
            result = self._connection.execute(
                """
                INSERT INTO checkpoints (task_id, status, checkpoint_json, generation, closed, updated_at, owner_issuer, owner_subject)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (task_id) DO NOTHING
                RETURNING generation
                """,
                (
                    task_id, state.status, self._checkpoint_json(state, new_generation), new_generation,
                    bool(closed), int(time.time()),
                    # PM-001: the owner is recorded on the CREATE, inside the admission transaction.
                    owner[0] if owner else None, owner[1] if owner else None,
                ),
            ).fetchone()
            if result is None:
                raise SecurityError("stale checkpoint generation")
            return new_generation
        if row["closed"]:
            raise SecurityError("task checkpoint is closed")
        # PM-001: ownership is compared in the same transaction as the generation CAS, and the
        # UPDATE below never rewrites the owner columns.
        _check_owner((row["owner_issuer"], row["owner_subject"]), owner)
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
        return PostgresRuntimeStore(str(location), audit_head_verifier, timeouts=PostgresTimeouts.from_environment())
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

    def consume_nonce(self, nonce: str, subject: str, audience: str, task_id: str, expires_at: int | None = None) -> None:
        if self._connection is None:
            raise RuntimeError("SQLite transaction was not opened")
        try:
            self._connection.execute(
                "INSERT INTO consumed_nonces (nonce, subject, audience, task_id, consumed_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                (nonce, subject, audience, task_id, int(time.time()), _checked_expiry(expires_at)),
            )
        except sqlite3.IntegrityError as error:
            raise SecurityError("permit nonce has already been consumed") from error

    def advance_time_floor(self, now: int) -> int | None:
        # Inside the open BEGIN IMMEDIATE write transaction, which already serializes writers, so this
        # UPDATE never waits on another one. Monotonic by the WHERE clause; at most once per cadence.
        if self._connection is None:
            raise RuntimeError("SQLite transaction was not opened")
        cursor = self._connection.execute(
            "UPDATE time_floor SET floor_at = ?, updated_at = ? WHERE singleton = 1 AND floor_at <= ?",
            (int(now), int(now), int(now) - TIME_FLOOR_CADENCE_SECONDS),
        )
        return int(now) if cursor.rowcount > 0 else None

    def is_task_cancelled(self, task_id: str) -> bool:
        # Read within the open BEGIN IMMEDIATE write transaction so the redeem (consume_nonce)
        # and the cancel check commit or roll back together -- a cancel that lands first is seen
        # here and rolls the redeem back; one that lands after is caught by the pre-launch re-check.
        if self._connection is None:
            raise RuntimeError("SQLite transaction was not opened")
        row = self._connection.execute(
            "SELECT 1 FROM task_cancellations WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        return row is not None

    def audit_head(self, task_id: str) -> tuple[str, int] | None:
        if self._connection is None:
            raise RuntimeError("SQLite transaction was not opened")
        row = self._connection.execute("SELECT head_hash, sequence FROM audit_heads WHERE task_id = ?", (task_id,)).fetchone()
        return None if row is None else (row["head_hash"], int(row["sequence"]))

    def audit_event_hash(self, task_id: str, sequence: int) -> str | None:
        if self._connection is None:
            raise RuntimeError("SQLite transaction was not opened")
        row = self._connection.execute(
            "SELECT hash FROM audit_events WHERE task_id = ? AND sequence = ?", (task_id, sequence)
        ).fetchone()
        return None if row is None else row["hash"]

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

    def save_checkpoint(self, task_id: str, state: AgentState, expected_generation: int, closed: bool = False, owner: tuple[str, str] | None = None) -> int:
        if self._connection is None:
            raise RuntimeError("SQLite transaction was not opened")
        row = self._connection.execute(
            "SELECT generation, closed, owner_issuer, owner_subject FROM checkpoints WHERE task_id = ?", (task_id,)
        ).fetchone()
        if row is None:
            if expected_generation != 0:
                raise SecurityError("stale checkpoint generation")
            new_generation = 1
            cursor = self._connection.execute(
                """
                INSERT INTO checkpoints (task_id, status, checkpoint_json, generation, closed, updated_at, owner_issuer, owner_subject)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO NOTHING
                """,
                (
                    task_id, state.status, self._checkpoint_json(state, new_generation), new_generation,
                    1 if closed else 0, int(time.time()),
                    # PM-001: the owner is recorded on the CREATE, inside the admission transaction.
                    owner[0] if owner else None, owner[1] if owner else None,
                ),
            )
            if cursor.rowcount != 1:
                raise SecurityError("stale checkpoint generation")
            return new_generation
        if row["closed"]:
            raise SecurityError("task checkpoint is closed")
        # PM-001: ownership is compared in the same transaction as the generation CAS, and the
        # UPDATE below never rewrites the owner columns.
        _check_owner((row["owner_issuer"], row["owner_subject"]), owner)
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


# The anchor a pre-Section-10 host wrote (exactly these keys), and the source proof a Section 10
# anchor carries in addition. Any other key set is malformed, never "legacy".
_LEGACY_ANCHOR_FIELDS = ("previous_audit_hash", "previous_audit_sequence", "previous_audit_host_id")
_ANCHOR_PROOF_FIELDS = ("previous_audit_task_id", "previous_audit_signature_key_id", "previous_audit_signature")

LEGACY_ANCHOR_REFUSED_REASON = (
    "migration anchor predates the kept source proof (legacy-anchor): the source signature cannot be "
    "independently reverified; pass --allow-legacy-anchor only to accept it for migration compatibility"
)
LEGACY_ANCHOR_ALLOWED_REASON = (
    "legacy migration anchor accepted by --allow-legacy-anchor: the source proof was NOT independently "
    "reverified (compatibility mode, not an equivalent security mode)"
)


def _check_migration_anchor(
    verifier: AuditHeadVerifier | None, head_result: AuditVerificationResult, first_details: Any, allow_legacy_anchor: bool = False
) -> AuditVerificationResult:
    """Re-verify a migration anchor from this database alone (Section 10 F2).

    A migration admission records the source's signed audit head in event 0's details
    (`host._audit_start`). The anchor is inside the hashed, head-signed chain, so it cannot be
    altered or stripped without breaking the destination's own signature -- this check adds
    that the SOURCE's proof is still authentic under the current trust registry. The source
    signed a v1 head for the "migration" purpose, so it is evaluated under the v1 historical
    policy with that usage: a source key revoked since is reported, not silently accepted.

    A complete pre-Section-10 anchor (exactly the three legacy keys, well formed) carries no
    proof to re-check. It is `unverifiable` by default; `allow_legacy_anchor` accepts it as
    `valid` for migration compatibility, but it is never relabelled `verified`. The flag never
    rescues a partial or malformed anchor: those are `invalid`.
    """
    if not head_result.valid:
        return head_result
    anchor = first_details.get("migration") if isinstance(first_details, dict) else None
    if anchor is None:
        return replace(head_result, anchor_status="none")
    if not isinstance(anchor, dict) or set(anchor) not in (set(_LEGACY_ANCHOR_FIELDS), set(_LEGACY_ANCHOR_FIELDS + _ANCHOR_PROOF_FIELDS)):
        return AuditVerificationResult("invalid", "migration anchor proof is incomplete or malformed", head_result.head_status, "invalid")
    is_legacy = set(anchor) == set(_LEGACY_ANCHOR_FIELDS)
    head_hash = anchor.get("previous_audit_hash")
    sequence = anchor.get("previous_audit_sequence")
    fields = _LEGACY_ANCHOR_FIELDS if is_legacy else _LEGACY_ANCHOR_FIELDS + _ANCHOR_PROOF_FIELDS
    strings = [anchor.get(field) for field in fields if field != "previous_audit_sequence"]
    if (
        not all(isinstance(value, str) and value for value in strings)
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence <= 0
    ):
        return AuditVerificationResult("invalid", "migration anchor proof is incomplete or malformed", head_result.head_status, "invalid")
    if is_legacy:
        if allow_legacy_anchor:
            return AuditVerificationResult("valid", LEGACY_ANCHOR_ALLOWED_REASON, head_result.head_status, "legacy-anchor")
        return AuditVerificationResult("unverifiable", LEGACY_ANCHOR_REFUSED_REASON, head_result.head_status, "legacy-anchor")
    if verifier is None:  # unreachable: a valid head_result required a verifier
        return AuditVerificationResult("unverifiable", "trust registry is not configured", head_result.head_status, "unverifiable")
    # debt: v1-only anchor payload (correct because host.py signs the migration handoff head
    # without signed_at); upgrade when the handoff head is signed as v2 -- then store the
    # anchor's signed_at and rebuild with _audit_head_payload_for, or every new anchor reports invalid.
    payload = audit_head_payload(anchor["previous_audit_task_id"], anchor["previous_audit_host_id"], str(head_hash), sequence)
    try:
        evaluation = verifier.evaluate_audit_head(
            anchor["previous_audit_signature_key_id"], payload, anchor["previous_audit_signature"], required_usage="migration"
        )
    except SecurityError as error:
        return AuditVerificationResult("unverifiable", str(error), head_result.head_status, "registry-unavailable")
    if not evaluation.ok:
        return AuditVerificationResult(
            "invalid",
            f"migration anchor proof failed ({evaluation.head_status}): {evaluation.detail}",
            head_result.head_status,
            "invalid",
        )
    return replace(head_result, anchor_status="verified")

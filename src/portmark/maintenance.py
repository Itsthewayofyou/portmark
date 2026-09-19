"""Operator maintenance: retention (Section 12 #4, owner decision D2) and the time floor (#6, D3).

`portmark store prune` deletes only rows that are provably no longer needed, and only when asked:

- A consumed nonce protects against replaying its authorization until that authorization expires. Its
  expiry is stored with it at consumption time. It is prunable once that expiry is older than the
  retention cutoff AND older than "now minus the clock tolerance" -- the most the trusted clock can be
  wrong without failing closed -- so no clock error within the tolerance can revive an authorization
  whose nonce is gone. Rows from before the expiry was stored are kept (they cannot be proven safe).
- A delivered migration outbox row is prunable once it is `delivered`, carries the verified destination
  receipt on the row, and was delivered before the cutoff. Pending and dead rows are always kept.

Everything else is evidence and is never pruned. A prune refuses to run while the clock is behind the
durable time floor, is a dry run unless `--apply`, works in bounded batches, never VACUUMs, and writes a
maintenance-log record per batch plus a summary.
"""

from __future__ import annotations

import datetime as _datetime
from typing import Any

from ._clock import TrustedClock, check_time_floor, default_clock
from .storage import MAX_PRUNE_BATCH


def parse_cutoff(value: str) -> int:
    """Epoch seconds, or an ISO-8601 date/time (UTC when no offset is given)."""
    text = value.strip()
    if text.isdigit():
        return int(text)
    try:
        moment = _datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"cutoff must be epoch seconds or an ISO-8601 date/time, got {value!r}") from error
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=_datetime.timezone.utc)
    return int(moment.timestamp())


def prune_cutoffs(before: int, now: int, tolerance: int) -> tuple[int, int]:
    """(nonce_cutoff, migration_cutoff) for a retention cutoff `before`. Refuses a cutoff in the future."""
    if before > now:
        raise ValueError(f"the cutoff {before} is in the future (now {now}); a prune only removes the past")
    return min(before, now - tolerance), before


def run_prune(store: Any, witness: Any, before: int, apply: bool = False, batch_size: int = MAX_PRUNE_BATCH, clock: TrustedClock | None = None) -> dict[str, Any]:
    clock = clock if clock is not None else default_clock()
    # A prune relies on the clock (expired = older than now - tolerance), so it runs only when the
    # clock is not behind the durable time floor -- the same check a host start performs.
    check_time_floor(store, witness, clock)
    nonce_cutoff, migration_cutoff = prune_cutoffs(before, clock.now(), clock.tolerance_seconds)
    report = store.prune(nonce_cutoff, migration_cutoff, apply=apply, batch_size=batch_size)
    report["clock_tolerance_seconds"] = clock.tolerance_seconds
    return report


def time_floor_status(store: Any, witness: Any, clock: TrustedClock | None = None) -> dict[str, Any]:
    clock = clock if clock is not None else default_clock()
    return {
        "database_floor": store.time_floor(),
        "mirrored_floor": None if witness is None else witness.witnessed_time_floor(),
        "host_now": clock.now(),
        "database_now": store.database_now(),
        "tolerance_seconds": clock.tolerance_seconds,
    }


def reset_time_floor(store: Any, witness: Any, floor_at: int, reason: str, at: int) -> dict[str, Any]:
    """Operator recovery ONLY: set the database floor and (if configured) the mirrored floor to `floor_at`,
    recording the reason in both. Never called by Portmark itself."""
    prior_database = store.reset_time_floor(floor_at, reason)
    prior_mirrored = None if witness is None else witness.reset_time_floor(floor_at, reason, at)
    return {"new": floor_at, "prior_database_floor": prior_database, "prior_mirrored_floor": prior_mirrored, "reason": reason}

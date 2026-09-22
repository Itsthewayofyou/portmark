"""The trusted clock for security expiry decisions (Section 12 #6, owner decision D3).

Permit, approval, key, receipt, and attestation expiry are decided with the host's wall clock. A
backward jump of that clock would make expired, unused authorization valid again; a forward jump would
reject valid work early. Two layers bound this:

1. In-process (this module). The wall clock is compared with a monotonic baseline taken at start-up
   (the monotonic clock never jumps). If the wall clock falls BEHIND the baseline by more than the
   tolerance, every security decision fails closed with ClockRollbackError until the process restarts
   (and the durable time floor then judges the new start). A FORWARD jump beyond the tolerance is
   allowed -- it may be a correction -- but surfaced loudly: a CRITICAL log line and a metric, because
   it will carry the durable time floor forward with it, and correcting the clock afterwards locks the
   host out until an operator resets the floor.
2. Across restarts: the durable time floor (storage + the audit-floor file), checked at start-up.

A jump smaller than the tolerance is accepted in both directions: that much skew is the stated bound
on how far expiry decisions can be off.
"""

from __future__ import annotations

import inspect
import logging
import math
import os
import threading
import time
import weakref
from collections.abc import Callable
from typing import Any

from .security import SecurityError

logger = logging.getLogger(__name__)

DEFAULT_CLOCK_TOLERANCE_SECONDS = 300
MAX_CLOCK_TOLERANCE_SECONDS = 3600
CLOCK_TOLERANCE_ENV = "PORTMARK_CLOCK_TOLERANCE_SECONDS"


class ClockRollbackError(SecurityError):
    """The wall clock moved backwards by more than the tolerance; security decisions fail closed."""


def clock_tolerance_from_environment(environ: Any = None) -> int:
    environ = os.environ if environ is None else environ
    raw = environ.get(CLOCK_TOLERANCE_ENV)
    if raw is None or not str(raw).strip():
        return DEFAULT_CLOCK_TOLERANCE_SECONDS
    try:
        value = int(str(raw).strip())
    except ValueError as error:
        raise ValueError(f"{CLOCK_TOLERANCE_ENV} must be an integer number of seconds, got {raw!r}") from error
    return validate_tolerance(value)


def validate_tolerance(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_CLOCK_TOLERANCE_SECONDS:
        raise ValueError(f"clock tolerance must be an integer from 1 to {MAX_CLOCK_TOLERANCE_SECONDS} seconds, got {value!r}")
    return value


class TrustedClock:
    def __init__(
        self,
        tolerance_seconds: int = DEFAULT_CLOCK_TOLERANCE_SECONDS,
        wall: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.tolerance_seconds = validate_tolerance(tolerance_seconds)
        self._wall = wall
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._wall_base = wall()
        self._monotonic_base = monotonic()
        self._rolled_back_by: float | None = None
        self.forward_jumps = 0
        self._forward_jump_listeners: list[Any] = []  # zero-argument references to listeners

    def set_tolerance(self, tolerance_seconds: int) -> None:
        """Change the tolerance, keeping the baseline: a drift seen since start-up is judged with it."""
        tolerance = validate_tolerance(tolerance_seconds)
        with self._lock:
            self.tolerance_seconds = tolerance

    def on_forward_jump(self, listener: Callable[[float], None]) -> None:
        # A bound method is held weakly, so registering a host's metrics does not keep that host alive.
        entry: Any = weakref.WeakMethod(listener) if inspect.ismethod(listener) else (lambda: listener)
        with self._lock:
            self._forward_jump_listeners = [ref for ref in self._forward_jump_listeners if ref() is not None]
            self._forward_jump_listeners.append(entry)

    def now(self) -> int:
        """Current time in epoch seconds for a security decision, or ClockRollbackError."""
        wall = self._wall()
        elapsed = self._monotonic()
        if not math.isfinite(wall):
            raise ClockRollbackError("the wall clock returned a non-finite time")
        listeners: list[Callable[[float], None]] = []
        jumped = False
        with self._lock:
            expected = self._wall_base + (elapsed - self._monotonic_base)
            drift = wall - expected
            if self._rolled_back_by is not None or drift < -self.tolerance_seconds:
                # Sticky: once seen, a rollback is not forgiven by the clock drifting back into range;
                # a restart re-judges it against the durable time floor.
                self._rolled_back_by = max(self._rolled_back_by or 0.0, -drift)
                raise ClockRollbackError(
                    f"the wall clock moved back by {self._rolled_back_by:.0f}s (tolerance {self.tolerance_seconds}s); "
                    "security decisions fail closed until the clock is corrected and the host restarted"
                )
            if drift > self.tolerance_seconds:
                jumped = True
                self.forward_jumps += 1
                # Re-base on the new time so one jump is reported once, not on every call.
                self._wall_base, self._monotonic_base = wall, elapsed
                listeners = [listener for listener in (ref() for ref in self._forward_jump_listeners) if listener is not None]
        if jumped:
            logger.critical(
                "the wall clock jumped FORWARD by %.0fs (tolerance %ds). If this is wrong, correct it now: the "
                "durable time floor will follow it, and once it has, correcting the clock makes the host refuse "
                "to start until an operator runs `portmark time-floor reset --to <epoch> --reason <text> --confirm` "
                "(with a remote witness, also --operator-id and --operator-key-file).",
                drift,
                self.tolerance_seconds,
            )
            for listener in listeners:
                listener(drift)
        return int(wall)


_default_clock = TrustedClock(DEFAULT_CLOCK_TOLERANCE_SECONDS)
_default_lock = threading.Lock()


def default_clock() -> TrustedClock:
    with _default_lock:
        return _default_clock


def configure_default_clock(tolerance_seconds: int) -> TrustedClock:
    """Set the process-wide trusted clock's tolerance IN PLACE and return that clock.

    Never a new clock: a new one would take a new baseline at the current -- possibly already rolled
    back -- time, and forget a rollback (or a sticky failure) seen since the process started."""
    with _default_lock:
        clock = _default_clock
    clock.set_tolerance(tolerance_seconds)
    return clock


def trusted_now() -> int:
    """The time to use for a security expiry decision (see the module note)."""
    return default_clock().now()


class TimeFloorError(ClockRollbackError):
    """Start-up refusal: the clock is behind the durable time floor (Section 12 #6). `code` is stable."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_RECOVERY = (
    "Correct the clock and start again. If the clock is right and the FLOOR is wrong (it followed a clock that "
    "was wrong, for example after a forward jump), an operator lowers it explicitly: "
    "`portmark time-floor reset --to <epoch-seconds> --reason <text> --confirm`. With a remote witness (EV-013), "
    "which keeps its own copy of the floor, also add `--operator-id <id> --operator-key-file <file>`. "
    "Portmark never lowers it by itself."
)


def check_time_floor(store: Any, witness: Any = None, clock: TrustedClock | None = None) -> None:
    """Refuse to start when the clock is behind the durable time floor by more than the tolerance.

    The floor is the higher of the database's floor and the one mirrored in the audit-floor file (if one is
    configured), so restoring an older database snapshot does not also restore an older floor. On Postgres
    the database clock is the shared authority: it must not be behind its own floor, and the host clock --
    which evaluates expiry -- must agree with it within the tolerance.
    """
    clock = clock if clock is not None else default_clock()
    tolerance = clock.tolerance_seconds
    host_now = clock.now()
    database_floor = int(store.time_floor()) if hasattr(store, "time_floor") else 0
    mirrored_floor = int(witness.witnessed_time_floor()) if witness is not None and hasattr(witness, "witnessed_time_floor") else 0
    floor = max(database_floor, mirrored_floor)
    if host_now + tolerance < floor:
        source = "the audit-floor file" if mirrored_floor > database_floor else "the database"
        raise TimeFloorError(
            "clock-behind-floor",
            f"the host clock ({host_now}) is {floor - host_now}s behind the durable time floor ({floor}, from {source}); "
            f"the tolerance is {tolerance}s. The clock was set back, or an older database was restored with a clock "
            f"set back to match it. {_RECOVERY}",
        )
    database_now = store.database_now() if hasattr(store, "database_now") else None
    if database_now is not None:
        if database_now + tolerance < database_floor:
            raise TimeFloorError(
                "database-clock-behind-floor",
                f"the database clock ({database_now}) is {database_floor - database_now}s behind its durable time floor "
                f"({database_floor}); the tolerance is {tolerance}s. {_RECOVERY}",
            )
        if abs(host_now - database_now) > tolerance:
            raise TimeFloorError(
                "host-database-clock-skew",
                f"the host clock ({host_now}) and the database clock ({database_now}) differ by "
                f"{abs(host_now - database_now)}s, more than the {tolerance}s tolerance. Synchronize both (NTP): the "
                "host decides expiry, the database keeps the shared time floor.",
            )

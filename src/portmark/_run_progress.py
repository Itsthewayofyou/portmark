"""Per-run progress for the bounded-shutdown report (Section 12 #1).

A run executing on a worker thread records only IDENTIFIERS here -- its task id, its latest durable
checkpoint generation, its execution phase, and the effect ids of side-effecting tools it started -- so
that when the shutdown grace expires, the unfinished work can be named without logging arguments,
state, results, or secrets (owner decision D1). Outside a tracked run every function here does nothing.

The fence is ONE atomic step (auditor, PR #97 round 1). A separate "is the run still live?" check
followed by "record the phase, then act" lets the shutdown deadline land between the two: the tool
starts after shutdown was reported, and the report names the previous phase without the effect id.
So `begin()` checks for abandonment AND records the new phase and effect id under the same lock that
`abandon()` takes, and `abandon()` takes the report snapshot under that lock too. Exactly one of two
orders is possible:

- `abandon()` first: `begin()` raises RunAbandoned, and the step never starts.
- `begin()` first: the step is under way, and the report names it -- its phase and effect id -- as the
  operation in flight when the deadline passed.

There is deliberately no check-only function: a check that does not also record the step is not a fence.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

# A run launches at most max_tool_calls tools; the report keeps a bounded tail so a runaway run cannot
# grow it without limit.
MAX_REPORTED_EFFECT_IDS = 16

# Operations a run starts with begin(). Each writes durable state or starts external work, so each is
# refused once the run is abandoned. "side_effecting_tool" is the one that matters most at shutdown:
# from the moment it begins, the effect may land (the ledger records `started` next), so recovery goes
# through the effect ledger (reconcile), never a blind retry.
OPERATIONS = frozenset({"deciding", "approving", "tool", "side_effecting_tool", "persisting"})
# Progress marks that start nothing: recorded with note(), never refused.
MARKS = frozenset({"admitting", "tool_returned", "persisted"})
PHASES = OPERATIONS | MARKS


class RunAbandoned(RuntimeError):
    """The shutdown grace expired while this run was active (Section 12 #1, D1).

    The run is abandoned as in a crash: from this point it starts no operation -- no provider call, no
    approval redemption, no tool launch, no checkpoint write. Recovery goes through the existing effect
    ledger and reconciliation, never a retry.
    """


class RunProgress:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._task_id: str | None = None
        self._checkpoint_generation: int | None = None
        self._phase = "admitting"
        self._effect_ids: list[str] = []
        self._abandoned = False

    def _snapshot_locked(self) -> dict[str, Any]:
        return {
            "task_id": self._task_id,
            "checkpoint_generation": self._checkpoint_generation,
            "phase": self._phase,
            "effect_ids": list(self._effect_ids),
        }

    def abandon(self) -> dict[str, Any]:
        """Abandon the run and return the report snapshot, atomically: nothing can begin in between."""
        with self._lock:
            self._abandoned = True
            return self._snapshot_locked()

    def begin(self, operation: str, *, effect_id: str | None = None) -> None:
        """Atomically refuse (if abandoned) or record `operation` as the step now in flight."""
        if operation not in OPERATIONS:
            raise ValueError(f"unknown run operation {operation!r}")
        with self._lock:
            if self._abandoned:
                raise RunAbandoned(f"run abandoned at the shutdown grace deadline; {operation} not started")
            self._phase = operation
            if effect_id is not None and effect_id not in self._effect_ids:
                self._effect_ids.append(str(effect_id))
                del self._effect_ids[:-MAX_REPORTED_EFFECT_IDS]

    def note(self, *, task_id: str | None = None, checkpoint_generation: int | None = None, phase: str | None = None) -> None:
        """Record identifiers and progress marks. Starts nothing, so it is never refused."""
        if phase is not None and phase not in MARKS:
            raise ValueError(f"{phase!r} is not a progress mark; start an operation with begin()")
        with self._lock:
            if task_id is not None:
                self._task_id = str(task_id)
            if checkpoint_generation is not None:
                self._checkpoint_generation = int(checkpoint_generation)
            if phase is not None:
                self._phase = phase

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return self._snapshot_locked()


_local = threading.local()


@contextmanager
def tracking(progress: RunProgress) -> Iterator[RunProgress]:
    """Make `progress` the current thread's run record for the duration of the block."""
    previous = getattr(_local, "progress", None)
    _local.progress = progress
    try:
        yield progress
    finally:
        _local.progress = previous


def begin(operation: str, *, effect_id: str | None = None) -> None:
    """Start `operation` for the current tracked run, or raise RunAbandoned (see the module note)."""
    progress = getattr(_local, "progress", None)
    if progress is not None:
        progress.begin(operation, effect_id=effect_id)


def note(**fields: Any) -> None:
    progress = getattr(_local, "progress", None)
    if progress is not None:
        progress.note(**fields)

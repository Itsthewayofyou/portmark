"""Per-run progress for the bounded-shutdown report (Section 12 #1).

A run executing on a worker thread records only IDENTIFIERS here -- its task id, its latest durable
checkpoint generation, its execution phase, and the effect ids of side-effecting tools it launched -- so
that when the shutdown grace expires, the unfinished work can be named without logging arguments,
state, results, or secrets (owner decision D1). Host code calls `note()`; outside a tracked run it does
nothing.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

# A run launches at most max_tool_calls tools; the report keeps a bounded tail so a runaway run cannot
# grow it without limit.
MAX_REPORTED_EFFECT_IDS = 16

# Phases a run passes through. "side_effecting_tool" is the one that matters at shutdown: the effect may
# have landed, so recovery must go through the effect ledger (reconcile), never a blind retry.
PHASES = frozenset({"admitting", "deciding", "tool", "side_effecting_tool", "tool_returned", "persisting", "persisted"})


class RunAbandoned(RuntimeError):
    """The shutdown grace expired while this run was active (Section 12 #1, D1).

    The run is abandoned as in a crash: from this point it launches no tool and writes no checkpoint.
    Recovery goes through the existing effect ledger and reconciliation, never a retry.
    """


class RunProgress:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._task_id: str | None = None
        self._checkpoint_generation: int | None = None
        self._phase = "admitting"
        self._effect_ids: list[str] = []
        self._abandoned = False

    def abandon(self) -> None:
        with self._lock:
            self._abandoned = True

    def ensure_live(self) -> None:
        with self._lock:
            if self._abandoned:
                raise RunAbandoned("run abandoned at the shutdown grace deadline")

    def note(
        self,
        *,
        task_id: str | None = None,
        checkpoint_generation: int | None = None,
        phase: str | None = None,
        effect_id: str | None = None,
    ) -> None:
        with self._lock:
            if task_id is not None:
                self._task_id = str(task_id)
            if checkpoint_generation is not None:
                self._checkpoint_generation = int(checkpoint_generation)
            if phase is not None:
                if phase not in PHASES:
                    raise ValueError(f"unknown run phase {phase!r}")
                self._phase = phase
            if effect_id is not None and effect_id not in self._effect_ids:
                self._effect_ids.append(str(effect_id))
                del self._effect_ids[:-MAX_REPORTED_EFFECT_IDS]

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "task_id": self._task_id,
                "checkpoint_generation": self._checkpoint_generation,
                "phase": self._phase,
                "effect_ids": list(self._effect_ids),
            }


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


def note(**fields: Any) -> None:
    progress = getattr(_local, "progress", None)
    if progress is not None:
        progress.note(**fields)


def ensure_live() -> None:
    """Raise RunAbandoned if the current tracked run was abandoned at the shutdown deadline.

    Called before each step that would launch a tool or write durable state, so a run that outlives
    the grace cannot start a NEW effect or write after the deadline. A step already in progress is not
    interrupted (a thread cannot be killed); its outcome is left to the effect ledger and recovery.
    """
    progress = getattr(_local, "progress", None)
    if progress is not None:
        progress.ensure_live()

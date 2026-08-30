from __future__ import annotations

import threading
from collections import Counter
from typing import Any


class RuntimeMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Counter[str] = Counter()

    def increment(self, name: str, value: int = 1) -> None:
        if value < 0:
            raise ValueError("metric increments must be non-negative")
        with self._lock:
            self._counters[name] += value

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"counters": dict(sorted(self._counters.items()))}

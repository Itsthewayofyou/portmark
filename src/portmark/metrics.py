from __future__ import annotations

import threading
from collections import Counter
from typing import Any


_HISTOGRAM_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
_REFUSAL_REASONS = frozenset({
    "invalid_request",
    "parse_error",
    "invalid_params",
    "method_not_found",
    "unauthorized",
    "rate_limited",
    "server_busy",
    "security",
    "internal",
    "not_ready",
})


class RuntimeMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Counter[str] = Counter()
        self._refusals: Counter[str] = Counter()
        self._histogram_counts: dict[str, int] = {}
        self._histogram_sums: dict[str, float] = {}
        self._histogram_buckets: dict[str, Counter[float]] = {}

    def increment(self, name: str, value: int = 1) -> None:
        if value < 0:
            raise ValueError("metric increments must be non-negative")
        with self._lock:
            self._counters[name] += value

    def increment_refusal(self, reason: str, value: int = 1) -> None:
        if value < 0:
            raise ValueError("metric increments must be non-negative")
        reason_code = reason if reason in _REFUSAL_REASONS else "internal"
        with self._lock:
            self._refusals[reason_code] += value

    def observe_duration(self, name: str, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("metric observations must be non-negative")
        with self._lock:
            self._histogram_counts[name] = self._histogram_counts.get(name, 0) + 1
            self._histogram_sums[name] = self._histogram_sums.get(name, 0.0) + seconds
            buckets = self._histogram_buckets.setdefault(name, Counter())
            for bucket in _HISTOGRAM_BUCKETS:
                if seconds <= bucket:
                    buckets[bucket] += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"counters": dict(sorted(self._counters.items()))}

    def prometheus_text(self) -> str:
        with self._lock:
            counters = dict(sorted(self._counters.items()))
            refusals = dict(sorted(self._refusals.items()))
            histogram_names = sorted(self._histogram_counts)
            histogram_counts = dict(self._histogram_counts)
            histogram_sums = dict(self._histogram_sums)
            histogram_buckets = {name: Counter(buckets) for name, buckets in self._histogram_buckets.items()}

        lines = [
            "# HELP portmark_runtime_counter_total Runtime event counters.",
            "# TYPE portmark_runtime_counter_total counter",
        ]
        for name, value in counters.items():
            lines.append(f'portmark_runtime_counter_total{{name="{_label_value(name)}"}} {value}')

        lines.extend([
            "# HELP portmark_refusals_total Refused requests or runtime actions by bounded reason code.",
            "# TYPE portmark_refusals_total counter",
        ])
        for reason, value in refusals.items():
            lines.append(f'portmark_refusals_total{{reason="{reason}"}} {value}')

        for name in histogram_names:
            metric = _metric_name(name)
            lines.append(f"# HELP {metric} Duration in seconds.")
            lines.append(f"# TYPE {metric} histogram")
            buckets = histogram_buckets.get(name, Counter())
            for bucket in _HISTOGRAM_BUCKETS:
                lines.append(f'{metric}_bucket{{le="{_bucket_label(bucket)}"}} {buckets[bucket]}')
            count = histogram_counts[name]
            lines.append(f'{metric}_bucket{{le="+Inf"}} {count}')
            lines.append(f"{metric}_count {count}")
            lines.append(f"{metric}_sum {_float_value(histogram_sums[name])}")

        return "\n".join(lines) + "\n"


def _metric_name(name: str) -> str:
    allowed = []
    for character in name:
        allowed.append(character if character.isalnum() else "_")
    normalized = "".join(allowed).strip("_")
    if not normalized:
        normalized = "metric"
    if not normalized.startswith("portmark_"):
        normalized = "portmark_" + normalized
    return normalized


def _label_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _bucket_label(value: float) -> str:
    return f"{value:g}"


def _float_value(value: float) -> str:
    return f"{value:.17g}"

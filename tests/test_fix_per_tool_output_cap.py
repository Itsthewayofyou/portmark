"""A per-tool output cap must bind on the host path.

`register_isolated(..., max_output_bytes=N)` sets a per-tool output cap. AgentHost always passes the
run budget's `max_output_bytes` to `ToolRegistry.invoke` (host.py), and `invoke` used that caller value
INSTEAD of the per-tool cap, so on the host path a tool registered with a 1 KiB cap could return up to
the run budget (64 KiB by default). The reconcile path already honoured the per-tool cap.

The effective cap is the smaller of the caller's budget and the per-tool cap. A tool with no per-tool
cap keeps the caller's budget (not the registry default), and a caller can always tighten.
Plain `register()` tools have no per-tool cap, so only isolated tools are affected.
"""

from __future__ import annotations

import os
import time
import unittest

from portmark.models import Permit, ToolGrant
from portmark.tools import ToolExecutionError, ToolRegistry


def _isolated_env() -> dict[str, str]:
    import portmark

    src_dir = os.path.dirname(os.path.dirname(os.path.abspath(portmark.__file__)))
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    return {"PYTHONPATH": os.pathsep.join([src_dir, tests_dir])}


def _permit(name: str) -> Permit:
    return Permit(
        issuer="issuer",
        subject="agent",
        audience="host",
        expires_at=int(time.time()) + 60,
        nonce="nonce-output-cap",
        grants=(ToolGrant(name),),
    )


# "x" * 4000 inside {"blob": ...} encodes to about 4 KB: over a 1 KiB cap, under 8 KiB and 64 KiB.
_SIZE = 4000
_RUN_BUDGET = 65_536


class PerToolOutputCapTests(unittest.TestCase):
    def _registry(self, per_tool_cap: int | None) -> ToolRegistry:
        registry = ToolRegistry()
        registry.register_isolated(
            "iso.big", "isolated_tool_fixtures:oversized", max_output_bytes=per_tool_cap, env=_isolated_env()
        )
        return registry

    def test_per_tool_cap_binds_when_the_caller_passes_a_larger_run_budget(self):
        # The host path: AgentHost passes the run budget (64 KiB). The tool's own 1 KiB cap must still bind.
        registry = self._registry(1024)
        with self.assertRaisesRegex(ToolExecutionError, "output budget"):
            registry.invoke(_permit("iso.big"), "iso.big", {"size": _SIZE}, _RUN_BUDGET)

    def test_output_within_the_per_tool_cap_still_runs(self):
        registry = self._registry(8192)
        result = registry.invoke(_permit("iso.big"), "iso.big", {"size": _SIZE}, _RUN_BUDGET)
        self.assertEqual(len(result["blob"]), _SIZE)

    def test_a_tool_without_a_per_tool_cap_keeps_the_callers_budget(self):
        # Regression guard: no override means the caller's budget, not min(caller, registry default).
        registry = ToolRegistry(max_output_bytes=1024)
        registry.register_isolated("iso.big", "isolated_tool_fixtures:oversized", env=_isolated_env())
        result = registry.invoke(_permit("iso.big"), "iso.big", {"size": _SIZE}, _RUN_BUDGET)
        self.assertEqual(len(result["blob"]), _SIZE)

    def test_a_smaller_caller_budget_still_wins(self):
        registry = self._registry(8192)
        with self.assertRaisesRegex(ToolExecutionError, "output budget"):
            registry.invoke(_permit("iso.big"), "iso.big", {"size": _SIZE}, 1024)

    def test_without_a_caller_budget_the_per_tool_cap_applies(self):
        registry = self._registry(1024)
        with self.assertRaisesRegex(ToolExecutionError, "output budget"):
            registry.invoke(_permit("iso.big"), "iso.big", {"size": _SIZE})


if __name__ == "__main__":
    unittest.main()

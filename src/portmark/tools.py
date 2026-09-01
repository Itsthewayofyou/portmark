from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from typing import Any

from .models import Permit
from .security import SecurityError, canonical_json, check_constraints


Tool = Callable[[dict[str, Any]], Any]


class ToolExecutionError(SecurityError):
    pass


class ToolRegistry:
    def __init__(self, default_timeout: float = 5.0, max_output_bytes: int = 65_536) -> None:
        self._tools: dict[str, Tool] = {}
        self._timeouts: dict[str, float] = {}
        self.default_timeout = default_timeout
        self.max_output_bytes = max_output_bytes

    def register(self, name: str, tool: Tool, timeout: float | None = None) -> None:
        self._tools[name] = tool
        if timeout is not None:
            self._timeouts[name] = timeout

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def invoke(self, permit: Permit, name: str, arguments: dict[str, Any], max_output_bytes: int | None = None) -> Any:
        grant = next((grant for grant in permit.grants if grant.name == name), None)
        if grant is None:
            # Only the effective permit is visible here, so this cannot say which
            # stage dropped the tool. AgentHost checks first and reports the
            # cause; see HostPolicy.explain_missing_grant.
            raise SecurityError(
                f"tool {name!r} is not in the effective permit. It was removed by the manifest, "
                "the permit or the host policy; run it through AgentHost, or call "
                "HostPolicy.explain_missing_grant, to find out which."
            )
        tool = self._tools.get(name)
        if tool is None:
            raise SecurityError(f"tool {name!r} is not installed")
        check_constraints(grant.constraints, arguments)
        timeout = self._timeouts.get(name, self.default_timeout)
        result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

        def run_tool() -> None:
            try:
                result_queue.put((True, tool(arguments)))
            except Exception as error:
                result_queue.put((False, error))

        thread = threading.Thread(target=run_tool, daemon=True)
        thread.start()
        try:
            succeeded, value = result_queue.get(timeout=timeout)
        except queue.Empty as error:
            raise ToolExecutionError("tool execution exceeded its deadline") from error
        if not succeeded:
            raise ToolExecutionError("tool execution failed") from value
        result = value
        try:
            encoded_size = len(canonical_json(result))
        except (TypeError, ValueError) as error:
            raise ToolExecutionError("tool output is not JSON serializable") from error
        if encoded_size > (max_output_bytes if max_output_bytes is not None else self.max_output_bytes):
            raise ToolExecutionError("tool output exceeds output budget")
        return result


def demo_registry() -> ToolRegistry:
    registry = ToolRegistry()

    def search(arguments: dict[str, Any]) -> list[dict[str, Any]]:
        limit = int(arguments["limit"])
        query = str(arguments["query"])
        return [
            {"id": f"item-{i + 1}", "title": f"Result {i + 1} for {query}", "score": round(1 - i * 0.1, 2)}
            for i in range(limit)
        ]

    def reserve(arguments: dict[str, Any]) -> dict[str, Any]:
        return {"reserved": True, "amount": arguments["amount"], "currency": arguments["currency"]}

    registry.register("catalog.search", search)
    registry.register("payments.reserve", reserve)
    return registry

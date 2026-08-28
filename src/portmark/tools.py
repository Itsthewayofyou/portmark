from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .models import Permit
from .security import SecurityError, check_constraints


Tool = Callable[[dict[str, Any]], Any]


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, name: str, tool: Tool) -> None:
        self._tools[name] = tool

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def invoke(self, permit: Permit, name: str, arguments: dict[str, Any]) -> Any:
        grant = next((grant for grant in permit.grants if grant.name == name), None)
        if grant is None:
            raise SecurityError(f"tool {name!r} was not granted")
        tool = self._tools.get(name)
        if tool is None:
            raise SecurityError(f"tool {name!r} is not installed")
        check_constraints(grant.constraints, arguments)
        return tool(arguments)


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


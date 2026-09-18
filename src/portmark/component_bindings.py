from __future__ import annotations

import json
from typing import Any

from .models import ProviderDecision, ProviderView
from .projection import provider_state
from .json_guard import StrictJSONError, strict_json_loads


WIT_PACKAGE = "portmark:agent@1.0.0"
WIT_WORLD = "portmark"
WIT_ABI = "portmark-json-lowered-v1"


def component_context(view: ProviderView, available_tools: tuple[str, ...]) -> dict[str, Any]:
    return {
        "wit": {"package": WIT_PACKAGE, "world": WIT_WORLD, "abi": WIT_ABI},
        "state": provider_state(view),
        "available_tools": list(available_tools),
    }


def component_checkpoint(view: ProviderView) -> dict[str, Any]:
    # `messages` is projected + detached inside the view; `_plain` un-proxies it for json.
    return {
        "task_id": view.task_id,
        "step": view.step,
        "tool_calls": view.tool_calls,
        "messages": list(view.messages),
    }


def encode_component_input(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def decode_component_decision(raw: str, available_tools: tuple[str, ...]) -> ProviderDecision:
    try:
        value = strict_json_loads(raw)
    except StrictJSONError as error:
        raise RuntimeError("Wasm component returned malformed or unsafe decision JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError("Wasm component decision must be a JSON object")
    outcome = value.get("outcome")
    if outcome == "tool":
        # Strict per-outcome schema (finding #4, Low): exactly {outcome, request}, and the nested
        # request is exactly {name, arguments_json} -- an unknown/contradictory field is rejected,
        # not silently ignored. Wasm migrate `content_json` (below) is accepted by the schema but
        # not currently propagated: pre-existing behavior, unchanged by this PR.
        _reject_unexpected_component_keys(value, {"outcome", "request"}, "tool decision")
        request = value.get("request")
        if not isinstance(request, dict):
            raise RuntimeError("Wasm component tool decision is missing a request")
        _reject_unexpected_component_keys(request, {"name", "arguments_json"}, "tool request")
        name = request.get("name")
        if not isinstance(name, str) or not name:
            raise RuntimeError("Wasm component tool decision has an invalid tool name")
        if name not in available_tools:
            return ProviderDecision("fail", content={"error": "required capability unavailable"})
        arguments = _decode_json_object(request.get("arguments_json", "{}"), "tool arguments")
        return ProviderDecision("tool", name, arguments)
    if outcome in {"completed", "awaiting-input", "failed", "suspended"}:
        _reject_unexpected_component_keys(value, {"outcome", "content_json"}, f"{outcome} decision")
        kind = {"completed": "complete", "awaiting-input": "await_input", "failed": "fail", "suspended": "await_input"}[outcome]
        return ProviderDecision(kind, content=_decode_json_value(value.get("content_json", "null"), f"{outcome} content"))
    if outcome == "migrate":
        _reject_unexpected_component_keys(value, {"outcome", "destination", "content_json"}, "migrate decision")
        destination = value.get("destination")
        if not isinstance(destination, str) or not destination:
            raise RuntimeError("Wasm component migration decision has an invalid destination")
        return ProviderDecision("migrate", destination=destination)
    raise RuntimeError("Wasm component returned an unknown outcome")


def _reject_unexpected_component_keys(value: dict[str, Any], allowed: set[str], label: str) -> None:
    extra = set(value) - allowed
    if extra:
        raise RuntimeError(f"Wasm component {label} has unexpected fields: {sorted(extra)}")


def _decode_json_object(raw: Any, label: str) -> dict[str, Any]:
    value = _decode_json_value(raw, label)
    if not isinstance(value, dict):
        raise RuntimeError(f"Wasm component {label} must decode to a JSON object")
    return value


def _decode_json_value(raw: Any, label: str) -> Any:
    if not isinstance(raw, str):
        raise RuntimeError(f"Wasm component {label} must be encoded as a JSON string")
    try:
        return strict_json_loads(raw)
    except StrictJSONError as error:
        raise RuntimeError(f"Wasm component {label} is malformed or unsafe JSON") from error

from __future__ import annotations

import json
from typing import Any

from .models import AgentState, ProviderDecision, ToolGrant
from .projection import provider_state, project_tool_messages


WIT_PACKAGE = "portmark:agent@1.0.0"
WIT_WORLD = "portmark"
WIT_ABI = "portmark-json-lowered-v1"


def component_context(state: AgentState, available_tools: tuple[str, ...], grants: tuple[ToolGrant, ...] = ()) -> dict[str, Any]:
    return {
        "wit": {"package": WIT_PACKAGE, "world": WIT_WORLD, "abi": WIT_ABI},
        "state": provider_state(state, grants),
        "available_tools": list(available_tools),
    }


def component_checkpoint(state: AgentState, grants: tuple[ToolGrant, ...] = ()) -> dict[str, Any]:
    return {
        "task_id": state.task_id,
        "step": state.step,
        "tool_calls": state.tool_calls,
        "messages": project_tool_messages(state.messages, grants),
    }


def encode_component_input(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def decode_component_decision(raw: str, available_tools: tuple[str, ...]) -> ProviderDecision:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("Wasm component returned malformed decision JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError("Wasm component decision must be a JSON object")
    outcome = value.get("outcome")
    if outcome == "tool":
        request = value.get("request")
        if not isinstance(request, dict):
            raise RuntimeError("Wasm component tool decision is missing a request")
        name = request.get("name")
        if not isinstance(name, str) or not name:
            raise RuntimeError("Wasm component tool decision has an invalid tool name")
        if name not in available_tools:
            return ProviderDecision("fail", content={"error": "required capability unavailable"})
        arguments = _decode_json_object(request.get("arguments_json", "{}"), "tool arguments")
        return ProviderDecision("tool", name, arguments)
    if outcome == "completed":
        return ProviderDecision("complete", content=_decode_json_value(value.get("content_json", "null"), "completion content"))
    if outcome == "awaiting-input":
        return ProviderDecision("await_input", content=_decode_json_value(value.get("content_json", "null"), "awaiting-input content"))
    if outcome == "migrate":
        destination = value.get("destination")
        if not isinstance(destination, str) or not destination:
            raise RuntimeError("Wasm component migration decision has an invalid destination")
        return ProviderDecision("migrate", destination=destination)
    if outcome == "failed":
        return ProviderDecision("fail", content=_decode_json_value(value.get("content_json", "null"), "failure content"))
    if outcome == "suspended":
        return ProviderDecision("await_input", content=_decode_json_value(value.get("content_json", "null"), "suspension content"))
    raise RuntimeError("Wasm component returned an unknown outcome")


def _decode_json_object(raw: Any, label: str) -> dict[str, Any]:
    value = _decode_json_value(raw, label)
    if not isinstance(value, dict):
        raise RuntimeError(f"Wasm component {label} must decode to a JSON object")
    return value


def _decode_json_value(raw: Any, label: str) -> Any:
    if not isinstance(raw, str):
        raise RuntimeError(f"Wasm component {label} must be encoded as a JSON string")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"Wasm component {label} is malformed JSON") from error

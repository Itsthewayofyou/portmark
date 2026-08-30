from __future__ import annotations

from typing import Any


def make_sdk_agent_card(base_url: str, require_bearer_auth: bool) -> dict[str, Any]:
    types, parse_dict, message_to_dict = _sdk()
    payload: dict[str, Any] = {
        "name": "Portable Wasm Agent Host",
        "description": "Runs signed, capability-limited portable agents",
        "supportedInterfaces": [{
            "url": f"{base_url}/message:send",
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0",
        }],
        "version": "0.1.0",
        "capabilities": {},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [{
            "id": "portmark",
            "name": "Portmark agent execution",
            "description": "Execute a signed Portmark agent envelope",
            "inputModes": ["application/json"],
            "outputModes": ["application/json"],
        }],
    }
    if require_bearer_auth:
        payload["securitySchemes"] = {
            "bearer": {"httpAuthSecurityScheme": {"scheme": "bearer", "bearerFormat": "opaque"}}
        }
        payload["securityRequirements"] = [{"schemes": {"bearer": {}}}]
    card = parse_dict(payload, types.AgentCard())
    return message_to_dict(card, preserving_proto_field_name=False)


def validate_sdk_message_send_params(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("message send params must be an object")
    types, parse_dict, _message_to_dict = _sdk()
    parse_dict({
        "message": _sdk_message(value.get("message")),
        "configuration": value.get("configuration", {}),
        "metadata": value.get("metadata", {}),
    }, types.SendMessageRequest())


def _sdk_message(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("message must be an object")
    role = value.get("role")
    if role == "user":
        role = "ROLE_USER"
    elif role == "agent":
        role = "ROLE_AGENT"
    return {
        "messageId": value.get("messageId"),
        "contextId": value.get("contextId"),
        "taskId": value.get("taskId"),
        "role": role,
        "parts": [_sdk_part(part) for part in value.get("parts", [])],
        "metadata": value.get("metadata", {}),
    }


def _sdk_part(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("message part must be an object")
    if value.get("kind") == "text" and "text" in value:
        return {"text": value["text"], "metadata": value.get("metadata", {})}
    return {key: item for key, item in value.items() if key != "kind"}


def _sdk():
    try:
        import a2a.types as types
        from google.protobuf.json_format import MessageToDict, ParseDict
    except Exception as exc:
        raise RuntimeError("official A2A SDK adapter requires installing portmark[a2a]") from exc
    return types, ParseDict, MessageToDict

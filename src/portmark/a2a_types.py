from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


A2A_PROTOCOL_VERSION = "1.0"
JSONRPC_VERSION = "2.0"
MESSAGE_SEND_METHOD = "message/send"


class A2ARequestError(RuntimeError):
    def __init__(self, code: int, message: str, http_status: int = 400, request_id: str | int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.request_id = request_id


@dataclass(frozen=True)
class Message:
    messageId: str
    role: str
    parts: tuple[dict[str, Any], ...]
    taskId: str | None = None
    contextId: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MessageSendParams:
    message: Message
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def portmark_envelope(self) -> dict[str, Any]:
        envelope = self.metadata.get("portmark_envelope")
        if not isinstance(envelope, dict):
            raise A2ARequestError(-32602, "invalid params")
        return envelope


@dataclass(frozen=True)
class JSONRPCRequest:
    jsonrpc: str
    id: str | int | None
    method: str
    params: MessageSendParams


def make_agent_card(base_url: str, require_bearer_auth: bool) -> dict[str, Any]:
    """The card, in the canonical AgentCard shape (A2A 1.0).

    The proto has no top-level url, protocolVersion or security field: the endpoint and protocol version
    live in supportedInterfaces, where a client must look for them, and a strict client refuses unknown
    fields. proto3 cannot tell false from unset, so a canonical round trip omits false capabilities; the
    empty `capabilities` matches that. A SecurityScheme is a oneof whose variant name is the wrapping key.
    """
    media = ("application/json",)
    card: dict[str, Any] = {
        "name": "Portable Wasm Agent Host",
        "description": "Runs signed, capability-limited portable agents",
        "version": "0.1.0",
        "supportedInterfaces": ({
            "url": f"{base_url}/message:send",
            "protocolBinding": "JSONRPC",
            "protocolVersion": A2A_PROTOCOL_VERSION,
        },),
        "capabilities": {},
        "defaultInputModes": media,
        "defaultOutputModes": media,
        "skills": ({
            "id": "portmark",
            "name": "Portmark agent execution",
            "description": "Execute a signed Portmark agent envelope",
            "inputModes": media,
            "outputModes": media,
        },),
    }
    if require_bearer_auth:
        card["securitySchemes"] = {"bearer": {"httpAuthSecurityScheme": {"scheme": "bearer", "bearerFormat": "opaque"}}}
        card["securityRequirements"] = ({"schemes": {"bearer": {}}},)
    return card


def parse_jsonrpc_request(value: Any) -> JSONRPCRequest:
    if not isinstance(value, dict):
        raise A2ARequestError(-32600, "invalid request")
    request_id = _valid_request_id(value.get("id"))
    if value.get("jsonrpc") != JSONRPC_VERSION:
        raise A2ARequestError(-32600, "invalid request", request_id=request_id)
    method = value.get("method")
    if not isinstance(method, str):
        raise A2ARequestError(-32600, "invalid request", request_id=request_id)
    if method != MESSAGE_SEND_METHOD:
        raise A2ARequestError(-32601, "method not found", request_id=request_id)
    return JSONRPCRequest(JSONRPC_VERSION, request_id, method, parse_message_send_params(value.get("params")))


def parse_message_send_params(value: Any) -> MessageSendParams:
    if not isinstance(value, dict):
        raise A2ARequestError(-32602, "invalid params")
    message = _parse_message(value.get("message"))
    metadata = _optional_object(value.get("metadata"), "metadata")
    params = MessageSendParams(message, metadata)
    params.portmark_envelope
    return params


def task_from_run_result(result: Any) -> dict[str, Any]:
    # Finding #4: the model provider is denied raw checkpoint memory
    # (projection.provider_state), but this A2A egress previously returned
    # asdict(result) -- the full internal checkpoint and the entire audit log,
    # including cause_message and tool arguments. Release only what the caller
    # needs: run status, task id, the agent's declared result, and the migration
    # envelope when the agent is handing off. The checkpoint and the raw audit
    # chain stay internal to the host.
    artifact: dict[str, Any] = {
        "task_id": result.task_id,
        "status": result.status,
        "result": result.result,
    }
    migration = getattr(result, "migration_envelope", None)
    if migration is not None:
        artifact["migration_envelope"] = migration
    # Section 4 #2: carry the destination's signed migration receipt back to the source so its
    # dispatcher can settle delivery (source verifies it, then mark_migration_delivered).
    receipt = getattr(result, "migration_receipt", None)
    if receipt is not None:
        artifact["migration_receipt"] = receipt
    return {
        "id": result.task_id,
        "status": {"state": _task_state(result.status)},
        "artifacts": (artifact,),
        "metadata": {"portmark_status": result.status},
    }


def success_response(request_id: str | int | None, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def error_response(request_id: str | int | None, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": {"code": code, "message": message}}


def _parse_message(value: Any) -> Message:
    if not isinstance(value, dict):
        raise A2ARequestError(-32602, "invalid params")
    message_id = value.get("messageId")
    role = value.get("role")
    parts = value.get("parts")
    if not isinstance(message_id, str) or not message_id:
        raise A2ARequestError(-32602, "invalid params")
    if role not in {"user", "agent"}:
        raise A2ARequestError(-32602, "invalid params")
    if not isinstance(parts, list) or not parts or not all(isinstance(part, dict) for part in parts):
        raise A2ARequestError(-32602, "invalid params")
    return Message(
        message_id,
        role,
        tuple(parts),
        _optional_string(value.get("taskId"), "taskId"),
        _optional_string(value.get("contextId"), "contextId"),
        _optional_object(value.get("metadata"), "metadata"),
    )


def _optional_object(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise A2ARequestError(-32602, "invalid params")
    return value


def _optional_string(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise A2ARequestError(-32602, "invalid params")
    return value


def _valid_request_id(value: Any) -> str | int | None:
    # A JSON-RPC id is a string, an integer, or null (absent is treated as null).
    # A present-but-malformed id -- bool (isinstance(True, int) is True), float,
    # array, or object -- is a malformed request, not a null id, so reject the whole
    # request rather than silently dropping the id (section 2, finding #5 follow-up).
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise A2ARequestError(-32600, "invalid request")


def _task_state(status: str) -> str:
    return {"completed": "completed", "migrated": "completed", "failed": "failed"}.get(status, "working")

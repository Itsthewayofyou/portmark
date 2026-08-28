from __future__ import annotations

from dataclasses import asdict, dataclass, field
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
class AgentInterface:
    url: str
    protocolBinding: str = "JSONRPC"
    protocolVersion: str = A2A_PROTOCOL_VERSION


@dataclass(frozen=True)
class AgentCapabilities:
    streaming: bool = False
    pushNotifications: bool = False
    stateTransitionHistory: bool = False


@dataclass(frozen=True)
class AgentSkill:
    id: str
    name: str
    description: str
    inputModes: tuple[str, ...] = ("application/json",)
    outputModes: tuple[str, ...] = ("application/json",)


@dataclass(frozen=True)
class SecurityScheme:
    type: str
    scheme: str | None = None
    bearerFormat: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


@dataclass(frozen=True)
class AgentCard:
    name: str
    description: str
    url: str
    version: str
    supportedInterfaces: tuple[AgentInterface, ...]
    capabilities: AgentCapabilities
    defaultInputModes: tuple[str, ...]
    defaultOutputModes: tuple[str, ...]
    skills: tuple[AgentSkill, ...]
    protocolVersion: str = A2A_PROTOCOL_VERSION
    securitySchemes: dict[str, SecurityScheme] = field(default_factory=dict)
    security: tuple[dict[str, tuple[str, ...]], ...] = ()
    securityRequirements: tuple[dict[str, tuple[str, ...]], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["securitySchemes"] = {key: scheme.to_dict() for key, scheme in self.securitySchemes.items()}
        if not payload["securitySchemes"]:
            payload.pop("securitySchemes")
        if not payload["security"]:
            payload.pop("security")
        if not payload["securityRequirements"]:
            payload.pop("securityRequirements")
        return payload


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


@dataclass(frozen=True)
class TaskStatus:
    state: str


@dataclass(frozen=True)
class Task:
    id: str
    status: TaskStatus
    artifacts: tuple[dict[str, Any], ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def make_agent_card(base_url: str, require_bearer_auth: bool) -> dict[str, Any]:
    security_schemes: dict[str, SecurityScheme] = {}
    security: tuple[dict[str, tuple[str, ...]], ...] = ()
    if require_bearer_auth:
        security_schemes = {"bearer": SecurityScheme("http", "bearer", "opaque")}
        security = ({"bearer": ()},)
    card = AgentCard(
        name="Portable Wasm Agent Host",
        description="Runs signed, capability-limited portable agents",
        url=f"{base_url}/message:send",
        version="0.1.0",
        supportedInterfaces=(AgentInterface(f"{base_url}/message:send"),),
        capabilities=AgentCapabilities(),
        defaultInputModes=("application/json",),
        defaultOutputModes=("application/json",),
        skills=(AgentSkill("portmark", "Portmark agent execution", "Execute a signed Portmark agent envelope"),),
        securitySchemes=security_schemes,
        security=security,
        securityRequirements=security,
    )
    return card.to_dict()


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
    return Task(
        id=result.task_id,
        status=TaskStatus(_task_state(result.status)),
        artifacts=(asdict(result),),
        metadata={"portmark_status": result.status},
    ).to_dict()


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
    if value is None or isinstance(value, (str, int)):
        return value
    return None


def _task_state(status: str) -> str:
    return {"completed": "completed", "migrated": "completed", "failed": "failed"}.get(status, "working")

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


Json = dict[str, Any]


@dataclass(frozen=True)
class ToolGrant:
    name: str
    constraints: Json = field(default_factory=dict)
    output_projection: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if self.output_projection is not None:
            object.__setattr__(self, "output_projection", tuple(self.output_projection))


@dataclass(frozen=True)
class ResourceBudget:
    max_steps: int = 12
    max_tool_calls: int = 8
    max_output_bytes: int = 65_536

    def intersect(self, other: "ResourceBudget") -> "ResourceBudget":
        return ResourceBudget(
            max_steps=min(self.max_steps, other.max_steps),
            max_tool_calls=min(self.max_tool_calls, other.max_tool_calls),
            max_output_bytes=min(self.max_output_bytes, other.max_output_bytes),
        )


@dataclass(frozen=True)
class AgentManifest:
    agent_id: str
    version: str
    provider: str
    requested_tools: tuple[str, ...]
    component_digest: str = "python:reference-agent-v1"


@dataclass(frozen=True)
class AttestationEvidence:
    verifier: str
    subject: str
    audience: str
    measurement: str
    issued_at: int
    expires_at: int
    nonce: str = ""
    claims: Json = field(default_factory=dict)
    signature_key_id: str = ""
    signature: str = ""

    def unsigned_dict(self) -> Json:
        value = asdict(self)
        value.pop("signature", None)
        return value


@dataclass(frozen=True)
class ApprovalToken:
    approval_id: str
    tool: str
    subject: str
    audience: str
    task_id: str
    permit_nonce: str
    arguments_hash: str
    policy_hash: str
    approved_by: str
    issued_at: int
    expires_at: int
    signature_key_id: str = ""
    signature: str = ""

    def unsigned_dict(self) -> Json:
        value = asdict(self)
        value.pop("signature", None)
        return value


@dataclass(frozen=True)
class Permit:
    issuer: str
    subject: str
    audience: str
    expires_at: int
    nonce: str
    grants: tuple[ToolGrant, ...]
    budget: ResourceBudget = field(default_factory=ResourceBudget)
    delegation_allowed: bool = False
    attestation: AttestationEvidence | None = None


@dataclass
class AgentState:
    task_id: str
    goal: str
    step: int = 0
    tool_calls: int = 0
    memory: Json = field(default_factory=dict)
    messages: list[Json] = field(default_factory=list)
    status: Literal["ready", "running", "awaiting_input", "migrating", "completed", "failed"] = "ready"
    result: Any = None


@dataclass
class AgentEnvelope:
    manifest: AgentManifest
    permit: Permit
    state: AgentState
    previous_audit_hash: str = ""
    previous_audit_sequence: int = 0
    previous_audit_host_id: str = ""
    previous_audit_signature_key_id: str = ""
    previous_audit_signature: str = ""
    signature_key_id: str = ""
    signature: str = ""

    def unsigned_dict(self) -> Json:
        value = asdict(self)
        value.pop("signature", None)
        return value


@dataclass(frozen=True)
class ProviderDecision:
    kind: Literal["tool", "complete", "await_input", "migrate", "fail"]
    tool: str | None = None
    arguments: Json = field(default_factory=dict)
    content: Any = None
    destination: str | None = None


@dataclass(frozen=True)
class RunResult:
    status: str
    task_id: str
    result: Any
    checkpoint: Json
    audit: tuple[Json, ...]
    migration_envelope: Json | None = None

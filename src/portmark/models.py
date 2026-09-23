from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any, Literal


Json = dict[str, Any]

# A tool name is an IDENTIFIER, not free text. It names authority: it is compared against grants,
# registered in the tool registry, written into the audit chain, exported to a SIEM, and (from the MCP
# work) supplied by another organization's server. Letters, digits, and inner `.`, `_`, `-` only, starting
# and ending on a letter or digit. That excludes control characters, whitespace, look-alike Unicode, path
# and URL separators, and the empty string -- all of which are indistinguishable from a legitimate name
# once they reach a log line or an operator's screen. The runtime cannot know which odd name was intended,
# so it refuses one at the door instead of guessing.
#
# The character set is the one the MCP specification (revision 2026-07-28, "Tool Names") says SHOULD be the
# only allowed one. MCP also says a name SHOULD be 1 to 128 characters, and that a client aggregating
# several servers SHOULD prefix names with a server identifier. Portmark will register such a tool as
# `mcp.<server>.<tool>`, so its own limit leaves room for that prefix on top of a 128-character MCP name
# (owner decision, 2026-09-22). Portmark stays stricter on the first and last character: a name that starts
# or ends on `.`, `_` or `-` reads as hidden or truncated to the operator who must judge it, and the MCP
# rule is a SHOULD, so such a server tool needs an operator-chosen alias.
MAX_TOOL_NAME_LENGTH = 192
# \Z, not $: in Python `$` also matches just BEFORE a final newline, so "catalog.search\n" -- a log
# injection carrying its own line break -- would have passed as a valid name.
_TOOL_NAME = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9._-]{0,190}[A-Za-z0-9])?\Z")


def validate_tool_name(name: Any, label: str = "tool name") -> str:
    """Return `name` when it is a well-formed tool name, else raise ValueError."""
    if not isinstance(name, str) or not _TOOL_NAME.match(name):
        shown = name if isinstance(name, str) and len(name) <= 80 else type(name).__name__
        raise ValueError(
            f"{label} {shown!r} is not a valid tool name: 1 to {MAX_TOOL_NAME_LENGTH} characters, "
            "letters, digits and inner '.', '_' or '-', starting and ending on a letter or digit"
        )
    return name


@dataclass(frozen=True)
class ToolGrant:
    name: str
    constraints: Json = field(default_factory=dict)
    output_projection: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        # Every grant passes through here -- the A2A decode of an incoming permit, the policy loader, the
        # envelope builder, and each intersection -- so this is the one door for grant names.
        validate_tool_name(self.name, "grant")
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

    def __post_init__(self) -> None:
        object.__setattr__(self, "requested_tools", tuple(self.requested_tools))
        for name in self.requested_tools:
            validate_tool_name(name, "requested tool")


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
    quote: str = ""
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
    # Section 5 #1 (High): the approval is bound to the exact stored checkpoint
    # generation it was issued for. Without this an approval minted for the task's
    # suspended state at generation N is replayable after the task legitimately
    # advances to a later generation M (same tool/args/permit-nonce/policy), letting
    # a stale authorization take effect in a context it never approved. REQUIRED,
    # never defaulted: an optional generation claim is no binding at all (an attacker
    # simply omits it). Verified against the DURABLE store generation, not the
    # caller-asserted envelope value.
    checkpoint_generation: int
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
    # Which stored checkpoint this state represents. The store owns and advances
    # this value (finding EV-008); on the wire it is an *assertion* the durable
    # store verifies via compare-and-swap, never authority. 0 means "a fresh task,
    # no checkpoint yet".
    checkpoint_generation: int = 0
    step: int = 0
    tool_calls: int = 0
    memory: Json = field(default_factory=dict)
    messages: list[Json] = field(default_factory=list)
    status: Literal["ready", "running", "awaiting_input", "migrating", "completed", "failed"] = "ready"
    result: Any = None


@dataclass(frozen=True)
class ProviderView:
    """The canonical, detached, immutable surface a provider sees (Section 8 finding #2).

    Every provider -- in-process or remote adapter -- receives exactly this and nothing
    more. Two things it deliberately is NOT:

    - NOT `AgentState`. The old path handed the in-process provider a whole (mutable)
      `AgentState` via `project_state_for_provider`, so a buggy or hostile in-process
      provider could see host bookkeeping in `memory` (approvals, used_approval_ids,
      migration) that the remote adapters never got, AND mutate the host's live state
      through aliased nested containers. This view drops `memory` entirely -- closing
      BOTH the over-exposure and the mutation -- and also drops `checkpoint_generation`
      (store-owned authority) and `result` (host-owned), neither of which a decision needs.
    - NOT shallow. `messages` is a tuple and `tool_results` a read-only Mapping, but the
      immutability is only skin-deep unless every nested container is detached too. The
      builder (`projection.provider_view`) recursively copies dict->MappingProxyType and
      list->tuple over NEW containers, so no object reachable from here is shared with the
      live state -- a `*` output_projection cannot leak an aliased result object.

    `tool_results` keeps the in-process shape (a mapping keyed by tool name) so a provider's
    truthiness-based "have I run this tool?" check is unchanged; `messages` keeps the remote
    shape. They are two views of ONE per-grant projection, not two different reductions.
    """

    task_id: str
    goal: str
    step: int
    tool_calls: int
    status: Literal["ready", "running", "awaiting_input", "migrating", "completed", "failed"]
    # A single derived boolean, not the raw `memory` dict: True iff this state resumed after
    # a migration (host sets memory["migration"] on the destination). A provider legitimately
    # needs to know it resumed elsewhere so it does not immediately re-migrate; the old path
    # served this by exposing the WHOLE memory dict (approvals bookkeeping included), which is
    # exactly finding #2's over-exposure. Narrowing it to this flag reveals no secret and
    # aliases nothing.
    migrated: bool = False
    messages: tuple[Any, ...] = ()
    tool_results: Mapping[str, Any] = field(default_factory=dict)


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
    # Section 4 #2: on the DESTINATION side, the signed receipt this run issued for an
    # admitted migration (None otherwise). The source verifies it to settle delivery.
    migration_receipt: Json | None = None

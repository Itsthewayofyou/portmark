from __future__ import annotations

from dataclasses import replace
from types import MappingProxyType
from typing import Any

from .models import AgentState, ProviderView, ToolGrant


def _detach(value: Any) -> Any:
    """Deep-copy into json-safe PLAIN containers so nothing reachable from the view aliases
    the caller's live objects (Section 8 finding #2). A shallow copy is not enough:
    `project_tool_output` returns the live object verbatim under a `*` projection, so a
    top-level copy alone would still leave `view.tool_results[k] is
    state.memory["tool_results"][k]`. dict/proxy -> new dict, list/tuple -> new list,
    scalars (immutable) as-is. Values stay PLAIN (not proxies) on purpose: a provider may
    echo tool output straight into its own decision content, which the host then
    json-serializes, and json.dumps raises on MappingProxyType. The view's read-only-ness
    is enforced at the TOP level in `provider_view` (a tuple of messages, a MappingProxyType
    of tool_results); the deep copy -- not deep immutability -- is what removes every alias
    to live host state, which is the actual finding."""
    if isinstance(value, (dict, MappingProxyType)):
        return {key: _detach(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_detach(item) for item in value]
    return value


def provider_view(state: AgentState, grants: tuple[ToolGrant, ...] = ()) -> ProviderView:
    """Build the canonical, detached, immutable view every provider receives (finding #2).

    Replaces `project_state_for_provider`, which handed the in-process provider a whole
    mutable `AgentState` with the host's `memory` bookkeeping still aliased. This projects
    tool output ONCE per grant (the same reduction the wire path uses) and exposes it in
    both shapes -- `tool_results` (in-process) and `messages` (remote) -- then recursively
    detaches both so no reachable object is shared with the live `state`. `memory`,
    `checkpoint_generation` and `result` are dropped entirely.

    The re-proposal semantic is preserved: a granted tool with a share-nothing projection
    keeps a PRESENT but falsy `tool_results[name] == {}` (via `project_tool_output(dict, ())`),
    so a provider's `"tool" not in results` guard still fires exactly once -- identical to the
    old provider path. A tool with no grant is dropped. Any non-dict `tool_results` shape
    fails closed to `{}`, never crossing to the provider unprojected."""
    projections = {grant.name: (grant.output_projection or ()) for grant in grants}
    raw_results = state.memory.get("tool_results") if isinstance(state.memory, dict) else None
    projected_results = {
        name: project_tool_output(result, projections[name])
        for name, result in raw_results.items()
        if name in projections
    } if isinstance(raw_results, dict) else {}
    return ProviderView(
        task_id=state.task_id,
        goal=state.goal,
        step=state.step,
        tool_calls=state.tool_calls,
        status=state.status,
        migrated="migration" in state.memory if isinstance(state.memory, dict) else False,
        # Top-level read-only wrappers over deeply-detached plain data: a tuple of
        # messages (no .append) and a MappingProxyType of tool_results (no key add/remove).
        messages=tuple(_detach(message) for message in project_tool_messages(state.messages, grants)),
        tool_results=MappingProxyType({name: _detach(result) for name, result in projected_results.items()}),
    )


def project_state_for_migration(state: AgentState, grants: tuple[ToolGrant, ...] = ()) -> AgentState:
    # Host-enforced payload confidentiality on migration (section 4 #6). A tool's
    # output_projection is the confidentiality ceiling on what that tool's output may
    # reveal, and the provider path enforces it (provider_view). But a
    # migration sealed the FULL raw state, so a tool's withheld fields crossed the trust
    # boundary to the destination HOST inside both memory["tool_results"] and the tool
    # messages -- bypassing the ceiling entirely. Apply the SAME ceiling here, to the
    # copy that is sealed and sent, so the destination receives only what its delegated
    # permit entitles it to. The delegated permit is minted with audience == the
    # destination and carries exactly these grants, so projecting to them IS
    # per-destination projection: the payload is reduced to that destination's
    # entitlement by construction.
    #
    # This differs from the provider view (provider_view) in one deliberate way: NON-tool
    # messages (user/assistant turns) are kept in full, because the destination RESUMES
    # the task and needs the conversation, whereas the provider projection rebuilds a
    # prompt and drops them. The confidentiality ceiling governs tool OUTPUT, which is
    # what output_projection bounds; user/assistant message content is out of its scope
    # and crosses unchanged. Returns a new state; the caller's own records are untouched.
    #
    # An empty projection (share-nothing) reduces a granted tool's output to {} (a falsy
    # but present value) exactly as the provider path does today: a truthiness-based
    # "have I run this tool?" provider check may then re-propose the tool at the
    # destination. That is the same behavior the provider path already has -- migration
    # merely stops bypassing the ceiling; it introduces no new leak and no new re-run
    # semantics beyond what the ceiling already implies.
    # Non-tool_results memory keys ("migration", "used_approval_ids", "approvals") cross
    # verbatim by design: they are source-side control data, not tool output, and dropping
    # the approval bookkeeping would weaken migration replay prevention. Only tool_results
    # (and the tool messages below) are reduced to the output_projection ceiling.
    projections = {grant.name: (grant.output_projection or ()) for grant in grants}
    projected_memory = dict(state.memory)
    raw_results = state.memory.get("tool_results")
    # Fail closed: tool_results is ALWAYS replaced when present, never passed through.
    # A well-formed dict is projected per grant; ANY other shape (a list, string, number,
    # null -- possible in signed/imported or legacy state) cannot be projected per grant,
    # so it is dropped to {} rather than crossing the trust boundary unprojected. The key
    # is replaced, not deleted, so a resumer sees an empty-but-present results bag.
    if "tool_results" in projected_memory:
        projected_memory["tool_results"] = {
            name: project_tool_output(result, projections[name])
            for name, result in raw_results.items()
            if name in projections
        } if isinstance(raw_results, dict) else {}
    projected_messages: list[dict[str, Any]] = []
    for message in state.messages:
        if message.get("role") != "tool":
            projected_messages.append(message)
            continue
        name = message.get("name")
        # A tool message whose tool the destination has no grant for is dropped: its
        # output is not part of the destination's entitlement (and the destination
        # cannot invoke that tool). A granted tool's message keeps its {role, name} but
        # its content is reduced to the grant's projection ceiling.
        if isinstance(name, str) and name in projections:
            projected_messages.append(
                {"role": "tool", "name": name, "content": project_tool_output(message.get("content"), projections[name])}
            )
    return replace(state, memory=projected_memory, messages=projected_messages)


def provider_state(view: ProviderView) -> dict[str, Any]:
    """Json-serializable wire dict for the remote adapters (HTTP / Wasm) -- a FAITHFUL
    serialization of every ProviderView field, so an in-process provider and a remote
    adapter receive the SAME canonical view and cannot make adapter-dependent decisions
    (Section 8 finding: cross-adapter consistency). `_detach` keeps container values plain,
    but the view's top-level `tool_results` is a MappingProxyType (json.dumps raises on
    that), so it is unwrapped with `dict(...)`; `messages` is a tuple of plain dicts."""
    return {
        "task_id": view.task_id,
        "goal": view.goal,
        "step": view.step,
        "tool_calls": view.tool_calls,
        "status": view.status,
        "migrated": view.migrated,
        "messages": list(view.messages),
        "tool_results": dict(view.tool_results),
    }


def project_tool_messages(messages: list[dict[str, Any]], grants: tuple[ToolGrant, ...]) -> list[dict[str, Any]]:
    projections = {grant.name: grant.output_projection or () for grant in grants}
    projected = []
    for message in messages:
        if message.get("role") != "tool":
            continue
        name = message.get("name")
        if not isinstance(name, str) or name not in projections:
            continue
        output_projection = projections[name]
        projected_message = {"role": "tool", "name": name}
        if output_projection:
            projected_message["content"] = project_tool_output(message.get("content"), output_projection)
        projected.append(projected_message)
    return projected


def project_tool_output(content: Any, output_projection: tuple[str, ...]) -> Any:
    if "*" in output_projection:
        return content
    if isinstance(content, dict):
        return {key: content[key] for key in output_projection if key in content}
    if isinstance(content, list):
        return [project_tool_output(item, output_projection) for item in content if isinstance(item, dict)]
    return None

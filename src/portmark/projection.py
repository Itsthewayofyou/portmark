from __future__ import annotations

from dataclasses import replace
from typing import Any

from .models import AgentState, ToolGrant


def project_state_for_provider(state: AgentState, grants: tuple[ToolGrant, ...] = ()) -> AgentState:
    # Host-enforced projection (finding #4). A grant's output_projection is the ceiling
    # on what tool output may reach the provider, and it was bypassable: an in-process
    # provider that reads state.memory["tool_results"] directly saw fields the grant
    # withheld, because only the adapter path (provider_state / messages) applied it.
    # Enforce it here too, on the same effective.grants the adapter path uses.
    # `grant.output_projection or ()` matches project_tool_messages below and fails
    # closed: an omitted projection is share-nothing, because the host policy is the
    # ceiling and normalizes its own omitted projection to () before the intersection
    # (see HostPolicy effective-permit construction, finding #1) -- so an effective
    # grant here is never None. A tool with no grant is dropped entirely. Each granted
    # tool's KEY is kept with a reduced value (never dropped), so a provider's
    # `"tool" not in results` re-proposal guard still fires exactly once. The real state
    # is untouched: this is a copy, and the host keeps the full tool_results for its own
    # bookkeeping.
    projections = {grant.name: (grant.output_projection or ()) for grant in grants}
    raw_results = state.memory.get("tool_results", {})
    projected_memory = dict(state.memory)
    if isinstance(raw_results, dict):
        projected_memory["tool_results"] = {
            name: project_tool_output(result, projections[name])
            for name, result in raw_results.items()
            if name in projections
        }
    return replace(
        state,
        memory=projected_memory,
        messages=project_tool_messages(state.messages, grants),
    )


def project_state_for_migration(state: AgentState, grants: tuple[ToolGrant, ...] = ()) -> AgentState:
    # Host-enforced payload confidentiality on migration (section 4 #6). A tool's
    # output_projection is the confidentiality ceiling on what that tool's output may
    # reveal, and the provider path enforces it (project_state_for_provider). But a
    # migration sealed the FULL raw state, so a tool's withheld fields crossed the trust
    # boundary to the destination HOST inside both memory["tool_results"] and the tool
    # messages -- bypassing the ceiling entirely. Apply the SAME ceiling here, to the
    # copy that is sealed and sent, so the destination receives only what its delegated
    # permit entitles it to. The delegated permit is minted with audience == the
    # destination and carries exactly these grants, so projecting to them IS
    # per-destination projection: the payload is reduced to that destination's
    # entitlement by construction.
    #
    # This differs from project_state_for_provider in one deliberate way: NON-tool
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


def provider_state(state: AgentState, grants: tuple[ToolGrant, ...] = ()) -> dict[str, Any]:
    return {
        "task_id": state.task_id,
        "goal": state.goal,
        "step": state.step,
        "tool_calls": state.tool_calls,
        "status": state.status,
        "messages": project_tool_messages(state.messages, grants),
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

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

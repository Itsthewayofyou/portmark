from __future__ import annotations

from typing import Any

from .models import AgentState, ToolGrant


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

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from .models import ResourceBudget, ToolGrant
from .security import HostPolicy, TrustedApprover, canonical_json


VALID_IMPACTS = {"low", "medium", "high", "destructive", "external-payment", "credentialed", "data-exfiltration"}


def load_host_policy(path: str | Path, audience: str) -> HostPolicy:
    value = _read_policy(path)
    return policy_from_dict(value, audience)


def policy_from_dict(value: dict[str, Any], audience: str) -> HostPolicy:
    version = _required_string(value, "version")
    tools = _required_object(value, "tools")
    budget = _budget(value.get("budget", {}))
    grants = []
    impacts: dict[str, str] = {}
    for name, config in tools.items():
        if not isinstance(name, str) or not name:
            raise ValueError("policy tool names must be non-empty strings")
        if not isinstance(config, dict):
            raise ValueError("policy tool entries must be objects")
        impact = config.get("impact", "low")
        if impact not in VALID_IMPACTS:
            raise ValueError(f"policy tool {name!r} has invalid impact")
        constraints = config.get("constraints", {})
        if not isinstance(constraints, dict):
            raise ValueError(f"policy tool {name!r} constraints must be an object")
        grants.append(ToolGrant(name, constraints, _output_projection(config.get("output_projection"), name)))
        impacts[name] = impact
    if not grants:
        raise ValueError("policy must grant at least one tool")
    approval_required_impacts = _approval_required_impacts(value.get("approval_required_impacts", HostPolicy.DEFAULT_APPROVAL_REQUIRED_IMPACTS))
    return HostPolicy(
        audience=audience,
        grants=tuple(grants),
        budget=budget,
        policy_version=version,
        policy_hash=_policy_hash(value),
        tool_impacts=impacts,
        approval_authorities=_approval_authorities(value.get("approval_authorities", ())),
        approval_required_impacts=approval_required_impacts,
    )


def _read_policy(path: str | Path) -> dict[str, Any]:
    with open(path, "rb") as file:
        value = json.load(file)
    if not isinstance(value, dict):
        raise ValueError("policy root must be an object")
    return value


def _policy_hash(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _budget(value: Any) -> ResourceBudget:
    if not isinstance(value, dict):
        raise ValueError("policy budget must be an object")
    allowed = {"max_steps", "max_tool_calls", "max_output_bytes"}
    unknown = set(value) - allowed
    if unknown:
        raise ValueError("policy budget contains unsupported fields")
    return ResourceBudget(**value)


def _approval_authorities(value: Any) -> tuple[TrustedApprover, ...]:
    if value in (None, ()):
        return ()
    if not isinstance(value, list):
        raise ValueError("approval_authorities must be a list")
    authorities = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("approval authority entries must be objects")
        authorities.append(
            TrustedApprover(
                key_id=_required_string(item, "key_id"),
                approver=_required_string(item, "approver"),
                public_key=_b64url_decode(_required_string(item, "public_key_b64")),
                not_before=int(item.get("not_before", 0)),
                expires_at=int(item["expires_at"]) if item.get("expires_at") is not None else None,
                revoked=bool(item.get("revoked", False)),
            )
        )
    return tuple(authorities)


def _approval_required_impacts(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ValueError("approval_required_impacts must be a non-empty list")
    impacts = tuple(value)
    if not all(isinstance(impact, str) and impact in VALID_IMPACTS for impact in impacts):
        raise ValueError("approval_required_impacts contains an invalid impact")
    return impacts


def _output_projection(value: Any, tool: str) -> tuple[str, ...] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError(f"policy tool {tool!r} output_projection must be a list")
    if not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"policy tool {tool!r} output_projection entries must be non-empty strings")
    if "*" in value and len(value) > 1:
        raise ValueError(f"policy tool {tool!r} output_projection cannot mix '*' with field names")
    return tuple(value)


def _required_string(value: dict[str, Any], name: str) -> str:
    result = value.get(name)
    if not isinstance(result, str) or not result:
        raise ValueError(f"policy {name} must be a non-empty string")
    return result


def _required_object(value: dict[str, Any], name: str) -> dict[str, Any]:
    result = value.get(name)
    if not isinstance(result, dict):
        raise ValueError(f"policy {name} must be an object")
    return result


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    decoded = base64.urlsafe_b64decode(value + padding)
    if len(decoded) != 32:
        raise ValueError("approval public keys must be 32 raw bytes")
    return decoded

"""`portmark policy check`: what a host policy file allows, in plain words, before it is deployed.

The file is loaded with the SAME strict loader the host uses (`policy_from_dict`), so the check can never
accept a policy the host would refuse, and the reported `policy_hash` is the one the host puts in its
approval requests. On top of the loader, it warns about settings that are valid but almost certainly not what
the operator meant (a rule that can never take effect, an approval nobody is trusted to give).

This is a reading aid, not a second policy engine: the host's decisions come from the host.
"""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

from ._clock import trusted_now
from .policy import _read_policy, policy_from_dict
from .spend import STORAGE_SCALE

# The policy file has no audience (the host supplies its own id); any value works for reading it.
_AUDIENCE = "host:policy-check"


def _units(minor: int) -> str:
    """Storage units (millionths) back to the plain amount: 50_000_000 -> "50", 99_990_000 -> "99.99"."""
    text = format((Decimal(minor) / (10**STORAGE_SCALE)).normalize(), "f")
    return text


def check_policy(value: Any) -> dict[str, Any]:
    """A report on a parsed policy file: status "ok" with a description and warnings, or "invalid" with the
    loader's reason."""
    if not isinstance(value, dict):
        return {"status": "invalid", "error": "policy root must be an object"}
    try:
        policy = policy_from_dict(value, _AUDIENCE)
    except (ValueError, TypeError, KeyError) as error:
        return {"status": "invalid", "error": str(error)}

    budgets = policy.spend_budgets
    budgeted_tools = set(budgets.tools) if budgets is not None else set()
    thresholds = dict(budgets.approval_above) if budgets is not None else {}
    impact_gated = set(policy.approval_required_impacts)
    # Counted the way HostPolicy.verify_approval accepts a signer: the host keeps the LAST entry per key_id,
    # and a revoked, not-yet-valid or expired key approves nothing (same comparisons, same clock).
    now = trusted_now()
    authorities = [
        authority for authority in policy._approval_authorities.values()  # noqa: SLF001 - read-only, same package
        if not authority.revoked and authority.not_before <= now and (authority.expires_at is None or authority.expires_at > now)
    ]
    warnings: list[str] = []
    tools = []
    for grant in policy.grants:
        name = grant.name
        impact = policy.impact_for_tool(name)
        budgeted = name in budgeted_tools
        if impact in impact_gated:
            approval = f"always (impact {impact})"
            if budgeted and thresholds:
                warnings.append(
                    f"{name}: approval_above has no effect here, because impact {impact!r} already needs approval "
                    "at every amount"
                )
        elif budgeted and thresholds:
            approval = ", ".join(f"over {_units(minor)} {currency}" for currency, minor in sorted(thresholds.items()))
        else:
            approval = "never"
        if name in policy.implicit_impacts and approval != f"always (impact {impact})" and "high" in impact_gated:
            # The host treats a side-effecting tool with no impact as "high" (HostPolicy.impact_for); the file
            # alone cannot say whether the installed tool is side-effecting.
            approval = f"{approval}; always if the installed tool is side-effecting (no impact set: treated as high)"
        if name in policy.implicit_impacts:
            warnings.append(
                f"{name}: no impact is set, so it defaults to \"low\" (a side-effecting tool is treated as \"high\"); "
                "the production profile refuses this policy"
            )
        tools.append({"name": name, "impact": impact, "approval": approval, "budgeted": budgeted})

    if not authorities and any(tool["approval"] != "never" for tool in tools):
        warnings.append(
            "no approval authority is trusted and active now (approval_authorities: none, or only revoked, expired "
            "or not-yet-valid keys), so a call that needs approval can never be approved"
        )

    spend = None
    if budgets is not None:
        for currency, limit in sorted(budgets.limits.items()):
            if limit == 0:
                warnings.append(f"{currency}: the limit is 0, so every call in this currency is refused")
            threshold = budgets.approval_above.get(currency)
            if threshold is not None and limit > 0 and threshold >= limit:
                warnings.append(
                    f"{currency}: approval_above ({_units(threshold)}) is at or above the {budgets.period} limit "
                    f"({_units(limit)}), so no approved call over it can ever fit in the limit"
                )
        spend = {
            "period": budgets.period,
            "owner": "permit signer (permit.issuer)",
            "limits": {currency: _units(minor) for currency, minor in sorted(budgets.limits.items())},
            "approval_above": {currency: _units(minor) for currency, minor in sorted(budgets.approval_above.items())},
            "tools": sorted(budgets.tools),
        }

    return {
        "status": "ok",
        "policy_version": policy.policy_version,
        "policy_hash": policy.policy_hash,
        "tools": tools,
        "spend_budgets": spend,
        "approval_authorities": len(authorities),
        "warnings": warnings,
    }


def check_policy_file(path: str | Path) -> dict[str, Any]:
    """`check_policy` on a file; an unreadable file or bad JSON is reported as invalid, never raised."""
    try:
        value = _read_policy(path)
    except (OSError, ValueError) as error:  # json.JSONDecodeError is a ValueError
        return {"status": "invalid", "error": f"cannot read {path}: {error}"}
    return check_policy(value)


def render_text(report: dict[str, Any]) -> str:
    if report["status"] != "ok":
        return f"Policy INVALID: {report['error']}\nThe host would refuse to load this file."
    lines = [
        f"Policy {report['policy_version']} ({report['policy_hash']}): OK"
        + (f", {len(report['warnings'])} warning(s)" if report["warnings"] else ""),
        "",
        "Tools:",
    ]
    width = max(len(tool["name"]) for tool in report["tools"])
    impact_width = max(len(tool["impact"]) for tool in report["tools"])
    for tool in report["tools"]:
        budget = "  budgeted" if tool["budgeted"] else ""
        lines.append(
            f"  {tool['name']:<{width}}  impact {tool['impact']:<{impact_width}}  approval: {tool['approval']}{budget}"
        )
    spend = report["spend_budgets"]
    lines.append("")
    if spend is None:
        lines.append("Spend budget: none (per-call constraints only)")
    else:
        limits = ", ".join(f"{amount} {currency}" for currency, amount in spend["limits"].items())
        lines.append(f"Spend budget: per {spend['owner']}, per UTC {spend['period']}: {limits}")
        if spend["approval_above"]:
            above = ", ".join(f"{amount} {currency}" for currency, amount in spend["approval_above"].items())
            lines.append(f"  approval needed for a single call over: {above}")
    lines.append(f"Approval authorities trusted: {report['approval_authorities']}")
    if report["warnings"]:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in report["warnings"])
    return "\n".join(lines)


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2)

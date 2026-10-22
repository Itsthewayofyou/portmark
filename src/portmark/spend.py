"""Host-enforced cumulative spend budgets (closes the per-call-only gap, PM-AUTH-015).

A per-call `max_amount` cannot stop two 99 USD payments under a 100 USD cap. A spend budget can: the
host policy names which tool arguments carry an amount and a currency, and a limit per currency. The
host then charges every call of such a tool against a running total kept in the store, per permit
signer (`permit.issuer`), per calendar period (UTC day or month), and refuses a call that would go over.

The host policy owns the budget; a permit cannot raise or remove it. Amounts are converted to integer
minor units from their canonical JSON text with `Decimal`, never with float arithmetic, and an amount
with more decimals than the policy's `scale` is refused rather than rounded.
"""

from __future__ import annotations

import datetime
import math
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

from .security import SecurityError, canonical_json

PERIODS = ("day", "month")
DEFAULT_PERIOD = "day"
DEFAULT_SCALE = 2
MAX_SCALE = 6
# Every amount and total is STORED in millionths of the currency unit, whatever the policy's `scale`.
# `scale` only limits how many decimals an amount may have. A fixed storage unit means a policy edit
# that changes `scale` can never reinterpret the running totals already in the store.
STORAGE_SCALE = 6
# 10**15 millionths = 10**9 currency units; far below 2**63 (BIGINT / SQLite INTEGER), so no overflow.
MAX_MINOR_UNITS = 10**15
_MAX_CURRENCY_LENGTH = 16
_POLICY_KEYS = frozenset({"period", "scale", "limits", "tools"})
_TOOL_KEYS = frozenset({"amount", "currency"})


@dataclass(frozen=True)
class SpendTool:
    amount: str
    currency: str


@dataclass(frozen=True)
class SpendBudgetPolicy:
    period: str
    scale: int
    limits: dict[str, int] = field(default_factory=dict)  # currency -> limit in minor units
    tools: dict[str, SpendTool] = field(default_factory=dict)


@dataclass(frozen=True)
class SpendCharge:
    currency: str
    amount_minor: int
    limit_minor: int


def parse_spend_budgets(value: Any) -> SpendBudgetPolicy | None:
    """Parse the host policy's `spend_budgets` block. None when absent. Unknown keys are refused:
    a typo in a money control must fail loudly, not silently switch the control off."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("policy spend_budgets must be an object")
    unknown = set(value) - _POLICY_KEYS
    if unknown:
        raise ValueError(f"policy spend_budgets has unknown keys: {sorted(unknown)}")
    period = value.get("period", DEFAULT_PERIOD)
    if period not in PERIODS:
        raise ValueError(f"policy spend_budgets period must be one of {list(PERIODS)}")
    scale = value.get("scale", DEFAULT_SCALE)
    if isinstance(scale, bool) or not isinstance(scale, int) or not 0 <= scale <= MAX_SCALE:
        raise ValueError(f"policy spend_budgets scale must be a whole number from 0 to {MAX_SCALE}")
    raw_limits = value.get("limits")
    if not isinstance(raw_limits, dict) or not raw_limits:
        raise ValueError("policy spend_budgets limits must be a non-empty object")
    limits: dict[str, int] = {}
    for currency, limit in raw_limits.items():
        _check_currency(currency)
        try:
            limits[currency] = to_minor_units(limit, scale, allow_zero=True)
        except SecurityError as error:
            raise ValueError(f"policy spend_budgets limit for {currency!r}: {error}") from None
    raw_tools = value.get("tools")
    if not isinstance(raw_tools, dict) or not raw_tools:
        raise ValueError("policy spend_budgets tools must be a non-empty object")
    tools: dict[str, SpendTool] = {}
    for name, config in raw_tools.items():
        if not isinstance(name, str) or not name:
            raise ValueError("policy spend_budgets tool names must be non-empty strings")
        if not isinstance(config, dict) or set(config) != _TOOL_KEYS:
            raise ValueError(f"policy spend_budgets tool {name!r} must name exactly 'amount' and 'currency'")
        amount, currency = config["amount"], config["currency"]
        if not (isinstance(amount, str) and amount and isinstance(currency, str) and currency) or amount == currency:
            raise ValueError(f"policy spend_budgets tool {name!r} must name two different argument names")
        tools[name] = SpendTool(amount=amount, currency=currency)
    return SpendBudgetPolicy(period=period, scale=scale, limits=limits, tools=tools)


def _check_currency(currency: Any) -> None:
    if not isinstance(currency, str) or not currency or len(currency) > _MAX_CURRENCY_LENGTH:
        raise ValueError("policy spend_budgets currencies must be short non-empty strings")


def to_minor_units(value: Any, scale: int, *, allow_zero: bool = False) -> int:
    """An amount as an integer count of storage units (millionths: 99.99 -> 99_990_000), or SecurityError.

    Read from the value's canonical JSON text with Decimal, so 99.99 is exact (float arithmetic would
    give 99.989999...). More decimals than `scale` is refused, never rounded."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SecurityError("spend amount must be a number")
    if isinstance(value, float) and not math.isfinite(value):
        raise SecurityError("spend amount must be finite")
    try:
        amount = Decimal(canonical_json(value).decode("ascii"))
    except (InvalidOperation, ValueError, TypeError) as error:
        raise SecurityError("spend amount is not a valid number") from error
    if amount < 0 or (amount == 0 and not allow_zero):
        raise SecurityError("spend amount must be greater than zero")
    scaled = amount.scaleb(scale)
    if scaled != scaled.to_integral_value():
        raise SecurityError(f"spend amount has more than {scale} decimal places")
    minor = int(amount.scaleb(STORAGE_SCALE))
    if minor > MAX_MINOR_UNITS:
        raise SecurityError("spend amount is too large")
    return minor


def charge_for(policy: SpendBudgetPolicy | None, tool: str, arguments: dict[str, Any] | None) -> SpendCharge | None:
    """What a call of `tool` with these (canonical, detached) arguments costs, or None if the tool is
    not budgeted. Raises SecurityError for a budgeted call whose amount or currency is unusable."""
    if policy is None or tool not in policy.tools:
        return None
    spec = policy.tools[tool]
    arguments = arguments or {}
    if spec.amount not in arguments or spec.currency not in arguments:
        raise SecurityError(f"budgeted tool {tool!r} needs arguments {spec.amount!r} and {spec.currency!r}")
    currency = arguments[spec.currency]
    if not isinstance(currency, str) or currency not in policy.limits:
        raise SecurityError(f"budgeted tool {tool!r}: no spend limit for this currency")
    return SpendCharge(
        currency=currency,
        amount_minor=to_minor_units(arguments[spec.amount], policy.scale),
        limit_minor=policy.limits[currency],
    )


def no_looser(previous: SpendBudgetPolicy | None, fresh: SpendBudgetPolicy | None) -> bool:
    """Whether `fresh` restricts at least as much as `previous`, for a run already in flight (U1: a reload
    in flight can only narrow). Same period (another period would start a different total); every
    previously budgeted tool still budgeted, with the same amount and currency arguments; every previous
    currency still listed, with a limit no higher. `scale` cannot loosen anything: totals are stored in
    a fixed unit, and a smaller scale only refuses more amounts."""
    if previous is None:
        return True
    if fresh is None or fresh.period != previous.period:
        return False
    for tool, spec in previous.tools.items():
        if fresh.tools.get(tool) != spec:
            return False
    for currency, limit in previous.limits.items():
        if currency not in fresh.limits or fresh.limits[currency] > limit:
            return False
    return True


def period_key(now: int, period: str) -> str:
    """The calendar period (UTC) that `now` falls in: '2026-10-22' for day, '2026-10' for month."""
    moment = datetime.datetime.fromtimestamp(now, tz=datetime.timezone.utc)
    if period == "day":
        return moment.strftime("%Y-%m-%d")
    if period == "month":
        return moment.strftime("%Y-%m")
    raise ValueError(f"unknown spend period {period!r}")

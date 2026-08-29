from __future__ import annotations

import json
import random
import string
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from portmark.a2a import envelope_from_dict
from portmark.a2a_types import A2ARequestError, parse_jsonrpc_request
from portmark.models import AgentEnvelope


def run_fuzz_cases(iterations: int = 500, seed: int = 20260829) -> None:
    # Deterministic fuzz corpus generation; not security randomness.
    rng = random.Random(seed)  # nosec B311
    for _ in range(iterations):
        value = _json_value(rng)
        _assert_parser_fails_closed(parse_jsonrpc_request, value)
        _assert_parser_fails_closed(envelope_from_dict, value, AgentEnvelope)

        encoded = json.dumps(value).encode()
        decoded = json.loads(encoded)
        _assert_parser_fails_closed(parse_jsonrpc_request, decoded)
        _assert_parser_fails_closed(envelope_from_dict, decoded, AgentEnvelope)

    for value in _targeted_malformed_envelopes():
        _assert_parser_fails_closed(envelope_from_dict, value, AgentEnvelope)


def _assert_parser_fails_closed(parser, value: Any, success_type: type | None = None) -> None:
    try:
        parsed = parser(value)
    except A2ARequestError:
        return
    except Exception as exc:
        raise AssertionError(f"{parser.__name__} leaked {type(exc).__name__} for {value!r}") from exc
    if success_type is not None and not isinstance(parsed, success_type):
        raise AssertionError(f"{parser.__name__} returned unexpected {type(parsed).__name__}")


def _targeted_malformed_envelopes() -> tuple[Any, ...]:
    return (
        {"manifest": {}, "permit": {}, "state": {}, "signature": "sig"},
        {"manifest": {"requested_tools": None}, "permit": {}, "state": {}, "signature": "sig"},
        {"manifest": [], "permit": {}, "state": {}, "signature": "sig"},
        {"manifest": {"requested_tools": []}, "permit": [], "state": {}, "signature": "sig"},
        {"manifest": {"requested_tools": []}, "permit": {"grants": None}, "state": {}, "signature": "sig"},
        {"manifest": {"requested_tools": []}, "permit": {"grants": [None]}, "state": {}, "signature": "sig"},
        {"manifest": {"requested_tools": []}, "permit": {"grants": []}, "state": [], "signature": "sig"},
    )


def _json_value(rng: random.Random, depth: int = 0) -> Any:
    if depth > 4:
        return _json_scalar(rng)
    kind = rng.randrange(7)
    if kind < 4:
        return _json_scalar(rng)
    if kind == 4:
        return [_json_value(rng, depth + 1) for _ in range(rng.randrange(5))]
    keys = ["jsonrpc", "id", "method", "params", "message", "metadata", "portmark_envelope", _random_string(rng)]
    return {rng.choice(keys): _json_value(rng, depth + 1) for _ in range(rng.randrange(6))}


def _json_scalar(rng: random.Random) -> Any:
    kind = rng.randrange(6)
    if kind == 0:
        return None
    if kind == 1:
        return rng.choice((True, False))
    if kind == 2:
        return rng.randrange(-10_000, 10_000)
    if kind == 3:
        return rng.random()
    return _random_string(rng)


def _random_string(rng: random.Random) -> str:
    alphabet = string.ascii_letters + string.digits + "_-.:/"
    return "".join(rng.choice(alphabet) for _ in range(rng.randrange(24)))


if __name__ == "__main__":
    run_fuzz_cases()

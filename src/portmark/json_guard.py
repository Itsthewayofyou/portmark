"""Strict JSON decoding for UNTRUSTED input crossing a trust boundary (Section 8 finding #4).

`json.loads` has two properties that are unsafe on adversarial input:

- A JSON object with **duplicate keys** parses silently, last-value-wins. Two parties can then
  disagree about what a message meant, and a validator that inspects one key can be bypassed by a
  second copy of it.
- A **deeply nested** document drives `json.loads`'s recursive-descent parser into a
  `RecursionError`, which is NOT a `json.JSONDecodeError` -- so a handler that only catches
  `JSONDecodeError` lets it escape as an uncaught crash.

`strict_json_loads` closes both: it pre-scans nesting depth (bounded, string-aware) BEFORE parsing so
the recursion never happens, rejects duplicate object keys via an `object_pairs_hook`, enforces an
optional byte cap, and turns malformed / non-UTF-8 / over-limit input into one `StrictJSONError`
(a `ValueError` subclass) that callers convert to their own domain error. Stdlib only."""

from __future__ import annotations

import json
from typing import Any

# Legit envelopes / decisions nest ~8-15 deep; json.loads hits RecursionError near the ~1000
# recursion limit. 64 sits comfortably between: adversarial nesting is refused, real traffic is not.
_MAX_JSON_DEPTH = 64


class StrictJSONError(ValueError):
    """Untrusted JSON rejected: malformed, invalid UTF-8, over the size cap, too deeply nested, or
    containing duplicate object keys. A `ValueError` subclass (as `json.JSONDecodeError` already is)
    so a caller can catch this one type and map it to its own error."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError(f"duplicate object key: {key!r}")
        result[key] = value
    return result


def _check_depth(text: str, max_depth: int) -> None:
    # String-aware structural scan: only { and [ OUTSIDE a string literal add depth, so braces or
    # brackets inside a string value never count, and an escaped quote (\") never ends the string.
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{" or char == "[":
            depth += 1
            if depth > max_depth:
                raise StrictJSONError(f"JSON nesting exceeds the depth cap ({max_depth})")
        elif char == "}" or char == "]":
            depth -= 1


def strict_json_loads(raw: str | bytes | bytearray, *, max_bytes: int | None = None, max_depth: int = _MAX_JSON_DEPTH) -> Any:
    """Parse untrusted JSON, or raise `StrictJSONError`. `max_bytes` bounds the encoded size (many
    callers already cap it upstream; pass it for defense in depth). Duplicate keys and nesting past
    `max_depth` are rejected; the depth pre-scan runs before `json.loads` so a hostile document can
    never reach the recursive parser."""
    if isinstance(raw, str):
        text = raw
        byte_length = len(raw.encode("utf-8"))
    elif isinstance(raw, (bytes, bytearray)):
        byte_length = len(raw)
        try:
            text = bytes(raw).decode("utf-8")
        except UnicodeDecodeError as error:
            raise StrictJSONError("input is not valid UTF-8") from error
    else:
        raise StrictJSONError("input must be str or bytes")
    if max_bytes is not None and byte_length > max_bytes:
        raise StrictJSONError(f"JSON input exceeds the size cap ({max_bytes} bytes)")
    _check_depth(text, max_depth)
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise StrictJSONError("malformed JSON") from error

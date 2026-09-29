"""Strict Base64URL and small field validators shared by the trust, policy and witness code.

A neutral home, so policy and the witness client do not reach into security.py's private helpers.
"""

from __future__ import annotations

import base64
import binascii
import string
from typing import Any

_B64URL_ALPHABET = frozenset(string.ascii_letters + string.digits + "-_")


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    # Strict, canonical unpadded Base64URL only (Codex audit finding #6). The lenient
    # form accepted non-alphabet characters, added padding and non-canonical trailing
    # bits, so byte-for-byte-different strings decoded to the same signature/key bytes
    # and could evade a naive tamper check or signature-string cache. We reject anything
    # that does not re-encode to exactly the input. Raises ValueError so the existing
    # (InvalidSignature, ValueError) handlers at every verify call site convert it to a
    # SecurityError, and load_trust_registry surfaces it as a validation error.
    if not isinstance(value, str):
        raise ValueError("base64url value must be a string")
    if len(value) % 4 == 1:
        raise ValueError("base64url value has an impossible length")
    if any(ch not in _B64URL_ALPHABET for ch in value):
        raise ValueError("base64url value contains a non-alphabet character")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.urlsafe_b64decode(value + padding)
    except (binascii.Error, ValueError) as error:
        raise ValueError("base64url value is not decodable") from error
    if b64url_encode(decoded) != value:
        raise ValueError("base64url value is not canonically encoded")
    return decoded


def decode_raw_key(value: str, label: str) -> bytes:
    """A strict Base64URL Ed25519 public key: exactly 32 raw bytes."""
    decoded = b64url_decode(value)
    if len(decoded) != 32:
        raise ValueError(f"{label} must be 32 raw bytes")
    return decoded


def required_string(value: dict[str, Any], name: str, label: str) -> str:
    result = value.get(name)
    if not isinstance(result, str) or not result:
        raise ValueError(f"{label} {name} must be a non-empty string")
    return result

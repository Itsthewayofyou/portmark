"""Optional authenticated encryption of stored checkpoints (EV-006, TM-005).

A checkpoint row holds the task state as JSON. With a keyring configured, the durable stores seal
that JSON with AES-256-GCM before they write it and open it when they read it. The associated data
binds the format version, the task id, the row generation, the key id and the plaintext columns the
store gates on (the effective `closed` value and the owner), so a sealed checkpoint cannot be moved to
another task or generation, a task cannot be reopened or closed and an owner cannot be rewritten by
editing a column, and a changed byte fails authentication. The `status` column is compared with the sealed state on every read.

Reads are strict (owner decision D2): with a keyring, a plaintext row is refused; without one, a
sealed row is refused. Existing plaintext rows are converted once with
`portmark store encrypt-checkpoints`. Encryption is optional (owner decision D1); the
`checkpoint_encryption_active` gauge reports it.

Not covered: a restore of a whole older row (its old ciphertext AND its old generation) still
authenticates. That is rollback, which the audit floor and a remote witness (EV-013) address. The
columns stay readable (the store queries them); they are authenticated, not hidden.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import secrets
import stat
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .security import SecurityError, canonical_json

CHECKPOINT_KEYS_ENV = "PORTMARK_CHECKPOINT_KEYS"
CHECKPOINT_KEYS_FILE_ENV = "PORTMARK_CHECKPOINT_KEYS_FILE"
SEALED_PREFIX = "pmc1:"
_KEY_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_NONCE_BYTES = 12


class CheckpointCryptoError(SecurityError):
    """A stored checkpoint cannot be opened: wrong key, changed bytes, or a plaintext/sealed mismatch."""


def is_sealed(stored: str) -> bool:
    return stored.startswith(SEALED_PREFIX)


def _associated_data(task_id: str, generation: int, key_id: str, row: Mapping[str, Any] | None) -> bytes:
    # `row` carries the plaintext columns the store gates on (closed, owner), so a changed column no
    # longer authenticates with the sealed state it claims to describe.
    return canonical_json({
        "format": "portmark.checkpoint.v1", "task_id": task_id, "generation": int(generation), "key_id": key_id,
        "row": dict(row or {}),
    })


class CheckpointCodec:
    """A keyring: the FIRST key seals new checkpoints; every key can open. Keys are 32 random bytes."""

    def __init__(self, keys: tuple[tuple[str, bytes], ...]) -> None:
        if not keys:
            raise ValueError("a checkpoint keyring needs at least one key")
        seen: set[str] = set()
        for key_id, key in keys:
            if not _KEY_ID.fullmatch(key_id):
                raise ValueError(f"checkpoint key id {key_id!r} must be 1-64 characters of A-Z a-z 0-9 . _ -")
            if key_id in seen:
                raise ValueError(f"checkpoint key id {key_id!r} appears twice")
            if len(key) != 32:
                raise ValueError(f"checkpoint key {key_id!r} must be exactly 32 bytes (AES-256)")
            seen.add(key_id)
        self._keys = {key_id: AESGCM(key) for key_id, key in keys}
        self.current_key_id = keys[0][0]

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(self._keys)

    def seal(self, task_id: str, generation: int, plaintext: str, row: Mapping[str, Any] | None = None) -> str:
        nonce = secrets.token_bytes(_NONCE_BYTES)
        sealed = self._keys[self.current_key_id].encrypt(
            nonce, plaintext.encode("utf-8"), _associated_data(task_id, generation, self.current_key_id, row)
        )
        body = base64.urlsafe_b64encode(nonce + sealed).decode("ascii").rstrip("=")
        return f"{SEALED_PREFIX}{self.current_key_id}:{body}"

    def key_id_of(self, stored: str) -> str:
        if not is_sealed(stored):
            raise CheckpointCryptoError("checkpoint is not encrypted")
        key_id, separator, _ = stored[len(SEALED_PREFIX):].partition(":")
        if not separator or not _KEY_ID.fullmatch(key_id):
            raise CheckpointCryptoError("encrypted checkpoint has a malformed header")
        return key_id

    def open(self, task_id: str, generation: int, stored: str, row: Mapping[str, Any] | None = None) -> str:
        key_id = self.key_id_of(stored)
        aead = self._keys.get(key_id)
        if aead is None:
            raise CheckpointCryptoError(f"checkpoint is encrypted with key {key_id!r}, which is not in the keyring")
        body = stored[len(SEALED_PREFIX) + len(key_id) + 1:]
        try:
            raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        except (binascii.Error, ValueError) as error:
            raise CheckpointCryptoError("encrypted checkpoint is not valid base64") from error
        if len(raw) < _NONCE_BYTES + 16:
            raise CheckpointCryptoError("encrypted checkpoint is too short")
        try:
            plaintext = aead.decrypt(raw[:_NONCE_BYTES], raw[_NONCE_BYTES:], _associated_data(task_id, generation, key_id, row))
        except InvalidTag as error:
            raise CheckpointCryptoError("checkpoint failed authentication (wrong key, changed bytes, or moved row)") from error
        return plaintext.decode("utf-8")

    def open_stored(self, task_id: str, generation: int, stored: str, row: Mapping[str, Any] | None = None) -> str:
        """The strict read (D2): refuse a plaintext row when a keyring is configured."""
        if not is_sealed(stored):
            raise CheckpointCryptoError(
                "checkpoint is not encrypted but a checkpoint keyring is configured; "
                "run `portmark store encrypt-checkpoints --apply` with the host stopped"
            )
        return self.open(task_id, generation, stored, row)


def refuse_sealed_without_key(stored: str) -> str:
    """The strict read with no keyring: a sealed row cannot be read and is refused, never guessed at."""
    if is_sealed(stored):
        raise CheckpointCryptoError(
            f"checkpoint is encrypted but no checkpoint keyring is configured ({CHECKPOINT_KEYS_ENV} or {CHECKPOINT_KEYS_FILE_ENV})"
        )
    return stored


def parse_keyring(text: str) -> CheckpointCodec:
    """Parse `key-id:base64key[,key-id:base64key...]` (commas or newlines). The first key seals."""
    keys: list[tuple[str, bytes]] = []
    for entry in re.split(r"[,\n]", text):
        entry = entry.strip()
        if not entry:
            continue
        key_id, separator, encoded = entry.partition(":")
        if not separator:
            raise ValueError("each checkpoint key must be written as key-id:base64-key")
        encoded = encoded.strip()
        try:
            key = base64.b64decode(encoded.replace("-", "+").replace("_", "/") + "=" * (-len(encoded) % 4), validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError(f"checkpoint key {key_id.strip()!r} is not valid base64") from error
        keys.append((key_id.strip(), key))
    return CheckpointCodec(tuple(keys))


def codec_from_environment(environ: Mapping[str, str] | None = None) -> CheckpointCodec | None:
    """The keyring from the environment, or None when encryption is not configured (D1: optional)."""
    environ = os.environ if environ is None else environ
    inline = environ.get(CHECKPOINT_KEYS_ENV, "").strip()
    path = environ.get(CHECKPOINT_KEYS_FILE_ENV, "").strip()
    if inline and path:
        raise ValueError(f"set {CHECKPOINT_KEYS_ENV} or {CHECKPOINT_KEYS_FILE_ENV}, not both")
    if path:
        try:
            mode = os.stat(path).st_mode
            if os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise ValueError(f"{CHECKPOINT_KEYS_FILE_ENV} {path} must not be readable by group or others (chmod 600)")
            with open(path, encoding="utf-8") as handle:
                inline = handle.read().strip()
        except OSError as error:
            raise ValueError(f"{CHECKPOINT_KEYS_FILE_ENV} {path} cannot be read: {error}") from error
        if not inline:
            raise ValueError(f"{CHECKPOINT_KEYS_FILE_ENV} {path} is empty")
    return parse_keyring(inline) if inline else None


def generate_key() -> str:
    """A new random 32-byte key, base64url without padding, for `key-id:<this>`."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")

"""Where one HTTP MCP server's OAuth tokens live between runs (MCP OAuth plan, phase 1).

A refresh token is a durable credential: it outlives the process, and whoever holds it can mint access
tokens until it is revoked. So this file is written owner-only and atomically, it is refused when the
filesystem says someone else can read it, and nothing here ever puts a token in a string that could reach a
log or an exception.

**The issuer binding is the point, not a detail.** The specification is explicit that credentials belong to
the authorization server that issued them: clients "MUST associate those credentials with the specific
authorization server that issued them, keyed by the authorization server's `issuer` identifier", MUST NOT
reuse credentials from a different authorization server, and SHOULD surface an error rather than silently
using mismatched ones. A server that changes the authorization server it names is either being reconfigured
or being attacked, and from here the two look identical -- so the stored issuer is recorded and checked, and
a mismatch refuses. That is the same shape as Portmark's tool pin: record what was approved, refuse on drift.
"""

from __future__ import annotations

import json
import os
import stat
import time
from dataclasses import dataclass, replace

from ._durable_file import atomic_write_bytes, sidecar_lock
from .json_guard import StrictJSONError, strict_json_loads

# The format this module writes. A file from a future version is refused rather than guessed at: a token
# store read under the wrong rules is a credential used under the wrong rules.
STORE_VERSION = 1
SCHEMA = "portmark.mcp.oauth.v1"
# A store holds a handful of short strings. Anything larger is not a token store.
MAX_STORE_BYTES = 64 * 1024
# Refresh this long before the access token actually expires, so a call never races its own expiry.
REFRESH_MARGIN_SECONDS = 60


class TokenStoreError(Exception):
    """The token store cannot be used as it stands. Always actionable by the operator."""


@dataclass(frozen=True)
class StoredTokens:
    """One server's tokens, bound to the authorization server and client that issued them."""

    issuer: str
    client_id: str
    access_token: str
    expires_at: int
    refresh_token: str = ""
    scopes: tuple[str, ...] = ()

    def __repr__(self) -> str:
        """Redacted on purpose. The default dataclass repr would print both tokens, and this object travels
        through exceptions and log records where a repr is exactly what gets written."""
        held = ",".join(name for name, value in (("access", self.access_token), ("refresh", self.refresh_token)) if value)
        return f"StoredTokens(issuer={self.issuer!r}, client_id={self.client_id!r}, expires_at={self.expires_at}, held={held or 'none'})"

    def fresh(self, now: int | None = None, margin: int = REFRESH_MARGIN_SECONDS) -> bool:
        """Whether the access token can still be used. `margin` is subtracted, never added: a token that
        expires during the call it authorizes has already failed."""
        return self.access_token != "" and self.expires_at - margin > (int(time.time()) if now is None else now)  # nosec B105 - "" is the ABSENCE of a token, not a hardcoded one

    def renewed(self, access_token: str, expires_at: int, refresh_token: str = "") -> "StoredTokens":  # nosec B107 - the empty default means "the server did not reissue one", not a hardcoded token
        """The same binding with new tokens. An authorization server that does not return a new refresh
        token means the old one stays valid, so an empty one here keeps what is held rather than erasing it."""
        return replace(self, access_token=access_token, expires_at=expires_at,
                       refresh_token=refresh_token or self.refresh_token)


def binding_error(tokens: StoredTokens, issuer: str, client_id: str) -> str | None:
    """Why these tokens must not be used against this authorization server and client, or None.

    Checked before every use, not only at login: the authorization server a resource names can change after
    the tokens were stored, and that is precisely the case the specification says to refuse."""
    if tokens.issuer != issuer:
        return (f"the stored tokens were issued by {tokens.issuer!r}, but the server now names {issuer!r}; "
                "log in again rather than reuse credentials from a different authorization server")
    if tokens.client_id != client_id:
        return (f"the stored tokens belong to client {tokens.client_id!r}, but the configuration now names "
                f"{client_id!r}; log in again")
    return None


def read_tokens(path: str) -> StoredTokens | None:
    """The stored tokens, or None when nothing is stored yet. Raises rather than guess at a damaged store."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_STORE_BYTES + 1)
            _refuse_if_others_can_read(handle.fileno(), path)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise TokenStoreError(f"cannot read the token store {path}: {error}") from error
    if len(raw) > MAX_STORE_BYTES:
        raise TokenStoreError(f"the token store {path} is larger than {MAX_STORE_BYTES} bytes")
    try:
        document = strict_json_loads(raw, max_bytes=MAX_STORE_BYTES)
    except StrictJSONError as error:
        raise TokenStoreError(f"the token store {path} is not valid JSON: {error}") from error
    if not isinstance(document, dict):
        raise TokenStoreError(f"the token store {path} is not a JSON object")
    if document.get("schema") != SCHEMA or document.get("version") != STORE_VERSION:
        raise TokenStoreError(
            f"the token store {path} was written by a different version of Portmark "
            f"({document.get('schema')!r} v{document.get('version')!r}); log in again to rewrite it"
        )
    return StoredTokens(
        _text(document, "issuer", path),
        _text(document, "client_id", path),
        _text(document, "access_token", path),
        _whole(document, "expires_at", path),
        _text(document, "refresh_token", path, required=False),
        tuple(_scopes(document, path)),
    )


def write_tokens(path: str, tokens: StoredTokens) -> None:
    """Replace the store atomically, owner-only.

    `mode=0o600` is passed rather than left to the existing file's permissions: a store that was once world
    readable -- restored from a backup, copied with the wrong umask -- must be tightened by this write, not
    preserved as it was found."""
    document = {
        "schema": SCHEMA,
        "version": STORE_VERSION,
        "issuer": tokens.issuer,
        "client_id": tokens.client_id,
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "expires_at": tokens.expires_at,
        "scopes": list(tokens.scopes),
    }
    body = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    if len(body) > MAX_STORE_BYTES:
        raise TokenStoreError("the tokens are too large to store; the authorization server returned something unusual")
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        raise TokenStoreError(f"the token store directory {directory} does not exist")
    try:
        with sidecar_lock(path):
            atomic_write_bytes(path, body, prefix=".portmark-mcp-token-", mode=0o600)
    except OSError as error:
        raise TokenStoreError(f"cannot write the token store {path}: {error}") from error


def clear_tokens(path: str) -> bool:
    """Forget the stored tokens. True when a store was removed, False when there was nothing to remove.

    Removal, not truncation: a file of empty strings still says a login happened here."""
    try:
        with sidecar_lock(path):
            os.remove(path)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise TokenStoreError(f"cannot remove the token store {path}: {error}") from error
    return True


def _refuse_if_others_can_read(fd: int, path: str) -> None:
    """A refresh token readable by group or other is already shared. POSIX only: Windows does not express
    permissions in the mode bits, so the check there would fail on every store and mean nothing."""
    if os.name != "posix":
        return
    mode = os.fstat(fd).st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise TokenStoreError(
            f"the token store {path} is accessible to other users (mode {stat.S_IMODE(mode):04o}); "
            "it holds a refresh token, so fix the permissions (chmod 600) and log in again"
        )


def _text(document: dict, key: str, path: str, required: bool = True) -> str:
    value = document.get(key, "")
    if not isinstance(value, str) or (required and not value):
        raise TokenStoreError(f"the token store {path} has no usable {key!r}")
    return value


def _whole(document: dict, key: str, path: str) -> int:
    value = document.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TokenStoreError(f"the token store {path} has no usable {key!r}")
    return value


def _scopes(document: dict, path: str) -> list[str]:
    value = document.get("scopes", [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TokenStoreError(f"the token store {path} has a malformed 'scopes'")
    return value

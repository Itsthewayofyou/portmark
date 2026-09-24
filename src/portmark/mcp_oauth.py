"""Driving the official SDK's OAuth flow over PORTMARK's transport (MCP OAuth plan, phase 2).

Owner decision D1: Portmark does not write OAuth. The official SDK is an exactly-pinned optional extra, and
it is the thing that knows the protocol -- PKCE, the `resource` parameter, the `iss` rules, the discovery
order. What this module does is decide *who performs the network*.

**The SDK never opens a socket here, and that is the whole design.** Its `mcp/client/auth/` package contains
no HTTP client: `async_auth_flow(request)` is an async generator that YIELDS `httpx2.Request` objects and
CONSUMES `httpx2.Response` objects, and whoever drives it performs the traffic. So Portmark drives it, and
every request goes through `checked_fetch` -- resolve-once anti-rebinding with a `getpeername()`
confirmation, verified TLS, a capped body and the wall-clock watchdog. `httpx2` is used as a DATA TYPE, not
as a network stack.

Three hazards live in the SDK, and all three are hazards of letting the SDK DRIVE, which never happens here:

1. `RedirectAwareAuth` follows redirects on its own internal requests. Portmark performs them, and a 3xx is
   refused rather than followed: a followed redirect reaches an address that was never checked.
2. `truststore` would hook the operating system's trust store into certificate verification -- but only
   inside `httpx2`'s own SSL configuration, and no `httpx2` connection is ever opened.
3. **The synchronous path fails OPEN.** The SDK overrides only `async_auth_flow`; there is no
   `sync_auth_flow` anywhere in it, and `httpx2`'s base `auth_flow` simply yields the request unchanged. A
   synchronous `httpx2.Client` with this provider attached would therefore send the request UNAUTHENTICATED
   and raise nothing at all. Nothing here ever constructs an `httpx2` client of either kind, and a test
   asserts the SDK still has no `sync_auth_flow`, so a future version that adds one is noticed rather than
   silently inherited.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .mcp_client import McpError
from .mcp_http import MAX_METADATA_BYTES, checked_fetch
from .mcp_token_store import StoredTokens

# `pip install "portmark[mcp-oauth]"`. Named once so the advice cannot drift between messages.
EXTRA_HINT = 'OAuth for MCP needs the official SDK: install the optional extra, `pip install "portmark[mcp-oauth]"`'
# A flow is a handful of requests: the unauthorized probe, protected-resource metadata, authorization-server
# metadata, the token exchange, the retry. A generator that keeps asking is a loop, not a flow.
MAX_FLOW_STEPS = 12
# What the authorization server is told this client is. `token_endpoint_auth_method` is decided per server:
# a client with a secret is confidential, one without is public and rests on PKCE.
CLIENT_NAME = "Portmark"


class McpOAuthError(Exception):
    """Authorization could not be completed. Always actionable by the operator, and never carries a token."""


@dataclass(frozen=True)
class Authorization:
    """What one completed flow produced, ready for the token store."""

    issuer: str
    client_id: str
    access_token: str
    expires_at: int
    refresh_token: str = ""
    scopes: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return f"Authorization(issuer={self.issuer!r}, client_id={self.client_id!r}, expires_at={self.expires_at})"

    def stored(self) -> StoredTokens:
        return StoredTokens(self.issuer, self.client_id, self.access_token, self.expires_at,
                            self.refresh_token, self.scopes)


def sdk_available() -> bool:
    """Whether the optional extra is installed. Used to say so plainly rather than fail on an import."""
    try:
        _sdk()
    except McpOAuthError:
        return False
    return True


def _sdk() -> Any:
    """The SDK pieces, imported late so a runtime without the extra pays nothing and fails clearly."""
    try:
        import httpx2  # noqa: PLC0415 - an optional extra, imported only when a server uses OAuth
        from mcp.client.auth.oauth2 import OAuthClientProvider  # noqa: PLC0415
        from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata  # noqa: PLC0415
    except ImportError as error:
        raise McpOAuthError(f"{EXTRA_HINT} ({error})") from error
    return httpx2, OAuthClientProvider, OAuthClientMetadata, OAuthClientInformationFull


class _Storage:
    """The SDK's `TokenStorage` protocol, backed by memory for the length of one flow.

    The client information is PRE-SEEDED, and that is what keeps Dynamic Client Registration out: the SDK's
    registration step is guarded by `if not self.context.client_info:`, so a client that is already known is
    never registered. DCR is out of scope by owner decision, and the specification now marks it deprecated.

    Nothing is persisted here. Writing the result to disk is the caller's job, through `mcp_token_store`,
    which is the only place that knows about file modes and the issuer binding."""

    def __init__(self, client_info: Any, tokens: Any = None) -> None:
        self._client_info = client_info
        self._tokens = tokens

    async def get_tokens(self) -> Any:
        return self._tokens

    async def set_tokens(self, tokens: Any) -> None:
        self._tokens = tokens

    async def get_client_info(self) -> Any:
        return self._client_info

    async def set_client_info(self, client_info: Any) -> None:
        self._client_info = client_info

    @property
    def tokens(self) -> Any:
        return self._tokens


class _Network:
    """Performs what the SDK asks for, under Portmark's rules and one shared budget."""

    def __init__(self, total_seconds: float, request_timeout: float, allow_private: bool, context: Any = None) -> None:
        self._deadline = time.monotonic() + total_seconds
        self._request_timeout = request_timeout
        self._allow_private = allow_private
        self._context = context
        self.performed: list[tuple[str, str]] = []

    def perform(self, request: Any) -> Any:
        httpx2 = _sdk()[0]
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise McpOAuthError("authorization did not finish within its budget")
        url = str(request.url)
        self.performed.append((request.method, url))
        try:
            answer = checked_fetch(
                request.method,
                url,
                total_seconds=remaining,
                request_timeout=min(self._request_timeout, remaining),
                headers={name: value for name, value in request.headers.items() if name.lower() != "host"},
                body=bytes(request.content or b""),
                allow_private=self._allow_private,
                max_bytes=MAX_METADATA_BYTES,
                context=self._context,
            )
        except McpError as error:
            raise McpOAuthError(f"{request.method} {_safe(url)} failed: {error}") from None
        if 300 <= answer.status < 400:
            # Not followed, and there is no option to follow. The SDK's own flow WOULD follow this; the
            # destination has been checked by nobody, and the next request would carry the client's
            # credentials to it.
            raise McpOAuthError(
                f"{request.method} {_safe(url)} answered {answer.status} with a redirect; "
                "an OAuth endpoint that redirects is not followed, because the destination was never checked"
            )
        return httpx2.Response(
            answer.status,
            headers=list(answer.headers.items()),
            content=answer.body,
            request=request,
        )


def _safe(url: str) -> str:
    """A url with its query removed. A token request's query can carry a code or an assertion, and this
    string ends up in an operator-visible error."""
    return url.split("?", 1)[0]


def authorize(
    *,
    server_url: str,
    client_id: str,
    client_secret: str = "",
    scopes: tuple[str, ...] = (),
    redirect_uri: str = "",
    open_authorization: Callable[[str], Awaitable[None]] | None = None,
    read_callback: Callable[[], Awaitable[Any]] | None = None,
    total_seconds: float = 300.0,
    request_timeout: float = 30.0,
    allow_private: bool = False,
    context: Any = None,
    existing: Any = None,
) -> Authorization:
    """Run one authorization flow and return what it produced.

    Synchronous on the outside: Portmark's host, CLI and worker are all synchronous, and the SDK's flow is an
    async generator, so exactly one event loop is started and it lives only as long as this call."""
    httpx2, provider_class, metadata_class, client_class = _sdk()
    client_info = existing or client_class(
        client_id=client_id,
        client_secret=client_secret or None,
        redirect_uris=[redirect_uri] if redirect_uri else None,
        grant_types=["authorization_code", "refresh_token"],
        token_endpoint_auth_method="client_secret_post" if client_secret else "none",
    )
    storage = _Storage(client_info)
    metadata = metadata_class(
        client_name=CLIENT_NAME,
        redirect_uris=[redirect_uri] if redirect_uri else None,
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope=" ".join(scopes) if scopes else None,
        token_endpoint_auth_method="client_secret_post" if client_secret else "none",
    )
    provider = provider_class(
        server_url=server_url,
        client_metadata=metadata,
        storage=storage,
        redirect_handler=open_authorization or _no_browser,
        callback_handler=read_callback or _no_callback,
    )
    network = _Network(total_seconds, request_timeout, allow_private, context)
    asyncio.run(_drive(provider, httpx2.Request("POST", server_url), network, storage))
    return _harvest(provider, storage, client_id, scopes)


async def _drive(provider: Any, request: Any, network: _Network, storage: _Storage) -> None:
    """Pump the SDK's generator, performing each request it asks for.

    The flow ends by yielding the ORIGINAL request again, now carrying `Authorization`. That retry is not
    performed: this call exists to obtain a token, and actually sending it would invoke whatever the first
    request was -- during `portmark mcp login`, a tool call nobody asked for."""
    flow = provider.async_auth_flow(request)
    try:
        reply = None
        for _ in range(MAX_FLOW_STEPS):
            try:
                outgoing = await flow.__anext__() if reply is None else await flow.asend(reply)
            except StopAsyncIteration:
                return
            if storage.tokens is not None and "authorization" in {name.lower() for name in outgoing.headers}:
                return
            reply = network.perform(outgoing)
        raise McpOAuthError(f"the authorization flow asked for more than {MAX_FLOW_STEPS} requests and was stopped")
    finally:
        await _close(flow)


async def _close(flow: Any) -> None:
    """Close the generator here, while the loop that started it is still running.

    Every exit from `_drive` leaves the generator unfinished: the happy path stops at the retry rather than
    performing it, and a refusal stops wherever it happened. Left alone, Python closes it later from the
    garbage collector -- and the SDK acquires an asyncio lock INSIDE the generator and releases it in a
    `finally`, so a close from outside the task that acquired it makes that release raise
    `RuntimeError: The current task is not holding this lock`. Closing it here keeps that inside one place,
    and the RuntimeError is swallowed because a provider is used for exactly one flow and then discarded:
    there is nothing left for the lock to protect. Without this the error surfaces later, unattached, and
    reads as a Portmark fault."""
    try:
        await flow.aclose()
    except RuntimeError:
        pass


def _harvest(provider: Any, storage: _Storage, client_id: str, scopes: tuple[str, ...]) -> Authorization:
    tokens = storage.tokens
    if tokens is None or not getattr(tokens, "access_token", ""):
        raise McpOAuthError("the authorization server did not return an access token")
    issuer = _issuer_of(provider)
    if not issuer:
        # Without an issuer there is nothing to bind the credentials to, and the specification's rule that a
        # client MUST NOT reuse credentials from a different authorization server could not be enforced.
        raise McpOAuthError("the authorization server did not identify itself; refusing to store unbound credentials")
    granted = getattr(tokens, "scope", None)
    expires_in = getattr(tokens, "expires_in", None)
    return Authorization(
        issuer,
        client_id,
        tokens.access_token,
        int(time.time()) + int(expires_in if isinstance(expires_in, int) else 3600),
        getattr(tokens, "refresh_token", "") or "",
        tuple(granted.split()) if isinstance(granted, str) and granted else scopes,
    )


def _issuer_of(provider: Any) -> str:
    metadata = getattr(getattr(provider, "context", None), "oauth_metadata", None)
    issuer = getattr(metadata, "issuer", None)
    return str(issuer) if issuer else ""


async def _no_browser(url: str) -> None:
    raise McpOAuthError(
        "this server needs a browser authorization, and none was offered; run `portmark mcp login <server>`"
    )


async def _no_callback() -> Any:
    raise McpOAuthError("no way to receive the authorization result was offered")


def refuse_sync_use(provider: Any) -> None:  # noqa: D401
    """Assert the SDK still has no synchronous auth path.

    Not defensive decoration. `httpx2`'s base `auth_flow` yields the request unchanged, and the SDK overrides
    only `async_auth_flow`, so attaching this provider to a SYNCHRONOUS client sends an unauthenticated
    request and raises nothing -- authorization silently becomes a no-op. Portmark never builds an `httpx2`
    client, but a future SDK that grows a `sync_auth_flow` would change what this module is reasoning about,
    and that must be noticed deliberately rather than inherited."""
    candidate = provider if isinstance(provider, type) else type(provider)
    if candidate.sync_auth_flow is not _base_sync_auth_flow():
        raise McpOAuthError(
            "this version of the MCP SDK defines its own `sync_auth_flow`; Portmark's reasoning about the "
            "synchronous path no longer holds and must be re-checked before the pin is raised"
        )


def _base_sync_auth_flow() -> Any:
    httpx2 = _sdk()[0]
    return httpx2.Auth.sync_auth_flow


def redact(headers: Mapping[str, str]) -> dict[str, str]:
    """Headers with any credential replaced. For logging a request that failed."""
    return {name: ("<redacted>" if name.lower() in ("authorization", "cookie") else value)
            for name, value in headers.items()}


__all__ = [
    "EXTRA_HINT",
    "Authorization",
    "McpOAuthError",
    "authorize",
    "redact",
    "refuse_sync_use",
    "sdk_available",
]

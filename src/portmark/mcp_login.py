"""`portmark mcp login` and `portmark mcp logout` (MCP OAuth plan, phase 4).

This is the ONE place a human is in the loop. Everything else about OAuth in Portmark runs unattended: the
host renews a stored token at start-up, and the isolated worker only ever reads the resulting string. Here an
operator is asked to visit an authorization server, approve a delegation, and bring back what it handed them.

Two ways back, because a Portmark box is very often reached over SSH and has no browser at all:

* `--manual` prints the authorization url and reads the redirected url the operator pastes. It needs nothing
  of the machine, so it is the path that always works.
* the default binds a one-shot listener on a LOOPBACK address and collects the redirect itself.

Neither one is allowed to invent anything. Whatever comes back is handed to the SDK exactly as received, so
the SDK's own `state` comparison and its RFC 9207 `iss` validation run on the real values -- dropping `iss`
here would silently skip a check the specification requires, and nothing downstream would notice.
"""

from __future__ import annotations

import http.server
import os
import sys
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .mcp_config import McpConfigError, McpServerConfig, load_config
from .mcp_token_store import clear_tokens, write_tokens

# The redirect the MCP specification's own example uses. RFC 8252 section 7.3 is why it is a literal address
# rather than `localhost`: the name may answer 127.0.0.1 on one machine and ::1 on another, and a redirect
# uri has to be the same string the authorization server has registered.
DEFAULT_REDIRECT = "http://127.0.0.1:3000/callback"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
# Long enough for a real authorization url with a state, a challenge and several scopes, short enough that a
# paste into a terminal cannot be used to spend memory.
MAX_PASTED_BYTES = 8 * 1024
# The whole login, INCLUDING the time the operator spends in the browser: the flow's budget starts when the
# first request is prepared and there is no way to stop that clock for a human.
DEFAULT_LOGIN_SECONDS = 600.0
# The operator is waiting at a terminal; a listener that never gets a redirect must give the terminal back.
LISTENER_POLL_SECONDS = 1.0

ANSWER = b"Portmark received the authorization response. You can close this window and return to the terminal.\n"


def login(
    config_path: str,
    server_name: str,
    *,
    manual: bool = False,
    redirect_uri: str = "",
    total_seconds: float = DEFAULT_LOGIN_SECONDS,
    out: Any = None,
) -> dict[str, Any]:
    """Run one authorization flow for `server_name` and store what it produced.

    Returns what was granted, for printing. The tokens themselves are written to the store and are NOT in
    the returned mapping: this value is printed to a terminal and may end up in a scrollback buffer."""
    from .mcp_oauth import authorize  # noqa: PLC0415 - `mcp_oauth` reaches `ssl`; only a login pays

    stream = out if out is not None else sys.stderr
    server = _oauth_server(config_path, server_name)
    client_id, client_secret = _client(server)
    target = redirect_uri or DEFAULT_REDIRECT
    if manual:
        collector: _Collector = _Manual(target, stream)
    else:
        collector = _Loopback(target, stream, total_seconds)
    with collector:
        granted = authorize(
            server_url=server.url,
            client_id=client_id,
            client_secret=client_secret,
            scopes=server.oauth.scopes if server.oauth else (),
            redirect_uri=target,
            open_authorization=collector.show,
            read_callback=collector.collect,
            total_seconds=total_seconds,
            allow_private=server.allow_private,
        )
    assert server.oauth is not None  # nosec B101 - `_oauth_server` refused a server without one
    write_tokens(server.oauth.token_store, granted.stored())
    return {
        "server": server_name,
        "issuer": granted.issuer,
        "client_id": granted.client_id,
        "scopes": list(granted.scopes),
        "expires_at": granted.expires_at,
        "refreshable": bool(granted.refresh_token),
        "token_store": server.oauth.token_store,
    }


def logout(config_path: str, server_name: str) -> dict[str, Any]:
    """Delete the stored authorization for one server. Saying nothing was there is not a failure."""
    server = _oauth_server(config_path, server_name)
    assert server.oauth is not None  # nosec B101 - `_oauth_server` refused a server without one
    return {
        "server": server_name,
        "token_store": server.oauth.token_store,
        "removed": clear_tokens(server.oauth.token_store),
    }


def _oauth_server(config_path: str, server_name: str) -> McpServerConfig:
    """The named server, refused unless it actually uses OAuth and the extra is installed."""
    from .mcp_oauth import sdk_available  # noqa: PLC0415 - as in `login`

    config = load_config(config_path)
    server = config.servers.get(server_name)
    if server is None:
        raise McpConfigError(f"the MCP config has no server {server_name!r}")
    if server.oauth is None:
        raise McpConfigError(
            f"MCP server {server_name!r} has no `oauth` block, so there is nothing to log in to; "
            "a server authenticated by `bearer_env` needs no login"
        )
    if not sdk_available():
        raise McpConfigError(
            f"MCP server {server_name!r} uses `oauth`, and the authorization code lives in an optional "
            "extra that is not installed: `pip install 'portmark[mcp-oauth]'`"
        )
    return server


def _client(server: McpServerConfig) -> tuple[str, str]:
    """The client id, and the secret when one is configured. Both by NAME from the environment."""
    oauth = server.oauth
    assert oauth is not None  # nosec B101 - the only caller checks
    client_id = os.environ.get(oauth.client_id_env, "")
    if not client_id:
        raise McpConfigError(
            f"the client id is read from {oauth.client_id_env}, and that variable is unset or empty"
        )
    return client_id, os.environ.get(oauth.client_secret_env, "") if oauth.client_secret_env else ""


def result_from_redirect(url: str) -> Any:
    """The SDK's `AuthorizationCodeResult`, built from the url the authorization server redirected to.

    `iss` is carried through even though Portmark does not read it: the SDK validates it against the
    discovered metadata (RFC 9207), and a parser that quietly dropped it would turn that MUST into a no-op
    while every test that only looks at the resulting token still passed."""
    from mcp.shared.auth import AuthorizationCodeResult  # noqa: PLC0415 - part of the optional extra

    from .mcp_oauth import McpOAuthError  # noqa: PLC0415 - as in `login`

    query = parse_qs(urlsplit(url).query)

    def first(name: str) -> str | None:
        values = query.get(name) or []
        return values[0] if values else None

    refusal = first("error")
    if refusal:
        # The description is the authorization server's own text; it is shown, not interpreted.
        raise McpOAuthError(f"the authorization server refused: {refusal} ({first('error_description') or '-'})")
    code = first("code")
    if not code:
        raise McpOAuthError("that url carries no `code` parameter; paste the whole url you were redirected to")
    return AuthorizationCodeResult(code=code, state=first("state"), iss=first("iss"))


class _Collector:
    """Shows the operator an authorization url, and brings back the redirect. One flow, then discarded."""

    def __enter__(self) -> _Collector:
        return self

    def __exit__(self, *_: Any) -> None:
        return None

    async def show(self, url: str) -> None:
        raise NotImplementedError

    async def collect(self) -> Any:
        raise NotImplementedError


class _Manual(_Collector):
    """Print the url, read the pasted redirect. Works on a machine with no browser and no free port."""

    def __init__(self, redirect_uri: str, stream: Any) -> None:
        self._redirect = redirect_uri
        self._stream = stream

    async def show(self, url: str) -> None:
        print(f"\nOpen this url and approve the request:\n\n  {url}\n", file=self._stream)
        print(f"Then paste the whole url you were redirected to (it starts with {self._redirect}):",
              file=self._stream)
        self._stream.flush()

    async def collect(self) -> Any:
        from .mcp_oauth import McpOAuthError  # noqa: PLC0415 - as in `login`

        pasted = sys.stdin.readline(MAX_PASTED_BYTES).strip()
        if not pasted:
            raise McpOAuthError("nothing was pasted, so the authorization could not be completed")
        return result_from_redirect(pasted)


class _Loopback(_Collector):
    """Collect the redirect from a one-shot listener on a loopback address.

    The listener exists for a single request and is closed on the way out, whatever happened. It is bound to
    a literal loopback address and nothing else: a redirect uri naming a routable interface would publish an
    authorization code to whoever else can reach that port."""

    def __init__(self, redirect_uri: str, stream: Any, total_seconds: float) -> None:
        split = urlsplit(redirect_uri)
        if split.scheme != "http" or split.hostname not in LOOPBACK_HOSTS:
            raise McpConfigError(
                f"the redirect uri {redirect_uri!r} is not a loopback http address "
                f"({', '.join(sorted(LOOPBACK_HOSTS))}); pass one that is, or use --manual"
            )
        self._redirect = redirect_uri
        self._stream = stream
        # The flow's own budget is only spent when a REQUEST is performed, and waiting for a human performs
        # none -- so a login nobody finishes would hold the terminal for ever without this.
        self._deadline = time.monotonic() + total_seconds
        self._answered: list[str] = []
        self._server = _one_shot_server(split.hostname or "", split.port or 80, self._answered)

    def __exit__(self, *_: Any) -> None:
        self._server.server_close()

    async def show(self, url: str) -> None:
        print(f"\nOpen this url and approve the request:\n\n  {url}\n", file=self._stream)
        print(f"Waiting for the redirect to {self._redirect} ...", file=self._stream)
        self._stream.flush()

    async def collect(self) -> Any:
        # `handle_request` returns on its own timeout as well as on a request, so the deadline is checked
        # between waits rather than only when something arrives.
        while not self._answered:
            if time.monotonic() >= self._deadline:
                from .mcp_oauth import McpOAuthError  # noqa: PLC0415 - as in `login`

                raise McpOAuthError(
                    f"no redirect arrived at {self._redirect} within the time allowed; "
                    "use --manual if this machine cannot receive the redirect"
                )
            self._server.handle_request()
        return result_from_redirect(self._answered[0])


def _one_shot_server(host: str, port: int, answered: list[str]) -> http.server.HTTPServer:
    """An HTTP server that records the path of the first GET it is given and answers a fixed page."""
    import socket  # noqa: PLC0415 - only the loopback path pays for it

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - the name BaseHTTPRequestHandler dispatches to
            answered.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(ANSWER)))
            self.end_headers()
            self.wfile.write(ANSWER)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - the base class names it so
            """Silent. The default writes the request line to stderr -- and that carries the CODE."""

    class _Server(http.server.HTTPServer):
        # Bind the family the address actually is, rather than assuming IPv4: `::1` is a loopback address
        # too, and an operator whose provider has `http://[::1]:3000/callback` registered must be able to
        # use it.
        address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        timeout = LISTENER_POLL_SECONDS

    return _Server((host, port), _Handler)


__all__ = ["DEFAULT_LOGIN_SECONDS", "DEFAULT_REDIRECT", "login", "logout", "result_from_redirect"]

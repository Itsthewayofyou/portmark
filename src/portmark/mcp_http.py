"""The Streamable HTTP transport for Portmark's MCP client (MCP/SIEM plan, PR 3).

One JSON-RPC message is one HTTP POST, on its own connection, and a POST that fails is NEVER sent again:
once any byte of a `tools/call` may have reached the server, resending it could double a real side effect.
The answer is either a single JSON object or a Server-Sent Events stream scoped to that one request.

The specification states no TLS requirement for an MCP endpoint -- HTTPS is mandated only for OAuth
endpoints. Requiring it here, and pinning the address the name resolved to, is PORTMARK's rule, not the
specification's. See MCP.md.
"""

from __future__ import annotations

import http.client  # nosec B404 - talks to the operator's configured MCP endpoint, no shell involved
import ipaddress
import json
import socket
import ssl
import threading
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from .json_guard import StrictJSONError, strict_json_loads
from .mcp_client import (
    MAX_MESSAGE_BYTES,
    PROTOCOL_ERROR,
    TRANSPORT_ERROR,
    HttpStatusError,
    McpError,
    Transport,
    is_header_safe,
)
from .providers import PinnedHTTPSConnection, _classify_address, resolve_public_address

ACCEPT = "application/json, text/event-stream"
JSON_TYPE = "application/json"
EVENT_TYPE = "text/event-stream"
_CHUNK_BYTES = 1 << 16
# One field line of an SSE stream. Bounded on its own, and WHILE it arrives: a server that sends a `data:`
# line and never a newline would otherwise grow the buffer until the machine runs out of memory.
MAX_SSE_LINE_BYTES = 1 << 16
MAX_EVENT_BYTES = MAX_MESSAGE_BYTES
MAX_STREAM_BYTES = 8 << 20
MAX_SSE_EVENTS = 256
MAX_ERROR_BODY_BYTES = 1 << 16
# An OAuth metadata document or token response is a small JSON object. A megabyte of one is not.
MAX_METADATA_BYTES = 1 << 20


def resolve_endpoint_address(host: str, port: int, allow_private: bool) -> str:
    """Resolve the endpoint ONCE and return the single address to connect to.

    Without `allow_private` this is exactly the provider rule: every answer must be public or the whole
    lookup fails. With it, the allowed class widens to loopback and private ONLY -- link-local, multicast,
    reserved and unspecified stay refused, and the classification goes through the providers' own
    `_classify_address`, so the IPv4-mapped IPv6 normalisation (`::ffff:127.0.0.1`) is not reimplemented here
    and cannot drift from it. A mixed answer fails closed rather than picking whichever came first, because
    resolver ordering must not decide where Portmark connects."""
    if not allow_private:
        try:
            return resolve_public_address(host, port)
        except Exception as error:  # noqa: BLE001 - SecurityError and OSError both mean "do not connect"
            raise McpError(TRANSPORT_ERROR, f"the MCP endpoint host {host!r} is not usable: {error}") from error
    try:
        answers = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as error:
            raise McpError(TRANSPORT_ERROR, f"the MCP endpoint host {host!r} did not resolve: {error}") from error
        answers = [
            str(sockaddr[0])
            for family, _type, _proto, _canon, sockaddr in infos
            if family in (socket.AF_INET, socket.AF_INET6)
        ]
    if not answers:
        raise McpError(TRANSPORT_ERROR, f"the MCP endpoint host {host!r} resolved to no usable address")
    for answer in answers:
        address = _classify_address(answer)
        if address.is_multicast or address.is_unspecified or address.is_link_local:
            raise McpError(TRANSPORT_ERROR, f"the MCP endpoint host {host!r} resolves to {answer}, which is never allowed")
        # Loopback is checked BEFORE `is_reserved`, because Python reports the IPv6 loopback `::1` as
        # reserved -- it sits inside a reserved block. Refusing it would break `https://localhost` wherever
        # the resolver answers IPv6 first: observed 2026-09-23, where this project's GitHub runners resolved
        # `localhost` to `::1` while the development machine answered `127.0.0.1`. Reserved still refuses a
        # non-loopback address such as 240.0.0.1.
        if address.is_loopback:
            continue
        if not address.is_private or address.is_reserved:
            raise McpError(
                TRANSPORT_ERROR,
                f"the MCP endpoint host {host!r} resolves to {answer}, which is not a loopback or private "
                "address; `allow_private` widens the rule to those, not to the internet",
            )
    return answers[0]


def checked_bearer(name: str, value: str | None) -> str:
    """The token, or a refusal that never contains it.

    A configured `bearer_env` is mandatory: silently sending an unauthenticated request could reach a
    different, anonymous service behind the same URL under a pin that was approved for the authenticated one.
    The token is checked here so `http.client` never rejects it -- its own error message would print the
    value (`http/client.py:1343`), and the worker forwards error text to the host."""
    if not value:
        raise McpError(TRANSPORT_ERROR, f"the MCP server needs a bearer token, and {name} is unset or empty")
    if not is_header_safe(value) or " " in value:
        raise McpError(TRANSPORT_ERROR, f"the token in {name} is not usable in an HTTP header")
    return value


class HttpTransport(Transport):
    """One MCP endpoint. Each message is its own POST on its own connection."""

    def __init__(
        self,
        url: str,
        request_timeout: float,
        total_seconds: float,
        bearer_name: str = "",
        bearer_value: str | None = None,
        allow_private: bool = False,
        context: ssl.SSLContext | None = None,
    ) -> None:
        split = urlsplit(url)
        self._scheme = split.scheme
        self._host = split.hostname or ""
        self._port = split.port or (443 if split.scheme == "https" else 80)
        self._path = split.path or "/"
        # The MCP endpoint may not carry a query string (the config refuses one), but an OAuth metadata or
        # token url routinely does, so the one-shot path keeps it. `_path` stays exactly as it was.
        self._target = self._path + (f"?{split.query}" if split.query else "")
        self._timeout = request_timeout
        self._deadline = time.monotonic() + total_seconds
        self._allow_private = allow_private
        self._context = context
        self._bearer = checked_bearer(bearer_name, bearer_value) if bearer_name else ""
        # A legacy server MAY hand out a session id on any response and expects it back on every later
        # request. That is transport state, like a cookie: the protocol above never sees it.
        self._session_id = ""
        self._frames: deque[bytes] = deque()
        self._sock: socket.socket | None = None
        # Set by the watchdog when the absolute deadline passes, so every exit path can report the budget
        # rather than the shutdown it caused.
        self._out_of_budget = False

    # -- Transport ----------------------------------------------------------------------------------------

    def send(self, encoded: bytes, headers: Mapping[str, str], expects_reply: bool = True) -> None:
        self._frames.clear()
        request_headers = self._request_headers(encoded, headers)
        connection = self._open()
        watchdog = self._watchdog()
        try:
            # Re-armed here, and again before the answer is read, because the socket timeout set in `_open`
            # was computed BEFORE the TCP connect and the TLS handshake: without this, the time those took is
            # never deducted and reading the status line and headers gets a whole fresh allowance.
            self._arm()
            connection.request("POST", self._path, body=encoded, headers=request_headers)
            self._arm()
            response = connection.getresponse()
            # `getresponse()` reads the status line and headers itself, each read bounded by the timeout armed
            # above. The budget is checked again HERE so an answer is never accepted after the deadline has
            # passed, whatever the individual reads cost.
            self._remaining()
            self._absorb(response, expects_reply)
        except (OSError, http.client.HTTPException) as error:
            self._refuse_if_out_of_budget()
            raise McpError(TRANSPORT_ERROR, f"the MCP endpoint could not be reached: {type(error).__name__}") from None
        except McpError:
            self._refuse_if_out_of_budget()
            raise
        finally:
            watchdog.cancel()
            connection.close()
            self._sock = None
        self._refuse_if_out_of_budget()

    def read(self, timeout: float) -> bytes | None:
        return self._frames.popleft() if self._frames else None

    def one_shot(self, method: str, headers: Mapping[str, str], body: bytes, max_bytes: int) -> "Fetched":
        """A single request/response on its own connection, for `checked_fetch`.

        Separate from `send`/`read`, which implement the MCP framing -- the session id, the SSE stream and
        the era rules have no meaning at an OAuth endpoint. What IS shared is every protection: `_open`
        resolves and confirms the address, `_watchdog` bounds the whole exchange from outside the read,
        `_read_bounded` caps the answer, and `_checked_headers` keeps a credential out of an exception."""
        connection = self._open()
        watchdog = self._watchdog()
        try:
            sent = self._checked_headers({"Host": self._host_header(), "Accept": JSON_TYPE, **dict(headers)})
            if body:
                sent.setdefault("Content-Type", "application/x-www-form-urlencoded")
                sent["Content-Length"] = str(len(body))
            connection.request(method, self._target, body or None, sent)
            self._arm()
            response = connection.getresponse()
            answer = Fetched(
                response.status,
                {name.lower(): value for name, value in response.getheaders()},
                self._read_bounded(response, max_bytes),
            )
        except (OSError, http.client.HTTPException) as error:
            self._refuse_if_out_of_budget()
            raise McpError(TRANSPORT_ERROR, f"the OAuth endpoint could not be read: {type(error).__name__}") from None
        finally:
            watchdog.cancel()
            connection.close()
        self._refuse_if_out_of_budget()
        return answer

    def close(self) -> None:
        self._frames.clear()

    # -- request ------------------------------------------------------------------------------------------

    def _host_header(self) -> str:
        """The `Host` value for this endpoint, shared by the MCP framing and the one-shot OAuth path.

        The default port belongs to the SCHEME, not to a list of well-known ports: 80 is the default for
        http and NOT for https, so `https://host:80/` must say `:80` or the server is told 443."""
        host = f"[{self._host}]" if ":" in self._host else self._host
        if self._port != (443 if self._scheme == "https" else 80):
            host += f":{self._port}"
        return host

    def _checked_headers(self, built: dict[str, str]) -> dict[str, str]:
        for name, value in built.items():
            # Checked HERE so `http.client` never refuses one: its own message prints the offending VALUE,
            # and a mirrored tool argument, a bearer token or an access token would travel out with it.
            if not is_header_safe(value):
                raise McpError(PROTOCOL_ERROR, f"the {name} header value is not usable in an HTTP header")
        return built

    def _request_headers(self, encoded: bytes, headers: Mapping[str, str]) -> dict[str, str]:
        built = {
            "Host": self._host_header(),
            "Accept": ACCEPT,
            "Content-Type": JSON_TYPE,
            "Content-Length": str(len(encoded)),
            **dict(headers),
        }
        if self._session_id:
            built["Mcp-Session-Id"] = self._session_id
        if self._bearer:
            built["Authorization"] = f"Bearer {self._bearer}"
        return self._checked_headers(built)

    def _open(self) -> http.client.HTTPConnection:
        address = resolve_endpoint_address(self._host, self._port, self._allow_private)
        remaining = self._remaining()
        if self._scheme == "https":
            context = self._context or ssl.create_default_context()
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                # A context that does not verify would still pin the address, which LOOKS secure while any
                # certificate is accepted -- and the bearer token rides on that connection.
                raise McpError(TRANSPORT_ERROR, "the TLS context does not verify certificates; refusing to connect")
            connection: http.client.HTTPConnection = PinnedHTTPSConnection(
                address, self._port, self._host, min(self._timeout, remaining), context
            )
        else:
            connection = http.client.HTTPConnection(address, self._port, timeout=min(self._timeout, remaining))
        try:
            connection.connect()
        except (OSError, http.client.HTTPException) as error:
            raise McpError(TRANSPORT_ERROR, f"the MCP endpoint could not be reached: {type(error).__name__}") from None
        self._sock = connection.sock
        self._confirm_peer(connection, address)
        return connection

    def _confirm_peer(self, connection: http.client.HTTPConnection, address: str) -> None:
        """The socket really is connected to the address that was checked, not to one DNS answered later."""
        try:
            peer = str(connection.sock.getpeername()[0]).split("%")[0]  # type: ignore[union-attr]
            same = ipaddress.ip_address(peer) == ipaddress.ip_address(address)
        except (OSError, ValueError, AttributeError, IndexError) as error:
            connection.close()
            raise McpError(TRANSPORT_ERROR, f"the MCP endpoint connection could not be confirmed: {error}") from error
        if not same:
            connection.close()
            raise McpError(TRANSPORT_ERROR, f"the MCP endpoint connected to {peer}, not to the checked address {address}")

    # -- response -----------------------------------------------------------------------------------------

    def _absorb(self, response: http.client.HTTPResponse, expects_reply: bool) -> None:
        status = response.status
        content_type = (response.getheader("Content-Type") or "").split(";")[0].strip().lower()
        encoding = (response.getheader("Content-Encoding") or "identity").strip().lower()
        session = response.getheader("Mcp-Session-Id")
        if session and is_header_safe(session):
            self._session_id = session
        if encoding not in ("", "identity"):
            # A compressed body could expand far past the caps, which are counted on the wire.
            raise McpError(TRANSPORT_ERROR, f"the MCP endpoint used Content-Encoding {encoding!r}; Portmark reads identity only")
        if 300 <= status < 400:
            raise McpError(TRANSPORT_ERROR, "the MCP endpoint answered with a redirect, which Portmark does not follow")
        if status == 202:
            if expects_reply:
                raise McpError(PROTOCOL_ERROR, "the MCP endpoint answered a request with 202, which is for notifications")
            return
        if status == 200:
            if content_type == JSON_TYPE:
                self._frames.append(self._read_bounded(response, MAX_MESSAGE_BYTES))
                return
            if content_type == EVENT_TYPE:
                self._read_events(response)
                return
            raise McpError(PROTOCOL_ERROR, f"the MCP endpoint answered with Content-Type {content_type!r}")
        raise self._status_error(response, status)

    def _status_error(self, response: http.client.HTTPResponse, status: int) -> HttpStatusError:
        raw = self._read_bounded(response, MAX_ERROR_BODY_BYTES, soft=True)
        try:
            body = strict_json_loads(raw, max_bytes=MAX_ERROR_BODY_BYTES) if raw else None
        except StrictJSONError:
            body = None
        if status == 404 and self._session_id:
            # The legacy meaning. The request is NOT replayed on a new session: it may already have run.
            return HttpStatusError(status, body, TRANSPORT_ERROR, "the MCP session ended; Portmark does not replay a request")
        if status in (401, 403):
            return HttpStatusError(status, body, TRANSPORT_ERROR, f"the MCP endpoint refused authorization ({status})")
        code = PROTOCOL_ERROR if isinstance(body, dict) and isinstance(body.get("error"), dict) else TRANSPORT_ERROR
        return HttpStatusError(status, body, code, f"the MCP endpoint answered {status}")

    def _read_bounded(self, response: http.client.HTTPResponse, limit: int, soft: bool = False) -> bytes:
        """At most `limit` bytes. `soft` truncates instead of failing, for a body that is only diagnostic."""
        buffer = bytearray()
        while len(buffer) <= limit:
            self._arm()
            chunk = response.read(min(_CHUNK_BYTES, limit + 1 - len(buffer)))
            if not chunk:
                return bytes(buffer)
            buffer.extend(chunk)
        if soft:
            return bytes(buffer[:limit])
        raise McpError(TRANSPORT_ERROR, f"an MCP endpoint answer exceeded {limit} bytes")

    def _read_events(self, response: http.client.HTTPResponse) -> None:
        """Parse the SSE stream until the response to THIS request arrives, then stop.

        Stopping at the terminal frame rather than at end-of-stream matters twice. A server is only advised
        to close the stream after the final response, so reading on would burn the deadline on keep-alives;
        and a reset arriving after a valid result must not be able to discard that result -- by then we have
        already stopped reading."""
        buffer = bytearray()
        data = bytearray()
        total = 0
        events = 0
        while True:
            self._arm()
            chunk = response.read1(_CHUNK_BYTES) if hasattr(response, "read1") else response.read(_CHUNK_BYTES)
            if not chunk:
                raise McpError(TRANSPORT_ERROR, "the MCP endpoint ended its stream before answering")
            total += len(chunk)
            if total > MAX_STREAM_BYTES:
                raise McpError(TRANSPORT_ERROR, f"an MCP endpoint stream exceeded {MAX_STREAM_BYTES} bytes")
            buffer.extend(chunk)
            while True:
                end = buffer.find(b"\n")
                if end < 0:
                    break
                line = bytes(buffer[:end]).rstrip(b"\r")
                del buffer[: end + 1]
                if not line:
                    if data:
                        events += 1
                        if events > MAX_SSE_EVENTS:
                            raise McpError(TRANSPORT_ERROR, f"an MCP endpoint stream sent more than {MAX_SSE_EVENTS} events")
                        if self._emit(bytes(data)):
                            return
                        data = bytearray()
                    continue
                if line.startswith(b":"):
                    continue  # a keep-alive comment: the SSE specification says carry no data, so ignore it
                field, _, value = line.partition(b":")
                if field == b"data":
                    if data:
                        data.extend(b"\n")
                    data.extend(value[1:] if value.startswith(b" ") else value)
                    if len(data) > MAX_EVENT_BYTES:
                        raise McpError(TRANSPORT_ERROR, f"an MCP endpoint event exceeded {MAX_EVENT_BYTES} bytes")
            if len(buffer) > MAX_SSE_LINE_BYTES:
                raise McpError(TRANSPORT_ERROR, f"an MCP endpoint stream line exceeded {MAX_SSE_LINE_BYTES} bytes")

    def _emit(self, data: bytes) -> bool:
        """Queue one event's payload. True once it is the response to this request, which ends the stream."""
        if b"\x00" in data:
            raise McpError(PROTOCOL_ERROR, "an MCP endpoint event contained a NUL byte")
        self._frames.append(data)
        try:
            message = json.loads(data)
        except ValueError:
            return False  # let the protocol layer report a malformed message, with its own wording
        return isinstance(message, dict) and "id" in message and ("result" in message or "error" in message)

    # -- budget -------------------------------------------------------------------------------------------

    def _watchdog(self) -> threading.Timer:
        """Shut the socket down when the absolute deadline passes, so a DRIPPED answer is interrupted.

        A socket timeout is per operation: it restarts on every byte that arrives, so a server sending one
        header byte just inside the timeout, over and over, is never cut off by it -- and `getresponse()`
        reads many times while parsing. Re-arming before each phase deducts time already spent but still
        cannot bound a phase from the inside; a check after the phase only notices an overrun that has
        already happened. Only something outside the read can END it.

        `shutdown` rather than `close`: it unblocks the read immediately without freeing the descriptor,
        which another thread is using. The reader then fails or sees end of stream, and every exit path asks
        `_refuse_if_out_of_budget` so the answer is the budget, not the shutdown it caused. Nothing is
        abandoned -- the blocked reader is this same call, and it is released rather than left running."""
        sock = self._sock

        def fire() -> None:
            self._out_of_budget = True
            try:
                if sock is not None:
                    sock.shutdown(socket.SHUT_RDWR)
            except OSError:  # pragma: no cover - already closed, or never connected
                pass

        watchdog = threading.Timer(max(0.0, self._deadline - time.monotonic()), fire)
        watchdog.daemon = True
        watchdog.start()
        return watchdog

    def _refuse_if_out_of_budget(self) -> None:
        if self._out_of_budget:
            raise McpError(TRANSPORT_ERROR, "the MCP endpoint did not finish within the call's budget")

    def _remaining(self) -> float:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise McpError(TRANSPORT_ERROR, "the MCP endpoint did not finish within the call's budget")
        return remaining

    def _arm(self) -> None:
        """Re-arm the socket timeout to what is LEFT of the total budget, before every read.

        A socket timeout is per-operation, so without this a server that dribbles one byte per timeout could
        hold the call open for as long as it liked -- the per-message bound would never be reached and the
        host's deadline would turn a reported failure into an unexplained kill."""
        remaining = self._remaining()
        if self._sock is not None:
            try:
                self._sock.settimeout(min(self._timeout, remaining))
            except OSError:  # pragma: no cover - the socket may already be released
                pass


@dataclass(frozen=True)
class Fetched:
    """One answer from `checked_fetch`. Header names are lowercased because HTTP header names are
    case-insensitive and the OAuth rules key off `WWW-Authenticate`, which servers spell every way there is."""

    status: int
    headers: Mapping[str, str]
    body: bytes


def checked_fetch(
    method: str,
    url: str,
    *,
    total_seconds: float,
    request_timeout: float,
    headers: Mapping[str, str] | None = None,
    body: bytes = b"",
    allow_private: bool = False,
    max_bytes: int = MAX_METADATA_BYTES,
    context: ssl.SSLContext | None = None,
) -> Fetched:
    """One request to ONE url, under every rule the MCP endpoint itself is held to.

    This exists for OAuth. Authorization makes a client fetch urls the SERVER chooses -- the metadata url
    arrives in a `WWW-Authenticate` header, and the authorization server's url arrives inside that document
    -- so those fetches are a server-controlled request surface. The specification says nothing about
    restraining it, so routing them through here is Portmark's rule rather than the specification's: the
    address is resolved once and checked, the socket is confirmed to be connected to the address that was
    checked, TLS verifies, the answer is capped, and the same wall-clock watchdog ends a dripped one.

    **Redirects are not followed, and there is no option to follow them.** `http.client` does not follow
    them, so a 3xx is returned as it stands and the caller decides. Following one would reach an address that
    was never checked -- the whole defence undone in a single hop. The official SDK's own auth flow DOES
    follow redirects on its internal requests, which is exactly why Portmark performs them instead of letting
    the SDK perform them."""
    split = urlsplit(url)
    if split.scheme != "https":
        # No exception, and deliberately not one that `allow_private` can open. `allow_private` says WHICH
        # ADDRESSES may be reached; it is not a statement about encryption, and letting it disable TLS here
        # would mean a discovered private token endpoint could receive a client secret, an authorization
        # code or a refresh token in clear. The specification mandates https for the OAuth endpoints --
        # unlike the MCP endpoint itself, where Portmark's rule is its own. The tests reach a loopback
        # authorization server over real TLS with a test trust anchor rather than by weakening this.
        raise McpError(TRANSPORT_ERROR, f"an OAuth endpoint must be https, not {split.scheme!r}")
    transport = HttpTransport(url, request_timeout, total_seconds, allow_private=allow_private, context=context)
    return transport.one_shot(method, headers or {}, body, max_bytes)

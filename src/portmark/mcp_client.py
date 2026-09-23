"""A small MCP client: newline-delimited JSON-RPC over a pair of streams (MCP/SIEM plan, PR 2).

It covers exactly what a mediated tool call needs -- discovery, `tools/list`, `tools/call` -- against both
protocol eras: the modern one (revision 2026-07-28: no `initialize`, per-request `_meta`, `server/discover`)
and the legacy `initialize` handshake of 2025-11-25 and earlier. Nothing here decides authority; the host's
permit, policy and effect ledger do. See MCP.md.

Written against the specification as read on 2026-09-23. No third-party dependency: the wire surface is a
handful of methods, and the official SDK would add 28 packages to a runtime that has two.
"""

from __future__ import annotations

import base64
import queue
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, BinaryIO

from .json_guard import StrictJSONError, strict_json_loads
from .security import canonical_json

MODERN_VERSION = "2026-07-28"
NEWEST_LEGACY_VERSION = "2025-11-25"
LEGACY_VERSION = "2025-06-18"
SUPPORTED_VERSIONS = (MODERN_VERSION, NEWEST_LEGACY_VERSION, LEGACY_VERSION)
LEGACY_VERSIONS = (NEWEST_LEGACY_VERSION, LEGACY_VERSION)
CLIENT_NAME = "portmark"
META_PREFIX = "io.modelcontextprotocol/"
UNSUPPORTED_PROTOCOL_VERSION = -32022

MAX_MESSAGE_BYTES = 1 << 20
_CHUNK_BYTES = 1 << 16
MAX_TOOL_PAGES = 20
MAX_TOOLS = 500
MAX_CONTENT_BLOCKS = 64
MAX_TEXT_BYTES = 1 << 18

# The machine codes the host records in `tool.failed` details. An unlisted code never reaches the audit.
# The body fields the Streamable HTTP binding mirrors into an `Mcp-Name` header, by method.
NAMED_METHODS = {"tools/call": "name", "resources/read": "uri", "prompts/get": "name"}
# The marker that says "this header value is Base64 of UTF-8". Lower-case and exact, per the specification.
SENTINEL_PREFIX = "=?base64?"
SENTINEL_SUFFIX = "?="

TOOL_ERROR = "mcp_tool_error"
TRANSPORT_ERROR = "mcp_transport_error"
PROTOCOL_ERROR = "mcp_protocol_error"
PIN_DRIFT = "mcp_pin_drift"
CONFIG_DRIFT = "mcp_config_drift"
ERROR_CODES = frozenset({TOOL_ERROR, TRANSPORT_ERROR, PROTOCOL_ERROR, PIN_DRIFT, CONFIG_DRIFT})


class McpError(Exception):
    """A failure with the machine code the host will record. `code` is one of ERROR_CODES."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code if code in ERROR_CODES else PROTOCOL_ERROR


@dataclass(frozen=True)
class ToolResult:
    """What a mediated MCP call returns. `is_error` is the server's own `isError`, not a transport failure."""

    value: dict[str, Any]
    is_error: bool


class _LineReader:
    """Reads newline-delimited messages in a thread, so a silent server cannot block a deadline.

    The worker process is also killed by the host at its deadline; this bound is the inner one, and it is
    what lets the legacy fallback decide "no answer in time" without hanging."""

    def __init__(self, stream: BinaryIO, max_bytes: int = MAX_MESSAGE_BYTES) -> None:
        self._queue: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=64)
        self._stream = stream
        self._max_bytes = max_bytes
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        # Chunks, not readline(): readline() returns only when it finds a newline, so a server that never
        # sends one would grow the buffer until the machine runs out of memory -- the size check has to bound
        # the frame WHILE it is arriving (Codex review R1).
        buffer = bytearray()
        try:
            while True:
                chunk = self._stream.read1(_CHUNK_BYTES) if hasattr(self._stream, "read1") else self._stream.read(_CHUNK_BYTES)
                if not chunk:
                    return
                buffer.extend(chunk)
                while True:
                    end = buffer.find(b"\n")
                    if end < 0:
                        break
                    line = bytes(buffer[:end])
                    del buffer[: end + 1]
                    if line.strip():
                        self._queue.put(("line", line))
                if len(buffer) > self._max_bytes:
                    self._queue.put(("error", f"a server message exceeded {self._max_bytes} bytes"))
                    return
        except Exception as error:  # noqa: BLE001 - reported as a transport failure
            self._queue.put(("error", str(error)))
        finally:
            self._queue.put(("eof", None))

    def read(self, timeout: float) -> bytes | None:
        """The next message, or None when the stream ended. Raises McpError on timeout or a read failure."""
        try:
            kind, value = self._queue.get(timeout=timeout)
        except queue.Empty:
            raise McpError(TRANSPORT_ERROR, f"the MCP server did not answer within {timeout:g}s") from None
        if kind == "line":
            return value
        if kind == "eof":
            return None
        raise McpError(TRANSPORT_ERROR, f"reading from the MCP server failed: {value}")


def header_value(value: str) -> str:
    """One body value, safe to put in an HTTP header.

    RFC 9110 allows visible ASCII, space and horizontal tab in a field value, and a field value may not begin
    or end with whitespace. Anything outside that -- and any plain value that would itself READ as the marker
    -- is carried as `=?base64?<base64 of the UTF-8 bytes>?=`. This is what stops a value from injecting a
    header or a request line, and the server undoes it before comparing the header to the body."""
    if _is_plain_header_ascii(value):
        return value
    return SENTINEL_PREFIX + base64.b64encode(value.encode("utf-8")).decode("ascii") + SENTINEL_SUFFIX


def _is_plain_header_ascii(value: str) -> bool:
    if value != value.strip():  # a field value may not begin or end with whitespace
        return False
    if value.startswith(SENTINEL_PREFIX) and value.endswith(SENTINEL_SUFFIX):
        return False  # a literal that looks like the marker must be encoded, or it would decode as one
    return all(0x21 <= ord(character) <= 0x7E or character in (" ", "\t") for character in value)


class Transport:
    """How one message reaches a server and how the answers come back.

    Two methods, because that is all the protocol above needs. `headers` is the HTTP request metadata the
    specification requires; the stdio transport ignores it, so the client can compute it once for both.
    `peer_closed` exists for the stdio worker, which relaunches a server that exited on the era probe."""

    peer_closed = False

    def send(self, encoded: bytes, headers: Mapping[str, str]) -> None:
        raise NotImplementedError

    def read(self, timeout: float) -> bytes | None:
        """The next message, or None when the peer is finished."""
        raise NotImplementedError

    def close(self) -> None:
        pass


class _StdioTransport(Transport):
    """Newline-delimited JSON-RPC over a pair of open streams, as the stdio binding prescribes."""

    def __init__(self, stdin: BinaryIO, stdout: BinaryIO, max_bytes: int = MAX_MESSAGE_BYTES) -> None:
        self._stdin = stdin
        self._reader = _LineReader(stdout, max_bytes)
        self.peer_closed = False

    def send(self, encoded: bytes, headers: Mapping[str, str]) -> None:
        if b"\n" in encoded:  # canonical_json escapes newlines; this is the framing invariant, asserted
            raise McpError(PROTOCOL_ERROR, "a request would break the one-message-per-line framing")
        try:
            self._stdin.write(encoded + b"\n")
            self._stdin.flush()
        except OSError as error:
            raise McpError(TRANSPORT_ERROR, f"writing to the MCP server failed: {error}") from error

    def read(self, timeout: float) -> bytes | None:
        line = self._reader.read(timeout)
        if line is None:
            self.peer_closed = True
        return line


class McpClient:
    """One connection to one MCP server, over a transport that is already open."""

    def __init__(self, transport: Transport, timeout: float, client_version: str = "") -> None:
        self._transport = transport
        self._timeout = timeout
        self._next_id = 0
        self._version: str | None = None
        self._legacy = False
        # A legacy server is told the agreed version on every request AFTER the handshake, never on
        # `initialize` itself -- that request is what decides the version.
        self._legacy_ready = False
        self._client_version = client_version

    @classmethod
    def over_streams(cls, stdin: BinaryIO, stdout: BinaryIO, timeout: float, client_version: str = "") -> "McpClient":
        return cls(_StdioTransport(stdin, stdout), timeout, client_version)

    @property
    def peer_closed(self) -> bool:
        return self._transport.peer_closed

    def close(self) -> None:
        self._transport.close()

    # -- framing ------------------------------------------------------------------------------------------

    def _meta(self) -> dict[str, Any]:
        info: dict[str, Any] = {"name": CLIENT_NAME}
        if self._client_version:
            info["version"] = self._client_version
        return {
            f"{META_PREFIX}protocolVersion": self._version or MODERN_VERSION,
            f"{META_PREFIX}clientInfo": info,
            # Portmark consumes tool results only: it offers the server no roots, sampling or elicitation.
            f"{META_PREFIX}clientCapabilities": {},
        }

    def _message_headers(self, message: Mapping[str, Any], extra: Mapping[str, str] = {}) -> dict[str, str]:
        """The request metadata the Streamable HTTP binding requires, mirrored from the body.

        Built for every message and ignored by the stdio transport, so there is ONE place that decides what a
        header says and it cannot drift from the body it was copied from -- which is exactly what a server
        rejects with `HeaderMismatch`. The version header is omitted before a legacy handshake has agreed
        one, because that request is what agrees it."""
        headers: dict[str, str] = {}
        method = message.get("method")
        if isinstance(method, str):
            headers["Mcp-Method"] = method
        if not self._legacy:
            headers["MCP-Protocol-Version"] = self._version or MODERN_VERSION
        elif self._legacy_ready and self._version:
            headers["MCP-Protocol-Version"] = self._version
        params = message.get("params")
        key = NAMED_METHODS.get(method) if isinstance(method, str) else None
        if key and isinstance(params, Mapping):
            name = params.get(key)
            if isinstance(name, str):
                headers["Mcp-Name"] = header_value(name)
        headers.update(extra)
        return headers

    def _send(self, message: Mapping[str, Any], headers: Mapping[str, str] = {}) -> None:
        try:
            encoded = canonical_json(message)
        except ValueError as error:
            raise McpError(PROTOCOL_ERROR, f"cannot encode a request for the MCP server: {error}") from error
        self._transport.send(encoded, self._message_headers(message, headers))

    def _receive(self, request_id: int) -> dict[str, Any]:
        """The response to `request_id`. Notifications are skipped; a server REQUEST is refused."""
        while True:
            line = self._transport.read(self._timeout)
            if line is None:
                raise McpError(TRANSPORT_ERROR, "the MCP server closed its output before answering")
            try:
                message = strict_json_loads(line, max_bytes=MAX_MESSAGE_BYTES)
            except StrictJSONError as error:
                raise McpError(PROTOCOL_ERROR, f"the MCP server sent a malformed message: {error}") from error
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                raise McpError(PROTOCOL_ERROR, "the MCP server sent a message that is not JSON-RPC 2.0")
            if "method" in message:
                if "id" in message:
                    # The stdio binding forbids it, and Portmark has no side channel to answer one.
                    raise McpError(PROTOCOL_ERROR, f"the MCP server sent a request ({message['method']!r}); refused")
                continue  # a notification: progress, logging, list_changed -- nothing to do here
            message_id = message.get("id")
            if message_id != request_id:
                if isinstance(message_id, int) and not isinstance(message_id, bool) and message_id < request_id:
                    # A late answer to an earlier request (the era probe that timed out): skip it, do not
                    # treat it as the answer to this one and do not fail on it.
                    continue
                raise McpError(PROTOCOL_ERROR, "the MCP server answered with the wrong request id")
            return message

    @property
    def version(self) -> str:
        """The protocol version in use, once connected."""
        return self._version or ""

    def request(
        self, method: str, params: dict[str, Any] | None = None, headers: Mapping[str, str] = {}
    ) -> dict[str, Any]:
        """Send one request and return its `result`, or raise McpError (JSON-RPC errors included)."""
        self._next_id += 1
        request_id = self._next_id
        body: dict[str, Any] = dict(params or {})
        if not self._legacy:
            body["_meta"] = {**body.get("_meta", {}), **self._meta()}
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": body}, headers)
        message = self._receive(request_id)
        if "error" in message:
            raise _error_from(message["error"], method)
        result = message.get("result")
        if not isinstance(result, dict):
            raise McpError(PROTOCOL_ERROR, f"the MCP server's answer to {method!r} has no result object")
        kind = result.get("resultType", "complete")  # absent means "complete" for pre-2026-07-28 servers
        if kind != "complete":
            raise McpError(
                TOOL_ERROR if kind == "input_required" else PROTOCOL_ERROR,
                f"the MCP server answered {method!r} with resultType {kind!r}; a mediated call cannot supply more input",
            )
        return result

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": dict(params or {})})

    # -- lifecycle ----------------------------------------------------------------------------------------

    def connect(self) -> str:
        """Agree a protocol version, exactly as the stdio binding's backward-compatibility rules prescribe.

        Probe with `server/discover`: a result means modern; `UnsupportedProtocolVersionError` means modern
        with another version; ANY other error, or no answer in time, means legacy -- the fallback is never
        keyed to one error code, because legacy servers answer an unknown pre-`initialize` method freely."""
        self._version = MODERN_VERSION
        try:
            result = self.request("server/discover")
        except McpError as error:
            if getattr(error, "unsupported_versions", None):
                return self._select_modern(error.unsupported_versions)  # type: ignore[attr-defined]
            if error.code == PROTOCOL_ERROR and "sent a request" in str(error):
                raise
            return self._initialize()
        supported = result.get("supportedVersions")
        if not isinstance(supported, list) or not all(isinstance(item, str) for item in supported):
            raise McpError(PROTOCOL_ERROR, "server/discover did not list supportedVersions")
        return self._select_modern(tuple(supported))

    def _select_modern(self, supported: tuple[str, ...]) -> str:
        for version in SUPPORTED_VERSIONS:
            if version in supported:
                self._version = version
                self._legacy = version != MODERN_VERSION
                if self._legacy:
                    return self._initialize(version)
                return version
        raise McpError(
            PROTOCOL_ERROR,
            f"the MCP server supports {list(supported)}, and Portmark speaks {list(SUPPORTED_VERSIONS)}",
        )

    def connect_legacy(self, version: str = NEWEST_LEGACY_VERSION) -> str:
        """The legacy handshake on a FRESH connection, for a server that exited on the modern probe."""
        return self._initialize(version)

    def _initialize(self, version: str = NEWEST_LEGACY_VERSION) -> str:
        """The legacy handshake. `version` is the revision the server advertised, or -- when the probe told us
        nothing -- the NEWEST legacy revision Portmark speaks, because asking for the oldest would settle for
        less than both sides support (Codex review R1)."""
        self._legacy = True
        self._version = version
        result = self.request(
            "initialize",
            {
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": self._client_version or "0"},
            },
        )
        agreed = result.get("protocolVersion")
        if not isinstance(agreed, str) or not agreed:
            raise McpError(PROTOCOL_ERROR, "the MCP server's initialize answer has no protocolVersion")
        if agreed not in LEGACY_VERSIONS:
            # The 2025-11-25 schema is explicit: a client that cannot support the revision the server answers
            # with MUST disconnect. Carrying on would speak a protocol neither side agreed (Codex review R2).
            raise McpError(
                PROTOCOL_ERROR,
                f"the MCP server answered initialize with {agreed!r}; Portmark speaks {list(LEGACY_VERSIONS)}",
            )
        self._version = agreed
        self._legacy_ready = True
        self.notify("notifications/initialized")
        return agreed

    # -- tools --------------------------------------------------------------------------------------------

    def list_tools(self) -> dict[str, dict[str, Any]]:
        """Every tool the server reports, by name. Bounded in pages and in count."""
        tools: dict[str, dict[str, Any]] = {}
        cursor: str | None = None
        for _ in range(MAX_TOOL_PAGES):
            params = {"cursor": cursor} if cursor else {}
            result = self.request("tools/list", params)
            page = result.get("tools")
            if not isinstance(page, list):
                raise McpError(PROTOCOL_ERROR, "tools/list did not return a list of tools")
            for definition in page:
                if not isinstance(definition, dict) or not isinstance(definition.get("name"), str):
                    raise McpError(PROTOCOL_ERROR, "tools/list returned a tool without a name")
                tools[definition["name"]] = definition
                if len(tools) > MAX_TOOLS:
                    raise McpError(PROTOCOL_ERROR, f"the MCP server reported more than {MAX_TOOLS} tools")
            cursor = result.get("nextCursor") if isinstance(result.get("nextCursor"), str) else None
            if not cursor:
                return tools
        raise McpError(PROTOCOL_ERROR, f"tools/list did not finish within {MAX_TOOL_PAGES} pages")

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> ToolResult:
        result = self.request("tools/call", {"name": name, "arguments": dict(arguments)})
        return ToolResult(_tool_value(result), bool(result.get("isError", False)))


def _error_from(error: Any, method: str) -> McpError:
    if not isinstance(error, dict):
        return McpError(PROTOCOL_ERROR, f"the MCP server's error for {method!r} is malformed")
    code = error.get("code")
    message = error.get("message") if isinstance(error.get("message"), str) else ""
    failure = McpError(PROTOCOL_ERROR, f"the MCP server refused {method!r} ({code}): {message[:200]}")
    if code == UNSUPPORTED_PROTOCOL_VERSION:
        data = error.get("data")
        supported = data.get("supported") if isinstance(data, dict) else None
        if isinstance(supported, list) and all(isinstance(item, str) for item in supported):
            failure.unsupported_versions = tuple(supported)  # type: ignore[attr-defined]
    return failure


def _tool_value(result: Mapping[str, Any]) -> dict[str, Any]:
    """The JSON-safe value the host stores and the model sees. A tool result is data, never instructions."""
    value: dict[str, Any] = {}
    if "structuredContent" in result:
        value["structured_content"] = result["structuredContent"]
    blocks = result.get("content")
    if isinstance(blocks, list):
        content: list[Any] = []
        for block in blocks[:MAX_CONTENT_BLOCKS]:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                content.append({"type": "text", "text": block["text"][:MAX_TEXT_BYTES]})
            else:
                # Images, audio and embedded resources are not dropped silently: the model is told one was
                # there, without the payload entering the checkpoint.
                content.append({"type": str(block.get("type", "unknown"))[:32], "omitted": True})
        value["content"] = content
        if len(blocks) > MAX_CONTENT_BLOCKS:
            value["content_truncated"] = True
    return value

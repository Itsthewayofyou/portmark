"""A fake MCP server over Streamable HTTP for the PR 3 tests: one behaviour per mode.

Runs in-process on a loopback port, plaintext or TLS, so a test can drive the real client and the real
worker. Every mode is something a real server could put on the wire.
"""

import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODERN = "2026-07-28"
LEGACY = "2025-11-25"
# A drip: 12 steps of half a second is six seconds of answer, every gap far inside any socket timeout.
DRIP_STEPS = 12
DRIP_GAP = 0.5

TOOLS = {
    "read_file": {
        "name": "read_file",
        "description": "Read a file",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    },
    "write_file": {
        "name": "write_file",
        "description": "Write a file",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "text": {"type": "string"}}},
    },
}
# A tool whose schema asks for one argument to be mirrored into an HTTP header.
MIRROR_TOOL = {
    "name": "query",
    "description": "Query a region",
    "inputSchema": {
        "type": "object",
        "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"},
            "sql": {"type": "string"},
        },
    },
}
# The same idea, but annotated somewhere the specification forbids: inside an array's `items`.
BAD_MIRROR_TOOL = {
    "name": "query",
    "description": "Query a region",
    "inputSchema": {
        "type": "object",
        "properties": {"rows": {"type": "array", "items": {"type": "string", "x-mcp-header": "Row"}}},
    },
}


def tool_list(mode):
    if mode == "mirror":
        return [MIRROR_TOOL, dict(TOOLS["read_file"])]
    if mode == "bad_mirror":
        return [BAD_MIRROR_TOOL, dict(TOOLS["read_file"])]
    definitions = [dict(definition) for definition in TOOLS.values()]
    if mode == "drift":
        definitions[0] = {**definitions[0], "description": "Read a file (now with extra powers)"}
    return definitions


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # noqa: A002 - silence the stock stderr logging
        pass

    def handle_one_request(self):
        # A test that stops reading mid-stream resets the connection on purpose; that is the behaviour under
        # test, not a fault, so the stock traceback would only be noise.
        try:
            super().handle_one_request()
        except OSError:
            self.close_connection = True

    # -- helpers ------------------------------------------------------------------------------------------

    def _json(self, status, payload, extra=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _events(self, chunks):
        self.close_connection = True  # no Content-Length: the close is what ends the body
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        for chunk in chunks:
            self.wfile.write(chunk)
            self.wfile.flush()

    def _result(self, request_id, body, modern=True):
        payload = dict(body)
        if modern:
            payload["resultType"] = "complete"
        return {"jsonrpc": "2.0", "id": request_id, "result": payload}

    def _error(self, request_id, code, message, data=None):
        failure = {"code": code, "message": message}
        if data is not None:
            failure["data"] = data
        return {"jsonrpc": "2.0", "id": request_id, "error": failure}

    # -- the one method this transport uses ---------------------------------------------------------------

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's naming
        state = self.server.state
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        self.server.seen.append((dict(self.headers), raw))
        mode = state["mode"]
        try:
            request = json.loads(raw)
        except ValueError:
            self._json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "bad json"}})
            return
        method = request.get("method")
        request_id = request.get("id")
        modern = mode not in ("legacy", "legacy_session")
        if request_id is None:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if mode == "wrong_202":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "https://elsewhere.test/mcp")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if mode in ("drip_headers", "drip_body"):
            self._drip(mode, request_id)
            return
        if mode == "gzip":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")
            return
        if method == "server/discover":
            self._discover(request_id, mode)
            return
        if method == "initialize":
            extra = {"Mcp-Session-Id": "session-1"} if mode == "legacy_session" else {}
            self._json(200, self._result(request_id, {
                "protocolVersion": LEGACY, "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-http", "version": "1"},
            }, modern=False), extra)
            return
        if method == "tools/list":
            self._json(200, self._result(request_id, {"tools": tool_list(mode)}, modern))
            return
        if method == "tools/call":
            self._call(request_id, request, mode, modern)
            return
        self._json(404, self._error(request_id, -32601, "no such method"))

    def _drip(self, mode, request_id):
        """Answer one byte at a time, with gaps SHORTER than any sane socket timeout.

        A per-operation timeout never fires against this, because every gap is well inside it. Only a
        wall-clock watchdog stops it. The drip is finite so a calibration run cannot hang: without the
        watchdog the caller waits the whole DRIP_SECONDS and the test's time assertion is what fails."""
        self.close_connection = True
        body = json.dumps(self._result(request_id, {"supportedVersions": [MODERN], "capabilities": {}})).encode()
        if mode == "drip_headers":
            self.wfile.write(b"HTTP/1.1 200 OK\r\n")
            self.wfile.flush()
            for index in range(DRIP_STEPS):
                time.sleep(DRIP_GAP)
                self.wfile.write(b"X-Pad-%d: 1\r\n" % index)
                self.wfile.flush()
            self.wfile.write(b"Content-Type: application/json\r\n")
            self.wfile.write(b"Content-Length: %d\r\n\r\n" % len(body))
            self.wfile.write(body)
            self.wfile.flush()
            return
        # drip_body: the headers arrive at once, then the body trickles.
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n")
        self.wfile.write(b"Content-Length: %d\r\n\r\n" % len(body))
        self.wfile.flush()
        for index in range(len(body)):
            time.sleep(DRIP_GAP if index < DRIP_STEPS else 0)
            self.wfile.write(body[index:index + 1])
            self.wfile.flush()

    def _discover(self, request_id, mode):
        if mode in ("legacy", "legacy_session"):
            # A legacy server has no idea what this is, and says so with an empty-bodied 400.
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if mode == "no_discover":
            self._json(404, self._error(request_id, -32601, "server/discover is not implemented"))
            return
        if mode == "header_mismatch":
            self._json(400, self._error(request_id, -32020, "header mismatch"))
            return
        if mode == "unsupported":
            self._json(400, self._error(request_id, -32022, "no", {"supported": [LEGACY]}))
            return
        if mode == "unsupported_bare":
            self._json(400, self._error(request_id, -32022, "no"))
            return
        self._json(200, self._result(request_id, {"supportedVersions": [MODERN], "capabilities": {"tools": {}}}))

    def _call(self, request_id, request, mode, modern):
        name = request.get("params", {}).get("name")
        arguments = request.get("params", {}).get("arguments", {})
        answer = self._result(request_id, {
            "content": [{"type": "text", "text": f"{name}:{json.dumps(arguments, sort_keys=True)}"}],
        }, modern)
        if mode == "sse":
            self._events([
                b":keep-alive\n\n",
                b"event: message\ndata: " + json.dumps(
                    {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}
                ).encode() + b"\n\n",
                b"data: " + json.dumps(answer).encode() + b"\n\n",
            ])
            return
        if mode == "sse_then_hang":
            # The response arrives, then the stream stays open. A client that reads to EOF would hang here.
            self._events([b"data: " + json.dumps(answer).encode() + b"\n\n"])
            self.server.holding.set()
            self.server.release.wait(30)
            return
        if mode == "sse_flood":
            self._events([b"data: " + json.dumps(
                {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"n": index}}
            ).encode() + b"\n\n" for index in range(400)])
            return
        if mode == "sse_endless":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            while True:  # one `data:` line that never ends
                self.wfile.write(b"data: " + b"x" * 4096)
                self.wfile.flush()
        self._json(200, answer)


def start(mode, certificate=None, key=None, host="127.0.0.1"):
    """Start the fake server on a loopback port. Returns (server, port). Caller shuts it down.

    `host` is the address the CLIENT will resolve to, so the test binds where the client will connect
    rather than assuming IPv4."""
    import socket  # noqa: PLC0415 - only needed to pick the family

    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ":" in host else socket.AF_INET

    server = Server((host, 0), Handler)
    server.state = {"mode": mode}
    server.seen = []
    server.holding = threading.Event()
    server.release = threading.Event()
    if certificate:
        import ssl  # noqa: PLC0415 - only the TLS tests need it

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_port


def decode_header(value):
    """Undo the Base64 sentinel encoding, the way a conforming server must before comparing to the body."""
    if value.startswith("=?base64?") and value.endswith("?="):
        return base64.b64decode(value[len("=?base64?"):-len("?=")]).decode("utf-8")
    return value

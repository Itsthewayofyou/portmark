"""A loopback OAuth authorization server and protected MCP resource, for the OAuth driver tests.

Small on purpose. It answers only what the flow actually asks for -- an unauthorized probe, protected-resource
metadata, authorization-server metadata, and a token exchange -- plus the specific malformed answers the
driver has to refuse. `mode` selects which of those it is being today.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

ACCESS_TOKEN = "access-token-from-the-fake-server"  # nosec B105 - a fixture, not a credential
REFRESH_TOKEN = "refresh-token-from-the-fake-server"  # nosec B105 - a fixture, not a credential
AUTHORIZATION_CODE = "the-authorization-code"
SCOPE = "files:read"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # -- plumbing ---------------------------------------------------------------------------------------

    def log_message(self, *args):  # noqa: A002 - silence the default stderr logging
        pass

    @property
    def origin(self) -> str:
        return f"http://{self.server.server_address[0]}:{self.server.server_address[1]}"

    def reply(self, status: int, body: bytes = b"", headers: dict | None = None) -> None:
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def json(self, status: int, document: dict, headers: dict | None = None) -> None:
        self.reply(status, json.dumps(document).encode(), headers)

    # -- the endpoints ----------------------------------------------------------------------------------

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
        mode = self.server.mode
        if self.path.startswith("/.well-known/oauth-protected-resource"):
            if mode == "redirecting_metadata":
                # Never followed: the destination has been checked by nobody.
                self.reply(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
                return
            self.json(200, {"resource": f"{self.origin}/mcp", "authorization_servers": [self.origin],
                            "scopes_supported": [SCOPE]})
            return
        if self.path.startswith("/.well-known/oauth-authorization-server") or self.path.startswith("/.well-known/openid-configuration"):
            if mode == "wrong_issuer":
                # The specification's own example attack: a document served from one origin claiming to be
                # another. The client MUST NOT use it.
                self.json(200, self._metadata(issuer="https://honest.example"))
                return
            if mode == "no_metadata":
                self.reply(404)
                return
            self.json(200, self._metadata(issuer=self.origin))
            return
        self.reply(404)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if self.path.startswith("/token"):
            self.server.token_requests.append(parse_qs(body.decode()))
            if self.server.mode == "token_refused":
                self.json(400, {"error": "invalid_grant"})
                return
            document = {"access_token": ACCESS_TOKEN, "token_type": "Bearer", "expires_in": 3600, "scope": SCOPE}  # nosec B105 - "Bearer" is the OAuth token TYPE, a protocol constant
            if self.server.mode != "no_refresh_token":
                document["refresh_token"] = REFRESH_TOKEN
            self.json(200, document)
            return
        if self.path.startswith("/mcp"):
            self.server.mcp_requests.append(dict(self.headers))
            challenge = (
                f'Bearer resource_metadata="{self.origin}/.well-known/oauth-protected-resource", scope="{SCOPE}"'
                if self.server.mode != "bare_challenge"
                else "Bearer"
            )
            self.reply(401, headers={"WWW-Authenticate": challenge})
            return
        self.reply(404)

    def _metadata(self, issuer: str) -> dict:
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{self.origin}/authorize",
            "token_endpoint": f"{self.origin}/token",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": [SCOPE],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
            "authorization_response_iss_parameter_supported": True,
        }


class FakeAuthorizationServer:
    """Start with `with FakeAuthorizationServer() as server:` and read `server.url`."""

    def __init__(self, mode: str = "ok") -> None:
        self._http = HTTPServer(("127.0.0.1", 0), _Handler)
        self._http.mode = mode
        self._http.token_requests = []
        self._http.mcp_requests = []
        self._thread = threading.Thread(target=self._http.serve_forever, daemon=True)

    def __enter__(self) -> "FakeAuthorizationServer":
        self._thread.start()
        return self

    def __exit__(self, *exception) -> None:
        self._http.shutdown()
        self._http.server_close()
        self._thread.join(timeout=5)

    @property
    def origin(self) -> str:
        host, port = self._http.server_address[0], self._http.server_address[1]
        return f"http://{host}:{port}"

    @property
    def url(self) -> str:
        return f"{self.origin}/mcp"

    @property
    def token_requests(self) -> list:
        return self._http.token_requests

    @property
    def mcp_requests(self) -> list:
        return self._http.mcp_requests

"""A loopback OAuth authorization server and protected MCP resource, for the OAuth driver tests.

Small on purpose. It answers only what the flow actually asks for -- an unauthorized probe, protected-resource
metadata, authorization-server metadata, and a token exchange -- plus the specific malformed answers the
driver has to refuse. `mode` selects which of those it is being today.
"""

from __future__ import annotations

import datetime
import json
import socket
import ssl
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
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
        return self.server.origin

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
            self.server.prm_requests.append(self.path)
            if mode == "redirecting_metadata":
                # Never followed: the destination has been checked by nobody.
                self.reply(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
                return
            # `moved_issuer`: the resource now names a DIFFERENT authorization server than the one that
            # issued the stored credentials. Not a hypothetical -- it is either a reconfiguration or an
            # attack, and from the client's side those look the same.
            named = "https://somewhere-else.example" if mode == "moved_issuer" else self.origin
            self.json(200, {"resource": f"{self.origin}/mcp", "authorization_servers": [named],
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
        if self.path.startswith("/token") or self.path.startswith("/elsewhere/token"):
            self.server.token_requests.append(parse_qs(body.decode()))
            self.server.token_paths.append(self.path)
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


def _trust_anchor(directory: Path) -> tuple[Path, Path]:
    """A throwaway certificate for `localhost`, so the tests reach this server over REAL TLS.

    The alternative -- letting `checked_fetch` accept plain http for a loopback address -- would be a test
    weakening a security rule, and the rule it weakens is the one that keeps a refresh token off the wire in
    clear. Generating a certificate is cheaper than that trade."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    certificate_path, key_path = directory / "cert.pem", directory / "key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    return certificate_path, key_path


class FakeAuthorizationServer:
    """A loopback authorization server over REAL TLS.

    `with FakeAuthorizationServer() as server:` then read `server.url` and pass `server.context` to whatever
    performs the request, so the throwaway certificate is the only anchor it trusts."""

    def __init__(self, mode: str = "ok") -> None:
        self._dir = tempfile.TemporaryDirectory()
        certificate_path, key_path = _trust_anchor(Path(self._dir.name))
        self._certificate = str(certificate_path)
        # BIND WHERE THE CLIENT WILL CONNECT, rather than assuming IPv4. The certificate names `localhost`,
        # and what `localhost` resolves to is not the same everywhere: this project's GitHub runners answer
        # `::1` while the development machine answers `127.0.0.1` (observed 2026-09-23). Binding 127.0.0.1
        # and connecting to `localhost` therefore passes locally and fails in CI with ConnectionRefused.
        from portmark.mcp_http import resolve_endpoint_address  # noqa: PLC0415 - a test helper, not runtime

        host = resolve_endpoint_address("localhost", 0, allow_private=True)

        class _Server(HTTPServer):
            address_family = socket.AF_INET6 if ":" in host else socket.AF_INET

        self._http = _Server((host, 0), _Handler)
        server_side = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_side.load_cert_chain(str(certificate_path), str(key_path))
        self._http.socket = server_side.wrap_socket(self._http.socket, server_side=True)
        # The client is given the NAME, so TLS verifies against the certificate; the transport resolves it
        # to the same address this server is bound to and pins that.
        self._http.origin = f"https://localhost:{self._http.server_address[1]}"
        self._http.mode = mode
        self._http.token_requests = []
        self._http.token_paths = []
        self._http.prm_requests = []
        self._http.mcp_requests = []
        self._context = ssl.create_default_context(cafile=str(certificate_path))
        self._thread = threading.Thread(target=self._http.serve_forever, daemon=True)

    def __enter__(self) -> "FakeAuthorizationServer":
        self._thread.start()
        return self

    def __exit__(self, *exception) -> None:
        self._http.shutdown()
        self._http.server_close()
        self._thread.join(timeout=5)
        self._dir.cleanup()

    @property
    def context(self) -> ssl.SSLContext:
        """A verifying context whose only trust anchor is this server's throwaway certificate."""
        return self._context

    @property
    def certificate(self) -> str:
        """The certificate file, for a test that must reach code which builds its own default context."""
        return self._certificate

    @property
    def origin(self) -> str:
        return self._http.origin

    @property
    def url(self) -> str:
        return f"{self.origin}/mcp"

    @property
    def token_requests(self) -> list:
        return self._http.token_requests

    @property
    def token_paths(self) -> list:
        return self._http.token_paths

    @property
    def prm_requests(self) -> list:
        return self._http.prm_requests

    @property
    def mcp_requests(self) -> list:
        return self._http.mcp_requests

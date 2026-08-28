from __future__ import annotations

import json
import logging
import os
import secrets
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .a2a_types import A2ARequestError, error_response, make_agent_card, parse_jsonrpc_request, success_response, task_from_run_result
from .host import AgentHost
from .models import AgentEnvelope, AgentManifest, AgentState, AttestationEvidence, Permit, ResourceBudget, ToolGrant


logger = logging.getLogger(__name__)
MAX_REQUEST_BYTES = 1_000_000


def envelope_from_dict(value: dict[str, Any]) -> AgentEnvelope:
    manifest = AgentManifest(**{**value["manifest"], "requested_tools": tuple(value["manifest"]["requested_tools"])})
    permit_value = value["permit"]
    permit = Permit(
        issuer=permit_value["issuer"], subject=permit_value["subject"], audience=permit_value["audience"],
        expires_at=permit_value["expires_at"], nonce=permit_value["nonce"],
        grants=tuple(ToolGrant(**grant) for grant in permit_value["grants"]),
        budget=ResourceBudget(**permit_value.get("budget", {})),
        delegation_allowed=permit_value.get("delegation_allowed", False),
        attestation=AttestationEvidence(**permit_value["attestation"]) if permit_value.get("attestation") else None,
    )
    return AgentEnvelope(
        manifest=manifest,
        permit=permit,
        state=AgentState(**value["state"]),
        previous_audit_hash=value.get("previous_audit_hash", ""),
        signature_key_id=value.get("signature_key_id", ""),
        signature=value["signature"],
    )


@dataclass(frozen=True)
class A2AAuthConfig:
    bearer_token: str | None = None
    realm: str = "portable-agent"

    @property
    def required(self) -> bool:
        return bool(self.bearer_token)


def make_handler(host: AgentHost, auth: A2AAuthConfig | None = None, enable_hsts: bool = False):
    auth_config = auth or A2AAuthConfig()

    class A2AHandler(BaseHTTPRequestHandler):
        server_version = "PortableAgentA2A/1.0"

        def _json(self, status: int, value: Any, headers: dict[str, str] | None = None) -> None:
            payload = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            if enable_hsts:
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            if headers:
                for key, value in headers.items():
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            if self.path == "/.well-known/agent-card.json":
                self._json(200, make_agent_card(self._base_url(), auth_config.required))
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path != "/message:send":
                self._json(404, error_response(None, -32601, "method not found"))
                return
            if not self._authorized(auth_config):
                self._json(
                    401,
                    error_response(None, -32001, "unauthorized"),
                    {"WWW-Authenticate": f'Bearer realm="{auth_config.realm}"'},
                )
                return
            request_id: str | int | None = None
            try:
                if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                    raise A2ARequestError(-32600, "invalid request", 415)
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                except ValueError as exc:
                    raise A2ARequestError(-32600, "invalid request", 400) from exc
                if size <= 0 or size > MAX_REQUEST_BYTES:
                    raise A2ARequestError(-32600, "invalid request", 413)
                try:
                    payload = json.loads(self.rfile.read(size))
                except json.JSONDecodeError as exc:
                    raise A2ARequestError(-32700, "parse error", 400) from exc
                request = parse_jsonrpc_request(payload)
                request_id = request.id
                envelope = envelope_from_dict(request.params.portable_agent_envelope)
                result = host.run(envelope)
                self._json(200, success_response(request.id, task_from_run_result(result)))
            except A2ARequestError as exc:
                self._json(exc.http_status, error_response(exc.request_id, exc.code, exc.message))
            except Exception:
                logger.exception("A2A message submission failed")
                self._json(400, error_response(request_id, -32000, "message submission failed"))

        def _base_url(self) -> str:
            return f"http://{self.headers.get('Host', '127.0.0.1')}"

        def _authorized(self, config: A2AAuthConfig) -> bool:
            if not config.bearer_token:
                return True
            header = self.headers.get("Authorization", "")
            prefix = "Bearer "
            if not header.startswith(prefix):
                return False
            return secrets.compare_digest(header[len(prefix):], config.bearer_token)

        def log_message(self, format: str, *args: Any) -> None:
            return

    return A2AHandler


def auth_from_environment() -> A2AAuthConfig:
    return A2AAuthConfig(os.environ.get("PORTABLE_AGENT_A2A_TOKEN"))


def serve(host: AgentHost, bind: str, port: int, auth: A2AAuthConfig | None = None, enable_hsts: bool = False) -> None:
    ThreadingHTTPServer((bind, port), make_handler(host, auth or auth_from_environment(), enable_hsts)).serve_forever()

from __future__ import annotations

import ipaddress
import json
import logging
import os
import secrets
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any, Iterator

from .a2a_types import A2ARequestError, error_response, make_agent_card, parse_jsonrpc_request, success_response, task_from_run_result
from .host import AgentHost
from .models import AgentEnvelope, AgentManifest, AgentState, AttestationEvidence, Permit, ResourceBudget, ToolGrant
from .official_a2a import make_sdk_agent_card, validate_sdk_message_send_params


logger = logging.getLogger(__name__)
MAX_REQUEST_BYTES = 1_000_000
DEFAULT_MAX_CONCURRENT_REQUESTS = 32
DEFAULT_RATE_LIMIT_PER_IP = 120
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60
DEFAULT_AGENT_CARD_RATE_LIMIT_PER_IP = 240
DEFAULT_AGENT_CARD_RATE_LIMIT_WINDOW_SECONDS = 60
DEFAULT_RATE_LIMIT_TRACKED_CLIENTS = 8192
A2A_ADAPTERS = ("local", "sdk")
BUSY_RESPONSE = (
    b"HTTP/1.1 503 Service Unavailable\r\n"
    b"Content-Type: application/json\r\n"
    b"Connection: close\r\n"
    b"X-Content-Type-Options: nosniff\r\n"
    b"Retry-After: 1\r\n"
)


def envelope_from_dict(value: dict[str, Any]) -> AgentEnvelope:
    if not isinstance(value, dict):
        raise A2ARequestError(-32602, "invalid params")
    try:
        manifest_value = value["manifest"]
        permit_value = value["permit"]
        if not isinstance(manifest_value, dict) or not isinstance(permit_value, dict):
            raise TypeError("envelope manifest and permit must be objects")
        manifest = AgentManifest(**{**manifest_value, "requested_tools": tuple(manifest_value["requested_tools"])})
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
            previous_audit_sequence=int(value.get("previous_audit_sequence", 0)),
            previous_audit_host_id=value.get("previous_audit_host_id", ""),
            previous_audit_signature_key_id=value.get("previous_audit_signature_key_id", ""),
            previous_audit_signature=value.get("previous_audit_signature", ""),
            signature_key_id=value.get("signature_key_id", ""),
            signature=value["signature"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise A2ARequestError(-32602, "invalid params") from exc


@dataclass(frozen=True)
class A2AAuthConfig:
    bearer_token: str | None = None
    realm: str = "portmark"

    @property
    def required(self) -> bool:
        return bool(self.bearer_token)


class RateLimiter:
    def __init__(
        self,
        limit_per_ip: int,
        window_seconds: int,
        max_tracked_clients: int = DEFAULT_RATE_LIMIT_TRACKED_CLIENTS,
    ):
        if limit_per_ip < 1:
            raise ValueError("limit_per_ip must be at least 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")
        if max_tracked_clients < 1:
            raise ValueError("max_tracked_clients must be at least 1")
        self._limit_per_ip = limit_per_ip
        self._window_seconds = window_seconds
        self._max_tracked_clients = max_tracked_clients
        self._lock = threading.Lock()
        self._requests_by_ip: dict[str, deque[float]] = {}

    def admit(self, client_ip: str) -> bool:
        now = time.monotonic()
        cutoff = now - self._window_seconds
        with self._lock:
            if client_ip not in self._requests_by_ip and len(self._requests_by_ip) >= self._max_tracked_clients:
                self._requests_by_ip.pop(next(iter(self._requests_by_ip)))
            requests = self._requests_by_ip.setdefault(client_ip, deque())
            while requests and requests[0] <= cutoff:
                requests.popleft()
            if len(requests) >= self._limit_per_ip:
                return False
            requests.append(now)
            return True


class NetworkGuard:
    def __init__(
        self,
        max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
        rate_limit_per_ip: int = DEFAULT_RATE_LIMIT_PER_IP,
        rate_limit_window_seconds: int = DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
    ):
        if max_concurrent_requests < 1:
            raise ValueError("max_concurrent_requests must be at least 1")
        self._concurrency = threading.BoundedSemaphore(max_concurrent_requests)
        self._rate_limiter = RateLimiter(rate_limit_per_ip, rate_limit_window_seconds)

    @contextmanager
    def admit(self, client_ip: str) -> Iterator[tuple[int, int, str] | None]:
        if not self._concurrency.acquire(blocking=False):
            yield (503, -32003, "server busy")
            return
        try:
            if not self._rate_limiter.admit(client_ip):
                yield (429, -32002, "rate limit exceeded")
                return
            yield None
        finally:
            self._concurrency.release()


class BoundedReferenceHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, max_connections: int = DEFAULT_MAX_CONCURRENT_REQUESTS):
        if max_connections < 1:
            raise ValueError("max_connections must be at least 1")
        self._connection_slots = threading.BoundedSemaphore(max_connections)
        super().__init__(server_address, RequestHandlerClass)

    def process_request(self, request, client_address) -> None:
        if not self._connection_slots.acquire(blocking=False):
            self._reject_busy(request)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()

    def _reject_busy(self, request) -> None:
        payload = json.dumps(error_response(None, -32003, "server busy")).encode()
        try:
            request.sendall(BUSY_RESPONSE + f"Content-Length: {len(payload)}\r\n\r\n".encode() + payload)
        except OSError:
            logger.debug("failed to write busy response", exc_info=True)


def make_handler(
    host: AgentHost,
    auth: A2AAuthConfig | None = None,
    enable_hsts: bool = False,
    max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
    rate_limit_per_ip: int = DEFAULT_RATE_LIMIT_PER_IP,
    rate_limit_window_seconds: int = DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
    agent_card_rate_limit_per_ip: int = DEFAULT_AGENT_CARD_RATE_LIMIT_PER_IP,
    agent_card_rate_limit_window_seconds: int = DEFAULT_AGENT_CARD_RATE_LIMIT_WINDOW_SECONDS,
    a2a_adapter: str = "local",
):
    if a2a_adapter not in A2A_ADAPTERS:
        raise ValueError("a2a_adapter must be 'local' or 'sdk'")
    if a2a_adapter == "sdk":
        make_sdk_agent_card("http://127.0.0.1", False)
    auth_config = auth or A2AAuthConfig()
    network_guard = NetworkGuard(max_concurrent_requests, rate_limit_per_ip, rate_limit_window_seconds)
    agent_card_limiter = RateLimiter(agent_card_rate_limit_per_ip, agent_card_rate_limit_window_seconds)
    metrics_limiter = RateLimiter(rate_limit_per_ip, rate_limit_window_seconds)

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
                if not agent_card_limiter.admit(self._client_ip()):
                    self._json(
                        429,
                        error_response(None, -32002, "rate limit exceeded"),
                        {"Retry-After": str(agent_card_rate_limit_window_seconds)},
                    )
                    return
                if a2a_adapter == "sdk":
                    self._json(200, make_sdk_agent_card(self._base_url(), auth_config.required))
                    return
                self._json(200, make_agent_card(self._base_url(), auth_config.required))
            elif self.path == "/metrics":
                if not metrics_limiter.admit(self._client_ip()):
                    self._json(
                        429,
                        error_response(None, -32002, "rate limit exceeded"),
                        {"Retry-After": str(rate_limit_window_seconds)},
                    )
                    return
                if not auth_config.required or not self._authorized(auth_config):
                    self._json(
                        401,
                        error_response(None, -32001, "unauthorized"),
                        {"WWW-Authenticate": f'Bearer realm="{auth_config.realm}"'},
                    )
                    return
                self._json(200, host.metrics.snapshot())
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path != "/message:send":
                self._json(404, error_response(None, -32601, "method not found"))
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
                with network_guard.admit(self._client_ip()) as rejection:
                    if rejection is not None:
                        status, code, message = rejection
                        self._json(status, error_response(None, code, message), {"Retry-After": str(rate_limit_window_seconds)})
                        return
                    if not self._authorized(auth_config):
                        self._json(
                            401,
                            error_response(None, -32001, "unauthorized"),
                            {"WWW-Authenticate": f'Bearer realm="{auth_config.realm}"'},
                        )
                        return
                    try:
                        payload = json.loads(self.rfile.read(size))
                    except json.JSONDecodeError as exc:
                        raise A2ARequestError(-32700, "parse error", 400) from exc
                    if a2a_adapter == "sdk":
                        try:
                            validate_sdk_message_send_params(payload.get("params"))
                        except Exception as exc:
                            raise A2ARequestError(-32602, "invalid params") from exc
                    request = parse_jsonrpc_request(payload)
                    request_id = request.id
                    envelope = envelope_from_dict(request.params.portmark_envelope)
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

        def _client_ip(self) -> str:
            if isinstance(self.client_address, tuple) and self.client_address:
                return str(self.client_address[0])
            return "unknown"

        def log_message(self, format: str, *args: Any) -> None:
            return

    return A2AHandler


def auth_from_environment() -> A2AAuthConfig:
    return A2AAuthConfig(os.environ.get("PORTMARK_A2A_TOKEN"))


def is_loopback_bind(bind: str) -> bool:
    if bind == "localhost":
        return True
    try:
        return ipaddress.ip_address(bind).is_loopback
    except ValueError:
        return False


def serve(
    host: AgentHost,
    bind: str,
    port: int,
    auth: A2AAuthConfig | None = None,
    enable_hsts: bool = False,
    max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
    rate_limit_per_ip: int = DEFAULT_RATE_LIMIT_PER_IP,
    rate_limit_window_seconds: int = DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
    agent_card_rate_limit_per_ip: int = DEFAULT_AGENT_CARD_RATE_LIMIT_PER_IP,
    agent_card_rate_limit_window_seconds: int = DEFAULT_AGENT_CARD_RATE_LIMIT_WINDOW_SECONDS,
    allow_direct_a2a: bool = False,
    a2a_adapter: str = "local",
) -> None:
    if not is_loopback_bind(bind):
        raise ValueError(
            "A2A reference server must bind to loopback and be fronted by a production reverse proxy for public exposure"
        )
    BoundedReferenceHTTPServer(
        (bind, port),
        make_handler(
            host,
            auth or auth_from_environment(),
            enable_hsts,
            max_concurrent_requests,
            rate_limit_per_ip,
            rate_limit_window_seconds,
            agent_card_rate_limit_per_ip,
            agent_card_rate_limit_window_seconds,
            a2a_adapter,
        ),
        max_connections=max_concurrent_requests,
    ).serve_forever()

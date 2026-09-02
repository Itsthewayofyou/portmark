from __future__ import annotations

import asyncio
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
from collections.abc import Callable
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
DEFAULT_READY_CACHE_SECONDS = 2.0
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



SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
}


def parse_content_length(raw: str) -> int:
    """Bounds-check Content-Length before any body is read.

    Rejecting on the header alone is the DoS property: an oversized request must
    never cause the body to be read. Shared by every transport so the check
    cannot drift between them.
    """
    try:
        size = int(raw or "0")
    except ValueError as exc:
        raise A2ARequestError(-32600, "invalid request", 400) from exc
    if size <= 0 or size > MAX_REQUEST_BYTES:
        raise A2ARequestError(-32600, "invalid request", 413)
    return size


def accepts_plain_text(raw: str) -> bool:
    for item in raw.split(","):
        media_type = item.split(";", 1)[0].strip().lower()
        if media_type == "text/plain":
            return True
    return False


def refusal_reason_for_error(code: int, status: int | None = None) -> str:
    if status == 429 or code == -32002:
        return "rate_limited"
    if status == 503 or code == -32003:
        return "server_busy"
    if code == -32700:
        return "parse_error"
    if code == -32602:
        return "invalid_params"
    if code == -32601:
        return "method_not_found"
    if code == -32600:
        return "invalid_request"
    if code == -32001:
        return "unauthorized"
    return "internal"


@dataclass(frozen=True)
class HttpResponse:
    status: int
    payload: bytes
    headers: dict[str, str]


class A2ARouter:
    """Transport-neutral A2A request handling.

    Owns the mutable limiter state. One router per server; every transport that
    wraps it shares these instances, so limits apply across the whole server
    rather than per request.
    """

    def __init__(
        self,
        host: AgentHost,
        auth: A2AAuthConfig | None = None,
        enable_hsts: bool = False,
        max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
        rate_limit_per_ip: int = DEFAULT_RATE_LIMIT_PER_IP,
        rate_limit_window_seconds: int = DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
        agent_card_rate_limit_per_ip: int = DEFAULT_AGENT_CARD_RATE_LIMIT_PER_IP,
        agent_card_rate_limit_window_seconds: int = DEFAULT_AGENT_CARD_RATE_LIMIT_WINDOW_SECONDS,
        a2a_adapter: str = "local",
        readiness_check: Callable[[], None] | None = None,
        readiness_cache_seconds: float = DEFAULT_READY_CACHE_SECONDS,
    ) -> None:
        if a2a_adapter not in A2A_ADAPTERS:
            raise ValueError("a2a_adapter must be 'local' or 'sdk'")
        if readiness_cache_seconds < 0:
            raise ValueError("readiness_cache_seconds must not be negative")
        if a2a_adapter == "sdk":
            make_sdk_agent_card("http://127.0.0.1", False)
        self.host = host
        self.auth_config = auth or A2AAuthConfig()
        self.enable_hsts = enable_hsts
        self.a2a_adapter = a2a_adapter
        self.rate_limit_window_seconds = rate_limit_window_seconds
        self.agent_card_rate_limit_window_seconds = agent_card_rate_limit_window_seconds
        self.network_guard = NetworkGuard(max_concurrent_requests, rate_limit_per_ip, rate_limit_window_seconds)
        self.agent_card_limiter = RateLimiter(agent_card_rate_limit_per_ip, agent_card_rate_limit_window_seconds)
        self.metrics_limiter = RateLimiter(rate_limit_per_ip, rate_limit_window_seconds)
        self.readiness_check = readiness_check or (lambda: default_readiness_check(host))
        self.readiness_cache_seconds = readiness_cache_seconds
        self._readiness_lock = threading.Lock()
        self._readiness_cached_until = 0.0
        self._readiness_cached = False
        self._cleartext_lock = threading.Lock()
        self._cleartext_warned = False

    def note_forwarded_proto(self, forwarded_proto: str) -> None:
        """Warn once when a proxy forwarded a request over plain HTTP.

        An `X-Forwarded-Proto` of anything other than https is positive proof the
        upstream proxy did not terminate TLS — stronger than the startup check,
        which can only observe whether HSTS was enabled. Fires once to avoid
        per-request log noise.
        """
        proto = forwarded_proto.split(",", 1)[0].strip().lower()
        if not proto or proto == "https":
            return
        with self._cleartext_lock:
            if self._cleartext_warned:
                return
            self._cleartext_warned = True
        logger.warning(
            "PROVEN cleartext: a request arrived with X-Forwarded-Proto=%r, so the "
            "upstream proxy is NOT terminating TLS. Envelopes are signed but readable "
            "in transit. Terminate HTTPS at the proxy. (Logged once.)",
            proto,
        )

    def response(self, status: int, value: Any, headers: dict[str, str] | None = None) -> HttpResponse:
        payload = json.dumps(value).encode()
        out = {
            "Content-Type": "application/json",
            "Content-Length": str(len(payload)),
            **SECURITY_HEADERS,
        }
        if self.enable_hsts:
            out["Strict-Transport-Security"] = "max-age=31536000"
        if headers:
            out.update(headers)
        return HttpResponse(status, payload, out)

    def text_response(self, status: int, payload: str, content_type: str) -> HttpResponse:
        encoded = payload.encode()
        headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(encoded)),
            **SECURITY_HEADERS,
        }
        if self.enable_hsts:
            headers["Strict-Transport-Security"] = "max-age=31536000"
        return HttpResponse(status, encoded, headers)

    def authorized(self, authorization: str) -> bool:
        if not self.auth_config.bearer_token:
            return True
        prefix = "Bearer "
        if not authorization.startswith(prefix):
            return False
        return secrets.compare_digest(authorization[len(prefix):], self.auth_config.bearer_token)

    def _unauthorized(self) -> HttpResponse:
        return self.response(
            401,
            error_response(None, -32001, "unauthorized"),
            {"WWW-Authenticate": f'Bearer realm="{self.auth_config.realm}"'},
        )

    def handle_get(
        self,
        path: str,
        host_header: str,
        client_ip: str,
        authorization: str = "",
        accept: str = "",
    ) -> HttpResponse:
        base_url = f"http://{host_header or '127.0.0.1'}"
        if path == "/healthz":
            return self.response(200, {"status": "ok"})
        if path == "/readyz":
            if self.ready():
                return self.response(200, {"status": "ready"})
            self.host.metrics.increment_refusal("not_ready")
            return self.response(503, {"status": "not_ready"})
        if path == "/.well-known/agent-card.json":
            if not self.agent_card_limiter.admit(client_ip):
                self.host.metrics.increment_refusal("rate_limited")
                return self.response(
                    429,
                    error_response(None, -32002, "rate limit exceeded"),
                    {"Retry-After": str(self.agent_card_rate_limit_window_seconds)},
                )
            if self.a2a_adapter == "sdk":
                return self.response(200, make_sdk_agent_card(base_url, self.auth_config.required))
            return self.response(200, make_agent_card(base_url, self.auth_config.required))
        if path == "/metrics":
            if not self.metrics_limiter.admit(client_ip):
                self.host.metrics.increment_refusal("rate_limited")
                return self.response(
                    429,
                    error_response(None, -32002, "rate limit exceeded"),
                    {"Retry-After": str(self.rate_limit_window_seconds)},
                )
            if not self.auth_config.required or not self.authorized(authorization):
                self.host.metrics.increment_refusal("unauthorized")
                return self._unauthorized()
            if accepts_plain_text(accept):
                return self.text_response(
                    200,
                    self.host.metrics.prometheus_text(),
                    "text/plain; version=0.0.4; charset=utf-8",
                )
            return self.response(200, self.host.metrics.snapshot())
        return self.response(404, {"error": "not found"})

    def ready(self) -> bool:
        now = time.monotonic()
        with self._readiness_lock:
            if self._readiness_cached_until > now:
                return self._readiness_cached
            try:
                self.readiness_check()
            except Exception:
                logger.exception("A2A readiness check failed")
                self._readiness_cached = False
            else:
                self._readiness_cached = True
            self._readiness_cached_until = now + self.readiness_cache_seconds
            return self._readiness_cached

    @contextmanager
    def admit_post(
        self,
        path: str,
        content_type: str,
        content_length: str,
        authorization: str,
        client_ip: str,
    ) -> Iterator[tuple[HttpResponse | None, int]]:
        """Validate and admit a submission *before* its body is read.

        Yields (rejection, size). When rejection is None the caller may read
        exactly `size` bytes and pass them to dispatch_post. The concurrency slot
        is held for the whole block, so the body read happens inside the guard on
        every transport — a rate-limited or over-capacity client never causes a
        body to be buffered.
        """
        try:
            if path != "/message:send":
                self.host.metrics.increment_refusal("method_not_found")
                yield self.response(404, error_response(None, -32601, "method not found")), 0
                return
            if content_type.split(";", 1)[0].strip().lower() != "application/json":
                raise A2ARequestError(-32600, "invalid request", 415)
            size = parse_content_length(content_length)
        except A2ARequestError as exc:
            self.host.metrics.increment_refusal(refusal_reason_for_error(exc.code, exc.http_status))
            yield self.response(exc.http_status, error_response(None, exc.code, exc.message)), 0
            return
        with self.network_guard.admit(client_ip) as rejection:
            if rejection is not None:
                status, code, message = rejection
                self.host.metrics.increment_refusal(refusal_reason_for_error(code, status))
                yield self.response(
                    status,
                    error_response(None, code, message),
                    {"Retry-After": str(self.rate_limit_window_seconds)},
                ), 0
                return
            if not self.authorized(authorization):
                self.host.metrics.increment_refusal("unauthorized")
                yield self._unauthorized(), 0
                return
            yield None, size

    def dispatch_post(self, body: bytes) -> HttpResponse:
        """Parse an admitted submission and run it. Called inside admit_post."""
        request_id: str | int | None = None
        try:
            try:
                payload = json.loads(body)
            except json.JSONDecodeError as exc:
                raise A2ARequestError(-32700, "parse error", 400) from exc
            if self.a2a_adapter == "sdk":
                try:
                    validate_sdk_message_send_params(payload.get("params"))
                except Exception as exc:
                    raise A2ARequestError(-32602, "invalid params") from exc
            request = parse_jsonrpc_request(payload)
            request_id = request.id
            envelope = envelope_from_dict(request.params.portmark_envelope)
            result = self.host.run(envelope)
            return self.response(200, success_response(request.id, task_from_run_result(result)))
        except A2ARequestError as exc:
            self.host.metrics.increment_refusal(refusal_reason_for_error(exc.code, exc.http_status))
            return self.response(exc.http_status, error_response(exc.request_id, exc.code, exc.message))
        except Exception:
            self.host.metrics.increment_refusal("internal")
            logger.exception("A2A message submission failed")
            return self.response(400, error_response(request_id, -32000, "message submission failed"))


def make_handler(host: AgentHost, auth: A2AAuthConfig | None = None, enable_hsts: bool = False, **kwargs: Any):
    """BaseHTTPRequestHandler transport over A2ARouter.

    Retained for tests and local development. Production serving uses the ASGI
    application; both share the router above, so the security logic has one
    implementation.
    """
    router = A2ARouter(host, auth, enable_hsts, **kwargs)

    class A2AHandler(BaseHTTPRequestHandler):
        server_version = "PortableAgentA2A/1.0"
        a2a_router = router

        def _send(self, response: HttpResponse) -> None:
            self.send_response(response.status)
            for key, value in response.headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(response.payload)

        def _client_ip(self) -> str:
            if isinstance(self.client_address, tuple) and self.client_address:
                return str(self.client_address[0])
            return "unknown"

        def do_GET(self) -> None:
            self._send(router.handle_get(
                self.path,
                self.headers.get("Host", "127.0.0.1"),
                self._client_ip(),
                self.headers.get("Authorization", ""),
                self.headers.get("Accept", ""),
            ))

        def do_POST(self) -> None:
            started = time.monotonic()
            router.note_forwarded_proto(self.headers.get("X-Forwarded-Proto", ""))
            try:
                with router.admit_post(
                    self.path,
                    self.headers.get("Content-Type", ""),
                    self.headers.get("Content-Length", "0"),
                    self.headers.get("Authorization", ""),
                    self._client_ip(),
                ) as (rejection, size):
                    if rejection is not None:
                        self._send(rejection)
                        return
                    self._send(router.dispatch_post(self.rfile.read(size)))
            finally:
                router.host.metrics.observe_duration("a2a_request_duration_seconds", time.monotonic() - started)

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


def default_readiness_check(host: AgentHost) -> None:
    active_policy = host._active_policy()
    if active_policy.audience != host.host_id:
        raise RuntimeError("policy audience does not match host")
    host.store.consumed_nonce_exists("__portmark_readyz__")
    verifier = getattr(host.signer, "registry", None)
    key_id = getattr(host.signer, "key_id", None)
    if verifier is not None and key_id is not None and not verifier.has_key(key_id):
        raise RuntimeError("host signing key is not trusted")


def make_asgi_app(host: AgentHost, auth: A2AAuthConfig | None = None, enable_hsts: bool = False, **kwargs: Any):
    """ASGI application over A2ARouter.

    Shares one router instance across every request, so the rate limiters and the
    concurrency guard are server-wide rather than per request.

    Transport note: ASGI delivers the body through `receive()`, so the body is
    buffered after the Content-Length bounds check and before the router runs.
    An oversized request is still rejected without its body being read, which is
    the DoS property. A request within the limit has at most MAX_REQUEST_BYTES
    buffered before per-IP rate limiting applies; uvicorn's own concurrency limit
    is the outer bound.
    """
    router = A2ARouter(host, auth, enable_hsts, **kwargs)

    def _header(scope: dict[str, Any], name: bytes) -> str:
        for key, value in scope.get("headers", ()):
            if key.lower() == name:
                return value.decode("latin-1")
        return ""

    def _client_ip(scope: dict[str, Any]) -> str:
        client = scope.get("client")
        if isinstance(client, (tuple, list)) and client:
            return str(client[0])
        return "unknown"

    async def _send(send, response: HttpResponse) -> None:
        await send({
            "type": "http.response.start",
            "status": response.status,
            "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in response.headers.items()],
        })
        await send({"type": "http.response.body", "body": response.payload})

    async def app(scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
            return
        if scope["type"] != "http":
            return
        path, method = scope.get("path", ""), scope.get("method", "GET").upper()
        client_ip = _client_ip(scope)
        if method == "GET":
            response = router.handle_get(
                path,
                _header(scope, b"host"),
                client_ip,
                _header(scope, b"authorization"),
                _header(scope, b"accept"),
            )
            await _send(send, response)
            return
        if method != "POST":
            await _send(send, router.response(404, {"error": "not found"}))
            return

        router.note_forwarded_proto(_header(scope, b"x-forwarded-proto"))
        started = time.monotonic()
        try:
            raw_length = _header(scope, b"content-length")
            content_type = _header(scope, b"content-type")
            with router.admit_post(path, content_type, raw_length, _header(scope, b"authorization"), client_ip) as (
                rejection,
                size,
            ):
                if rejection is not None:
                    await _send(send, rejection)
                    return
                body = bytearray()
                while len(body) < size:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    body.extend(message.get("body", b""))
                    if len(body) > MAX_REQUEST_BYTES:
                        router.host.metrics.increment_refusal("invalid_request")
                        await _send(send, router.response(413, error_response(None, -32600, "invalid request")))
                        return
                    if not message.get("more_body", False):
                        break
                response = router.dispatch_post(bytes(body))
            await _send(send, response)
        finally:
            router.host.metrics.observe_duration("a2a_request_duration_seconds", time.monotonic() - started)

    app.a2a_router = router  # type: ignore[attr-defined]
    return app


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
    """Serve the A2A boundary on uvicorn.

    The loopback restriction is retained deliberately and is not overridable by
    `allow_direct_a2a`. Moving to a production ASGI server removes the
    slow-client thread exhaustion of http.server; it is not on its own a
    decision to expose the reference host publicly.
    """
    if not is_loopback_bind(bind):
        raise ValueError(
            "A2A reference server must bind to loopback and be fronted by a production reverse proxy for public exposure"
        )
    if not enable_hsts:
        logger.warning(
            "TLS NOT asserted: --enable-hsts is off, so the upstream reverse proxy is "
            "not confirmed to terminate HTTPS. Envelopes are SIGNED (tamper- and "
            "replay-proof) but NOT encrypted in transit — anyone who intercepts a "
            "request can READ its contents. Terminate TLS at the proxy and pass "
            "--enable-hsts before public exposure. See THREAT_MODEL.md."
        )
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - exercised by packaging, not unit tests
        raise RuntimeError("serving the A2A boundary requires uvicorn; install portmark with its default dependencies") from exc

    app = make_asgi_app(
        host,
        auth or auth_from_environment(),
        enable_hsts,
        max_concurrent_requests=max_concurrent_requests,
        rate_limit_per_ip=rate_limit_per_ip,
        rate_limit_window_seconds=rate_limit_window_seconds,
        agent_card_rate_limit_per_ip=agent_card_rate_limit_per_ip,
        agent_card_rate_limit_window_seconds=agent_card_rate_limit_window_seconds,
        a2a_adapter=a2a_adapter,
    )
    uvicorn.run(
        app,
        host=bind,
        port=port,
        log_level="warning",
        limit_concurrency=max_concurrent_requests,
        timeout_keep_alive=5,
        access_log=False,
    )

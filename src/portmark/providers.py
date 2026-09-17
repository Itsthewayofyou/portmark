from __future__ import annotations

import http.client
import json
import hashlib
import base64
import ipaddress
import os
import shutil
import socket
import ssl
import subprocess  # nosec B404
import sys
import time
from urllib.parse import urlparse
from abc import ABC, abstractmethod
from typing import Any

from .component_bindings import component_checkpoint, component_context, decode_component_decision, encode_component_input
from .models import AgentState, ProviderDecision, ToolGrant
from .projection import provider_state
from .security import SecurityError

DEFAULT_MAX_WASM_COMPONENT_BYTES = 10_000_000
# CPU (instruction) and memory ceilings for a native Wasmtime guest. A legitimate
# single decision consumes tens of fuel units and a small memory; these leave huge
# headroom while trapping a runaway loop or memory.grow. See finding #6.
DEFAULT_WASM_FUEL = 1_000_000_000
DEFAULT_WASM_MEMORY_BYTES = 256 * 1024 * 1024

# Finding #6: the native Wasmtime provider launches a child Python that imports the
# arch-specific `wasmtime` wheel. Passing env={PYTHONPATH only} stripped SYSTEMROOT,
# PATH and the Windows process/arch vars the C runtime and the wheel read at import, so
# the child failed to start on Windows. Forward a fixed allowlist of non-secret OS vars
# instead -- the tool runner's set (see tools._INHERITED_ENV_KEYS: PYTHONPATH, PATH,
# locale, SYSTEMROOT) plus the Windows process/arch vars a native extension needs. No
# credential-shaped variable is forwarded, so this does not widen the trust boundary.
_WASMTIME_SUBPROCESS_ENV_KEYS = (
    "PYTHONPATH", "PATH", "LANG", "LC_ALL", "LC_CTYPE",
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT",
    "PROCESSOR_ARCHITECTURE", "PROCESSOR_ARCHITEW6432", "NUMBER_OF_PROCESSORS",
    "TEMP", "TMP",
)


def _wasmtime_subprocess_env() -> dict[str, str]:
    return {key: os.environ[key] for key in _WASMTIME_SUBPROCESS_ENV_KEYS if key in os.environ}


class ModelProvider(ABC):
    @abstractmethod
    def decide(self, state: AgentState, available_tools: tuple[str, ...], grants: tuple[ToolGrant, ...] = ()) -> ProviderDecision:
        """Return a proposal. The host remains responsible for authorization and execution."""


class DeterministicProvider(ModelProvider):
    """Offline provider used for tests and the demo."""

    def decide(self, state: AgentState, available_tools: tuple[str, ...], grants: tuple[ToolGrant, ...] = ()) -> ProviderDecision:
        results = state.memory.get("tool_results", {})
        if not results.get("catalog.search") and "catalog.search" in available_tools:
            return ProviderDecision("tool", "catalog.search", {"query": state.goal, "limit": 3})
        return ProviderDecision(
            "complete",
            content={"summary": f"Completed: {state.goal}", "evidence": results.get("catalog.search", [])},
        )


class ProviderError(Exception):
    """A controlled provider transport/response failure (Section 8, findings 1 + 3): a refused
    redirect, a disallowed address, a DNS-rebinding mismatch, a total-deadline timeout, a premature
    EOF/reset, or a non-200 status. Distinct from a bug -- but the host persists a durable `failed`
    checkpoint on ANY decide() failure, so an admitted task is never left only as `running`."""


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to a pre-validated IP while validating the TLS certificate against the ORIGINAL
    hostname (server_hostname). Connecting to the literal we already classified -- not re-resolving
    the hostname at connect time -- is the DNS-rebinding defense; the cert check stays on the name."""

    def __init__(self, ip: str, port: int, hostname: str, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(ip, port, timeout=timeout, context=context)
        self._pin_hostname = hostname
        self._ssl_context = context

    def connect(self) -> None:
        http.client.HTTPConnection.connect(self)  # TCP-connect to self.host, which is the pinned IP
        self.sock = self._ssl_context.wrap_socket(self.sock, server_hostname=self._pin_hostname)


def _classify_address(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    # Normalize an IPv4-mapped IPv6 address (::ffff:127.0.0.1) to its IPv4 form BEFORE classifying --
    # otherwise the mapped form sidesteps is_loopback/is_private (the classic SSRF bypass).
    address = ipaddress.ip_address(ip_str)
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address


def _address_is_disallowed(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        address.is_loopback or address.is_private or address.is_link_local
        or address.is_multicast or address.is_reserved or address.is_unspecified
    )


class GenericHttpProvider(ModelProvider):
    """Provider-neutral JSON adapter for a local or remote model gateway.

    Section 8 hardening (findings 1 + 3): no automatic redirects, SSRF address validation with a
    DNS-rebinding pin, a total end-to-end deadline, and a bounded streaming read. Runs directly on
    http.client so the transport -- connect target, TLS server_hostname, Host header, per-read
    timeout, redirect handling -- is under our control rather than urllib's default opener.
    """

    def __init__(
        self, endpoint: str, bearer_token: str | None = None, timeout: float = 30.0,
        max_response_bytes: int = 65_536, allow_local_endpoint: bool = False,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("provider endpoint must use http or https")
        if parsed.username or parsed.password:
            raise ValueError("provider endpoint must not contain credentials")
        if parsed.fragment:
            raise ValueError("provider endpoint must not contain a fragment")
        host = parsed.hostname
        if not host or any(character in host for character in "/\\?#@ \t\r\n"):
            raise ValueError("provider endpoint host is missing or malformed")
        self.endpoint = endpoint
        self._scheme = parsed.scheme
        self._host = host
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        self._path = path + (f"?{parsed.query}" if parsed.query else "")
        default_port = self._port == (443 if parsed.scheme == "https" else 80)
        self._host_header = host if default_port else f"{host}:{self._port}"
        self.bearer_token = bearer_token
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self._allow_local = allow_local_endpoint

    def decide(self, state: AgentState, available_tools: tuple[str, ...], grants: tuple[ToolGrant, ...] = ()) -> ProviderDecision:
        body = json.dumps({"state": provider_state(state, grants), "available_tools": available_tools}).encode()
        raw = self._post(body)
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise SecurityError("provider response is malformed JSON") from error
        return _provider_decision(value)

    # ---- Section 8 transport -------------------------------------------------------------------

    def _resolve(self) -> list[tuple[int, str]]:
        # A literal-IP endpoint is classified directly (no resolution). A hostname is resolved ONCE,
        # and every A/AAAA answer is returned so the caller can reject a mixed public+private answer.
        try:
            literal = ipaddress.ip_address(self._host)
            return [(socket.AF_INET6 if literal.version == 6 else socket.AF_INET, str(literal))]
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(self._host, self._port, type=socket.SOCK_STREAM)
        except socket.gaierror as error:
            raise ProviderError(f"provider endpoint did not resolve: {error}") from error
        answers = [(family, sockaddr[0]) for family, _t, _p, _c, sockaddr in infos
                   if family in (socket.AF_INET, socket.AF_INET6)]
        if not answers:
            raise ProviderError("provider endpoint resolved to no usable address")
        return answers

    def _validated_target(self) -> tuple[int, str]:
        answers = self._resolve()
        # Fail closed on ANY disallowed answer (a mixed public+loopback response must not proceed on
        # the public one), unless it is loopback AND the operator opted into a local provider.
        for _family, ip in answers:
            address = _classify_address(ip)
            if _address_is_disallowed(address) and not (address.is_loopback and self._allow_local):
                raise ProviderError(f"provider endpoint address is not permitted: {ip}")
        family, ip = answers[0]
        effective = _classify_address(ip)
        if not effective.is_loopback and self._scheme != "https":
            raise ProviderError("provider endpoint must use https unless it is a loopback address")
        return family, ip

    def _open_connection(self, ip: str, deadline: float) -> http.client.HTTPConnection:
        # https connects through the pinned-IP + hostname-cert connection. Plain http skips the pin,
        # but _validated_target permits http ONLY for a loopback address, so the http branch is
        # loopback-only by construction -- a remote endpoint must be https and takes the pinned path.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProviderError("provider deadline exceeded before connect")
        if self._scheme == "https":
            connection: http.client.HTTPConnection = _PinnedHTTPSConnection(
                ip, self._port, self._host, remaining, ssl.create_default_context()
            )
        else:
            connection = http.client.HTTPConnection(ip, self._port, timeout=remaining)
        connection.connect()
        return connection

    def _post(self, body: bytes) -> bytes:
        deadline = time.monotonic() + self.timeout
        _family, ip = self._validated_target()
        try:
            connection = self._open_connection(ip, deadline)
        except (OSError, ssl.SSLError) as error:
            raise ProviderError(f"provider connection failed: {error}") from error
        try:
            # DNS-rebinding backstop: confirm the socket really connected to the address we validated.
            # connection.sock is valid here (before getresponse, which may release it for a close).
            if connection.sock is None:
                raise ProviderError("provider connection has no socket")
            if _classify_address(connection.sock.getpeername()[0]) != _classify_address(ip):
                raise ProviderError("connected peer does not match the validated address")
            return self._exchange(connection, body, deadline)
        finally:
            connection.close()

    def _exchange(self, connection: http.client.HTTPConnection, body: bytes, deadline: float) -> bytes:
        try:
            # skip_host so we set Host ourselves (the hostname, not the pinned IP the socket is on).
            connection.putrequest("POST", self._path, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", self._host_header)
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(len(body)))
            if self.bearer_token:
                connection.putheader("Authorization", f"Bearer {self.bearer_token}")
            self._check_deadline(deadline)
            connection.endheaders(body)
            self._check_deadline(deadline)
            response = connection.getresponse()
        except (OSError, http.client.HTTPException) as error:
            raise ProviderError(f"provider request failed: {error}") from error
        # A redirect is NOT followed -- it is a controlled failure (SSRF vector + would forward the
        # bearer token cross-origin). Any non-200 is likewise a provider failure.
        if 300 <= response.status < 400:
            raise ProviderError(f"provider returned an unfollowed redirect (HTTP {response.status})")
        if response.status != 200:
            raise ProviderError(f"provider returned HTTP {response.status}")
        return self._read_bounded(response, deadline)

    def _read_bounded(self, response: http.client.HTTPResponse, deadline: float) -> bytes:
        # Bound the body DURING the read (never buffer unbounded) and enforce the total deadline. The
        # socket carries a connect-time timeout (set from the remaining budget in _open_connection),
        # which bounds a TOTAL stall (a read that gets no data). read1() returns whatever one recv
        # yields, so a slow-drip is re-checked against the wall clock between chunks and aborted on the
        # end-to-end deadline rather than trickling to completion (finding #3).
        limit = self.max_response_bytes
        buffer = bytearray()
        while len(buffer) <= limit:
            self._check_deadline(deadline)
            try:
                # read1(), not read(): read(amt) blocks until it has accumulated the full amt (or the
                # Content-Length is met), so a slow-drip that trickles within the idle socket timeout
                # keeps a single read() blocked for the whole body and defeats the deadline. read1()
                # returns whatever one underlying recv yields, so the deadline is re-checked between
                # chunks and a drip is aborted on the total clock (finding #3).
                chunk = response.read1(min(65_536, limit + 1 - len(buffer)))
            except (OSError, http.client.HTTPException) as error:
                raise ProviderError(f"provider response read failed: {error}") from error
            if not chunk:
                # EOF. If the framing promised more (Content-Length not fully delivered), the body was
                # truncated -- a controlled provider failure, not a valid short response (finding #3).
                if getattr(response, "length", None):
                    raise ProviderError("provider response ended prematurely")
                return bytes(buffer)
            buffer.extend(chunk)
            if len(buffer) > limit:
                raise SecurityError("provider response exceeds output limit")
        raise SecurityError("provider response exceeds output limit")

    def _check_deadline(self, deadline: float) -> None:
        # Wall-clock check of the total end-to-end deadline (independent of the socket idle timeout,
        # which a slow-drip can beat). Called between read1() chunks so a trickling response is aborted.
        if deadline - time.monotonic() <= 0:
            raise ProviderError("provider deadline exceeded")


def _provider_decision(value: Any) -> ProviderDecision:
    if not isinstance(value, dict):
        raise SecurityError("provider response must be a JSON object")
    kind = value.get("kind")
    if kind == "tool":
        tool = value.get("tool")
        if not isinstance(tool, str) or not tool:
            raise SecurityError("provider tool decision has an invalid tool name")
        arguments = value.get("arguments", {})
        if not isinstance(arguments, dict):
            raise SecurityError("provider tool decision arguments must be a JSON object")
        return ProviderDecision("tool", tool=tool, arguments=arguments, content=value.get("content"), destination=value.get("destination"))
    if kind in {"complete", "await_input", "fail"}:
        return ProviderDecision(kind, content=value.get("content"))
    if kind == "migrate":
        destination = value.get("destination")
        if not isinstance(destination, str) or not destination:
            raise SecurityError("provider migration decision has an invalid destination")
        content = value.get("content")
        if content is not None and not isinstance(content, dict):
            raise SecurityError("provider migration decision content must be a JSON object")
        return ProviderDecision("migrate", content=content, destination=destination)
    raise SecurityError("provider response kind is not supported")


def _read_component_file(path: str, max_component_bytes: int) -> bytes:
    if max_component_bytes < 1:
        raise ValueError("max_component_bytes must be at least 1")
    read_limit = max_component_bytes + 1
    if path.endswith(".b64"):
        read_limit = max_component_bytes * 2 + 1
    with open(path, "rb") as file:
        component = file.read(read_limit)
    if len(component) >= read_limit:
        raise RuntimeError("Wasm component exceeds input limit")
    if path.endswith(".b64"):
        component = base64.b64decode(component.strip(), validate=True)
    if len(component) > max_component_bytes:
        raise RuntimeError("Wasm component exceeds input limit")
    return component


class WasmDecisionProvider(ModelProvider):
    """Runs WIT-shaped portable agent decision logic in Wasm with no ambient imports."""

    # debt: the Node fallback guest EXPORTS its own memory, so the host cannot cap
    # it post-instantiation; memory is bounded only by the module's declared maximum
    # (spec cap 4 GiB) plus the subprocess wall-clock (memory.grow past the OS limit
    # returns -1 gracefully and degrades to a CPU loop the deadline catches). An OS
    # RLIMIT_AS is unusable here because V8 reserves multi-GB of virtual space at
    # startup. The native Wasmtime engine (the default) enforces real fuel + memory
    # limits. Upgrade when the Node path becomes primary or needs a hard memory cap.

    def __init__(
        self,
        component: bytes,
        timeout: float = 2.0,
        max_output_bytes: int = 65_536,
        max_component_bytes: int = DEFAULT_MAX_WASM_COMPONENT_BYTES,
    ) -> None:
        node = shutil.which("node")
        if not node:
            raise RuntimeError("Node.js is required to execute WebAssembly capsules")
        if len(component) > max_component_bytes:
            raise RuntimeError("Wasm component exceeds input limit")
        self._node = node
        self._component = component
        self._timeout = timeout
        self._max_output_bytes = max_output_bytes
        self._runner = os.path.join(os.path.dirname(__file__), "wasm_runner.mjs")
        self.component_digest = "sha256:" + hashlib.sha256(component).hexdigest()

    @classmethod
    def from_file(
        cls,
        path: str,
        timeout: float = 2.0,
        max_output_bytes: int = 65_536,
        max_component_bytes: int = DEFAULT_MAX_WASM_COMPONENT_BYTES,
    ) -> "WasmDecisionProvider":
        component = _read_component_file(path, max_component_bytes)
        return cls(component, timeout, max_output_bytes, max_component_bytes)

    def decide(self, state: AgentState, available_tools: tuple[str, ...], grants: tuple[ToolGrant, ...] = ()) -> ProviderDecision:
        encoded_component = base64.b64encode(self._component).decode("ascii")
        context_json = encode_component_input(component_context(state, available_tools, grants))
        checkpoint_json = encode_component_input(component_checkpoint(state, grants))
        try:
            # Shell is disabled and the executable/runner paths are host-controlled.
            process = subprocess.run(  # nosec B603
                [self._node, self._runner],
                input=json.dumps({"component": encoded_component, "context_json": context_json, "checkpoint_json": checkpoint_json}),
                capture_output=True, text=True, timeout=self._timeout, check=False,
                # Node needs the normal Windows process environment to initialize.
                # The Wasm guest cannot observe it because the module receives no imports.
                env=os.environ.copy(),
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("Wasm capsule exceeded its execution deadline") from error
        if process.returncode != 0:
            raise RuntimeError("Wasm capsule rejected: " + process.stderr.strip())
        if len(process.stdout.encode()) > self._max_output_bytes:
            raise RuntimeError("Wasm component decision exceeded output limit")
        return decode_component_decision(process.stdout, available_tools)


class NativeWasmtimeComponentProvider(ModelProvider):
    """Runs a Component Model provider through wasmtime-py."""

    def __init__(
        self,
        component: bytes,
        timeout: float = 2.0,
        max_output_bytes: int = 65_536,
        max_component_bytes: int = DEFAULT_MAX_WASM_COMPONENT_BYTES,
        max_fuel: int = DEFAULT_WASM_FUEL,
        max_memory_bytes: int = DEFAULT_WASM_MEMORY_BYTES,
    ) -> None:
        if len(component) > max_component_bytes:
            raise RuntimeError("Wasm component exceeds input limit")
        if max_fuel < 1:
            raise RuntimeError("max_fuel must be positive")
        if max_memory_bytes < 1:
            raise RuntimeError("max_memory_bytes must be positive")
        self._component = component
        self._timeout = timeout
        self._max_output_bytes = max_output_bytes
        self._max_fuel = max_fuel
        self._max_memory_bytes = max_memory_bytes
        self.component_digest = "sha256:" + hashlib.sha256(component).hexdigest()

    @classmethod
    def from_file(
        cls,
        path: str,
        timeout: float = 2.0,
        max_output_bytes: int = 65_536,
        max_component_bytes: int = DEFAULT_MAX_WASM_COMPONENT_BYTES,
        max_fuel: int = DEFAULT_WASM_FUEL,
        max_memory_bytes: int = DEFAULT_WASM_MEMORY_BYTES,
    ) -> "NativeWasmtimeComponentProvider":
        component = _read_component_file(path, max_component_bytes)
        return cls(component, timeout, max_output_bytes, max_component_bytes, max_fuel, max_memory_bytes)

    def decide(
        self,
        state: AgentState,
        available_tools: tuple[str, ...],
        grants: tuple[ToolGrant, ...] = (),
    ) -> ProviderDecision:
        context_json = encode_component_input(component_context(state, available_tools, grants))
        checkpoint_json = encode_component_input(component_checkpoint(state, grants))
        environment = _wasmtime_subprocess_env()
        try:
            process = subprocess.run(  # nosec B603
                [sys.executable, "-m", "portmark.wasmtime_component_runner"],
                input=json.dumps({
                    "component": base64.b64encode(self._component).decode("ascii"),
                    "context_json": context_json,
                    "checkpoint_json": checkpoint_json,
                    "max_output_bytes": self._max_output_bytes,
                    "max_fuel": self._max_fuel,
                    "max_memory_bytes": self._max_memory_bytes,
                }),
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
                env=environment,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("native Wasmtime component exceeded its execution deadline") from error
        if process.returncode != 0:
            error_text = process.stderr.strip()
            if len(error_text.encode()) > 4096:
                error_text = error_text.encode()[:4096].decode("utf-8", "replace")
            raise RuntimeError("native Wasmtime component rejected: " + error_text)
        if len(process.stdout.encode()) > self._max_output_bytes:
            raise RuntimeError("native Wasmtime component decision exceeded output limit")
        return decode_component_decision(process.stdout, available_tools)

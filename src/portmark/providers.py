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
import threading
import time
from urllib.parse import urlparse
from abc import ABC, abstractmethod
from typing import Any

from .component_bindings import component_checkpoint, component_context, decode_component_decision, encode_component_input
from .models import ProviderDecision, ProviderView
from .projection import provider_state
from .security import SecurityError
from .json_guard import StrictJSONError, strict_json_loads

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
    def decide(self, view: ProviderView, available_tools: tuple[str, ...]) -> ProviderDecision:
        """Return a proposal from the canonical detached ProviderView (finding #2). The host
        builds the view (applying every grant's projection) and remains responsible for
        authorization and execution -- the provider never receives grants or live state."""


class DeterministicProvider(ModelProvider):
    """Offline provider used for tests and the demo."""

    def decide(self, view: ProviderView, available_tools: tuple[str, ...]) -> ProviderDecision:
        results = view.tool_results
        if not results.get("catalog.search") and "catalog.search" in available_tools:
            return ProviderDecision("tool", "catalog.search", {"query": view.goal, "limit": 3})
        return ProviderDecision(
            "complete",
            content={"summary": f"Completed: {view.goal}", "evidence": results.get("catalog.search", [])},
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


# The whole synchronous transaction (DNS + TCP + TLS + request + response) runs in a worker thread so
# ONE external deadline bounds it -- a socket idle timeout resets on every dribbled byte, so it cannot
# bound getresponse()/the TLS handshake, which read many times while parsing. A blocking socket thread
# cannot be killed; most abandoned threads die at once (the watchdog closes their connection), but a
# thread stalled INSIDE the TLS handshake or DNS (before the connection is published) lingers until it
# unblocks -- the documented residual. This semaphore bounds how many such threads can accumulate. It is
# sized well above any plausible healthy concurrency (A2A default is 32) and acquired with a wait rather
# than a hard refusal, so it bounds LEAKS, not concurrency: healthy transactions finish in well under the
# deadline and recycle their slot immediately, so a slot is essentially always available unless stalled
# threads have genuinely piled up.
_TRANSACTION_SLOTS = threading.BoundedSemaphore(256)


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
        # An IPv6 literal must be bracketed in the Host authority ([::1]:8080, not ::1:8080); urlparse
        # strips the brackets in .hostname, so restore them for the header.
        try:
            header_host = f"[{host}]" if ipaddress.ip_address(host).version == 6 else host
        except ValueError:
            header_host = host
        default_port = self._port == (443 if parsed.scheme == "https" else 80)
        self._host_header = header_host if default_port else f"{header_host}:{self._port}"
        self.bearer_token = bearer_token
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self._allow_local = allow_local_endpoint

    def decide(self, view: ProviderView, available_tools: tuple[str, ...]) -> ProviderDecision:
        body = json.dumps({"state": provider_state(view), "available_tools": available_tools}).encode()
        raw = self._post(body)
        try:
            value = strict_json_loads(raw, max_bytes=self.max_response_bytes)
        except StrictJSONError as error:
            raise SecurityError("provider response is malformed or unsafe JSON") from error
        return _provider_decision(value)

    # ---- Section 8 transport -------------------------------------------------------------------

    def _resolve(self) -> list[tuple[int, str]]:
        # A literal-IP endpoint is classified directly (no resolution). A hostname is resolved ONCE.
        # getaddrinfo has no timeout, but the whole transaction runs under an external deadline
        # (see _post), so a stuck resolver leaks a bounded worker thread rather than the caller.
        try:
            literal = ipaddress.ip_address(self._host)
            return [(socket.AF_INET6 if literal.version == 6 else socket.AF_INET, str(literal))]
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(self._host, self._port, type=socket.SOCK_STREAM)
        except OSError as error:  # gaierror is a subclass
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
        # Run the ENTIRE synchronous transaction (DNS, TCP, TLS, request, response headers, body) in a
        # worker thread joined on the deadline. A socket idle timeout resets on every dribbled byte, so
        # it cannot bound getresponse() or the TLS handshake -- which read many times while parsing; a
        # malicious drip would otherwise hold the caller far past the advertised timeout. The join is
        # the authoritative total bound: the CALLER returns at the deadline regardless of what the
        # transaction is doing. A blocking socket thread cannot be killed, so it is abandoned as a
        # bounded (semaphore-capped) daemon; closing its connection unblocks its read so it dies fast.
        # Acquire with a bounded WAIT, not a hard refusal: a healthy burst above the pool size waits a
        # moment for a fast completion to free a slot, and only genuinely-stalled accumulation (the pool
        # full of lingering DNS/TLS-drip leaks) is refused. The slot is released by the worker thread's
        # finally, so a leaked thread holds its slot until it finally dies. Both this wait AND the join
        # below are bounded by the SAME absolute deadline -- otherwise time spent waiting for a slot
        # would be spent AGAIN in the join, letting a contended call take up to twice its timeout.
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not _TRANSACTION_SLOTS.acquire(timeout=remaining):
            raise ProviderError("provider transaction pool exhausted (too many stalled requests in flight)")
        holder: dict[str, Any] = {}
        result: dict[str, Any] = {}

        def _run() -> None:
            try:
                result["value"] = self._transaction(body, deadline, holder)
            except Exception as error:  # noqa: BLE001 -- re-raised in the caller thread below
                result["error"] = error
            finally:
                _TRANSACTION_SLOTS.release()

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=max(0.0, deadline - time.monotonic()))  # remaining budget, not a fresh timeout
        if thread.is_alive():
            connection = holder.get("connection")
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
            raise ProviderError("provider request exceeded the deadline")
        if "error" in result:
            raise result["error"]
        return result["value"]

    def _transaction(self, body: bytes, deadline: float, holder: dict[str, Any]) -> bytes:
        _family, ip = self._validated_target()
        try:
            connection = self._open_connection(ip, deadline)
        except (OSError, ssl.SSLError) as error:
            raise ProviderError(f"provider connection failed: {error}") from error
        # Publish the connection so the watchdog in _post can close it to unblock this thread on timeout.
        holder["connection"] = connection
        try:
            # DNS-rebinding backstop: confirm the socket really connected to the address we validated.
            sock = connection.sock
            if sock is None:
                raise ProviderError("provider connection has no socket")
            if _classify_address(sock.getpeername()[0]) != _classify_address(ip):
                raise ProviderError("connected peer does not match the validated address")
            return self._exchange(connection, sock, body, deadline)
        finally:
            connection.close()

    def _exchange(self, connection: http.client.HTTPConnection, sock: socket.socket, body: bytes, deadline: float) -> bytes:
        try:
            # skip_host so we set Host ourselves (the hostname, not the pinned IP the socket is on).
            connection.putrequest("POST", self._path, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", self._host_header)
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(len(body)))
            if self.bearer_token:
                connection.putheader("Authorization", f"Bearer {self.bearer_token}")
            self._arm_deadline(sock, deadline)
            connection.endheaders(body)
            self._arm_deadline(sock, deadline)
            response = connection.getresponse()
        except (OSError, http.client.HTTPException) as error:
            raise ProviderError(f"provider request failed: {error}") from error
        # A redirect is NOT followed -- it is a controlled failure (SSRF vector + would forward the
        # bearer token cross-origin). Any non-200 is likewise a provider failure.
        if 300 <= response.status < 400:
            raise ProviderError(f"provider returned an unfollowed redirect (HTTP {response.status})")
        if response.status != 200:
            raise ProviderError(f"provider returned HTTP {response.status}")
        return self._read_bounded(response, sock, deadline)

    def _read_bounded(self, response: http.client.HTTPResponse, sock: socket.socket, deadline: float) -> bytes:
        # Bound the body DURING the read (never buffer unbounded) and enforce the total deadline. The
        # socket timeout is re-armed to the REMAINING deadline before each read (finding round-1 #2:
        # a per-operation socket timeout that is not re-armed lets each phase re-spend the full budget).
        # read1() returns whatever one recv yields, so a slow-drip is also re-checked against the wall
        # clock between chunks and aborted on the total deadline rather than trickling to completion.
        limit = self.max_response_bytes
        buffer = bytearray()
        while len(buffer) <= limit:
            self._arm_deadline(sock, deadline)
            try:
                chunk = response.read1(min(65_536, limit + 1 - len(buffer)))
            except (OSError, http.client.HTTPException) as error:
                raise ProviderError(f"provider response read failed: {error}") from error
            if not chunk:
                # EOF. If the framing promised more (Content-Length not fully delivered), the body was
                # truncated -- a controlled provider failure, not a valid short response.
                if getattr(response, "length", None):
                    raise ProviderError("provider response ended prematurely")
                return bytes(buffer)
            buffer.extend(chunk)
            if len(buffer) > limit:
                raise SecurityError("provider response exceeds output limit")
        raise SecurityError("provider response exceeds output limit")

    def _arm_deadline(self, sock: socket.socket, deadline: float) -> None:
        # Re-arm the socket timeout to the time REMAINING on the total deadline, and fail closed if the
        # deadline has passed. A socket timeout is per-operation (idle), so without re-arming before
        # each phase/read the time already spent (DNS, connect, prior reads) could be spent again in
        # the next operation, overshooting the advertised total bound. settimeout is guarded: after a
        # Connection: close response http.client releases the socket, and a best-effort re-arm on the
        # released reference must not mask the deadline the wall-clock check above already enforces.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProviderError("provider deadline exceeded")
        try:
            sock.settimeout(remaining)
        except OSError:
            pass


def _require_exact_keys(value: dict[str, Any], allowed: set[str], required: set[str], label: str) -> None:
    # Strict per-kind decision schema (finding #4, Low): reject fields that do not belong to this
    # decision kind, so a `complete` cannot also smuggle a `tool`/`destination` and a validator that
    # keys off `kind` alone stays unambiguous. Only known keys are permitted; missing required keys
    # (kind, plus tool/destination for those kinds) are rejected too.
    keys = set(value)
    extra = keys - allowed
    if extra:
        raise SecurityError(f"provider {label} decision has unexpected fields: {sorted(extra)}")
    missing = required - keys
    if missing:
        raise SecurityError(f"provider {label} decision is missing required fields: {sorted(missing)}")


def _provider_decision(value: Any) -> ProviderDecision:
    if not isinstance(value, dict):
        raise SecurityError("provider response must be a JSON object")
    kind = value.get("kind")
    if kind == "tool":
        _require_exact_keys(value, {"kind", "tool", "arguments"}, {"kind", "tool"}, "tool")
        tool = value.get("tool")
        if not isinstance(tool, str) or not tool:
            raise SecurityError("provider tool decision has an invalid tool name")
        arguments = value.get("arguments", {})
        if not isinstance(arguments, dict):
            raise SecurityError("provider tool decision arguments must be a JSON object")
        return ProviderDecision("tool", tool=tool, arguments=arguments)
    if kind in {"complete", "await_input", "fail"}:
        _require_exact_keys(value, {"kind", "content"}, {"kind"}, kind)
        return ProviderDecision(kind, content=value.get("content"))
    if kind == "migrate":
        _require_exact_keys(value, {"kind", "destination", "content"}, {"kind", "destination"}, "migrate")
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


def _kill_process(process: subprocess.Popen) -> None:
    """Best-effort terminate; a process that already exited is left alone."""
    if process.poll() is not None:
        return
    try:
        process.kill()
    except OSError:
        pass


def _run_bounded(
    argv: list[str],
    request: bytes,
    *,
    timeout: float,
    max_output_bytes: int,
    env: dict[str, str],
    stderr_cap: int = 4096,
) -> tuple[int | None, bytes, str, bool, bool]:
    """Run a subprocess, draining stdout/stderr on reader threads under a hard byte cap.

    Unlike ``subprocess.run(capture_output=True)``, output is bounded DURING the read: the
    instant stdout passes ``max_output_bytes`` the process is killed and reading stops, so a
    hostile child cannot exhaust host memory before a post-hoc size check (finding #5). stderr
    is retained only up to ``stderr_cap`` bytes but kept draining past it, so the pipe never
    blocks the child yet the retained error text cannot itself grow without bound.

    Reader threads start BEFORE stdin is written: the stdin payload (base64 component + context)
    far exceeds the OS pipe buffer, so writing first would deadlock -- host blocked writing stdin
    while the child blocks writing stdout. One monotonic deadline bounds the whole call and every
    wait derives its remaining budget from it, so no phase can re-spend the full timeout.

    Returns ``(returncode, stdout_bytes, stderr_text, timed_out, overflowed)``.

    debt: ``process.kill()`` ends only the direct child, not a descendant tree. Sufficient here:
    the Wasm guest receives NO imports (it cannot spawn) and the node/runner executable paths are
    host-controlled. Upgrade to the tools.py isolated-executor (process-group / Job Object
    kill-tree) if the runner ever gains spawn/exec capability.
    """
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(  # nosec B603
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    overflow = threading.Event()

    def drain_stdout() -> None:
        stream = process.stdout
        if stream is None:
            return
        try:
            while True:
                chunk = stream.read(65_536)
                if not chunk:
                    break
                stdout_buffer.extend(chunk)
                if len(stdout_buffer) > max_output_bytes:
                    overflow.set()
                    _kill_process(process)
                    break
        except (OSError, ValueError):
            pass

    def drain_stderr() -> None:
        stream = process.stderr
        if stream is None:
            return
        try:
            while True:
                chunk = stream.read(65_536)
                if not chunk:
                    break
                if len(stderr_buffer) < stderr_cap:
                    stderr_buffer.extend(chunk[: stderr_cap - len(stderr_buffer)])
        except (OSError, ValueError):
            pass

    out_reader = threading.Thread(target=drain_stdout, daemon=True)
    err_reader = threading.Thread(target=drain_stderr, daemon=True)
    timed_out = False
    try:
        out_reader.start()
        err_reader.start()
        if process.stdin is not None:
            try:
                process.stdin.write(request)
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process(process)
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                pass
        # Flat grace, NOT deadline-derived: the process has exited (natural EOF, overflow kill, or
        # confirmed timeout kill) so the readers are draining a closed pipe. A deadline-derived join
        # could block far past the caller's budget on the overflow path, where the deadline may have
        # plenty left (cf. the round-1 finding on waits that re-spend the full timeout).
        out_reader.join(timeout=2.0)
        err_reader.join(timeout=2.0)
    finally:
        _kill_process(process)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
    stderr_text = bytes(stderr_buffer).decode("utf-8", "replace").strip()
    return process.returncode, bytes(stdout_buffer), stderr_text, timed_out, overflow.is_set()


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

    def decide(self, view: ProviderView, available_tools: tuple[str, ...]) -> ProviderDecision:
        encoded_component = base64.b64encode(self._component).decode("ascii")
        context_json = encode_component_input(component_context(view, available_tools))
        checkpoint_json = encode_component_input(component_checkpoint(view))
        request = json.dumps(
            {"component": encoded_component, "context_json": context_json, "checkpoint_json": checkpoint_json}
        ).encode("utf-8")
        # Shell is disabled and the executable/runner paths are host-controlled. Node needs the
        # normal process environment to initialize; the Wasm guest cannot observe it because the
        # module receives no imports. Output is drained under a hard byte cap (see _run_bounded).
        returncode, stdout_bytes, stderr_text, timed_out, overflowed = _run_bounded(
            [self._node, self._runner],
            request,
            timeout=self._timeout,
            max_output_bytes=self._max_output_bytes,
            env=os.environ.copy(),
        )
        # Precedence: an overflow kill leaves returncode == -SIGKILL, so the output-limit and
        # deadline outcomes must be reported BEFORE the generic non-zero-exit rejection.
        if timed_out:
            raise RuntimeError("Wasm capsule exceeded its execution deadline")
        if overflowed:
            raise RuntimeError("Wasm component decision exceeded output limit")
        if returncode != 0:
            raise RuntimeError("Wasm capsule rejected: " + stderr_text)
        try:
            stdout_text = stdout_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeError("Wasm capsule produced invalid output") from error
        return decode_component_decision(stdout_text, available_tools)


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
        view: ProviderView,
        available_tools: tuple[str, ...],
    ) -> ProviderDecision:
        context_json = encode_component_input(component_context(view, available_tools))
        checkpoint_json = encode_component_input(component_checkpoint(view))
        environment = _wasmtime_subprocess_env()
        request = json.dumps({
            "component": base64.b64encode(self._component).decode("ascii"),
            "context_json": context_json,
            "checkpoint_json": checkpoint_json,
            "max_output_bytes": self._max_output_bytes,
            "max_fuel": self._max_fuel,
            "max_memory_bytes": self._max_memory_bytes,
        }).encode("utf-8")
        # Bounded incremental drain (see _run_bounded): defence-in-depth alongside the guest's
        # fuel/memory bounds, so hostile runner output cannot buffer without limit.
        returncode, stdout_bytes, stderr_text, timed_out, overflowed = _run_bounded(
            [sys.executable, "-m", "portmark.wasmtime_component_runner"],
            request,
            timeout=self._timeout,
            max_output_bytes=self._max_output_bytes,
            env=environment,
        )
        # Same precedence as the Node path: overflow/deadline outcomes beat the non-zero-exit
        # rejection because an overflow kill sets returncode == -SIGKILL.
        if timed_out:
            raise RuntimeError("native Wasmtime component exceeded its execution deadline")
        if overflowed:
            raise RuntimeError("native Wasmtime component decision exceeded output limit")
        if returncode != 0:
            raise RuntimeError("native Wasmtime component rejected: " + stderr_text)
        try:
            stdout_text = stdout_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeError("native Wasmtime component produced invalid output") from error
        return decode_component_decision(stdout_text, available_tools)

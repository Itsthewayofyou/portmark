from __future__ import annotations

import http.client
import json
import hashlib
import base64
import functools
import ipaddress
import logging
import math
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

from . import _windows_job
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
_MiB = 1024 * 1024
# Section 9 (#1/#3): the native Wasmtime ceiling is three layers that must agree.
#  1. Store: memory_size is PER LINEAR MEMORY; instances/memories/tables/table_elements cap how
#     many of each a component may create, so it cannot multiply the per-memory ceiling.
#  2. Aggregate guest memory = DEFAULT_WASM_MAX_MEMORIES x DEFAULT_WASM_MEMORY_BYTES (128 MiB).
#  3. OS: the whole worker (Python + wasmtime + JIT compiler + guest) runs under an address-space
#     cap (POSIX RLIMIT_AS) or a per-process commit cap (Windows Job Object).
# Invariant, checked at provider construction:
#     max_memories x max_memory_bytes + WASMTIME_WORKER_BASELINE_BYTES <= worker_memory_limit
# The real capsule needs 1 instance, 1 memory, 0 tables and 64 KiB; the rest is headroom.
DEFAULT_WASM_MEMORY_BYTES = 64 * _MiB  # per linear memory (was 256 MiB before Section 9)
DEFAULT_WASM_MAX_INSTANCES = 8
DEFAULT_WASM_MAX_MEMORIES = 2
DEFAULT_WASM_MAX_TABLES = 4
DEFAULT_WASM_MAX_TABLE_ELEMENTS = 10_000
# Python + the wasmtime wheel + compiler working set. Probed: the worker runs, with two 64 MiB
# memories grown to their cap, under a 384 MiB address-space cap.
WASMTIME_WORKER_BASELINE_BYTES = 256 * _MiB
DEFAULT_WASMTIME_WORKER_MEMORY_LIMIT = 512 * _MiB
# Workers (each compiles its component afresh) allowed at once, separate from request
# concurrency: N concurrent decisions no longer mean N simultaneous native compilers (#3).
DEFAULT_MAX_CONCURRENT_WASMTIME_WORKERS = 2
_WASMTIME_WORKER_SLOTS = threading.BoundedSemaphore(DEFAULT_MAX_CONCURRENT_WASMTIME_WORKERS)

logger = logging.getLogger(__name__)

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


class PinnedHTTPSConnection(http.client.HTTPSConnection):
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


def resolve_public_address(host: str, port: int) -> str:
    """Resolve `host` ONCE and return the address to connect to. Every answer must be a PUBLIC address:
    one loopback, private, link-local, multicast, reserved, or unspecified answer (IPv4-mapped IPv6
    included) fails the whole lookup closed (SecurityError), so a mixed answer cannot slip through on its
    public half. Connect to the returned literal with PinnedHTTPSConnection, so DNS is never asked again
    for routing (the DNS-rebinding defense). A lookup failure is an OSError."""
    try:
        answers = [str(ipaddress.ip_address(host))]
    except ValueError:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        answers = [str(sockaddr[0]) for family, _t, _p, _c, sockaddr in infos if family in (socket.AF_INET, socket.AF_INET6)]
    if not answers:
        raise OSError(f"{host!r} resolved to no usable address")
    for ip in answers:
        if _address_is_disallowed(_classify_address(ip)):
            raise SecurityError(f"{host!r} resolves to a non-public address ({ip})")
    return answers[0]


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
            connection: http.client.HTTPConnection = PinnedHTTPSConnection(
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
        try:
            thread.start()
        except RuntimeError as error:
            # Section 12 #5: the OS refused a new thread, so _run's finally will never release the slot
            # reserved above. Release it here and fail closed, or each failed start leaks one slot
            # until the pool is permanently exhausted.
            _TRANSACTION_SLOTS.release()
            raise ProviderError("could not start a provider transaction thread") from error
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


def _freeze_component(component: Any, max_component_bytes: int) -> bytes:
    """Take an immutable private copy of the component bytes (Section 9, finding #2).

    The provider publishes ``component_digest`` once, and the host checks it against the signed
    manifest (host.py), but the bytes are read again on every ``decide``. Keeping the caller's
    object let a mutable ``bytearray`` change after construction, so the code that ran was not the
    code the signed digest names. Freeze FIRST, then hash and execute that one copy.

    ``memoryview`` accepts only buffer objects. Plain ``bytes(value)`` is NOT a safe freeze:
    ``bytes(5)`` silently yields five zero bytes and ``bytes([1, 2])`` accepts a list of ints.
    The buffer must also be one-dimensional with one-byte items, so an ``array('i', ...)`` or a
    multi-dimensional buffer is refused instead of being reinterpreted as its raw memory. A
    released memoryview raises ``ValueError`` and is refused the same way.

    The size limit is checked on the view BEFORE the copy (PR #78 review): copying first let an
    oversized buffer force a second full-size allocation before the input cap applied. The view is
    held across the check and the copy, which locks a ``bytearray`` against resizing in between.
    """
    try:
        view = memoryview(component)
    except (TypeError, ValueError) as error:
        raise RuntimeError("Wasm component must be bytes-like") from error
    with view:
        if view.ndim != 1 or view.itemsize != 1:
            raise RuntimeError("Wasm component must be bytes-like")
        if view.nbytes > max_component_bytes:
            raise RuntimeError("Wasm component exceeds input limit")
        return bytes(view)


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


# A child that proves the POSIX address-space cap is ENFORCED, not merely accepted: it caps
# itself, then allocates twice the cap. Exit 0 only if that allocation is refused.
_CAP_SELF_CHECK = (
    "import resource, sys\n"
    "cap = 256 * 1024 * 1024\n"
    "resource.setrlimit(resource.RLIMIT_AS, (cap, cap))\n"
    "try:\n"
    "    bytearray(2 * cap)\n"
    "except MemoryError:\n"
    "    sys.exit(0)\n"
    "sys.exit(3)\n"
)


@functools.lru_cache(maxsize=1)
def _worker_memory_cap_enforceable() -> bool:
    """Whether this platform can put an ENFORCED memory ceiling on the native Wasmtime worker.

    Windows: a Job Object with a per-process memory limit. POSIX: RLIMIT_AS -- proven once per
    process by a self-check child, because a platform may accept ``setrlimit`` without enforcing
    it (an accepted-but-ignored cap is the silent, worse case). Decided by behaviour, not by an OS
    name list. Cached: the answer cannot change within a process.
    """
    if sys.platform == "win32":
        return _windows_job.available()
    try:
        import resource  # noqa: F401 -- presence check only
    except ImportError:
        return False
    try:
        result = subprocess.run(  # nosec B603 - fixed argv, host interpreter, no shell
            [sys.executable, "-c", _CAP_SELF_CHECK],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


class _Worker:
    """A launched worker: the process, how to kill it, and how to release it."""

    def __init__(self, process: subprocess.Popen, kill: Any = None, close: Any = None) -> None:
        self.process = process
        self._kill = kill or (lambda: _kill_process(process))
        self._close = close or (lambda: None)

    def kill(self) -> None:
        if self.process.poll() is not None:
            return
        try:
            self._kill()
        except OSError:
            pass

    def close(self) -> None:
        try:
            self._close()
        except OSError:
            pass


def _launch_plain(argv: list[str], popen_kwargs: dict[str, Any]) -> _Worker:
    return _Worker(subprocess.Popen(argv, **popen_kwargs))  # nosec B603


def _windows_job_launcher(process_memory_limit: int) -> Any:
    """Launch inside a kill-on-close Job Object with a per-process memory ceiling (Windows).

    Reuses the isolated-tool executor's race-free launch (suspended -> assign -> resume) and its
    fail-closed cleanup; a failed job setup raises instead of falling back to an unmanaged child.
    """
    from .tools import _launch_windows_job_tree

    def launch(argv: list[str], popen_kwargs: dict[str, Any]) -> _Worker:
        tree = _launch_windows_job_tree(argv, popen_kwargs, process_memory_limit=process_memory_limit)
        return _Worker(tree._process, kill=tree.terminate_tree, close=tree.close)

    return launch


def _run_bounded(
    argv: list[str],
    request: bytes,
    *,
    timeout: float,
    max_output_bytes: int,
    env: dict[str, str],
    stderr_cap: int = 4096,
    launch: Any = None,
) -> tuple[int | None, bytes, str, bool, bool]:
    """Run a subprocess, draining stdout/stderr on reader threads under a hard byte cap.

    Unlike ``subprocess.run(capture_output=True)``, output is bounded DURING the read: the
    instant stdout passes ``max_output_bytes`` the process is killed and reading stops, so a
    hostile child cannot exhaust host memory before a post-hoc size check (finding #5). stderr
    is retained only up to ``stderr_cap`` bytes but kept draining past it, so the pipe never
    blocks the child yet the retained error text cannot itself grow without bound.

    stdin is written on a dedicated WRITER thread, and readers start before it: the stdin payload
    (base64 component + context) far exceeds the OS pipe buffer, so a synchronous write on the main
    thread would (a) deadlock against the child's own blocked stdout write, and (b) -- if the child
    never reads stdin (a wedged or failed-to-start runner) -- block the main thread past the
    advertised deadline, since ``process.wait(timeout=...)`` is only reached AFTER the write returns.
    With the write off the main thread, ``process.wait`` supervises the one absolute deadline for the
    whole call; on expiry the process is killed, which closes the child's stdin read end so the
    blocked writer unblocks with ``BrokenPipeError``. Every wait derives its budget from that one
    deadline, so no phase can re-spend the full timeout.

    ``launch(argv, popen_kwargs) -> _Worker`` selects how the child starts and is killed; the
    default is a plain ``Popen``. The native Wasmtime provider passes a Job Object launcher on
    Windows so the worker runs under a per-process memory ceiling (Section 9, #1).

    Returns ``(returncode, stdout_bytes, stderr_text, timed_out, overflowed)``.

    debt: ``process.kill()`` ends only the direct child, not a descendant tree. Sufficient here:
    the Wasm guest receives NO imports (it cannot spawn) and the node/runner executable paths are
    host-controlled. Upgrade to the tools.py isolated-executor (process-group / Job Object
    kill-tree) if the runner ever gains spawn/exec capability.
    """
    deadline = time.monotonic() + timeout
    worker = (launch or _launch_plain)(
        argv,
        {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "env": env},
    )
    process = worker.process
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
                    worker.kill()
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

    def write_stdin() -> None:
        stream = process.stdin
        if stream is None:
            return
        try:
            stream.write(request)
            stream.close()
        except (BrokenPipeError, OSError, ValueError):
            # Child never read stdin / exited / was killed -> its read end closed; nothing to do.
            pass

    out_reader = threading.Thread(target=drain_stdout, daemon=True)
    err_reader = threading.Thread(target=drain_stderr, daemon=True)
    writer = threading.Thread(target=write_stdin, daemon=True)
    timed_out = False
    try:
        out_reader.start()
        err_reader.start()
        writer.start()
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            worker.kill()
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                pass
        # Flat grace, NOT deadline-derived: the process has exited (natural EOF, overflow kill, or
        # confirmed timeout kill), which closes both pipe ends -- so the readers are draining a
        # closed pipe and the writer's blocked write has unblocked with BrokenPipeError. A
        # deadline-derived join could block far past the caller's budget on the overflow path,
        # where the deadline may have plenty left (cf. the round-1 finding on waits that re-spend
        # the full timeout).
        out_reader.join(timeout=2.0)
        err_reader.join(timeout=2.0)
        writer.join(timeout=2.0)
    finally:
        worker.kill()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        worker.close()
    stderr_text = bytes(stderr_buffer).decode("utf-8", "replace").strip()
    return process.returncode, bytes(stdout_buffer), stderr_text, timed_out, overflow.is_set()


class WasmDecisionProvider(ModelProvider):
    """Runs WIT-shaped portable agent decision logic in Wasm with no ambient imports."""

    # debt: the Node fallback guest EXPORTS its own memory, so the host cannot cap
    # it post-instantiation; memory is bounded only by the module's declared maximum
    # (spec cap 4 GiB) plus the subprocess wall-clock (memory.grow past the OS limit
    # returns -1 gracefully and degrades to a CPU loop the deadline catches). An OS
    # RLIMIT_AS is unusable here because V8 reserves multi-GB of virtual space at
    # startup (this is about V8 only; the native Wasmtime worker DOES run under an
    # RLIMIT_AS cap -- see _engine_config). The optional native Wasmtime engine enforces
    # real fuel + memory limits. Upgrade when the Node path becomes primary or needs a
    # hard memory cap.

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
        component = _freeze_component(component, max_component_bytes)
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
    """Runs a Component Model provider through wasmtime-py in a short-lived, OS-capped worker.

    Section 9 resource model (see the constants at the top of this module): per-memory
    ``max_memory_bytes`` plus instance/memory/table count limits inside the store, an OS memory
    ceiling on the whole worker process, a cap on concurrent workers, and fuel for guest CPU.
    Where the OS ceiling cannot be enforced, construction is REFUSED unless the operator opts out
    with ``allow_uncapped_worker=True`` (every run is then logged as uncapped).
    """

    def __init__(
        self,
        component: bytes,
        timeout: float = 2.0,
        max_output_bytes: int = 65_536,
        max_component_bytes: int = DEFAULT_MAX_WASM_COMPONENT_BYTES,
        max_fuel: int = DEFAULT_WASM_FUEL,
        max_memory_bytes: int = DEFAULT_WASM_MEMORY_BYTES,
        *,
        max_instances: int = DEFAULT_WASM_MAX_INSTANCES,
        max_memories: int = DEFAULT_WASM_MAX_MEMORIES,
        max_tables: int = DEFAULT_WASM_MAX_TABLES,
        max_table_elements: int = DEFAULT_WASM_MAX_TABLE_ELEMENTS,
        worker_memory_limit: int = DEFAULT_WASMTIME_WORKER_MEMORY_LIMIT,
        allow_uncapped_worker: bool = False,
    ) -> None:
        component = _freeze_component(component, max_component_bytes)
        if max_fuel < 1:
            raise RuntimeError("max_fuel must be positive")
        if max_memory_bytes < 1:
            raise RuntimeError("max_memory_bytes must be positive")
        for name, value in (
            ("max_instances", max_instances), ("max_memories", max_memories),
            ("max_tables", max_tables), ("max_table_elements", max_table_elements),
            ("worker_memory_limit", worker_memory_limit),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise RuntimeError(f"{name} must be a positive integer")
        # The layers must agree, or the store limits and the OS ceiling can disagree and one of
        # them is only advisory: every memory the store admits, at full size, plus the worker's own
        # baseline, must fit inside the OS ceiling.
        guest_ceiling = max_memories * max_memory_bytes
        if guest_ceiling + WASMTIME_WORKER_BASELINE_BYTES > worker_memory_limit:
            raise RuntimeError(
                "native Wasmtime limits do not fit the worker memory ceiling: "
                f"max_memories x max_memory_bytes ({guest_ceiling}) + worker baseline "
                f"({WASMTIME_WORKER_BASELINE_BYTES}) exceeds worker_memory_limit ({worker_memory_limit})"
            )
        self._os_capped = _worker_memory_cap_enforceable()
        if not self._os_capped and not allow_uncapped_worker:
            raise RuntimeError(
                "native Wasmtime needs an enforceable OS memory ceiling for its worker, and this "
                "platform does not provide one; pass allow_uncapped_worker=True to run it uncapped"
            )
        self._component = component
        self._timeout = timeout
        self._max_output_bytes = max_output_bytes
        self._max_fuel = max_fuel
        self._max_memory_bytes = max_memory_bytes
        self._count_limits = {
            "instances": max_instances,
            "memories": max_memories,
            "tables": max_tables,
            "table_elements": max_table_elements,
        }
        self._worker_memory_limit = worker_memory_limit
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
        **limits: Any,
    ) -> "NativeWasmtimeComponentProvider":
        component = _read_component_file(path, max_component_bytes)
        return cls(component, timeout, max_output_bytes, max_component_bytes, max_fuel, max_memory_bytes, **limits)

    def _worker_rlimits(self) -> dict[str, int]:
        # POSIX caps, applied inside the worker before the Engine exists. CPU seconds cover JIT
        # compilation, which fuel does not meter. Windows uses the Job Object instead (launcher).
        if not self._os_capped or sys.platform == "win32":
            return {}
        return {"address_space": self._worker_memory_limit, "cpu_seconds": math.ceil(self._timeout) + 1}

    def _worker_launcher(self) -> Any:
        if self._os_capped and sys.platform == "win32":
            return _windows_job_launcher(self._worker_memory_limit)
        return None

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
            **self._count_limits,
            "rlimits": self._worker_rlimits(),
        }).encode("utf-8")
        if not self._os_capped:
            logger.warning("native Wasmtime worker is running WITHOUT an OS memory ceiling (allow_uncapped_worker)")
        # One deadline covers waiting for a worker slot AND the run, so a busy host cannot stretch
        # a decision past its timeout; a slot that does not free up in time fails closed.
        deadline = time.monotonic() + self._timeout
        if not _WASMTIME_WORKER_SLOTS.acquire(timeout=self._timeout):
            raise RuntimeError("native Wasmtime worker capacity exhausted before the execution deadline")
        try:
            # Bounded incremental drain (see _run_bounded): defence-in-depth alongside the guest's
            # fuel/memory bounds, so hostile runner output cannot buffer without limit.
            returncode, stdout_bytes, stderr_text, timed_out, overflowed = _run_bounded(
                [sys.executable, "-m", "portmark.wasmtime_component_runner"],
                request,
                timeout=max(0.0, deadline - time.monotonic()),
                max_output_bytes=self._max_output_bytes,
                env=environment,
                launch=self._worker_launcher(),
            )
        finally:
            _WASMTIME_WORKER_SLOTS.release()
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

"""Host-side wiring for MCP tools: registration and the start-up pin check (MCP/SIEM plan, PR 2).

An MCP tool becomes an ordinary isolated tool whose target is `portmark.mcp_worker:call`, so it inherits the
whole existing contract: the deadline, the process-tree kill, the effect ledger, the one-use launch
capability, and the audit chain. This module adds nothing to that path; it only decides what is registered
and refuses everything the operator did not approve. See MCP.md.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess  # nosec B404 - runs THIS interpreter to probe a server inside a bounded child tree
import sys
import threading
from dataclasses import dataclass, field
from typing import Any

from .json_guard import StrictJSONError, strict_json_loads
from .mcp_client import ERROR_CODES
from .mcp_config import McpConfig, McpConfigError, McpServerConfig, McpToolConfig, load_config
from .mcp_worker import tool_environment
from .tools import ToolRegistry, _launch_process_tree

logger = logging.getLogger(__name__)

CALL_TARGET = "portmark.mcp_worker:call"
# The per-call worker deadline: the server has to start, agree a protocol version, list its tools and answer.
# The client's own per-request timeout is a quarter of it, so a silent server produces a reported
# `mcp_transport_error` before the host's kill turns the same failure into `tool.killed`.
# Start-up, plus the worker's own shutdown of the server (up to ~6 s: wait, terminate, kill). Smaller than
# this would turn a finished call into `tool.killed` while the worker was still closing down (Codex R1).
STARTUP_ALLOWANCE_SECONDS = 10.0
PIN_CHECK_TIMEOUT_SECONDS = 60.0
MAX_PROBE_BYTES = 1 << 20
PROBE_CHUNK_BYTES = 1 << 16
# The probe worker sweeps its OWN process group before exiting, to take the MCP server's background children
# with it, and that sweep kills the worker by SIGKILL (Codex R3). So a finished probe ends one of two ways:
# 0 where there is no sweep (Windows, or a launch that did not make the worker its own group leader), or
# -SIGKILL where the sweep ran. The report itself is read from the PIPE, never from the exit status; this
# check only refuses an exit that means the worker died before it could report.
_CLEAN_PROBE_EXITS = frozenset({0, -getattr(signal, "SIGKILL", 9)})


class McpStartupError(McpConfigError):
    """A pin no longer matches, or a server could not be probed: the host does not start."""


@dataclass(frozen=True)
class PinReport:
    server: str
    protocol_version: str
    tools: dict[str, str]
    # Tools the server offered but the client refused to use, with the reason. A refused tool is NOT a
    # missing one, and an operator told the wrong story looks in the wrong place.
    rejected: dict[str, str] = field(default_factory=dict)


def refresh_oauth_tokens(config: McpConfig) -> tuple[str, ...]:
    """Make every `oauth` server's stored access token usable, BEFORE anything tries to use it.

    This is the host half of the separation: renewing drives the `mcp` SDK, so it happens here and never in
    the isolated worker, which only ever reads the resulting string out of the store. Returns the servers
    whose store was made current, in configuration order.

    It is not a guard, and it is deliberately not written as one. A caller that skips it does not produce an
    unauthenticated request -- the worker refuses a stale token itself. Skipping it only turns a start-up
    failure into a first-call failure."""
    from .mcp_oauth import McpOAuthError, current_access_token, sdk_available  # noqa: PLC0415 - oauth only

    made_current: list[str] = []
    for name, server in config.servers.items():
        if server.oauth is None:
            continue
        if not sdk_available():
            raise McpStartupError(
                f"MCP server {name!r} uses `oauth`, and the authorization code lives in an optional extra "
                "that is not installed: `pip install 'portmark[mcp-oauth]'`"
            )
        client_id = os.environ.get(server.oauth.client_id_env, "")
        if not client_id:
            raise McpStartupError(
                f"MCP server {name!r} reads its client id from {server.oauth.client_id_env}, "
                "and that variable is unset or empty"
            )
        try:
            current_access_token(
                server_url=server.url,
                token_store=server.oauth.token_store,
                client_id=client_id,
                client_secret=os.environ.get(server.oauth.client_secret_env, "")
                if server.oauth.client_secret_env
                else "",
                scopes=server.oauth.scopes,
                allow_private=server.allow_private,
            )
        except McpOAuthError as error:
            raise McpStartupError(f"MCP server {name!r}: {error}") from error
        made_current.append(name)
    return tuple(made_current)


def register_mcp_tools(registry: ToolRegistry, config: McpConfig, client_version: str = "") -> tuple[str, ...]:
    """Register every approved tool. Returns the registered names, in configuration order.

    A tool the operator did not mark `read_only` is registered as SIDE-EFFECTING, which the registry only
    accepts with a reconcile target and an acknowledged IsolationProfile. That is deliberate: MCP cannot say
    whether a tool changes the world, and its own annotations are untrusted."""
    if not config.path:
        raise McpConfigError("the MCP config must be loaded from a file: the worker re-reads it by path")
    existing = set(registry.names())
    names: list[str] = []
    for server in config.servers.values():
        for tool in server.tools.values():
            if tool.name in existing:
                # A server must never shadow a tool that is already installed.
                raise McpConfigError(f"MCP tool {tool.name!r} collides with a tool that is already registered")
            registry.register_isolated(
                tool.name,
                CALL_TARGET,
                timeout=server.timeout_seconds + STARTUP_ALLOWANCE_SECONDS,
                side_effecting=not tool.read_only,
                reconcile=tool.reconcile,
                error_codes=tuple(sorted(ERROR_CODES)),
                env=_worker_environment(config.path, server, tool, client_version),
            )
            existing.add(tool.name)
            names.append(tool.name)
    return tuple(names)


def _worker_environment(path: str, server: McpServerConfig, tool: McpToolConfig, version: str) -> dict[str, str]:
    """Small identifiers plus the named secrets, captured now from the host's own environment.

    The values live in the registry from here on, as every isolated tool's `env` does; a name the host does
    not have is simply absent, so a missing credential surfaces as the server's own failure, not as a
    Portmark error about a variable the operator can see for themselves."""
    environment = tool_environment(path, server, tool, version)
    names = tuple(server.secret_env)
    if server.bearer_env:
        names += (server.bearer_env,)
    if server.oauth is not None:
        # The CLIENT ID, and never the client secret: the worker does not talk to the authorization server,
        # so a secret there would be a credential with no use and a place to leak from. The id lets the
        # worker refuse tokens that were issued to a DIFFERENT application than the one now configured.
        names += (server.oauth.client_id_env,)
    for name in names:
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def probe_server(config_path: str, server: str, timeout: float = PIN_CHECK_TIMEOUT_SECONDS) -> PinReport:
    """List one server's tools and their digests, in a bounded child process TREE.

    The probe never runs in the host process: starting an MCP server means running the operator's configured
    program, and that belongs behind the same boundary a tool call has (Codex review R1). It runs through the
    same tree launcher a tool does, so a probe that has to be killed takes the MCP server with it -- killing
    only the probe process would leave the server it started running with nobody to stop it (Codex review R2).
    """
    tree = _launch_process_tree([sys.executable, "-m", "portmark.mcp_worker", config_path, server], dict(os.environ))
    buffer = bytearray()

    def drain() -> None:
        stream = tree.stdout
        while stream is not None:
            chunk = stream.read(PROBE_CHUNK_BYTES)
            if not chunk:
                return
            if len(buffer) < MAX_PROBE_BYTES:
                buffer.extend(chunk)

    reader = threading.Thread(target=drain, daemon=True)
    try:
        if tree.stdin is not None:
            tree.stdin.close()
        reader.start()
        try:
            tree.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise McpStartupError(f"probing MCP server {server!r} timed out after {timeout:g}s") from error
        reader.join(timeout=2.0)
    finally:
        try:
            tree.terminate_tree()
        except OSError:  # pragma: no cover - the process is already gone
            pass
        tree.close()
    return _probe_report(server, bytes(buffer), tree.returncode)


def _probe_report(server: str, raw: bytes, returncode: int | None) -> PinReport:
    """The worker reports both success and failure as JSON on stdout: the tree launcher discards stderr."""
    try:
        report = strict_json_loads(raw, max_bytes=MAX_PROBE_BYTES)
    except StrictJSONError as error:
        raise McpStartupError(f"the probe of MCP server {server!r} produced no usable report") from error
    if isinstance(report, dict) and isinstance(report.get("error"), str):
        raise McpStartupError(f"probing MCP server {server!r} failed: {report['error'][:300]}")
    if returncode not in _CLEAN_PROBE_EXITS or not isinstance(report, dict) or not isinstance(report.get("tools"), dict):
        raise McpStartupError(f"the probe of MCP server {server!r} produced no usable report")
    rejected = report.get("rejected")
    return PinReport(
        server,
        str(report.get("protocol_version", "")),
        dict(report["tools"]),
        {str(name): str(reason) for name, reason in rejected.items()} if isinstance(rejected, dict) else {},
    )


def check_pins(config: McpConfig, timeout: float = PIN_CHECK_TIMEOUT_SECONDS) -> tuple[PinReport, ...]:
    """Fail closed when any approved tool is missing or its definition changed. Used at host start-up."""
    reports = []
    for name, server in config.servers.items():
        if server.allow_private:
            # A loosening the operator chose, recorded where an audit of the start-up will find it.
            logger.warning(
                "MCP server %r allows private addresses for %s: loopback and private answers are accepted",
                name, server.url,
            )
        report = probe_server(config.path, name, timeout)
        for tool in server.tools.values():
            current = report.tools.get(tool.tool)
            if current is None and tool.tool in report.rejected:
                raise McpStartupError(
                    f"MCP server {name!r} offers {tool.tool!r}, but its definition is unusable: "
                    f"{report.rejected[tool.tool]}"
                )
            if current is None:
                raise McpStartupError(f"MCP server {name!r} no longer offers the approved tool {tool.tool!r}")
            if current != tool.pin:
                raise McpStartupError(
                    f"the definition of {name}.{tool.tool} changed since it was approved "
                    f"(now {current}); re-run `portmark mcp pin` and approve the new definition"
                )
        reports.append(report)
    return tuple(reports)


def pin_report(config_path: str, server: str | None = None, timeout: float = PIN_CHECK_TIMEOUT_SECONDS) -> dict[str, Any]:
    """What `portmark mcp pin` prints: every tool a server offers now, with the pin to paste into the config."""
    config = load_config(config_path)
    names = [server] if server is not None else list(config.servers)
    if server is not None and server not in config.servers:
        raise McpStartupError(f"the MCP config has no server {server!r}")
    out: dict[str, Any] = {}
    for name in names:
        report = probe_server(config_path, name, timeout)
        approved = {tool.tool: tool.pin for tool in config.servers[name].tools.values()}
        out[name] = {
            "protocol_version": report.protocol_version,
            "tools": {
                tool: {
                    "pin": digest,
                    "approved": approved.get(tool) == digest,
                    "state": _pin_state(approved.get(tool), digest),
                }
                for tool, digest in sorted(report.tools.items())
            },
            "missing": sorted(set(approved) - set(report.tools)),
        }
    return out


def _pin_state(approved: str | None, current: str) -> str:
    if approved is None:
        return "not-configured"
    return "approved" if approved == current else "CHANGED"


def dumps(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


__all__ = [
    "CALL_TARGET",
    "McpStartupError",
    "PinReport",
    "check_pins",
    "pin_report",
    "probe_server",
    "refresh_oauth_tokens",
    "register_mcp_tools",
    "dumps",
]

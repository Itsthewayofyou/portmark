"""Host-side wiring for MCP tools: registration and the start-up pin check (MCP/SIEM plan, PR 2).

An MCP tool becomes an ordinary isolated tool whose target is `portmark.mcp_worker:call`, so it inherits the
whole existing contract: the deadline, the process-tree kill, the effect ledger, the one-use launch
capability, and the audit chain. This module adds nothing to that path; it only decides what is registered
and refuses everything the operator did not approve. See MCP.md.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - runs THIS interpreter to probe a server inside a bounded child tree
import sys
import threading
from dataclasses import dataclass
from typing import Any

from .json_guard import StrictJSONError, strict_json_loads
from .mcp_client import ERROR_CODES
from .mcp_config import McpConfig, McpConfigError, McpServerConfig, McpToolConfig, load_config
from .mcp_worker import tool_environment
from .tools import ToolRegistry, _launch_process_tree

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


class McpStartupError(McpConfigError):
    """A pin no longer matches, or a server could not be probed: the host does not start."""


@dataclass(frozen=True)
class PinReport:
    server: str
    protocol_version: str
    tools: dict[str, str]


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
    for name in server.secret_env:
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
    if returncode != 0 or not isinstance(report, dict) or not isinstance(report.get("tools"), dict):
        raise McpStartupError(f"the probe of MCP server {server!r} produced no usable report")
    return PinReport(server, str(report.get("protocol_version", "")), dict(report["tools"]))


def check_pins(config: McpConfig, timeout: float = PIN_CHECK_TIMEOUT_SECONDS) -> tuple[PinReport, ...]:
    """Fail closed when any approved tool is missing or its definition changed. Used at host start-up."""
    reports = []
    for name, server in config.servers.items():
        report = probe_server(config.path, name, timeout)
        for tool in server.tools.values():
            current = report.tools.get(tool.tool)
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
    "register_mcp_tools",
    "dumps",
]

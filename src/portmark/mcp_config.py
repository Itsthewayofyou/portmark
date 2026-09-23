"""Operator configuration for MCP servers and the pins that approve their tools (MCP/SIEM plan, PR 2).

An MCP server is a remote party even when it runs as a local subprocess: nothing it reports is authority.
The operator names each server, names each tool it may expose, and approves that tool as the SHA-256 of its
canonical definition. A definition that changes later is refused. See MCP.md.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .json_guard import StrictJSONError, strict_json_loads
from .models import MAX_TOOL_NAME_LENGTH, validate_tool_name
from .security import canonical_json

CONFIG_SCHEMA = "portmark.mcp.config.v1"
MAX_CONFIG_BYTES = 1 << 20
DEFAULT_TIMEOUT_SECONDS = 20.0
MAX_TIMEOUT_SECONDS = 300.0
NAME_PREFIX = "mcp"
# The server label an operator chooses. Short and lower-case, so `mcp.<server>.<tool>` stays readable and
# leaves room for a 128-character MCP tool name inside Portmark's 192-character limit.
_SERVER_NAME = re.compile(r"\A[a-z0-9][a-z0-9_-]{0,31}\Z")
# What the MCP specification (revision 2026-07-28, "Tool Names") says a server tool name SHOULD be. Portmark
# accepts leading and trailing punctuation HERE, because that is the server's name for its own tool; the
# REGISTERED name is checked separately, and a tool whose name cannot be registered needs an `alias`.
_SERVER_TOOL_NAME = re.compile(r"\A[A-Za-z0-9._-]{1,128}\Z")
_ENV_NAME = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_PIN = re.compile(r"\Asha256:[0-9a-f]{64}\Z")

SERVER_FIELDS = ("command", "args", "secret_env", "timeout_seconds", "tools")
TOOL_FIELDS = ("pin", "read_only", "reconcile", "alias")


class McpConfigError(ValueError):
    """A malformed or unsafe MCP configuration: the host does not start (CLI exit 2)."""


def server_digest(server: "McpServerConfig") -> str:
    """The launch configuration of one server: what program runs, with which arguments and which secrets.

    The host records this at start-up and the worker re-checks it, so editing `command` in the config file
    after approval cannot make an approved pin launch a different program (Codex review R1)."""
    body = {
        "command": server.command,
        "args": list(server.args),
        "secret_env": sorted(server.secret_env),
        "timeout_seconds": server.timeout_seconds,
    }
    return "sha256:" + hashlib.sha256(canonical_json(body)).hexdigest()


def definition_digest(definition: Mapping[str, Any]) -> str:
    """The pin of one tool definition: SHA-256 over the WHOLE definition, minus protocol `_meta`.

    Not a chosen list of fields: an allowlist would silently ignore any field a later MCP revision adds,
    which is exactly the drift a pin exists to catch. The cost is that a cosmetic change (a description, an
    icon) needs the operator to approve the tool again, which is the fail-closed direction."""
    if not isinstance(definition, Mapping):
        raise McpConfigError("a tool definition must be an object")
    body = {key: value for key, value in definition.items() if key != "_meta"}
    return "sha256:" + hashlib.sha256(canonical_json(body)).hexdigest()


def request_timeout(total_seconds: float) -> float:
    """The client's per-request timeout: a quarter of the call's whole budget, so a silent server produces a
    reported `mcp_transport_error` before the host's deadline turns the same failure into `tool.killed`."""
    return max(1.0, total_seconds / 4)


def _reject_unknown(value: Mapping[str, Any], allowed: tuple[str, ...], label: str) -> None:
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise McpConfigError(f"{label} has unknown keys: {unknown}")


@dataclass(frozen=True)
class McpToolConfig:
    """One approved tool: what it is called on the server, what Portmark registers it as, and its pin."""

    server: str
    tool: str
    name: str
    pin: str
    read_only: bool = False
    # A `module:function` the operator wrote. NOT an MCP tool: the host's reconcile contract is
    # `{"landed": bool, "result"?: ...}` (host.reconcile_effect), and a foreign tool answers with free
    # content, so only an adapter the operator controls can turn one into that answer.
    reconcile: str | None = None


@dataclass(frozen=True)
class McpServerConfig:
    name: str
    command: str
    args: tuple[str, ...] = ()
    secret_env: tuple[str, ...] = ()
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    tools: Mapping[str, McpToolConfig] = field(default_factory=dict)


@dataclass(frozen=True)
class McpConfig:
    servers: Mapping[str, McpServerConfig]
    path: str = ""

    def tools(self) -> tuple[McpToolConfig, ...]:
        return tuple(tool for server in self.servers.values() for tool in server.tools.values())


def registered_name(server: str, tool: str, alias: str | None) -> str:
    """The FINAL registered name. An over-long or malformed generated name is refused, never shortened."""
    if alias is not None:
        try:
            return validate_tool_name(alias, "mcp alias")
        except ValueError as error:
            raise McpConfigError(str(error)) from error
    name = f"{NAME_PREFIX}.{server}.{tool}"
    try:
        return validate_tool_name(name, "mcp tool")
    except ValueError as error:
        # A server label is at most 32 characters and an MCP tool name at most 128, so a generated name is at
        # most 165 -- length alone never reaches here. What does is a server tool whose name starts or ends on
        # `.`, `_` or `-`: MCP permits that, and Portmark refuses it because it reads as hidden or truncated.
        raise McpConfigError(
            f"{name!r} cannot be registered ({error}); give this tool an `alias` "
            f"of at most {MAX_TOOL_NAME_LENGTH} characters"
        ) from error


def _tool_from_spec(server: str, tool: str, value: Any) -> McpToolConfig:
    label = f"servers[{server!r}].tools[{tool!r}]"
    if not _SERVER_TOOL_NAME.match(tool):
        raise McpConfigError(f"{label}: a server tool name must match {_SERVER_TOOL_NAME.pattern}")
    if not isinstance(value, dict):
        raise McpConfigError(f"{label} must be an object")
    _reject_unknown(value, TOOL_FIELDS, label)
    pin = value.get("pin")
    if not isinstance(pin, str) or not _PIN.match(pin):
        raise McpConfigError(f"{label}.pin must be 'sha256:' plus 64 lower-case hex characters; run `portmark mcp pin`")
    read_only = value.get("read_only", False)
    if not isinstance(read_only, bool):
        raise McpConfigError(f"{label}.read_only must be true or false")
    alias = value.get("alias")
    if alias is not None and not isinstance(alias, str):
        raise McpConfigError(f"{label}.alias must be a string")
    reconcile = value.get("reconcile")
    if reconcile is not None and (not isinstance(reconcile, str) or not reconcile):
        raise McpConfigError(f"{label}.reconcile must be a non-empty string")
    if read_only and reconcile is not None:
        # A reconcile exists to settle an effect. A tool the operator calls read-only has none to settle, and
        # accepting both would hide which of the two statements was meant.
        raise McpConfigError(f"{label}: a read_only tool cannot have a reconcile target")
    if not read_only and reconcile is None:
        raise McpConfigError(
            f"{label}: a tool that is not read_only is side-effecting, so it needs a `reconcile` target "
            "(a module:function that reports whether the effect landed). MCP cannot tell Portmark whether a "
            "tool changes the world, and the server's own annotations are untrusted."
        )
    if reconcile is not None:
        module_name, separator, object_path = reconcile.partition(":")
        if not separator or not module_name or not object_path:
            raise McpConfigError(
                f"{label}.reconcile must use module:function syntax. An MCP tool cannot BE a reconcile "
                "target: the host expects {'landed': bool, 'result'?: ...} and a foreign tool answers with "
                "free content, so write a small adapter that asks the server and returns that answer."
            )
    return McpToolConfig(server, tool, registered_name(server, tool, alias), pin, read_only, reconcile)


def _server_from_spec(name: str, value: Any) -> McpServerConfig:
    label = f"servers[{name!r}]"
    if not _SERVER_NAME.match(name):
        raise McpConfigError(f"server name {name!r} must match {_SERVER_NAME.pattern}")
    if not isinstance(value, dict):
        raise McpConfigError(f"{label} must be an object")
    _reject_unknown(value, SERVER_FIELDS, label)
    command = value.get("command")
    if not isinstance(command, str) or not command:
        raise McpConfigError(f"{label}.command must be a non-empty string")
    if not os.path.isabs(command):
        # An absolute path only: a name resolved through PATH lets whoever can change PATH decide which
        # program speaks for this server.
        raise McpConfigError(f"{label}.command must be an absolute path, not a name resolved through PATH")
    args = value.get("args", [])
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise McpConfigError(f"{label}.args must be a list of strings")
    secret_env = value.get("secret_env", [])
    if not isinstance(secret_env, list) or not all(isinstance(item, str) and _ENV_NAME.match(item) for item in secret_env):
        raise McpConfigError(f"{label}.secret_env must be a list of environment variable NAMES, not values")
    timeout = value.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise McpConfigError(f"{label}.timeout_seconds must be a number from 0 (exclusive) to {MAX_TIMEOUT_SECONDS}")
    raw_tools = value.get("tools")
    if not isinstance(raw_tools, dict) or not raw_tools:
        raise McpConfigError(f"{label}.tools must name at least one tool; there is no expose-everything switch")
    tools = {tool: _tool_from_spec(name, tool, spec) for tool, spec in raw_tools.items()}
    return McpServerConfig(name, command, tuple(args), tuple(secret_env), float(timeout), tools)


def config_from_bytes(raw: bytes, path: str = "") -> McpConfig:
    try:
        document = strict_json_loads(raw, max_bytes=MAX_CONFIG_BYTES)
    except StrictJSONError as error:
        raise McpConfigError(f"MCP config is not valid JSON: {error}") from error
    if not isinstance(document, dict):
        raise McpConfigError("MCP config must be a JSON object")
    _reject_unknown(document, ("schema", "servers"), "MCP config")
    if document.get("schema") != CONFIG_SCHEMA:
        raise McpConfigError(f"MCP config schema must be {CONFIG_SCHEMA!r}")
    raw_servers = document.get("servers")
    if not isinstance(raw_servers, dict) or not raw_servers:
        raise McpConfigError("MCP config needs a non-empty `servers` object")
    servers = {name: _server_from_spec(name, spec) for name, spec in raw_servers.items()}
    registered: dict[str, str] = {}
    for server in servers.values():
        for tool in server.tools.values():
            other = registered.get(tool.name)
            if other is not None:
                # Two servers exposing the same tool name would otherwise race for it; the operator decides
                # with an alias, rather than the load order deciding silently.
                raise McpConfigError(f"{tool.name!r} is claimed by both {other!r} and {tool.server!r}; give one an `alias`")
            registered[tool.name] = tool.server
    return McpConfig(servers, path)


def load_config(path: str) -> McpConfig:
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as error:
        raise McpConfigError(f"cannot read MCP config {path!r}: {error.strerror}") from error
    return config_from_bytes(raw, path)

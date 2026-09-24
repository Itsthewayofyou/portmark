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
from urllib.parse import urlsplit

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

# A server is reached EITHER by launching a program (stdio) OR over Streamable HTTP. The two sets of keys are
# mutually exclusive, so a config can never describe a server that is half one and half the other, and the
# error can name the transport it decided on.
STDIO_FIELDS = ("command", "args", "secret_env")
HTTP_FIELDS = ("url", "bearer_env", "allow_private", "oauth")
SERVER_FIELDS = (*STDIO_FIELDS, *HTTP_FIELDS, "timeout_seconds", "tools")
OAUTH_FIELDS = ("client_id_env", "client_secret_env", "token_store", "scopes")
TOOL_FIELDS = ("pin", "read_only", "reconcile", "alias")
STDIO = "stdio"
HTTP = "http"


class McpConfigError(ValueError):
    """A malformed or unsafe MCP configuration: the host does not start (CLI exit 2)."""


@dataclass(frozen=True)
class McpOAuthConfig:
    """How ONE server is authorized: names of variables and a path, never a secret.

    The operator registers an OAuth client with the service themselves and puts the resulting identifiers in
    the environment. Dynamic Client Registration is out of scope, which is also where the specification now
    points -- it marks DCR deprecated and puts pre-registered client information FIRST in its own priority
    order. Client ID Metadata Documents are out of scope too: they would require Portmark to HOST a public
    HTTPS document whose URL is the client id, which a self-hosted runtime generally cannot do."""

    client_id_env: str
    token_store: str
    client_secret_env: str = ""
    scopes: tuple[str, ...] = ()


def server_digest(server: "McpServerConfig") -> str:
    """How one server is REACHED: which program runs, or which endpoint is called, and under what terms.

    The host records this at start-up and the worker re-checks it, so editing the config file after approval
    cannot make an approved pin talk to a different program (Codex review R1) -- or, now, to a different
    endpoint. The `transport` discriminator is part of the body so a stdio and an HTTP binding can never
    produce the same digest. The bearer token's VALUE is deliberately absent: rotating the secret must not
    invalidate an approved pin, while repointing the config at a different variable must."""
    if server.transport == HTTP:
        body = {
            "transport": HTTP,
            "url": server.url,
            "bearer_env": server.bearer_env,
            "allow_private": server.allow_private,
            "timeout_seconds": server.timeout_seconds,
        }
        if server.oauth is not None:
            # Added ONLY when the server is actually OAuth-authorized, so every pin approved before this
            # feature existed keeps exactly the digest it was approved under. A key carrying `null` for the
            # servers that do not use it would re-digest all of them and read as drift on the next start-up.
            # Names and a path, never a token: rotating a credential must not invalidate an approved pin,
            # while repointing the config at a different variable, store or scope set must.
            body["oauth"] = {
                "client_id_env": server.oauth.client_id_env,
                "client_secret_env": server.oauth.client_secret_env,
                "token_store": server.oauth.token_store,
                "scopes": list(server.oauth.scopes),
            }
    else:
        body = {
            "transport": STDIO,
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
    command: str = ""
    args: tuple[str, ...] = ()
    secret_env: tuple[str, ...] = ()
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    tools: Mapping[str, McpToolConfig] = field(default_factory=dict)
    url: str = ""
    bearer_env: str = ""
    allow_private: bool = False
    oauth: McpOAuthConfig | None = None

    @property
    def transport(self) -> str:
        """`http` or `stdio`. The loader guarantees exactly one of `url` and `command` is set."""
        return HTTP if self.url else STDIO


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
    transport = _transport_of(value, label)
    _reject_foreign_keys(value, transport, label)
    command, args, secret_env = "", [], []
    url, bearer_env, allow_private = "", "", False
    oauth: McpOAuthConfig | None = None
    if transport == STDIO:
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
    else:
        allow_private = value.get("allow_private", False)
        if not isinstance(allow_private, bool):
            raise McpConfigError(f"{label}.allow_private must be true or false")
        url = _checked_url(value.get("url"), allow_private, label)
        bearer_env = value.get("bearer_env", "")
        if not isinstance(bearer_env, str) or (bearer_env and not _ENV_NAME.match(bearer_env)):
            raise McpConfigError(f"{label}.bearer_env must be the NAME of an environment variable, not a token")
        if bearer_env and url.startswith("http://"):
            # A token on a plaintext connection is a token anyone on the path can read and reuse.
            raise McpConfigError(f"{label} cannot send `bearer_env` over plain http; use https")
        if "oauth" in value:
            if bearer_env:
                # Two answers to one question. Which token travels would be decided by reading the code.
                raise McpConfigError(f"{label} sets both `bearer_env` and `oauth`: a server is authorized one way, not two")
            if not url.startswith("https://"):
                # Unlike the MCP endpoint, the specification DOES mandate https for the OAuth endpoints, and
                # an authorization code or refresh token on a plaintext hop is a durable credential in clear.
                raise McpConfigError(f"{label} cannot use `oauth` over plain http; the OAuth endpoints must be https")
            oauth = _oauth_from_spec(value["oauth"], f"{label}.oauth")
    timeout = value.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise McpConfigError(f"{label}.timeout_seconds must be a number from 0 (exclusive) to {MAX_TIMEOUT_SECONDS}")
    raw_tools = value.get("tools")
    if not isinstance(raw_tools, dict) or not raw_tools:
        raise McpConfigError(f"{label}.tools must name at least one tool; there is no expose-everything switch")
    tools = {tool: _tool_from_spec(name, tool, spec) for tool, spec in raw_tools.items()}
    return McpServerConfig(
        name, command, tuple(args), tuple(secret_env), float(timeout), tools, url, bearer_env, allow_private, oauth
    )


def _oauth_from_spec(value: Any, label: str) -> McpOAuthConfig:
    """The `oauth` block: variable NAMES, a store path, and the scopes to ask for."""
    if not isinstance(value, dict):
        raise McpConfigError(f"{label} must be an object")
    _reject_unknown(value, OAUTH_FIELDS, label)
    client_id_env = value.get("client_id_env")
    if not isinstance(client_id_env, str) or not _ENV_NAME.match(client_id_env):
        raise McpConfigError(f"{label}.client_id_env must be the NAME of an environment variable, not a client id")
    client_secret_env = value.get("client_secret_env", "")
    if not isinstance(client_secret_env, str) or (client_secret_env and not _ENV_NAME.match(client_secret_env)):
        raise McpConfigError(f"{label}.client_secret_env must be the NAME of an environment variable, not a secret")
    token_store = value.get("token_store")
    if not isinstance(token_store, str) or not token_store:
        raise McpConfigError(f"{label}.token_store must be a non-empty path")
    if "\x00" in token_store or any(character.isspace() and character != " " for character in token_store):
        raise McpConfigError(f"{label}.token_store must not contain NUL or control characters")
    if not os.path.isabs(token_store):
        # The host, the CLI and the worker each resolve this path from a different working directory. A
        # relative path would name a different file in each, and the one that mattered would be whichever
        # process wrote last.
        raise McpConfigError(f"{label}.token_store must be an absolute path")
    scopes = value.get("scopes", [])
    if not isinstance(scopes, list) or not all(isinstance(item, str) for item in scopes):
        raise McpConfigError(f"{label}.scopes must be a list of strings")
    for scope in scopes:
        # RFC 6749 scope-token: visible ASCII except space, double quote and backslash. Scopes travel
        # space-separated in a query string, so one containing a space would silently become two.
        if not scope or not all(0x21 <= ord(character) <= 0x7E and character not in '"\\' for character in scope):
            raise McpConfigError(f"{label}.scopes has an entry that is not a usable OAuth scope: {scope!r}")
    return McpOAuthConfig(client_id_env, token_store, client_secret_env, tuple(scopes))


def _transport_of(value: Mapping[str, Any], label: str) -> str:
    """Exactly one of `command` and `url`. Neither is not a default, and both is not a preference order."""
    has_command, has_url = "command" in value, "url" in value
    if has_command and has_url:
        raise McpConfigError(f"{label} sets both `command` and `url`: a server is reached one way, not two")
    if not has_command and not has_url:
        raise McpConfigError(f"{label} must set `command` (a program to launch) or `url` (a Streamable HTTP endpoint)")
    return STDIO if has_command else HTTP


def _reject_foreign_keys(value: Mapping[str, Any], transport: str, label: str) -> None:
    """A key that belongs to the OTHER transport is refused, never ignored: silently dropping `allow_private`
    from a stdio server, or `secret_env` from an HTTP one, would read as a setting that is in force."""
    foreign = HTTP_FIELDS if transport == STDIO else STDIO_FIELDS
    for key in foreign:
        if key in value:
            raise McpConfigError(f"{label} is a {transport} server, so it cannot set `{key}`")


def _checked_url(url: Any, allow_private: bool, label: str) -> str:
    """The MCP endpoint. HTTPS unless the operator has explicitly allowed a private address.

    The MCP specification states no TLS requirement for this endpoint -- HTTPS is mandated only for OAuth
    endpoints -- so this rule is Portmark's, not the specification's. A query or fragment is refused because
    the endpoint is a destination, not a request; the request is the POST body."""
    if not isinstance(url, str) or not url:
        raise McpConfigError(f"{label}.url must be a non-empty string")
    if any(character.isspace() or ord(character) < 0x20 for character in url):
        raise McpConfigError(f"{label}.url must not contain whitespace or control characters")
    try:
        split = urlsplit(url)
        port = split.port
    except ValueError as error:
        raise McpConfigError(f"{label}.url is not a usable URL: {error}") from error
    if split.scheme == "http":
        if not allow_private:
            raise McpConfigError(f"{label}.url must be https; plain http needs an explicit `allow_private: true`")
    elif split.scheme != "https":
        raise McpConfigError(f"{label}.url must be an https URL")
    if split.username is not None or split.password is not None:
        raise McpConfigError(f"{label}.url must not carry a username or password; use `bearer_env`")
    if split.query or split.fragment:
        raise McpConfigError(f"{label}.url must not carry a query string or fragment")
    if not split.hostname:
        raise McpConfigError(f"{label}.url must name a host")
    if port is not None and not 0 < port < 65536:
        raise McpConfigError(f"{label}.url has an out-of-range port")
    return url


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

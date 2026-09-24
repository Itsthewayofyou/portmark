"""The isolated-worker side of an MCP tool call (MCP/SIEM plan, PR 2).

`portmark.mcp_worker:call` is the `register_isolated` target of every MCP tool. It runs INSIDE the
deadline-bounded worker the host spawns, so the MCP server it starts is a descendant of a process tree the
host can hard-kill -- the same containment every isolated tool has. Nothing here decides authority: the
permit, the policy, the constraints and the effect ledger were applied before this process existed.

Which server and tool this call is for travels in the worker's environment, together with the pin the
operator approved. The pin is re-checked HERE, against what the server reports right now, so a definition
that changed after startup fails this call rather than being noticed at the next restart. See MCP.md.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 - launches the operator's configured MCP server, absolute path, no shell
import sys
from typing import Any

from .mcp_client import CONFIG_DRIFT, PIN_DRIFT, PROTOCOL_ERROR, TRANSPORT_ERROR, McpClient, McpError
from .mcp_config import (
    HTTP,
    McpServerConfig,
    McpToolConfig,
    definition_digest,
    load_config,
    request_timeout,
    server_digest,
)

CONFIG_ENV = "PORTMARK_MCP_CONFIG"
LAUNCH_ENV = "PORTMARK_MCP_LAUNCH"
SERVER_ENV = "PORTMARK_MCP_SERVER"
TOOL_ENV = "PORTMARK_MCP_TOOL"
PIN_ENV = "PORTMARK_MCP_PIN"
VERSION_ENV = "PORTMARK_MCP_CLIENT_VERSION"
# What the server process inherits, on top of the operator's `secret_env`: nothing that identifies Portmark's
# own configuration, and no credential the operator did not name.
_SERVER_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "TMPDIR", "TEMP", "HOME", "USERPROFILE")


class _WorkerError(McpError):
    """An McpError that carries its code to the host through the worker reply (tools.tool_error_code)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message)
        self.portmark_error_code = self.code


def _fail(code: str, message: str) -> _WorkerError:
    return _WorkerError(code, message)


def _settings() -> tuple[McpServerConfig, McpToolConfig]:
    path, server_name, tool_name, pin, launch = (
        os.environ.get(key, "") for key in (CONFIG_ENV, SERVER_ENV, TOOL_ENV, PIN_ENV, LAUNCH_ENV)
    )
    if not (path and server_name and tool_name and pin and launch):
        raise _fail(PROTOCOL_ERROR, "the MCP worker was started without its server, tool, pin and launch digest")
    config = load_config(path)
    server = config.servers.get(server_name)
    tool = server.tools.get(tool_name) if server is not None else None
    if server is None or tool is None:
        raise _fail(CONFIG_DRIFT, f"the MCP config no longer defines {server_name}.{tool_name}")
    if tool.pin != pin:
        # The config file changed after the host approved this tool at startup. The pin in the environment is
        # the approved one, so this call fails rather than running under a pin nobody approved.
        raise _fail(CONFIG_DRIFT, f"the pin of {server_name}.{tool_name} changed since the host started")
    if server_digest(server) != launch:
        # The pin approves a tool DEFINITION; it says nothing about which program produces it. Without this,
        # rewriting `command` in the config would run another program under an approved pin, and that program
        # could simply report the pinned definition (Codex review R1).
        raise _fail(CONFIG_DRIFT, f"the launch configuration of MCP server {server_name!r} changed since the host started")
    return server, tool


def _server_environment(server: McpServerConfig) -> dict[str, str]:
    environment = {key: os.environ[key] for key in _SERVER_ENV_KEYS if key in os.environ}
    for name in server.secret_env:
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _launch(server: McpServerConfig) -> subprocess.Popen[bytes]:
    try:
        return subprocess.Popen(  # nosec B603 - absolute path from the operator's config, list argv, no shell
            [server.command, *server.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,  # the spec says stderr is logging, not an error signal
            env=_server_environment(server),
            close_fds=True,
        )
    except OSError as error:
        raise _fail(TRANSPORT_ERROR, f"could not start the MCP server: {error.strerror}") from error


def _shutdown(process: subprocess.Popen[bytes]) -> None:
    """The specification's shutdown: close stdin, wait, then terminate. The host's tree-kill is the backstop.

    stdout is closed LAST, after the process is gone. Closing it while the reader thread is blocked inside a
    read waits for that thread's buffer lock, which the read only releases at end of stream -- a deadlock the
    deadline would have to break."""
    try:
        if process.stdin is not None:
            process.stdin.close()
    except OSError:
        pass
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        try:
            process.terminate()
            process.wait(timeout=2.0)
        except (subprocess.TimeoutExpired, OSError):
            try:
                process.kill()
                process.wait(timeout=2.0)
            except (subprocess.TimeoutExpired, OSError):  # pragma: no cover - the host's tree-kill follows
                pass
    try:
        if process.stdout is not None:
            process.stdout.close()
    except OSError:  # pragma: no cover - already closed
        pass


def _stored_access_token(server: McpServerConfig) -> str:
    """The access token for an `oauth` server, read from the store. No SDK, and NO renewal.

    This runs inside the isolated worker, and that is the whole reason it may not renew anything: renewing
    drives the `mcp` SDK, whose 28 packages include a web-server framework, and keeping those out of the
    sandbox is why the token logic lives in the host at all. The worker reads a string -- exactly as
    `bearer_env` gives it one -- and refuses a stale one rather than sending it.

    The store is kept current by `mcp.TokenRefresher` in the host, which renews further ahead of expiry than
    the margin this refusal uses -- so under a running host a stale token here means the renewal itself is
    failing, and this refusal is the report of that."""
    from .mcp_token_store import TokenStoreError, client_mismatch, read_tokens  # noqa: PLC0415 - oauth only

    oauth = server.oauth
    assert oauth is not None  # nosec B101 - the only caller checks, and mypy needs it said
    try:
        stored = read_tokens(oauth.token_store)
    except TokenStoreError as error:
        raise _fail(TRANSPORT_ERROR, f"the OAuth token store for {server.name!r} is unusable: {error}") from None
    if stored is None:
        raise _fail(
            TRANSPORT_ERROR,
            f"there is no stored authorization for MCP server {server.name!r}: "
            f"run `portmark mcp login {server.name}`",
        )
    # The store records which client the tokens were issued TO. If the operator re-pointed `client_id_env`
    # at a different application, the stored token belongs to the old one and must not be sent to the new
    # one's account. Checked only when the host passed the value through, since a name the host does not
    # have is absent rather than empty.
    configured = os.environ.get(oauth.client_id_env, "")
    mismatch = client_mismatch(stored, configured) if configured else None
    if mismatch:
        raise _fail(TRANSPORT_ERROR, mismatch)
    if not stored.fresh():
        raise _fail(
            TRANSPORT_ERROR,
            f"the stored access token for MCP server {server.name!r} has expired, and the isolated worker "
            "never renews one; restart the host to refresh it, or run `portmark mcp login "
            f"{server.name}` if the refresh token is gone too",
        )
    return stored.access_token


def _connect_http(server: McpServerConfig) -> tuple[None, McpClient]:
    """One MCP endpoint over Streamable HTTP. No process, and deliberately NO restart of any kind.

    The stdio path relaunches a server that exited on the era probe. There is nothing to relaunch here, and a
    second POST after an ambiguous first one is a replay: the server may already have acted on it. Era
    selection is decided entirely by what the endpoint answered."""
    from .mcp_http import HttpTransport  # noqa: PLC0415 - only an HTTP server pays for http.client and ssl

    transport = HttpTransport(
        server.url,
        request_timeout(server.timeout_seconds),
        server.timeout_seconds,
        server.bearer_env,
        os.environ.get(server.bearer_env) if server.bearer_env else None,
        server.allow_private,
        bearer_token=_stored_access_token(server) if server.oauth is not None else "",
    )
    client = McpClient(transport, request_timeout(server.timeout_seconds), os.environ.get(VERSION_ENV, ""))
    try:
        client.connect_http()
    except McpError as error:
        client.close()
        raise _WorkerError(error.code, str(error)) from error
    return None, client


def _connect(server: McpServerConfig) -> tuple[subprocess.Popen[bytes] | None, McpClient]:
    """Reach the server and agree a protocol version, restarting a LAUNCHED one if the probe killed it.

    The stdio binding's own fallback rules assume the probe may be answered by silence or an error -- but some
    legacy servers simply EXIT on an unknown pre-`initialize` request. Talking `initialize` to that dead
    process would report a transport failure for a server that is merely old, so the second attempt gets a
    fresh process and skips the probe (Codex review R2)."""
    if server.transport == HTTP:
        return _connect_http(server)
    process = _launch(server)
    if process.stdin is None or process.stdout is None:
        _shutdown(process)
        raise _fail(TRANSPORT_ERROR, "the MCP server has no usable standard streams")
    version = os.environ.get(VERSION_ENV, "")
    client = McpClient.over_streams(process.stdin, process.stdout, request_timeout(server.timeout_seconds), version)
    try:
        client.connect()
        return process, client
    except McpError as error:
        exited = process.poll() is not None
        _shutdown(process)
        if not (exited or client.peer_closed):
            # Carry the code out of the connect phase too: a silent or malformed server must reach the host
            # as `mcp_transport_error`/`mcp_protocol_error`, not as an unlabelled failure.
            raise _WorkerError(error.code, str(error)) from error
    process = _launch(server)
    if process.stdin is None or process.stdout is None:
        _shutdown(process)
        raise _fail(TRANSPORT_ERROR, "the MCP server has no usable standard streams")
    client = McpClient.over_streams(process.stdin, process.stdout, request_timeout(server.timeout_seconds), version)
    try:
        client.connect_legacy()
    except McpError as error:
        _shutdown(process)
        raise _WorkerError(error.code, str(error)) from error
    return process, client


def _release(process: "subprocess.Popen[bytes] | None", client: McpClient) -> None:
    """Let go of whatever was opened. An HTTP endpoint has no process to stop."""
    client.close()
    if process is not None:
        _shutdown(process)


def call(arguments: dict[str, Any], effect_id: str | None = None) -> Any:
    """Call the configured MCP tool once. `effect_id` is accepted (and deliberately not sent).

    MCP has no idempotency key, so passing Portmark's would invent a meaning the server does not have. The
    ledger still records the effect as `unknown` on a failure, and the operator's reconcile settles it."""
    server, tool = _settings()
    process, client = _connect(server)
    try:
        definitions = client.list_tools()
        definition = definitions.get(tool.tool)
        if definition is None:
            reason = client.rejected.get(tool.tool)
            if reason:
                # Excluded, not missing. Saying so points the operator at the definition, not at the pin.
                raise _fail(PROTOCOL_ERROR, f"the MCP server's definition of {tool.tool!r} is unusable: {reason}")
            raise _fail(PIN_DRIFT, f"the MCP server no longer offers {tool.tool!r}")
        digest = definition_digest(definition)
        if digest != tool.pin:
            raise _fail(PIN_DRIFT, f"the definition of {tool.tool!r} changed since the operator approved it")
        result = client.call_tool(tool.tool, arguments)
        if result.is_error:
            # The tool ran and reported failure. That is not a transport failure, and the difference decides
            # whether an operator hunts a broken connection or a rejected request.
            raise _WorkerError("mcp_tool_error", f"the MCP tool {tool.tool!r} reported an error")
        return result.value
    except McpError as error:
        raise _WorkerError(error.code, str(error)) from error
    finally:
        _release(process, client)


def discover(arguments: dict[str, Any]) -> Any:
    """List one server's tools with their current digests, for `portmark mcp pin`. Never approves anything."""
    server_name = arguments.get("server")
    path = arguments.get("config")
    if not isinstance(server_name, str) or not isinstance(path, str):
        raise _fail(PROTOCOL_ERROR, "discover needs a config path and a server name")
    config = load_config(path)
    server = config.servers.get(server_name)
    if server is None:
        raise _fail(PROTOCOL_ERROR, f"the MCP config has no server {server_name!r}")
    process, client = _connect(server)
    try:
        version = client.version
        definitions = client.list_tools()
        return {
            "server": server_name,
            "protocol_version": version,
            "tools": {name: definition_digest(definition) for name, definition in sorted(definitions.items())},
            # Carried so `check_pins` can say an annotation is invalid, rather than "the tool is gone".
            "rejected": dict(sorted(client.rejected.items())),
        }
    except McpError as error:
        raise _WorkerError(error.code, str(error)) from error
    finally:
        _release(process, client)


def tool_environment(config_path: str, server: McpServerConfig, tool: McpToolConfig, version: str = "") -> dict[str, str]:
    """The small, non-secret identifiers the worker needs. Secrets travel only through `secret_env`.

    An `oauth` server's token STORE PATH is not carried here: the worker re-reads the config by path and
    finds it there, which keeps one description of where the tokens live."""
    environment = {
        CONFIG_ENV: os.path.abspath(config_path),
        SERVER_ENV: tool.server,
        TOOL_ENV: tool.tool,
        PIN_ENV: tool.pin,
        LAUNCH_ENV: server_digest(server),
    }
    if version:
        environment[VERSION_ENV] = version
    return environment


if __name__ == "__main__":  # `python -m portmark.mcp_worker <config> <server>`
    import json

    from .tool_subprocess_runner import _sweep_own_process_group

    # Both outcomes are JSON on STDOUT: the caller launches this through the tree launcher, which discards
    # stderr, so a failure reported there would reach nobody (Codex review R2).
    status = 0
    try:
        print(json.dumps(discover({"config": sys.argv[1], "server": sys.argv[2]}), indent=2, sort_keys=True))
    except BaseException as failure:  # noqa: BLE001 - the probe reports every failure the same way
        print(json.dumps({"error": f"{type(failure).__name__}: {failure}"[:500]}))
        status = 1
    # The report must be in the pipe BEFORE the sweep, because the sweep kills this process (Codex R3).
    sys.stdout.flush()
    # A tool CALL runs inside tool_subprocess_runner, which sweeps its own process group before exiting; this
    # probe is launched directly, so it has to do the same. Without it, a background child the MCP server left
    # behind survives a NORMAL probe exit: the parent's killpg is skipped once the probe process is reaped.
    # The sweep exits this process by SIGKILL, which is why `_probe_report` accepts that as a clean end.
    _sweep_own_process_group()
    sys.exit(status)

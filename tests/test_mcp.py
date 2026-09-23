"""MCP tools over stdio (MCP/SIEM plan, PR 2).

Portmark is an MCP client, not a gateway: an MCP tool is an ordinary isolated tool, so it keeps the deadline,
the tree-kill, the effect ledger and the audit chain. What is new is the wire (two protocol eras), the pin
that approves a tool definition, and the rule that nothing the server says is authority.
"""

import base64
import datetime
import io
import json
import os
import ssl
import subprocess  # nosec B404 - launches this test's own fake MCP server
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from portmark.cli import main as cli_main
from portmark.factory import build_envelope, make_host
from portmark.mcp import CALL_TARGET, McpStartupError, check_pins, pin_report, probe_server, register_mcp_tools
from portmark.mcp_client import (
    LEGACY_VERSION,
    MODERN_VERSION,
    AnnotationError,
    McpClient,
    McpError,
    header_value,
    mirror_annotations,
)
from portmark.mcp_http import HttpTransport, resolve_endpoint_address
from portmark import mcp_worker
from portmark.mcp_config import (
    McpConfigError,
    config_from_bytes,
    definition_digest,
    load_config,
    server_digest,
)

import mcp_http_server
from portmark.models import Permit, ToolGrant
from portmark.providers import ProviderDecision
from portmark.security import EnvelopeSigner
from portmark.storage import InMemoryRuntimeStore
from portmark.tools import IsolationMechanism, IsolationProfile, ToolExecutionError, ToolRegistry, tool_error_code

FAKE_SERVER = str(Path(__file__).parent / "mcp_fake_server.py")
HOST = "host:mcp"


def permit_for(*names):
    return Permit(
        issuer="user:a", subject="agent:a", audience=HOST, expires_at=2 ** 40, nonce="n",
        grants=tuple(ToolGrant(name) for name in names),
    )


def _alive(pid):
    """Whether that process is still RUNNING.

    A killed child whose parent is gone is reparented, and in a container with no init it is never reaped, so
    it stays as a zombie -- and a zombie answers signal 0 exactly like a live process. On Linux the process
    state is authoritative, so read it; elsewhere fall back to the signal probe."""
    status = Path(f"/proc/{pid}/stat")
    if status.exists():
        try:
            fields = status.read_text(encoding="utf-8", errors="replace").rsplit(") ", 1)[-1].split()
            return bool(fields) and fields[0] != "Z"
        except OSError:  # pragma: no cover - it exited between the check and the read
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:  # pragma: no cover - a permission error means it is still there
        return True
    return True


def launch(mode):
    return subprocess.Popen(  # nosec B603 - this interpreter, this test's own script
        [sys.executable, FAKE_SERVER, mode], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )


class ClientTests(unittest.TestCase):
    """The wire: both eras, and every misbehaviour a server could put on stdout."""

    def client(self, mode, timeout=5.0):
        process = launch(mode)
        self.addCleanup(self._stop, process)
        return McpClient.over_streams(process.stdin, process.stdout, timeout)

    def _stop(self, process):
        # Kill first, close after: closing stdout while the client's reader thread is blocked on it would
        # wait for that thread's buffer lock (the deadlock this order exists to avoid).
        process.kill()
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                stream.close()

    def test_a_modern_server_needs_no_handshake(self):
        client = self.client("modern")
        self.assertEqual(client.connect(), MODERN_VERSION)
        self.assertEqual(sorted(client.list_tools()), ["read_file", "write_file"])
        result = client.call_tool("read_file", {"path": "sample.txt"})
        self.assertFalse(result.is_error)
        self.assertEqual(result.value["content"][0]["text"], 'read_file:{"path": "sample.txt"}')

    def test_a_legacy_server_falls_back_to_initialize(self):
        client = self.client("legacy")
        self.assertEqual(client.connect(), LEGACY_VERSION)
        # A legacy result has no resultType, which the specification says to read as "complete".
        self.assertEqual(sorted(client.list_tools()), ["read_file", "write_file"])
        self.assertFalse(client.call_tool("read_file", {}).is_error)

    def test_an_unsupported_version_is_retried_not_treated_as_legacy(self):
        # The server answers the probe with UnsupportedProtocolVersionError listing 2025-06-18, and then
        # accepts only that revision -- so the version it advertised must be the one Portmark asks for.
        client = self.client("unsupported")
        self.assertEqual(client.connect(), LEGACY_VERSION)
        self.assertEqual(sorted(client.list_tools()), ["read_file", "write_file"])

    def test_a_server_to_client_request_is_refused(self):
        client = self.client("server_request")
        client.connect()
        with self.assertRaises(McpError) as raised:
            client.call_tool("read_file", {})
        self.assertEqual(raised.exception.code, "mcp_protocol_error")

    def test_malformed_and_oversized_messages_are_refused(self):
        for mode, code in (("not_json", "mcp_protocol_error"), ("big", "mcp_transport_error")):
            with self.subTest(mode):
                client = self.client(mode)
                client.connect()
                with self.assertRaises(McpError) as raised:
                    client.list_tools()
                self.assertEqual(raised.exception.code, code)

    def test_a_frame_that_never_ends_is_bounded(self):
        # The size check has to bound the frame while it arrives: a server that never sends a newline would
        # otherwise grow the buffer until the machine runs out of memory (Codex review R1).
        client = self.client("flood", timeout=10.0)
        client.connect()
        with self.assertRaises(McpError) as raised:
            client.list_tools()
        self.assertEqual(raised.exception.code, "mcp_transport_error")
        self.assertIn("exceeded", str(raised.exception))

    def test_a_legacy_server_is_asked_for_the_newest_legacy_revision(self):
        client = self.client("legacy_new")
        self.assertEqual(client.connect(), "2025-11-25")
        self.assertEqual(sorted(client.list_tools()), ["read_file", "write_file"])

    def test_an_answer_with_the_wrong_id_is_refused(self):
        client = self.client("wrong_id")
        client.connect()
        with self.assertRaises(McpError) as raised:
            client.list_tools()
        self.assertEqual(raised.exception.code, "mcp_protocol_error")

    def test_an_unsupported_counter_offer_is_refused(self):
        # The 2025-11-25 schema says a client that cannot support the answered revision MUST disconnect.
        client = self.client("bad_version")
        with self.assertRaises(McpError) as raised:
            client.connect()
        self.assertEqual(raised.exception.code, "mcp_protocol_error")
        self.assertIn("1999-01-01", str(raised.exception))

    def test_a_silent_server_times_out_instead_of_hanging(self):
        client = self.client("hang", timeout=1.0)
        with self.assertRaises(McpError) as raised:
            client.list_tools()
        self.assertEqual(raised.exception.code, "mcp_transport_error")

    def test_input_required_is_a_tool_failure_not_a_conversation(self):
        client = self.client("input_required")
        client.connect()
        with self.assertRaises(McpError) as raised:
            client.call_tool("read_file", {})
        self.assertEqual(raised.exception.code, "mcp_tool_error")

    def test_is_error_is_reported_as_the_server_said_it(self):
        client = self.client("tool_error")
        client.connect()
        self.assertTrue(client.call_tool("read_file", {}).is_error)

    def test_non_text_blocks_are_named_but_never_carried(self):
        client = self.client("blocks")
        client.connect()
        value = client.call_tool("read_file", {}).value
        self.assertEqual(value["structured_content"], {"read": True})
        self.assertEqual(value["content"], [{"type": "text", "text": "ok"}, {"type": "image", "omitted": True}])
        self.assertNotIn("A" * 100, json.dumps(value))


class ConfigTests(unittest.TestCase):
    BASE = {
        "schema": "portmark.mcp.config.v1",
        "servers": {"files": {"command": sys.executable, "tools": {"read_file": {"pin": "sha256:" + "a" * 64, "read_only": True}}}},
    }

    def load(self, document):
        return config_from_bytes(json.dumps(document).encode())

    def test_a_valid_config_registers_namespaced_names(self):
        config = self.load(self.BASE)
        self.assertEqual([tool.name for tool in config.tools()], ["mcp.files.read_file"])

    def test_an_alias_replaces_the_generated_name(self):
        document = json.loads(json.dumps(self.BASE))
        document["servers"]["files"]["tools"]["read_file"]["alias"] = "files.read"
        self.assertEqual([tool.name for tool in self.load(document).tools()], ["files.read"])

    def http(self, **server_changes):
        tools = {"read_file": {"pin": "sha256:" + "a" * 64, "read_only": True}}
        return {
            "schema": "portmark.mcp.config.v1",
            "servers": {"files": {"url": "https://mcp.example.com/mcp", "tools": tools, **server_changes}},
        }

    def test_an_http_server_loads_and_reports_its_transport(self):
        config = self.load(self.http(bearer_env="MCP_TOKEN", allow_private=False))
        server = config.servers["files"]
        self.assertEqual(server.transport, "http")
        self.assertEqual(server.bearer_env, "MCP_TOKEN")
        self.assertEqual([tool.name for tool in config.tools()], ["mcp.files.read_file"])

    def test_http_refusals(self):
        cases = {
            "both transports": {**self.http(), "servers": {"files": {
                "command": sys.executable, "url": "https://x.test/mcp",
                "tools": {"read_file": {"pin": "sha256:" + "a" * 64, "read_only": True}},
            }}},
            "neither transport": {**self.http(), "servers": {"files": {
                "tools": {"read_file": {"pin": "sha256:" + "a" * 64, "read_only": True}},
            }}},
            "plain http without allow_private": self.http(url="http://mcp.example.com/mcp"),
            "a bearer over plain http": self.http(url="http://127.0.0.1:9/mcp", allow_private=True, bearer_env="T"),
            "a stdio key on an http server": self.http(secret_env=["T"]),
            "a token instead of a variable name": self.http(bearer_env="sk-live-abc"),
            "userinfo in the url": self.http(url="https://user:pw@mcp.example.com/mcp"),
            "a query string": self.http(url="https://mcp.example.com/mcp?a=1"),
            "a fragment": self.http(url="https://mcp.example.com/mcp#x"),
            "a non-http scheme": self.http(url="ftp://mcp.example.com/mcp"),
            "whitespace in the url": self.http(url="https://mcp.example.com/m cp"),
            "allow_private is not a string": self.http(allow_private="yes"),
        }
        for label, document in cases.items():
            with self.subTest(label):
                with self.assertRaises(McpConfigError):
                    self.load(document)

    def test_an_http_key_on_a_stdio_server_is_refused(self):
        document = json.loads(json.dumps(self.BASE))
        document["servers"]["files"]["allow_private"] = True
        with self.assertRaises(McpConfigError):
            self.load(document)

    def test_the_launch_digest_binds_the_endpoint_not_the_token(self):
        # Rotating the secret must not invalidate an approved pin; repointing the config must.
        base = self.load(self.http(bearer_env="MCP_TOKEN")).servers["files"]
        same = self.load(self.http(bearer_env="MCP_TOKEN")).servers["files"]
        moved = self.load(self.http(url="https://other.example.com/mcp", bearer_env="MCP_TOKEN")).servers["files"]
        renamed = self.load(self.http(bearer_env="OTHER_TOKEN")).servers["files"]
        self.assertEqual(server_digest(base), server_digest(same))
        self.assertNotEqual(server_digest(base), server_digest(moved))
        self.assertNotEqual(server_digest(base), server_digest(renamed))
        # A stdio server and an http server can never collide, whatever their fields.
        self.assertNotEqual(server_digest(base), server_digest(self.load(self.BASE).servers["files"]))

    def test_the_digest_ignores_protocol_meta_only(self):
        definition = {"name": "t", "description": "d", "inputSchema": {"type": "object"}}
        self.assertEqual(definition_digest(definition), definition_digest({**definition, "_meta": {"x": 1}}))
        self.assertNotEqual(definition_digest(definition), definition_digest({**definition, "description": "d2"}))
        self.assertNotEqual(definition_digest(definition), definition_digest({**definition, "icons": []}))

    def test_refusals(self):
        def with_tool(**changes):
            document = json.loads(json.dumps(self.BASE))
            document["servers"]["files"]["tools"]["read_file"].update(changes)
            return document

        def with_server(**changes):
            document = json.loads(json.dumps(self.BASE))
            document["servers"]["files"].update(changes)
            return document

        cases = {
            "unknown top key": {**self.BASE, "extra": 1},
            "wrong schema": {**self.BASE, "schema": "x"},
            "no servers": {"schema": "portmark.mcp.config.v1", "servers": {}},
            "relative command": with_server(command="mcp-files"),
            "unknown server key": with_server(note="x"),
            "no tools": with_server(tools={}),
            "secret value not name": with_server(secret_env=["TOKEN=abc"]),
            "timeout too large": with_server(timeout_seconds=10_000),
            "timeout zero": with_server(timeout_seconds=0),
            "bad pin": with_tool(pin="deadbeef"),
            "unknown tool key": with_tool(note="x"),
            "read_only with reconcile": with_tool(reconcile="m:f"),
            "side-effecting without reconcile": with_tool(read_only=False),
            "reconcile names an mcp tool": with_tool(read_only=False, reconcile="read_file"),
            "alias is not a valid tool name": with_tool(alias="files read"),
            "server name too long": {"schema": "portmark.mcp.config.v1", "servers": {"s" * 40: self.BASE["servers"]["files"]}},
            "server tool name with a space": {"schema": "portmark.mcp.config.v1", "servers": {"files": {
                "command": sys.executable, "tools": {"read file": {"pin": "sha256:" + "a" * 64, "read_only": True}}}}},
        }
        for label, document in cases.items():
            with self.subTest(label):
                with self.assertRaises(McpConfigError):
                    self.load(document)
    def test_a_name_portmark_cannot_register_is_refused_never_trimmed(self):
        # MCP allows a tool name to start or end on punctuation; Portmark does not, and it will not quietly
        # trim one. (Length never reaches here: a 32-character server plus a 128-character tool fits in 192.)
        document = {"schema": "portmark.mcp.config.v1", "servers": {"files": {
            "command": sys.executable, "tools": {"hidden.": {"pin": "sha256:" + "a" * 64, "read_only": True}}}}}
        with self.assertRaises(McpConfigError) as raised:
            self.load(document)
        self.assertIn("alias", str(raised.exception))
        document["servers"]["files"]["tools"]["hidden."]["alias"] = "files.hidden"
        self.assertEqual([tool.name for tool in self.load(document).tools()], ["files.hidden"])

    def test_two_servers_cannot_claim_one_registered_name(self):
        document = json.loads(json.dumps(self.BASE))
        document["servers"]["other"] = {
            "command": sys.executable,
            "tools": {"x": {"pin": "sha256:" + "b" * 64, "read_only": True, "alias": "mcp.files.read_file"}},
        }
        with self.assertRaises(McpConfigError):
            self.load(document)


class RecordingProvider:
    """Proposes the MCP tool once, then completes; records exactly what the host showed it."""

    def __init__(self, tool):
        self.tool = tool
        self.seen = []

    def decide(self, view, available_tools):
        self.seen.append({"tools": list(available_tools), "view": repr(view)})
        results = getattr(view, "tool_results", {}) or {}
        if self.tool in results:
            return ProviderDecision(kind="complete", content={"done": True})
        return ProviderDecision(kind="tool", tool=self.tool, arguments={"path": "sample.txt"})


class EndToEndTests(unittest.TestCase):
    """The worker path: a real fake server, launched per call inside the isolated worker."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)
        self.config_path = self.root / "mcp.json"

    def tearDown(self):
        self._dir.cleanup()

    def write_config(self, mode="modern", pins=None, **tool_changes):
        tools = {"read_file": {"pin": (pins or {}).get("read_file", "sha256:" + "a" * 64), "read_only": True}}
        tools["read_file"].update(tool_changes)
        document = {
            "schema": "portmark.mcp.config.v1",
            "servers": {"files": {
                "command": sys.executable, "args": [FAKE_SERVER, mode], "timeout_seconds": 4, "tools": tools,
            }},
        }
        self.config_path.write_text(json.dumps(document), encoding="utf-8")
        return self.config_path

    def approved_config(self, mode="modern", **tool_changes):
        """Probe the live server, paste its pins in, and load the config -- the operator's own flow."""
        self.write_config(mode, **tool_changes)
        report = probe_server(str(self.config_path), "files", timeout=30)
        self.write_config(mode, pins={"read_file": report.tools["read_file"]}, **tool_changes)
        return load_config(str(self.config_path))

    def registry(self, config, profile=False):
        registry = ToolRegistry(
            isolation_profile=IsolationProfile(IsolationMechanism.EXTERNAL_CONTAINER, "test") if profile else None
        )
        register_mcp_tools(registry, config)
        return registry

    def test_pins_are_taken_from_the_live_server_and_then_enforced(self):
        config = self.approved_config()
        self.assertEqual(check_pins(config, timeout=30)[0].protocol_version, MODERN_VERSION)
        registry = self.registry(config)
        self.assertEqual(registry.names(), ("mcp.files.read_file",))
        result = registry.invoke(permit_for("mcp.files.read_file"), "mcp.files.read_file", {"path": "sample.txt"})
        self.assertEqual(result["content"][0]["text"], 'read_file:{"path": "sample.txt"}')

    def test_a_changed_definition_fails_startup_and_the_call(self):
        config = self.approved_config()
        drifted = self.write_config("drift", pins={"read_file": config.servers["files"].tools["read_file"].pin})
        drifted_config = load_config(str(drifted))
        with self.assertRaises(McpStartupError):
            check_pins(drifted_config, timeout=30)
        registry = self.registry(drifted_config)
        with self.assertRaises(ToolExecutionError) as raised:
            registry.invoke(permit_for("mcp.files.read_file"), "mcp.files.read_file", {"path": "sample.txt"})
        self.assertEqual(tool_error_code(raised.exception), "mcp_pin_drift")

    def test_a_missing_tool_is_pin_drift_too(self):
        config = self.approved_config()
        gone = load_config(str(self.write_config("gone", pins={"read_file": config.servers["files"].tools["read_file"].pin})))
        with self.assertRaises(McpStartupError):
            check_pins(gone, timeout=30)

    def test_a_tool_that_vanished_is_pin_drift_at_call_time(self):
        config = self.approved_config()
        pin = config.servers["files"].tools["read_file"].pin
        gone = load_config(str(self.write_config("gone", pins={"read_file": pin})))
        registry = self.registry(gone)
        with self.assertRaises(ToolExecutionError) as raised:
            registry.invoke(permit_for("mcp.files.read_file"), "mcp.files.read_file", {"path": "sample.txt"})
        self.assertEqual(tool_error_code(raised.exception), "mcp_pin_drift")

    def test_changing_the_launch_command_after_approval_is_refused(self):
        # The pin approves a tool DEFINITION, not the program that reports it. Rewriting `command` in the
        # config after start-up must not let an approved pin launch something else (Codex review R1).
        config = self.approved_config()
        pin = config.servers["files"].tools["read_file"].pin
        registry = self.registry(config)
        document = json.loads(self.config_path.read_text())
        document["servers"]["files"]["args"] = [FAKE_SERVER, "blocks"]  # a different program's arguments
        self.config_path.write_text(json.dumps(document), encoding="utf-8")
        self.assertEqual(config.servers["files"].tools["read_file"].pin, pin)
        with self.assertRaises(ToolExecutionError) as raised:
            registry.invoke(permit_for("mcp.files.read_file"), "mcp.files.read_file", {"path": "sample.txt"})
        self.assertEqual(tool_error_code(raised.exception), "mcp_config_drift")

    def test_a_tool_cannot_report_a_code_its_registration_did_not_allow(self):
        # Any isolated tool can RAISE with a shaped code; only a code its registration allows may reach the
        # host, or an unrelated tool could forge an MCP security classification (Codex review R1).
        worker_path = {"PYTHONPATH": os.pathsep.join([str(Path(__file__).parent.parent / "src"), str(Path(__file__).parent)])}
        registry = ToolRegistry()
        registry.register_isolated("forger", "isolated_tool_fixtures:forge_error_code", env=worker_path)
        with self.assertRaises(ToolExecutionError) as raised:
            registry.invoke(permit_for("forger"), "forger", {})
        self.assertIsNone(tool_error_code(raised.exception))
        registry.register_isolated(
            "allowed", "isolated_tool_fixtures:forge_error_code", env=worker_path, error_codes=("mcp_pin_drift",)
        )
        with self.assertRaises(ToolExecutionError) as raised:
            registry.invoke(permit_for("allowed"), "allowed", {})
        self.assertEqual(tool_error_code(raised.exception), "mcp_pin_drift")

    def test_a_legacy_server_that_exits_on_the_probe_still_works(self):
        # The probe is a pre-`initialize` request, and some legacy servers exit on one. The second attempt
        # gets a FRESH process and skips the probe (Codex review R2).
        config = self.approved_config()
        pin = config.servers["files"].tools["read_file"].pin
        exiting = load_config(str(self.write_config("legacy_exit", pins={"read_file": pin})))
        registry = self.registry(exiting)
        result = registry.invoke(permit_for("mcp.files.read_file"), "mcp.files.read_file", {"path": "sample.txt"})
        self.assertEqual(result["content"][0]["text"], 'read_file:{"path": "sample.txt"}')

    @unittest.skipUnless(os.name == "posix", "os.kill(pid, 0) TERMINATES a process on Windows")
    def test_a_probe_that_times_out_takes_the_server_with_it(self):
        # Killing only the probe process would leave the MCP server it started running with nobody to stop it.
        marker = self.root / "server.json"
        self.write_config("sleeper")
        document = json.loads(self.config_path.read_text())
        document["servers"]["files"]["secret_env"] = ["FAKE_MCP_MARKER_FILE"]
        self.config_path.write_text(json.dumps(document), encoding="utf-8")
        with patch.dict(os.environ, {"FAKE_MCP_MARKER_FILE": str(marker)}):
            with self.assertRaises(McpStartupError) as raised:
                probe_server(str(self.config_path), "files", timeout=3)
        self.assertIn("timed out", str(raised.exception))
        pid = json.loads(marker.read_text())["pid"]
        for _ in range(100):  # the kill is asynchronous; wait briefly for the process to disappear
            if not _alive(pid):
                break
            time.sleep(0.05)
        self.assertFalse(_alive(pid), "the MCP server outlived the probe that started it")

    @unittest.skipUnless(os.name == "posix", "os.kill(pid, 0) TERMINATES a process on Windows")
    def test_a_normal_probe_sweeps_the_server_background_children(self):
        # The TIMEOUT path is covered above. This is the NORMAL path: the probe answered, the worker exited by
        # itself, and the parent's group signal is then skipped because that pid is already reaped. A child the
        # MCP server left behind would survive, so the probe worker sweeps its own group before exiting
        # (Codex review R3) -- the same thing tool_subprocess_runner does for an ordinary isolated tool.
        marker = self.root / "server.json"
        self.write_config("spawner")
        document = json.loads(self.config_path.read_text())
        document["servers"]["files"]["secret_env"] = ["FAKE_MCP_MARKER_FILE"]
        self.config_path.write_text(json.dumps(document), encoding="utf-8")
        with patch.dict(os.environ, {"FAKE_MCP_MARKER_FILE": str(marker)}):
            report = probe_server(str(self.config_path), "files", timeout=30)
        self.assertIn("read_file", report.tools)  # the probe really did succeed the ordinary way
        child = json.loads(marker.read_text())["child"]
        self.assertTrue(child)
        for _ in range(100):  # the kill is asynchronous; wait briefly for the process to disappear
            if not _alive(child):
                break
            time.sleep(0.05)
        self.assertFalse(_alive(child), "a background child of the MCP server outlived the probe")

    def test_failure_codes_reach_the_caller(self):
        for mode, code in (("tool_error", "mcp_tool_error"), ("hang", "mcp_transport_error"), ("server_request", "mcp_protocol_error")):
            with self.subTest(mode):
                config = self.approved_config()
                pin = config.servers["files"].tools["read_file"].pin
                broken = load_config(str(self.write_config(mode, pins={"read_file": pin})))
                registry = self.registry(broken)
                with self.assertRaises(ToolExecutionError) as raised:
                    registry.invoke(permit_for("mcp.files.read_file"), "mcp.files.read_file", {"path": "sample.txt"})
                self.assertEqual(tool_error_code(raised.exception), code)

    def test_a_tool_that_is_not_read_only_needs_a_reconcile_and_a_profile(self):
        config = self.approved_config(read_only=False, reconcile="tests.isolated_tool_fixtures:reconcile_ok")
        with self.assertRaises(Exception) as raised:  # noqa: B017 - the registry's own SecurityError
            self.registry(config)
        self.assertIn("IsolationProfile", str(raised.exception))
        registry = self.registry(config, profile=True)
        self.assertEqual(registry.names(), ("mcp.files.read_file",))
        self.assertTrue(registry.is_side_effecting("mcp.files.read_file"))
        self.assertTrue(registry.has_reconcile("mcp.files.read_file"))

    def test_a_collision_with_an_installed_tool_is_refused(self):
        config = self.approved_config()
        registry = ToolRegistry()
        registry.register("mcp.files.read_file", lambda arguments: None)
        with self.assertRaises(McpConfigError):
            register_mcp_tools(registry, config)

    def test_only_named_secrets_reach_the_server_process(self):
        self.approved_config()
        marker = self.root / "environment.json"
        document = json.loads(self.config_path.read_text())
        document["servers"]["files"]["secret_env"] = ["FAKE_MCP_SECRET", "FAKE_MCP_MARKER_FILE"]
        self.config_path.write_text(json.dumps(document), encoding="utf-8")
        secret_value = "value-" + os.urandom(6).hex()
        environment = {"FAKE_MCP_SECRET": secret_value, "FAKE_MCP_MARKER_FILE": str(marker), "FAKE_MCP_OTHER": "nope"}
        with patch.dict(os.environ, environment):
            registry = self.registry(load_config(str(self.config_path)))
            registry.invoke(permit_for("mcp.files.read_file"), "mcp.files.read_file", {"path": "sample.txt"})
        seen = json.loads(marker.read_text())
        self.assertEqual(seen["FAKE_MCP_SECRET"], secret_value)
        # The worker's own identifiers are not the server's business.
        self.assertEqual(seen["PORTMARK_MCP_PIN"], "")

    def _host_for(self, registry, store=None, provider=None):
        """A host that grants exactly the MCP tool, with the agent key trusted through a registry file."""
        provider = provider or RecordingProvider("mcp.files.read_file")
        policy_path = self.root / "policy.json"
        policy_path.write_text(json.dumps({
            "version": "mcp-test-v1", "audience": HOST,
            "tools": {"mcp.files.read_file": {"impact": "low", "constraints": {"arguments": {"path": {"type": "string"}}}}},
        }), encoding="utf-8")
        host_signer = EnvelopeSigner.from_private_key_bytes("hk", HOST, bytes(range(32)))
        signer = EnvelopeSigner.from_private_key_bytes("ak", "user:a", bytes(range(1, 33)))
        registry_path = self.root / "trust.json"
        registry_path.write_text(json.dumps({"identities": [
            {
                "key_id": each.key_id, "issuer": each.issuer,
                "public_key_b64": base64.urlsafe_b64encode(each.public_key_bytes()).decode("ascii").rstrip("="),
                "allowed_audiences": ["*"],
            }
            for each in (host_signer, signer)
        ]}), encoding="utf-8")
        environment = {
            "PORTMARK_ED25519_PRIVATE_KEY_B64": base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("="),
            "PORTMARK_SIGNING_KEY_ID": host_signer.key_id,
            "PORTMARK_SIGNING_ISSUER": HOST,
        }
        with patch.dict(os.environ, environment):
            host = make_host(
                host_id=HOST, tools=registry, providers={"recording": provider}, store=store,
                policy_path=str(policy_path), trust_registry_path=str(registry_path),
            )
        envelope = build_envelope({
            "goal": "read it", "provider": "recording", "audience": HOST,
            "grants": [{"name": "mcp.files.read_file", "constraints": {"arguments": {"path": {"type": "string"}}}}],
        }, signer)
        return host, envelope

    def test_the_tool_description_never_reaches_the_provider(self):
        registry = self.registry(self.approved_config())
        provider = RecordingProvider("mcp.files.read_file")
        host, envelope = self._host_for(registry, provider=provider)
        result = host.run(envelope)
        self.assertEqual(result.status, "completed", result.result)
        shown = json.dumps(provider.seen)
        self.assertIn("mcp.files.read_file", shown)
        self.assertNotIn("Read a file", shown)  # the server's description
        self.assertNotIn("inputSchema", shown)


    def test_the_failure_code_is_written_into_the_audit_chain(self):
        config = self.approved_config()
        pin = config.servers["files"].tools["read_file"].pin
        failing = load_config(str(self.write_config("tool_error", pins={"read_file": pin})))
        store = InMemoryRuntimeStore()
        host, envelope = self._host_for(self.registry(failing), store)
        result = host.run(envelope)
        self.assertEqual(result.status, "failed")
        page = store.audit_export_page(None, {}, 500, 2000)
        events = [json.loads(row["details_json"]) | {"event": row["event"]} for row in page.tasks[0].events]
        failed = next(event for event in events if event["event"] == "tool.failed")
        self.assertEqual(failed["error_code"], "mcp_tool_error")
        self.assertEqual(failed["tool"], "mcp.files.read_file")


class CliTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)
        self.config_path = self.root / "mcp.json"
        self.config_path.write_text(json.dumps({
            "schema": "portmark.mcp.config.v1",
            "servers": {"files": {
                "command": sys.executable, "args": [FAKE_SERVER, "modern"], "timeout_seconds": 4,
                "tools": {"read_file": {"pin": "sha256:" + "c" * 64, "read_only": True}},
            }},
        }), encoding="utf-8")

    def tearDown(self):
        self._dir.cleanup()

    def test_mcp_pin_reports_what_the_server_offers_now(self):
        argv = ["portmark", "--mcp-config", str(self.config_path), "mcp", "pin"]
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", argv), redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                cli_main()
            except SystemExit as exit_:
                self.assertEqual(exit_.code, 0, stderr.getvalue())
        report = json.loads(stdout.getvalue())["files"]
        self.assertEqual(report["protocol_version"], MODERN_VERSION)
        self.assertEqual(report["tools"]["read_file"]["state"], "CHANGED")  # the configured pin is a placeholder
        self.assertFalse(report["tools"]["read_file"]["approved"])
        self.assertTrue(report["tools"]["read_file"]["pin"].startswith("sha256:"))

    def test_pin_report_helper_marks_an_approved_tool(self):
        report = pin_report(str(self.config_path), "files", timeout=30)
        digest = report["files"]["tools"]["read_file"]["pin"]
        document = json.loads(self.config_path.read_text())
        document["servers"]["files"]["tools"]["read_file"]["pin"] = digest
        self.config_path.write_text(json.dumps(document), encoding="utf-8")
        approved = pin_report(str(self.config_path), "files", timeout=30)
        self.assertEqual(approved["files"]["tools"]["read_file"]["state"], "approved")


class RegistrationContractTests(unittest.TestCase):
    def test_the_call_target_is_the_worker(self):
        self.assertEqual(CALL_TARGET, "portmark.mcp_worker:call")


if __name__ == "__main__":
    unittest.main()


class HttpTransportTests(unittest.TestCase):
    """The Streamable HTTP transport, against a fake server on loopback."""

    def client(self, mode, timeout=5.0, bearer_name="", bearer_value=None):
        server, port = mcp_http_server.start(mode)
        self.addCleanup(server.server_close)  # cleanups run last-added-first: release, shutdown, then close
        self.addCleanup(server.shutdown)
        self.addCleanup(server.release.set)
        self.server = server
        transport = HttpTransport(
            f"http://127.0.0.1:{port}/mcp", timeout, timeout, bearer_name, bearer_value, allow_private=True
        )
        return McpClient(transport, timeout, "9.9")

    def headers_of(self, index=0):
        return {name.lower(): value for name, value in self.server.seen[index][0].items()}

    def test_a_modern_server_round_trips_over_json(self):
        client = self.client("modern")
        self.assertEqual(client.connect(), MODERN_VERSION)
        self.assertIn("read_file", client.list_tools())
        result = client.call_tool("read_file", {"path": "a.txt"})
        self.assertEqual(result.value["content"][0]["text"], 'read_file:{"path": "a.txt"}')

    def test_every_post_carries_the_headers_the_binding_requires(self):
        # Mcp-Method, Mcp-Name and MCP-Protocol-Version are REQUIRED for compliance, and the version header
        # must equal the body -- a server answers 400 with `HeaderMismatch` when it does not.
        client = self.client("modern")
        client.connect()
        client.call_tool("read_file", {"path": "a.txt"})
        headers, raw = self.server.seen[-1]
        sent = {name.lower(): value for name, value in headers.items()}
        body = json.loads(raw)
        self.assertEqual(sent["mcp-method"], "tools/call")
        self.assertEqual(sent["mcp-name"], "read_file")
        self.assertEqual(sent["mcp-protocol-version"], MODERN_VERSION)
        self.assertEqual(sent["mcp-protocol-version"], body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"])
        self.assertIn("application/json", sent["accept"])
        self.assertIn("text/event-stream", sent["accept"])

    def test_an_event_stream_answer_is_read(self):
        # A keep-alive comment line and a progress notification both precede the real answer.
        client = self.client("sse")
        client.connect()
        result = client.call_tool("read_file", {"path": "a.txt"})
        self.assertEqual(result.value["content"][0]["text"], 'read_file:{"path": "a.txt"}')

    def test_a_stream_held_open_after_the_answer_does_not_hang(self):
        # A server is only ADVISED to close the stream after the final response. Reading to end-of-stream
        # would spend the whole deadline on a call that already succeeded (Codex review of the plan, #10).
        client = self.client("sse_then_hang", timeout=8.0)
        client.connect()
        started = time.monotonic()
        result = client.call_tool("read_file", {"path": "a.txt"})
        self.assertEqual(result.value["content"][0]["text"], 'read_file:{"path": "a.txt"}')
        self.assertLess(time.monotonic() - started, 5.0)

    def test_an_endless_event_line_is_bounded(self):
        # Named in the message on purpose: a LINE that never ends must be cut by the line bound, not merely
        # by the whole-stream bound after megabytes have been read.
        client = self.client("sse_endless")
        client.connect()
        with self.assertRaises(McpError) as raised:
            client.call_tool("read_file", {"path": "a.txt"})
        self.assertEqual(raised.exception.code, "mcp_transport_error")
        self.assertIn("line", str(raised.exception))

    def test_too_many_events_are_refused(self):
        client = self.client("sse_flood")
        client.connect()
        with self.assertRaises(McpError) as raised:
            client.call_tool("read_file", {"path": "a.txt"})
        self.assertIn("events", str(raised.exception))

    def test_a_legacy_server_falls_back_to_initialize(self):
        # An empty-bodied 400 is not a recognised modern error, so the server is old.
        client = self.client("legacy")
        self.assertEqual(client.connect_http(), "2025-11-25")
        self.assertIn("read_file", client.list_tools())

    def test_a_legacy_session_id_is_echoed_on_later_requests(self):
        client = self.client("legacy_session")
        client.connect_http()
        client.list_tools()
        self.assertEqual(self.headers_of(-1).get("mcp-session-id"), "session-1")

    def test_a_modern_server_without_discover_stays_modern(self):
        # `404` + `-32601` is a recognised modern error: the specification lets a client call inline.
        client = self.client("no_discover")
        self.assertEqual(client.connect_http(), MODERN_VERSION)
        self.assertEqual(len(self.server.seen), 1)  # no `initialize` was sent

    def test_a_header_mismatch_fails_closed_instead_of_falling_back(self):
        # -32020 proves the server IS modern. Falling back would send a second POST to a modern server.
        client = self.client("header_mismatch")
        with self.assertRaises(McpError) as raised:
            client.connect_http()
        self.assertEqual(raised.exception.code, "mcp_protocol_error")
        self.assertEqual(len(self.server.seen), 1)

    def test_an_unsupported_version_picks_one_the_server_offers(self):
        client = self.client("unsupported")
        self.assertEqual(client.connect_http(), "2025-11-25")

    def test_an_unsupported_version_without_a_list_is_refused(self):
        client = self.client("unsupported_bare")
        with self.assertRaises(McpError) as raised:
            client.connect_http()
        self.assertEqual(raised.exception.code, "mcp_protocol_error")

    def test_a_202_to_a_request_is_a_protocol_error(self):
        client = self.client("wrong_202")
        with self.assertRaises(McpError) as raised:
            client.connect_http()
        self.assertEqual(raised.exception.code, "mcp_protocol_error")
        self.assertIn("202", str(raised.exception))

    def test_a_redirect_is_not_followed(self):
        client = self.client("redirect")
        with self.assertRaises(McpError) as raised:
            client.connect_http()
        self.assertIn("redirect", str(raised.exception))

    def test_a_compressed_answer_is_refused(self):
        # The byte caps are counted on the wire, so a compressed body could expand straight past them.
        client = self.client("gzip")
        with self.assertRaises(McpError) as raised:
            client.connect_http()
        self.assertIn("Content-Encoding", str(raised.exception))

    def test_a_bearer_token_travels_and_a_missing_one_fails_closed(self):
        client = self.client("modern", bearer_name="MCP_TOKEN", bearer_value="abc123")
        client.connect()
        self.assertEqual(self.headers_of(0).get("authorization"), "Bearer abc123")
        with self.assertRaises(McpError) as raised:
            self.client("modern", bearer_name="MCP_TOKEN", bearer_value=None)
        self.assertIn("MCP_TOKEN", str(raised.exception))

    def test_a_malformed_token_is_refused_without_printing_it(self):
        # `http.client` puts the rejected VALUE in its own error text, and the worker forwards error text.
        with self.assertRaises(McpError) as raised:
            self.client("modern", bearer_name="MCP_TOKEN", bearer_value="secret\r\nX: y")
        self.assertNotIn("secret", str(raised.exception))
        self.assertIn("MCP_TOKEN", str(raised.exception))

    def test_an_annotated_argument_is_mirrored_into_a_header(self):
        client = self.client("mirror")
        client.connect()
        client.list_tools()
        client.call_tool("query", {"region": "us-west1", "sql": "SELECT 1"})
        self.assertEqual(self.headers_of(-1).get("mcp-param-region"), "us-west1")

    def test_a_mirrored_value_that_is_not_safe_ascii_is_encoded(self):
        client = self.client("mirror")
        client.connect()
        client.list_tools()
        client.call_tool("query", {"region": "Hello, 世界"})
        sent = self.headers_of(-1)["mcp-param-region"]
        self.assertTrue(sent.startswith("=?base64?"))
        self.assertEqual(mcp_http_server.decode_header(sent), "Hello, 世界")

    def test_a_tool_annotated_where_the_specification_forbids_is_excluded(self):
        client = self.client("bad_mirror")
        client.connect()
        tools = client.list_tools()
        self.assertNotIn("query", tools)
        self.assertIn("read_file", tools)
        self.assertIn("properties", client.rejected["query"])


class HttpAddressTests(unittest.TestCase):
    """Where the transport is allowed to connect."""

    def test_a_socket_connected_elsewhere_is_refused(self):
        # The address was checked, but the socket must actually BE on it: a connection that ended up
        # somewhere else -- a second lookup, a stale reuse -- defeats the whole point of pinning.
        transport = HttpTransport("https://mcp.example.com/mcp", 5.0, 5.0)

        class Elsewhere:
            def __init__(self):
                self.sock = self
                self.closed = False

            def getpeername(self):
                return ("10.9.9.9", 443)

            def close(self):
                self.closed = True

        connection = Elsewhere()
        with self.assertRaises(McpError) as raised:
            transport._confirm_peer(connection, "93.184.215.14")
        self.assertIn("10.9.9.9", str(raised.exception))
        self.assertTrue(connection.closed)

    def test_allow_private_does_not_permit_a_public_address(self):
        # `allow_private` widens the rule to loopback and private answers, not to the internet.
        for host in ("93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c", "240.0.0.1"):
            with self.subTest(host):
                with self.assertRaises(McpError) as raised:
                    resolve_endpoint_address(host, 443, allow_private=True)
                self.assertIn("not a loopback or private", str(raised.exception))

    def test_the_ipv6_loopback_is_allowed_like_the_ipv4_one(self):
        # Python reports `::1` as RESERVED as well as loopback. Checking reserved first would refuse
        # `https://localhost` on every machine whose resolver answers IPv6 first.
        self.assertEqual(resolve_endpoint_address("::1", 443, allow_private=True), "::1")
        self.assertEqual(resolve_endpoint_address("fd00::1", 443, allow_private=True), "fd00::1")

    def test_addresses_that_are_never_allowed_are_refused_even_with_allow_private(self):
        for host in ("224.0.0.1", "0.0.0.0", "169.254.1.1"):  # noqa: S104  # nosec B104 - refusing it is the point
            with self.subTest(host):
                with self.assertRaises(McpError) as raised:
                    resolve_endpoint_address(host, 443, allow_private=True)
                self.assertIn("never allowed", str(raised.exception))

    def test_a_private_address_is_allowed_only_when_the_operator_asked(self):
        self.assertEqual(resolve_endpoint_address("127.0.0.1", 443, allow_private=True), "127.0.0.1")
        with self.assertRaises(McpError):
            resolve_endpoint_address("127.0.0.1", 443, allow_private=False)

    def test_an_ipv4_mapped_loopback_is_classified_as_loopback(self):
        # The classic bypass: ::ffff:127.0.0.1 sidesteps a naive is_loopback check.
        with self.assertRaises(McpError):
            resolve_endpoint_address("::ffff:127.0.0.1", 443, allow_private=False)


class HttpBudgetAndHostTests(unittest.TestCase):
    """Two things `send` owes that no live server can prove: the Host port, and the total budget."""

    def transport(self, url, total=2.0, request_timeout=30.0):
        return HttpTransport(url, request_timeout, total, allow_private=True)

    def test_the_host_port_is_judged_against_the_scheme_not_a_list(self):
        # 80 is the default for http and NOT for https. Treating both as "default" tells an https server on
        # port 80 that it is on 443, and a server that validates the Host header rejects the request.
        cases = {
            "https://mcp.test/mcp": "mcp.test",
            "https://mcp.test:443/mcp": "mcp.test",
            "https://mcp.test:80/mcp": "mcp.test:80",
            "https://mcp.test:8443/mcp": "mcp.test:8443",
            "http://mcp.test/mcp": "mcp.test",
            "http://mcp.test:80/mcp": "mcp.test",
            "http://mcp.test:443/mcp": "mcp.test:443",
            "https://[::1]:443/mcp": "[::1]",
            "https://[::1]:80/mcp": "[::1]:80",
        }
        for url, expected in cases.items():
            with self.subTest(url):
                built = self.transport(url)._request_headers(b"{}", {})
                self.assertEqual(built["Host"], expected)

    # -- a connection that answers on command, so the budget can be observed ---------------------------

    class Socket:
        def __init__(self):
            self.armed = []

        def settimeout(self, value):
            self.armed.append(value)

    class Response:
        def __init__(self, status=200, body=b'{"jsonrpc":"2.0","id":1,"result":{}}'):
            self.status = status
            self._body = body

        def getheader(self, name, default=None):
            return {"Content-Type": "application/json"}.get(name, default) if self._body else default

        def read(self, size=-1):
            body, self._body = self._body[:size], self._body[size:]
            return body

    def connection_for(self, transport, sock, before_request=0.0, before_response=0.0, response=None):
        outer = self
        seen = {}

        class Connection:
            def request(self, *args, **kwargs):
                time.sleep(before_request)

            def getresponse(self):
                # What the socket's timeout was AT THIS MOMENT. Arming that happens later, while the body is
                # read, must not be able to satisfy an assertion about the header phase.
                seen["armed"] = list(sock.armed)
                time.sleep(before_response)
                return response or outer.Response()

            def close(self):
                seen["closed"] = True

        def open_it():
            transport._sock = sock
            return Connection()

        return open_it, seen

    def test_the_budget_is_re_armed_before_the_answer_is_read(self):
        # The socket timeout set while opening was computed BEFORE the connect and the TLS handshake. If it
        # is not re-armed, reading the status line and headers gets a whole fresh allowance and the call can
        # run for the budget twice over. Measured AT `getresponse`, because `_read_bounded` arms again later.
        transport = self.transport("https://mcp.test/mcp", total=4.0, request_timeout=30.0)
        sock = self.Socket()
        open_it, seen = self.connection_for(transport, sock, before_request=0.4)
        with patch.object(transport, "_open", open_it):
            transport.send(b'{"jsonrpc":"2.0","id":1,"method":"x","params":{}}', {})
        armed = seen["armed"]
        self.assertGreaterEqual(len(armed), 2)
        self.assertLessEqual(max(armed), 4.0)  # never the 30 s per-message timeout
        self.assertLess(armed[-1], armed[0] - 0.2)  # the time already spent was deducted

    def test_an_accepted_notification_that_arrives_after_the_budget_is_refused(self):
        # A `202` is answered without reading a body, so nothing else re-checks the clock on that path: only
        # the check after `getresponse` can refuse an acknowledgement that came back too late.
        transport = self.transport("https://mcp.test/mcp", total=0.5, request_timeout=30.0)
        sock = self.Socket()
        open_it, _ = self.connection_for(
            transport, sock, before_response=0.8, response=self.Response(202, b"")
        )
        with patch.object(transport, "_open", open_it):
            with self.assertRaises(McpError) as raised:
                transport.send(b'{"jsonrpc":"2.0","method":"notifications/x","params":{}}', {}, expects_reply=False)
        self.assertEqual(raised.exception.code, "mcp_transport_error")
        self.assertIn("budget", str(raised.exception))


class HeaderValueTests(unittest.TestCase):
    def test_encoding(self):
        cases = {
            "us-west1": "us-west1",
            "Hello, 世界": "=?base64?SGVsbG8sIOS4lueVjA==?=",
            " padded ": "=?base64?IHBhZGRlZCA=?=",
            "line1\nline2": "=?base64?bGluZTEKbGluZTI=?=",
            "=?base64?literal?=": "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=",
        }
        for original, expected in cases.items():
            with self.subTest(original):
                self.assertEqual(header_value(original), expected)


class MirrorAnnotationTests(unittest.TestCase):
    def schema(self, properties):
        return {"name": "t", "inputSchema": {"type": "object", "properties": properties}}

    def test_refusals(self):
        cases = {
            "not a token": {"a": {"type": "string", "x-mcp-header": "bad name"}},
            "empty": {"a": {"type": "string", "x-mcp-header": ""}},
            "duplicate": {
                "a": {"type": "string", "x-mcp-header": "R"},
                "b": {"type": "string", "x-mcp-header": "r"},
            },
            "number is not allowed": {"a": {"type": "number", "x-mcp-header": "R"}},
            "unreachable through items": {"a": {"type": "array", "items": {"type": "string", "x-mcp-header": "R"}}},
            "unreachable through anyOf": {"a": {"anyOf": [{"type": "string", "x-mcp-header": "R"}]}},
        }
        for label, properties in cases.items():
            with self.subTest(label):
                with self.assertRaises(AnnotationError):
                    mirror_annotations(self.schema(properties))

    def test_a_nested_properties_chain_is_reachable(self):
        schema = self.schema({"outer": {"type": "object", "properties": {"inner": {"type": "string", "x-mcp-header": "R"}}}})
        self.assertEqual(mirror_annotations(schema), ((("outer", "inner"), "R"),))


class HttpEndToEndTests(unittest.TestCase):
    """An MCP tool over HTTP, through the real isolated worker and the real registry."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)
        self.config_path = self.root / "mcp.json"

    def tearDown(self):
        self._dir.cleanup()

    def serve(self, mode="modern"):
        server, port = mcp_http_server.start(mode)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(server.release.set)
        self.server = server
        return port

    def write_config(self, port, pins=None, **server_changes):
        tools = {"read_file": {"pin": (pins or {}).get("read_file", "sha256:" + "a" * 64), "read_only": True}}
        document = {
            "schema": "portmark.mcp.config.v1",
            "servers": {"files": {
                "url": f"http://127.0.0.1:{port}/mcp", "allow_private": True,
                "timeout_seconds": 10, "tools": tools, **server_changes,
            }},
        }
        self.config_path.write_text(json.dumps(document), encoding="utf-8")
        return self.config_path

    def test_an_http_tool_is_probed_pinned_and_called(self):
        port = self.serve("modern")
        self.write_config(port)
        report = probe_server(str(self.config_path), "files", timeout=30)
        self.assertEqual(report.protocol_version, MODERN_VERSION)
        config = load_config(str(self.write_config(port, pins={"read_file": report.tools["read_file"]})))
        registry = ToolRegistry()
        register_mcp_tools(registry, config)
        result = registry.invoke(permit_for("mcp.files.read_file"), "mcp.files.read_file", {"path": "a.txt"})
        self.assertEqual(result["content"][0]["text"], 'read_file:{"path": "a.txt"}')

    def test_a_changed_definition_fails_the_start_up_check(self):
        port = self.serve("modern")
        self.write_config(port)
        report = probe_server(str(self.config_path), "files", timeout=30)
        drifted = load_config(str(self.write_config(port, pins={"read_file": report.tools["read_file"]})))
        self.server.state["mode"] = "drift"
        with self.assertRaises(McpStartupError):
            check_pins(drifted, timeout=30)

    def test_a_tool_with_an_invalid_annotation_is_named_as_such(self):
        # Excluded, not vanished. The message must point at the definition, not at a missing tool.
        port = self.serve("bad_mirror")
        document = {
            "schema": "portmark.mcp.config.v1",
            "servers": {"files": {
                "url": f"http://127.0.0.1:{port}/mcp", "allow_private": True, "timeout_seconds": 10,
                "tools": {"query": {"pin": "sha256:" + "a" * 64, "read_only": True}},
            }},
        }
        self.config_path.write_text(json.dumps(document), encoding="utf-8")
        report = probe_server(str(self.config_path), "files", timeout=30)
        self.assertNotIn("query", report.tools)
        self.assertIn("properties", report.rejected["query"])
        with self.assertRaises(McpStartupError) as raised:
            check_pins(load_config(str(self.config_path)), timeout=30)
        self.assertIn("unusable", str(raised.exception))


class HttpTlsTests(unittest.TestCase):
    """The composition that carries the secret: a verifying context, SNI on the name, the pinned address.

    Driven through `mcp_worker.call` in this process, because the isolated worker inherits only Portmark's
    own variables (tools.py:177) and so cannot be handed a test trust anchor."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)
        self.addCleanup(self._dir.cleanup)

    def certificate(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        certificate_path = self.root / "cert.pem"
        key_path = self.root / "key.pem"
        certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ))
        return certificate_path, key_path

    def test_a_call_over_real_tls_carries_the_bearer_to_the_pinned_address(self):
        certificate_path, key_path = self.certificate()
        address = resolve_endpoint_address("localhost", 0, allow_private=True)
        server, port = mcp_http_server.start("modern", str(certificate_path), str(key_path), host=address)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        config_path = self.root / "mcp.json"
        document = {
            "schema": "portmark.mcp.config.v1",
            "servers": {"files": {
                "url": f"https://localhost:{port}/mcp", "allow_private": True, "bearer_env": "MCP_TOKEN",
                "timeout_seconds": 20,
                "tools": {"read_file": {"pin": "sha256:" + "a" * 64, "read_only": True}},
            }},
        }
        config_path.write_text(json.dumps(document), encoding="utf-8")
        environment = {
            "SSL_CERT_FILE": str(certificate_path), "MCP_TOKEN": "tok-123",  # nosec B105 - a fake token
            "PORTMARK_MCP_CONFIG": str(config_path), "PORTMARK_MCP_SERVER": "files",
            "PORTMARK_MCP_TOOL": "read_file",
        }
        with patch.dict(os.environ, environment):
            pin = definition_digest(mcp_http_server.TOOLS["read_file"])
            document["servers"]["files"]["tools"]["read_file"]["pin"] = pin
            config_path.write_text(json.dumps(document), encoding="utf-8")
            server_config = load_config(str(config_path)).servers["files"]
            with patch.dict(os.environ, {
                "PORTMARK_MCP_PIN": pin, "PORTMARK_MCP_LAUNCH": server_digest(server_config)
            }):
                value = mcp_worker.call({"path": "a.txt"})
        self.assertEqual(value["content"][0]["text"], 'read_file:{"path": "a.txt"}')
        headers = {name.lower(): item for name, item in server.seen[-1][0].items()}
        self.assertEqual(headers["authorization"], "Bearer tok-123")
        self.assertEqual(headers["host"], f"localhost:{port}")  # the NAME, not the pinned address

    def test_a_context_that_does_not_verify_is_refused(self):
        # Address pinning without certificate verification LOOKS secure while any certificate is accepted.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # A literal, so this test turns only on the context: no name is resolved on the way.
        transport = HttpTransport("https://127.0.0.1:1/mcp", 5.0, 5.0, allow_private=True, context=context)
        with self.assertRaises(McpError) as raised:
            transport.send(b'{"jsonrpc":"2.0","id":1,"method":"x","params":{}}', {})
        self.assertIn("verify", str(raised.exception))

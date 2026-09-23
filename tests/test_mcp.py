"""MCP tools over stdio (MCP/SIEM plan, PR 2).

Portmark is an MCP client, not a gateway: an MCP tool is an ordinary isolated tool, so it keeps the deadline,
the tree-kill, the effect ledger and the audit chain. What is new is the wire (two protocol eras), the pin
that approves a tool definition, and the rule that nothing the server says is authority.
"""

import base64
import io
import json
import os
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
from portmark.mcp_client import LEGACY_VERSION, MODERN_VERSION, McpClient, McpError
from portmark.mcp_config import McpConfigError, config_from_bytes, definition_digest, load_config
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

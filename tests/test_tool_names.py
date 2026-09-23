"""A tool name is an identifier, not free text (MCP/SIEM plan, open finding from the Codex R1 review).

A tool name is compared against grants, registered in the tool registry, written into the audit chain,
exported to a SIEM, and -- from the MCP work -- supplied by another organization's server. Before this,
any non-empty string was accepted, including control characters, whitespace and look-alike Unicode.
Every door that DEFINES tool authority now refuses a malformed name. A name a provider merely proposes
needs no new check: it matches no grant, so the existing refusal path closes the run.
"""

import json
import unittest
from dataclasses import asdict

from portmark.a2a import A2ARequestError, envelope_from_dict
from portmark.factory import build_envelope
from portmark.models import MAX_TOOL_NAME_LENGTH, AgentManifest, ToolGrant, validate_tool_name
from portmark.policy import policy_from_dict
from portmark.security import EnvelopeSigner
from portmark.tools import ToolRegistry

VALID = (
    "t",
    "a1",
    "catalog.search",
    "payments.reserve",
    "mcp.files.read_file",
    "a-b_c.d9",
    "A" * MAX_TOOL_NAME_LENGTH,
    # MCP's own examples (specification 2026-07-28, "Tool Names") must be accepted as-is.
    "getUser",
    "DATA_EXPORT_v2",
    "admin.tools.list",
    # A 128-character MCP name under Portmark's `mcp.<server>.` prefix still fits.
    "mcp.files." + "n" * 128,
)
INVALID = {
    "empty": "",
    "space inside": "catalog search",
    "leading space": " catalog.search",
    "trailing space": "catalog.search ",
    "tab": "catalog\tsearch",
    "newline (log injection)": "catalog.search\nagent.accepted",
    "trailing newline": "catalog.search\n",  # Python's `$` would have accepted this
    "trailing newline only": "t\n",
    "carriage return": "catalog\rsearch",
    "null byte": "catalog\x00search",
    "escape sequence": "catalog\x1b[31m",
    "zero width space": "catalog​search",
    "look-alike unicode": "catаlog.search",  # Cyrillic а
    "path separator": "../etc/passwd",
    "url separator": "https://host/tool",
    "colon": "module:function",
    "star": "*",
    "leading dot": ".hidden",
    "trailing dot": "catalog.",
    "leading dash": "-tool",
    "too long": "a" * (MAX_TOOL_NAME_LENGTH + 1),
}
NOT_STRINGS = (None, 5, True, b"catalog.search", ["catalog.search"], {"name": "catalog.search"})


class ValidateToolNameTests(unittest.TestCase):
    def test_accepts_the_names_portmark_itself_uses(self):
        for name in VALID:
            with self.subTest(name):
                self.assertEqual(validate_tool_name(name), name)

    def test_refuses_malformed_names(self):
        for label, name in INVALID.items():
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    validate_tool_name(name)

    def test_refuses_values_that_are_not_strings(self):
        for value in NOT_STRINGS:
            with self.subTest(repr(value)):
                with self.assertRaises(ValueError):
                    validate_tool_name(value)

    def test_the_message_never_echoes_an_unbounded_value(self):
        with self.assertRaises(ValueError) as raised:
            validate_tool_name("x" * 5000)
        self.assertLess(len(str(raised.exception)), 300)


class AuthorityDoorTests(unittest.TestCase):
    """Every door that DEFINES tool authority refuses a malformed name."""

    def test_grant_refuses(self):
        for label, name in INVALID.items():
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    ToolGrant(name)

    def test_manifest_requested_tools_refuse(self):
        AgentManifest("agent:a", "1", "deterministic", ("catalog.search",))
        with self.assertRaises(ValueError):
            AgentManifest("agent:a", "1", "deterministic", ("catalog.search", "bad name"))

    def test_registry_registration_refuses(self):
        registry = ToolRegistry()
        with self.assertRaises(ValueError):
            registry.register("bad name", lambda arguments: None)
        with self.assertRaises(ValueError):
            registry.register_isolated("bad name", "tests.isolated_tool_fixtures:echo")
        self.assertEqual(registry.names(), ())

    def test_host_policy_refuses(self):
        document = {"version": "v1", "audience": "host:x", "tools": {"catalog.search": {"impact": "low"}}}
        self.assertEqual(policy_from_dict(document, "host:x").grants[0].name, "catalog.search")
        with self.assertRaises(ValueError):
            policy_from_dict({**document, "tools": {"bad name": {"impact": "low"}}}, "host:x")

    def test_envelope_builder_refuses(self):
        signer = EnvelopeSigner.from_private_key_bytes("k", "user:a", bytes(range(32)))
        spec = {"goal": "g", "grants": [{"name": "catalog.search"}], "audience": "host:x"}
        self.assertEqual(build_envelope(spec, signer).permit.grants[0].name, "catalog.search")
        with self.assertRaises(ValueError):
            build_envelope({**spec, "grants": [{"name": "catalog\nsearch"}]}, signer)
        with self.assertRaises(ValueError):
            build_envelope({**spec, "requested_tools": ["catalog search"]}, signer)

    def test_an_incoming_a2a_envelope_is_refused_at_decode(self):
        signer = EnvelopeSigner.from_private_key_bytes("k", "user:a", bytes(range(32)))
        envelope = build_envelope({"goal": "g", "grants": [{"name": "catalog.search"}], "audience": "host:x"}, signer)
        payload = json.loads(json.dumps(asdict(envelope)))
        self.assertIsNotNone(envelope_from_dict(payload))
        for label, field in (("grant name", "permit"), ("requested tool", "manifest")):
            with self.subTest(label):
                broken = json.loads(json.dumps(payload))
                if field == "permit":
                    broken["permit"]["grants"][0]["name"] = "catalog\nsearch"
                else:
                    broken["manifest"]["requested_tools"] = ["catalog search"]
                with self.assertRaises(A2ARequestError) as raised:
                    envelope_from_dict(broken)
                self.assertEqual(raised.exception.code, -32602)


if __name__ == "__main__":
    unittest.main()

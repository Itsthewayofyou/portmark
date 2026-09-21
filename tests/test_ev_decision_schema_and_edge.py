"""EXTERNAL_VALIDATION EV-007 and EV-001: the remaining acceptance criteria.

EV-007: the decision validators already refuse UNKNOWN fields (tested elsewhere). These mutation tests prove
the rest of the schema: wrong types, missing required keys, and an unsupported kind or outcome, for both the
HTTP provider decoder and the Wasm component decoder. Each case names its exact refusal, so a case cannot
pass on an earlier, different refusal.

EV-001: with several replicas, the rate limit must be enforced at a shared edge. DEPLOYMENT.md states the
requirement, and every route the reference nginx front forwards to Portmark carries a per-client limit.
"""

import re
import unittest
from pathlib import Path

from portmark.component_bindings import decode_component_decision
from portmark.providers import _provider_decision
from portmark.security import SecurityError

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ("catalog.search",)


class HttpProviderDecisionSchemaTests(unittest.TestCase):
    CASES = [
        # (label, decision, the exact refusal)
        ("not an object", ["kind", "complete"], "must be a JSON object"),
        ("no kind", {}, "kind is not supported"),
        ("unsupported kind", {"kind": "delete"}, "kind is not supported"),
        ("kind of the wrong type", {"kind": 1}, "kind is not supported"),
        ("tool without its tool", {"kind": "tool"}, r"missing required fields: \['tool'\]"),
        ("migrate without its destination", {"kind": "migrate"}, r"missing required fields: \['destination'\]"),
        ("tool name of the wrong type", {"kind": "tool", "tool": 5}, "invalid tool name"),
        ("empty tool name", {"kind": "tool", "tool": ""}, "invalid tool name"),
        ("arguments of the wrong type", {"kind": "tool", "tool": "catalog.search", "arguments": ["q"]}, "arguments must be a JSON object"),
        ("destination of the wrong type", {"kind": "migrate", "destination": 7}, "invalid destination"),
        ("empty destination", {"kind": "migrate", "destination": ""}, "invalid destination"),
        ("migrate content of the wrong type", {"kind": "migrate", "destination": "host:b", "content": "x"}, "content must be a JSON object"),
    ]

    def test_every_malformed_decision_is_refused_for_its_own_reason(self):
        for label, decision, refusal in self.CASES:
            with self.subTest(label):
                with self.assertRaisesRegex(SecurityError, refusal):
                    _provider_decision(decision)

    def test_every_accepted_kind_still_decodes(self):
        accepted = [
            {"kind": "tool", "tool": "catalog.search", "arguments": {"query": "x"}},
            {"kind": "tool", "tool": "catalog.search"},
            {"kind": "complete", "content": {"ok": True}},
            {"kind": "await_input"},
            {"kind": "fail", "content": "reason"},
            {"kind": "migrate", "destination": "host:b"},
            {"kind": "migrate", "destination": "host:b", "content": {"note": 1}},
        ]
        for decision in accepted:
            with self.subTest(kind=decision["kind"]):
                self.assertEqual(_provider_decision(decision).kind, decision["kind"])


class WasmDecisionSchemaTests(unittest.TestCase):
    CASES = [
        ("not an object", '["tool"]', "must be a JSON object"),
        ("no outcome", "{}", "unknown outcome"),
        ("unsupported outcome", '{"outcome": "delete"}', "unknown outcome"),
        ("tool without a request", '{"outcome": "tool"}', "missing a request"),
        ("request of the wrong type", '{"outcome": "tool", "request": "catalog.search"}', "missing a request"),
        ("tool name of the wrong type", '{"outcome": "tool", "request": {"name": 5}}', "invalid tool name"),
        ("empty tool name", '{"outcome": "tool", "request": {"name": ""}}', "invalid tool name"),
        ("arguments not encoded as a string", '{"outcome": "tool", "request": {"name": "catalog.search", "arguments_json": {}}}',
         "tool arguments must be encoded as a JSON string"),
        ("arguments that are not an object", '{"outcome": "tool", "request": {"name": "catalog.search", "arguments_json": "[1]"}}',
         "tool arguments must decode to a JSON object"),
        ("malformed arguments", '{"outcome": "tool", "request": {"name": "catalog.search", "arguments_json": "{"}}',
         "tool arguments is malformed or unsafe JSON"),
        ("content not encoded as a string", '{"outcome": "completed", "content_json": {"ok": true}}',
         "completed content must be encoded as a JSON string"),
        ("destination of the wrong type", '{"outcome": "migrate", "destination": 7}', "invalid destination"),
        ("empty destination", '{"outcome": "migrate", "destination": ""}', "invalid destination"),
    ]

    def test_every_malformed_decision_is_refused_for_its_own_reason(self):
        for label, raw, refusal in self.CASES:
            with self.subTest(label):
                with self.assertRaisesRegex(RuntimeError, refusal):
                    decode_component_decision(raw, TOOLS)

    def test_every_accepted_outcome_still_decodes(self):
        accepted = [
            ('{"outcome": "tool", "request": {"name": "catalog.search", "arguments_json": "{\\"query\\": \\"x\\"}"}}', "tool"),
            ('{"outcome": "completed", "content_json": "{\\"ok\\": true}"}', "complete"),
            ('{"outcome": "awaiting-input"}', "await_input"),
            ('{"outcome": "suspended"}', "await_input"),
            ('{"outcome": "failed"}', "fail"),
            ('{"outcome": "migrate", "destination": "host:b"}', "migrate"),
        ]
        for raw, kind in accepted:
            with self.subTest(kind=kind):
                self.assertEqual(decode_component_decision(raw, TOOLS).kind, kind)


class SharedEdgeRateLimitTests(unittest.TestCase):
    def test_deployment_states_the_multi_replica_requirement(self):
        deployment = (ROOT / "DEPLOYMENT.md").read_text(encoding="utf-8")
        self.assertIn("### Multiple Replicas", deployment)
        section = deployment.split("### Multiple Replicas", 1)[1].split("\n## ", 1)[0]
        for required in (
            "the rate limit must be enforced at a shared edge",
            "not shared",  # the in-process limits are per process
            "N times the limit",
            "only inside one nginx instance",  # a scaled-out edge needs shared state too
            "PORTMARK_A2A_TRUSTED_PROXIES",
            'portmark_refusals_total{reason="rate_limited"}',
        ):
            with self.subTest(required=required):
                self.assertIn(required, section)

    def test_every_route_the_edge_forwards_is_rate_limited(self):
        config = (ROOT / "deploy" / "nginx" / "portmark.conf").read_text(encoding="utf-8")
        zones = set(re.findall(r"limit_req_zone\s+\S+\s+zone=(\w+):", config))
        blocks = re.findall(r"location\s+=?\s*(\S+)\s*\{(.*?)\n\s*\}", config, flags=re.DOTALL)
        forwarded = {path: body for path, body in blocks if "proxy_pass" in body}
        # The routes Portmark serves to clients; a new forwarded route must bring its own limit.
        self.assertEqual(set(forwarded), {"/.well-known/agent-card.json", "/message:send", "/metrics"})
        for path, body in forwarded.items():
            with self.subTest(route=path):
                used = re.findall(r"limit_req\s+zone=(\w+)", body)
                self.assertTrue(used, f"{path} is forwarded with no per-client rate limit")
                self.assertTrue(set(used) <= zones, f"{path} uses an undefined zone {used}")
        self.assertRegex(forwarded["/message:send"], r"limit_conn\s+portmark_a2a_conn\s+\d+")


if __name__ == "__main__":
    unittest.main()

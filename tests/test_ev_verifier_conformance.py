"""EV-004 / TM-007: the conformance kit for an external attestation verifier command.

A toy reference verifier stands in for a platform verifier. Its "quote" is an HMAC over the values it
binds (subject, audience, measurement, nonce, validity window), so it can prove what a real quote
proves. The kit must PASS it. Each broken variant skips exactly one check, and the kit must FAIL it on
exactly that check's case -- this proves each case tests one dimension and cannot pass for another
reason.
"""

import base64
import contextlib
import hashlib
import hmac
import io
import json
import os
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from portmark.cli import main as cli_main
from portmark.security import ExternalAttestationVerifier
from portmark.verifier_conformance import NEGATIVE_CASES, load_base_request, run_conformance

_KEY = b"portmark-conformance-test-key"
_NOW = 1_800_000_030

# The reference verifier. argv[1] names one check to skip ("none" skips nothing), so each broken
# variant differs from the correct verifier in exactly one place.
_VERIFIER = r'''
import base64, hashlib, hmac, json, sys

KEY = %r
BOUND = ("subject", "audience", "measurement", "nonce", "issued_at", "expires_at")
blind = sys.argv[1]
if blind == "rubber-stamp":
    print(json.dumps({"valid": True}))
    sys.exit(0)
if blind == "reject-all":
    sys.exit(1)
request = json.loads(sys.stdin.buffer.read())
evidence = request["evidence"]
try:
    payload, mac = evidence["quote"].split(".")
    body = base64.urlsafe_b64decode(payload.encode() + b"=" * (-len(payload) %% 4))
    if not hmac.compare_digest(hmac.new(KEY, body, hashlib.sha256).hexdigest(), mac):
        raise ValueError("quote MAC is invalid")
    quoted = json.loads(body)
except Exception:
    if blind == "quote-fail-open":
        print(json.dumps({"valid": True}))
        sys.exit(0)
    sys.exit(1)
skip = {"subject": ("subject",), "audience": ("audience",), "measurement": ("measurement",),
        "nonce": ("nonce",), "window": ("issued_at", "expires_at")}.get(blind, ())
for name in BOUND:
    if name not in skip and quoted.get(name) != evidence[name]:
        sys.exit(1)
if evidence["subject"] != request["expected_subject"]:
    sys.exit(1)
if evidence["audience"] not in (request["relying_party"], "*"):
    sys.exit(1)
if (request["expected_nonce"] or "") != evidence["nonce"]:
    sys.exit(1)
if not evidence["issued_at"] <= request["now"] < evidence["expires_at"]:
    sys.exit(1)
print(json.dumps({"valid": True}))
''' % (_KEY,)

# Each broken variant, and the ONLY cases the kit may fail it on.
_BLIND = {
    "subject": {"wrong-subject"},
    "audience": {"wrong-audience"},
    "measurement": {"wrong-measurement"},
    "nonce": {"wrong-nonce"},
    "window": {"stale"},
    "quote-fail-open": {"malformed-quote-corrupted", "malformed-quote-truncated", "malformed-quote-garbage"},
    "rubber-stamp": {name for name, _ in NEGATIVE_CASES},
    "reject-all": {"valid"},
}


def _quote(**bound) -> str:
    body = json.dumps(bound, sort_keys=True).encode()
    payload = base64.urlsafe_b64encode(body).rstrip(b"=").decode()
    return f"{payload}.{hmac.new(_KEY, body, hashlib.sha256).hexdigest()}"


def _base_request(nonce: str = "permit-nonce-1") -> dict:
    bound = {
        "subject": "host:destination",
        "audience": "host:source",
        "measurement": "measurement:destination",
        "nonce": nonce,
        "issued_at": _NOW - 30,
        "expires_at": _NOW + 30,
    }
    evidence = dict(bound, verifier="verifier:external", claims={}, quote=_quote(**bound))
    return {
        "evidence": evidence,
        "expected_subject": "host:destination",
        "relying_party": "host:source",
        "expected_nonce": nonce or None,
        "now": _NOW,
    }


class VerifierConformanceKitTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.script = self.root / "verifier.py"
        self.script.write_text(_VERIFIER, encoding="utf-8")

    def _verifier(self, blind: str) -> ExternalAttestationVerifier:
        return ExternalAttestationVerifier((sys.executable, str(self.script), blind), timeout=30)

    def _failed(self, blind: str, base: dict | None = None) -> set:
        report = run_conformance(self._verifier(blind), load_base_request(base or _base_request()))
        return {case.name for case in report.cases if not case.passed}

    def test_a_correct_verifier_passes_every_case(self):
        report = run_conformance(self._verifier("none"), load_base_request(_base_request()))
        self.assertTrue(report.passed, report.to_dict())
        self.assertEqual(
            [case.name for case in report.cases],
            ["valid", "wrong-subject", "wrong-audience", "wrong-measurement", "wrong-nonce", "stale",
             "malformed-quote-corrupted", "malformed-quote-truncated", "malformed-quote-garbage"],
        )
        self.assertEqual(report.to_dict()["status"], "pass")

    def test_a_correct_verifier_passes_with_unbound_nonce_evidence(self):
        # Measurement evidence with no nonce is legal; the wrong-nonce case still applies to it.
        self.assertEqual(self._failed("none", _base_request(nonce="")), set())

    def test_each_broken_verifier_fails_exactly_its_own_cases(self):
        for blind, expected in _BLIND.items():
            with self.subTest(blind=blind):
                self.assertEqual(self._failed(blind), expected)

    def test_negative_cases_keep_claims_and_request_consistent(self):
        # A case where the claims already disagree with the request is refused by Portmark itself, so a
        # verifier that accepts it has no hole. Every case must be a lie only the quote can expose.
        from portmark.security import AttestationPolicy

        captured = []

        class Recorder:
            def verify(self, evidence, expected_subject, relying_party, expected_nonce, now):
                captured.append((evidence, expected_subject, relying_party, expected_nonce, now))

        class Accept:
            def verify(self, *args):
                pass

        run_conformance(Recorder(), load_base_request(_base_request()))
        self.assertEqual(len(captured), 1 + len(NEGATIVE_CASES))
        policy = AttestationPolicy(allowed_measurements=(), external_verifier=Accept())
        for evidence, subject, relying_party, nonce, now in captured:
            with self.subTest(case=evidence):
                policy.verify(evidence, subject, relying_party, nonce, now=now, require_nonce=True)

    def test_the_base_request_must_be_clean(self):
        cases = {
            "must hold a JSON object": [],
            "unknown request keys": dict(_base_request(), extra=1),
            "must carry an 'evidence' object": dict(_base_request(), evidence="x"),
            "invalid shape": dict(_base_request(), evidence=dict(_base_request()["evidence"], bogus=1)),
            "non-empty strings": dict(_base_request(), relying_party=""),
            "string or null": dict(_base_request(), expected_nonce=5),
            "must be an integer": dict(_base_request(), now=True),
            "must carry a platform quote": dict(_base_request(), evidence=dict(_base_request()["evidence"], quote="")),
            "subject must equal": dict(_base_request(), expected_subject="host:other"),
            "audience must equal": dict(_base_request(), relying_party="host:other"),
            "validity window": dict(_base_request(), now=_NOW + 30),
            "nonce must equal": dict(_base_request(), expected_nonce="other"),
        }
        for message, value in cases.items():
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    load_base_request(value)
        self.assertEqual(load_base_request(dict(_base_request(), relying_party="host:x",
                                                evidence=dict(_base_request()["evidence"], audience="*")))["relying_party"], "host:x")


class VerifierConformanceCliTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "verifier.py").write_text(_VERIFIER, encoding="utf-8")
        self.evidence = self.root / "evidence.json"
        self.evidence.write_text(json.dumps(_base_request()), encoding="utf-8")

    def _run(self, argv: list, env: dict) -> tuple:
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, env, clear=True), patch.object(sys, "argv", ["portmark", *argv]):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                try:
                    cli_main()
                    code = 0
                except SystemExit as exit_:
                    code = exit_.code
        return code, stdout.getvalue(), stderr.getvalue()

    def _command(self, blind: str) -> dict:
        # The argv string is parsed like PORTMARK_ATTESTATION_VERIFIER_COMMAND, with no shell.
        return {"PORTMARK_ATTESTATION_VERIFIER_COMMAND": shlex.join([sys.executable, str(self.root / "verifier.py"), blind])}

    def test_cli_passes_a_correct_verifier_without_a_store(self):
        code, out, _ = self._run(["attest-conformance", "--evidence", str(self.evidence)], self._command("none"))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["status"], "pass")

    def test_cli_exits_1_and_names_the_failed_case(self):
        code, out, _ = self._run(["attest-conformance", "--evidence", str(self.evidence)], self._command("nonce"))
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertEqual(report["status"], "fail")
        self.assertEqual([case["name"] for case in report["cases"] if not case["passed"]], ["wrong-nonce"])

    def test_cli_refuses_without_a_verifier_command_or_with_a_bad_evidence_file(self):
        code, _, err = self._run(["attest-conformance", "--evidence", str(self.evidence)], {})
        self.assertEqual(code, 2)
        self.assertIn("requires --attestation-verifier-command", err)
        self.evidence.write_text("{not json", encoding="utf-8")
        code, _, err = self._run(["attest-conformance", "--evidence", str(self.evidence)], self._command("none"))
        self.assertEqual(code, 2)
        self.assertIn("--evidence:", err)
        code, _, err = self._run(["attest-conformance", "--evidence", str(self.root / "missing.json")], self._command("none"))
        self.assertEqual(code, 2)
        self.assertIn("--evidence:", err)


class VerifierConformanceDocsTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]

    def test_deployment_requires_the_kit_before_production(self):
        text = (self.ROOT / "DEPLOYMENT.md").read_text(encoding="utf-8")
        self.assertIn("**Requirement: run the verifier conformance kit before production use.**", text)
        self.assertIn("portmark attest-conformance --evidence", text)

    def test_attestation_lists_every_case_the_kit_runs(self):
        text = (self.ROOT / "ATTESTATION.md").read_text(encoding="utf-8")
        self.assertIn("### Verifier Conformance Kit", text)
        for name in ["valid", *(name for name, _ in NEGATIVE_CASES)]:
            with self.subTest(case=name):
                self.assertIn(f"| `{name}` |", text)


if __name__ == "__main__":
    unittest.main()

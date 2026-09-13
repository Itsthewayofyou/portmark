"""Section 3 — signing & key lifecycle hardening.

Each test class maps to an audit finding (see SECTION3_SIGNING_KEY_LIFECYCLE_PLAN.md).
Tests are written to FAIL against the pre-fix code and pass once the fix lands.
"""

import json
import secrets
import tempfile
import time
import unittest
from pathlib import Path

from portmark.factory import make_host
from portmark.models import AgentEnvelope, AgentManifest, AgentState, Permit, ResourceBudget, ToolGrant
from portmark.security import (
    EnvelopeSigner,
    SecurityError,
    TrustedIdentity,
    TrustRegistry,
    TrustSource,
    _b64url_decode,
    _b64url_encode,
)


def _write_registry(path: Path, signer: EnvelopeSigner, audiences=("*",), revoked: bool = False) -> None:
    entry = {
        "key_id": signer.key_id,
        "issuer": signer.issuer,
        "public_key_b64": _b64url_encode(signer.public_key_bytes()),
        "allowed_audiences": list(audiences),
    }
    if revoked:
        entry["revoked"] = True
    path.write_text(json.dumps({"identities": [entry]}), encoding="utf-8")


def _agent_envelope(signer: EnvelopeSigner, host_id: str, goal: str = "find a red widget") -> AgentEnvelope:
    manifest = AgentManifest("agent:demo", "1.0.0", "deterministic", ("catalog.search",), "python:reference-agent-v1")
    permit = Permit(
        issuer=signer.issuer,
        subject=manifest.agent_id,
        audience=host_id,
        expires_at=int(time.time()) + 3600,
        nonce=secrets.token_hex(16),
        grants=(ToolGrant("catalog.search", {"max_limit": 3, "arguments": {"query": {"type": "string"}}}, ("id", "title")),),
        budget=ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=32_768),
    )
    return signer.seal(AgentEnvelope(manifest, permit, AgentState(secrets.token_hex(8), goal)))


def _registry(*, revoked: bool = False, not_before: int = 0, expires_at: int | None = None) -> TrustRegistry:
    registry = TrustRegistry()
    registry.add(
        TrustedIdentity(
            key_id="k",
            issuer="user:a",
            public_key=bytes(32),
            allowed_audiences=("*",),
            not_before=not_before,
            expires_at=expires_at,
            revoked=revoked,
        )
    )
    return registry


# ---------------------------------------------------------------------------
# Finding #6 — Base64URL signature/key representation must be canonical.
# ---------------------------------------------------------------------------
class Base64UrlStrictTests(unittest.TestCase):
    def test_b64url_canonical_roundtrip_still_works(self):
        for raw in (b"", b"\x00", bytes(range(32)), b"portmark"):
            with self.subTest(raw=raw):
                self.assertEqual(_b64url_decode(_b64url_encode(raw)), raw)

    def test_b64url_decode_rejects_noncanonical_forms(self):
        canonical = _b64url_encode(bytes(range(32)))
        bad_forms = {
            "leading-non-alphabet": "!!!!" + canonical,
            "trailing-non-alphabet": canonical + "!!!!",
            "added-padding": canonical + "=",
            "double-padding": canonical + "==",
            "leading-space": " " + canonical,
            "trailing-newline": canonical + "\n",
            "standard-b64-plus": _b64url_encode(b"\xfb\xff\xfe") .replace("_", "+"),
        }
        for name, form in bad_forms.items():
            with self.subTest(form=name):
                with self.assertRaises(ValueError):
                    _b64url_decode(form)

    def test_b64url_decode_rejects_noncanonical_trailing_bits(self):
        # "AA" is the canonical encoding of b"\x00". "AB" also decodes to b"\x00"
        # under lenient decoding but has non-zero discarded bits -> must be rejected.
        self.assertEqual(_b64url_decode("AA"), b"\x00")
        with self.assertRaises(ValueError):
            _b64url_decode("AB")

    def test_b64url_decode_rejects_non_string(self):
        with self.assertRaises(ValueError):
            _b64url_decode(b"AA")  # type: ignore[arg-type]  # bytes, not str

    def test_b64url_decode_rejects_impossible_length(self):
        # A single base64 char (2 leftover bits) can never be a valid quantum.
        with self.assertRaises(ValueError):
            _b64url_decode("A")


# ---------------------------------------------------------------------------
# Finding #2a — a single validity predicate (trusted AND not-revoked AND active
# AND not-expired); bare membership (has_key) must not be treated as usable.
# ---------------------------------------------------------------------------
class ValidityPredicateTests(unittest.TestCase):
    NOW = 1_000_000

    def test_validity_predicate_accepts_only_a_currently_valid_key(self):
        self.assertTrue(_registry().is_usable("k", self.NOW))

    def test_validity_predicate_rejects_unknown_revoked_inactive_expired(self):
        cases = {
            "unknown": (_registry(), "missing"),
            "revoked": (_registry(revoked=True), "k"),
            "not-yet-active": (_registry(not_before=self.NOW + 10), "k"),
            "expired": (_registry(expires_at=self.NOW - 1), "k"),
        }
        for name, (registry, key_id) in cases.items():
            with self.subTest(case=name):
                self.assertFalse(registry.is_usable(key_id, self.NOW))

    def test_validity_predicate_has_key_alone_is_insufficient_for_a_revoked_key(self):
        # The bug behind finding #2: has_key returns True for a revoked key.
        registry = _registry(revoked=True)
        self.assertTrue(registry.has_key("k"))
        self.assertFalse(registry.is_usable("k", self.NOW))


# ---------------------------------------------------------------------------
# Finding #2b — deployed revocation must take effect in the ADMISSION path, not
# only readiness. TrustSource fails closed on any on-disk registry change.
# ---------------------------------------------------------------------------
class EffectiveRevocationTests(unittest.TestCase):
    NOW = 2_000_000

    def test_effective_revocation_trust_source_fails_closed_on_disk_change(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trust.json"
            agent = EnvelopeSigner.generate("agent-key", "user:alice", ("host:local-demo",))
            _write_registry(path, agent, audiences=("host:local-demo",))
            source = TrustSource.from_path(path)
            self.assertTrue(source.is_usable("agent-key", self.NOW))  # loads clean

            # Operator deploys a revocation (any on-disk change flips the digest).
            _write_registry(path, agent, audiences=("host:local-demo",), revoked=True)
            with self.assertRaisesRegex(SecurityError, "changed on disk"):
                source.is_usable("agent-key", self.NOW)
            with self.assertRaisesRegex(SecurityError, "changed on disk"):
                source.has_key("agent-key")

    def test_effective_revocation_trust_source_fails_closed_when_file_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trust.json"
            agent = EnvelopeSigner.generate("agent-key", "user:alice", ("host:local-demo",))
            _write_registry(path, agent, audiences=("host:local-demo",))
            source = TrustSource.from_path(path)
            path.unlink()
            with self.assertRaisesRegex(SecurityError, "unavailable"):
                source.has_key("agent-key")

    def test_effective_revocation_rejects_a_direct_request_after_on_disk_change(self):
        # The auditor's requirement: a DIRECT request to a live host is rejected after
        # the on-disk registry changes — not merely /readyz. Both the envelope verifier
        # and the audit verifier share the one fail-closed source, so both transition.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trust.json"
            agent = EnvelopeSigner.generate("agent-key", "user:alice", ("host:local-demo",))
            _write_registry(path, agent, audiences=("host:local-demo",))
            host = make_host(host_id="host:local-demo", trust_registry_path=str(path))

            first = _agent_envelope(agent, "host:local-demo")
            self.assertEqual(host.run(first).status, "completed")

            _write_registry(path, agent, audiences=("host:local-demo",), revoked=True)
            second = _agent_envelope(agent, "host:local-demo")
            with self.assertRaisesRegex(SecurityError, "changed on disk"):
                host.run(second)


if __name__ == "__main__":
    unittest.main()

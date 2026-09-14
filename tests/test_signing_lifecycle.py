"""Section 3 — signing & key lifecycle hardening.

Each test class maps to an audit finding (see SECTION3_SIGNING_KEY_LIFECYCLE_PLAN.md).
Tests are written to FAIL against the pre-fix code and pass once the fix lands.
"""

import io
import json
import os
import secrets
import subprocess  # nosec B404
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from portmark.cli import main as cli_main
from portmark.factory import make_host, signer_from_environment
from portmark.models import AgentEnvelope, AgentManifest, AgentState, Permit, ResourceBudget, ToolGrant
from portmark.security import (
    EnvelopeSigner,
    HmacEnvelopeSigner,
    SecurityError,
    TrustedIdentity,
    TrustRegistry,
    TrustSource,
    _b64url_decode,
    _b64url_encode,
    audit_head_payload,
)
from portmark.storage import InMemoryRuntimeStore, SQLiteRuntimeStore


# The keygen env-export shell tests source output in a POSIX shell; skip them where none
# exists (Windows CI) so they don't fail with WinError 2. Platform-independent coverage
# (JSON output, shlex-quoting as a string check, control-char rejection) runs everywhere.
_HAS_POSIX_SH = os.path.exists("/bin/sh") and not os.environ.get("PORTMARK_TEST_NO_POSIX_SH")


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


# ---------------------------------------------------------------------------
# Finding #4 — keygen --format env must not emit shell-injectable exports.
# ---------------------------------------------------------------------------
class KeygenExportTests(unittest.TestCase):
    def _env_output(self, key_id: str, issuer: str) -> str:
        buffer = io.StringIO()
        argv = ["portmark", "keygen", "--format", "env", "--key-id", key_id, "--issuer", issuer]
        with patch.object(sys, "argv", argv):
            with redirect_stdout(buffer), redirect_stderr(io.StringIO()):
                try:
                    cli_main()
                except SystemExit:
                    pass
        return buffer.getvalue()

    @unittest.skipUnless(_HAS_POSIX_SH, "requires a POSIX shell at /bin/sh")
    def test_keygen_injection_env_output_is_inert_when_sourced(self):
        with tempfile.TemporaryDirectory() as directory:
            marker_semi = Path(directory) / "PWNED_SEMI"
            marker_sub = Path(directory) / "PWNED_SUB"
            payloads = {
                "semicolon": f"safe; touch {marker_semi}",
                "command-substitution": f"x$(touch {marker_sub})",
            }
            for name, issuer in payloads.items():
                with self.subTest(case=name):
                    exports = self._env_output("agent-key", issuer)
                    subprocess.run(  # nosec B603 B607 -- deliberately sourcing keygen output in a throwaway shell
                        ["/bin/sh", "-c", exports + "\n:"], cwd=directory, capture_output=True, timeout=10
                    )
            self.assertFalse(marker_semi.exists(), "semicolon payload executed when sourced")
            self.assertFalse(marker_sub.exists(), "command-substitution payload executed when sourced")

    @unittest.skipUnless(_HAS_POSIX_SH, "requires a POSIX shell at /bin/sh")
    def test_keygen_injection_value_roundtrips_through_shell(self):
        issuer = "weird; value $with (chars) `here`"
        exports = self._env_output("agent-key", issuer)
        result = subprocess.run(  # nosec B603 B607
            ["/bin/sh", "-c", exports + '\nprintf "%s" "$PORTMARK_SIGNING_ISSUER"'],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.stdout, issuer)

    @unittest.skipUnless(_HAS_POSIX_SH, "requires a POSIX shell at /bin/sh")
    def test_issuer_uri_allowed(self):
        for issuer in ("user:portmark", "https://example.com/agents/portmark"):
            with self.subTest(issuer=issuer):
                exports = self._env_output("agent-key", issuer)
                self.assertIn("PORTMARK_SIGNING_ISSUER=", exports)
                result = subprocess.run(  # nosec B603 B607
                    ["/bin/sh", "-c", exports + '\nprintf "%s" "$PORTMARK_SIGNING_ISSUER"'],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.stdout, issuer)

    def _json_output(self, key_id: str, issuer: str) -> dict:
        buffer = io.StringIO()
        argv = ["portmark", "keygen", "--format", "json", "--key-id", key_id, "--issuer", issuer]
        with patch.object(sys, "argv", argv):
            with redirect_stdout(buffer), redirect_stderr(io.StringIO()):
                try:
                    cli_main()
                except SystemExit:
                    pass
        return json.loads(buffer.getvalue())

    def test_keygen_json_output_is_platform_independent(self):
        # No shell involved — safe everywhere including Windows. JSON escaping (not shell
        # quoting) carries the values, so a metacharacter issuer round-trips verbatim.
        material = self._json_output("agent-key", "safe; touch PWNED $(id)")
        self.assertEqual(material["key_id"], "agent-key")
        self.assertEqual(material["issuer"], "safe; touch PWNED $(id)")
        self.assertIn("private_key_b64", material)

    def test_keygen_env_output_is_shell_quoted_string_check(self):
        # Platform-independent injection check: the export line quotes the value so the
        # payload is a single shell token, without needing to run a shell to prove it.
        exports = self._env_output("agent-key", "safe; touch PWNED")
        issuer_line = next(l for l in exports.splitlines() if l.startswith("export PORTMARK_SIGNING_ISSUER="))
        self.assertIn("'safe; touch PWNED'", issuer_line)  # shlex.quote wraps the whole value

    def test_issuer_uri_accepted_platform_independent(self):
        for issuer in ("user:portmark", "https://example.com/agents/portmark"):
            with self.subTest(issuer=issuer):
                material = self._json_output("agent-key", issuer)
                self.assertEqual(material["issuer"], issuer)

    def test_keygen_rejects_control_characters_in_identifiers(self):
        # Newlines/control chars can't be safely single-lined even quoted; reject them.
        with patch.object(sys, "argv", ["portmark", "keygen", "--format", "env", "--issuer", "a\nb"]):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    cli_main()


# ---------------------------------------------------------------------------
# Finding #1 — a durable store must not run on an ephemeral (per-restart) key.
# ---------------------------------------------------------------------------
class DurableKeyCustodyTests(unittest.TestCase):
    def test_durable_requires_key_refuses_ephemeral_generated_key(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(str(Path(directory) / "store.sqlite"))
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, "durable store requires"):
                    make_host(store=store)

    def test_durable_requires_key_allows_ephemeral_with_explicit_optin(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(str(Path(directory) / "store.sqlite"))
            with patch.dict(os.environ, {}, clear=True):
                host = make_host(store=store, allow_ephemeral_signing_key=True)
            self.assertIsNotNone(host)

    def test_durable_requires_key_in_memory_store_is_not_durable(self):
        with patch.dict(os.environ, {}, clear=True):
            host = make_host(store=InMemoryRuntimeStore())
        self.assertIsNotNone(host)


class FingerprintKeyIdTests(unittest.TestCase):
    def test_fingerprint_key_id_is_namespaced_and_unique(self):
        first = EnvelopeSigner.generate()
        second = EnvelopeSigner.generate()
        self.assertTrue(first.key_id.startswith("ed25519:"), first.key_id)
        self.assertNotEqual(first.key_id, second.key_id)

    def test_fingerprint_key_id_explicit_id_is_preserved(self):
        self.assertEqual(EnvelopeSigner.generate("my-explicit-key").key_id, "my-explicit-key")


class KeyIdContinuityTests(unittest.TestCase):
    def test_key_id_continuity_stable_signer_keeps_its_id_and_verifies(self):
        # A stable (from_private_key_bytes) signer keeps its caller-chosen id and is not
        # ephemeral, so the generated-id fingerprint scheme does not orphan audit heads
        # stored under ids like "env-ed25519-key" (finding #1 must not reintroduce itself).
        raw = EnvelopeSigner.generate().private_key_bytes()
        signer = EnvelopeSigner.from_private_key_bytes("env-ed25519-key", "host:x", raw)
        self.assertEqual(signer.key_id, "env-ed25519-key")
        self.assertFalse(signer.ephemeral)
        payload = audit_head_payload("task", "host:x", "deadbeef", 0)
        signature = signer.sign_audit_head("task", "host:x", "deadbeef", 0)
        signer.registry.verify_audit_head("env-ed25519-key", payload, signature)  # resolves by stored id


# ---------------------------------------------------------------------------
# Finding #5 — key-purpose separation: a valid key lacking the required usage
# must be rejected (an envelope key cannot sign an audit head, and vice versa).
# ---------------------------------------------------------------------------
class KeyUsageTests(unittest.TestCase):
    HOST = "host:usage"

    def _registry_for(self, signer: EnvelopeSigner, usages: tuple[str, ...]) -> TrustRegistry:
        registry = TrustRegistry()
        registry.add(
            TrustedIdentity(
                key_id=signer.key_id,
                issuer=signer.issuer,
                public_key=signer.public_key_bytes(),
                allowed_audiences=("*",),
                usages=usages,
            )
        )
        return registry

    def test_key_usage_envelope_only_key_cannot_sign_audit_head(self):
        signer = EnvelopeSigner.generate("k", self.HOST)
        registry = self._registry_for(signer, ("envelope",))
        payload = audit_head_payload("t", self.HOST, "hash", 0)
        signature = signer.sign_audit_head("t", self.HOST, "hash", 0)
        with self.assertRaisesRegex(SecurityError, "usage"):
            registry.verify_audit_head("k", payload, signature)

    def test_key_usage_audit_only_key_cannot_verify_envelope(self):
        signer = EnvelopeSigner.generate("k", self.HOST)
        registry = self._registry_for(signer, ("audit",))
        envelope = _agent_envelope(signer, self.HOST)
        with self.assertRaisesRegex(SecurityError, "usage"):
            registry.require_identity(envelope)

    def test_key_usage_unrestricted_key_allows_both(self):
        signer = EnvelopeSigner.generate("k", self.HOST)
        registry = self._registry_for(signer, ())  # empty = no restriction (backward compat)
        payload = audit_head_payload("t", self.HOST, "hash", 0)
        signature = signer.sign_audit_head("t", self.HOST, "hash", 0)
        registry.verify_audit_head("k", payload, signature)  # no raise
        registry.require_identity(_agent_envelope(signer, self.HOST))  # no raise


# ---------------------------------------------------------------------------
# Additional lifecycle limitations — #15: strict typing (bool is an int subclass)
# and duplicate-id rejection on every registry construction path.
# ---------------------------------------------------------------------------
class RegistryStrictTypingTests(unittest.TestCase):
    def _write(self, path: Path, identity_extra: dict) -> None:
        entry = {"key_id": "k", "issuer": "user:a", "public_key_b64": _b64url_encode(bytes(32))}
        entry.update(identity_extra)
        path.write_text(json.dumps({"identities": [entry]}), encoding="utf-8")

    def test_strict_typing_rejects_bool_and_non_int_timestamps(self):
        from portmark.security import load_trust_registry

        cases = {
            "bool-not_before": {"not_before": True},
            "float-not_before": {"not_before": 1.5},
            "str-expires_at": {"expires_at": "later"},
            "bool-expires_at": {"expires_at": False},
            "str-revoked": {"revoked": "yes"},
        }
        for name, extra in cases.items():
            with self.subTest(case=name):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "trust.json"
                    self._write(path, extra)
                    with self.assertRaises(ValueError):
                        load_trust_registry(path)

    def test_strict_typing_accepts_plain_ints_and_bools(self):
        from portmark.security import load_trust_registry

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trust.json"
            self._write(path, {"not_before": 10, "expires_at": 20, "revoked": True})
            registry = load_trust_registry(path)
            self.assertTrue(registry.has_key("k"))


class DuplicateIdRejectionTests(unittest.TestCase):
    def _identity(self, key_id: str) -> TrustedIdentity:
        return TrustedIdentity(key_id=key_id, issuer="user:a", public_key=bytes(32), allowed_audiences=("*",))

    def test_duplicate_id_rejected_in_trust_registry_constructor(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            TrustRegistry((self._identity("dup"), self._identity("dup")))


# ---------------------------------------------------------------------------
# Auditor follow-up on PR #58 — merge blockers + hardening.
# ---------------------------------------------------------------------------
class FollowupAuditTests(unittest.TestCase):
    def test_signer_with_trust_registry_path_is_rejected(self):
        # Blocker: a caller-supplied signer keeps its own in-memory registry, so a
        # file-backed TrustSource built from trust_registry_path would be orphaned and
        # revocation via that file would not take effect. Reject the combination.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trust.json"
            agent = EnvelopeSigner.generate("k", "user:a", ("host:local-demo",))
            _write_registry(path, agent, audiences=("host:local-demo",))
            signer = EnvelopeSigner.generate("host-key", "host:local-demo", ("*",))
            with self.assertRaisesRegex(ValueError, "either an explicit signer OR"):
                make_host(host_id="host:local-demo", signer=signer, trust_registry_path=str(path))

    def test_env_private_key_uses_strict_decoder(self):
        # #6: PORTMARK_ED25519_PRIVATE_KEY_B64 must go through the strict decoder too.
        noncanonical = _b64url_encode(bytes(32)) + "="  # valid 32 bytes leniently, padding is non-canonical
        env = {"PORTMARK_ED25519_PRIVATE_KEY_B64": noncanonical, "PORTMARK_SIGNING_ISSUER": "host:x"}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError):
                signer_from_environment("host:x")

    def test_durable_refuses_signer_without_affirmative_stability_marker(self):
        # #5b: stability must be affirmative. A signer that does not declare ephemeral=False
        # (e.g. a randomly-generated HMAC signer) is not presumed stable.
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(str(Path(directory) / "store.sqlite"))
            signer = HmacEnvelopeSigner.generate()
            with self.assertRaisesRegex(ValueError, "durable store requires"):
                make_host(signer=signer, store=store)

    def test_durable_stable_env_key_signer_is_accepted(self):
        # Control: an affirmatively-stable key (from_private_key_bytes) runs on a durable store.
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(str(Path(directory) / "store.sqlite"))
            raw = EnvelopeSigner.generate().private_key_bytes()
            signer = EnvelopeSigner.from_private_key_bytes("env-ed25519-key", "host:local-demo", raw)
            host = make_host(host_id="host:local-demo", signer=signer, store=store)
            self.assertIsNotNone(host)


# ---------------------------------------------------------------------------
# Part 2 / Phase A — audit-head.v2 + signed_at.
# ---------------------------------------------------------------------------
class AuditHeadV2PayloadTests(unittest.TestCase):
    def test_audit_head_v2_payload_shape(self):
        from portmark.security import audit_head_payload, audit_head_payload_v2

        v1 = audit_head_payload("t", "host:x", "hash", 0)
        self.assertEqual(v1["type"], "portmark.audit-head.v1")
        self.assertNotIn("signed_at", v1)

        v2 = audit_head_payload_v2("t", "host:x", "hash", 0, 12345)
        self.assertEqual(v2["type"], "portmark.audit-head.v2")
        self.assertEqual(v2["signed_at"], 12345)
        self.assertEqual(v2["head_hash"], "hash")

    def test_audit_head_v2_sign_emits_v2_when_signed_at_given(self):
        from portmark.security import audit_head_payload, audit_head_payload_v2

        signer = EnvelopeSigner.generate("k", "host:x")
        sig2 = signer.sign_audit_head("t", "host:x", "hash", 0, signed_at=999)
        # verifies against the v2 payload, not the v1 payload
        signer.registry.verify_audit_head("k", audit_head_payload_v2("t", "host:x", "hash", 0, 999), sig2)
        with self.assertRaises(SecurityError):
            signer.registry.verify_audit_head("k", audit_head_payload("t", "host:x", "hash", 0), sig2)

    def test_audit_head_v2_sign_without_signed_at_is_v1(self):
        from portmark.security import audit_head_payload

        signer = EnvelopeSigner.generate("k", "host:x")
        sig1 = signer.sign_audit_head("t", "host:x", "hash", 0)
        signer.registry.verify_audit_head("k", audit_head_payload("t", "host:x", "hash", 0), sig1)  # v1 unchanged


class SignedAtMigrationTests(unittest.TestCase):
    def test_signed_at_migration_adds_column_and_bumps_version(self):
        import sqlite3

        from portmark.storage import SQLITE_SCHEMA_VERSION, SQLiteRuntimeStore

        self.assertGreaterEqual(SQLITE_SCHEMA_VERSION, 6)
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "store.sqlite")
            store = SQLiteRuntimeStore(path)
            store.check_ready()  # exact-version readiness still passes at the new version
            connection = sqlite3.connect(path)
            try:
                cols = [row[1] for row in connection.execute("PRAGMA table_info(audit_heads)")]
            finally:
                connection.close()
            self.assertIn("signed_at", cols)

    def test_signed_at_migration_upgrades_an_existing_v5_store(self):
        import sqlite3

        from portmark.storage import SQLITE_SCHEMA_VERSION, SQLiteRuntimeStore

        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "store.sqlite")
            SQLiteRuntimeStore(path)  # build current schema
            # Simulate an OLD (pre-signed_at) store: drop the column and roll user_version back.
            connection = sqlite3.connect(path)
            try:
                connection.execute("ALTER TABLE audit_heads DROP COLUMN signed_at")
                connection.execute("PRAGMA user_version = 5")
                connection.commit()
            finally:
                connection.close()
            # Reopening runs the v6 migration rather than failing readiness.
            store = SQLiteRuntimeStore(path)
            store.check_ready()
            connection = sqlite3.connect(path)
            try:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                cols = [row[1] for row in connection.execute("PRAGMA table_info(audit_heads)")]
            finally:
                connection.close()
            self.assertEqual(version, SQLITE_SCHEMA_VERSION)
            self.assertIn("signed_at", cols)


class EvaluateAuditHeadTests(unittest.TestCase):
    HOST = "host:eval"

    def _v2(self, signer: EnvelopeSigner, signed_at: int, seq: int = 0):
        from portmark.security import audit_head_payload_v2

        sig = signer.sign_audit_head("t", self.HOST, "hash", seq, signed_at=signed_at)
        return audit_head_payload_v2("t", self.HOST, "hash", seq, signed_at), sig

    def _registry(self, signer: EnvelopeSigner, **identity_kwargs) -> TrustRegistry:
        registry = TrustRegistry()
        registry.add(
            TrustedIdentity(key_id=signer.key_id, issuer=self.HOST, public_key=signer.public_key_bytes(), allowed_audiences=("*",), **identity_kwargs)
        )
        return registry

    # PA3 -----------------------------------------------------------------
    def test_verify_at_signing_time_expired_key_still_verifies_old_head(self):
        signer = EnvelopeSigner.generate("k", self.HOST)
        payload, sig = self._v2(signer, signed_at=1000)
        registry = self._registry(signer, expires_at=1500)  # expired long after signing
        evaluation = registry.evaluate_audit_head("k", payload, sig, now=5000)
        self.assertTrue(evaluation.ok)
        self.assertEqual(evaluation.head_status, "valid-key-expired")

    def test_verify_at_signing_time_currently_valid_key_is_plain_valid(self):
        signer = EnvelopeSigner.generate("k", self.HOST)
        payload, sig = self._v2(signer, signed_at=1000)
        registry = self._registry(signer)  # no expiry/revocation
        evaluation = registry.evaluate_audit_head("k", payload, sig, now=5000)
        self.assertTrue(evaluation.ok)
        self.assertEqual(evaluation.head_status, "valid")

    # PA4 -----------------------------------------------------------------
    def test_four_way_status_outcomes_are_distinct(self):
        signer = EnvelopeSigner.generate("k", self.HOST)
        payload, sig = self._v2(signer, signed_at=1000)

        # 1. signature invalid
        bad = self._registry(signer)
        ev = bad.evaluate_audit_head("k", payload, sig[:-2] + ("AA" if not sig.endswith("AA") else "BB"), now=5000)
        self.assertFalse(ev.ok)
        self.assertEqual(ev.head_status, "signature-invalid")

        # 2. valid, key later expired
        ev = self._registry(signer, expires_at=1500).evaluate_audit_head("k", payload, sig, now=5000)
        self.assertEqual((ev.ok, ev.head_status), (True, "valid-key-expired"))

        # 3. valid, key later revoked (revoked AFTER signing)
        ev = self._registry(signer, revoked=True, revoked_at=1500).evaluate_audit_head("k", payload, sig, now=5000)
        self.assertEqual((ev.ok, ev.head_status), (True, "valid-key-revoked"))

        # 4. signed after revocation
        ev = self._registry(signer, revoked=True, revoked_at=500).evaluate_audit_head("k", payload, sig, now=5000)
        self.assertEqual((ev.ok, ev.head_status), (False, "signed-after-revocation"))

    def test_four_way_status_revocation_takes_precedence_over_expiry(self):
        # A v2 head signed while valid, on a key that is now BOTH expired and later-revoked:
        # revocation is the more serious fact and wins the reported status.
        signer = EnvelopeSigner.generate("k", self.HOST)
        payload, sig = self._v2(signer, signed_at=1000)
        registry = self._registry(signer, expires_at=1500, revoked=True, revoked_at=2000)
        evaluation = registry.evaluate_audit_head("k", payload, sig, now=5000)
        self.assertEqual((evaluation.ok, evaluation.head_status), (True, "valid-key-revoked"))

    # PA5 -----------------------------------------------------------------
    def test_v1_legacy_policy_valid_and_revoked_suspect(self):
        from portmark.security import audit_head_payload

        signer = EnvelopeSigner.generate("k", self.HOST)
        v1_sig = signer.sign_audit_head("t", self.HOST, "hash", 0)  # v1, no signed_at
        v1_payload = audit_head_payload("t", self.HOST, "hash", 0)

        ev = self._registry(signer).evaluate_audit_head("k", v1_payload, v1_sig, now=5000)
        self.assertEqual((ev.ok, ev.head_status), (True, "valid-legacy-v1"))

        # v1 head + now-revoked key: cannot establish pre-compromise without a signing time.
        ev = self._registry(signer, revoked=True).evaluate_audit_head("k", v1_payload, v1_sig, now=5000)
        self.assertEqual((ev.ok, ev.head_status), (False, "revoked-key-legacy-v1"))

        # v1 head + expired key: benign expiry is NOT applied retroactively.
        ev = self._registry(signer, expires_at=1).evaluate_audit_head("k", v1_payload, v1_sig, now=5000)
        self.assertTrue(ev.ok)

    # PA6 -----------------------------------------------------------------
    def test_revocation_effective_time_distinguishes_before_and_after(self):
        signer = EnvelopeSigner.generate("k", self.HOST)
        payload, sig = self._v2(signer, signed_at=1000)

        before = self._registry(signer, revoked=True, revoked_at=2000).evaluate_audit_head("k", payload, sig, now=5000)
        self.assertEqual((before.ok, before.head_status), (True, "valid-key-revoked"))

        after = self._registry(signer, revoked=True, revoked_at=1000).evaluate_audit_head("k", payload, sig, now=5000)
        self.assertEqual((after.ok, after.head_status), (False, "signed-after-revocation"))

        # revoked with NO effective time => no pre-revocation trust
        no_time = self._registry(signer, revoked=True).evaluate_audit_head("k", payload, sig, now=5000)
        self.assertEqual((no_time.ok, no_time.head_status), (False, "signed-after-revocation"))


class KeygenForceMergeTests(unittest.TestCase):
    def _keygen(self, args: list[str]) -> None:
        with patch.object(sys, "argv", ["portmark", "keygen", *args]):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                try:
                    cli_main()
                except SystemExit:
                    pass

    def test_force_merge_adds_rotation_entry_without_clobbering(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trust.json"
            self._keygen(["--key-id", "key-a", "--issuer", "user:a", "--out-registry", str(path)])
            first = json.loads(path.read_text())
            self.assertEqual([i["key_id"] for i in first["identities"]], ["key-a"])

            self._keygen(["--key-id", "key-b", "--issuer", "user:a", "--out-registry", str(path), "--force"])
            merged = json.loads(path.read_text())
            self.assertEqual(sorted(i["key_id"] for i in merged["identities"]), ["key-a", "key-b"])

    def test_force_merge_rejects_duplicate_key_id_with_different_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trust.json"
            self._keygen(["--key-id", "dup", "--issuer", "user:a", "--out-registry", str(path)])
            with patch.object(sys, "argv", ["portmark", "keygen", "--key-id", "dup", "--issuer", "user:a", "--out-registry", str(path), "--force"]):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        cli_main()

    def test_force_merge_preserves_restrictive_permissions(self):
        if os.name != "posix":
            self.skipTest("POSIX file modes only")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trust.json"
            self._keygen(["--key-id", "key-a", "--issuer", "user:a", "--out-registry", str(path)])
            os.chmod(path, 0o600)
            self._keygen(["--key-id", "key-b", "--issuer", "user:a", "--out-registry", str(path), "--force"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


class MigrationUsageTests(unittest.TestCase):
    HOST = "host:mig"

    def _registry(self, signer: EnvelopeSigner, usages: tuple[str, ...]) -> TrustRegistry:
        registry = TrustRegistry()
        registry.add(TrustedIdentity(key_id=signer.key_id, issuer=self.HOST, public_key=signer.public_key_bytes(), allowed_audiences=("*",), usages=usages))
        return registry

    def test_migration_usage_required_for_migration_handoff_verification(self):
        from portmark.security import audit_head_payload

        signer = EnvelopeSigner.generate("k", self.HOST)
        payload = audit_head_payload("t", self.HOST, "hash", 3)
        sig = signer.sign_audit_head("t", self.HOST, "hash", 3)

        # A key permitted only for "audit" (not "migration") is rejected when the required
        # usage is "migration" (the migration-handoff verification path).
        audit_only = self._registry(signer, ("audit",))
        with self.assertRaisesRegex(SecurityError, "migration"):
            audit_only.verify_audit_head("k", payload, sig, required_usage="migration")
        # ... but still accepted on the ordinary audit path.
        audit_only.verify_audit_head("k", payload, sig)  # required_usage defaults to "audit"

    def test_migration_usage_permitted_key_verifies(self):
        signer = EnvelopeSigner.generate("k", self.HOST)
        from portmark.security import audit_head_payload

        payload = audit_head_payload("t", self.HOST, "hash", 3)
        sig = signer.sign_audit_head("t", self.HOST, "hash", 3)
        self._registry(signer, ("envelope", "migration")).verify_audit_head("k", payload, sig, required_usage="migration")


if __name__ == "__main__":
    unittest.main()

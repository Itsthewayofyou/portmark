import copy
import base64
import concurrent.futures
import json
import logging
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from dataclasses import asdict
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from portable_agent.a2a import A2AAuthConfig, envelope_from_dict, make_handler
from portable_agent.config import RuntimeConfig
from portable_agent.factory import make_demo_envelope, make_host
from portable_agent.logging_config import JsonLogFormatter
from portable_agent.models import AgentEnvelope, AgentManifest, AgentState, Permit, ProviderDecision, ResourceBudget, ToolGrant
from portable_agent.providers import GenericHttpProvider, ModelProvider
from portable_agent.policy import load_host_policy
from portable_agent.security import (
    ApprovalAuthority,
    AttestationAuthority,
    AttestationPolicy,
    EnvelopeSigner,
    HostPolicy,
    SecurityError,
    TrustRegistry,
    TrustedIdentity,
    canonical_json,
    load_trust_registry,
)
from portable_agent.storage import SQLiteRuntimeStore


WASM_TOOL_REQUEST = "AGFzbQEAAAABCQFgBH9/f38BfgMCAQAFAwEAAQcTAgZtZW1vcnkCAAZyZXN1bWUAAAoLAQkAQu+AgICAAgsLdQEAQRALb3sib3V0Y29tZSI6InRvb2wiLCJyZXF1ZXN0Ijp7Im5hbWUiOiJjYXRhbG9nLnNlYXJjaCIsImFyZ3VtZW50c19qc29uIjoie1wicXVlcnlcIjpcImZyb20gd2FzbVwiLFwibGltaXRcIjozfSJ9fQ=="
WASM_MALFORMED_JSON = "AGFzbQEAAAABCQFgBH9/f38BfgMCAQAFAwEAAQcTAgZtZW1vcnkCAAZyZXN1bWUAAAoLAQkAQomAgICAAgsLDwEAQRALCXtiYWQganNvbg=="
WASM_TIMEOUT = "AGFzbQEAAAABCQFgBH9/f38BfgMCAQAFAwEAAQcTAgZtZW1vcnkCAAZyZXN1bWUAAAoLAQkAA0AMAAtCAAs="
WASM_FORBIDDEN_IMPORT = "AGFzbQEAAAABDAJgAABgBH9/f38BfgIJAQNlbnYBeAAAAwIBAQUDAQABBxMCBm1lbW9yeQIABnJlc3VtZQABCgYBBABCAAs="
WASM_MISSING_RESUME = "AGFzbQEAAAAFAwEAAQcKAQZtZW1vcnkCAA=="


class FixedProvider(ModelProvider):
    def __init__(self, decision): self.decision = decision
    def decide(self, state, available_tools): return self.decision


class MigrateThenCompleteProvider(ModelProvider):
    def __init__(self, destination): self.destination = destination
    def decide(self, state, available_tools):
        if "migration" not in state.memory:
            return ProviderDecision("migrate", destination=self.destination)
        return ProviderDecision("complete", content={"resumed_on": self.destination})


class AttestedMigrateThenCompleteProvider(ModelProvider):
    def __init__(self, destination, attestation):
        self.destination = destination
        self.attestation = attestation
    def decide(self, state, available_tools):
        if "migration" not in state.memory:
            return ProviderDecision("migrate", destination=self.destination, content={"attestation": asdict(self.attestation)})
        return ProviderDecision("complete", content={"resumed_on": self.destination})


class ExplodingProvider(ModelProvider):
    def decide(self, state, available_tools):
        raise RuntimeError("provider crashed")


class PaymentProvider(ModelProvider):
    def __init__(self, amount=50):
        self.amount = amount
    def decide(self, state, available_tools):
        if "payments_reserve" not in state.memory:
            return ProviderDecision("tool", "payments.reserve", {"amount": self.amount, "currency": "USD"})
        return ProviderDecision("complete", content={"payment": state.memory["payments_reserve"]})


class RuntimeTests(unittest.TestCase):
    def test_demo_completes_with_audited_tool_call(self):
        host = make_host()
        result = host.run(make_demo_envelope(host, "research Telescript"))
        self.assertEqual(result.status, "completed")
        self.assertEqual([e["event"] for e in result.audit].count("tool.executed"), 1)
        self.assertEqual(len(result.result["evidence"]), 3)

    def test_runtime_config_merges_environment_and_cli_arguments(self):
        environment = {
            "PORTABLE_AGENT_HOST_ID": "host:env",
            "PORTABLE_AGENT_PROVIDER_ENDPOINT": "https://provider.example/run",
            "PORTABLE_AGENT_STORE_PATH": "env.sqlite",
            "PORTABLE_AGENT_POLICY_PATH": "env-policy.json",
            "PORTABLE_AGENT_TRUST_REGISTRY_PATH": "env-trust.json",
            "PORTABLE_AGENT_RELOAD_POLICY": "1",
            "PORTABLE_AGENT_LOG_LEVEL": "DEBUG",
            "PORTABLE_AGENT_LOG_JSON": "1",
            "PORTABLE_AGENT_ENABLE_HSTS": "1",
        }
        environment["PORTABLE_AGENT_A2A_" + "TOKEN"] = "env-" + "token"
        with patch.dict(os.environ, environment, clear=True):
            config = RuntimeConfig.from_environment().merged_with_args(SimpleNamespace(
                host_id="host:cli",
                provider_endpoint=None,
                wasm_component="capsule.wasm",
                store_path=None,
                policy_path="cli-policy.json",
                trust_registry_path=None,
                reload_policy=False,
                a2a_token=None,
                log_level=None,
                log_json=False,
                enable_hsts=False,
            ))
        self.assertEqual(config.host_id, "host:cli")
        self.assertEqual(config.provider_endpoint, "https://provider.example/run")
        self.assertEqual(config.wasm_component, "capsule.wasm")
        self.assertEqual(config.store_path, "env.sqlite")
        self.assertEqual(config.policy_path, "cli-policy.json")
        self.assertEqual(config.trust_registry_path, "env-trust.json")
        self.assertTrue(config.reload_policy)
        self.assertEqual(config.a2a_token, "env-token")
        self.assertTrue(config.log_json)
        self.assertTrue(config.enable_hsts)

    def test_json_log_formatter_emits_structured_internal_exception(self):
        formatter = JsonLogFormatter()
        try:
            raise RuntimeError("internal failure")
        except RuntimeError:
            record = logging.getLogger("portable_agent.test").makeRecord(
                "portable_agent.test", logging.ERROR, __file__, 1, "operation failed", (), exc_info=sys.exc_info()
            )
        payload = json.loads(formatter.format(record))
        self.assertEqual(payload["level"], "ERROR")
        self.assertEqual(payload["logger"], "portable_agent.test")
        self.assertEqual(payload["message"], "operation failed")
        self.assertIn("RuntimeError", payload["exception"])

    def test_external_trust_registry_allows_configured_signing_key(self):
        with tempfile.TemporaryDirectory() as directory:
            signer = EnvelopeSigner.generate("external-key", "host:local-demo", ("host:local-demo",))
            registry_path = Path(directory) / "trust.json"
            registry_path.write_text(json.dumps({
                "identities": [{
                    "key_id": "external-key",
                    "issuer": "host:local-demo",
                    "public_key_b64": base64.urlsafe_b64encode(signer.public_key_bytes()).decode("ascii").rstrip("="),
                    "allowed_audiences": ["host:local-demo"],
                }]
            }), encoding="utf-8")
            registry = load_trust_registry(registry_path)
            verifying_signer = EnvelopeSigner.from_private_key_bytes(
                "external-key",
                "host:local-demo",
                signer.private_key_bytes(),
                ("host:local-demo",),
                registry,
            )
            host = make_host(signer=verifying_signer)
            self.assertEqual(host.run(make_demo_envelope(host, "external trust")).status, "completed")

    def test_config_files_reject_malformed_policy_and_trust_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "bad-policy.json"
            policy_path.write_text(json.dumps({
                "version": "bad",
                "approval_required_impacts": ["external-payment", "invalid-impact"],
                "tools": {"payments.reserve": {"impact": "external-payment", "constraints": {}}},
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid impact"):
                load_host_policy(policy_path, "host:local-demo")

            registry_path = Path(directory) / "bad-trust.json"
            registry_path.write_text(json.dumps({
                "identities": [{
                    "key_id": "key",
                    "issuer": "host:issuer",
                    "public_key_b64": base64.urlsafe_b64encode(b"x" * 32).decode("ascii").rstrip("="),
                    "allowed_audiences": "host:destination",
                }]
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "allowed_audiences"):
                load_trust_registry(registry_path)

    def test_modified_envelope_is_rejected(self):
        host = make_host()
        envelope = make_demo_envelope(host, "safe goal")
        envelope.state.goal = "tampered goal"
        with self.assertRaisesRegex(SecurityError, "signature"):
            host.run(envelope)

    def test_ed25519_signature_and_key_id_are_required(self):
        signer = EnvelopeSigner.generate("trusted-key", "host:local-demo", ("host:local-demo",))
        host = make_host(signer=signer)
        envelope = make_demo_envelope(host, "signed goal")
        self.assertEqual(envelope.signature_key_id, "trusted-key")
        result = host.run(envelope)
        self.assertEqual(result.status, "completed")

        missing_key_id = make_demo_envelope(host, "missing key id")
        missing_key_id.signature_key_id = ""
        with self.assertRaisesRegex(SecurityError, "key id is missing"):
            host.run(missing_key_id)

    def test_canonical_signature_is_stable(self):
        private_key = bytes(range(32))
        signer = EnvelopeSigner.from_private_key_bytes("stable-key", "host:local-demo", private_key, ("host:local-demo",))
        host = make_host(signer=signer)
        first = make_demo_envelope(host, "stable")
        second = copy.deepcopy(first)
        first.signature = ""
        second.signature = ""
        self.assertEqual(canonical_json(first.unsigned_dict()), canonical_json(second.unsigned_dict()))
        self.assertEqual(signer.seal(first).signature, signer.seal(second).signature)

    def test_wrong_public_key_is_rejected(self):
        signer = EnvelopeSigner.generate("shared-key-id", "host:local-demo", ("host:local-demo",))
        verifier_with_wrong_key = EnvelopeSigner.generate("shared-key-id", "host:local-demo", ("host:local-demo",))
        host = make_host(signer=signer)
        envelope = make_demo_envelope(host, "wrong verifier")
        verifying_host = make_host(signer=verifier_with_wrong_key)
        with self.assertRaisesRegex(SecurityError, "signature"):
            verifying_host.run(envelope)

    def test_unknown_expired_and_revoked_keys_are_rejected(self):
        signer = EnvelopeSigner.generate("active-key", "host:local-demo", ("host:local-demo",))
        host = make_host(signer=signer)

        unknown = make_demo_envelope(host, "unknown key")
        unknown.signature_key_id = "missing-key"
        with self.assertRaisesRegex(SecurityError, "not trusted"):
            host.run(unknown)

        now = int(time.time())
        expired_registry = TrustRegistry((
            TrustedIdentity("expired-key", "host:local-demo", signer.public_key_bytes(), ("host:local-demo",), expires_at=now - 1),
        ))
        expired_signer = EnvelopeSigner.from_private_key_bytes(
            "expired-key", "host:local-demo", signer.private_key_bytes(), ("host:local-demo",), expired_registry
        )
        expired_host = make_host(signer=expired_signer)
        expired = make_demo_envelope(expired_host, "expired key")
        with self.assertRaisesRegex(SecurityError, "expired"):
            expired_host.run(expired)

        revoked_registry = TrustRegistry((
            TrustedIdentity("revoked-key", "host:local-demo", signer.public_key_bytes(), ("host:local-demo",), revoked=True),
        ))
        revoked_signer = EnvelopeSigner.from_private_key_bytes(
            "revoked-key", "host:local-demo", signer.private_key_bytes(), ("host:local-demo",), revoked_registry
        )
        revoked_host = make_host(signer=revoked_signer)
        revoked = make_demo_envelope(revoked_host, "revoked key")
        with self.assertRaisesRegex(SecurityError, "revoked"):
            revoked_host.run(revoked)

    def test_attested_execution_accepts_approved_measurement(self):
        authority = AttestationAuthority.generate()
        policy = AttestationPolicy((authority.trusted_authority(),), ("measurement:approved",), required_for_execution=True)
        host = make_host(attestation_policy=policy)
        envelope = make_demo_envelope(host, "attested execution")
        object.__setattr__(
            envelope.permit,
            "attestation",
            authority.issue(
                subject=host.host_id,
                audience=envelope.permit.issuer,
                measurement="measurement:approved",
                expires_at=int(time.time()) + 60,
                nonce=envelope.permit.nonce,
            ),
        )
        host.signer.seal(envelope)
        self.assertEqual(host.run(envelope).status, "completed")

    def test_attested_execution_rejects_missing_expired_wrong_measurement_audience_and_nonce(self):
        authority = AttestationAuthority.generate()
        policy = AttestationPolicy((authority.trusted_authority(),), ("measurement:approved",), required_for_execution=True)
        host = make_host(attestation_policy=policy)
        now = int(time.time())
        cases = [
            (None, "required"),
            (authority.issue(host.host_id, "host:local-demo", "measurement:approved", now - 1), "expired"),
            (authority.issue(host.host_id, "host:local-demo", "measurement:unapproved", now + 60), "measurement"),
            (authority.issue(host.host_id, "host:other", "measurement:approved", now + 60), "audience"),
            (authority.issue(host.host_id, "host:local-demo", "measurement:approved", now + 60, nonce="wrong"), "nonce"),
        ]
        for evidence, message in cases:
            with self.subTest(message=message):
                envelope = make_demo_envelope(host, "attested rejection")
                object.__setattr__(envelope.permit, "attestation", evidence)
                host.signer.seal(envelope)
                with self.assertRaisesRegex(SecurityError, message):
                    host.run(envelope)

    def test_attestation_rejects_unknown_verifier_and_tampered_evidence(self):
        authority = AttestationAuthority.generate()
        other = AttestationAuthority.generate("other-attestation-key", "verifier:other")
        policy = AttestationPolicy((authority.trusted_authority(),), ("measurement:approved",), required_for_execution=True)
        host = make_host(attestation_policy=policy)
        now = int(time.time())

        unknown = make_demo_envelope(host, "unknown verifier")
        object.__setattr__(
            unknown.permit,
            "attestation",
            other.issue(host.host_id, unknown.permit.issuer, "measurement:approved", now + 60, nonce=unknown.permit.nonce),
        )
        host.signer.seal(unknown)
        with self.assertRaisesRegex(SecurityError, "not trusted"):
            host.run(unknown)

        tampered = make_demo_envelope(host, "tampered evidence")
        evidence = authority.issue(host.host_id, tampered.permit.issuer, "measurement:approved", now + 60, nonce=tampered.permit.nonce)
        object.__setattr__(evidence, "claims", {"tampered": True})
        object.__setattr__(tampered.permit, "attestation", evidence)
        host.signer.seal(tampered)
        with self.assertRaisesRegex(SecurityError, "signature"):
            host.run(tampered)

    def test_signing_identity_must_match_issuer_and_audience(self):
        signer = EnvelopeSigner.generate("scoped-key", "host:local-demo", ("host:local-demo",))
        host = make_host(signer=signer)

        wrong_issuer = make_demo_envelope(host, "wrong issuer")
        object.__setattr__(wrong_issuer.permit, "issuer", "host:other")
        signer.seal(wrong_issuer)
        with self.assertRaisesRegex(SecurityError, "cannot sign for this issuer"):
            host.run(wrong_issuer)

        wrong_audience = make_demo_envelope(host, "wrong audience")
        object.__setattr__(wrong_audience.permit, "audience", "host:other")
        signer.seal(wrong_audience)
        with self.assertRaisesRegex(SecurityError, "cannot sign for this audience"):
            host.run(wrong_audience)

    def test_ungranted_tool_is_rejected_even_when_provider_requests_it(self):
        host = make_host()
        host.providers["evil"] = FixedProvider(ProviderDecision("tool", "payments.reserve", {"amount": 50, "currency": "USD"}))
        envelope = make_demo_envelope(host, "buy something", "evil")
        with self.assertRaisesRegex(SecurityError, "not granted"):
            host.run(envelope)

    def test_http_provider_rejects_non_http_schemes(self):
        with self.assertRaisesRegex(ValueError, "http or https"):
            GenericHttpProvider("file:///tmp/provider.json")

    def test_host_restricts_permit_more_than_agent_requests(self):
        host = make_host()
        host.providers["evil"] = FixedProvider(ProviderDecision("tool", "catalog.search", {"query": "x", "limit": 4}))
        envelope = make_demo_envelope(host, "search", "evil")
        with self.assertRaisesRegex(SecurityError, "maximum"):
            host.run(envelope)

    def test_json_policy_loads_grants_impacts_version_and_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            authority = ApprovalAuthority.generate()
            policy_path = self._write_policy(directory, authority)
            policy = load_host_policy(policy_path, "host:local-demo")
            self.assertEqual(policy.policy_version, "policy-v1")
            self.assertTrue(policy.policy_hash.startswith("sha256:"))
            self.assertEqual(policy.impact_for_tool("payments.reserve"), "external-payment")
            self.assertTrue(policy.requires_approval("payments.reserve"))
            self.assertFalse(policy.requires_approval("catalog.search"))

    def test_external_policy_denies_unlisted_tool_and_narrows_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = self._write_policy(directory, tools={
                "catalog.search": {"impact": "low", "constraints": {"max_limit": 2}},
            })
            host = make_host(policy_path=str(policy_path))
            host.providers["evil"] = FixedProvider(ProviderDecision("tool", "payments.reserve", {"amount": 50, "currency": "USD"}))
            with self.assertRaisesRegex(SecurityError, "not granted"):
                host.run(make_demo_envelope(host, "pay", "evil"))

            host.providers["searcher"] = FixedProvider(ProviderDecision("tool", "catalog.search", {"query": "x", "limit": 3}))
            with self.assertRaisesRegex(SecurityError, "maximum"):
                host.run(make_demo_envelope(host, "search", "searcher"))

    def test_high_impact_tool_requires_signed_approval_then_executes(self):
        authority = ApprovalAuthority.generate()
        policy = HostPolicy(
            "host:local-demo",
            (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}),),
            ResourceBudget(),
            "policy-v1",
            "policy-hash",
            {"payments.reserve": "external-payment"},
            (authority.trusted_approver(),),
        )
        host = make_host(attestation_policy=None)
        host.policy = policy
        host.providers["payer"] = PaymentProvider()
        envelope = make_demo_envelope(host, "pay vendor", "payer")
        object.__setattr__(envelope.permit, "grants", (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}),))
        host.signer.seal(envelope)

        first = host.run(envelope)
        self.assertEqual(first.status, "awaiting_input")
        self.assertEqual(first.result["approval_required"], True)
        self.assertEqual(first.result["policy_hash"], "policy-hash")
        self.assertIn("approval.requested", [event["event"] for event in first.audit])

        token = authority.issue(
            "payments.reserve",
            envelope.permit.subject,
            envelope.permit.audience,
            envelope.state.task_id,
            envelope.permit.nonce,
            {"amount": 50, "currency": "USD"},
            "policy-hash",
            int(time.time()) + 60,
        )
        envelope.state.memory["approvals"] = {"payments.reserve": asdict(token)}
        host.signer.seal(envelope)
        second = host.run(envelope)
        events = [event["event"] for event in second.audit]
        self.assertEqual(second.status, "completed")
        self.assertIn("approval.approved", events)
        self.assertIn("approval.used", events)
        self.assertEqual(second.result["payment"]["reserved"], True)

    def test_high_impact_approval_expiry_and_replay_are_rejected(self):
        authority = ApprovalAuthority.generate()
        policy = HostPolicy(
            "host:local-demo",
            (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}),),
            ResourceBudget(),
            "policy-v1",
            "policy-hash",
            {"payments.reserve": "external-payment"},
            (authority.trusted_approver(),),
        )
        host = make_host()
        host.policy = policy
        host.providers["payer"] = PaymentProvider()

        expired = make_demo_envelope(host, "expired approval", "payer")
        object.__setattr__(expired.permit, "grants", (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}),))
        expired_token = authority.issue(
            "payments.reserve",
            expired.permit.subject,
            expired.permit.audience,
            expired.state.task_id,
            expired.permit.nonce,
            {"amount": 50, "currency": "USD"},
            "policy-hash",
            int(time.time()) - 1,
        )
        expired.state.memory["approvals"] = {"payments.reserve": asdict(expired_token)}
        host.signer.seal(expired)
        expired_result = host.run(expired)
        self.assertEqual(expired_result.status, "failed")
        self.assertIn("approval.expired", [event["event"] for event in expired_result.audit])

        replayed = make_demo_envelope(host, "replayed approval", "payer")
        object.__setattr__(replayed.permit, "grants", (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}),))
        token = authority.issue(
            "payments.reserve",
            replayed.permit.subject,
            replayed.permit.audience,
            replayed.state.task_id,
            replayed.permit.nonce,
            {"amount": 50, "currency": "USD"},
            "policy-hash",
            int(time.time()) + 60,
        )
        replayed.state.memory["approvals"] = {"payments.reserve": asdict(token)}
        replayed.state.memory["used_approval_ids"] = [token.approval_id]
        host.signer.seal(replayed)
        replay_result = host.run(replayed)
        self.assertEqual(replay_result.status, "failed")
        self.assertIn("approval.denied", [event["event"] for event in replay_result.audit])

    def test_policy_reload_invalidates_stale_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            authority = ApprovalAuthority.generate()
            policy_path = self._write_policy(directory, authority, version="policy-v1")
            host = make_host(policy_path=str(policy_path), reload_policy=True)
            host.providers["payer"] = PaymentProvider()
            envelope = make_demo_envelope(host, "reload policy", "payer")
            object.__setattr__(envelope.permit, "grants", (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}),))
            host.signer.seal(envelope)
            first = host.run(envelope)

            token = authority.issue(
                "payments.reserve",
                envelope.permit.subject,
                envelope.permit.audience,
                envelope.state.task_id,
                envelope.permit.nonce,
                {"amount": 50, "currency": "USD"},
                first.result["policy_hash"],
                int(time.time()) + 60,
            )
            self._write_policy(directory, authority, version="policy-v2")
            envelope.state.memory["approvals"] = {"payments.reserve": asdict(token)}
            host.signer.seal(envelope)
            second = host.run(envelope)
            self.assertEqual(second.status, "failed")
            self.assertIn("approval.denied", [event["event"] for event in second.audit])

    def test_wrong_audience_and_expired_permits_are_rejected(self):
        for mutate, message in [
            (lambda p: p.__dict__.update(audience="host:other"), "intended"),
            (lambda p: p.__dict__.update(expires_at=int(time.time()) - 1), "expired"),
        ]:
            host = make_host(signer=EnvelopeSigner.generate("policy-test-key", "host:local-demo", ("*",)))
            envelope = make_demo_envelope(host, "goal")
            mutate(envelope.permit)
            host.signer.seal(envelope)
            with self.assertRaisesRegex(SecurityError, message):
                host.run(envelope)

    def test_replay_of_fresh_envelope_is_rejected(self):
        host = make_host()
        envelope = make_demo_envelope(host, "goal")
        host.run(envelope)
        envelope.state.status = "ready"
        host.signer.seal(envelope)
        with self.assertRaisesRegex(SecurityError, "nonce"):
            host.run(envelope)

    def test_sqlite_store_rejects_replay_after_host_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            signer = EnvelopeSigner.generate("store-key", "host:local-demo", ("host:local-demo",))
            first_host = make_host(signer=signer, store=SQLiteRuntimeStore(path))
            envelope = make_demo_envelope(first_host, "durable replay")
            result = first_host.run(envelope)
            self.assertEqual(result.status, "completed")

            second_host = make_host(signer=signer, store=SQLiteRuntimeStore(path))
            replay = copy.deepcopy(envelope)
            replay.state.status = "ready"
            signer.seal(replay)
            with self.assertRaisesRegex(SecurityError, "nonce"):
                second_host.run(replay)
            self.assertTrue(second_host.store.consumed_nonce_exists(replay.permit.nonce))

    def test_sqlite_store_persists_checkpoint_and_audit_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host = make_host(store=store)
            result = host.run(make_demo_envelope(host, "persist me"))
            checkpoint = store.load_checkpoint(result.task_id)
            self.assertIsNotNone(checkpoint)
            self.assertEqual(checkpoint["status"], "completed")
            self.assertEqual(checkpoint["result"], result.result)
            self.assertTrue(store.verify_audit_chain(result.task_id))
            self.assertEqual(store.audit_head(result.task_id), (result.audit[-1]["hash"], result.audit[-1]["sequence"] + 1))

    def test_sqlite_transaction_rolls_back_partial_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            event = {"sequence": 0, "event": "agent.accepted", "details": {}, "previous": "", "hash": "duplicate"}
            with self.assertRaisesRegex(SecurityError, "audit"):
                with store.transaction() as transaction:
                    transaction.consume_nonce("nonce-1", "agent:demo", "host:local-demo", "task-1")
                    transaction.append_audit_events("task-1", "host:local-demo", (event, event))
            self.assertFalse(store.consumed_nonce_exists("nonce-1"))
            self.assertIsNone(store.load_checkpoint("task-1"))
            self.assertIsNone(store.audit_head("task-1"))

    def test_sqlite_store_rejects_non_contiguous_audit_previous_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            first = {"sequence": 0, "event": "agent.accepted", "details": {}, "previous": "", "hash": "head"}
            second = {"sequence": 1, "event": "agent.completed", "details": {}, "previous": "wrong", "hash": "tail"}
            with self.assertRaisesRegex(SecurityError, "previous hash"):
                with store.transaction() as transaction:
                    transaction.append_audit_events("task-1", "host:local-demo", (first, second))
            self.assertIsNone(store.audit_head("task-1"))

    def test_sqlite_migration_checkpoint_and_audit_are_recoverable(self):
        with tempfile.TemporaryDirectory() as directory:
            signer = EnvelopeSigner.generate("source-key", "host:source", ("host:source", "host:destination"))
            source_store = SQLiteRuntimeStore(Path(directory) / "source.sqlite")
            destination_store = SQLiteRuntimeStore(Path(directory) / "destination.sqlite")
            source = make_host(host_id="host:source", signer=signer, store=source_store)
            destination = make_host(host_id="host:destination", signer=signer, store=destination_store)
            provider = MigrateThenCompleteProvider(destination.host_id)
            source.providers["migrator"] = provider
            destination.providers["migrator"] = provider
            envelope = make_demo_envelope(source, "move durably", "migrator")
            object.__setattr__(envelope.permit, "delegation_allowed", True)
            signer.seal(envelope)

            first = source.run(envelope)
            source_checkpoint = source_store.load_checkpoint(first.task_id)
            self.assertEqual(source_checkpoint["status"], "ready")
            self.assertEqual(source_checkpoint["memory"]["migration"], {"from": "host:source", "to": "host:destination"})
            self.assertTrue(source_store.verify_audit_chain(first.task_id))

            from portable_agent.a2a import envelope_from_dict
            second = destination.run(envelope_from_dict(first.migration_envelope))
            self.assertEqual(second.status, "completed")
            self.assertEqual(destination_store.load_checkpoint(second.task_id)["status"], "completed")
            self.assertTrue(destination_store.verify_audit_chain(second.task_id))

    def test_sqlite_store_rejects_concurrent_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            signer = EnvelopeSigner.generate("concurrent-key", "host:local-demo", ("host:local-demo",))
            host = make_host(signer=signer, store=SQLiteRuntimeStore(path))
            envelope = make_demo_envelope(host, "race")

            def run_once():
                local_host = make_host(signer=signer, store=SQLiteRuntimeStore(path))
                return local_host.run(copy.deepcopy(envelope)).status

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(run_once) for _ in range(2)]
                outcomes = []
                for future in futures:
                    try:
                        outcomes.append(future.result())
                    except SecurityError:
                        outcomes.append("rejected")
            self.assertEqual(outcomes.count("completed"), 1)
            self.assertEqual(outcomes.count("rejected"), 1)

    def test_delegated_migration_resumes_on_destination(self):
        signer = EnvelopeSigner.generate("source-key", "host:source", ("host:source", "host:destination"))
        source = make_host(host_id="host:source", signer=signer)
        destination = make_host(host_id="host:destination", signer=source.signer)
        provider = MigrateThenCompleteProvider(destination.host_id)
        source.providers["migrator"] = provider
        destination.providers["migrator"] = provider
        envelope = make_demo_envelope(source, "move safely", "migrator")
        object.__setattr__(envelope.permit, "delegation_allowed", True)
        source.signer.seal(envelope)
        first = source.run(envelope)
        self.assertIsNotNone(first.migration_envelope)
        from portable_agent.a2a import envelope_from_dict
        migrated = envelope_from_dict(first.migration_envelope)
        self.assertEqual(migrated.permit.audience, destination.host_id)
        self.assertFalse(migrated.permit.delegation_allowed)
        second = destination.run(migrated)
        self.assertEqual(second.status, "completed")
        self.assertEqual(second.result["resumed_on"], destination.host_id)

    def test_attested_migration_requires_destination_evidence_and_resumes(self):
        authority = AttestationAuthority.generate()
        policy = AttestationPolicy(
            (authority.trusted_authority(),),
            ("measurement:destination",),
            required_for_execution=True,
            required_for_migration=True,
        )
        signer = EnvelopeSigner.generate("source-key", "host:source", ("host:source", "host:destination"))
        source = make_host(host_id="host:source", signer=signer, attestation_policy=policy)
        destination = make_host(host_id="host:destination", signer=signer, attestation_policy=policy)
        destination_evidence = authority.issue(
            subject=destination.host_id,
            audience=source.host_id,
            measurement="measurement:destination",
            expires_at=int(time.time()) + 60,
        )
        provider = AttestedMigrateThenCompleteProvider(destination.host_id, destination_evidence)
        source.providers["attested-migrator"] = provider
        destination.providers["attested-migrator"] = provider
        envelope = make_demo_envelope(source, "move into enclave", "attested-migrator")
        object.__setattr__(envelope.permit, "delegation_allowed", True)
        object.__setattr__(
            envelope.permit,
            "attestation",
            authority.issue(source.host_id, envelope.permit.issuer, "measurement:destination", int(time.time()) + 60, nonce=envelope.permit.nonce),
        )
        signer.seal(envelope)

        first = source.run(envelope)
        self.assertEqual(first.checkpoint["memory"]["migration"]["attested_measurement"], "measurement:destination")
        migrated = envelope_from_dict(first.migration_envelope)
        self.assertEqual(migrated.permit.attestation.measurement, "measurement:destination")
        second = destination.run(migrated)
        self.assertEqual(second.status, "completed")
        self.assertEqual(second.result["resumed_on"], destination.host_id)

    def test_attested_migration_rejects_missing_destination_evidence(self):
        authority = AttestationAuthority.generate()
        policy = AttestationPolicy((authority.trusted_authority(),), ("measurement:destination",), required_for_migration=True)
        signer = EnvelopeSigner.generate("source-key", "host:source", ("host:source", "host:destination"))
        source = make_host(host_id="host:source", signer=signer, attestation_policy=policy)
        source.providers["migrator"] = MigrateThenCompleteProvider("host:destination")
        envelope = make_demo_envelope(source, "move without proof", "migrator")
        object.__setattr__(envelope.permit, "delegation_allowed", True)
        signer.seal(envelope)
        with self.assertRaisesRegex(SecurityError, "required"):
            source.run(envelope)

    def test_a2a_agent_card_and_signed_submission(self):
        host = make_host()
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(host, A2AAuthConfig("a2a-secret")))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urllib.request.urlopen(base + "/.well-known/agent-card.json") as response:  # nosec B310
                card = json.load(response)
            self.assertEqual(card["protocolVersion"], "1.0")
            self.assertEqual(card["supportedInterfaces"][0]["protocolBinding"], "JSONRPC")
            self.assertEqual(card["supportedInterfaces"][0]["protocolVersion"], "1.0")
            self.assertEqual(card["defaultInputModes"], ["application/json"])
            self.assertEqual(card["securitySchemes"]["bearer"]["scheme"], "bearer")
            self.assertEqual(card["securityRequirements"], [{"bearer": []}])
            self.assertEqual(card["skills"][0]["id"], "portable-agent")
            body = self._a2a_request_body(host, "A2A task")
            request = urllib.request.Request(
                base + "/message:send",
                data=body,
                headers={"Content-Type": "application/json", "Authorization": "Bearer a2a-secret"},
            )
            with urllib.request.urlopen(request) as response:  # nosec B310
                result = json.load(response)
            self.assertEqual(result["jsonrpc"], "2.0")
            self.assertEqual(result["id"], "req-1")
            self.assertEqual(result["result"]["status"]["state"], "completed")
            self.assertEqual(result["result"]["metadata"]["portable_agent_status"], "completed")
        finally:
            server.shutdown()
            server.server_close()

    def test_a2a_security_headers_are_set_with_opt_in_hsts(self):
        host = make_host()
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(host, enable_hsts=True))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urllib.request.urlopen(base + "/.well-known/agent-card.json") as response:  # nosec B310
                self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
                self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
                self.assertEqual(response.headers["X-Frame-Options"], "DENY")
                self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])
                self.assertIn("geolocation=()", response.headers["Permissions-Policy"])
                self.assertEqual(response.headers["Strict-Transport-Security"], "max-age=31536000")
        finally:
            server.shutdown()
            server.server_close()

    def test_a2a_errors_do_not_expose_internal_exception_details(self):
        host = make_host()
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(host))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            envelope = make_demo_envelope(host, "A2A tamper")
            envelope.state.goal = "tampered after signing"
            body = self._a2a_request_body(host, "A2A tamper", envelope=envelope)
            request = urllib.request.Request(base + "/message:send", data=body, headers={"Content-Type": "application/json"})
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request)  # nosec B310
            payload = json.load(raised.exception)
            self.assertEqual(payload, {"jsonrpc": "2.0", "id": "req-1", "error": {"code": -32000, "message": "message submission failed"}})
            self.assertNotIn("SecurityError", json.dumps(payload))
            self.assertNotIn("signature", json.dumps(payload))
        finally:
            server.shutdown()
            server.server_close()

    def test_a2a_requires_bearer_auth_before_envelope_parsing(self):
        host = make_host()
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(host, A2AAuthConfig("a2a-secret")))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            body = json.dumps({
                "jsonrpc": "2.0",
                "id": "req-1",
                "method": "message/send",
                "params": {
                    "message": {"messageId": "msg-1", "role": "user", "parts": [{"kind": "text", "text": "run"}]},
                    "metadata": {"portable_agent_envelope": {"signature": "broken"}},
                },
            }).encode()
            request = urllib.request.Request(base + "/message:send", data=body, headers={"Content-Type": "application/json"})
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request)  # nosec B310
            self.assertEqual(raised.exception.code, 401)
            payload = json.load(raised.exception)
            self.assertEqual(payload["error"]["code"], -32001)
            self.assertEqual(payload["error"]["message"], "unauthorized")
            self.assertNotIn("signature", json.dumps(payload))

            request = urllib.request.Request(
                base + "/message:send",
                data=body,
                headers={"Content-Type": "application/json", "Authorization": "Bearer wrong"},
            )
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request)  # nosec B310
            self.assertEqual(raised.exception.code, 401)
        finally:
            server.shutdown()
            server.server_close()

    def test_a2a_rejects_malformed_unsupported_oversized_and_wrong_content_type(self):
        host = make_host()
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(host))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            cases = [
                (b"{", {"Content-Type": "application/json"}, 400, -32700),
                (json.dumps({"jsonrpc": "2.0", "id": "bad-method", "method": "tasks/get", "params": {}}).encode(), {"Content-Type": "application/json"}, 400, -32601),
                (b"{}", {"Content-Type": "text/plain"}, 415, -32600),
                (b"x" * 1_000_001, {"Content-Type": "application/json"}, 413, -32600),
            ]
            for body, headers, status, code in cases:
                request = urllib.request.Request(base + "/message:send", data=body, headers=headers)
                with self.subTest(status=status, code=code):
                    with self.assertRaises(urllib.error.HTTPError) as raised:
                        urllib.request.urlopen(request)  # nosec B310
                    self.assertEqual(raised.exception.code, status)
                    payload = json.load(raised.exception)
                    self.assertEqual(payload["jsonrpc"], "2.0")
                    self.assertEqual(payload["error"]["code"], code)
        finally:
            server.shutdown()
            server.server_close()

    def _a2a_request_body(self, host, text, envelope=None):
        return json.dumps({
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "message/send",
            "params": {
                "message": {"messageId": "msg-1", "role": "user", "parts": [{"kind": "text", "text": text}]},
                "metadata": {"portable_agent_envelope": asdict(envelope or make_demo_envelope(host, text))},
            },
        }).encode()

    def _write_policy(self, directory, authority=None, version="policy-v1", tools=None):
        path = Path(directory) / "host-policy.json"
        authorities = []
        if authority is not None:
            authorities.append({
                "key_id": authority.key_id,
                "approver": authority.approver,
                "public_key_b64": authority.public_key_b64(),
            })
        path.write_text(json.dumps({
            "version": version,
            "budget": {"max_steps": 10, "max_tool_calls": 5, "max_output_bytes": 65536},
            "approval_authorities": authorities,
            "tools": tools or {
                "catalog.search": {"impact": "low", "constraints": {"max_limit": 5}},
                "payments.reserve": {"impact": "external-payment", "constraints": {"max_amount": 100, "currency": "USD"}},
            },
        }), encoding="utf-8")
        return path

    def test_real_wasm_capsule_completes_inside_deadline_limited_sandbox(self):
        capsule = Path(__file__).parents[1] / "capsules" / "research-agent.wasm.b64"
        host = make_host(wasm_component=str(capsule))
        result = host.run(make_demo_envelope(host, "portable execution", "wasm"))
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.result["summary"], "Wasm completed through WIT resume")
        self.assertEqual(result.result["evidence"], [])

    def test_wasm_with_ambient_wasi_import_cannot_instantiate(self):
        from portable_agent.providers import WasmDecisionProvider
        hostile = base64.b64decode(WASM_FORBIDDEN_IMPORT)
        provider = WasmDecisionProvider(hostile)
        with self.assertRaisesRegex(RuntimeError, "ambient imports"):
            provider.decide(AgentState("task", "goal"), ())

    def test_wasm_component_tool_decision_uses_structured_wit_outcome(self):
        from portable_agent.providers import WasmDecisionProvider
        provider = WasmDecisionProvider(base64.b64decode(WASM_TOOL_REQUEST))
        decision = provider.decide(AgentState("task", "goal"), ("catalog.search",))
        self.assertEqual(decision.kind, "tool")
        self.assertEqual(decision.tool, "catalog.search")
        self.assertEqual(decision.arguments, {"query": "from wasm", "limit": 3})

    def test_wasm_component_unavailable_capability_fails_closed(self):
        from portable_agent.providers import WasmDecisionProvider
        provider = WasmDecisionProvider(base64.b64decode(WASM_TOOL_REQUEST))
        decision = provider.decide(AgentState("task", "goal"), ())
        self.assertEqual(decision.kind, "fail")
        self.assertEqual(decision.content, {"error": "required capability unavailable"})

    def test_wasm_component_malformed_missing_timeout_and_oversized_outputs_are_rejected(self):
        from portable_agent.providers import WasmDecisionProvider
        cases = [
            (WASM_MALFORMED_JSON, {}, "malformed decision JSON"),
            (WASM_MISSING_RESUME, {}, "must export resume"),
            (WASM_TIMEOUT, {"timeout": 0.01}, "deadline"),
            (WASM_TOOL_REQUEST, {"max_output_bytes": 8}, "output limit"),
        ]
        for encoded, kwargs, message in cases:
            provider = WasmDecisionProvider(base64.b64decode(encoded), **kwargs)
            with self.subTest(message=message):
                with self.assertRaisesRegex(RuntimeError, message):
                    provider.decide(AgentState("task", "goal"), ("catalog.search",))


if __name__ == "__main__":
    unittest.main()

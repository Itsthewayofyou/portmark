import copy
import asyncio
import base64
import concurrent.futures
import hashlib
import importlib.util
import io
import json
import logging
import os
import secrets
import sqlite3
import sys
import tempfile
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request
from dataclasses import asdict
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from http.client import HTTPResponse
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from portmark.a2a import MAX_REQUEST_BYTES, DEFAULT_MAX_CONCURRENT_REQUESTS, A2AAuthConfig, BoundedReferenceHTTPServer, RateLimiter, envelope_from_dict, is_loopback_bind, make_asgi_app, make_handler, serve
from portmark.a2a_types import make_agent_card
from portmark.config import RuntimeConfig
from portmark.factory import build_envelope, make_demo_envelope, make_host, signer_from_environment
from portmark.metrics import RuntimeMetrics
from portmark.logging_config import JsonLogFormatter
from portmark.models import AgentEnvelope, AgentManifest, AgentState, AttestationEvidence, Permit, ProviderDecision, ResourceBudget, ToolGrant
from portmark.providers import GenericHttpProvider, ModelProvider, NativeWasmtimeComponentProvider
from portmark.policy import load_host_policy
from portmark.security import (
    ApprovalAuthority,
    AttestationAuthority,
    AttestationPolicy,
    EnvelopeSigner,
    ExternalAttestationVerifier,
    HmacEnvelopeSigner,
    HostPolicy,
    SecurityError,
    TrustRegistry,
    TrustedIdentity,
    canonical_json,
    generate_signing_material,
    load_trust_registry,
)
from portmark.storage import SQLITE_BUSY_TIMEOUT_MS, SQLITE_SCHEMA_VERSION, PostgresRuntimeStore, SQLiteRuntimeStore
from portmark.cli import main as cli_main
from portmark.tools import ToolRegistry
from examples.tools import http_fetch
from fuzz_a2a_parser import run_fuzz_cases


WASM_TOOL_REQUEST = "AGFzbQEAAAABCQFgBH9/f38BfgMCAQAFAwEAAQcTAgZtZW1vcnkCAAZyZXN1bWUAAAoLAQkAQu+AgICAAgsLdQEAQRALb3sib3V0Y29tZSI6InRvb2wiLCJyZXF1ZXN0Ijp7Im5hbWUiOiJjYXRhbG9nLnNlYXJjaCIsImFyZ3VtZW50c19qc29uIjoie1wicXVlcnlcIjpcImZyb20gd2FzbVwiLFwibGltaXRcIjozfSJ9fQ=="
WASM_MALFORMED_JSON = "AGFzbQEAAAABCQFgBH9/f38BfgMCAQAFAwEAAQcTAgZtZW1vcnkCAAZyZXN1bWUAAAoLAQkAQomAgICAAgsLDwEAQRALCXtiYWQganNvbg=="
WASM_TIMEOUT = "AGFzbQEAAAABCQFgBH9/f38BfgMCAQAFAwEAAQcTAgZtZW1vcnkCAAZyZXN1bWUAAAoLAQkAA0AMAAtCAAs="
WASM_FORBIDDEN_IMPORT = "AGFzbQEAAAABDAJgAABgBH9/f38BfgIJAQNlbnYBeAAAAwIBAQUDAQABBxMCBm1lbW9yeQIABnJlc3VtZQABCgYBBABCAAs="
WASM_MISSING_RESUME = "AGFzbQEAAAAFAwEAAQcKAQZtZW1vcnkCAA=="
HAS_REAL_WASMTIME = importlib.util.find_spec("wasmtime") is not None
HAS_REAL_A2A_SDK = importlib.util.find_spec("a2a") is not None


class FixedProvider(ModelProvider):
    def __init__(self, decision): self.decision = decision
    def decide(self, state, available_tools, grants=()): return self.decision


class MigrateThenCompleteProvider(ModelProvider):
    def __init__(self, destination): self.destination = destination
    def decide(self, state, available_tools, grants=()):
        if "migration" not in state.memory:
            return ProviderDecision("migrate", destination=self.destination)
        return ProviderDecision("complete", content={"resumed_on": self.destination})


class AttestedMigrateThenCompleteProvider(ModelProvider):
    def __init__(self, destination, attestation):
        self.destination = destination
        self.attestation = attestation
    def decide(self, state, available_tools, grants=()):
        if "migration" not in state.memory:
            return ProviderDecision("migrate", destination=self.destination, content={"attestation": asdict(self.attestation)})
        return ProviderDecision("complete", content={"resumed_on": self.destination})


class ExplodingProvider(ModelProvider):
    def decide(self, state, available_tools, grants=()):
        raise RuntimeError("provider crashed")


class PaymentProvider(ModelProvider):
    def __init__(self, amount=50):
        self.amount = amount
    def decide(self, state, available_tools, grants=()):
        if "payments_reserve" not in state.memory:
            return ProviderDecision("tool", "payments.reserve", {"amount": self.amount, "currency": "USD"})
        return ProviderDecision("complete", content={"payment": state.memory["payments_reserve"]})


class BlockingProvider(ModelProvider):
    def __init__(self, entered, release):
        self.entered = entered
        self.release = release

    def decide(self, state, available_tools, grants=()):
        self.entered.set()
        self.release.wait(10)
        return ProviderDecision("complete", content={"blocked": True})


class LargeToolProvider(ModelProvider):
    def decide(self, state, available_tools, grants=()):
        if "large" not in state.memory:
            return ProviderDecision("tool", "large.output", {})
        return ProviderDecision("complete", content={"large": state.memory["large"]})


class EchoThenCompleteProvider(ModelProvider):
    def decide(self, state, available_tools, grants=()):
        if "custom_echo" not in state.memory:
            return ProviderDecision("tool", "custom.echo", {"text": "hello"})
        return ProviderDecision("complete", content={"echo": state.memory["custom_echo"]})


class HttpFetchThenCompleteProvider(ModelProvider):
    def __init__(self, arguments):
        self.arguments = arguments

    def decide(self, state, available_tools, grants=()):
        if "http_fetch" not in state.memory:
            return ProviderDecision("tool", "http.fetch", self.arguments)
        return ProviderDecision("complete", content={"fetch": state.memory["http_fetch"]})


class DigestProvider(FixedProvider):
    component_digest = "wasm:expected"


def trusted_identity_for(signer: EnvelopeSigner, allowed_audiences=("*",)):
    return TrustedIdentity(signer.key_id, signer.issuer, signer.public_key_bytes(), tuple(allowed_audiences))


def trust_signer(verifier: EnvelopeSigner, signer: EnvelopeSigner) -> EnvelopeSigner:
    if not verifier.registry.has_key(signer.key_id):
        verifier.registry.add(trusted_identity_for(signer))
    return verifier


class FakeHttpResponse:
    def __init__(self, body, status=200, headers=None):
        self.body = body
        self.read_size = None
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def read(self, size=-1):
        self.read_size = size
        if size < 0:
            return self.body
        return self.body[:size]


class RuntimeTests(unittest.TestCase):
    def test_demo_completes_with_audited_tool_call(self):
        host = make_host()
        result = host.run(make_demo_envelope(host, "research Telescript"))
        self.assertEqual(result.status, "completed")
        self.assertEqual([e["event"] for e in result.audit].count("tool.executed"), 1)
        self.assertEqual(len(result.result["evidence"]), 3)

    def test_runtime_metrics_record_run_provider_tool_and_security_outcomes(self):
        metrics = RuntimeMetrics()
        host = make_host(metrics=metrics)
        self.assertEqual(host.run(make_demo_envelope(host, "metrics")).status, "completed")
        snapshot = metrics.snapshot()["counters"]
        self.assertEqual(snapshot["runs.started"], 1)
        self.assertEqual(snapshot["runs.completed"], 1)
        self.assertEqual(snapshot["provider.decisions"], 2)
        self.assertEqual(snapshot["tools.executed"], 1)

        tampered = make_demo_envelope(host, "metrics reject")
        tampered.state.goal = "tampered"
        with self.assertRaises(SecurityError):
            host.run(tampered)
        snapshot = metrics.snapshot()["counters"]
        self.assertEqual(snapshot["runs.failed"], 1)
        self.assertEqual(snapshot["security.rejections"], 1)

    def test_runtime_metrics_snapshot_remains_counter_only_json_shape(self):
        metrics = RuntimeMetrics()
        metrics.increment("runs.started")
        metrics.increment_refusal("unauthorized")
        metrics.observe_duration("run_duration_seconds", 0.01)
        self.assertEqual(metrics.snapshot(), {"counters": {"runs.started": 1}})

    def test_runtime_metrics_prometheus_output_includes_operational_metrics(self):
        metrics = RuntimeMetrics()
        metrics.increment("runs.started")
        metrics.increment_refusal("unauthorized")
        metrics.observe_duration("run_duration_seconds", 0.01)
        text = metrics.prometheus_text()
        self.assertIn('portmark_runtime_counter_total{name="runs.started"} 1', text)
        self.assertIn('portmark_refusals_total{reason="unauthorized"} 1', text)
        self.assertIn("portmark_run_duration_seconds_count 1", text)
        self.assertIn("portmark_run_duration_seconds_sum ", text)

    def test_runtime_metrics_refusal_labels_are_bounded(self):
        metrics = RuntimeMetrics()
        metrics.increment_refusal('task-123";tool="payments.reserve')
        text = metrics.prometheus_text()
        self.assertIn('portmark_refusals_total{reason="internal"} 1', text)
        self.assertNotIn("task-123", text)
        self.assertNotIn("payments.reserve", text)

    def test_runtime_config_merges_environment_and_cli_arguments(self):
        environment = {
            "PORTMARK_HOST_ID": "host:env",
            "PORTMARK_PROVIDER_ENDPOINT": "https://provider.example/run",
            "PORTMARK_STORE_BACKEND": "postgres",
            "PORTMARK_STORE_PATH": "env.sqlite",
            "PORTMARK_WASM_ENGINE": "wasmtime",
            "PORTMARK_POLICY_PATH": "env-policy.json",
            "PORTMARK_TRUST_REGISTRY_PATH": "env-trust.json",
            "PORTMARK_RELOAD_POLICY": "1",
            "PORTMARK_ATTESTATION_VERIFIER_COMMAND": "/bin/verify-attestation --json",
            "PORTMARK_REQUIRE_ATTESTATION": "1",
            "PORTMARK_A2A_ADAPTER": "sdk",
            "PORTMARK_LOG_LEVEL": "DEBUG",
            "PORTMARK_LOG_JSON": "1",
            "PORTMARK_ENABLE_HSTS": "1",
            "PORTMARK_ALLOW_DIRECT_A2A": "1",
            "PORTMARK_A2A_MAX_CONCURRENT_REQUESTS": "12",
            "PORTMARK_A2A_RATE_LIMIT_PER_IP": "34",
            "PORTMARK_A2A_RATE_LIMIT_WINDOW_SECONDS": "56",
            "PORTMARK_A2A_AGENT_CARD_RATE_LIMIT_PER_IP": "78",
            "PORTMARK_A2A_AGENT_CARD_RATE_LIMIT_WINDOW_SECONDS": "90",
        }
        environment["PORTMARK_A2A_" + "TOKEN"] = "env-" + "token"
        with patch.dict(os.environ, environment, clear=True):
            config = RuntimeConfig.from_environment().merged_with_args(SimpleNamespace(
                host_id="host:cli",
                provider_endpoint=None,
                wasm_component="capsule.wasm",
                wasm_engine=None,
                store_backend=None,
                store_path=None,
                policy_path="cli-policy.json",
                trust_registry_path=None,
                reload_policy=False,
                attestation_verifier_command=None,
                require_attestation=False,
                a2a_adapter=None,
                a2a_token=None,
                log_level=None,
                log_json=False,
                enable_hsts=False,
                allow_direct_a2a=False,
                a2a_agent_card_rate_limit_per_ip=None,
                a2a_agent_card_rate_limit_window_seconds=None,
            ))
        self.assertEqual(config.host_id, "host:cli")
        self.assertEqual(config.provider_endpoint, "https://provider.example/run")
        self.assertEqual(config.wasm_component, "capsule.wasm")
        self.assertEqual(config.wasm_engine, "wasmtime")
        self.assertEqual(config.store_backend, "postgres")
        self.assertEqual(config.store_path, "env.sqlite")
        self.assertEqual(config.policy_path, "cli-policy.json")
        self.assertEqual(config.trust_registry_path, "env-trust.json")
        self.assertTrue(config.reload_policy)
        self.assertEqual(config.attestation_verifier_command, ("/bin/verify-attestation", "--json"))
        self.assertTrue(config.require_attestation)
        self.assertEqual(config.a2a_adapter, "sdk")
        self.assertEqual(config.a2a_token, "env-token")
        self.assertTrue(config.log_json)
        self.assertTrue(config.enable_hsts)
        self.assertTrue(config.allow_direct_a2a)
        self.assertEqual(config.a2a_max_concurrent_requests, 12)
        self.assertEqual(config.a2a_rate_limit_per_ip, 34)
        self.assertEqual(config.a2a_rate_limit_window_seconds, 56)
        self.assertEqual(config.a2a_agent_card_rate_limit_per_ip, 78)
        self.assertEqual(config.a2a_agent_card_rate_limit_window_seconds, 90)

    def test_json_log_formatter_emits_structured_internal_exception(self):
        formatter = JsonLogFormatter()
        try:
            raise RuntimeError("internal failure with signature='sig-secret'")
        except RuntimeError:
            record = logging.getLogger("portmark.test").makeRecord(
                "portmark.test",
                logging.ERROR,
                __file__,
                1,
                "operation failed Authorization: Bearer token-secret PORTMARK_ED25519_PRIVATE_KEY_B64=key-secret",
                (),
                exc_info=sys.exc_info(),
            )
        payload = json.loads(formatter.format(record))
        self.assertEqual(payload["level"], "ERROR")
        self.assertEqual(payload["logger"], "portmark.test")
        self.assertEqual(payload["message"], "operation failed Authorization: Bearer [REDACTED] PORTMARK_ED25519_PRIVATE_KEY_B64=[REDACTED]")
        self.assertIn("RuntimeError", payload["exception"])
        self.assertNotIn("token-secret", json.dumps(payload))
        self.assertNotIn("key-secret", json.dumps(payload))
        self.assertNotIn("sig-secret", json.dumps(payload))

    def test_rate_limiter_bounds_tracked_client_state(self):
        limiter = RateLimiter(limit_per_ip=10, window_seconds=60, max_tracked_clients=2)
        self.assertTrue(limiter.admit("192.0.2.1"))
        self.assertTrue(limiter.admit("192.0.2.2"))
        self.assertTrue(limiter.admit("192.0.2.3"))
        self.assertLessEqual(len(limiter._requests_by_ip), 2)
        self.assertNotIn("192.0.2.1", limiter._requests_by_ip)

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

    def test_legacy_hmac_signer_requires_explicit_unsafe_test_opt_in_and_key(self):
        with patch.dict(os.environ, {"PORTMARK_ALLOW_LEGACY_HMAC": "1"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "unsafe-test-only"):
                signer_from_environment()
        with patch.dict(os.environ, {"PORTMARK_ALLOW_LEGACY_HMAC": "unsafe-test-only"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "PORTMARK_SIGNING_KEY"):
                signer_from_environment()
        with patch.dict(os.environ, {
            "PORTMARK_ALLOW_LEGACY_HMAC": "unsafe-test-only",
            "PORTMARK_SIGNING_KEY": "explicit legacy integration test key",
        }, clear=True):
            signer = signer_from_environment()
        self.assertIsInstance(signer, HmacEnvelopeSigner)

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

    def test_external_attestation_verifier_accepts_rejects_and_bounds_responses(self):
        with tempfile.TemporaryDirectory() as directory:
            verifier = Path(directory) / "verifier.py"
            verifier.write_text(
                "\n".join((
                    "import json, sys",
                    "payload = json.loads(sys.stdin.buffer.read())",
                    "quote = payload['evidence'].get('quote')",
                    "if quote == 'large':",
                    "    sys.stdout.write('x' * 8192)",
                    "elif quote == 'ok' and payload['expected_subject'] == payload['evidence']['subject']:",
                    "    sys.stdout.write(json.dumps({'valid': True}))",
                    "else:",
                    "    sys.stdout.write(json.dumps({'valid': False}))",
                    "",
                )),
                encoding="utf-8",
            )
            policy = AttestationPolicy(
                required_for_execution=True,
                external_verifier=ExternalAttestationVerifier((sys.executable, str(verifier)), max_response_bytes=128),
            )
            host = make_host(attestation_policy=policy)

            accepted = make_demo_envelope(host, "external attestation")
            object.__setattr__(
                accepted.permit,
                "attestation",
                AttestationEvidence(
                    verifier="verifier:external",
                    subject=host.host_id,
                    audience=accepted.permit.issuer,
                    measurement="measurement:external",
                    issued_at=int(time.time()) - 1,
                    expires_at=int(time.time()) + 60,
                    nonce=accepted.permit.nonce,
                    quote="ok",
                ),
            )
            host.signer.seal(accepted)
            self.assertEqual(host.run(accepted).status, "completed")

            for quote, message in [("", "quote is required"), ("bad", "rejected"), ("large", "output limit")]:
                with self.subTest(quote=quote):
                    rejected = make_demo_envelope(host, "external rejection")
                    object.__setattr__(
                        rejected.permit,
                        "attestation",
                        AttestationEvidence(
                            verifier="verifier:external",
                            subject=host.host_id,
                            audience=rejected.permit.issuer,
                            measurement="measurement:external",
                            issued_at=int(time.time()) - 1,
                            expires_at=int(time.time()) + 60,
                            nonce=rejected.permit.nonce,
                            quote=quote,
                        ),
                    )
                    host.signer.seal(rejected)
                    with self.assertRaisesRegex(SecurityError, message):
                        host.run(rejected)

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

    def test_http_provider_bounds_response_before_json_parsing(self):
        response = FakeHttpResponse(b'{"kind":"complete","content":{"ok":true}}')
        with patch("urllib.request.urlopen", return_value=response):
            decision = GenericHttpProvider("https://provider.example/run", max_response_bytes=64).decide(AgentState("task", "goal"), ())
        self.assertEqual(response.read_size, 65)
        self.assertEqual(decision.kind, "complete")
        self.assertEqual(decision.content, {"ok": True})

        response = FakeHttpResponse(b"x" * 65)
        with patch("urllib.request.urlopen", return_value=response):
            with self.assertRaisesRegex(SecurityError, "provider response exceeds"):
                GenericHttpProvider("https://provider.example/run", max_response_bytes=64).decide(AgentState("task", "goal"), ())

    def test_http_provider_sends_minimal_state_payload(self):
        state = AgentState(
            "task-1",
            "sensitive goal",
            step=2,
            tool_calls=1,
            memory={"private_note": "blocked-content"},
            messages=[{"role": "tool", "name": "catalog.search", "content": {"id": "public", "internal_note": "blocked-content"}}],
            status="running",
            result={"private_note": "blocked-content"},
        )
        captured = {}

        def capture(request, timeout):
            captured["body"] = json.loads(request.data)
            captured["timeout"] = timeout
            return FakeHttpResponse(b'{"kind":"complete","content":{"ok":true}}')

        with patch("urllib.request.urlopen", side_effect=capture):
            decision = GenericHttpProvider("https://provider.example/run", timeout=7).decide(
                state,
                ("catalog.search",),
                (ToolGrant("catalog.search"),),
            )

        self.assertEqual(decision.kind, "complete")
        self.assertEqual(captured["timeout"], 7)
        self.assertEqual(captured["body"], {
            "state": {
                "task_id": "task-1",
                "goal": "sensitive goal",
                "step": 2,
                "tool_calls": 1,
                "status": "running",
                "messages": [{"role": "tool", "name": "catalog.search"}],
            },
            "available_tools": ["catalog.search"],
        })
        self.assertNotIn("memory", captured["body"]["state"])
        self.assertNotIn("result", captured["body"]["state"])
        self.assertNotIn("internal_note", json.dumps(captured["body"]))

    def test_http_provider_projects_allowed_tool_output_fields(self):
        state = AgentState(
            "task-1",
            "goal",
            messages=[
                {"role": "tool", "name": "catalog.search", "content": [{"id": "doc-1", "title": "Visible", "internal_note": "blocked-content"}]},
                {"role": "tool", "name": "payments.reserve", "content": {"receipt": "blocked-content"}},
            ],
        )
        captured = {}

        def capture(request, timeout):
            captured["body"] = json.loads(request.data)
            return FakeHttpResponse(b'{"kind":"complete","content":{"ok":true}}')

        with patch("urllib.request.urlopen", side_effect=capture):
            GenericHttpProvider("https://provider.example/run").decide(
                state,
                ("catalog.search",),
                (ToolGrant("catalog.search", output_projection=("id", "title")),),
            )

        self.assertEqual(
            captured["body"]["state"]["messages"],
            [{"role": "tool", "name": "catalog.search", "content": [{"id": "doc-1", "title": "Visible"}]}],
        )
        self.assertNotIn("internal_note", json.dumps(captured["body"]))
        self.assertNotIn("receipt", json.dumps(captured["body"]))

    def test_remote_provider_loop_sees_projected_tool_result_on_second_call(self):
        host = make_host(provider_endpoint="https://provider.example/run")
        host.policy = HostPolicy(
            host.host_id,
            (ToolGrant("catalog.search", {"max_limit": 3}, ("*",)),),
            ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=32_768),
        )
        envelope = make_demo_envelope(host, "portable agents", "http")
        bodies = []
        responses = [
            FakeHttpResponse(b'{"kind":"tool","tool":"catalog.search","arguments":{"query":"portable agents","limit":3}}'),
            FakeHttpResponse(b'{"kind":"complete","content":{"ok":true}}'),
        ]

        def capture(request, timeout):
            bodies.append(json.loads(request.data))
            return responses.pop(0)

        with patch("urllib.request.urlopen", side_effect=capture):
            result = host.run(envelope)

        self.assertEqual(result.status, "completed")
        self.assertEqual(len(bodies), 2)
        self.assertEqual(bodies[0]["state"]["messages"], [])
        self.assertIn("catalog.search", bodies[1]["available_tools"])
        self.assertEqual(bodies[1]["state"]["messages"][0]["role"], "tool")
        self.assertEqual(bodies[1]["state"]["messages"][0]["name"], "catalog.search")
        self.assertEqual(len(bodies[1]["state"]["messages"][0]["content"]), 3)
        self.assertIn("title", bodies[1]["state"]["messages"][0]["content"][0])
        self.assertNotIn("memory", bodies[1]["state"])
        self.assertNotIn("result", bodies[1]["state"])

    def test_http_provider_rejects_malformed_response_shapes(self):
        cases = [
            (b"{", "malformed JSON"),
            (b"[]", "JSON object"),
            (b"{}", "kind"),
            (b'{"kind":"unknown"}', "kind"),
            (b'{"kind":"tool","tool":"","arguments":{}}', "tool name"),
            (b'{"kind":"tool","tool":"catalog.search","arguments":[]}', "arguments"),
            (b'{"kind":"migrate","destination":""}', "destination"),
            (b'{"kind":"migrate","destination":"host:other","content":[]}', "content"),
        ]
        for body, message in cases:
            with self.subTest(message=message):
                with patch("urllib.request.urlopen", return_value=FakeHttpResponse(body)):
                    with self.assertRaisesRegex(SecurityError, message):
                        GenericHttpProvider("https://provider.example/run").decide(AgentState("task", "goal"), ("catalog.search",))

    def test_host_restricts_permit_more_than_agent_requests(self):
        host = make_host()
        host.providers["evil"] = FixedProvider(ProviderDecision("tool", "catalog.search", {"query": "x", "limit": 4}))
        envelope = make_demo_envelope(host, "search", "evil")
        with self.assertRaisesRegex(SecurityError, "maximum"):
            host.run(envelope)

    def test_rich_argument_constraints_enforce_required_type_range_enum_pattern_and_extras(self):
        registry = ToolRegistry()
        registry.register("catalog.search", lambda arguments: {"ok": True})
        permit = Permit(
            issuer="issuer",
            subject="agent",
            audience="host",
            expires_at=int(time.time()) + 60,
            nonce="nonce",
            grants=(ToolGrant("catalog.search", {
                "arguments": {
                    "query": {"type": "string", "min_length": 3, "max_length": 20, "pattern": "[a-z ]+"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 3},
                    "source": {"enum": ["catalog", "archive"]},
                },
                "required": ["query", "limit", "source"],
                "additional_arguments": False,
            }),),
        )
        self.assertEqual(
            registry.invoke(permit, "catalog.search", {"query": "portable agents", "limit": 2, "source": "catalog"}),
            {"ok": True},
        )
        cases = [
            ({"limit": 2, "source": "catalog"}, "required"),
            ({"query": "portable agents", "limit": 2.5, "source": "catalog"}, "type"),
            ({"query": "portable agents", "limit": 4, "source": "catalog"}, "maximum"),
            ({"query": "portable agents", "limit": 2, "source": "web"}, "allowed set"),
            ({"query": "Portable Agents", "limit": 2, "source": "catalog"}, "pattern"),
            ({"query": "portable agents", "limit": 2, "source": "catalog", "debug": True}, "unsupported fields"),
        ]
        for arguments, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(SecurityError, message):
                    registry.invoke(permit, "catalog.search", arguments)

    def test_tool_registry_bounds_timeout_exceptions_serialization_and_output(self):
        registry = ToolRegistry(default_timeout=0.01, max_output_bytes=64)
        registry.register("slow.tool", lambda arguments: time.sleep(0.1) or {"ok": True})
        registry.register("bad.tool", lambda arguments: (_ for _ in ()).throw(RuntimeError("internal failure")))
        registry.register("raw.tool", lambda arguments: object())
        registry.register("large.tool", lambda arguments: {"value": "x" * 128})
        permit = Permit(
            issuer="issuer",
            subject="agent",
            audience="host",
            expires_at=int(time.time()) + 60,
            nonce="nonce",
            grants=(
                ToolGrant("slow.tool"),
                ToolGrant("bad.tool"),
                ToolGrant("raw.tool"),
                ToolGrant("large.tool"),
            ),
        )

        for tool, message in [
            ("slow.tool", "deadline"),
            ("bad.tool", "tool execution failed"),
            ("raw.tool", "not JSON serializable"),
            ("large.tool", "output budget"),
        ]:
            with self.subTest(tool=tool):
                with self.assertRaisesRegex(SecurityError, message):
                    registry.invoke(permit, tool, {})

    def test_make_host_accepts_a_custom_tool_registry(self):
        registry = ToolRegistry()
        registry.register("custom.echo", lambda arguments: {"echo": arguments["text"]})

        host = make_host(tools=registry)

        self.assertIs(host.tools, registry)
        self.assertEqual(host.tools.names(), ("custom.echo",))

    def test_custom_tool_runs_only_when_policy_manifest_and_permit_align(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = ToolRegistry()
            registry.register("custom.echo", lambda arguments: {"echo": arguments["text"]})
            policy_path = self._write_policy(directory, tools={
                "custom.echo": {
                    "impact": "low",
                    "constraints": {
                        "arguments": {"text": {"type": "string", "max_length": 20}},
                        "required": ["text"],
                        "additional_arguments": False,
                    },
                    "output_projection": ["echo"],
                },
            })
            host = make_host(policy_path=str(policy_path), tools=registry)
            host.providers["echo"] = EchoThenCompleteProvider()
            envelope = make_demo_envelope(host, "echo", "echo")
            object.__setattr__(envelope.manifest, "requested_tools", ("custom.echo",))
            object.__setattr__(envelope.permit, "grants", (ToolGrant("custom.echo"),))
            host.signer.seal(envelope)

            result = host.run(envelope)

            self.assertEqual(result.status, "completed")
            self.assertEqual(result.result, {"echo": {"echo": "hello"}})

    def test_custom_tool_is_denied_when_policy_does_not_grant_it(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = ToolRegistry()
            registry.register("custom.echo", lambda arguments: {"echo": arguments["text"]})
            policy_path = self._write_policy(directory, tools={
                "catalog.search": {"impact": "low", "constraints": {"max_limit": 5}},
            })
            host = make_host(policy_path=str(policy_path), tools=registry)
            host.providers["echo"] = EchoThenCompleteProvider()
            envelope = make_demo_envelope(host, "echo", "echo")
            object.__setattr__(envelope.manifest, "requested_tools", ("custom.echo",))
            object.__setattr__(envelope.permit, "grants", (ToolGrant("custom.echo"),))
            host.signer.seal(envelope)

            with self.assertRaisesRegex(SecurityError, "not granted"):
                host.run(envelope)

    def _http_fetch_host(self, directory, arguments):
        policy_path = self._write_policy(directory, tools={
            "http.fetch": {
                "impact": "low",
                "constraints": {
                    "arguments": {
                        "url": {
                            "type": "string",
                            "scheme": "https",
                            "allowed_hosts": ["allowed.example"],
                            "max_length": 2048,
                        },
                        "method": {"const": "GET"},
                    },
                    "required": ["url"],
                    "additional_arguments": False,
                },
                "output_projection": ["url", "status", "content_type"],
            },
        })
        host = make_host(policy_path=str(policy_path), tools=http_fetch.registry())
        host.providers["fetcher"] = HttpFetchThenCompleteProvider(arguments)
        envelope = make_demo_envelope(host, "fetch", "fetcher")
        object.__setattr__(envelope.manifest, "requested_tools", ("http.fetch",))
        object.__setattr__(envelope.permit, "grants", (ToolGrant("http.fetch"),))
        host.signer.seal(envelope)
        return host, envelope

    def test_http_fetch_example_allowed_url_succeeds(self):
        with tempfile.TemporaryDirectory() as directory:
            host, envelope = self._http_fetch_host(directory, {"url": "https://allowed.example/resource", "method": "GET"})
            response = FakeHttpResponse(b"hello", headers={"Content-Type": "text/plain"})
            with patch("urllib.request.OpenerDirector.open", return_value=response) as opened:
                result = host.run(envelope)

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.result["fetch"]["status"], 200)
        self.assertEqual(result.result["fetch"]["body"], "hello")
        self.assertEqual(response.read_size, http_fetch.MAX_RESPONSE_BYTES + 1)
        self.assertEqual(opened.call_count, 1)

    def test_http_fetch_example_denies_disallowed_host_before_network_call(self):
        with tempfile.TemporaryDirectory() as directory:
            host, envelope = self._http_fetch_host(directory, {"url": "https://evil.example/resource", "method": "GET"})
            with patch("urllib.request.OpenerDirector.open") as opened:
                with self.assertRaisesRegex(SecurityError, "host is outside its allowed set"):
                    host.run(envelope)

        opened.assert_not_called()

    def test_http_fetch_example_denies_non_https_before_network_call(self):
        with tempfile.TemporaryDirectory() as directory:
            host, envelope = self._http_fetch_host(directory, {"url": "http://allowed.example/resource", "method": "GET"})
            with patch("urllib.request.OpenerDirector.open") as opened:
                with self.assertRaisesRegex(SecurityError, "URL scheme must be https"):
                    host.run(envelope)

        opened.assert_not_called()

    def test_http_fetch_example_oversized_output_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            host, envelope = self._http_fetch_host(directory, {"url": "https://allowed.example/resource", "method": "GET"})
            response = FakeHttpResponse(b"x" * (http_fetch.MAX_RESPONSE_BYTES + 1), headers={"Content-Type": "text/plain"})
            with patch("urllib.request.OpenerDirector.open", return_value=response):
                result = host.run(envelope)

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.result, {"error": "tool execution failed"})
        failed = next(event for event in result.audit if event["event"] == "tool.failed")
        self.assertEqual(failed["details"]["cause"], "ToolExecutionError")
        self.assertEqual(failed["details"]["cause_message"], "http.fetch response exceeds output limit")

    def test_http_fetch_example_timeout_fails_as_tool_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            host, envelope = self._http_fetch_host(directory, {"url": "https://allowed.example/resource", "method": "GET"})
            with patch("urllib.request.OpenerDirector.open", side_effect=TimeoutError("timed out")):
                result = host.run(envelope)

        self.assertEqual(result.status, "failed")
        failed = next(event for event in result.audit if event["event"] == "tool.failed")
        self.assertEqual(failed["details"]["cause"], "ToolExecutionError")
        self.assertEqual(failed["details"]["cause_message"], "http.fetch request failed")

    def test_http_fetch_example_provider_cannot_request_undeclared_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            host, envelope = self._http_fetch_host(directory, {
                "url": "https://allowed.example/resource",
                "method": "GET",
                "headers": {"Authorization": "Bearer secret"},
            })
            with patch("urllib.request.OpenerDirector.open") as opened:
                with self.assertRaisesRegex(SecurityError, "unsupported fields"):
                    host.run(envelope)

        opened.assert_not_called()

    def test_host_rejects_oversized_tool_output_before_checkpointing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            store = SQLiteRuntimeStore(path)
            tools = ToolRegistry()
            tools.register("large.output", lambda arguments: {"payload": "x" * 2048})
            host = make_host(store=store)
            host.tools = tools
            host.policy = HostPolicy(host.host_id, (ToolGrant("large.output"),), ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=1024))
            host.providers["large"] = LargeToolProvider()
            envelope = make_demo_envelope(host, "large output", "large")
            object.__setattr__(envelope.manifest, "requested_tools", ("large.output",))
            object.__setattr__(envelope.permit, "grants", (ToolGrant("large.output"),))
            object.__setattr__(envelope.permit, "budget", ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=1024))
            host.signer.seal(envelope)

            result = host.run(envelope)
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.result, {"error": "tool execution failed"})
            failed_events = [event for event in result.audit if event["event"] == "tool.failed"]
            self.assertEqual(len(failed_events), 1)
            self.assertEqual(failed_events[0]["details"]["error"], "tool output exceeds output budget")
            checkpoint = store.load_checkpoint(envelope.state.task_id)
            self.assertIsNotNone(checkpoint)
            self.assertNotIn("large", checkpoint["memory"])
            self.assertEqual(checkpoint["messages"], [])

    def test_host_audits_tool_timeout_and_exception_as_failed_steps(self):
        cases = [
            ("slow.output", lambda arguments: time.sleep(0.1) or {"ok": True}, "tool execution exceeded its deadline", "Empty"),
            ("bad.output", lambda arguments: (_ for _ in ()).throw(RuntimeError("internal failure")), "tool execution failed", "RuntimeError"),
        ]
        for tool_name, tool, message, cause in cases:
            with self.subTest(tool=tool_name):
                with tempfile.TemporaryDirectory() as directory:
                    store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
                    tools = ToolRegistry(default_timeout=0.01)
                    tools.register(tool_name, tool)
                    host = make_host(store=store)
                    host.tools = tools
                    host.policy = HostPolicy(host.host_id, (ToolGrant(tool_name),), ResourceBudget())
                    host.providers["tool-failure"] = FixedProvider(ProviderDecision("tool", tool_name, {}))
                    envelope = make_demo_envelope(host, f"{tool_name} failure", "tool-failure")
                    object.__setattr__(envelope.manifest, "requested_tools", (tool_name,))
                    object.__setattr__(envelope.permit, "grants", (ToolGrant(tool_name),))
                    host.signer.seal(envelope)

                    result = host.run(envelope)
                    self.assertEqual(result.status, "failed")
                    self.assertEqual(result.result, {"error": "tool execution failed"})
                    failed = next(event for event in result.audit if event["event"] == "tool.failed")
                    self.assertEqual(failed["details"]["error"], message)
                    self.assertEqual(failed["details"]["cause"], cause)
                    self.assertEqual(store.load_checkpoint(result.task_id)["status"], "failed")

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
            catalog = next(grant for grant in policy.grants if grant.name == "catalog.search")
            self.assertEqual(catalog.output_projection, ("id", "title"))

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

    @contextmanager
    def _sqlite_store_case(self, verifier=None):
        with tempfile.TemporaryDirectory() as directory:
            yield "sqlite", SQLiteRuntimeStore(Path(directory) / "runtime.sqlite", verifier)

    @contextmanager
    def _postgres_store_case(self, verifier=None):
        dsn = os.environ["PORTMARK_TEST_POSTGRES_DSN"]
        schema = "portmark_test_" + secrets.token_hex(8)
        store = PostgresRuntimeStore(dsn, verifier, schema=schema)
        try:
            yield "postgres", store
        finally:
            self._drop_postgres_schema(dsn, schema)

    def _store_case_contexts(self, verifier=None):
        contexts = [self._sqlite_store_case(verifier)]
        if os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available():
            contexts.append(self._postgres_store_case(verifier))
        return contexts

    @contextmanager
    def _sqlite_dual_store_case(self, source_verifier=None, destination_verifier=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            yield (
                "sqlite",
                SQLiteRuntimeStore(root / "source.sqlite", source_verifier),
                SQLiteRuntimeStore(root / "destination.sqlite", destination_verifier),
            )

    @contextmanager
    def _postgres_dual_store_case(self, source_verifier=None, destination_verifier=None):
        dsn = os.environ["PORTMARK_TEST_POSTGRES_DSN"]
        source_schema = "portmark_source_" + secrets.token_hex(8)
        destination_schema = "portmark_destination_" + secrets.token_hex(8)
        source = PostgresRuntimeStore(dsn, source_verifier, schema=source_schema)
        destination = PostgresRuntimeStore(dsn, destination_verifier, schema=destination_schema)
        try:
            yield "postgres", source, destination
        finally:
            self._drop_postgres_schema(dsn, source_schema)
            self._drop_postgres_schema(dsn, destination_schema)

    def _dual_store_case_contexts(self, source_verifier=None, destination_verifier=None):
        contexts = [self._sqlite_dual_store_case(source_verifier, destination_verifier)]
        if os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available():
            contexts.append(self._postgres_dual_store_case(source_verifier, destination_verifier))
        return contexts

    def _drop_postgres_schema(self, dsn, schema):
        import psycopg
        from psycopg import sql

        with psycopg.connect(dsn, autocommit=True) as connection:
            connection.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema)))

    def _reopen_store(self, backend, store, verifier=None):
        if backend == "sqlite":
            return SQLiteRuntimeStore(store.path, verifier)
        return PostgresRuntimeStore(store.dsn, verifier, schema=store.schema)

    def _corrupt_store_audit(self, store, task_id, backend):
        if backend == "sqlite":
            with sqlite3.connect(store.path) as connection:
                connection.execute("UPDATE audit_heads SET head_hash = 'tampered' WHERE task_id = ?", (task_id,))
            return
        with store._connect() as connection:
            connection.execute("UPDATE audit_heads SET head_hash = 'tampered' WHERE task_id = %s", (task_id,))
            connection.commit()

    def test_runtime_store_contract_persists_checkpoint_audit_and_three_state_verification(self):
        signer = EnvelopeSigner.generate("contract-key", "host:local-demo", ("host:local-demo",))
        for context in self._store_case_contexts(signer):
            with context as (backend, store):
                with self.subTest(backend=backend):
                    host = make_host(signer=signer, store=store)
                    result = host.run(make_demo_envelope(host, f"{backend} contract"))
                    checkpoint = store.load_checkpoint(result.task_id)
                    self.assertIsNotNone(checkpoint)
                    self.assertEqual(checkpoint["status"], "completed")
                    self.assertEqual(checkpoint["result"], result.result)
                    self.assertEqual(store.audit_head(result.task_id), (result.audit[-1]["hash"], result.audit[-1]["sequence"] + 1))
                    self.assertEqual(store.verify_audit_chain_status(result.task_id).status, "valid")
                    self.assertTrue(store.verify_audit_chain(result.task_id))

                    unverifiable = self._reopen_store(backend, store)
                    self.assertEqual(unverifiable.verify_audit_chain_status(result.task_id).status, "unverifiable")

    def test_runtime_store_contract_rejects_concurrent_nonce_replay(self):
        signer = EnvelopeSigner.generate("contract-concurrent-key", "host:local-demo", ("host:local-demo",))
        for context in self._store_case_contexts(signer):
            with context as (backend, store):
                with self.subTest(backend=backend):
                    host = make_host(signer=signer, store=store)
                    envelope = make_demo_envelope(host, f"{backend} race")

                    def run_once():
                        local_store = self._reopen_store(backend, store, signer)
                        local_host = make_host(signer=signer, store=local_store)
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
                    self.assertTrue(store.consumed_nonce_exists(envelope.permit.nonce))

    def test_runtime_store_contract_detects_audit_chain_corruption(self):
        signer = EnvelopeSigner.generate("contract-corrupt-key", "host:local-demo", ("host:local-demo",))
        for context in self._store_case_contexts(signer):
            with context as (backend, store):
                with self.subTest(backend=backend):
                    host = make_host(signer=signer, store=store)
                    result = host.run(make_demo_envelope(host, f"{backend} corrupt"))
                    self.assertTrue(store.verify_audit_chain(result.task_id))
                    self._corrupt_store_audit(store, result.task_id, backend)
                    verification = store.verify_audit_chain_status(result.task_id)
                    self.assertEqual(verification.status, "invalid")
                    self.assertEqual(verification.reason, "stored audit head does not match audit events")
                    self.assertFalse(store.verify_audit_chain(result.task_id))

    def test_runtime_store_contract_recovers_migration_checkpoints_and_audits(self):
        source_signer = EnvelopeSigner.generate("contract-source-key", "host:source", ("host:source", "host:destination"))
        destination_signer = trust_signer(
            EnvelopeSigner.generate("contract-destination-key", "host:destination", ("host:destination",)),
            source_signer,
        )
        for context in self._dual_store_case_contexts(source_signer, destination_signer):
            with context as (backend, source_store, destination_store):
                with self.subTest(backend=backend):
                    source = make_host(host_id="host:source", signer=source_signer, store=source_store)
                    destination = make_host(host_id="host:destination", signer=destination_signer, store=destination_store)
                    provider = MigrateThenCompleteProvider(destination.host_id)
                    source.providers["migrator"] = provider
                    destination.providers["migrator"] = provider
                    envelope = make_demo_envelope(source, f"{backend} migration", "migrator")
                    object.__setattr__(envelope.permit, "delegation_allowed", True)
                    source_signer.seal(envelope)

                    first = source.run(envelope)
                    self.assertEqual(source_store.load_checkpoint(first.task_id)["status"], "ready")
                    self.assertTrue(source_store.verify_audit_chain(first.task_id))
                    self.assertIsNotNone(first.migration_envelope)

                    second = destination.run(envelope_from_dict(first.migration_envelope))
                    self.assertEqual(second.status, "completed")
                    self.assertEqual(destination_store.load_checkpoint(second.task_id)["status"], "completed")
                    self.assertTrue(destination_store.verify_audit_chain(second.task_id))

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

    def test_sqlite_store_sets_schema_version_busy_timeout_and_rejects_future_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            store = SQLiteRuntimeStore(path)
            with sqlite3.connect(path) as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], SQLITE_SCHEMA_VERSION)
                connection.execute("PRAGMA user_version = 999")
            with store._connect() as connection:
                self.assertEqual(connection.execute("PRAGMA busy_timeout").fetchone()[0], SQLITE_BUSY_TIMEOUT_MS)
            with self.assertRaisesRegex(RuntimeError, "newer than supported"):
                SQLiteRuntimeStore(path)

    def test_sqlite_store_migrates_legacy_v0_database_without_losing_existing_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            with sqlite3.connect(path) as connection:
                connection.executescript(
                    """
                    CREATE TABLE consumed_nonces (
                        nonce TEXT PRIMARY KEY,
                        subject TEXT NOT NULL,
                        audience TEXT NOT NULL,
                        task_id TEXT NOT NULL,
                        consumed_at INTEGER NOT NULL
                    );
                    CREATE TABLE checkpoints (
                        task_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL,
                        checkpoint_json TEXT NOT NULL,
                        updated_at INTEGER NOT NULL
                    );
                    CREATE TABLE audit_events (
                        task_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        host_id TEXT NOT NULL,
                        event TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        hash TEXT NOT NULL UNIQUE,
                        created_at INTEGER NOT NULL,
                        PRIMARY KEY (task_id, sequence)
                    );
                    CREATE TABLE audit_heads (
                        task_id TEXT PRIMARY KEY,
                        head_hash TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL
                    );
                    INSERT INTO consumed_nonces VALUES ('legacy-nonce', 'agent:demo', 'host:local-demo', 'task-legacy', 1);
                    """
                )
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 0)

            store = SQLiteRuntimeStore(path)
            self.assertTrue(store.consumed_nonce_exists("legacy-nonce"))
            with sqlite3.connect(path) as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], SQLITE_SCHEMA_VERSION)

    def test_sqlite_store_migrates_v1_global_audit_hash_uniqueness(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            with sqlite3.connect(path) as connection:
                connection.executescript(
                    """
                    CREATE TABLE consumed_nonces (
                        nonce TEXT PRIMARY KEY,
                        subject TEXT NOT NULL,
                        audience TEXT NOT NULL,
                        task_id TEXT NOT NULL,
                        consumed_at INTEGER NOT NULL
                    );
                    CREATE TABLE checkpoints (
                        task_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL,
                        checkpoint_json TEXT NOT NULL,
                        updated_at INTEGER NOT NULL
                    );
                    CREATE TABLE audit_events (
                        task_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        host_id TEXT NOT NULL,
                        event TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        hash TEXT NOT NULL UNIQUE,
                        created_at INTEGER NOT NULL,
                        PRIMARY KEY (task_id, sequence)
                    );
                    CREATE TABLE audit_heads (
                        task_id TEXT PRIMARY KEY,
                        head_hash TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL
                    );
                    PRAGMA user_version = 1;
                    """
                )

            signer = EnvelopeSigner.generate("v1-migration-key", "host:local-demo", ("host:local-demo",))
            store = SQLiteRuntimeStore(path)
            self.assertEqual(store.audit_head("missing"), None)
            first = make_host(signer=signer, store=store)
            second = make_host(signer=signer, store=SQLiteRuntimeStore(path))
            self.assertEqual(first.run(make_demo_envelope(first, "first migrated task")).status, "completed")
            self.assertEqual(second.run(make_demo_envelope(second, "second migrated task")).status, "completed")
            with sqlite3.connect(path) as connection:
                indexes = {
                    row[1]: connection.execute(f"PRAGMA index_info({row[1]})").fetchall()
                    for row in connection.execute("PRAGMA index_list(audit_events)").fetchall()
                    if row[2]
                }
            self.assertTrue(any([column[2] for column in columns] == ["task_id", "hash"] for columns in indexes.values()))

    def test_sqlite_audit_chain_verifier_rejects_tampering_and_missing_chains(self):
        cases = {
            "mutated payload": "UPDATE audit_events SET details_json = '{\"tampered\":true}' WHERE task_id = ? AND sequence = 1",
            "broken previous hash": "UPDATE audit_events SET previous_hash = 'broken' WHERE task_id = ? AND sequence = 1",
            "deleted middle event": "DELETE FROM audit_events WHERE task_id = ? AND sequence = 1",
            "reordered sequence": "UPDATE audit_events SET sequence = 99 WHERE task_id = ? AND sequence = 1",
            "malformed details": "UPDATE audit_events SET details_json = '{' WHERE task_id = ? AND sequence = 1",
            "stale head": "UPDATE audit_heads SET head_hash = 'stale' WHERE task_id = ?",
            "malformed head sequence": "UPDATE audit_heads SET sequence = 'wrong' WHERE task_id = ?",
            "tampered signature": "UPDATE audit_heads SET signature = 'tampered' WHERE task_id = ?",
        }
        for name, statement in cases.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "runtime.sqlite"
                    store = SQLiteRuntimeStore(path)
                    host = make_host(store=store)
                    result = host.run(make_demo_envelope(host, f"audit tamper {name}"))
                    self.assertTrue(store.verify_audit_chain(result.task_id))
                    with sqlite3.connect(path) as connection:
                        connection.execute(statement, (result.task_id,))
                    self.assertEqual(store.verify_audit_chain_status(result.task_id).status, "invalid")
                    self.assertFalse(store.verify_audit_chain(result.task_id))

        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            self.assertEqual(store.verify_audit_chain_status("missing-task").status, "invalid")
            self.assertFalse(store.verify_audit_chain("missing-task"))

    def test_sqlite_audit_chain_rejects_fabricated_consistent_history(self):
        def event(sequence, name, details, previous):
            record = {"sequence": sequence, "event": name, "details": details, "previous": previous}
            return {**record, "hash": hashlib.sha256(canonical_json(record)).hexdigest()}

        signer = EnvelopeSigner.generate("audit-forgery-key", "host:local-demo", ("host:local-demo",))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            store = SQLiteRuntimeStore(path, signer)
            fabricated = []
            previous = ""
            for sequence, name, details in [
                (0, "agent.accepted", {"agent": "agent:demo", "host": "host:local-demo"}),
                (1, "provider.proposed", {"kind": "tool", "tool": "payments.reserve"}),
                (2, "tool.executed", {"tool": "payments.reserve", "arguments": {"amount": 250000, "currency": "USD"}}),
                (3, "agent.completed", {"result": {"payment": "reserved"}}),
            ]:
                row = event(sequence, name, details, previous)
                fabricated.append(row)
                previous = row["hash"]

            with sqlite3.connect(path) as connection:
                for row in fabricated:
                    connection.execute(
                        """
                        INSERT INTO audit_events
                            (task_id, sequence, host_id, event, details_json, previous_hash, hash, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "task-forged",
                            row["sequence"],
                            "host:local-demo",
                            row["event"],
                            json.dumps(row["details"], sort_keys=True, separators=(",", ":")),
                            row["previous"],
                            row["hash"],
                            int(time.time()),
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO audit_heads
                        (task_id, head_hash, sequence, host_id, signature_key_id, signature, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("task-forged", previous, len(fabricated), "host:local-demo", "", "", int(time.time())),
                )

            self.assertFalse(store.verify_audit_chain("task-forged"))

            host = make_host(signer=signer, store=store)
            result = host.run(make_demo_envelope(host, "signed history"))
            self.assertTrue(store.verify_audit_chain(result.task_id))
            with sqlite3.connect(path) as connection:
                connection.execute("UPDATE audit_heads SET signature = 'tampered' WHERE task_id = ?", (result.task_id,))
            self.assertEqual(store.verify_audit_chain_status(result.task_id).status, "invalid")
            self.assertFalse(store.verify_audit_chain(result.task_id))

    def test_sqlite_audit_chain_status_reports_unverifiable_without_trust_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            signer = EnvelopeSigner.generate("audit-status-key", "host:local-demo", ("host:local-demo",))
            signing_store = SQLiteRuntimeStore(path, signer)
            host = make_host(signer=signer, store=signing_store)
            result = host.run(make_demo_envelope(host, "operator audit without registry"))

            verified = SQLiteRuntimeStore(path, signer).verify_audit_chain_status(result.task_id)
            self.assertEqual(verified.status, "valid")
            self.assertTrue(verified.valid)

            unverifiable = SQLiteRuntimeStore(path).verify_audit_chain_status(result.task_id)
            self.assertEqual(unverifiable.status, "unverifiable")
            self.assertIn("trust registry", unverifiable.reason)
            self.assertFalse(unverifiable.valid)
            self.assertFalse(SQLiteRuntimeStore(path).verify_audit_chain(result.task_id))

    def test_verify_audit_cli_reports_valid_invalid_unverifiable_and_missing_chains(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            signer = EnvelopeSigner.generate("cli-audit-key", "host:local-demo", ("host:local-demo",))
            registry_path = self._write_trust_registry(directory, signer)
            store = SQLiteRuntimeStore(path)
            host = make_host(signer=signer, store=store)
            result = host.run(make_demo_envelope(host, "operator audit"))

            output = io.StringIO()
            with patch.object(sys, "argv", ["portmark", "--store-path", str(path), "--trust-registry-path", str(registry_path), "verify-audit", "--task-id", result.task_id]):
                with redirect_stdout(output):
                    cli_main()
            self.assertEqual(
                json.loads(output.getvalue()),
                {"task_id": result.task_id, "status": "valid", "reason": "audit chain and signed head verified"},
            )

            output = io.StringIO()
            with patch.object(sys, "argv", ["portmark", "--store-path", str(path), "verify-audit", "--task-id", result.task_id]):
                with redirect_stdout(output):
                    with self.assertRaises(SystemExit) as raised:
                        cli_main()
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(
                json.loads(output.getvalue()),
                {"task_id": result.task_id, "status": "unverifiable", "reason": "trust registry is not configured"},
            )

            with sqlite3.connect(path) as connection:
                connection.execute("UPDATE audit_heads SET head_hash = 'tampered' WHERE task_id = ?", (result.task_id,))
            output = io.StringIO()
            with patch.object(sys, "argv", ["portmark", "--store-path", str(path), "--trust-registry-path", str(registry_path), "verify-audit", "--task-id", result.task_id]):
                with redirect_stdout(output):
                    with self.assertRaises(SystemExit) as raised:
                        cli_main()
            self.assertEqual(raised.exception.code, 1)
            self.assertEqual(
                json.loads(output.getvalue()),
                {"task_id": result.task_id, "status": "invalid", "reason": "stored audit head does not match audit events"},
            )

            output = io.StringIO()
            with patch.object(sys, "argv", ["portmark", "--store-path", str(path), "--trust-registry-path", str(registry_path), "verify-audit", "--task-id", "missing-task"]):
                with redirect_stdout(output):
                    with self.assertRaises(SystemExit) as raised:
                        cli_main()
            self.assertEqual(raised.exception.code, 1)
            self.assertEqual(
                json.loads(output.getvalue()),
                {"task_id": "missing-task", "status": "invalid", "reason": "audit chain is missing"},
            )

    def test_host_security_guards_are_directly_reachable(self):
        host = make_host()
        envelope = make_demo_envelope(host, "missing provider", "deterministic")
        object.__setattr__(envelope.manifest, "provider", "missing")
        host.signer.seal(envelope)
        with self.assertRaisesRegex(SecurityError, "not configured"):
            host.run(envelope)

        host = make_host()
        host.providers["digest"] = DigestProvider(ProviderDecision("complete", content={}))
        envelope = make_demo_envelope(host, "digest mismatch", "digest")
        object.__setattr__(envelope.manifest, "component_digest", "wasm:tampered")
        host.signer.seal(envelope)
        with self.assertRaisesRegex(SecurityError, "digest"):
            host.run(envelope)

        for decision, message, mutate in [
            (ProviderDecision("tool"), "without a tool name", None),
            (ProviderDecision("tool", "catalog.search", {"query": "x", "limit": 1}), "tool-call budget", lambda e: object.__setattr__(e.permit, "budget", ResourceBudget(max_steps=6, max_tool_calls=0))),
            (ProviderDecision("migrate"), "lacks a destination", lambda e: object.__setattr__(e.permit, "delegation_allowed", True)),
            (ProviderDecision("migrate", destination="host:destination"), "does not allow migration", None),
            (ProviderDecision("migrate", destination="host:destination", content={"attestation": "bad"}), "attestation has invalid shape", lambda e: object.__setattr__(e.permit, "delegation_allowed", True)),
        ]:
            with self.subTest(message=message):
                host = make_host()
                host.providers["guard"] = FixedProvider(decision)
                envelope = make_demo_envelope(host, message, "guard")
                if mutate is not None:
                    mutate(envelope)
                host.signer.seal(envelope)
                with self.assertRaisesRegex(SecurityError, message):
                    host.run(envelope)

        authority = ApprovalAuthority.generate()
        host = make_host()
        host.policy = HostPolicy(
            host.host_id,
            (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}),),
            ResourceBudget(),
            "policy-v1",
            "policy-hash",
            {"payments.reserve": "external-payment"},
            (authority.trusted_approver(),),
        )
        host.providers["payer"] = PaymentProvider()
        envelope = make_demo_envelope(host, "bad approval", "payer")
        object.__setattr__(envelope.permit, "grants", (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}),))
        envelope.state.memory["approvals"] = {"payments.reserve": "bad-shape"}
        host.signer.seal(envelope)
        with self.assertRaisesRegex(SecurityError, "approval token has invalid shape"):
            host.run(envelope)

    def test_stored_audit_head_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            signer = EnvelopeSigner.generate("audit-head-key", "host:local-demo", ("host:local-demo",))
            host = make_host(signer=signer, store=store)
            result = host.run(make_demo_envelope(host, "stored head"))
            envelope = make_demo_envelope(host, "bad head")
            envelope.state.task_id = result.task_id
            envelope.previous_audit_hash = "wrong-head"
            signer.seal(envelope)
            with self.assertRaisesRegex(SecurityError, "audit head"):
                host.run(envelope)

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
            source_signer = EnvelopeSigner.generate("source-key", "host:source", ("host:source", "host:destination"))
            destination_signer = trust_signer(EnvelopeSigner.generate("destination-key", "host:destination", ("host:destination",)), source_signer)
            source_store = SQLiteRuntimeStore(Path(directory) / "source.sqlite")
            destination_store = SQLiteRuntimeStore(Path(directory) / "destination.sqlite")
            source = make_host(host_id="host:source", signer=source_signer, store=source_store)
            destination = make_host(host_id="host:destination", signer=destination_signer, store=destination_store)
            provider = MigrateThenCompleteProvider(destination.host_id)
            source.providers["migrator"] = provider
            destination.providers["migrator"] = provider
            envelope = make_demo_envelope(source, "move durably", "migrator")
            object.__setattr__(envelope.permit, "delegation_allowed", True)
            source_signer.seal(envelope)

            first = source.run(envelope)
            source_checkpoint = source_store.load_checkpoint(first.task_id)
            self.assertEqual(source_checkpoint["status"], "ready")
            self.assertEqual(source_checkpoint["memory"]["migration"], {"from": "host:source", "to": "host:destination"})
            self.assertTrue(source_store.verify_audit_chain(first.task_id))
            self.assertEqual(first.migration_envelope["previous_audit_host_id"], "host:source")
            self.assertEqual(first.migration_envelope["previous_audit_signature_key_id"], source_signer.key_id)
            self.assertTrue(first.migration_envelope["previous_audit_signature"])

            from portmark.a2a import envelope_from_dict
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

    def test_sqlite_store_parallel_writers_keep_nonce_and_audit_sequences_consistent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            signer = EnvelopeSigner.generate("parallel-key", "host:local-demo", ("host:local-demo",))
            envelopes = []
            for index in range(8):
                host = make_host(signer=signer, store=SQLiteRuntimeStore(path))
                envelopes.append(copy.deepcopy(make_demo_envelope(host, f"parallel {index}")))

            def run_envelope(envelope):
                local_host = make_host(signer=signer, store=SQLiteRuntimeStore(path))
                return local_host.run(envelope)

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                results = list(executor.map(run_envelope, envelopes))

            self.assertEqual([result.status for result in results], ["completed"] * len(envelopes))
            store = SQLiteRuntimeStore(path, signer)
            nonces_by_task = {envelope.state.task_id: envelope.permit.nonce for envelope in envelopes}
            for result in results:
                self.assertTrue(store.verify_audit_chain(result.task_id))
                self.assertTrue(store.consumed_nonce_exists(nonces_by_task[result.task_id]))
            with sqlite3.connect(path) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM consumed_nonces").fetchone()[0], len(envelopes))
                rows = connection.execute(
                    """
                    SELECT task_id, COUNT(*) AS count, MIN(sequence) AS first_sequence, MAX(sequence) AS last_sequence
                    FROM audit_events
                    GROUP BY task_id
                    """
                ).fetchall()
            self.assertEqual(len(rows), len(envelopes))
            for task_id, count, first_sequence, last_sequence in rows:
                with self.subTest(task_id=task_id):
                    self.assertEqual(first_sequence, 0)
                    self.assertEqual(last_sequence, count - 1)

    def test_delegated_migration_resumes_on_destination(self):
        source_signer = EnvelopeSigner.generate("source-key", "host:source", ("host:source", "host:destination"))
        destination_signer = trust_signer(EnvelopeSigner.generate("destination-key", "host:destination", ("host:destination",)), source_signer)
        source = make_host(host_id="host:source", signer=source_signer)
        destination = make_host(host_id="host:destination", signer=destination_signer)
        provider = MigrateThenCompleteProvider(destination.host_id)
        source.providers["migrator"] = provider
        destination.providers["migrator"] = provider
        envelope = make_demo_envelope(source, "move safely", "migrator")
        object.__setattr__(envelope.permit, "delegation_allowed", True)
        source.signer.seal(envelope)
        first = source.run(envelope)
        self.assertIsNotNone(first.migration_envelope)
        from portmark.a2a import envelope_from_dict
        migrated = envelope_from_dict(first.migration_envelope)
        self.assertEqual(migrated.permit.audience, destination.host_id)
        self.assertFalse(migrated.permit.delegation_allowed)

        forged = envelope_from_dict(first.migration_envelope)
        forged.previous_audit_signature = "tampered"
        source.signer.seal(forged)
        fresh_destination = make_host(host_id="host:destination", signer=destination_signer)
        fresh_destination.providers["migrator"] = provider
        with self.assertRaisesRegex(SecurityError, "audit head signature"):
            fresh_destination.run(forged)

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
        source_signer = EnvelopeSigner.generate("source-key", "host:source", ("host:source", "host:destination"))
        destination_signer = trust_signer(EnvelopeSigner.generate("destination-key", "host:destination", ("host:destination",)), source_signer)
        source = make_host(host_id="host:source", signer=source_signer, attestation_policy=policy)
        destination = make_host(host_id="host:destination", signer=destination_signer, attestation_policy=policy)
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
        source_signer.seal(envelope)

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
            self.assertNotIn("protocolVersion", card)  # not an AgentCard field
            self.assertNotIn("url", card)              # lives in supportedInterfaces
            self.assertEqual(card["supportedInterfaces"][0]["protocolBinding"], "JSONRPC")
            self.assertEqual(card["supportedInterfaces"][0]["protocolVersion"], "1.0")
            self.assertEqual(card["defaultInputModes"], ["application/json"])
            self.assertEqual(card["securitySchemes"]["bearer"]["httpAuthSecurityScheme"]["scheme"], "bearer")
            self.assertEqual(card["securityRequirements"], [{"schemes": {"bearer": {}}}])
            self.assertEqual(card["skills"][0]["id"], "portmark")
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
            self.assertEqual(result["result"]["metadata"]["portmark_status"], "completed")
        finally:
            server.shutdown()
            server.server_close()

    def test_a2a_sdk_adapter_emits_official_agent_card_shape(self):
        with self._fake_official_a2a_sdk():
            host = make_host()
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                make_handler(host, A2AAuthConfig("a2a-secret"), a2a_adapter="sdk"),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                with urllib.request.urlopen(base + "/.well-known/agent-card.json") as response:  # nosec B310
                    card = json.load(response)
                self.assertEqual(card["securitySchemes"]["bearer"]["httpAuthSecurityScheme"]["scheme"], "bearer")
                self.assertEqual(card["securityRequirements"], [{"schemes": {"bearer": {}}}])
                self.assertEqual(card["supportedInterfaces"][0]["protocolBinding"], "JSONRPC")
            finally:
                server.shutdown()
                server.server_close()

    def test_a2a_sdk_adapter_rejects_request_parts_before_host_execution(self):
        with self._fake_official_a2a_sdk():
            host = make_host()
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(host, a2a_adapter="sdk"))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                body = json.loads(self._a2a_request_body(host, "sdk invalid part").decode())
                body["params"]["message"]["parts"] = [{"kind": "unknown", "payload": "locally accepted"}]
                request = urllib.request.Request(
                    base + "/message:send",
                    data=json.dumps(body).encode(),
                    headers={"Content-Type": "application/json"},
                )
                with patch.object(host, "run", wraps=host.run) as run:
                    with self.assertRaises(urllib.error.HTTPError) as raised:
                        urllib.request.urlopen(request)  # nosec B310
                self.assertEqual(raised.exception.code, 400)
                self.assertEqual(json.load(raised.exception)["error"]["code"], -32602)
                run.assert_not_called()
            finally:
                server.shutdown()
                server.server_close()

    def test_a2a_sdk_adapter_requires_optional_dependency(self):
        original_import = __import__

        def blocked_import(name, *args, **kwargs):
            if name == "a2a.types":
                raise ImportError("blocked a2a-sdk")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=blocked_import):
            with self.assertRaisesRegex(RuntimeError, "portmark\\[a2a\\]"):
                make_handler(make_host(), a2a_adapter="sdk")

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

    def test_a2a_metrics_endpoint_requires_bearer_auth_and_returns_snapshot(self):
        host = make_host()
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(host, A2AAuthConfig("metrics-secret"), rate_limit_per_ip=100),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            body = self._a2a_request_body(host, "metrics endpoint")
            submit = urllib.request.Request(
                base + "/message:send",
                data=body,
                headers={"Content-Type": "application/json", "Authorization": "Bearer metrics-secret"},
            )
            with urllib.request.urlopen(submit) as response:  # nosec B310
                self.assertEqual(json.load(response)["result"]["status"]["state"], "completed")

            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(base + "/metrics")  # nosec B310
            self.assertEqual(raised.exception.code, 401)
            self.assertEqual(json.load(raised.exception)["error"]["message"], "unauthorized")

            wrong = urllib.request.Request(base + "/metrics", headers={"Authorization": "Bearer wrong"})
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(wrong)  # nosec B310
            self.assertEqual(raised.exception.code, 401)

            request = urllib.request.Request(base + "/metrics", headers={"Authorization": "Bearer metrics-secret"})
            with urllib.request.urlopen(request) as response:  # nosec B310
                self.assertEqual(response.headers["Content-Type"], "application/json")
                metrics = json.load(response)
            self.assertEqual(metrics["counters"]["runs.completed"], 1)
            self.assertEqual(metrics["counters"]["runs.started"], 1)
            self.assertEqual(metrics["counters"]["provider.decisions"], 2)
            self.assertEqual(metrics["counters"]["tools.executed"], 1)

            prometheus = urllib.request.Request(
                base + "/metrics",
                headers={"Authorization": "Bearer metrics-secret", "Accept": "text/plain"},
            )
            with urllib.request.urlopen(prometheus) as response:  # nosec B310
                self.assertTrue(response.headers["Content-Type"].startswith("text/plain"))
                text = response.read().decode()
            self.assertIn('portmark_runtime_counter_total{name="runs.started"} 1', text)
            self.assertIn("portmark_run_duration_seconds_count 1", text)
            self.assertIn("portmark_provider_decision_duration_seconds_count 2", text)
            self.assertIn("portmark_tool_invocation_duration_seconds_count 1", text)
            self.assertIn("portmark_a2a_request_duration_seconds_count 1", text)
        finally:
            server.shutdown()
            server.server_close()

    def test_a2a_metrics_endpoint_is_rate_limited_separately(self):
        host = make_host()
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(host, A2AAuthConfig("metrics-secret"), rate_limit_per_ip=1, rate_limit_window_seconds=60),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            request = urllib.request.Request(base + "/metrics", headers={"Authorization": "Bearer metrics-secret"})
            with urllib.request.urlopen(request) as response:  # nosec B310
                self.assertEqual(json.load(response), {"counters": {}})

            request = urllib.request.Request(base + "/metrics", headers={"Authorization": "Bearer metrics-secret"})
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request)  # nosec B310
            self.assertEqual(raised.exception.code, 429)
            self.assertEqual(raised.exception.headers["Retry-After"], "60")
            self.assertEqual(json.load(raised.exception)["error"], {"code": -32002, "message": "rate limit exceeded"})
        finally:
            server.shutdown()
            server.server_close()

    def test_a2a_metrics_endpoint_is_not_open_when_message_auth_is_disabled(self):
        host = make_host()
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(host))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(base + "/metrics")  # nosec B310
            self.assertEqual(raised.exception.code, 401)
            payload = json.load(raised.exception)
            self.assertEqual(payload["error"], {"code": -32001, "message": "unauthorized"})
            self.assertEqual(raised.exception.headers["WWW-Authenticate"], 'Bearer realm="portmark"')
        finally:
            server.shutdown()
            server.server_close()

    def test_a2a_serve_requires_loopback_even_when_direct_exposure_flag_is_set(self):
        public_bind = ".".join(("0", "0", "0", "0"))
        self.assertTrue(is_loopback_bind("127.0.0.1"))
        self.assertTrue(is_loopback_bind("::1"))
        self.assertTrue(is_loopback_bind("localhost"))
        self.assertFalse(is_loopback_bind(public_bind))
        self.assertFalse(is_loopback_bind("192.0.2.10"))
        self.assertFalse(issubclass(BoundedReferenceHTTPServer, ThreadingHTTPServer))

        host = make_host()
        with patch("uvicorn.run") as run:
            with self.assertRaisesRegex(ValueError, "loopback"):
                serve(host, public_bind, 8080)
        run.assert_not_called()

        with patch("uvicorn.run") as run:
            with self.assertRaisesRegex(ValueError, "reverse proxy"):
                serve(host, public_bind, 8080, allow_direct_a2a=True)
        run.assert_not_called()

        with patch("uvicorn.run") as run:
            serve(host, "127.0.0.1", 8080)
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs["host"], "127.0.0.1")
        self.assertEqual(run.call_args.kwargs["limit_concurrency"], DEFAULT_MAX_CONCURRENT_REQUESTS)

    def _asgi_call(self, app, method, path, headers=None, body=b"", client=("203.0.113.9", 5555)):
        """Drive an ASGI app directly and collect the response."""
        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "client": client,
            "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        }
        sent = []

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            sent.append(message)

        asyncio.run(app(scope, receive, send))
        status = sent[0]["status"]
        response_headers = {k.decode(): v.decode() for k, v in sent[0]["headers"]}
        payload = b"".join(m.get("body", b"") for m in sent[1:])
        return status, response_headers, payload

    def test_asgi_app_serves_agent_card_with_security_headers(self):
        app = make_asgi_app(make_host())
        status, headers, payload = self._asgi_call(app, "GET", "/.well-known/agent-card.json", {"Host": "127.0.0.1"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["supportedInterfaces"][0]["protocolVersion"], "1.0")
        for header in ("x-content-type-options", "x-frame-options", "content-security-policy", "referrer-policy"):
            self.assertIn(header, headers)

    def test_asgi_healthz_and_readyz(self):
        app = make_asgi_app(make_host())
        status, _, payload = self._asgi_call(app, "GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {"status": "ok"})
        status, _, payload = self._asgi_call(app, "GET", "/readyz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {"status": "ready"})

    def test_asgi_readyz_fails_generically_when_policy_or_store_config_is_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bad_policy = root / "bad-policy.json"
            bad_policy.write_text("[]", encoding="utf-8")
            bad_store = root / "store-dir"
            bad_store.mkdir()
            cases = [
                (lambda: load_host_policy(bad_policy, "host:local-demo"), "bad-policy"),
                (lambda: SQLiteRuntimeStore(bad_store), "store-dir"),
            ]
            for readiness_check, leaked in cases:
                with self.subTest(leaked=leaked):
                    app = make_asgi_app(make_host(), readiness_check=readiness_check, readiness_cache_seconds=0)
                    with patch("portmark.a2a.logger.exception") as logged:
                        status, _, payload = self._asgi_call(app, "GET", "/readyz")
                    self.assertEqual(status, 503)
                    self.assertEqual(json.loads(payload), {"status": "not_ready"})
                    self.assertNotIn(leaked, payload.decode())
                    logged.assert_called_once_with("A2A readiness check failed")

    def test_asgi_app_accepts_signed_message_submission(self):
        host = make_host()
        app = make_asgi_app(host, A2AAuthConfig("secret"))
        body = self._a2a_request_body(host, "ASGI task")
        status, _, payload = self._asgi_call(
            app,
            "POST",
            "/message:send",
            {"Content-Type": "application/json", "Content-Length": str(len(body)), "Authorization": "Bearer secret"},
            body,
        )
        result = json.loads(payload)
        self.assertEqual(status, 200)
        self.assertEqual(result["jsonrpc"], "2.0")
        self.assertEqual(result["result"]["status"]["state"], "completed")

        status, headers, metrics_payload = self._asgi_call(
            app,
            "GET",
            "/metrics",
            {"Authorization": "Bearer secret", "Accept": "text/plain"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(headers["content-type"].startswith("text/plain"))
        text = metrics_payload.decode()
        self.assertIn("portmark_run_duration_seconds_count 1", text)
        self.assertIn("portmark_provider_decision_duration_seconds_count 2", text)
        self.assertIn("portmark_tool_invocation_duration_seconds_count 1", text)
        self.assertIn("portmark_a2a_request_duration_seconds_count 1", text)

    def test_asgi_app_returns_generic_submission_errors(self):
        host = make_host()
        app = make_asgi_app(host, A2AAuthConfig("secret"))
        envelope = make_demo_envelope(host, "ASGI tamper")
        envelope.state.goal = 'tampered-goal-with-label";reason="owned'
        envelope.state.task_id = 'task-with-label";reason="owned'
        body = self._a2a_request_body(host, "ASGI tamper", envelope=envelope)
        with patch("portmark.a2a.logger.exception") as logged:
            status, _, payload = self._asgi_call(
                app,
                "POST",
                "/message:send",
                {
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "Authorization": "Bearer secret",
                },
                body,
            )
        decoded = json.loads(payload)
        self.assertEqual(status, 400)
        self.assertEqual(decoded["error"], {"code": -32000, "message": "message submission failed"})
        self.assertNotIn("SecurityError", payload.decode())
        self.assertNotIn("signature", payload.decode())
        logged.assert_called_once_with("A2A message submission failed")

        status, _, metrics_payload = self._asgi_call(
            app,
            "GET",
            "/metrics",
            {"Authorization": "Bearer secret", "Accept": "text/plain"},
        )
        text = metrics_payload.decode()
        self.assertEqual(status, 200)
        self.assertIn('portmark_refusals_total{reason="internal"} 1', text)
        self.assertNotIn("tampered-goal-with-label", text)
        self.assertNotIn("task-with-label", text)

    def test_asgi_app_rejects_oversized_content_length_without_reading_body(self):
        app = make_asgi_app(make_host())
        read = []

        async def receive():
            read.append(True)
            return {"type": "http.request", "body": b"x", "more_body": False}

        sent = []

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http", "method": "POST", "path": "/message:send", "client": ("203.0.113.9", 1),
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(MAX_REQUEST_BYTES + 1).encode())],
        }
        asyncio.run(app(scope, receive, send))
        self.assertEqual(sent[0]["status"], 413)
        self.assertEqual(read, [], "oversized request must be rejected before the body is read")

    def test_asgi_app_requires_auth_for_metrics_and_shares_rate_limit_state(self):
        host = make_host()
        app = make_asgi_app(host, A2AAuthConfig("secret"), rate_limit_per_ip=2)
        status, headers, _ = self._asgi_call(app, "GET", "/metrics")
        self.assertEqual(status, 401)
        self.assertIn("www-authenticate", headers)  # ASGI header names are lowercase
        status, _, payload = self._asgi_call(app, "GET", "/metrics", {"Authorization": "Bearer secret"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {"counters": {}})
        self.assertNotIn("portmark_", payload.decode())
        # The limiter lives on the router, not the request: a third call must be refused.
        status, _, _ = self._asgi_call(app, "GET", "/metrics", {"Authorization": "Bearer secret"})
        self.assertEqual(status, 429)

    def test_asgi_app_rate_limits_before_reading_the_body(self):
        """A refused submission must not cause its body to be buffered.

        The guard has to wrap the body read, not follow it, or a flood costs one
        buffered body per rejected request.
        """
        app = make_asgi_app(make_host(), rate_limit_per_ip=1)
        body = b'{"jsonrpc":"2.0","id":"1","method":"message/send","params":{}}'
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
        reads = []

        def run_once():
            async def receive():
                reads.append(True)
                return {"type": "http.request", "body": body, "more_body": False}

            sent = []

            async def send(message):
                sent.append(message)

            scope = {"type": "http", "method": "POST", "path": "/message:send",
                     "client": ("203.0.113.9", 1), "headers": headers}
            asyncio.run(app(scope, receive, send))
            return sent[0]["status"]

        self.assertEqual(run_once(), 400)
        self.assertEqual(len(reads), 1)
        self.assertEqual(run_once(), 429)
        self.assertEqual(len(reads), 1, "rate-limited request must not read its body")

    def test_asgi_app_handles_missing_client_and_unknown_paths(self):
        app = make_asgi_app(make_host())
        status, _, _ = self._asgi_call(app, "GET", "/nope")
        self.assertEqual(status, 404)
        # scope["client"] is None under some deployments; the limiter must still key deterministically.
        status, _, _ = self._asgi_call(app, "GET", "/.well-known/agent-card.json", {"Host": "h"}, client=None)
        self.assertEqual(status, 200)

    @unittest.skipUnless(HAS_REAL_A2A_SDK, "requires portmark[a2a]")
    def test_local_agent_card_parses_under_strict_official_schema(self):
        """The card must parse WITHOUT ignore_unknown_fields.

        Unknown fields are an error to a strict A2A client, not something it
        skips, so a card carrying non-schema fields is undiscoverable. This is
        the check that fails when the card drifts; the rest of the suite does
        not notice, because it only asserts fields it already knows about.
        """
        from google.protobuf.json_format import ParseDict
        import a2a.types as sdk_types

        for require_auth in (True, False):
            with self.subTest(require_auth=require_auth):
                card = json.loads(json.dumps(make_agent_card("http://h", require_auth)))
                ParseDict(card, sdk_types.AgentCard())

    @unittest.skipUnless(HAS_REAL_A2A_SDK, "requires portmark[a2a]")
    def test_local_and_sdk_agent_cards_are_identical(self):
        """Both adapters must serve the same card.

        The card is swapped rather than stacked when --a2a-adapter changes, so
        without this the two modes can silently diverge.
        """
        for require_auth in (True, False):
            with self.subTest(require_auth=require_auth):
                local = json.loads(json.dumps(make_agent_card("http://h", require_auth)))
                from portmark.official_a2a import make_sdk_agent_card

                self.assertEqual(local, make_sdk_agent_card("http://h", require_auth))

    def test_a2a_cli_rejects_public_bind_without_traceback(self):
        error = io.StringIO()
        public_bind = ".".join(("0", "0", "0", "0"))
        with patch.object(sys, "argv", ["portmark", "--allow-direct-a2a", "serve", "--bind", public_bind, "--port", "8080"]):
            with redirect_stderr(error):
                with self.assertRaises(SystemExit) as raised:
                    cli_main()
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("must bind to loopback", error.getvalue())
        self.assertNotIn("Traceback", error.getvalue())
        self.assertNotIn("ValueError", error.getvalue())

    def test_a2a_nginx_front_documents_required_controls(self):
        config = (Path(__file__).parents[1] / "deploy" / "nginx" / "portmark.conf").read_text(encoding="utf-8")
        for required in [
            "proxy_pass http://127.0.0.1:8080",
            "client_max_body_size 1m",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "limit_req_zone",
            "limit_conn_zone",
            "zone=portmark_agent_card_rate",
            "zone=portmark_metrics_rate",
            "location = /.well-known/agent-card.json",
            "location = /message:send",
            "location = /metrics",
            "proxy_set_header Authorization $http_authorization",
            "return 308 https://$host$request_uri",
        ]:
            with self.subTest(required=required):
                self.assertIn(required, config)

    def test_dockerfile_uses_non_root_runtime_and_does_not_bake_secrets(self):
        dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")
        required = [
            "FROM python:3.12.12-slim-bookworm",
            "pip==26.2.1",
            "setuptools==83.0.0",
            "pip install --no-cache-dir .",
            "useradd",
            "USER portmark",
            "uvicorn",
            "portmark.asgi:app",
        ]
        for item in required:
            with self.subTest(required=item):
                self.assertIn(item, dockerfile)
        forbidden = [
            "PORTMARK_ED25519_PRIVATE_KEY_B64=",
            "PORTMARK_SIGNING_KEY=",
            "PORTMARK_A2A_TOKEN=",
            "SECRET",
            "TOKEN=",
            "apt-get",
            "build-essential",
            " gcc",
        ]
        for item in forbidden:
            with self.subTest(forbidden=item):
                self.assertNotIn(item, dockerfile)

    def test_container_asgi_entrypoint_builds_app_from_environment(self):
        with patch.dict(os.environ, {}, clear=True):
            from portmark.asgi import create_app

            app = create_app()
        status, _, payload = self._asgi_call(app, "GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {"status": "ok"})

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
                    "metadata": {"portmark_envelope": {"signature": "broken"}},
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
                (
                    json.dumps({
                        "jsonrpc": "2.0",
                        "id": "bad-envelope",
                        "method": "message/send",
                        "params": {
                            "message": {"messageId": "msg-1", "role": "user", "parts": [{"kind": "text", "text": "run"}]},
                            "metadata": {"portmark_envelope": {"signature": "broken"}},
                        },
                    }).encode(),
                    {"Content-Type": "application/json"},
                    400,
                    -32602,
                ),
                (b"{}", {"Content-Type": "text/plain"}, 415, -32600),
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
            with self.subTest(status=413, code=-32600):
                self.assertEqual(self._oversized_rejection(server.server_port), (413, -32600))
        finally:
            server.shutdown()
            server.server_close()

    def test_a2a_parser_fuzz_target_fails_closed(self):
        run_fuzz_cases(iterations=200)

    def test_a2a_rate_limits_message_submissions_per_ip(self):
        host = make_host()
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(host, rate_limit_per_ip=1, rate_limit_window_seconds=60))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            first = urllib.request.Request(
                base + "/message:send",
                data=self._a2a_request_body(host, "first limited task"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(first) as response:  # nosec B310
                self.assertEqual(json.load(response)["result"]["status"]["state"], "completed")

            second = urllib.request.Request(
                base + "/message:send",
                data=self._a2a_request_body(host, "second limited task"),
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(second)  # nosec B310
            self.assertEqual(raised.exception.code, 429)
            self.assertEqual(raised.exception.headers["Retry-After"], "60")
            payload = json.load(raised.exception)
            self.assertEqual(payload["error"], {"code": -32002, "message": "rate limit exceeded"})
        finally:
            server.shutdown()
            server.server_close()

    def test_a2a_rate_limits_agent_card_per_ip(self):
        host = make_host()
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(host, agent_card_rate_limit_per_ip=1, agent_card_rate_limit_window_seconds=60),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urllib.request.urlopen(base + "/.well-known/agent-card.json") as response:  # nosec B310
                self.assertEqual(json.load(response)["supportedInterfaces"][0]["protocolVersion"], "1.0")

            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(base + "/.well-known/agent-card.json")  # nosec B310
            self.assertEqual(raised.exception.code, 429)
            self.assertEqual(raised.exception.headers["Retry-After"], "60")
            payload = json.load(raised.exception)
            self.assertEqual(payload["error"], {"code": -32002, "message": "rate limit exceeded"})
        finally:
            server.shutdown()
            server.server_close()

    def test_a2a_bounded_reference_server_handles_concurrent_loopback_load(self):
        """Concurrent requests all complete and none are cross-contaminated.

        The caps are deliberately double the worker count. With them equal, a
        connection slot the server has not finished releasing can reject the next
        request with 503 and fail this test for a reason it does not test --
        observed once on CI, green on a re-run of the same commit. Saturation
        behaviour has its own deterministic test below, which blocks a provider
        rather than racing the cap, so widening the margin here loses no coverage.
        """
        workers = 8
        host = make_host()
        server = BoundedReferenceHTTPServer(
            ("127.0.0.1", 0),
            make_handler(
                host,
                max_concurrent_requests=workers * 2,
                rate_limit_per_ip=100,
                agent_card_rate_limit_per_ip=100,
            ),
            max_connections=workers * 2,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"

        def submit(index):
            body = self._a2a_request_body(host, f"load task {index}")
            request = urllib.request.Request(base + "/message:send", data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=10) as response:  # nosec B310
                payload = json.load(response)
            return payload["result"]["status"]["state"]

        def get_card(_):
            with urllib.request.urlopen(base + "/.well-known/agent-card.json", timeout=10) as response:  # nosec B310
                return json.load(response)["supportedInterfaces"][0]["protocolVersion"]

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                message_states = list(executor.map(submit, range(12)))
                card_versions = list(executor.map(get_card, range(12)))
            self.assertEqual(message_states, ["completed"] * 12)
            self.assertEqual(card_versions, ["1.0"] * 12)
        finally:
            server.shutdown()
            server.server_close()

    def test_a2a_connection_cap_rejects_saturated_message_submissions(self):
        host = make_host()
        entered = threading.Event()
        release = threading.Event()
        host.providers["blocker"] = BlockingProvider(entered, release)
        server = BoundedReferenceHTTPServer(
            ("127.0.0.1", 0),
            make_handler(host, max_concurrent_requests=100, rate_limit_per_ip=100),
            max_connections=1,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"

        def submit_blocking_request():
            request = urllib.request.Request(
                base + "/message:send",
                data=self._a2a_request_body(host, "blocking task", make_demo_envelope(host, "blocking task", "blocker")),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request) as response:  # nosec B310
                return json.load(response)

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(submit_blocking_request)
            try:
                self.assertTrue(entered.wait(5))
                second = urllib.request.Request(
                    base + "/message:send",
                    data=self._a2a_request_body(host, "busy task"),
                    headers={"Content-Type": "application/json"},
                )
                status, payload = self._busy_rejection(server.server_port, second.data)
                self.assertEqual(status, 503)
                self.assertEqual(payload["error"], {"code": -32003, "message": "server busy"})
            finally:
                release.set()
                server.shutdown()
                server.server_close()
            self.assertEqual(future.result(timeout=10)["result"]["status"]["state"], "completed")

    def _busy_rejection(self, port, body):
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        try:
            sock.sendall(
                b"POST /message:send HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
            )
            response = sock.makefile("rb")
            status = int(response.readline().split()[1])
            headers = {}
            while True:
                line = response.readline()
                if line in (b"\r\n", b""):
                    break
                key, value = line.decode("latin-1").split(":", 1)
                headers[key.lower()] = value.strip()
            payload = json.loads(response.read(int(headers["content-length"])))
            return status, payload
        finally:
            sock.close()

    def _oversized_rejection(self, port):
        """Declare an oversized body in the headers without sending one.

        The server rejects on Content-Length alone and never reads the body,
        which is the DoS property we want. Actually sending the body races that
        response: the server closes first and the client sees a broken pipe
        instead of the 413. Sending headers only makes the check deterministic.
        """
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        try:
            sock.sendall(
                b"POST /message:send HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 1000001\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )
            response = HTTPResponse(sock)
            response.begin()
            payload = json.loads(response.read())
            self.assertEqual(payload["jsonrpc"], "2.0")
            return response.status, payload["error"]["code"]
        finally:
            sock.close()

    def _a2a_request_body(self, host, text, envelope=None):
        return json.dumps({
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "message/send",
            "params": {
                "message": {"messageId": "msg-1", "role": "user", "parts": [{"kind": "text", "text": text}]},
                "metadata": {"portmark_envelope": asdict(envelope or make_demo_envelope(host, text))},
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
                "catalog.search": {"impact": "low", "constraints": {"max_limit": 5}, "output_projection": ["id", "title"]},
                "payments.reserve": {"impact": "external-payment", "constraints": {"max_amount": 100, "currency": "USD"}},
            },
        }), encoding="utf-8")
        return path

    def _write_trust_registry(self, directory, signer):
        path = Path(directory) / "trust.json"
        path.write_text(json.dumps({
            "identities": [{
                "key_id": signer.key_id,
                "issuer": signer.issuer,
                "public_key_b64": base64.urlsafe_b64encode(signer.public_key_bytes()).decode("ascii").rstrip("="),
                "allowed_audiences": ["*"],
            }]
        }), encoding="utf-8")
        return path

    @contextmanager
    def _fake_official_a2a_sdk(self):
        a2a = ModuleType("a2a")
        a2a_types = ModuleType("a2a.types")
        google = ModuleType("google")
        protobuf = ModuleType("google.protobuf")
        json_format = ModuleType("google.protobuf.json_format")

        class AgentCard:
            pass

        class SendMessageRequest:
            pass

        def parse_dict(payload, target):
            if isinstance(target, SendMessageRequest):
                message = payload.get("message")
                if not isinstance(message, dict) or message.get("role") not in {"ROLE_USER", "ROLE_AGENT"}:
                    raise ValueError("invalid SDK message")
                for part in message.get("parts", []):
                    if not any(key in part for key in ("text", "raw", "url", "data")):
                        raise ValueError("invalid SDK message part")
            target.payload = payload
            return target

        def message_to_dict(value, preserving_proto_field_name=False):
            return value.payload

        a2a_types.AgentCard = AgentCard
        a2a_types.SendMessageRequest = SendMessageRequest
        json_format.ParseDict = parse_dict
        json_format.MessageToDict = message_to_dict
        with patch.dict(sys.modules, {
            "a2a": a2a,
            "a2a.types": a2a_types,
            "google": google,
            "google.protobuf": protobuf,
            "google.protobuf.json_format": json_format,
        }):
            yield

    @contextmanager
    def _fake_wasmtime_runtime(self, sleep_seconds=0, content=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "wasmtime"
            package.mkdir()
            (package / "__init__.py").write_text(
                "class Engine:\n"
                "    pass\n"
                "class Store:\n"
                "    def __init__(self, engine=None):\n"
                "        self.engine = engine\n",
                encoding="utf-8",
            )
            response = content
            if response is None:
                response = json.dumps({
                    "outcome": "tool",
                    "request": {
                        "name": "catalog.search",
                        "arguments_json": json.dumps({"query": "from native wasmtime", "limit": 2}),
                    },
                })
            (package / "component.py").write_text(
                "\n".join((
                    "import time",
                    "class Component:",
                    "    def __init__(self, engine, wasm):",
                    "        if wasm == b'import':",
                    "            raise RuntimeError('imports are not linked')",
                    "        self.wasm = wasm",
                    "class Linker:",
                    "    def __init__(self, engine):",
                    "        self.engine = engine",
                    "    def instantiate(self, store, component):",
                    "        return Instance(component.wasm)",
                    "class Instance:",
                    "    def __init__(self, wasm):",
                    "        self.wasm = wasm",
                    "    def get_func(self, store, name):",
                    "        if self.wasm == b'missing-resume' or name != 'resume':",
                    "            return None",
                    "        return Func()",
                    "class Func:",
                    "    def __call__(self, store, context_json, checkpoint_json):",
                    f"        time.sleep({sleep_seconds!r})",
                    f"        return {response!r}",
                    "    def post_return(self, store):",
                    "        pass",
                    "",
                )),
                encoding="utf-8",
            )
            python_path = os.pathsep.join(filter(None, (directory, os.environ.get("PYTHONPATH", ""))))
            with patch.dict(os.environ, {"PYTHONPATH": python_path}):
                yield

    def test_real_wasm_capsule_completes_inside_deadline_limited_sandbox(self):
        capsule = Path(__file__).parents[1] / "capsules" / "research-agent.wasm.b64"
        host = make_host(wasm_component=str(capsule))
        envelope = make_demo_envelope(host, "portable execution", "wasm")
        result = host.run(envelope)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.result["summary"], "Wasm resumed from checkpointed tool result")
        self.assertEqual(result.result["evidence"], ["checkpoint-observed"])
        self.assertEqual([event["event"] for event in result.audit].count("tool.executed"), 1)
        self.assertEqual(result.checkpoint["messages"][0]["content"][0]["title"], "Result 1 for from capsule checkpoint")

    def test_native_wasmtime_provider_uses_component_api_in_isolated_worker(self):
        component = b"native-component"
        with self._fake_wasmtime_runtime():
            provider = NativeWasmtimeComponentProvider(component)
            decision = provider.decide(AgentState("task", "goal"), ("catalog.search",))
        self.assertEqual(decision.kind, "tool")
        self.assertEqual(decision.tool, "catalog.search")
        self.assertEqual(decision.arguments, {"query": "from native wasmtime", "limit": 2})

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    def test_real_native_wasmtime_component_runs_and_resumes_from_projected_checkpoint(self):
        capsule = Path(__file__).parents[1] / "capsules" / "research-agent.component.wasm.b64"
        host = make_host(wasm_component=str(capsule), wasm_engine="wasmtime")
        result = host.run(make_demo_envelope(host, "portable native component", "wasm"))
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.result["summary"], "Native Wasmtime component resumed from checkpoint")
        self.assertEqual(result.result["evidence"], ["native-checkpoint-observed"])
        self.assertEqual([event["event"] for event in result.audit].count("tool.executed"), 1)
        self.assertEqual(result.checkpoint["messages"][0]["content"][0]["title"], "Result 1 for from native component checkpoint")

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    def test_real_native_wasmtime_component_artifact_matches_source(self):
        from wasmtime import wat2wasm

        root = Path(__file__).parents[1]
        source = (root / "capsules" / "research-agent.component.wat").read_text(encoding="utf-8")
        artifact = base64.b64decode((root / "capsules" / "research-agent.component.wasm.b64").read_bytes().strip(), validate=True)
        self.assertEqual(bytes(wat2wasm(source)), artifact)

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    def test_real_native_wasmtime_rejects_importing_component_after_component_parse(self):
        from wasmtime import wat2wasm

        importing_component = bytes(wat2wasm("""
        (component
          (import "host-resume" (func $resume
            (param "context-json" string)
            (param "checkpoint-json" string)
            (result string)))
          (export "resume" (func $resume)))
        """))
        provider = NativeWasmtimeComponentProvider(importing_component)
        with self.assertRaisesRegex(RuntimeError, "unknown import|import"):
            provider.decide(AgentState("task", "goal"), ("catalog.search",))

        core_provider = NativeWasmtimeComponentProvider(base64.b64decode(WASM_TOOL_REQUEST))
        with self.assertRaisesRegex(RuntimeError, "component parser|parse a wasm module"):
            core_provider.decide(AgentState("task", "goal"), ("catalog.search",))

    def test_native_wasmtime_provider_rejects_unlinkable_or_missing_resume_components(self):
        with self._fake_wasmtime_runtime():
            provider = NativeWasmtimeComponentProvider(b"import")
            with self.assertRaisesRegex(RuntimeError, "native Wasmtime component rejected"):
                provider.decide(AgentState("task", "goal"), ("catalog.search",))

        with self._fake_wasmtime_runtime():
            provider = NativeWasmtimeComponentProvider(b"missing-resume")
            with self.assertRaisesRegex(RuntimeError, "native Wasmtime component rejected"):
                provider.decide(AgentState("task", "goal"), ("catalog.search",))

    def test_native_wasmtime_provider_enforces_timeout_and_output_limit(self):
        with self._fake_wasmtime_runtime(sleep_seconds=2):
            provider = NativeWasmtimeComponentProvider(b"slow", timeout=0.1)
            with self.assertRaisesRegex(RuntimeError, "execution deadline"):
                provider.decide(AgentState("task", "goal"), ("catalog.search",))

        with self._fake_wasmtime_runtime(content="x" * 1024):
            provider = NativeWasmtimeComponentProvider(b"large", max_output_bytes=128)
            with self.assertRaisesRegex(RuntimeError, "output limit|rejected"):
                provider.decide(AgentState("task", "goal"), ("catalog.search",))

    def test_native_wasmtime_provider_rejects_oversized_component_files(self):
        with tempfile.NamedTemporaryFile() as capsule:
            capsule.write(b"x" * 5)
            capsule.flush()
            with self.assertRaisesRegex(RuntimeError, "input limit"):
                NativeWasmtimeComponentProvider.from_file(capsule.name, max_component_bytes=4)

    def test_factory_selects_optional_native_wasmtime_provider(self):
        with self._fake_wasmtime_runtime():
            with tempfile.NamedTemporaryFile() as capsule:
                capsule.write(b"native-component")
                capsule.flush()
                host = make_host(
                    wasm_component=capsule.name,
                    wasm_engine="wasmtime",
                )
        self.assertIsInstance(host.providers["wasm"], NativeWasmtimeComponentProvider)

    def test_wasm_component_inputs_use_projected_provider_state(self):
        from portmark.component_bindings import component_checkpoint, component_context

        state = AgentState(
            "task-1",
            "goal",
            memory={"internal_note": "blocked-content"},
            messages=[{"role": "tool", "name": "catalog.search", "content": {"id": "doc-1", "title": "Visible", "internal_note": "blocked-content"}}],
            result={"internal_note": "blocked-content"},
        )
        grants = (ToolGrant("catalog.search", output_projection=("title",)),)
        context = component_context(state, ("catalog.search",), grants)
        checkpoint = component_checkpoint(state, grants)

        self.assertEqual(context["state"]["messages"], [{"role": "tool", "name": "catalog.search", "content": {"title": "Visible"}}])
        self.assertEqual(checkpoint["messages"], [{"role": "tool", "name": "catalog.search", "content": {"title": "Visible"}}])
        self.assertNotIn("memory", context["state"])
        self.assertNotIn("result", context["state"])
        self.assertNotIn("memory", checkpoint)
        self.assertNotIn("internal_note", json.dumps(context))
        self.assertNotIn("internal_note", json.dumps(checkpoint))

    def test_wasm_with_ambient_wasi_import_cannot_instantiate(self):
        from portmark.providers import WasmDecisionProvider
        hostile = base64.b64decode(WASM_FORBIDDEN_IMPORT)
        provider = WasmDecisionProvider(hostile)
        with self.assertRaisesRegex(RuntimeError, "ambient imports"):
            provider.decide(AgentState("task", "goal"), ())

    def test_wasm_component_tool_decision_uses_structured_wit_outcome(self):
        from portmark.providers import WasmDecisionProvider
        provider = WasmDecisionProvider(base64.b64decode(WASM_TOOL_REQUEST))
        decision = provider.decide(AgentState("task", "goal"), ("catalog.search",))
        self.assertEqual(decision.kind, "tool")
        self.assertEqual(decision.tool, "catalog.search")
        self.assertEqual(decision.arguments, {"query": "from wasm", "limit": 3})

    def test_wasm_component_unavailable_capability_fails_closed(self):
        from portmark.providers import WasmDecisionProvider
        provider = WasmDecisionProvider(base64.b64decode(WASM_TOOL_REQUEST))
        decision = provider.decide(AgentState("task", "goal"), ())
        self.assertEqual(decision.kind, "fail")
        self.assertEqual(decision.content, {"error": "required capability unavailable"})

    def test_wasm_component_malformed_missing_timeout_and_oversized_outputs_are_rejected(self):
        from portmark.providers import WasmDecisionProvider
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



class AgentSideToolingTests(unittest.TestCase):
    """The agent-side half: mint a key, build an envelope, have a separate host accept it."""

    def _keygen(self, directory, key_id="portmark-agent-key", issuer="user:alice"):
        material = generate_signing_material(key_id, issuer)
        registry_path = Path(directory) / f"{key_id}.trust.json"
        registry_path.write_text(json.dumps(material["trust_registry"]), encoding="utf-8")
        return material, registry_path

    def _agent_env(self, material):
        return {
            "PORTMARK_ED25519_PRIVATE_KEY_B64": material["private_key_b64"],
            "PORTMARK_SIGNING_KEY_ID": material["key_id"],
            "PORTMARK_SIGNING_ISSUER": material["issuer"],
        }

    def _policy(self, directory, tools):
        path = Path(directory) / "host-policy.json"
        path.write_text(json.dumps({
            "version": "policy-v1",
            "budget": {"max_steps": 10, "max_tool_calls": 5, "max_output_bytes": 65536},
            "tools": tools,
        }), encoding="utf-8")
        return path

    def _tool_module(self, directory, body):
        path = Path(directory) / "custom_tools.py"
        path.write_text(body, encoding="utf-8")
        return path

    def _run_cli(self, argv, env):
        output = io.StringIO()
        with patch.dict(os.environ, env, clear=False):
            with patch.object(sys, "argv", argv):
                with redirect_stdout(output), redirect_stderr(io.StringIO()):
                    cli_main()
        return json.loads(output.getvalue())

    def test_cli_refuses_custom_tools_without_policy_path(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(sys, "argv", ["portmark", "--tools", "custom_tools:registry", "demo"]):
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as caught:
                        cli_main()

        self.assertEqual(caught.exception.code, 2)
        self.assertIn("--tools requires --policy-path", stderr.getvalue())

    def test_cli_rejects_missing_tools_module_or_function(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = self._policy(directory, {
                "catalog.search": {"impact": "low", "constraints": {"max_limit": 5}},
            })
            cases = [
                ("missing_tools_module:registry", "could not load --tools"),
                ("custom_tools:missing_registry", "could not load --tools"),
                ("custom_tools", "module:function"),
            ]
            self._tool_module(directory, "from portmark.tools import ToolRegistry\n\ndef registry():\n    return ToolRegistry()\n")
            with patch.dict(os.environ, {}, clear=True):
                with patch.object(sys, "path", [directory, *sys.path]):
                    for loader, message in cases:
                        with self.subTest(loader=loader):
                            sys.modules.pop("custom_tools", None)
                            with patch.object(sys, "argv", ["portmark", "--policy-path", str(policy_path), "--tools", loader, "demo"]):
                                stderr = io.StringIO()
                                with redirect_stderr(stderr):
                                    with self.assertRaises(SystemExit) as caught:
                                        cli_main()
                            self.assertEqual(caught.exception.code, 2)
                            self.assertIn(message, stderr.getvalue())

    def test_cli_rejects_tools_loader_returning_the_wrong_type(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = self._policy(directory, {
                "catalog.search": {"impact": "low", "constraints": {"max_limit": 5}},
            })
            self._tool_module(directory, "def registry():\n    return {'catalog.search': object()}\n")
            with patch.dict(os.environ, {}, clear=True):
                with patch.object(sys, "path", [directory, *sys.path]):
                    sys.modules.pop("custom_tools", None)
                    with patch.object(sys, "argv", ["portmark", "--policy-path", str(policy_path), "--tools", "custom_tools:registry", "demo"]):
                        stderr = io.StringIO()
                        with redirect_stderr(stderr):
                            with self.assertRaises(SystemExit) as caught:
                                cli_main()

        self.assertEqual(caught.exception.code, 2)
        self.assertIn("must return a portmark.tools.ToolRegistry", stderr.getvalue())

    def test_cli_demo_uses_loaded_custom_tools_when_policy_grants_them(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = self._policy(directory, {
                "catalog.search": {"impact": "low", "constraints": {"max_limit": 5}, "output_projection": ["id", "title"]},
            })
            self._tool_module(directory, """
from portmark.tools import ToolRegistry

def registry():
    tools = ToolRegistry()
    tools.register("catalog.search", lambda arguments: [{"id": "custom-1", "title": "Custom result"}])
    return tools
""")
            with patch.dict(os.environ, {}, clear=True):
                with patch.object(sys, "path", [directory, *sys.path]):
                    sys.modules.pop("custom_tools", None)
                    result = self._run_cli(
                        ["portmark", "--policy-path", str(policy_path), "--tools", "custom_tools:registry", "demo", "find custom"],
                        {},
                    )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["result"]["evidence"], [{"id": "custom-1", "title": "Custom result"}])

    def test_trust_registry_path_is_honoured_without_an_operator_private_key(self):
        """A host given only a registry file must trust the keys inside it.

        Regression: the no-private-key branch built a fresh registry and silently
        discarded the configured one, so an explicit trust anchor did nothing.
        """
        with tempfile.TemporaryDirectory() as directory:
            _, registry_path = self._keygen(directory)
            with patch.dict(os.environ, {}, clear=True):
                signer = signer_from_environment("host:local-demo", str(registry_path))
            self.assertTrue(signer.registry.has_key("portmark-agent-key"))
            self.assertTrue(signer.registry.has_key(signer.key_id))

    def test_signer_refuses_a_registry_entry_holding_a_different_public_key(self):
        """Same key id, different key: fail at construction, not at some later signature."""
        registry = TrustRegistry()
        registry.add(
            TrustedIdentity(
                key_id="collide",
                issuer="user:alice",
                public_key=b"\x01" * 32,
                allowed_audiences=("*",),
            )
        )
        with self.assertRaisesRegex(SecurityError, "different public key"):
            EnvelopeSigner.generate("collide", "user:alice", ("*",), registry=registry)
        with self.assertRaisesRegex(SecurityError, "different public key"):
            EnvelopeSigner.from_private_key_bytes("collide", "user:alice", b"\x02" * 32, ("*",), registry)

    def test_build_envelope_rejects_unknown_and_incomplete_specs(self):
        signer = EnvelopeSigner.generate("spec-key", "user:alice", ("*",))
        cases = [
            ({"goal": "g", "grants": [{"name": "catalog.search"}], "typo": 1}, "unknown envelope spec fields: typo"),
            ({"grants": [{"name": "catalog.search"}]}, "non-empty 'goal'"),
            ({"goal": "g", "grants": []}, "non-empty 'grants'"),
            ({"goal": "g", "grants": [{"nmae": "x"}]}, "unknown grant fields: nmae"),
            ({"goal": "g", "grants": [{"name": "x"}], "budget": {"max_step": 1}}, "unknown budget fields: max_step"),
        ]
        for spec, message in cases:
            with self.subTest(spec=spec):
                with self.assertRaisesRegex(ValueError, message):
                    build_envelope(spec, signer)

    def test_build_envelope_mints_a_fresh_nonce_and_task_id_per_call(self):
        """A saved spec must not become a replayable envelope."""
        signer = EnvelopeSigner.generate("nonce-key", "user:alice", ("*",))
        spec = {"goal": "same goal", "grants": [{"name": "catalog.search"}]}
        first = build_envelope(spec, signer)
        second = build_envelope(spec, signer)
        self.assertNotEqual(first.permit.nonce, second.permit.nonce)
        self.assertNotEqual(first.state.task_id, second.state.task_id)

    def test_envelope_cli_output_is_accepted_by_a_host_that_only_loaded_the_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            material, registry_path = self._keygen(directory)
            request = self._run_cli(
                ["portmark", "envelope", "--goal", "find a red widget", "--tool", "catalog.search"],
                self._agent_env(material),
            )
            self.assertEqual(request["method"], "message/send")

            with patch.dict(os.environ, {}, clear=True):
                host = make_host(trust_registry_path=str(registry_path))
            envelope = envelope_from_dict(request["params"]["metadata"]["portmark_envelope"])
            self.assertEqual(host.run(envelope).status, "completed")

    def test_envelope_signed_by_an_untrusted_key_is_refused_by_that_host(self):
        """Control for the test above: without it, a passing run proves nothing about trust."""
        with tempfile.TemporaryDirectory() as directory:
            _, registry_path = self._keygen(directory)
            stranger, _ = self._keygen(directory, key_id="stranger-key")
            request = self._run_cli(
                ["portmark", "envelope", "--goal", "find a red widget", "--tool", "catalog.search"],
                self._agent_env(stranger),
            )
            with patch.dict(os.environ, {}, clear=True):
                host = make_host(trust_registry_path=str(registry_path))
            envelope = envelope_from_dict(request["params"]["metadata"]["portmark_envelope"])
            with self.assertRaisesRegex(SecurityError, "not trusted"):
                host.run(envelope)

    def test_envelope_cli_refuses_to_sign_with_an_ephemeral_key(self):
        """No soft fallback: a key no host has seen would fail far from its cause."""
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(sys, "argv", ["portmark", "envelope", "--goal", "g", "--tool", "catalog.search"]):
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    with self.assertRaises(SystemExit):
                        cli_main()
        self.assertIn("PORTMARK_ED25519_PRIVATE_KEY_B64", stderr.getvalue())

    def test_keygen_cli_writes_a_registry_and_refuses_to_clobber_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trust.json"
            material = self._run_cli(["portmark", "keygen", "--issuer", "user:alice", "--out-registry", str(path)], {})
            self.assertEqual(json.loads(path.read_text())["identities"][0]["issuer"], "user:alice")
            self.assertEqual(material["issuer"], "user:alice")

            before = path.read_text()
            with patch.object(sys, "argv", ["portmark", "keygen", "--out-registry", str(path)]):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        cli_main()
            self.assertEqual(path.read_text(), before, "existing trust registry must survive")


if __name__ == "__main__":
    unittest.main()

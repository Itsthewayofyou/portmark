import copy
import dataclasses
import functools
import asyncio
import base64
import concurrent.futures
import contextlib
import hashlib
import http.server
import importlib.util
import io
import json
import logging
import os
import platform
import re
import secrets
import shutil
import sqlite3
import subprocess  # nosec B404
import sys
import tempfile
import socket
import threading
import time
import types
import unittest
import urllib.error
import urllib.request
from dataclasses import FrozenInstanceError, asdict
from contextlib import contextmanager, nullcontext, redirect_stderr, redirect_stdout
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
from portmark.models import AgentState, AttestationEvidence, Permit, ProviderDecision, ResourceBudget, ToolGrant
from portmark.projection import project_state_for_migration, provider_state, provider_view
from portmark.providers import GenericHttpProvider, ModelProvider, NativeWasmtimeComponentProvider, ProviderError
from portmark.policy import load_host_policy
from portmark.security import (
    AUDIT_HASH_VERSION,
    ApprovalAuthority,
    AttestationAuthority,
    AttestationPolicy,
    AuditLog,
    EnvelopeSigner,
    audit_event_record,
    ExternalAttestationVerifier,
    HmacEnvelopeSigner,
    HostPolicy,
    MigrationPolicy,
    SecurityError,
    TrustRegistry,
    TrustedIdentity,
    canonical_json,
    effect_id,
    generate_signing_material,
    load_trust_registry,
)
from portmark.host import AgentHost
from portmark.storage import POSTGRES_SCHEMA_VERSION, SQLITE_BUSY_TIMEOUT_MS, SQLITE_SCHEMA_VERSION, InMemoryRuntimeStore, PostgresRuntimeStore, SQLiteRuntimeStore
from portmark.cli import main as cli_main
from portmark.tools import (
    IsolationMechanism,
    IsolationProfile,
    ToolExecutionError,
    ToolRegistry,
    _CAN_KILL_PROCESS_GROUP,
    _has_tree_termination_primitive,
)
from examples.tools import http_fetch
from fuzz_a2a_parser import run_fuzz_cases

# Section 7 PR 2b: a side-effecting tool now requires an acknowledged IsolationProfile on the
# registry. EXTERNAL_CONTAINER is valid on every platform (it is the operator's own affirmation),
# so the test suite uses it as the standard acknowledgement.
_TEST_ISOLATION_PROFILE = IsolationProfile(
    mechanism=IsolationMechanism.EXTERNAL_CONTAINER, acknowledged_by="test-suite"
)


WASM_TOOL_REQUEST = "AGFzbQEAAAABCQFgBH9/f38BfgMCAQAFAwEAAQcTAgZtZW1vcnkCAAZyZXN1bWUAAAoLAQkAQu+AgICAAgsLdQEAQRALb3sib3V0Y29tZSI6InRvb2wiLCJyZXF1ZXN0Ijp7Im5hbWUiOiJjYXRhbG9nLnNlYXJjaCIsImFyZ3VtZW50c19qc29uIjoie1wicXVlcnlcIjpcImZyb20gd2FzbVwiLFwibGltaXRcIjozfSJ9fQ=="
WASM_MALFORMED_JSON = "AGFzbQEAAAABCQFgBH9/f38BfgMCAQAFAwEAAQcTAgZtZW1vcnkCAAZyZXN1bWUAAAoLAQkAQomAgICAAgsLDwEAQRALCXtiYWQganNvbg=="
WASM_TIMEOUT = "AGFzbQEAAAABCQFgBH9/f38BfgMCAQAFAwEAAQcTAgZtZW1vcnkCAAZyZXN1bWUAAAoLAQkAA0AMAAtCAAs="
WASM_FORBIDDEN_IMPORT = "AGFzbQEAAAABDAJgAABgBH9/f38BfgIJAQNlbnYBeAAAAwIBAQUDAQABBxMCBm1lbW9yeQIABnJlc3VtZQABCgYBBABCAAs="
WASM_MISSING_RESUME = "AGFzbQEAAAAFAwEAAQcKAQZtZW1vcnkCAA=="
HAS_REAL_WASMTIME = importlib.util.find_spec("wasmtime") is not None
# The runner refuses anything that is not a BINARY Component Model artifact (fuzz finding), so
# fake-wasmtime tests put this real header in front of their made-up component bytes; the fake
# Component strips it again, so each test still reaches the check it is about.
FAKE_COMPONENT_HEADER = b"\x00asm\x0d\x00\x01\x00"


def _requires_enforced_worker_cap(test):
    """Skip a real native-Wasmtime test where the engine is BLOCKED by design (Section 9 owner
    decision: no enforceable OS memory ceiling -> the provider refuses to start). The blocked
    behaviour itself is asserted, on every platform, by
    test_real_native_wasmtime_platform_outcome_matches_cap_enforcement -- this only stops tests
    that exercise a RUNNING capped worker from erroring where no such worker can exist."""

    @functools.wraps(test)
    def wrapper(self, *args, **kwargs):
        from portmark.providers import _worker_memory_cap_enforceable

        if not _worker_memory_cap_enforceable():
            self.skipTest("native Wasmtime is blocked here: no enforceable worker memory ceiling")
        return test(self, *args, **kwargs)

    return wrapper
HAS_REAL_A2A_SDK = importlib.util.find_spec("a2a") is not None


class FixedProvider(ModelProvider):
    def __init__(self, decision): self.decision = decision
    def decide(self, state, available_tools, grants=()): return self.decision


class AlwaysSuspendProvider(ModelProvider):
    """Suspends on every decision (awaiting_input), so its checkpoint stays open
    and resumable. Counts decisions to prove a rejected replay never reaches it."""

    def __init__(self):
        self.decisions = 0

    def decide(self, state, available_tools, grants=()):
        self.decisions += 1
        return ProviderDecision("await_input", None, {"need": "more input"})


class MigrateThenCompleteProvider(ModelProvider):
    def __init__(self, destination): self.destination = destination
    def decide(self, state, available_tools, grants=()):
        if not state.migrated:
            return ProviderDecision("migrate", destination=self.destination)
        return ProviderDecision("complete", content={"resumed_on": self.destination})


class AttestedMigrateThenCompleteProvider(ModelProvider):
    def __init__(self, destination, attestation):
        self.destination = destination
        self.attestation = attestation
    def decide(self, state, available_tools, grants=()):
        if not state.migrated:
            return ProviderDecision("migrate", destination=self.destination, content={"attestation": asdict(self.attestation)})
        return ProviderDecision("complete", content={"resumed_on": self.destination})


class _StubMigrationAttester:
    """Section 4 #5 test attester. Wraps an AttestationAuthority and issues evidence over the challenge.

    Knobs forge the dimensions the source verifies (audience, nonce, expiry) or simulate a flaky
    attester (raise) to exercise the fail-closed-before-persist path. Records the challenges it saw so a
    test can assert the challenge is fresh per migration.
    """

    def __init__(self, authority, measurement="measurement:enclave", audience_override=None,
                 nonce_override=None, subject_override=None, expires_in=60, raise_error=False,
                 sleep_seconds=0.0):
        self._authority = authority
        self._measurement = measurement
        self._audience_override = audience_override
        self._nonce_override = nonce_override
        self._subject_override = subject_override
        self._expires_in = expires_in
        self._raise_error = raise_error
        self._sleep_seconds = sleep_seconds
        self.challenges = []

    def attest(self, *, subject, audience, challenge):
        self.challenges.append(challenge)
        if self._sleep_seconds:
            time.sleep(self._sleep_seconds)
        if self._raise_error:
            raise RuntimeError("attester unavailable")
        return self._authority.issue(
            subject=self._subject_override if self._subject_override is not None else subject,
            audience=self._audience_override if self._audience_override is not None else audience,
            measurement=self._measurement,
            expires_at=int(time.time()) + self._expires_in,
            nonce=self._nonce_override if self._nonce_override is not None else challenge,
        )


class SearchThenMigrateProvider(ModelProvider):
    # Section 4 #6 fixture. Run catalog.search (its result carries a `score` field the
    # grant's ("id", "title") output_projection deliberately WITHHOLDS), THEN migrate,
    # then complete at the destination. Exercises payload confidentiality on migration:
    # the withheld field must not cross to the destination inside the sealed envelope.
    def __init__(self, destination):
        self.destination = destination
    def decide(self, state, available_tools, grants=()):
        # The canonical view drops raw memory (finding #2) but exposes `migrated`: True once
        # this task resumed at the destination. Same three phases as before -- search, migrate,
        # then complete on resume -- keyed on `migrated` instead of memory["migration"].
        if state.migrated:
            return ProviderDecision("complete", content={"resumed_on": self.destination})
        if not state.tool_results.get("catalog.search"):
            return ProviderDecision("tool", "catalog.search", {"query": "widgets", "limit": 2})
        return ProviderDecision("migrate", destination=self.destination)


def _json_contains_key(obj, key):
    # True if `key` appears as a dict key anywhere in a JSON-shaped structure.
    if isinstance(obj, dict):
        return key in obj or any(_json_contains_key(value, key) for value in obj.values())
    if isinstance(obj, list):
        return any(_json_contains_key(item, key) for item in obj)
    return False


class ExplodingProvider(ModelProvider):
    def decide(self, state, available_tools, grants=()):
        raise RuntimeError("provider crashed")


class PaymentProvider(ModelProvider):
    def __init__(self, amount=50):
        self.amount = amount
    def decide(self, state, available_tools, grants=()):
        results = state.tool_results
        if "payments.reserve" not in results:
            return ProviderDecision("tool", "payments.reserve", {"amount": self.amount, "currency": "USD"})
        return ProviderDecision("complete", content={"payment": results["payments.reserve"]})


class ChargeProvider(ModelProvider):
    # Proposes one side-effecting "iso.charge" call, then completes -- so a run makes exactly one
    # tool call (Section 7 PR 2 effect-ledger tests).
    def __init__(self, directory, amount=5, tool="iso.charge"):
        self.directory = directory
        self.amount = amount
        self.tool = tool

    def decide(self, state, available_tools, grants=()):
        results = state.tool_results
        if self.tool not in results:
            return ProviderDecision("tool", self.tool, {"dir": self.directory, "amount": self.amount})
        return ProviderDecision("complete", content={"done": results[self.tool]})


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
        if "large.output" not in state.tool_results:
            return ProviderDecision("tool", "large.output", {})
        return ProviderDecision("complete", content={"large": state.tool_results["large.output"]})


class OversizedResultProvider(ModelProvider):
    # Calls one tool, then completes. The tool's result is legal at invoke time but,
    # once recorded in both memory["tool_results"] and messages, doubles over the
    # checkpoint output budget.
    def decide(self, state, available_tools, grants=()):
        results = state.tool_results
        if "big.echo" not in results:
            return ProviderDecision("tool", "big.echo", {})
        return ProviderDecision("complete", content={"done": True})


class EchoThenCompleteProvider(ModelProvider):
    def decide(self, state, available_tools, grants=()):
        results = state.tool_results
        if "custom.echo" not in results:
            return ProviderDecision("tool", "custom.echo", {"text": "hello"})
        return ProviderDecision("complete", content={"echo": results["custom.echo"]})


class HttpFetchThenCompleteProvider(ModelProvider):
    def __init__(self, arguments):
        self.arguments = arguments

    def decide(self, state, available_tools, grants=()):
        results = state.tool_results
        if "http.fetch" not in results:
            return ProviderDecision("tool", "http.fetch", self.arguments)
        return ProviderDecision("complete", content={"fetch": results["http.fetch"]})


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

    def getheader(self, name, default=None):
        return self.headers.get(name, default)


PUBLIC_TEST_ADDRESS = "93.184.215.14"  # a public address; never contacted (the connection is faked)


class FakeFetchNetwork:
    """The example http.fetch tool's network, faked: DNS answers (a list per lookup, the last one
    repeating), and a pinned connection that records where it was pointed and returns `response`."""

    def __init__(self, *answers, response=None, error=None):
        self.answers = [list(answer) for answer in answers] or [[PUBLIC_TEST_ADDRESS]]
        self.response, self.error = response, error
        self.lookups, self.connections, self.requests = [], [], []

    def _getaddrinfo(self, host, port, *args, **kwargs):
        answer = self.answers[min(len(self.lookups), len(self.answers) - 1)]
        self.lookups.append(host)
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in answer]

    def __enter__(self):
        network = self

        class Connection:
            def __init__(self, ip, port, hostname, timeout, context):
                network.connections.append((ip, port, hostname))

            def request(self, method, target, headers=None):
                network.requests.append((method, target, dict(headers or {})))
                if network.error is not None:
                    raise network.error

            def getresponse(self):
                return network.response

            def close(self):
                pass

        self._patches = [patch("portmark.providers.socket.getaddrinfo", self._getaddrinfo),
                         patch.object(http_fetch, "PinnedHTTPSConnection", Connection)]
        for active in self._patches:
            active.start()
        return self

    def __exit__(self, *exc):
        for active in self._patches:
            active.stop()
        return False


class _LocalProviderHandler(http.server.BaseHTTPRequestHandler):
    # Section 8 PR 1: a real loopback provider for the transport tests -- the only faithful way to
    # exercise redirect refusal, the total deadline (slow-drip), premature EOF, and the bounded read.
    def do_POST(self):
        server = self.server
        length = int(self.headers.get("Content-Length", 0))
        server.last_body = self.rfile.read(length) if length else b""
        server.last_authorization = self.headers.get("Authorization")
        server.behavior(self)

    def log_message(self, *args):  # silence
        pass


class _ThreadingProviderServer(http.server.ThreadingHTTPServer):
    request_queue_size = 128  # accept backlog, for the concurrency test's simultaneous connects
    daemon_threads = True


@contextlib.contextmanager
def local_provider_server(behavior):
    server = _ThreadingProviderServer(("127.0.0.1", 0), _LocalProviderHandler)
    server.behavior = behavior
    server.last_body = None
    server.last_authorization = None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}/run"
    finally:
        server.shutdown()
        server.server_close()


def _respond_json(payload_bytes):
    def behavior(handler):
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(payload_bytes)))
        handler.end_headers()
        handler.wfile.write(payload_bytes)
    return behavior


def _warm_node_binary() -> None:
    """Start the node binary once before any Node-path test runs.

    Observed in CI (postgres-store, the one job that had no setup-node step, which runs node itself):
    the FIRST Node test of the run hit its 2.0 s PRODUCTION deadline (exactly 2.00 s), sometimes the
    second too, while every later Node test in the same run took about 0.03 s. That pattern is a
    one-time start-up cost charged to whichever Node test runs first -- most likely the ~100 MiB
    binary and its libraries being read cold from disk (not reliably reproducible locally). Warming
    here keeps each deadline assertion about the capsule, not about process start-up; no deadline
    or check changes.
    """
    node = shutil.which("node")
    if node:
        subprocess.run(  # nosec B603 - fixed argv (resolved node binary), no shell, no input
            [node, "--version"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=120, check=False,
        )


def _skip_if_declared_no_node_environment():
    """Skip a Node-backed Wasm test ONLY in an environment that declares it has no Node.js.

    CI's `container` job runs the suite inside the shipped image, which has no Node.js (the image does
    not execute Node-backed Wasm capsules), and sets PORTMARK_TEST_ENV_HAS_NO_NODE=1. Everywhere else
    nothing changes: a missing Node still fails the test, so a host job that loses Node cannot turn
    these tests into silent skips.
    """
    if shutil.which("node") is None and os.environ.get("PORTMARK_TEST_ENV_HAS_NO_NODE") == "1":
        raise unittest.SkipTest("declared no-Node environment (the shipped image)")


class NoNodeSkipIsDeclaredOnlyTests(unittest.TestCase):
    @staticmethod
    def _skips():
        # Caught here: a SkipTest escaping would skip THIS test instead of failing it.
        try:
            _skip_if_declared_no_node_environment()
        except unittest.SkipTest:
            return True
        return False

    def test_missing_node_skips_only_when_the_environment_declares_it(self):
        with patch.object(shutil, "which", return_value=None):
            for value in (None, "", "0", "true"):
                env = {k: v for k, v in os.environ.items() if k != "PORTMARK_TEST_ENV_HAS_NO_NODE"}
                if value is not None:
                    env["PORTMARK_TEST_ENV_HAS_NO_NODE"] = value
                with self.subTest(flag=value), patch.dict(os.environ, env, clear=True):
                    self.assertFalse(self._skips())  # no skip: the Node test runs and fails loudly
            with patch.dict(os.environ, {"PORTMARK_TEST_ENV_HAS_NO_NODE": "1"}):
                self.assertTrue(self._skips())
        # With Node present the flag changes nothing: the tests run.
        with patch.object(shutil, "which", return_value="/usr/bin/node"):
            with patch.dict(os.environ, {"PORTMARK_TEST_ENV_HAS_NO_NODE": "1"}):
                self.assertFalse(self._skips())


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        _warm_node_binary()

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

    def test_external_validation_documents_are_reviewable_and_actionable(self):
        root = Path(__file__).parents[1]
        threat_model = (root / "THREAT_MODEL.md").read_text(encoding="utf-8")
        security_policy = (root / "SECURITY.md").read_text(encoding="utf-8")
        validation = (root / "EXTERNAL_VALIDATION.md").read_text(encoding="utf-8")

        for required in (
            "## Executive Summary",
            "## Scope And Assumptions",
            "## System Model",
            "## Assets And Security Objectives",
            "## Attacker Model",
            "## Entry Points And Attack Surfaces",
            "## Top Abuse Paths",
            "## Threat Model Table",
            "## Focus Paths For Security Review",
            "## Residual Risks",
        ):
            with self.subTest(document="threat_model", required=required):
                self.assertIn(required, threat_model)
        for threat_id in ("TM-001", "TM-002", "TM-003", "TM-004", "TM-005", "TM-006", "TM-007", "TM-008"):
            with self.subTest(threat_id=threat_id):
                self.assertIn(threat_id, threat_model)

        for required in ("## Supported Versions", "## Reporting A Vulnerability", "## Handling Timeline", "## Security Scope"):
            with self.subTest(document="security", required=required):
                self.assertIn(required, security_policy)

        for task_id in ("EV-001", "EV-002", "EV-003", "EV-004", "EV-005", "EV-006", "EV-007"):
            with self.subTest(task_id=task_id):
                self.assertIn(task_id, validation)
        self.assertIn("| Task ID | Priority | Finding | Concrete Task | Acceptance Criteria | Related Threats |", validation)
        self.assertNotIn("harden more", validation.lower())
        self.assertNotIn("todo", validation.lower())

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

        # A host whose OWN audit-signing key is expired or revoked must not even START:
        # make_host now fails closed at boot (finding #2) rather than admitting work whose
        # audit head would be invalid from birth. This is strictly stronger than the former
        # request-time rejection -- the key never gets a chance to sign.
        now = int(time.time())
        expired_registry = TrustRegistry((
            TrustedIdentity("expired-key", "host:local-demo", signer.public_key_bytes(), ("host:local-demo",), expires_at=now - 1),
        ))
        expired_signer = EnvelopeSigner.from_private_key_bytes(
            "expired-key", "host:local-demo", signer.private_key_bytes(), ("host:local-demo",), expired_registry
        )
        with self.assertRaisesRegex(ValueError, "cannot sign audit heads .expired"):
            make_host(signer=expired_signer)

        revoked_registry = TrustRegistry((
            TrustedIdentity("revoked-key", "host:local-demo", signer.public_key_bytes(), ("host:local-demo",), revoked=True),
        ))
        revoked_signer = EnvelopeSigner.from_private_key_bytes(
            "revoked-key", "host:local-demo", signer.private_key_bytes(), ("host:local-demo",), revoked_registry
        )
        with self.assertRaisesRegex(ValueError, "cannot sign audit heads .revoked"):
            make_host(signer=revoked_signer)

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

    def test_attestation_empty_nonce_is_rejected_when_binding_expected(self):
        authority = AttestationAuthority.generate()
        policy = AttestationPolicy(
            (authority.trusted_authority(),),
            ("measurement:approved",),
            required_for_execution=True,
            require_execution_nonce=True,
        )
        host = make_host(attestation_policy=policy)
        now = int(time.time())
        # Valid in every dimension EXCEPT the nonce, which is empty while the
        # permit nonce is not. With require_execution_nonce set, an empty nonce
        # must not silently skip the binding.
        evidence = authority.issue(host.host_id, "host:local-demo", "measurement:approved", now + 60)
        envelope = make_demo_envelope(host, "empty attestation nonce")
        object.__setattr__(envelope.permit, "attestation", evidence)
        host.signer.seal(envelope)
        with self.assertRaisesRegex(SecurityError, "nonce"):
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

    def test_http_provider_decodes_a_valid_response(self):
        # Transport is mocked at _post; this exercises payload build + decision decode.
        provider = GenericHttpProvider("https://provider.example/run", max_response_bytes=64)
        with patch.object(provider, "_post", return_value=b'{"kind":"complete","content":{"ok":true}}'):
            decision = provider.decide(provider_view(AgentState("task", "goal")), ())
        self.assertEqual(decision.kind, "complete")
        self.assertEqual(decision.content, {"ok": True})

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
        provider = GenericHttpProvider("https://provider.example/run", timeout=7)
        captured = {}

        def fake_post(body):
            captured["body"] = json.loads(body)
            return b'{"kind":"complete","content":{"ok":true}}'

        with patch.object(provider, "_post", side_effect=fake_post):
            decision = provider.decide(provider_view(state, (ToolGrant("catalog.search"),)), ("catalog.search",))

        self.assertEqual(decision.kind, "complete")
        self.assertEqual(captured["body"], {
            "state": {
                "task_id": "task-1",
                "goal": "sensitive goal",
                "step": 2,
                "tool_calls": 1,
                "status": "running",
                "migrated": False,
                "messages": [{"role": "tool", "name": "catalog.search"}],
                "tool_results": {},
            },
            "available_tools": ["catalog.search"],
        })
        # The wire is a faithful serialization of the ProviderView (cross-adapter consistency)
        # and must be json-serializable end to end (no MappingProxyType leaks).
        json.dumps(captured["body"])
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
        provider = GenericHttpProvider("https://provider.example/run")
        captured = {}

        def fake_post(body):
            captured["body"] = json.loads(body)
            return b'{"kind":"complete","content":{"ok":true}}'

        with patch.object(provider, "_post", side_effect=fake_post):
            provider.decide(provider_view(state, (ToolGrant("catalog.search", output_projection=("id", "title")),)), ("catalog.search",))

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
            (ToolGrant("catalog.search", {"max_limit": 3, "arguments": {"query": {"type": "string"}}}, ("*",)),),
            ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=32_768),
        )
        envelope = make_demo_envelope(host, "portable agents", "http")
        bodies = []
        responses = [
            b'{"kind":"tool","tool":"catalog.search","arguments":{"query":"portable agents","limit":3}}',
            b'{"kind":"complete","content":{"ok":true}}',
        ]

        def fake_post(body):
            bodies.append(json.loads(body))
            return responses.pop(0)

        with patch.object(host.providers["http"], "_post", side_effect=fake_post):
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
            (b"{", "malformed or unsafe JSON"),
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
                provider = GenericHttpProvider("https://provider.example/run")
                with patch.object(provider, "_post", return_value=body):
                    with self.assertRaisesRegex(SecurityError, message):
                        provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))

    def test_host_restricts_permit_more_than_agent_requests(self):
        host = make_host()
        host.providers["evil"] = FixedProvider(ProviderDecision("tool", "catalog.search", {"query": "x", "limit": 4}))
        envelope = make_demo_envelope(host, "search", "evil")
        with self.assertRaisesRegex(SecurityError, "maximum"):
            host.run(envelope)

    def test_side_effecting_tool_is_refused_on_the_thread_timeout_path(self):
        # Finding #3: a side-effecting tool must not run on the thread+timeout
        # path, which cannot cancel it -- a deadline there records failure while
        # the side effect may still land. It fails closed until an isolated
        # hard-kill executor exists.
        from portmark.security import SecurityError

        ran = []
        registry = ToolRegistry()
        # Section 7 PR 2b: a side-effecting tool on the thread path now fails closed AT REGISTRATION,
        # not (as before) only at the first invoke. register() cannot carry an effect ledger and cannot
        # cancel a running tool, so it refuses side_effecting outright -- a stronger guarantee than the
        # old invoke-time refusal, and it never lets the name into _side_effecting without a contract.
        with self.assertRaisesRegex(SecurityError, "side-effecting"):
            registry.register(
                "payments.charge", lambda arguments: ran.append(True) or {"ok": True}, side_effecting=True
            )
        self.assertNotIn("payments.charge", registry.names())  # refused registration left no trace
        # A tool not marked side-effecting still registers and runs on the normal path.
        registry.register("catalog.search", lambda arguments: {"ok": True})
        permit = Permit(
            issuer="issuer",
            subject="agent",
            audience="host",
            expires_at=int(time.time()) + 60,
            nonce="nonce-se",
            grants=(ToolGrant("catalog.search"),),
        )
        self.assertEqual(registry.invoke(permit, "catalog.search", {}), {"ok": True})
        self.assertEqual(ran, [])  # the refused side-effecting tool never executed

    def test_thread_path_caps_inflight_executions_and_fails_closed(self):
        # Finding #5: a thread-path tool that exceeds its deadline leaks a daemon thread
        # (the queue-timeout path cannot cancel it). A bounded semaphore caps how many can
        # be in flight; a leaked thread holds its slot until it actually finishes, so once
        # the cap fills with leaked threads a new invocation fails closed instead of
        # spawning another unbounded leak.
        from portmark.tools import ToolExecutionError

        release = threading.Event()
        registry = ToolRegistry(max_inflight_threaded=2)
        registry.register("hang", lambda arguments: release.wait(10) or {"ok": True}, timeout=0.05)
        permit = Permit(
            issuer="issuer",
            subject="agent",
            audience="host",
            expires_at=int(time.time()) + 60,
            nonce="nonce-cap",
            grants=(ToolGrant("hang"),),
        )
        try:
            # Two timed-out invocations leak their still-running threads; each holds a slot.
            for _ in range(2):
                with self.assertRaisesRegex(ToolExecutionError, "deadline"):
                    registry.invoke(permit, "hang", {})
            # Both slots held by the leaked threads -> the next invocation fails closed.
            with self.assertRaisesRegex(ToolExecutionError, "in-flight"):
                registry.invoke(permit, "hang", {})
        finally:
            release.set()  # let the leaked threads finish and release their slots

    def _isolated_env(self):
        # The worker runs in a fresh process, so it must be able to import both
        # portmark (from src) and the fixture module (from tests). Absolute paths
        # so the worker's cwd does not matter.
        import portmark

        src_dir = os.path.dirname(os.path.dirname(os.path.abspath(portmark.__file__)))
        tests_dir = os.path.dirname(os.path.abspath(__file__))
        return {"PYTHONPATH": os.pathsep.join([src_dir, tests_dir])}

    def _isolated_permit(self, *names):
        return Permit(
            issuer="issuer",
            subject="agent",
            audience="host",
            expires_at=int(time.time()) + 60,
            nonce="nonce-iso",
            grants=tuple(ToolGrant(name) for name in names),
        )

    def test_isolated_tool_runs_in_a_subprocess_and_ignores_stdout_noise(self):
        # EV-002: a tool registered isolated runs in a hard-killable worker. Its
        # stdout noise (including a forged JSON line) must not corrupt the
        # protocol -- the real result still comes back.
        registry = ToolRegistry()
        registry.register_isolated("iso.echo", "isolated_tool_fixtures:echo", env=self._isolated_env())
        registry.register_isolated("iso.noisy", "isolated_tool_fixtures:noisy", env=self._isolated_env())
        permit = self._isolated_permit("iso.echo", "iso.noisy")
        self.assertEqual(registry.invoke(permit, "iso.echo", {"text": "hi"}), {"echo": {"text": "hi"}})
        self.assertEqual(registry.invoke(permit, "iso.noisy", {"n": 1}), {"echo": {"n": 1}})

    def test_isolated_tool_does_not_inherit_host_secrets(self):
        # The minimal-env property: a secret in the host process must not reach
        # the worker, because it is not on the inherited allowlist.
        registry = ToolRegistry()
        registry.register_isolated("iso.env", "isolated_tool_fixtures:read_env", env=self._isolated_env())
        permit = self._isolated_permit("iso.env")
        key = "PORTMARK_TEST_SECRET_" + secrets.token_hex(4)
        os.environ[key] = "leaked-value"
        try:
            result = registry.invoke(permit, "iso.env", {"key": key})
        finally:
            os.environ.pop(key, None)
        self.assertEqual(result, {"value": None})

    def test_isolated_worker_discards_flooded_stdout_without_corrupting_response(self):
        # Section 7 #6: a tool that prints ~20 MiB via Python stdout must not buffer it in memory
        # (io.StringIO grew unbounded before) and must not corrupt the JSON protocol. The tiny
        # real result still round-trips intact.
        registry = ToolRegistry()
        registry.register_isolated("iso.flood", "isolated_tool_fixtures:flood_stdout_then_return", env=self._isolated_env())
        permit = self._isolated_permit("iso.flood")
        self.assertEqual(registry.invoke(permit, "iso.flood", {"lines": 20_000}), {"ok": True})

    @unittest.skipUnless(_CAN_KILL_PROCESS_GROUP, "RLIMIT_FSIZE is POSIX-only")
    def test_isolated_worker_applies_file_size_rlimit(self):
        # Section 7 #6, CALIBRATED: the worker applies the resource caps it is handed. Under a tiny
        # RLIMIT_FSIZE a large write is refused by the kernel (the tool fails); with the caps
        # disabled the same write succeeds -- proving the failure is the cap, not the tool.
        from portmark.tools import ToolExecutionError

        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "big.bin")
            big = 8 * 1024 * 1024  # 8 MiB, far over the 4 KiB cap below

            capped = ToolRegistry(resource_limits={"file_size": 4096})
            capped.register_isolated("iso.write", "isolated_tool_fixtures:write_file", env=self._isolated_env())
            permit = self._isolated_permit("iso.write")
            # The write raises inside the tool (OSError/EFBIG) because the kernel refuses it under
            # RLIMIT_FSIZE -- confirming the rlimit mechanism, not a kill-confirmation timeout path.
            with self.assertRaisesRegex(ToolExecutionError, "tool raised OSError"):
                capped.invoke(permit, "iso.write", {"path": target, "size": big})

            # CALIBRATION: caps disabled -> the identical write succeeds.
            uncapped = ToolRegistry(disable_resource_limits=True)
            uncapped.register_isolated("iso.write", "isolated_tool_fixtures:write_file", env=self._isolated_env())
            self.assertEqual(
                uncapped.invoke(permit, "iso.write", {"path": target, "size": big}),
                {"written": big},
            )

    def test_process_tree_termination_honesty(self):
        # Section 7 #1: the executor no longer CLAIMS whole-tree termination on POSIX. POSIX killpg
        # is cooperative (a setsid child escapes) -> False; the Windows Job Object genuinely
        # contains the tree -> True. This flag is the honest counterpart to the prose contract.
        # Class-attribute reads: this asserts the DECLARED contract on each backend, not observed
        # Windows behavior (the Job Object class is never constructed on this Linux CI).
        import portmark.tools as tools_module
        self.assertFalse(tools_module._PosixProcessTree.terminates_whole_tree)
        self.assertFalse(tools_module._UnmanagedProcessTree.terminates_whole_tree)
        self.assertTrue(tools_module._WindowsJobProcessTree.terminates_whole_tree)

    def test_module_scope_stdout_flood_is_discarded_before_import(self):
        # Section 7 #1, CALIBRATED: a hostile tool's harmful behavior can run at MODULE SCOPE
        # (Python executes top-level code during import), not only in the tool function. Here the
        # module prints ~20 MiB the moment the worker imports it. The worker must redirect stdout
        # to a discard sink BEFORE importing the tool; the tiny real result still round-trips.
        # CALIBRATION: with the redirect applied only AROUND the function call (the old order),
        # the module-scope flood lands in the protocol stream and overflows -> invoke() raises.
        registry = ToolRegistry()
        registry.register_isolated(
            "iso.mod_flood", "isolated_tool_module_scope_flood:run", env=self._isolated_env()
        )
        permit = self._isolated_permit("iso.mod_flood")
        self.assertEqual(
            registry.invoke(permit, "iso.mod_flood", {}),
            {"ok": True, "scope": "module-flood"},
        )

    @unittest.skipUnless(_CAN_KILL_PROCESS_GROUP, "RLIMIT_FSIZE is POSIX-only")
    def test_module_scope_filesystem_write_is_capped_before_import(self):
        # Section 7 #1, CALIBRATED: the resource caps must apply BEFORE the untrusted module is
        # imported, so module-scope code cannot act uncapped. This fixture writes a large file at
        # import time. Under a tiny RLIMIT_FSIZE the kernel refuses the write and the worker
        # reports a CONTROLLED failure ("tool import raised OSError") -- not a crashed, response-
        # less worker (the EV-010 class) and not a write that already succeeded.
        # CALIBRATION: caps applied AFTER import (the old order) -> the write lands and the tool
        # returns {"ok": True, ...} instead of failing.
        from portmark.tools import ToolExecutionError

        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "module-scope.bin")
            big = 8 * 1024 * 1024  # 8 MiB, far over the 4 KiB cap
            registry = ToolRegistry(resource_limits={"file_size": 4096})
            registry.register_isolated(
                "iso.mod_write",
                "isolated_tool_module_scope_write:run",
                env={
                    **self._isolated_env(),
                    "PORTMARK_TEST_MODULE_WRITE_PATH": target,
                    "PORTMARK_TEST_MODULE_WRITE_SIZE": str(big),
                },
            )
            permit = self._isolated_permit("iso.mod_write")
            with self.assertRaisesRegex(ToolExecutionError, "tool import raised OSError"):
                registry.invoke(permit, "iso.mod_write", {})

    def test_resource_limits_unknown_key_fails_startup(self):
        # Section 7 #3: a typo like "adress_space" must fail LOUDLY at construction, not silently
        # disable the cap the operator meant to set.
        with self.assertRaisesRegex(ValueError, "unknown resource_limits key"):
            ToolRegistry(resource_limits={"adress_space": 1024})

    def test_resource_limits_non_positive_or_bool_fails_startup(self):
        # Section 7 #3: zero, negative, and bool are all rejected (zero open_files is as bad as
        # negative; bool is an int subclass and would sneak through a naive isinstance check).
        for bad in (0, -1, True, 1.5, "4096"):
            with self.assertRaisesRegex(ValueError, "positive integer"):
                ToolRegistry(resource_limits={"file_size": bad})

    def test_resource_limits_cpu_seconds_is_not_an_operator_key(self):
        # Section 7 #3: cpu_seconds is derived per invocation from each tool's timeout (a deadline
        # backstop); letting an operator pin it could make it fire before the host's own deadline.
        with self.assertRaisesRegex(ValueError, "unknown resource_limits key 'cpu_seconds'"):
            ToolRegistry(resource_limits={"cpu_seconds": 5})

    def test_resource_limits_merge_keeps_other_defaults(self):
        # Section 7 #3: supplying one key MERGES over the defaults -- it must not silently drop the
        # memory / fd caps (the old replace-everything behavior).
        registry = ToolRegistry(resource_limits={"file_size": 4096})
        self.assertEqual(registry.resource_limits["file_size"], 4096)
        self.assertEqual(registry.resource_limits["address_space"], 1024 * 1024 * 1024)
        self.assertEqual(registry.resource_limits["open_files"], 512)
        # RLIMIT_NPROC stays opt-in through the validated path: absent by default, settable under a
        # dedicated uid, and merged in without dropping the other defaults.
        self.assertNotIn("processes", ToolRegistry().resource_limits)
        opted_in = ToolRegistry(resource_limits={"processes": 128})
        self.assertEqual(opted_in.resource_limits["processes"], 128)
        self.assertEqual(opted_in.resource_limits["address_space"], 1024 * 1024 * 1024)

    def test_isolated_worker_error_messages_survive_the_stdout_redirect(self):
        # Section 7 #1: the import/resolve error paths now return through a tuple and are reported
        # AFTER the redirect block -- prove the actual message text still reaches the parent (writing
        # it inside the redirect would send it to the discard sink and surface as "invalid output").
        from portmark.tools import ToolExecutionError

        registry = ToolRegistry()
        registry.register_isolated(
            "iso.badmod", "portmark_no_such_module_xyz:run", env=self._isolated_env()
        )
        registry.register_isolated(
            "iso.notcallable", "isolated_tool_fixtures:__doc__", env=self._isolated_env()
        )
        permit = self._isolated_permit("iso.badmod", "iso.notcallable")
        with self.assertRaisesRegex(ToolExecutionError, "could not import tool target"):
            registry.invoke(permit, "iso.badmod", {})
        with self.assertRaisesRegex(ToolExecutionError, "tool target is not callable"):
            registry.invoke(permit, "iso.notcallable", {})

    def test_disable_resource_limits_empties_the_caps(self):
        # Section 7 #3: the explicit off switch, replacing the overloaded empty dict.
        registry = ToolRegistry(disable_resource_limits=True)
        self.assertEqual(registry.resource_limits, {})
        # And {} now MEANS defaults, not disabled -- an empty dict can no longer silently disable.
        self.assertEqual(ToolRegistry(resource_limits={}).resource_limits["address_space"], 1024 * 1024 * 1024)

    def test_disable_and_resource_limits_together_fails(self):
        with self.assertRaisesRegex(ValueError, "either resource_limits or disable_resource_limits"):
            ToolRegistry(resource_limits={"file_size": 4096}, disable_resource_limits=True)

    @unittest.skipUnless(_CAN_KILL_PROCESS_GROUP, "setrlimit fail-closed is POSIX-only")
    def test_apply_resource_limits_reports_unappliable_without_mutating(self):
        # Fail-open fix: the worker's cap application REPORTS what it could not put in force instead
        # of silently skipping. Only the non-setrlimit paths are exercised here so the test process's
        # own limits are never mutated: no requested caps -> nothing unapplied; an unknown key or a
        # non-int value -> reported unapplied (both hit the filter before any setrlimit call).
        from portmark.tool_subprocess_runner import _apply_resource_limits

        # Empty/absent rlimits -> []: this is a DEFENSIVE branch, not a reachable config -- the host
        # always fills cpu_seconds in _invoke_isolated, so a real worker request is never empty.
        self.assertEqual(_apply_resource_limits({}), [])
        self.assertEqual(_apply_resource_limits(None), [])
        self.assertEqual(_apply_resource_limits({"bogus_cap": 1}), ["bogus_cap"])
        self.assertEqual(_apply_resource_limits({"file_size": "not-an-int"}), ["file_size"])
        self.assertEqual(
            sorted(_apply_resource_limits({"bogus_cap": 1, "also_bogus": 2})),
            ["also_bogus", "bogus_cap"],
        )

    @unittest.skipUnless(_CAN_KILL_PROCESS_GROUP, "setrlimit fail-closed is POSIX-only")
    def test_worker_fails_closed_when_a_requested_cap_cannot_apply(self):
        # Fail-open fix, CALIBRATED: if a requested cap cannot be put in force, the worker must
        # REFUSE to run the tool (and name the cap), never run it under weaker caps than configured.
        # Driven at the worker's JSON protocol directly (a bogus cap key cannot pass ToolRegistry's
        # validation, so this is the honest way to exercise the worker's own fail-closed path).
        # NOTE: this launches the worker WITHOUT start_new_session, so it shares this test's process
        # group -- the exit-time group sweep therefore correctly no-ops (its getpgrp==getpid guard),
        # and this test covers the fail-closed REPLY, not the sweep (that is test_normal_exit_sweeps_*).
        # CALIBRATION: with the old silent-skip, the bogus key is ignored, the valid file_size cap
        # applies, and echo runs -> {"ok": true, ...} instead of the refusal asserted here.
        import subprocess  # nosec B404

        env = dict(os.environ)
        env["PYTHONPATH"] = self._isolated_env()["PYTHONPATH"]
        request = json.dumps(
            {
                "target": "isolated_tool_fixtures:echo",
                "arguments": {"x": 1},
                "max_output_bytes": 65_536,
                "rlimits": {"file_size": 4096, "bogus_cap": 1},
            }
        )
        completed = subprocess.run(  # nosec B603
            [sys.executable, "-m", "portmark.tool_subprocess_runner"],
            input=request.encode("utf-8"),
            capture_output=True,
            env=env,
            timeout=30,
        )
        response = json.loads(completed.stdout.decode("utf-8"))
        self.assertFalse(response["ok"])
        self.assertIn("worker could not apply resource limits", response["error"])
        self.assertIn("bogus_cap", response["error"])

    def test_isolated_tool_timeout_hard_kills_and_fails_closed(self):
        from portmark.tools import ToolKilledError

        registry = ToolRegistry()
        registry.register_isolated(
            "iso.slow", "isolated_tool_fixtures:slow_then_return", timeout=1.0, env=self._isolated_env()
        )
        permit = self._isolated_permit("iso.slow")
        with self.assertRaises(ToolKilledError):
            registry.invoke(permit, "iso.slow", {"seconds": 30})

    @unittest.skipUnless(_has_tree_termination_primitive(), "requires a process-tree hard-kill primitive")
    def test_isolated_tool_kill_reaches_grandchildren(self):
        # The kill must reach the whole process group, not just the worker: a
        # grandchild the tool spawned would otherwise survive and write a marker.
        # Skipped where the platform has no process groups (Windows) -- there the
        # guarantee does not hold, and register_isolated refuses side-effecting
        # tools for exactly that reason (tested separately, unskipped).
        from portmark.tools import ToolKilledError

        registry = ToolRegistry()
        registry.register_isolated(
            "iso.spawn", "isolated_tool_fixtures:spawn_grandchild_then_sleep", timeout=1.0, env=self._isolated_env()
        )
        permit = self._isolated_permit("iso.spawn")
        with tempfile.TemporaryDirectory() as directory:
            marker = os.path.join(directory, "grandchild-alive")
            with self.assertRaises(ToolKilledError):
                registry.invoke(permit, "iso.spawn", {"marker": marker, "delay": 5.0})
            # Wait past the grandchild's +5.0s "alive" write. The "started" marker
            # proves the grandchild really ran; "alive" being absent proves the
            # process-group kill reached it before the delay elapsed -- so the
            # test cannot pass merely because the grandchild never spawned.
            time.sleep(6.0)
            self.assertTrue(os.path.exists(marker + ".started"))
            self.assertFalse(os.path.exists(marker))

    @unittest.skipUnless(_CAN_KILL_PROCESS_GROUP, "process-group sweep is POSIX-only")
    def test_normal_exit_sweeps_background_child(self):
        # PR 1b, CALIBRATED: a tool that spawns a background child and then RETURNS NORMALLY used to
        # leave that child running (the worker exited cleanly, the parent's already-exited kill path
        # early-returned). The worker now SIGKILLs its own process group before exiting, so the child
        # dies too. Returns normally (no ToolKilledError). "started" proves the child ran; "alive"
        # absent proves the sweep reached it.
        # CALIBRATION: remove the _sweep_own_process_group() call -> the child survives its delay and
        # writes "alive". (Proven by neutralizing the runner: see the gate ledger.)
        registry = ToolRegistry()
        registry.register_isolated(
            "iso.bgspawn", "isolated_tool_fixtures:spawn_bg_child_then_return_normally", env=self._isolated_env()
        )
        permit = self._isolated_permit("iso.bgspawn")
        with tempfile.TemporaryDirectory() as directory:
            marker = os.path.join(directory, "bgchild-alive")
            self.assertEqual(
                registry.invoke(permit, "iso.bgspawn", {"marker": marker, "delay": 3.0}),
                {"spawned": True},
            )
            time.sleep(4.5)  # past the child's +3.0s "alive" write
            self.assertTrue(os.path.exists(marker + ".started"))
            self.assertFalse(os.path.exists(marker))

    @unittest.skipUnless(_CAN_KILL_PROCESS_GROUP, "process-group sweep is POSIX-only")
    def test_new_group_child_escapes_normal_exit_sweep_documented_residual(self):
        # PR 1b: pin the DOCUMENTED escape residuals. A child that moves to its OWN process group --
        # via setsid() (new session) OR setpgid(0,0) (new group, same session) -- is no longer in the
        # worker's group, so the killpg(0) sweep cannot reach it: "alive" DOES appear. This matches
        # the residual list one-to-one and fails loudly if a future change claims whole-tree kill.
        registry = ToolRegistry()
        registry.register_isolated(
            "iso.bgescape", "isolated_tool_fixtures:spawn_bg_child_then_return_normally", env=self._isolated_env()
        )
        permit = self._isolated_permit("iso.bgescape")
        for escape in ("setsid", "setpgid"):
            with self.subTest(escape=escape), tempfile.TemporaryDirectory() as directory:
                marker = os.path.join(directory, f"{escape}-alive")
                self.assertEqual(
                    registry.invoke(permit, "iso.bgescape", {"marker": marker, "delay": 2.0, "escape": escape}),
                    {"spawned": True},
                )
                time.sleep(3.5)  # past the child's +2.0s "alive" write
                self.assertTrue(os.path.exists(marker + ".started"))
                self.assertTrue(os.path.exists(marker))  # escaped the sweep -- documented residual
                # ...and escaped BECAUSE it left the worker's group: it is now its own group leader.
                with open(marker, encoding="utf-8") as handle:
                    self.assertEqual(handle.read(), "True")

    @unittest.skipUnless(_CAN_KILL_PROCESS_GROUP, "references signal.SIGKILL (absent on Windows)")
    def test_self_sweep_confirmed_decision_logic(self):
        # PR 1b (parent verification): the decision that gates accepting a reply. This unit test is
        # near-tautological ON ITS OWN -- the REAL coverage is that EVERY isolated-success test now
        # traverses this gate in _invoke_isolated, so an inverted check turns the whole isolated
        # suite red. Kept explicit so a "tidy-up" to a truthy check (which would read a clean 0 as
        # confirmed) fails here. See the gate ledger for the neutralize-the-sweep integration proof.
        import signal as _signal

        from portmark.tools import _self_sweep_confirmed

        class _FakeTree:
            def __init__(self, expects, rc):
                self.expects_self_sweep = expects
                self.returncode = rc

        self.assertTrue(_self_sweep_confirmed(_FakeTree(True, -_signal.SIGKILL)))  # swept
        self.assertFalse(_self_sweep_confirmed(_FakeTree(True, 0)))                # clean exit, no sweep
        self.assertFalse(_self_sweep_confirmed(_FakeTree(True, None)))             # never reaped
        self.assertFalse(_self_sweep_confirmed(_FakeTree(True, -_signal.SIGTERM)))  # wrong signal
        self.assertTrue(_self_sweep_confirmed(_FakeTree(False, 0)))                # non-self-sweep backend: not gated

    @unittest.skipUnless(_has_tree_termination_primitive(), "requires a process-tree hard-kill primitive")
    def test_isolated_tool_kill_not_confirmed_fails_closed(self):
        # Fail-closed: if the deadline fires but the tree cannot be CONFIRMED dead --
        # the kill fails to issue, or the process outlives the post-kill wait -- the host
        # must not report a clean ToolKilledError, because that would overstate
        # containment. Simulate an ineffective kill by patching the active ProcessTree's
        # terminate_tree to a no-op, so the (still-sleeping) worker survives the wait.
        from portmark.tools import ToolExecutionError
        import portmark.tools as tools_module

        if _CAN_KILL_PROCESS_GROUP:
            tree_cls = tools_module._PosixProcessTree
        elif tools_module._windows_job.available():
            tree_cls = tools_module._WindowsJobProcessTree
        else:  # pragma: no cover - covered by the skip guard
            self.skipTest("no tree-kill primitive")

        registry = ToolRegistry()
        registry.register_isolated(
            "iso.slow", "isolated_tool_fixtures:slow_then_return", timeout=0.5, env=self._isolated_env()
        )
        permit = self._isolated_permit("iso.slow")
        with patch.object(tree_cls, "terminate_tree", lambda self: None):
            with self.assertRaisesRegex(ToolExecutionError, "could not be confirmed terminated"):
                registry.invoke(permit, "iso.slow", {"seconds": 3.0})

    def test_process_tree_close_reaps_worker_and_closes_pipes(self):
        # close() is the resource-release contract the launch-failure and timeout
        # cleanup paths rely on: it must kill a still-running worker, REAP it (collect
        # exit status -- an un-waited Popen warns "subprocess ... is still running" and
        # leaves a zombie), close both pipes, and be idempotent. Cross-platform.
        import portmark.tools as tools_module

        tree = tools_module._launch_process_tree(
            [sys.executable, "-c", "import sys; sys.stdin.read()"],
            dict(os.environ),
        )
        process = tree._process
        self.assertIsNone(process.poll())  # worker is alive, blocked on stdin
        tree.close()
        self.assertIsNotNone(process.poll())  # reaped, not leaked
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        tree.close()  # idempotent: a second close must not raise

    @unittest.skipUnless(sys.platform == "win32", "Windows Job Object launch path")
    def test_windows_launch_fails_closed_when_resume_fails(self):
        # A ResumeThread failure (0 threads resumed) must fail the launch closed, never
        # run the worker unmanaged. Finding: unchecked ResumeThread return. The failed
        # launch must also reap the suspended worker and close its pipes -- no leak.
        from portmark.tools import ToolExecutionError
        import portmark.tools as tools_module

        created = []
        real_popen = tools_module.subprocess.Popen

        def capture(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            created.append(proc)
            return proc

        registry = ToolRegistry()
        registry.register_isolated("iso.echo", "isolated_tool_fixtures:echo", env=self._isolated_env())
        permit = self._isolated_permit("iso.echo")
        with patch("portmark.tools.subprocess.Popen", side_effect=capture), patch(
            "portmark.tools._windows_job.resume_process_main_thread", return_value=0
        ):
            with self.assertRaisesRegex(ToolExecutionError, "could not start isolated tool worker"):
                registry.invoke(permit, "iso.echo", {})
        self.assertEqual(len(created), 1)
        worker = created[0]
        self.assertIsNotNone(worker.poll())  # reaped, not leaked
        self.assertTrue(worker.stdin.closed)
        self.assertTrue(worker.stdout.closed)

    @unittest.skipUnless(sys.platform == "win32", "Windows Job Object launch path")
    def test_windows_launch_fails_closed_when_assignment_fails(self):
        # An AssignProcessToJobObject failure must reap the suspended worker and fail
        # closed -- never fall back to an unmanaged (un-killable) process -- and must
        # leave no leaked Popen or open pipe behind.
        from portmark.tools import ToolExecutionError
        import portmark.tools as tools_module

        created = []
        real_popen = tools_module.subprocess.Popen

        def capture(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            created.append(proc)
            return proc

        registry = ToolRegistry()
        registry.register_isolated("iso.echo", "isolated_tool_fixtures:echo", env=self._isolated_env())
        permit = self._isolated_permit("iso.echo")
        with patch("portmark.tools.subprocess.Popen", side_effect=capture), patch(
            "portmark.tools._windows_job.assign_process", side_effect=OSError("assign failed")
        ):
            with self.assertRaisesRegex(ToolExecutionError, "could not start isolated tool worker"):
                registry.invoke(permit, "iso.echo", {})
        self.assertEqual(len(created), 1)
        worker = created[0]
        self.assertIsNotNone(worker.poll())  # reaped, not leaked
        self.assertTrue(worker.stdin.closed)
        self.assertTrue(worker.stdout.closed)

    def test_isolated_tool_exception_fails_closed(self):
        from portmark.tools import ToolExecutionError

        registry = ToolRegistry()
        registry.register_isolated("iso.boom", "isolated_tool_fixtures:boom", env=self._isolated_env())
        permit = self._isolated_permit("iso.boom")
        with self.assertRaisesRegex(ToolExecutionError, "isolated tool failed"):
            registry.invoke(permit, "iso.boom", {})

    def test_isolated_tool_oversized_output_fails_closed(self):
        from portmark.tools import ToolExecutionError

        registry = ToolRegistry(max_output_bytes=64)
        registry.register_isolated("iso.big", "isolated_tool_fixtures:oversized", env=self._isolated_env())
        permit = self._isolated_permit("iso.big")
        with self.assertRaisesRegex(ToolExecutionError, "output budget"):
            registry.invoke(permit, "iso.big", {"size": 100_000})

    @unittest.skipUnless(_has_tree_termination_primitive(), "requires a process-tree hard-kill primitive")
    def test_side_effecting_tool_runs_when_registered_isolated(self):
        # The thread path refuses side-effecting tools; the isolated path is the
        # sanctioned way to run one, because the host can hard-kill it. Skipped
        # where the platform cannot hard-kill (Windows): register_isolated refuses
        # a side-effecting tool there, which the sibling fail-closed test asserts.
        registry = ToolRegistry(isolation_profile=_TEST_ISOLATION_PROFILE)
        registry.register_isolated(
            "iso.pay", "isolated_tool_fixtures:echo", side_effecting=True,
            reconcile="isolated_tool_fixtures:reconcile_charge", env=self._isolated_env(),
        )
        registry.register_isolated(
            "iso.other", "isolated_tool_fixtures:echo", side_effecting=True,
            reconcile="isolated_tool_fixtures:reconcile_charge", env=self._isolated_env(),
        )
        permit = self._isolated_permit("iso.pay", "iso.other")
        # Section 7 PR 2 (round 3): launching a side-effecting tool requires a ONE-USE launch capability
        # the host armed and bound to (effect_id, tool, canonical args). Knowledge of a (deterministic,
        # non-secret) effect_id is NOT launch authority -- the auditor's round-3 P1s. There is no public
        # rebindable predicate any more.
        from portmark.tools import ToolExecutionError
        # Arming is NOT a public registry method any more (round-3-r1 hole: a public mint let a caller
        # forge capabilities). It is only reachable via the handle attach_effect_ledger returns.
        self.assertFalse(hasattr(registry, "bind_effect_ledger"))   # the rebindable-predicate hole is gone
        self.assertFalse(hasattr(registry, "arm_effect_launch"))    # no public mint
        # Attach a read-only ledger view, exactly as AgentHost does; keep the private armer handle.
        ledger: dict[str, dict] = {}
        armer = registry.attach_effect_ledger(lambda eid: ledger.get(eid))
        self.assertRaises(RuntimeError, registry.attach_effect_ledger, lambda eid: None)  # set-once
        pay_args = {"amount": 10}
        canonical_pay = canonical_json(pay_args).decode("utf-8")
        # (a) No launch capability at all -> refuse.
        with self.assertRaisesRegex(ToolExecutionError, "must run through the effect ledger"):
            registry.invoke(permit, "iso.pay", pay_args)
        # (b) A fabricated effect_id has no `started` row -> cannot even be armed.
        with self.assertRaisesRegex(SecurityError, "no `started` ledger row matches|not launch authority"):
            armer.arm("forged", "iso.pay", pay_args)
        # Record a real started row and arm a capability for it (as the host does pre-launch).
        ledger["e-real"] = {"effect_id": "e-real", "state": "started", "tool": "iso.pay", "arguments_json": canonical_pay}
        cap = armer.arm("e-real", "iso.pay", pay_args)
        # (b2) CALIBRATED: even the armer cannot mint a SECOND outstanding capability for one started
        #      effect (the auditor's repeated-minting bypass). Calibration (gate ledger): drop the
        #      `any(existing[0] == effect_id ...)` refusal in arm -> a second cap is minted and this fails.
        with self.assertRaisesRegex(SecurityError, "already outstanding"):
            armer.arm("e-real", "iso.pay", pay_args)
        # (c) A fabricated capability string never armed -> refuse.
        with self.assertRaisesRegex(SecurityError, "does not authorize"):
            registry.invoke(permit, "iso.pay", pay_args, launch_capability="fabricated-cap")
        # (d) The capability is bound to iso.pay -- using it to launch a DIFFERENT tool -> refuse.
        with self.assertRaisesRegex(SecurityError, "does not authorize"):
            registry.invoke(permit, "iso.other", pay_args, launch_capability=cap)
        # (e) The capability is bound to these arguments -- drifted arguments -> refuse.
        with self.assertRaisesRegex(SecurityError, "does not authorize"):
            registry.invoke(permit, "iso.pay", {"amount": 999}, launch_capability=cap)
        # (f) Exact match -> runs once, and the effect_id reaches the tool.
        self.assertEqual(
            registry.invoke(permit, "iso.pay", pay_args, launch_capability=cap),
            {"echo": {"amount": 10}},
        )
        # (g) CALIBRATED one-use: the SAME capability is consumed, so a replay -> refuse. Calibration
        #     (gate ledger): drop the `del self._armed[launch_capability]` line in invoke -> the reused
        #     capability runs the tool a SECOND time and this assertion fails.
        with self.assertRaisesRegex(SecurityError, "does not authorize"):
            registry.invoke(permit, "iso.pay", pay_args, launch_capability=cap)

    def test_side_effecting_isolated_tool_refused_without_process_group_kill(self):
        # Fail-closed on a platform with no process-tree hard-kill primitive: a
        # side-effecting isolated tool is refused at registration, not silently run
        # without the guarantee. Patch the capability itself (not just the POSIX flag,
        # since Windows now has its own Job Object primitive) so this proves the throw
        # on every CI rather than leaving it unreachable.
        registry = ToolRegistry()
        with patch("portmark.tools._has_tree_termination_primitive", return_value=False):
            with self.assertRaisesRegex(SecurityError, "hard-kill|process tree"):
                registry.register_isolated(
                    "iso.pay", "isolated_tool_fixtures:echo", side_effecting=True, env=self._isolated_env()
                )
            # A non-side-effecting isolated tool is still allowed there -- a leaked
            # grandchild is a resource concern, not an effect-safety one.
            registry.register_isolated("iso.safe", "isolated_tool_fixtures:echo", env=self._isolated_env())
        self.assertIn("iso.safe", registry.names())
        self.assertNotIn("iso.pay", registry.names())

    @unittest.skipUnless(_has_tree_termination_primitive(), "requires a process-tree hard-kill primitive")
    def test_host_audits_isolated_tool_kill_as_effect_status_unknown(self):
        # The honest audit trail: a hard-kill stops new effects but cannot prove
        # an in-flight one did not land, so the host records effect status as
        # unknown -- a distinct signal from a clean tool.failed.
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            tools = ToolRegistry(isolation_profile=_TEST_ISOLATION_PROFILE)
            tools.register_isolated(
                "slow.side",
                "isolated_tool_fixtures:slow_then_return",
                timeout=1.0,
                side_effecting=True,
                reconcile="isolated_tool_fixtures:reconcile_charge",
                env=self._isolated_env(),
            )
            host = make_host(store=store, allow_ephemeral_signing_key=True)
            host.tools = tools
            host._effect_armer = host.tools.attach_effect_ledger(host._effect_ledger_row)  # plain-attribute swap: re-attach + re-arm (round 3)
            # Under B-lite the host policy must name the argument it allows; a bare
            # policy grant now denies unnamed arguments. This test is about the kill
            # audit, not argument policy, so the grant declares `seconds` explicitly.
            host.policy = HostPolicy(host.host_id, (ToolGrant("slow.side", {"arguments": {"seconds": {"type": "number"}}}),), ResourceBudget())
            host.providers["kill"] = FixedProvider(ProviderDecision("tool", "slow.side", {"seconds": 30}))
            envelope = make_demo_envelope(host, "slow side kill", "kill")
            object.__setattr__(envelope.manifest, "requested_tools", ("slow.side",))
            object.__setattr__(envelope.permit, "grants", (ToolGrant("slow.side"),))
            host.signer.seal(envelope)

            result = host.run(envelope)

            self.assertEqual(result.status, "failed")
            self.assertEqual(result.result, {"error": "tool killed at deadline"})
            killed = next(event for event in result.audit if event["event"] == "tool.killed")
            self.assertEqual(killed["details"]["effect_status"], "unknown")
            self.assertEqual(killed["details"]["tool"], "slow.side")
            # Section 7 PR 2b (G11): the effect-unknown audit event records WHAT containment the
            # operator claimed, so an incident responder resolving this unknown effect sees it.
            # Neutralize check: drop the two `if ... claim` lines in host._apply_decision -> this fails.
            self.assertEqual(
                killed["details"]["isolation_profile"],
                {"mechanism": "external_container", "acknowledged_by": "test-suite"},
            )

    # ---- Section 7 PR 2: effect ledger ---------------------------------------------------------

    def _charge_host(self, store, directory, target="idempotent_charge", reconcile="isolated_tool_fixtures:reconcile_charge"):
        tools = ToolRegistry(isolation_profile=_TEST_ISOLATION_PROFILE)
        tools.register_isolated(
            "iso.charge", f"isolated_tool_fixtures:{target}", timeout=5.0, side_effecting=True,
            reconcile=reconcile, env=self._isolated_env(),
        )
        host = make_host(store=store, allow_ephemeral_signing_key=True)
        host.tools = tools
        host._effect_armer = host.tools.attach_effect_ledger(host._effect_ledger_row)  # plain-attribute swap: re-attach + re-arm (round 3)
        host.policy = HostPolicy(
            host.host_id,
            (ToolGrant("iso.charge", {"arguments": {"dir": {"type": "string"}, "amount": {"type": "integer"}}}),),
            ResourceBudget(),
        )
        host.providers["charge"] = ChargeProvider(directory)
        envelope = make_demo_envelope(host, "charge", "charge")
        object.__setattr__(envelope.manifest, "requested_tools", ("iso.charge",))
        object.__setattr__(envelope.permit, "grants", (ToolGrant("iso.charge"),))
        host.signer.seal(envelope)
        return host, envelope

    def _charge_eid(self, envelope, directory):
        return effect_id(envelope.state.task_id, 0)  # first tool call -> sequence 0

    @unittest.skipUnless(_has_tree_termination_primitive(), "isolated side-effecting tools need a process-tree termination primitive")
    def test_side_effecting_effect_is_confirmed_and_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host, envelope = self._charge_host(store, directory)
            result = host.run(envelope)
            self.assertEqual(result.status, "completed")
            row = store.get_effect(self._charge_eid(envelope, directory))
            self.assertEqual(row["state"], "confirmed")
            self.assertEqual(json.loads(row["result_json"])["charged"], 5)
            with open(Path(directory) / "attempts.log", encoding="utf-8") as handle:
                self.assertEqual(len(handle.read().splitlines()), 1)  # ran exactly once

    @unittest.skipUnless(_has_tree_termination_primitive(), "isolated side-effecting tools need a process-tree termination primitive")
    def test_confirmed_effect_replays_without_rerunning(self):
        # CALIBRATED: a prior identical call already CONFIRMED -> the host returns the stored result
        # and does NOT run the tool. Proves the effect_id derivation matches across a resume (same
        # task/tool/args/sequence=0). Calibration (gate ledger): neutralize _effect_pre_launch to
        # always return ("run", None) -> the tool runs and attempts.log appears.
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host, envelope = self._charge_host(store, directory)
            eid = self._charge_eid(envelope, directory)
            store.record_effect_prepared(eid, envelope.state.task_id, "iso.charge",
                                         canonical_json({"dir": directory, "amount": 5}).decode("utf-8"))
            store.mark_effect_started(eid)
            store.settle_effect(eid, "confirmed", canonical_json({"charged": 5, "prior": True}).decode("utf-8"), None)
            result = host.run(envelope)
            self.assertEqual(result.status, "completed")
            self.assertFalse((Path(directory) / "attempts.log").exists())  # tool NEVER ran
            self.assertTrue(any(event["event"] == "tool.replayed" for event in result.audit))

    @unittest.skipUnless(_has_tree_termination_primitive(), "isolated side-effecting tools need a process-tree termination primitive")
    def test_unknown_effect_refuses_rerun(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host, envelope = self._charge_host(store, directory)
            eid = self._charge_eid(envelope, directory)
            store.record_effect_prepared(eid, envelope.state.task_id, "iso.charge",
                                         canonical_json({"dir": directory, "amount": 5}).decode("utf-8"))
            store.settle_effect(eid, "unknown", None, "prior kill")
            result = host.run(envelope)
            self.assertEqual(result.status, "failed")
            self.assertFalse((Path(directory) / "attempts.log").exists())  # never auto-retried
            self.assertTrue(any(event["event"] == "tool.refused" for event in result.audit))

    @unittest.skipUnless(_has_tree_termination_primitive(), "isolated side-effecting tools need a process-tree termination primitive")
    def test_error_settles_unknown_then_reconcile_confirms_a_landed_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host, envelope = self._charge_host(store, directory, target="charge_then_fail")
            result = host.run(envelope)
            self.assertEqual(result.status, "failed")  # tool raised after the effect landed
            eid = self._charge_eid(envelope, directory)
            self.assertEqual(store.get_effect(eid)["state"], "unknown")
            # Section 7 PR 2b round 2 (G18): the tool.failed event self-records effect_status:"unknown"
            # (as tool.killed already did), so an incident responder need not cross-reference the ledger.
            # Neutralize: drop `failed_details["effect_status"] = "unknown"` in host._apply_decision -> fails.
            failed = next(event for event in result.audit if event["event"] == "tool.failed")
            self.assertEqual(failed["details"]["effect_status"], "unknown")
            # Reconcile finds the landed marker -> confirmed.
            self.assertEqual(host.reconcile_effect(eid, envelope.state.task_id), "confirmed")
            self.assertEqual(store.get_effect(eid)["state"], "confirmed")

    @unittest.skipUnless(_has_tree_termination_primitive(), "isolated side-effecting tools need a process-tree termination primitive")
    def test_reconcile_settles_reconciled_when_effect_did_not_land(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host, envelope = self._charge_host(store, directory, target="fail_without_landing")
            self.assertEqual(host.run(envelope).status, "failed")
            eid = self._charge_eid(envelope, directory)
            self.assertEqual(store.get_effect(eid)["state"], "unknown")
            self.assertEqual(host.reconcile_effect(eid, envelope.state.task_id), "reconciled")

    @unittest.skipUnless(_has_tree_termination_primitive(), "isolated side-effecting tools need a process-tree termination primitive")
    def test_side_effecting_tool_missing_effect_id_param_fails_controlled(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            # reconcile is mandatory now (Section 7 PR 2b), and it is unrelated to what this test
            # exercises (the WORKER-side controlled failure when the tool signature omits effect_id),
            # so keep the default reconcile target -- it is never called here.
            host, envelope = self._charge_host(store, directory, target="no_effect_id_param")
            result = host.run(envelope)
            self.assertEqual(result.status, "failed")
            failed = next(event for event in result.audit if event["event"] == "tool.failed")
            self.assertIn("does not accept effect_id", failed["details"]["error"])
            self.assertEqual(store.get_effect(self._charge_eid(envelope, directory))["state"], "unknown")

    @unittest.skipUnless(_has_tree_termination_primitive(), "isolated side-effecting tools need a process-tree termination primitive")
    def test_reconcile_rejects_a_foreign_task(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host, envelope = self._charge_host(store, directory, target="fail_without_landing")
            host.run(envelope)
            eid = self._charge_eid(envelope, directory)
            with self.assertRaisesRegex(SecurityError, "does not belong to task"):
                host.reconcile_effect(eid, "some-other-task")

    def test_effect_id_is_bound_only_to_task_and_position(self):
        # The id identifies the logical call POSITION: task_id + sequence, and NOTHING else. Tool and
        # arguments are deliberately excluded so provider drift at one position cannot mint a second id
        # (the auditor's argument-drift hole). The host passes only (task_id, sequence).
        base = effect_id("task", 0)
        self.assertEqual(base, effect_id("task", 0))        # deterministic
        self.assertNotEqual(base, effect_id("task", 1))     # position (sequence) distinguishes
        self.assertNotEqual(base, effect_id("other", 0))    # task distinguishes

    @unittest.skipUnless(_has_tree_termination_primitive(), "isolated side-effecting tools need a process-tree termination primitive")
    def test_replay_refuses_on_argument_drift(self):
        # CALIBRATED (P1 round 2). Position 0 already holds a CONFIRMED effect recorded with amount=999.
        # The provider re-proposes the SAME position with amount=5. Because the effect_id is
        # position-only, the host must REFUSE -- never replay the amount=999 result, never re-run at a
        # bound position. Calibration (gate ledger): drop the drift check in _effect_pre_launch -> the
        # confirmed row REPLAYS and the run completes (tool.replayed), so status is not "failed".
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host, envelope = self._charge_host(store, directory)
            eid = self._charge_eid(envelope, directory)
            store.record_effect_prepared(eid, envelope.state.task_id, "iso.charge",
                                         canonical_json({"dir": directory, "amount": 999}).decode("utf-8"))
            store.mark_effect_started(eid)
            store.settle_effect(eid, "confirmed", canonical_json({"charged": 999}).decode("utf-8"), None)
            result = host.run(envelope)
            self.assertEqual(result.status, "failed")
            refused = next(event for event in result.audit if event["event"] == "tool.refused")
            self.assertIn("arguments", refused["details"]["reason"])
            self.assertFalse((Path(directory) / "attempts.log").exists())  # the tool never ran
            self.assertFalse(any(event["event"] == "tool.replayed" for event in result.audit))  # not replayed
            self.assertFalse(any(event["event"] == "tool.executed" for event in result.audit))

    @unittest.skipUnless(_has_tree_termination_primitive(), "isolated side-effecting tools need a process-tree termination primitive")
    def test_replay_refuses_on_tool_drift(self):
        # The auditor's exact case: "a different TOOL's result". Position 0 holds a confirmed effect
        # recorded for tool "iso.other" (same arguments). The provider now proposes "iso.charge" at that
        # position -> refuse; the host must not hand back another tool's recorded result.
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host, envelope = self._charge_host(store, directory)
            eid = self._charge_eid(envelope, directory)
            store.record_effect_prepared(eid, envelope.state.task_id, "iso.other",
                                         canonical_json({"dir": directory, "amount": 5}).decode("utf-8"))
            store.mark_effect_started(eid)
            store.settle_effect(eid, "confirmed", canonical_json({"charged": 777}).decode("utf-8"), None)
            result = host.run(envelope)
            self.assertEqual(result.status, "failed")
            refused = next(event for event in result.audit if event["event"] == "tool.refused")
            self.assertIn("tool", refused["details"]["reason"])
            self.assertFalse((Path(directory) / "attempts.log").exists())  # the tool never ran
            self.assertFalse(any(event["event"] == "tool.replayed" for event in result.audit))  # not replayed

    @unittest.skipUnless(_has_tree_termination_primitive(), "isolated side-effecting tools need a process-tree termination primitive")
    def test_reconciling_effect_refuses_relaunch(self):
        # CALIBRATED (P3 round 3, the re-run bug the fix pass must not introduce). A row left `reconciling`
        # (a reconcile pass in flight) must REFUSE a fresh launch -- launching now would run the tool WHILE
        # reconciliation resolves whether the prior effect landed, the double-effect the ledger prevents.
        # Calibration (gate ledger): drop "reconciling" from the refuse set in _effect_pre_launch -> the
        # row falls through to the drift/run path and the tool RUNS, so status is not "failed".
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host, envelope = self._charge_host(store, directory)
            eid = self._charge_eid(envelope, directory)
            store.record_effect_prepared(eid, envelope.state.task_id, "iso.charge",
                                         canonical_json({"dir": directory, "amount": 5}).decode("utf-8"))
            store.mark_effect_started(eid)
            store.settle_effect(eid, "reconciling", None, "a reconcile is in flight")
            result = host.run(envelope)
            self.assertEqual(result.status, "failed")
            self.assertFalse((Path(directory) / "attempts.log").exists())  # never launched under reconciliation
            self.assertTrue(any(event["event"] == "tool.refused" for event in result.audit))

    def test_effect_reconcile_claim_is_owned_lease_bounded_and_race_safe(self):
        # P3 round 3 remediation: a reconcile claim has an OWNER (reconcile_claim_id). Two operators
        # cannot clobber each other -- a settle requires the owning id AND a live lease, so a non-owner
        # (or a superseded holder) can neither overwrite a recorded settlement nor reset the claim. This
        # test covers the owner semantics with LIVE leases; lease EXPIRY + reclaim is covered
        # deterministically by test_effect_reconcile_expiry_reclaims_with_a_new_owner (injected clock).
        # Runs on InMemory (the DEFAULT store, so its owned-lease methods are covered too) AND SQLite AND
        # (when a DSN is set) Postgres via two real synchronized connections -- the Section-6 bar.
        for context in [nullcontext(("memory", InMemoryRuntimeStore()))] + self._store_case_contexts():
            with context as (backend, store):
                with self.subTest(backend=backend):
                    def seed_unknown(eid: str) -> None:
                        store.record_effect_prepared(eid, "t", "iso.charge", "{}")
                        store.mark_effect_started(eid)
                        store.settle_effect(eid, "unknown", None, "kill")

                    # A FRESH claim's live lease blocks another owner (lease_seconds is the NEW claim's).
                    seed_unknown("live-1")
                    self.assertTrue(store.claim_effect_for_reconcile("live-1", "A", 10_000))    # unknown -> reconciling (A)
                    self.assertFalse(store.claim_effect_for_reconcile("live-1", "B", 10_000))   # A's lease live -> B refused

                    # Owned CAS settle: the owner settles; a late loser with its OWN id cannot clobber it.
                    seed_unknown("cas-1")
                    self.assertTrue(store.claim_effect_for_reconcile("cas-1", "W", 10_000))
                    self.assertTrue(store.settle_effect_from_claim("cas-1", "W", "confirmed",
                                                                   canonical_json({"charged": 5}).decode("utf-8"), "landed"))
                    self.assertFalse(store.settle_effect_from_claim("cas-1", "L", "reconciled", None, "did not land"))  # loser's own id
                    self.assertFalse(store.settle_effect_from_claim("cas-1", "W", "reconciled", None, "did not land"))  # even W: no longer reconciling
                    final = store.get_effect("cas-1")
                    self.assertEqual(final["state"], "confirmed")
                    self.assertEqual(json.loads(final["result_json"])["charged"], 5)  # confirmed result intact

                    # The claim OWNER may RELEASE its claim back to unknown (liveness); a non-owner cannot.
                    seed_unknown("rel-1")
                    self.assertTrue(store.claim_effect_for_reconcile("rel-1", "R", 10_000))
                    self.assertFalse(store.release_effect_claim("rel-1", "not-R"))             # non-owner cannot reset
                    self.assertTrue(store.release_effect_claim("rel-1", "R"))                  # owner relinquishes
                    self.assertEqual(store.get_effect("rel-1")["state"], "unknown")           # retryable, not stranded

                    # Two real connections race to claim the SAME unknown effect; exactly one wins.
                    seed_unknown("race-1")
                    barrier = threading.Barrier(2)
                    wins: list[bool] = []
                    lock = threading.Lock()

                    def claim(claim_id: str) -> None:
                        barrier.wait()
                        won = store.claim_effect_for_reconcile("race-1", claim_id, 10_000)
                        with lock:
                            wins.append(won)

                    threads = [threading.Thread(target=claim, args=(cid,)) for cid in ("race-A", "race-B")]
                    for thread in threads:
                        thread.start()
                    for thread in threads:
                        thread.join(timeout=30)
                    self.assertEqual(sorted(wins), [False, True])  # exactly one claimant wins the race

    def test_effect_reconcile_expiry_reclaims_with_a_new_owner(self):
        # Round-4 hardening: lease EXPIRY tested deterministically with an INJECTED clock (no negative
        # lease, no sleep) on the embedded stores -- the store's reconcile methods read self._clock().
        # An expired claim is reclaimable, the reclaim mints a DIFFERENT owner id, and the superseded
        # holder can then neither settle nor reset the new claim. (Postgres uses DB time, not the injected
        # clock; its owner-scoped settle is covered by the race test above.)
        now = {"t": 1000}
        clock = lambda: now["t"]  # noqa: E731
        with tempfile.TemporaryDirectory() as directory:
            stores = [("memory", InMemoryRuntimeStore(clock=clock)),
                      ("sqlite", SQLiteRuntimeStore(Path(directory) / "eff.sqlite", clock=clock))]
            for backend, store in stores:
                with self.subTest(backend=backend):
                    now["t"] = 1000
                    store.record_effect_prepared("e", "t", "iso.charge", "{}")
                    store.mark_effect_started("e")
                    store.settle_effect("e", "unknown", None, "kill")
                    self.assertTrue(store.claim_effect_for_reconcile("e", "A", 100))   # lease -> 1100
                    now["t"] = 1050                                                    # still live
                    self.assertFalse(store.claim_effect_for_reconcile("e", "B", 100))  # B refused, A's lease live
                    now["t"] = 1200                                                    # A's lease expired
                    self.assertTrue(store.claim_effect_for_reconcile("e", "C", 100))   # C reclaims
                    self.assertEqual(store.get_effect("e")["reconcile_claim_id"], "C")  # a NEW owner id
                    # A, superseded, can neither settle nor reset C's live claim.
                    self.assertFalse(store.settle_effect_from_claim("e", "A", "confirmed", None, "stale"))
                    self.assertFalse(store.release_effect_claim("e", "A"))
                    self.assertEqual(store.get_effect("e")["state"], "reconciling")     # C's claim untouched
                    # C, the live owner, settles it.
                    self.assertTrue(store.settle_effect_from_claim("e", "C", "reconciled", None, "did not land"))
                    self.assertEqual(store.get_effect("e")["state"], "reconciled")

    def test_renew_effect_claim_extends_owner_and_fails_after_reclaim(self):  # G22 store (CALIBRATED)
        # PR 2b round 3: the host renews its claim immediately before running a reconcile. renew re-stamps
        # the lease for the OWNING claim (claim-id match, authoritative clock) and FAILS once a reclaimer
        # has taken the row -- so a paused/expired holder that lost the row aborts instead of running
        # concurrently. CALIBRATED: make renew_effect_claim return True unconditionally and the
        # post-reclaim renew succeeds (both holders would proceed), so this test fails.
        now = {"t": 1000}
        clock = lambda: now["t"]  # noqa: E731
        with tempfile.TemporaryDirectory() as directory:
            stores = [("memory", InMemoryRuntimeStore(clock=clock)),
                      ("sqlite", SQLiteRuntimeStore(Path(directory) / "eff.sqlite", clock=clock))]
            for backend, store in stores:
                with self.subTest(backend=backend):
                    now["t"] = 1000
                    store.record_effect_prepared("e", "t", "iso.charge", "{}")
                    store.mark_effect_started("e")
                    store.settle_effect("e", "unknown", None, "kill")
                    self.assertTrue(store.claim_effect_for_reconcile("e", "A", 100))    # lease -> 1100
                    now["t"] = 1050                                                     # still owned + live
                    self.assertTrue(store.renew_effect_claim("e", "A", 100))            # extend -> 1150
                    self.assertEqual(store.get_effect("e")["reconcile_lease_expires_at"], 1150)
                    self.assertFalse(store.claim_effect_for_reconcile("e", "B", 100))   # A's renewed lease keeps B out
                    now["t"] = 1200                                                     # A paused past the renewed lease
                    self.assertTrue(store.claim_effect_for_reconcile("e", "B", 100))    # B reclaims, new owner id
                    self.assertEqual(store.get_effect("e")["reconcile_claim_id"], "B")
                    # A resumes and tries to renew before running -> FAILS (B owns) -> A aborts, no concurrent run.
                    self.assertFalse(store.renew_effect_claim("e", "A", 100))
                    self.assertEqual(store.get_effect("e")["reconcile_claim_id"], "B")  # B untouched
                    now["t"] = 1250
                    self.assertTrue(store.renew_effect_claim("e", "B", 100))            # the live owner can renew

    @unittest.skipUnless(_has_tree_termination_primitive(), "isolated side-effecting tools need a process-tree termination primitive")
    def test_reconcile_effect_aborts_when_claim_renewal_fails(self):  # G22 host (CALIBRATED)
        # If the claim cannot be renewed right before running (a reclaimer took the row during a pause),
        # reconcile_effect must NOT run the reconcile target. CALIBRATED: remove the renew-or-abort guard
        # in host.reconcile_effect and the effect settles `confirmed` even though renewal failed.
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host, envelope = self._charge_host(store, directory, target="charge_then_fail")
            host.run(envelope)  # settles `unknown` (effect landed, tool then raised)
            eid = self._charge_eid(envelope, directory)
            with patch.object(store, "renew_effect_claim", return_value=False):
                state = host.reconcile_effect(eid, envelope.state.task_id)
            # The reconcile did NOT run: the claim (state `reconciling`) is left untouched, and the
            # returned state is that same non-terminal state -- not `confirmed`/`reconciled`.
            self.assertEqual(store.get_effect(eid)["state"], "reconciling")
            self.assertEqual(state, "reconciling")

    def test_reconcile_claim_rejects_invalid_lease_or_owner(self):
        # Round-4 hardening (auditor note): the store validates its OWN inputs so a zero/negative lease
        # (which would make the claim instantly reclaimable, defeating exclusivity) or an empty owner id
        # is rejected at the boundary, not trusted from the caller. CALIBRATED: neutralize the validator
        # call and a negative lease is accepted (the claim's lease lands in the past -> instantly
        # reclaimable), so this test fails; restored -> passes.
        with tempfile.TemporaryDirectory() as directory:
            stores = [("memory", InMemoryRuntimeStore()),
                      ("sqlite", SQLiteRuntimeStore(Path(directory) / "eff.sqlite"))]
            for backend, store in stores:
                with self.subTest(backend=backend):
                    store.record_effect_prepared("e", "t", "iso.charge", "{}")
                    store.mark_effect_started("e")
                    store.settle_effect("e", "unknown", None, "kill")
                    for bad in (0, -1, True, 1.5):
                        with self.assertRaisesRegex(SecurityError, "lease_seconds"):
                            store.claim_effect_for_reconcile("e", "owner", bad)
                    for bad_id in ("", "   ", None):
                        with self.assertRaisesRegex(SecurityError, "claim_id"):
                            store.claim_effect_for_reconcile("e", bad_id, 100)
                    self.assertTrue(store.claim_effect_for_reconcile("e", "owner", 100))  # a well-formed claim still works

    @unittest.skipUnless(_has_tree_termination_primitive(), "isolated side-effecting tools need a process-tree termination primitive")
    def test_reconcile_effect_refuses_a_live_reconciling_claim(self):
        # A host-level reconcile cannot start while another reconcile holds a live claim: the CAS claim
        # fails and reconcile_effect raises rather than running a second reconciler concurrently.
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host, envelope = self._charge_host(store, directory, target="fail_without_landing")
            host.run(envelope)
            eid = self._charge_eid(envelope, directory)
            self.assertEqual(store.get_effect(eid)["state"], "unknown")
            # Simulate a reconcile already in flight (another worker holds a live claim).
            self.assertTrue(store.claim_effect_for_reconcile(eid, "other-worker", 10_000))
            with self.assertRaisesRegex(SecurityError, "only an unknown"):
                host.reconcile_effect(eid, envelope.state.task_id)

    @unittest.skipUnless(_has_tree_termination_primitive(), "isolated side-effecting tools need a process-tree termination primitive")
    def test_launch_capability_is_disarmed_when_not_consumed(self):
        # A capability armed but not consumed (invoke failed before the gate) must not outlive its one
        # intended launch. disarm() drops it, so a later invoke with it is refused.
        registry = ToolRegistry(isolation_profile=_TEST_ISOLATION_PROFILE)
        registry.register_isolated(
            "iso.pay", "isolated_tool_fixtures:echo", side_effecting=True,
            reconcile="isolated_tool_fixtures:reconcile_charge", env=self._isolated_env(),
        )
        permit = self._isolated_permit("iso.pay")
        args = {"amount": 3}
        canonical_args = canonical_json(args).decode("utf-8")
        armer = registry.attach_effect_ledger(lambda eid: {"effect_id": eid, "state": "started", "tool": "iso.pay", "arguments_json": canonical_args} if eid == "e-1" else None)
        cap = armer.arm("e-1", "iso.pay", args)
        armer.disarm(cap)  # the host's `finally` path
        with self.assertRaisesRegex(SecurityError, "does not authorize"):
            registry.invoke(permit, "iso.pay", args, launch_capability=cap)

    def test_sqlite_v9_to_v10_adds_tool_effects(self):
        # Section 7 PR 2a (G2, upgrade path). An existing v9 SQLite store opened by v10 code migrates
        # to v10 and gains the tool_effects table -- the path a real deployment takes.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            SQLiteRuntimeStore(path)  # build a full v10 store, then roll it back to look like v9
            with self._raw_sqlite(str(path)) as connection:
                connection.execute("DROP TABLE tool_effects")
                connection.execute("PRAGMA user_version = 9")
            with self._raw_sqlite(str(path)) as connection:
                self.assertEqual(int(connection.execute("PRAGMA user_version").fetchone()[0]), 9)

            store = SQLiteRuntimeStore(path)  # v10 code opens a v9 db -> migrates
            with self._raw_sqlite(str(path)) as connection:
                self.assertEqual(int(connection.execute("PRAGMA user_version").fetchone()[0]), SQLITE_SCHEMA_VERSION)
                self.assertIsNotNone(connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='tool_effects'").fetchone())
            store.record_effect_prepared("e1", "t1", "pay", "{}")
            self.assertEqual(store.get_effect("e1")["state"], "prepared")

    def test_sqlite_v10_to_v11_adds_reconcile_lease_columns(self):
        # Section 7 PR 2 (round 3, G-migration). An existing v10 SQLite store opened by v11 code migrates
        # to v11 and gains the OWNED-reconcile-lease columns -- the path a real deployment takes. A v10 row
        # (no lease columns) upgrades untouched and is then claimable under an owner.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            store = SQLiteRuntimeStore(path)  # full v11
            store.record_effect_prepared("e1", "t1", "pay", "{}")  # a pre-existing row
            with self._raw_sqlite(str(path)) as connection:  # roll it back to look like v10
                connection.execute("ALTER TABLE tool_effects DROP COLUMN reconcile_claim_id")
                connection.execute("ALTER TABLE tool_effects DROP COLUMN reconcile_lease_expires_at")
                connection.execute("PRAGMA user_version = 10")
            with self._raw_sqlite(str(path)) as connection:
                self.assertEqual(int(connection.execute("PRAGMA user_version").fetchone()[0]), 10)

            store = SQLiteRuntimeStore(path)  # v11 code opens a v10 db -> migrates
            with self._raw_sqlite(str(path)) as connection:
                self.assertEqual(int(connection.execute("PRAGMA user_version").fetchone()[0]), SQLITE_SCHEMA_VERSION)
                columns = {row[1] for row in connection.execute("PRAGMA table_info(tool_effects)").fetchall()}
                self.assertIn("reconcile_claim_id", columns)
                self.assertIn("reconcile_lease_expires_at", columns)
            # The pre-existing row survived and now carries NULL lease fields; make it unknown + claim it.
            self.assertEqual(store.get_effect("e1")["reconcile_claim_id"], None)
            store.mark_effect_started("e1")
            store.settle_effect("e1", "unknown", None, "kill")
            self.assertTrue(store.claim_effect_for_reconcile("e1", "owner-1", 300))
            self.assertEqual(store.get_effect("e1")["reconcile_claim_id"], "owner-1")

    def test_constrained_grant_denies_unknown_arguments_without_an_explicit_flag(self):
        # Regression: a grant that constrains ANY argument thereby whitelists the
        # names it mentions -- an unknown field must not ride through to a
        # side-effecting tool just because additional_arguments was not set to
        # false. Previously {amount, currency, recipient, memo} passed against a
        # grant of {max_amount, allowed_currency}; recipient/memo reached the tool.
        executed: list[dict] = []
        registry = ToolRegistry()
        registry.register("payments.reserve", lambda arguments: executed.append(arguments) or {"ok": True})
        permit = Permit(
            issuer="issuer",
            subject="agent",
            audience="host",
            expires_at=int(time.time()) + 60,
            nonce="nonce-deny",
            grants=(ToolGrant("payments.reserve", {"max_amount": 20, "allowed_currency": ["USD"]}),),
        )
        with self.assertRaisesRegex(SecurityError, "unsupported fields"):
            registry.invoke(
                permit,
                "payments.reserve",
                {"amount": 5, "currency": "USD", "recipient": "attacker", "memo": "drain"},
            )
        self.assertEqual(executed, [])  # the tool never ran
        # The declared arguments alone are still accepted.
        self.assertEqual(
            registry.invoke(permit, "payments.reserve", {"amount": 5, "currency": "USD"}), {"ok": True}
        )
        # A grant that constrains nothing stays a pure capability grant: it is the
        # shape a bare tool-name manifest produces and must still pass arguments.
        open_permit = Permit(
            issuer="issuer",
            subject="agent",
            audience="host",
            expires_at=int(time.time()) + 60,
            nonce="nonce-open",
            grants=(ToolGrant("payments.reserve"),),
        )
        self.assertEqual(
            registry.invoke(open_permit, "payments.reserve", {"amount": 5, "extra": "ok"}), {"ok": True}
        )

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
            with FakeFetchNetwork(response=response) as network:
                result = host.run(envelope)

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.result["fetch"]["status"], 200)
        # Finding #4: the policy grants output_projection ["url", "status",
        # "content_type"] and deliberately WITHHOLDS "body". The in-process fetch
        # provider used to read the un-projected result from memory and leak the body;
        # host-enforced projection now feeds it only the granted fields, so the body it
        # completes with is gone.
        self.assertNotIn("body", result.result["fetch"])
        self.assertEqual(result.result["fetch"]["url"], "https://allowed.example/resource")
        self.assertEqual(response.read_size, http_fetch.MAX_RESPONSE_BYTES + 1)
        self.assertEqual(network.connections, [(PUBLIC_TEST_ADDRESS, 443, "allowed.example")])

    def test_http_fetch_example_denies_disallowed_host_before_network_call(self):
        with tempfile.TemporaryDirectory() as directory:
            host, envelope = self._http_fetch_host(directory, {"url": "https://evil.example/resource", "method": "GET"})
            with FakeFetchNetwork() as network:
                with self.assertRaisesRegex(SecurityError, "host is outside its allowed set"):
                    host.run(envelope)

        self.assertEqual((network.lookups, network.connections), ([], []))

    def test_http_fetch_example_denies_ssrf_host_confusion_before_network_call(self):
        cases = [
            ("userinfo host confusion", "https://allowed.example@evil.com/resource", "must not contain userinfo"),
            ("trailing dot host", "https://evil.com./resource", "host is outside its allowed set"),
            ("sibling suffix host", "https://notexample.com/resource", "host is outside its allowed set"),
            ("metadata ip host", "https://169.254.169.254/latest/meta-data/", "host is outside its allowed set"),
        ]
        for label, url, message in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as directory:
                    host, envelope = self._http_fetch_host(directory, {"url": url, "method": "GET"})
                    with FakeFetchNetwork() as network:
                        with self.assertRaisesRegex(SecurityError, message):
                            host.run(envelope)

                self.assertEqual((network.lookups, network.connections), ([], []))

    def test_http_fetch_example_accepts_uppercase_allowed_host(self):
        with tempfile.TemporaryDirectory() as directory:
            host, envelope = self._http_fetch_host(directory, {"url": "https://ALLOWED.EXAMPLE/resource", "method": "GET"})
            response = FakeHttpResponse(b"hello", headers={"Content-Type": "text/plain"})
            with FakeFetchNetwork(response=response) as network:
                result = host.run(envelope)

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.result["fetch"]["url"], "https://ALLOWED.EXAMPLE/resource")
        self.assertEqual(len(network.connections), 1)

    def test_http_fetch_example_denies_non_https_before_network_call(self):
        with tempfile.TemporaryDirectory() as directory:
            host, envelope = self._http_fetch_host(directory, {"url": "http://allowed.example/resource", "method": "GET"})
            with FakeFetchNetwork() as network:
                with self.assertRaisesRegex(SecurityError, "URL scheme must be https"):
                    host.run(envelope)

        self.assertEqual((network.lookups, network.connections), ([], []))

    def test_http_fetch_example_oversized_output_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            host, envelope = self._http_fetch_host(directory, {"url": "https://allowed.example/resource", "method": "GET"})
            response = FakeHttpResponse(b"x" * (http_fetch.MAX_RESPONSE_BYTES + 1), headers={"Content-Type": "text/plain"})
            with FakeFetchNetwork(response=response):
                result = host.run(envelope)

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.result, {"error": "tool execution failed"})
        failed = next(event for event in result.audit if event["event"] == "tool.failed")
        self.assertEqual(failed["details"]["cause"], "ToolExecutionError")
        self.assertEqual(failed["details"]["cause_message"], "http.fetch response exceeds output limit")

    def test_http_fetch_example_timeout_fails_as_tool_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            host, envelope = self._http_fetch_host(directory, {"url": "https://allowed.example/resource", "method": "GET"})
            with FakeFetchNetwork(error=TimeoutError("timed out")):
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
            with FakeFetchNetwork() as network:
                with self.assertRaisesRegex(SecurityError, "unsupported fields"):
                    host.run(envelope)

        self.assertEqual((network.lookups, network.connections), ([], []))

    def test_http_fetch_example_refuses_a_name_that_resolves_to_a_non_public_address(self):
        # Audit plan 005: the policy allowlists the NAME; every address it resolves to must be public too.
        cases = {
            "loopback": ["127.0.0.1"],
            "private": ["10.0.0.5"],
            "link-local (cloud metadata)": ["169.254.169.254"],
            "unspecified": ["0.0.0.0"],  # nosec B104 -- a faked DNS answer the tool must refuse, not a bind
            "multicast": ["224.0.0.1"],
            "reserved": ["240.0.0.1"],
            "documentation range": ["192.0.2.10"],
            "IPv6 loopback": ["::1"],
            "IPv6 unique local": ["fd00::1"],
            "IPv4-mapped IPv6 loopback": ["::ffff:127.0.0.1"],
            "mixed public and private": [PUBLIC_TEST_ADDRESS, "10.0.0.1"],
        }
        for label, answer in cases.items():
            with self.subTest(label), FakeFetchNetwork(answer) as network:
                with self.assertRaisesRegex(SecurityError, "non-public address"):
                    http_fetch.fetch({"url": "https://allowed.example/resource"})
                self.assertEqual(network.connections, [])

    def test_http_fetch_example_connects_only_to_the_address_it_checked(self):
        # DNS rebinding: the name answers a public address once, then an internal one. The tool asks DNS
        # ONCE and connects to that checked literal; TLS still verifies the ORIGINAL name.
        response = FakeHttpResponse(b"ok", headers={"Content-Type": "text/plain"})
        with FakeFetchNetwork([PUBLIC_TEST_ADDRESS], ["127.0.0.1"], response=response) as network:
            result = http_fetch.fetch({"url": "https://allowed.example:8443/a/b?q=1#frag"})
        self.assertEqual(result["status"], 200)
        self.assertEqual(network.lookups, ["allowed.example"])
        self.assertEqual(network.connections, [(PUBLIC_TEST_ADDRESS, 8443, "allowed.example")])
        method, target, headers = network.requests[0]
        self.assertEqual((method, target, headers["Host"]), ("GET", "/a/b?q=1", "allowed.example:8443"))

    def test_http_fetch_example_classifies_a_literal_address_without_dns(self):
        response = FakeHttpResponse(b"ok")
        with FakeFetchNetwork(response=response) as network:
            http_fetch.fetch({"url": f"https://{PUBLIC_TEST_ADDRESS}/"})
            with self.assertRaisesRegex(SecurityError, "non-public address"):
                http_fetch.fetch({"url": "https://[::ffff:10.0.0.1]/"})
        self.assertEqual(network.lookups, [])
        self.assertEqual([connection[0] for connection in network.connections], [PUBLIC_TEST_ADDRESS])

    def test_http_fetch_example_round_trips_over_real_tls_to_the_pinned_address(self):
        # The fakes above prove the address rules; this proves the real transport: http.client over TLS to
        # the pinned address, the certificate checked against the URL's NAME, and what reaches the wire.
        import datetime
        import ssl

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("Host")))
                body = b"fetched over tls"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        with tempfile.TemporaryDirectory() as directory:
            cert_path, key_path = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert_path, key_path)
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.socket = server_context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            client_context = ssl.create_default_context(cafile=str(cert_path))
            port = server.server_port
            try:
                # Only the public-address rule is bypassed (the test server is on loopback); DNS is not used.
                with patch.object(http_fetch, "resolve_public_address", return_value="127.0.0.1"), \
                        patch.object(http_fetch.ssl, "create_default_context", return_value=client_context):
                    result = http_fetch.fetch({"url": f"https://localhost:{port}/page?x=1"})
                    self.assertEqual((result["status"], result["body"], result["content_type"]), (200, "fetched over tls", "text/plain"))
                    self.assertEqual(seen, [("/page?x=1", f"localhost:{port}")])
                    # The same pinned address under ANOTHER name: the certificate is checked against the
                    # URL's name, not the address, so it is refused.
                    with self.assertRaisesRegex(ToolExecutionError, "request failed"):
                        http_fetch.fetch({"url": f"https://other.test:{port}/"})
            finally:
                server.shutdown()
                server.server_close()
        self.assertEqual(len(seen), 1)

    def test_http_fetch_example_keeps_its_redirect_and_error_rules(self):
        with FakeFetchNetwork(response=FakeHttpResponse(b"", status=302)):
            with self.assertRaisesRegex(SecurityError, "redirects are disabled"):
                http_fetch.fetch({"url": "https://allowed.example/"})
        with FakeFetchNetwork(response=FakeHttpResponse(b"", status=404)):
            with self.assertRaisesRegex(ToolExecutionError, "request failed"):
                http_fetch.fetch({"url": "https://allowed.example/"})
        with patch("portmark.providers.socket.getaddrinfo", side_effect=socket.gaierror("no such name")):
            with self.assertRaisesRegex(ToolExecutionError, "request failed"):
                http_fetch.fetch({"url": "https://allowed.example/"})

    def test_host_rejects_oversized_tool_output_before_checkpointing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            store = SQLiteRuntimeStore(path)
            tools = ToolRegistry()
            tools.register("large.output", lambda arguments: {"payload": "x" * 2048})
            host = make_host(store=store, allow_ephemeral_signing_key=True)
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

    @staticmethod
    def _read_durable_audit_events(path, task_id):
        connection = sqlite3.connect(str(path))
        try:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT event, details_json FROM audit_events WHERE task_id = ? ORDER BY sequence",
                (str(task_id),),
            ).fetchall()
        finally:
            connection.close()
        return [{"event": row["event"], "details": json.loads(row["details_json"])} for row in rows]

    def test_host_records_honest_terminal_refusal_when_checkpoint_exceeds_budget_after_a_tool(self):
        # A tool result can pass the invoke cap yet still exceed the *checkpoint* budget
        # once it is recorded in both memory["tool_results"] and messages. The tool has
        # already run -- its side effect may have landed -- so the host must not silently
        # roll back this step (erasing the record that it ran) nor leave a resumable
        # checkpoint (a resume could re-propose the tool and land the effect twice). It
        # records a bounded, terminal, closed refusal with the effect status unknown,
        # exactly like a hard-killed tool. Proven against the durable store, because a
        # test that read the in-memory audit list would pass even if nothing persisted.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            store = SQLiteRuntimeStore(path)
            tools = ToolRegistry()
            tools.register("big.echo", lambda arguments: {"blob": "y" * 900})
            host = make_host(store=store, allow_ephemeral_signing_key=True)
            host.tools = tools
            budget = ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=1024)
            host.policy = HostPolicy(host.host_id, (ToolGrant("big.echo"),), budget)
            host.providers["big"] = OversizedResultProvider()
            envelope = make_demo_envelope(host, "oversized checkpoint", "big")
            object.__setattr__(envelope.manifest, "requested_tools", ("big.echo",))
            object.__setattr__(envelope.permit, "grants", (ToolGrant("big.echo"),))
            object.__setattr__(envelope.permit, "budget", budget)
            host.signer.seal(envelope)
            task = envelope.state.task_id

            result = host.run(envelope)

            # The run fails cleanly -- run() returns a failed result, it does not raise.
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.result, {"error": "checkpoint exceeds output budget after tool execution"})

            # The honest record is durable: reopen the store from disk and read the chain.
            # A bare reopen has no head-signature verifier wired, so the chain reads back
            # as "unverifiable" (signature unchecked) rather than "valid" -- both mean the
            # hash chain is present and internally consistent; only "invalid"/"missing" fail.
            reopened = SQLiteRuntimeStore(path)
            self.assertIn(reopened.verify_audit_chain_status(task).status, ("valid", "unverifiable"))
            durable_events = self._read_durable_audit_events(path, task)
            self.assertEqual([event["event"] for event in durable_events][-2:], ["output.refused", "agent.failed"])
            refused = [event for event in durable_events if event["event"] == "output.refused"]
            self.assertEqual(len(refused), 1)
            self.assertEqual(refused[0]["details"]["effect_status"], "unknown")
            self.assertEqual(refused[0]["details"]["tool"], "big.echo")
            # The tool.executed for this step is durable too -- the step was not rolled back.
            self.assertTrue(any(event["event"] == "tool.executed" for event in durable_events))

            # The durable checkpoint is the bounded terminal tombstone: the working
            # state (memory + messages) is dropped so it fits by construction, and the
            # oversized tool result is not in it. The record of what happened lives in
            # the audit chain (output.refused, above), not the checkpoint.
            checkpoint = reopened.load_checkpoint(task)
            self.assertIsNotNone(checkpoint)
            self.assertEqual(checkpoint["status"], "failed")
            self.assertEqual(checkpoint["memory"], {})
            self.assertEqual(checkpoint["messages"], [])

            # The checkpoint is closed: a resume cannot reopen it, so the tool's side
            # effect can never be landed a second time.
            with self.assertRaisesRegex(SecurityError, "closed"):
                with reopened.transaction() as transaction:
                    transaction.save_checkpoint(task, envelope.state, envelope.state.checkpoint_generation, closed=False)

    @unittest.skipUnless(_has_tree_termination_primitive(), "requires a process-tree hard-kill primitive")
    def test_killed_tool_near_ceiling_terminalizes_and_keeps_kill_reason(self):
        # Finding 1, the dangerous case: a hard-killed side-effecting tool near the
        # checkpoint ceiling. The kill sets a small terminal failure state that tips a
        # near-ceiling checkpoint over the budget. tool_calls does NOT increment on a
        # kill, so the original EV-010 guard did not fire: _persist raised out of run()
        # and the durable checkpoint stayed status="running" -- resumable, so a resume
        # could re-propose the killed effect and land it twice. The generalized
        # terminalization now closes it, and the tool.killed record (effect_status
        # "unknown") survives in the durable audit.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            store = SQLiteRuntimeStore(path)
            tools = ToolRegistry(isolation_profile=_TEST_ISOLATION_PROFILE)
            tools.register_isolated(
                "slow.side",
                "isolated_tool_fixtures:slow_then_return",
                timeout=1.0,
                side_effecting=True,
                reconcile="isolated_tool_fixtures:reconcile_charge",
                env=self._isolated_env(),
            )
            host = make_host(store=store, allow_ephemeral_signing_key=True)
            host.tools = tools
            host._effect_armer = host.tools.attach_effect_ledger(host._effect_ledger_row)  # plain-attribute swap: re-attach + re-arm (round 3)
            budget = ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=32768)
            host.policy = HostPolicy(
                host.host_id,
                (ToolGrant("slow.side", {"arguments": {"seconds": {"type": "number"}}}),),
                budget,
            )
            host.providers["kill"] = FixedProvider(ProviderDecision("tool", "slow.side", {"seconds": 30}))
            # A goal that lands the initial (running) checkpoint just under the ceiling,
            # so the small kill-failure terminal state tips it over.
            envelope = make_demo_envelope(host, "x" * 32600, "kill")
            object.__setattr__(envelope.manifest, "requested_tools", ("slow.side",))
            object.__setattr__(envelope.permit, "grants", (ToolGrant("slow.side"),))
            object.__setattr__(envelope.permit, "budget", budget)
            host.signer.seal(envelope)
            task = envelope.state.task_id

            result = host.run(envelope)  # returns, does not raise

            self.assertEqual(result.status, "failed")
            durable_events = self._read_durable_audit_events(path, task)
            killed = [event for event in durable_events if event["event"] == "tool.killed"]
            self.assertEqual(len(killed), 1)
            self.assertEqual(killed[0]["details"]["effect_status"], "unknown")
            self.assertTrue(any(event["event"] == "checkpoint.terminalized" for event in durable_events))

            reopened = SQLiteRuntimeStore(path)
            checkpoint = reopened.load_checkpoint(task)
            self.assertIsNotNone(checkpoint)
            self.assertEqual(checkpoint["status"], "failed")
            # Closed: a resume is refused, so the killed effect can never be re-proposed.
            with self.assertRaisesRegex(SecurityError, "closed"):
                with reopened.transaction() as transaction:
                    transaction.save_checkpoint(task, envelope.state, envelope.state.checkpoint_generation, closed=False)

    def test_admission_failure_over_budget_leaves_nothing_durable(self):
        # The safe boundary the fix must NOT terminalize: a fresh task whose very first
        # (admission) checkpoint already exceeds the budget. Admission is the gate --
        # nothing was committed, so nothing is resumable. run() must keep raising and
        # leave no durable checkpoint or audit head; a too-eager fallback that committed
        # here would admit a task the budget rejected.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            store = SQLiteRuntimeStore(path)
            tools = ToolRegistry()
            tools.register("noop", lambda arguments: {"ok": True})
            host = make_host(store=store, allow_ephemeral_signing_key=True)
            host.tools = tools
            host._effect_armer = host.tools.attach_effect_ledger(host._effect_ledger_row)  # plain-attribute swap: re-attach + re-arm (round 3)
            budget = ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=32768)
            host.policy = HostPolicy(host.host_id, (ToolGrant("noop", {"arguments": {"n": {"type": "number"}}}),), budget)
            host.providers["big"] = OversizedResultProvider()  # never reached; admission fails first
            envelope = make_demo_envelope(host, "x" * 33000, "big")  # goal alone exceeds the ceiling
            object.__setattr__(envelope.manifest, "requested_tools", ("noop",))
            object.__setattr__(envelope.permit, "grants", (ToolGrant("noop"),))
            object.__setattr__(envelope.permit, "budget", budget)
            host.signer.seal(envelope)
            task = envelope.state.task_id

            with self.assertRaisesRegex(SecurityError, "checkpoint exceeds output budget"):
                host.run(envelope)

            self.assertIsNone(store.load_checkpoint(task))
            self.assertIsNone(store.audit_head(task))

    def _counting_tool_host(self, store, calls, budget):
        # A host whose one tool tallies each execution, so a budget-bypass test can
        # assert exactly how many times the tool actually ran.
        tools = ToolRegistry()

        def counting(arguments):
            calls["n"] += 1
            return {"ok": True}

        tools.register("noop", counting)
        host = make_host(store=store, allow_ephemeral_signing_key=True)
        host.tools = tools
        host.policy = HostPolicy(host.host_id, (ToolGrant("noop", {"arguments": {"n": {"type": "number"}}}),), budget)
        host.providers["always"] = FixedProvider(ProviderDecision("tool", "noop", {"n": 1}))
        return host

    def test_negative_starting_counter_is_rejected_before_any_tool_runs(self):
        # Finding #3: budget accounting (max_tool_calls) trusts the caller-supplied
        # state.tool_calls. A fresh task that starts at tool_calls=-3 under a 1-call
        # budget runs the tool four times (-3,-2,-1,0) before the counter climbs to the
        # limit. Admission must reject the negative counter, and reject it BEFORE the
        # loop executes a single tool call, so nothing durable is left behind either.
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            calls = {"n": 0}
            budget = ResourceBudget(max_steps=10, max_tool_calls=1, max_output_bytes=32768)
            host = self._counting_tool_host(store, calls, budget)
            envelope = make_demo_envelope(host, "negative counter", "always")
            object.__setattr__(envelope.manifest, "requested_tools", ("noop",))
            object.__setattr__(envelope.permit, "grants", (ToolGrant("noop"),))
            object.__setattr__(envelope.permit, "budget", budget)
            object.__setattr__(envelope.state, "tool_calls", -3)
            host.signer.seal(envelope)
            with self.assertRaisesRegex(SecurityError, "invalid tool_calls counter"):
                host.run(envelope)
            self.assertEqual(calls["n"], 0)  # rejected before any tool executed
            self.assertIsNone(store.load_checkpoint(envelope.state.task_id))

    def test_crafted_migration_envelope_cannot_inject_negative_counter(self):
        # A migration accepted onto a fresh local chain legitimately carries the source
        # run's non-zero counters, so the fresh-admission guard cannot simply demand
        # zero. But a crafted migration-shaped envelope (a forged previous_audit_hash)
        # must not smuggle in a negative counter either: the counter guard runs at
        # admission -- before the audit head is even checked -- so the tool never runs.
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            calls = {"n": 0}
            budget = ResourceBudget(max_steps=10, max_tool_calls=1, max_output_bytes=32768)
            host = self._counting_tool_host(store, calls, budget)
            envelope = make_demo_envelope(host, "crafted migration", "always")
            object.__setattr__(envelope.manifest, "requested_tools", ("noop",))
            object.__setattr__(envelope.permit, "grants", (ToolGrant("noop"),))
            object.__setattr__(envelope.permit, "budget", budget)
            object.__setattr__(envelope.state, "tool_calls", -3)
            object.__setattr__(envelope, "previous_audit_hash", "forged-head")
            host.signer.seal(envelope)
            with self.assertRaisesRegex(SecurityError, "invalid tool_calls counter"):
                host.run(envelope)
            self.assertEqual(calls["n"], 0)
            self.assertIsNone(store.load_checkpoint(envelope.state.task_id))

    def test_non_serializable_provider_content_fails_cleanly_not_stranded(self):
        # Finding #7 x #2: with canonical_json(allow_nan=False), a provider that
        # completes with NaN content would raise inside _persist and leave the prior
        # checkpoint status="running" -- resumable. The host now rejects un-encodable
        # provider content at the _apply_decision boundary and lands a clean, bounded
        # terminal failure instead: run() returns failed (never raises), and the
        # durable checkpoint is closed (failed), not a resumable running one.
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host = make_host(store=store, allow_ephemeral_signing_key=True)
            host.providers["poison"] = FixedProvider(ProviderDecision("complete", content={"x": float("nan")}))
            envelope = make_demo_envelope(host, "poison content", "poison")
            host.signer.seal(envelope)
            result = host.run(envelope)  # must not raise
            self.assertEqual(result.status, "failed")
            self.assertIn("content.rejected", [event["event"] for event in result.audit])
            checkpoint = store.load_checkpoint(envelope.state.task_id)
            self.assertIsNotNone(checkpoint)
            self.assertEqual(checkpoint["status"], "failed")  # closed terminal, not running

    def test_oversized_migration_close_terminalizes_source_not_strands_it(self):
        # Finding #1 extended to migration: when the source-close checkpoint overflows
        # the output budget, the source must still CLOSE (its working state has moved to
        # the already-sealed migrated envelope), not raise and leave a resumable
        # status="running" checkpoint alongside that envelope -- which would let the
        # source resume AND the destination run the same work (double effect).
        source_signer = EnvelopeSigner.generate("source-key", "host:source", ("host:source", "host:destination"))
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            source = make_host(host_id="host:source", signer=source_signer, store=store, allow_ephemeral_signing_key=True)
            source.policy.migration = MigrationPolicy(allowed=True, destinations=("host:destination",))
            source.providers["migrator"] = MigrateThenCompleteProvider("host:destination")
            envelope = make_demo_envelope(source, "M" * 1500, "migrator")
            object.__setattr__(envelope.permit, "delegation_allowed", True)
            # Size the ceiling to admit the fresh checkpoint but refuse the migrate-close,
            # which adds the migration memory and the destination result (~90 bytes).
            running = asdict(envelope.state)
            running["status"] = "running"
            ceiling = len(canonical_json(running)) + 40
            budget = ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=ceiling)
            object.__setattr__(envelope.permit, "budget", budget)
            source.policy.budget = budget
            source_signer.seal(envelope)

            result = source.run(envelope)  # must not raise
            self.assertIsNotNone(result.migration_envelope)  # migrated envelope still returned
            checkpoint = store.load_checkpoint(result.task_id)
            self.assertIsNotNone(checkpoint)
            self.assertEqual(checkpoint["status"], "ready")  # closed source, migrated away
            self.assertEqual(checkpoint["memory"], {})  # working state dropped under budget pressure
            self.assertIn("checkpoint.terminalized", [event["event"] for event in result.audit])
            self.assertTrue(store.verify_audit_chain(result.task_id))

    def test_host_enforced_projection_hides_undeclared_fields_from_in_process_provider(self):
        # Finding #4: a grant's output_projection is enforced at the host boundary, so
        # an in-process provider that reads state.memory["tool_results"] directly sees
        # only the declared fields. The demo policy grants catalog.search (id, title),
        # so `score` (returned by the tool) must never reach the provider -- while the
        # host keeps the full result, score included, in its own durable state.
        seen = {}

        class RecordingProvider(ModelProvider):
            def decide(self, state, available_tools, grants=()):
                results = state.tool_results
                if "catalog.search" not in results:
                    return ProviderDecision("tool", "catalog.search", {"query": state.goal, "limit": 2})
                seen["view"] = results["catalog.search"]
                return ProviderDecision("complete", content={"evidence": results["catalog.search"]})

        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host = make_host(store=store, allow_ephemeral_signing_key=True)  # demo policy: catalog.search -> (id, title)
            host.providers["recorder"] = RecordingProvider()
            envelope = make_demo_envelope(host, "search", "recorder")
            host.signer.seal(envelope)
            result = host.run(envelope)
            self.assertEqual(result.status, "completed")
            # The provider saw only the declared fields -- no score.
            self.assertTrue(seen["view"])
            for item in seen["view"]:
                self.assertEqual(set(item), {"id", "title"})
            # The host's own durable state still holds the full result, score included.
            stored = store.load_checkpoint(result.task_id)["memory"]["tool_results"]["catalog.search"]
            self.assertTrue(any("score" in item for item in stored))

    def test_checkpoint_ceiling_is_the_host_minimum_not_the_permit(self):
        # F1: the checkpoint size ceiling must be effective.budget = min(permit, host),
        # not the visitor's permit alone -- "budgets take the minimum", and a migration
        # can transport the checkpoint to a peer host. Here the permit allows a large
        # output budget but the HOST policy sets a much smaller one. A tool result that
        # fits the permit's ceiling (and even the invoke cap, which already uses the
        # host minimum) but whose checkpoint exceeds the host minimum must be refused at
        # the host number -- proving the ceiling follows the host, and that the guard is
        # not decorative. Before F1 the checkpoint was sized against the permit, so this
        # run would have completed.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            store = SQLiteRuntimeStore(path)
            tools = ToolRegistry()
            tools.register("big.echo", lambda arguments: {"blob": "y" * 900})
            host = make_host(store=store, allow_ephemeral_signing_key=True)
            host.tools = tools
            host_budget = ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=1024)
            permit_budget = ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=8192)
            host.policy = HostPolicy(host.host_id, (ToolGrant("big.echo"),), host_budget)
            host.providers["big"] = OversizedResultProvider()
            envelope = make_demo_envelope(host, "narrow host budget", "big")
            object.__setattr__(envelope.manifest, "requested_tools", ("big.echo",))
            object.__setattr__(envelope.permit, "grants", (ToolGrant("big.echo"),))
            object.__setattr__(envelope.permit, "budget", permit_budget)
            host.signer.seal(envelope)
            task = envelope.state.task_id

            result = host.run(envelope)

            # Refused -- because the host's 1024 is the ceiling, even though the permit
            # would have allowed the ~1800-byte checkpoint.
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.result, {"error": "checkpoint exceeds output budget after tool execution"})

            durable_events = self._read_durable_audit_events(path, task)
            refused = [event for event in durable_events if event["event"] == "output.refused"]
            self.assertEqual(len(refused), 1)
            # The ceiling reported is the host minimum (1024), not the permit's 8192.
            self.assertEqual(refused[0]["details"]["max_output_bytes"], host_budget.max_output_bytes)
            self.assertEqual(refused[0]["details"]["effect_status"], "unknown")

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
                    host = make_host(store=store, allow_ephemeral_signing_key=True)
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
                "catalog.search": {"impact": "low", "constraints": {"max_limit": 2, "arguments": {"query": {"type": "string"}}}},
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
            # Finding #4: the host policy is the projection ceiling and an omitted
            # projection shares nothing, so a policy that wants the provider to confirm
            # the reservation must DECLARE the field it exposes -- here just "reserved"
            # (least privilege; amount/currency stay withheld). Host-enforced projection
            # then feeds the provider exactly that field, whether it reads memory or
            # messages.
            (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}, ("reserved",)),),
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
            # Section 5 #1: bind the suspended checkpoint's generation, which the operator
            # reads back from the awaiting-input run's returned checkpoint.
            checkpoint_generation=first.checkpoint["checkpoint_generation"],
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
            # Fresh single-run admission with the approval pre-injected: generation 0.
            checkpoint_generation=0,
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
            checkpoint_generation=0,
        )
        replayed.state.memory["approvals"] = {"payments.reserve": asdict(token)}
        replayed.state.memory["used_approval_ids"] = [token.approval_id]
        host.signer.seal(replayed)
        replay_result = host.run(replayed)
        self.assertEqual(replay_result.status, "failed")
        self.assertIn("approval.denied", [event["event"] for event in replay_result.audit])

    def test_captured_approved_suspended_envelope_cannot_replay_tool(self):
        import copy
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

        env = make_demo_envelope(host, "approved once", "payer")
        object.__setattr__(env.permit, "grants", (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}),))
        token = authority.issue(
            "payments.reserve",
            env.permit.subject,
            env.permit.audience,
            env.state.task_id,
            env.permit.nonce,
            {"amount": 50, "currency": "USD"},
            "policy-hash",
            int(time.time()) + 60,
            checkpoint_generation=0,
        )
        env.state.memory["approvals"] = {"payments.reserve": asdict(token)}
        # A suspended (resumed) envelope: the permit nonce is NOT consumed on this
        # path, so nonce replay defense does not apply — the approval must.
        object.__setattr__(env.state, "status", "awaiting_input")
        host.signer.seal(env)
        captured = copy.deepcopy(env)  # attacker captures the signed wire envelope

        first = host.run(env)
        self.assertEqual(first.status, "completed")  # legitimate resume executes once

        # Finding EV-008 now backstops the approval-nonce defense (EV-005). Once the
        # task completes its checkpoint is closed, so replaying the captured envelope
        # is rejected at admission by the generation/closed guard -- before the
        # approval gate is ever reached, and before any tool runs. The durable
        # approval-id consumption remains underneath as defense in depth.
        with self.assertRaisesRegex(SecurityError, "closed"):
            host.run(captured)  # same task_id + approval_id, same store

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
                checkpoint_generation=first.checkpoint["checkpoint_generation"],
            )
            self._write_policy(directory, authority, version="policy-v2")
            envelope.state.memory["approvals"] = {"payments.reserve": asdict(token)}
            host.signer.seal(envelope)
            second = host.run(envelope)
            self.assertEqual(second.status, "failed")
            self.assertIn("approval.denied", [event["event"] for event in second.audit])

    # ---- Section 5 (Approvals) helpers + tests ----

    def _approval_gated_host(self, store=None, tools=None):
        authority = ApprovalAuthority.generate()
        host = make_host(store=store, tools=tools, attestation_policy=None, allow_ephemeral_signing_key=True)
        host.policy = HostPolicy(
            "host:local-demo",
            (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}, ("reserved",)),),
            ResourceBudget(),
            "policy-v1",
            "policy-hash",
            {"payments.reserve": "external-payment"},
            (authority.trusted_approver(),),
        )
        host.providers["payer"] = PaymentProvider()
        return host, authority

    def _suspend_payment_envelope(self, host, goal):
        envelope = make_demo_envelope(host, goal, "payer")
        object.__setattr__(envelope.permit, "grants", (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}),))
        host.signer.seal(envelope)
        first = host.run(envelope)
        return envelope, first

    def _mint_payment_approval(self, authority, envelope, generation, expires_delta=60):
        return authority.issue(
            "payments.reserve",
            envelope.permit.subject,
            envelope.permit.audience,
            envelope.state.task_id,
            envelope.permit.nonce,
            {"amount": 50, "currency": "USD"},
            "policy-hash",
            int(time.time()) + expires_delta,
            checkpoint_generation=generation,
        )

    def test_approval_generation_binding_refuses_replay_at_later_generation(self):
        # Section 5 #1 (High), CALIBRATED. An approval minted for the task's suspended checkpoint at
        # generation N must not authorize the tool after the task advances to a later generation
        # (the auditor's repro: issued at gen N, redeemed at gen M, tool executed).
        host, authority = self._approval_gated_host()
        envelope, first = self._suspend_payment_envelope(host, "pay once")
        self.assertEqual(first.status, "awaiting_input")
        bound_generation = first.checkpoint["checkpoint_generation"]

        # Advance the suspended task WITHOUT redeeming: a resume with no approval re-suspends at a
        # higher generation. The stale approval below is minted for the ORIGINAL generation.
        host.signer.seal(envelope)
        advanced = host.run(envelope)
        self.assertEqual(advanced.status, "awaiting_input")
        self.assertGreater(advanced.checkpoint["checkpoint_generation"], bound_generation)

        stale_token = self._mint_payment_approval(authority, envelope, bound_generation)
        envelope.state.memory["approvals"] = {"payments.reserve": asdict(stale_token)}
        host.signer.seal(envelope)
        result = host.run(envelope)

        self.assertEqual(result.status, "failed")
        events = [event["event"] for event in result.audit]
        self.assertIn("approval.denied", events)
        self.assertNotIn("approval.approved", events)
        # CALIBRATION: comment out the `if token.checkpoint_generation != expected_generation` raise in
        # security.verify_approval and this run COMPLETES -- the stale approval executes payments.reserve
        # at the wrong generation (the auditor's replay). Verified by hand, then reverted.

    def test_malformed_approval_memory_is_controlled_failure_not_crash(self):
        # Section 5 #4 (class sweep), CALIBRATED. Every malformed approval shape from untrusted memory
        # yields a controlled approval.denied + terminal fail, never an uncaught exception out of run()
        # that strands the admitted task (the EV-010 nonterminal-strand class).
        malformations = [
            ("extra key", lambda tok: {**asdict(tok), "surprise": 1}),
            ("wrong-typed field", lambda tok: {**asdict(tok), "expires_at": "soon"}),
            ("bool generation", lambda tok: {**asdict(tok), "checkpoint_generation": True}),
            ("missing key", lambda tok: {k: v for k, v in asdict(tok).items() if k != "signature"}),
        ]
        for label, mutate in malformations:
            with self.subTest(label=label):
                host, authority = self._approval_gated_host()
                envelope, first = self._suspend_payment_envelope(host, f"malformed {label}")
                token = self._mint_payment_approval(authority, envelope, first.checkpoint["checkpoint_generation"])
                envelope.state.memory["approvals"] = {"payments.reserve": mutate(token)}
                host.signer.seal(envelope)
                result = host.run(envelope)
                self.assertEqual(result.status, "failed")
                self.assertIn("approval.denied", [event["event"] for event in result.audit])
        # CALIBRATION: revert _approval_token to `ApprovalToken(**value)` and the "extra/missing key"
        # cases raise TypeError out of run() (never returns), the wrong-typed cases crash later --
        # reproducing the strand. Verified by hand, then reverted.

    def test_malformed_used_approval_ids_is_controlled_failure(self):
        # Section 5 #4: used_approval_ids is also untrusted memory. A non-list would raise inside
        # set(); it must be a controlled denial instead of a crash.
        host, authority = self._approval_gated_host()
        envelope, first = self._suspend_payment_envelope(host, "bad used ids")
        token = self._mint_payment_approval(authority, envelope, first.checkpoint["checkpoint_generation"])
        envelope.state.memory["approvals"] = {"payments.reserve": asdict(token)}
        envelope.state.memory["used_approval_ids"] = 5  # not a list -> set(5) would raise
        host.signer.seal(envelope)
        result = host.run(envelope)
        self.assertEqual(result.status, "failed")
        self.assertIn("approval.denied", [event["event"] for event in result.audit])

    def test_cancelled_task_is_refused_at_approval_gate(self):
        # Section 5 #3. A task cancelled before its approval is redeemed is refused at the gate (inside
        # the same transaction that consumes the approval nonce); the tool never runs and, because the
        # consume rolls back, no approval is burned.
        host, authority = self._approval_gated_host()
        envelope, first = self._suspend_payment_envelope(host, "cancel before redeem")
        token = self._mint_payment_approval(authority, envelope, first.checkpoint["checkpoint_generation"])
        envelope.state.memory["approvals"] = {"payments.reserve": asdict(token)}
        host.signer.seal(envelope)
        host.cancel_task(envelope.state.task_id)
        result = host.run(envelope)
        self.assertEqual(result.status, "failed")
        denials = [event for event in result.audit if event["event"] == "approval.denied"]
        self.assertTrue(denials)
        self.assertEqual(denials[0]["details"]["reason"], "cancelled")
        self.assertNotIn("approval.approved", [event["event"] for event in result.audit])

    def test_cancel_and_redeem_are_atomic_under_concurrency(self):
        # Section 5 #3 CONCURRENT, on SQLite AND Postgres (two real connections synchronized on a
        # barrier). Redeem (consume_nonce + the in-transaction cancel check) and cancel racing can
        # never both win: the tool-authorizing nonce is consumed IFF the redeem committed as
        # not-cancelled; otherwise the whole transaction rolls back. No half state. Postgres serializes
        # on the per-task advisory xact lock, SQLite on BEGIN IMMEDIATE.
        class _Rollback(Exception):
            pass

        for context in self._store_case_contexts():
            with context as (backend, store):
                with self.subTest(backend=backend):
                    trials = 8 if backend == "postgres" else 25
                    for trial in range(trials):
                        task_id = f"task-{backend}-{trial}"
                        nonce = f"approval:{task_id}:a"
                        barrier = threading.Barrier(2)
                        outcome = {}

                        def redeem():
                            barrier.wait()
                            try:
                                with store.transaction() as txn:
                                    txn.consume_nonce(nonce, "s", "a", task_id)
                                    if txn.is_task_cancelled(task_id):
                                        raise _Rollback
                                outcome["redeemed"] = True
                            except (_Rollback, SecurityError):
                                outcome["redeemed"] = False

                        def cancel():
                            barrier.wait()
                            store.cancel_task(task_id)

                        tr = threading.Thread(target=redeem)
                        tc = threading.Thread(target=cancel)
                        tr.start()
                        tc.start()
                        tr.join(timeout=30)
                        tc.join(timeout=30)
                        self.assertTrue(store.is_task_cancelled(task_id))
                        self.assertEqual(store.consumed_nonce_exists(nonce), outcome["redeemed"])

    def test_cancel_during_tool_launch_does_not_prevent_effect_best_effort_limit(self):
        # Section 5 #3 — the documented BEST-EFFORT boundary, asserted (not just documented). Tier 3:
        # a cancel that commits AFTER the pre-launch re-check does not prevent the tool effect. This
        # reproduces exactly the auditor's observed sequence (cancel committed, effect produced): the
        # tool cancels its own task mid-execution (a cancel landing past the pre-launch read), yet the
        # run completes and the effect happens. Closing this fully needs per-tool idempotency keys +
        # reconciliation (Section 7); here it is the intended, known limit.
        store = InMemoryRuntimeStore()
        ctx: dict[str, str] = {}
        effects: list[str] = []
        registry = ToolRegistry()

        def reserve(arguments):
            store.cancel_task(ctx["task_id"])  # a cancel commits after the pre-launch check, during launch
            effects.append("effect")
            return {"reserved": True}

        # In-process tool so it can observe the store; side_effecting is orthogonal to the timing
        # boundary this asserts (the tool runs past the pre-launch cancellation read either way).
        registry.register("payments.reserve", reserve)
        host, authority = self._approval_gated_host(store=store, tools=registry)
        envelope, first = self._suspend_payment_envelope(host, "cancel during launch")
        ctx["task_id"] = envelope.state.task_id
        token = self._mint_payment_approval(authority, envelope, first.checkpoint["checkpoint_generation"])
        envelope.state.memory["approvals"] = {"payments.reserve": asdict(token)}
        host.signer.seal(envelope)
        result = host.run(envelope)

        # Best-effort limit: the effect happened despite the task now being cancelled.
        self.assertEqual(result.status, "completed")
        self.assertEqual(effects, ["effect"])
        self.assertTrue(store.is_task_cancelled(envelope.state.task_id))

    def test_cancel_after_consume_is_caught_before_tool_launch(self):
        # Section 5 #3, tier-3 ENFORCED sub-case. A cancel committed AFTER the approval is consumed but
        # BEFORE the pre-launch re-check reads is caught; the tool never runs. (A cancel that commits
        # AFTER the read is NOT caught -- that best-effort limit is asserted separately in
        # test_cancel_during_tool_launch_does_not_prevent_effect_best_effort_limit.) Modeled by a store
        # whose in-transaction check does not yet see the cancel while the store-level pre-launch read does.
        class _CancelBetween(InMemoryRuntimeStore):
            def transaction(self):
                txn = super().transaction()
                txn.is_task_cancelled = lambda task_id: False  # cancel not yet committed at gate time
                return txn

        store = _CancelBetween()
        host, authority = self._approval_gated_host(store=store)
        envelope, first = self._suspend_payment_envelope(host, "cancel between")
        token = self._mint_payment_approval(authority, envelope, first.checkpoint["checkpoint_generation"])
        envelope.state.memory["approvals"] = {"payments.reserve": asdict(token)}
        host.signer.seal(envelope)
        store.cancel_task(envelope.state.task_id)  # committed; the pre-launch read will observe it
        result = host.run(envelope)
        self.assertEqual(result.status, "failed")
        denials = [event for event in result.audit if event["event"] == "approval.denied"]
        self.assertTrue(denials)
        self.assertEqual(denials[0]["details"]["reason"], "cancelled")
        self.assertNotIn("payment", str(result.result or ""))

    def test_cancellation_end_to_end_on_both_backends(self):
        # Section 5 #3 + schema v9/v7: cancel_task + is_task_cancelled + the gate refusal on BOTH durable
        # backends, exercising the new task_cancellations table and (Postgres) the advisory-lock path.
        for context in self._store_case_contexts():
            with context as (backend, store):
                with self.subTest(backend=backend):
                    host, authority = self._approval_gated_host(store=store)
                    envelope, first = self._suspend_payment_envelope(host, f"cancel {backend}")
                    token = self._mint_payment_approval(authority, envelope, first.checkpoint["checkpoint_generation"])
                    envelope.state.memory["approvals"] = {"payments.reserve": asdict(token)}
                    host.signer.seal(envelope)
                    host.cancel_task(envelope.state.task_id)
                    self.assertTrue(store.is_task_cancelled(envelope.state.task_id))
                    result = host.run(envelope)
                    self.assertEqual(result.status, "failed")
                    self.assertIn("approval.denied", [event["event"] for event in result.audit])

    def test_stale_asserted_generation_cannot_satisfy_approval_gate(self):
        # Section 5 #1 (G2). The expected generation is sourced from the DURABLE store, so an
        # attacker cannot redeem a stale-generation approval by ASSERTING the stale generation on the
        # resume envelope: the pre-loop admission CAS rejects the stale assertion before the approval
        # gate is ever reached, and the tool never runs. This is what makes store-sourcing (not
        # envelope-sourcing) the actual fix.
        host, authority = self._approval_gated_host()
        envelope, first = self._suspend_payment_envelope(host, "stale assertion")
        stale_generation = first.checkpoint["checkpoint_generation"]
        stale_token = self._mint_payment_approval(authority, envelope, stale_generation)

        # Advance the store past the suspended generation.
        host.signer.seal(envelope)
        advanced = host.run(envelope)
        self.assertGreater(advanced.checkpoint["checkpoint_generation"], stale_generation)

        # Craft a resume that ASSERTS the stale generation (== the token's) while the store is ahead.
        object.__setattr__(envelope.state, "checkpoint_generation", stale_generation)
        envelope.state.memory["approvals"] = {"payments.reserve": asdict(stale_token)}
        host.signer.seal(envelope)
        # Rejected at admission (CAS) before the gate; the tool never runs.
        with self.assertRaisesRegex(SecurityError, "stale checkpoint generation"):
            host.run(envelope)

    def test_sqlite_v8_to_v9_upgrade_adds_cancellations(self):
        # Section 5 #3 (G8, upgrade path). An existing v8 SQLite store opened by v9 code migrates to
        # v9 and gains the task_cancellations table -- the path real deployments take (fresh stores
        # only exercise the 0->9 chain).
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            SQLiteRuntimeStore(path)  # build a full v9 store, then roll it back to look like v8
            with self._raw_sqlite(str(path)) as connection:
                connection.execute("DROP TABLE task_cancellations")
                connection.execute("PRAGMA user_version = 8")
            with self._raw_sqlite(str(path)) as connection:
                self.assertEqual(int(connection.execute("PRAGMA user_version").fetchone()[0]), 8)
                self.assertIsNone(connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='task_cancellations'").fetchone())

            store = SQLiteRuntimeStore(path)  # v9 code opens a v8 db -> migrates
            with self._raw_sqlite(str(path)) as connection:
                self.assertEqual(int(connection.execute("PRAGMA user_version").fetchone()[0]), SQLITE_SCHEMA_VERSION)
                self.assertIsNotNone(connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='task_cancellations'").fetchone())
            store.cancel_task("t1")
            self.assertTrue(store.is_task_cancelled("t1"))

    @unittest.skipUnless(
        os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available(),
        "needs a live Postgres (PORTMARK_TEST_POSTGRES_DSN)",
    )
    def test_postgres_v6_to_v7_upgrade_adds_cancellations(self):
        # Section 5 #3 (G8, upgrade path, Postgres). A v6 schema re-initialized by v7 code creates
        # task_cancellations idempotently and bumps the recorded version to 7.
        import psycopg
        dsn = os.environ["PORTMARK_TEST_POSTGRES_DSN"]
        schema = "portmark_upgrade_" + secrets.token_hex(8)
        try:
            PostgresRuntimeStore(dsn, schema=schema)  # full v7 schema
            with psycopg.connect(dsn) as connection:
                connection.execute(f'SET search_path TO "{schema}"')
                connection.execute("DROP TABLE task_cancellations")
                connection.execute("UPDATE portmark_schema SET version = 6")
                connection.commit()
            store = PostgresRuntimeStore(dsn, schema=schema)  # re-initialize as v7
            with psycopg.connect(dsn) as connection:
                connection.execute(f'SET search_path TO "{schema}"')
                version = connection.execute("SELECT version FROM portmark_schema").fetchone()[0]
                self.assertEqual(version, POSTGRES_SCHEMA_VERSION)
                exists = connection.execute(
                    "SELECT to_regclass(%s)", (f"{schema}.task_cancellations",)).fetchone()[0]
                self.assertIsNotNone(exists)
            store.cancel_task("t1")
            self.assertTrue(store.is_task_cancelled("t1"))
        finally:
            self._drop_postgres_schema(dsn, schema)

    def test_effect_ledger_store_round_trip_on_both_backends(self):
        # Section 7 PR 2a (G2): the effect-ledger store methods on SQLite AND Postgres. Exercises the
        # ON CONFLICT DO NOTHING idempotency, the state=prepared-guarded start, and the settle path,
        # so the Postgres arm is not left unrun until CI.
        for context in self._store_case_contexts():
            with context as (backend, store), self.subTest(backend=backend):
                self.assertIsNone(store.get_effect("e1"))
                store.record_effect_prepared("e1", "task1", "pay", '{"amount": 5}')
                self.assertEqual(store.get_effect("e1")["state"], "prepared")
                store.record_effect_prepared("e1", "task1", "pay", '{"amount": 9}')  # idempotent
                self.assertEqual(store.get_effect("e1")["arguments_json"], '{"amount": 5}')  # kept first
                store.mark_effect_started("e1")
                self.assertEqual(store.get_effect("e1")["state"], "started")
                store.settle_effect("e1", "confirmed", '{"ok": true}', None)
                row = store.get_effect("e1")
                self.assertEqual(row["state"], "confirmed")
                self.assertEqual(row["result_json"], '{"ok": true}')

    @unittest.skipUnless(
        os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available(),
        "needs a live Postgres (PORTMARK_TEST_POSTGRES_DSN)",
    )
    def test_postgres_v7_to_v8_upgrade_adds_tool_effects(self):
        # Section 7 PR 2a (G2, upgrade path, Postgres). A v7 schema re-initialized by v8 code creates
        # tool_effects idempotently and bumps the recorded version to 8.
        import psycopg
        dsn = os.environ["PORTMARK_TEST_POSTGRES_DSN"]
        schema = "portmark_upgrade_" + secrets.token_hex(8)
        try:
            PostgresRuntimeStore(dsn, schema=schema)  # full v8 schema
            with psycopg.connect(dsn) as connection:
                connection.execute(f'SET search_path TO "{schema}"')
                connection.execute("DROP TABLE tool_effects")
                connection.execute("UPDATE portmark_schema SET version = 7")
                connection.commit()
            store = PostgresRuntimeStore(dsn, schema=schema)  # re-initialize as v8
            with psycopg.connect(dsn) as connection:
                connection.execute(f'SET search_path TO "{schema}"')
                version = connection.execute("SELECT version FROM portmark_schema").fetchone()[0]
                self.assertEqual(version, POSTGRES_SCHEMA_VERSION)
                exists = connection.execute(
                    "SELECT to_regclass(%s)", (f"{schema}.tool_effects",)).fetchone()[0]
                self.assertIsNotNone(exists)
            store.record_effect_prepared("e1", "t1", "pay", "{}")
            self.assertEqual(store.get_effect("e1")["state"], "prepared")
        finally:
            self._drop_postgres_schema(dsn, schema)

    @unittest.skipUnless(
        os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available(),
        "needs a live Postgres (PORTMARK_TEST_POSTGRES_DSN)",
    )
    def test_postgres_v8_to_v9_adds_reconcile_lease_columns(self):
        # Section 7 PR 2 (round 3, Postgres upgrade path). A v8 schema (tool_effects WITHOUT the owned-
        # lease columns) re-initialized by v9 code ADDs reconcile_claim_id + reconcile_lease_expires_at
        # idempotently and bumps the recorded version to 9. A pre-existing row upgrades and is claimable.
        import psycopg
        dsn = os.environ["PORTMARK_TEST_POSTGRES_DSN"]
        schema = "portmark_upgrade_" + secrets.token_hex(8)
        try:
            store = PostgresRuntimeStore(dsn, schema=schema)  # full v9 schema
            store.record_effect_prepared("e1", "t1", "pay", "{}")
            with psycopg.connect(dsn) as connection:  # roll back to look like v8
                connection.execute(f'SET search_path TO "{schema}"')
                connection.execute("ALTER TABLE tool_effects DROP COLUMN reconcile_claim_id")
                connection.execute("ALTER TABLE tool_effects DROP COLUMN reconcile_lease_expires_at")
                connection.execute("UPDATE portmark_schema SET version = 8")
                connection.commit()
            store = PostgresRuntimeStore(dsn, schema=schema)  # re-initialize as v9
            with psycopg.connect(dsn) as connection:
                connection.execute(f'SET search_path TO "{schema}"')
                version = connection.execute("SELECT version FROM portmark_schema").fetchone()[0]
                self.assertEqual(version, POSTGRES_SCHEMA_VERSION)
                columns = {row[0] for row in connection.execute(
                    "SELECT column_name FROM information_schema.columns WHERE table_schema = %s AND table_name = 'tool_effects'",
                    (schema,)).fetchall()}
                self.assertIn("reconcile_claim_id", columns)
                self.assertIn("reconcile_lease_expires_at", columns)
            store.mark_effect_started("e1")
            store.settle_effect("e1", "unknown", None, "kill")
            self.assertTrue(store.claim_effect_for_reconcile("e1", "owner-1", 300))
            self.assertEqual(store.get_effect("e1")["reconcile_claim_id"], "owner-1")
        finally:
            self._drop_postgres_schema(dsn, schema)

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
        # Finding EV-008: after the task completes, its checkpoint is closed, so a
        # replay of the original envelope is rejected at admission by the
        # checkpoint-generation guard -- before any provider or tool runs -- rather
        # than later by the permit nonce. A finished task must never re-run.
        host = make_host()
        envelope = make_demo_envelope(host, "goal")
        host.run(envelope)
        envelope.state.status = "ready"
        host.signer.seal(envelope)
        with self.assertRaisesRegex(SecurityError, "closed"):
            host.run(envelope)

    def test_forged_running_status_still_consumes_nonce_on_first_run(self):
        # Finding #2: an issuer must not skip nonce consumption by signing a FIRST
        # submission with a non-"ready" status. Pre-fix, any status other than
        # "ready" meant "resume, do not consume", so the permit's nonce was never
        # spent and the permit could be replayed. The fix only treats a run as a
        # resume when a checkpoint already exists, so a first submission consumes
        # the nonce no matter what status it claims.
        host = make_host()
        envelope = make_demo_envelope(host, "goal")
        envelope.state.status = "running"  # forged on the very first submission
        host.signer.seal(envelope)
        host.run(envelope)

        # A different task reusing the same permit nonce must now be rejected.
        replay = make_demo_envelope(host, "goal")
        object.__setattr__(replay.permit, "nonce", envelope.permit.nonce)
        replay.state.task_id = "a-different-task"
        host.signer.seal(replay)
        with self.assertRaisesRegex(SecurityError, "nonce"):
            host.run(replay)

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

    @contextmanager
    def _raw_sqlite(self, path):
        # Tests that open a raw connection to inspect or tamper with the store must
        # close it, or Windows keeps the database file open and its temp dir cannot
        # be deleted. sqlite3's own `with connection` commits but never closes.
        created = not os.path.exists(path)
        connection = sqlite3.connect(path)
        if created:
            # A legacy database built here stands in for an operator's file, which the store
            # requires to be owner-only (Section 11 #5).
            os.chmod(path, 0o600)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

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

    @unittest.skipUnless(
        os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available(),
        "requires a real PostgreSQL",
    )
    def test_renew_effect_claim_on_postgres_uses_database_time(self):  # G22 Postgres (DB-time path)
        # The DB-time renew statement (EXTRACT(EPOCH FROM clock_timestamp())) is a DIFFERENT code path
        # from the injected-clock embedded stores, so exercise it against a live Postgres with a short
        # REAL lease (auditor round-3 coverage note). Mirrors the SQLite/InMemory renew race: renew
        # extends an owned claim, refuses a foreign claim, and -- once the lease expires and a reclaimer
        # takes the row -- refuses the superseded holder (which must then NOT run its reconcile). The
        # sleep is longer than the lease, so expiry is deterministic on wall-clock/DB time.
        dsn = os.environ["PORTMARK_TEST_POSTGRES_DSN"]
        schema = "portmark_renew_" + secrets.token_hex(8)
        try:
            store = PostgresRuntimeStore(dsn, schema=schema)
            store.record_effect_prepared("e", "t", "iso.charge", "{}")
            store.mark_effect_started("e")
            store.settle_effect("e", "unknown", None, "kill")
            self.assertTrue(store.claim_effect_for_reconcile("e", "A", 1))     # ~1s lease (database time)
            self.assertTrue(store.renew_effect_claim("e", "A", 1))             # the owner can renew
            self.assertFalse(store.renew_effect_claim("e", "WRONG", 1))        # a foreign claim is refused
            time.sleep(1.4)                                                    # A's renewed lease expires
            self.assertTrue(store.claim_effect_for_reconcile("e", "B", 5))     # B reclaims -> new owner id
            self.assertEqual(store.get_effect("e")["reconcile_claim_id"], "B")
            self.assertFalse(store.renew_effect_claim("e", "A", 1))            # superseded holder -> aborts (no concurrent run)
            self.assertTrue(store.renew_effect_claim("e", "B", 5))             # the live owner can renew
        finally:
            self._drop_postgres_schema(dsn, schema)

    def _reopen_store(self, backend, store, verifier=None):
        if backend == "sqlite":
            return SQLiteRuntimeStore(store.path, verifier)
        return PostgresRuntimeStore(store.dsn, verifier, schema=store.schema)

    def _corrupt_store_audit(self, store, task_id, backend):
        if backend == "sqlite":
            with self._raw_sqlite(store.path) as connection:
                connection.execute("UPDATE audit_heads SET head_hash = 'tampered' WHERE task_id = ?", (task_id,))
            return
        with store._connect() as connection:
            connection.execute("UPDATE audit_heads SET head_hash = 'tampered' WHERE task_id = %s", (task_id,))
            connection.commit()

    def _tamper_store_host_id(self, store, task_id, backend):
        if backend == "sqlite":
            with self._raw_sqlite(store.path) as connection:
                connection.execute(
                    "UPDATE audit_events SET host_id = 'host:impostor' WHERE task_id = ? AND sequence = 0", (task_id,)
                )
            return
        with store._connect() as connection:
            connection.execute(
                "UPDATE audit_events SET host_id = 'host:impostor' WHERE task_id = %s AND sequence = 0", (task_id,)
            )
            connection.commit()

    def test_runtime_store_contract_persists_checkpoint_audit_and_three_state_verification(self):
        signer = EnvelopeSigner.generate("contract-key", "host:local-demo", ("host:local-demo",))
        for context in self._store_case_contexts(signer):
            with context as (backend, store):
                with self.subTest(backend=backend):
                    host = make_host(signer=signer, store=store, allow_ephemeral_signing_key=True)
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
                    host = make_host(signer=signer, store=store, allow_ephemeral_signing_key=True)
                    envelope = make_demo_envelope(host, f"{backend} race")

                    def run_once():
                        local_store = self._reopen_store(backend, store, signer)
                        local_host = make_host(signer=signer, store=local_store, allow_ephemeral_signing_key=True)
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
                    host = make_host(signer=signer, store=store, allow_ephemeral_signing_key=True)
                    result = host.run(make_demo_envelope(host, f"{backend} corrupt"))
                    self.assertTrue(store.verify_audit_chain(result.task_id))
                    self._corrupt_store_audit(store, result.task_id, backend)
                    verification = store.verify_audit_chain_status(result.task_id)
                    self.assertEqual(verification.status, "invalid")
                    self.assertEqual(verification.reason, "stored audit head does not match audit events")
                    self.assertFalse(store.verify_audit_chain(result.task_id))

    def test_runtime_store_contract_detects_audit_host_id_tamper(self):
        # Altering a stored event's host_id must break verification: host_id is
        # inside the per-event hash (finding #7). Without that, attribution could
        # be rewritten while the chain still verified.
        signer = EnvelopeSigner.generate("contract-host-key", "host:local-demo", ("host:local-demo",))
        for context in self._store_case_contexts(signer):
            with context as (backend, store):
                with self.subTest(backend=backend):
                    host = make_host(signer=signer, store=store, allow_ephemeral_signing_key=True)
                    result = host.run(make_demo_envelope(host, f"{backend} host tamper"))
                    self.assertTrue(store.verify_audit_chain(result.task_id))
                    self._tamper_store_host_id(store, result.task_id, backend)
                    verification = store.verify_audit_chain_status(result.task_id)
                    self.assertEqual(verification.status, "invalid")
                    self.assertEqual(verification.reason, "audit event hash is invalid")
                    self.assertFalse(store.verify_audit_chain(result.task_id))

    def test_audit_event_hash_commits_to_format_version(self):
        # The per-event hash covers hash_version, so the audit format is
        # self-describing and a future format change stays backward compatible.
        signer = EnvelopeSigner.generate("contract-version-key", "host:local-demo", ("host:local-demo",))
        host = make_host(signer=signer)
        result = host.run(make_demo_envelope(host, "version tag"))
        first = result.audit[0]
        versioned = audit_event_record(
            first["sequence"], first["event"], first["details"], first["previous"], "host:local-demo", AUDIT_HASH_VERSION
        )
        self.assertEqual(first["hash"], hashlib.sha256(canonical_json(versioned)).hexdigest())
        self.assertEqual(versioned["hash_version"], AUDIT_HASH_VERSION)
        # A record WITHOUT the version tag (the pre-versioning format) hashes
        # differently, proving the tag is actually committed to the bytes.
        untagged = {k: v for k, v in versioned.items() if k != "hash_version"}
        self.assertNotEqual(first["hash"], hashlib.sha256(canonical_json(untagged)).hexdigest())

    def test_runtime_store_contract_recovers_migration_checkpoints_and_audits(self):
        source_signer = EnvelopeSigner.generate("contract-source-key", "host:source", ("host:source", "host:destination"))
        destination_signer = trust_signer(
            EnvelopeSigner.generate("contract-destination-key", "host:destination", ("host:destination",)),
            source_signer,
        )
        for context in self._dual_store_case_contexts(source_signer, destination_signer):
            with context as (backend, source_store, destination_store):
                with self.subTest(backend=backend):
                    source = make_host(host_id="host:source", signer=source_signer, store=source_store, allow_ephemeral_signing_key=True)
                    destination = make_host(host_id="host:destination", signer=destination_signer, store=destination_store, allow_ephemeral_signing_key=True)
                    source.policy.migration = MigrationPolicy(allowed=True, destinations=(destination.host_id,))
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

                    migrated = envelope_from_dict(first.migration_envelope)
                    second = destination.run(migrated)
                    self.assertEqual(second.status, "completed")
                    self.assertEqual(destination_store.load_checkpoint(second.task_id)["status"], "completed")
                    self.assertTrue(destination_store.verify_audit_chain(second.task_id))

                    # Finding #3: the destination's local sequence restarts at 0, so
                    # the verified prior anchor is recorded in the first event's
                    # details (inside the hashed chain) instead of being discarded.
                    anchor = second.audit[0]["details"]["migration"]
                    self.assertEqual(anchor["previous_audit_hash"], migrated.previous_audit_hash)
                    self.assertEqual(anchor["previous_audit_sequence"], migrated.previous_audit_sequence)
                    self.assertEqual(anchor["previous_audit_host_id"], "host:source")
                    # The anchor ties this chain to the source's actual head hash.
                    self.assertEqual(anchor["previous_audit_hash"], first.audit[-1]["hash"])

    # -- Section 10 F3: verification reads events and head from ONE snapshot -----------------
    class _InterleavingConnection:
        """Wraps a real store connection and runs `hook` right after the audit_events read
        returns, before the audit_heads read -- the exact interleaving the auditor used."""

        def __init__(self, inner, hook):
            object.__setattr__(self, "_inner", inner)
            object.__setattr__(self, "_hook", hook)

        def execute(self, query, *args):
            cursor = self._inner.execute(query, *args)
            if "FROM audit_events" in query and self._hook is not None:
                rows = cursor.fetchall()
                hook = self._hook
                object.__setattr__(self, "_hook", None)
                hook()
                return types.SimpleNamespace(fetchall=lambda: rows, fetchone=lambda: rows[0] if rows else None)
            return cursor

        def __enter__(self):
            self._inner.__enter__()
            return self

        def __exit__(self, *exc):
            return self._inner.__exit__(*exc)

        def __getattr__(self, name):
            return getattr(self._inner, name)

        def __setattr__(self, name, value):
            setattr(self._inner, name, value)

    def _commit_one_more_audit_event(self, store, task_id, host_id, signer):
        head_hash, sequence = store.audit_head(task_id)
        log = AuditLog(head_hash, sequence, host_id)
        log.append("interleaved.write", {"note": "committed between the two verification reads"})
        signed_at = int(time.time())
        with store.transaction() as transaction:
            transaction.append_audit_events(
                task_id,
                host_id,
                log.events,
                lambda head, seq: (signer.key_id, signer.sign_audit_head(task_id, host_id, head, seq, signed_at=signed_at), signed_at),
            )

    def test_verify_audit_reads_events_and_head_from_one_snapshot_under_a_concurrent_commit(self):
        signer = EnvelopeSigner.generate("snapshot-key", "host:local-demo", ("host:local-demo",))
        for context in self._store_case_contexts(signer):
            with context as (backend, store):
                with self.subTest(backend=backend):
                    host = make_host(signer=signer, store=store, allow_ephemeral_signing_key=True)
                    task_id = host.run(make_demo_envelope(host, f"{backend} snapshot")).task_id
                    _, before = store.audit_head(task_id)
                    original_connect = store._connect
                    armed = {"used": False}

                    def connect():
                        connection = original_connect()
                        if armed["used"]:
                            return connection
                        armed["used"] = True
                        return self._InterleavingConnection(
                            connection, lambda: self._commit_one_more_audit_event(store, task_id, host.host_id, signer)
                        )

                    with patch.object(store, "_connect", side_effect=connect):
                        interleaved = store.verify_audit_chain_status(task_id)
                    # The writer really committed between the reads...
                    self.assertEqual(store.audit_head(task_id)[1], before + 1)
                    # ...but the verifier saw one consistent snapshot (the pre-commit chain).
                    self.assertEqual(interleaved.status, "valid", interleaved.reason)
                    stable = store.verify_audit_chain_status(task_id)
                    self.assertEqual(stable.status, "valid", stable.reason)

    # -- Section 10 F2: the destination keeps the source's migration proof -------------------
    def _migrate_once(self, backend, source_store, destination_store, source_signer, destination_signer):
        source = make_host(host_id="host:source", signer=source_signer, store=source_store, allow_ephemeral_signing_key=True)
        destination = make_host(host_id="host:destination", signer=destination_signer, store=destination_store, allow_ephemeral_signing_key=True)
        source.policy.migration = MigrationPolicy(allowed=True, destinations=(destination.host_id,))
        provider = MigrateThenCompleteProvider(destination.host_id)
        source.providers["migrator"] = provider
        destination.providers["migrator"] = provider
        envelope = make_demo_envelope(source, f"{backend} anchored migration", "migrator")
        object.__setattr__(envelope.permit, "delegation_allowed", True)
        source_signer.seal(envelope)
        first = source.run(envelope)
        migrated = envelope_from_dict(first.migration_envelope)
        second = destination.run(migrated)
        self.assertEqual(second.status, "completed")
        return envelope, migrated, second

    def _migration_signers(self, prefix):
        source_signer = EnvelopeSigner.generate(f"{prefix}-source-key", "host:source", ("host:source", "host:destination"))
        destination_signer = trust_signer(
            EnvelopeSigner.generate(f"{prefix}-destination-key", "host:destination", ("host:destination",)),
            source_signer,
        )
        return source_signer, destination_signer

    def test_migration_anchor_keeps_the_source_proof_and_reverifies_from_the_destination_alone(self):
        source_signer, destination_signer = self._migration_signers("anchor")
        for context in self._dual_store_case_contexts(source_signer, destination_signer):
            with context as (backend, source_store, destination_store):
                with self.subTest(backend=backend):
                    envelope, migrated, second = self._migrate_once(backend, source_store, destination_store, source_signer, destination_signer)
                    anchor = second.audit[0]["details"]["migration"]
                    self.assertEqual(anchor["previous_audit_task_id"], envelope.state.task_id)
                    self.assertEqual(anchor["previous_audit_signature_key_id"], source_signer.key_id)
                    self.assertEqual(anchor["previous_audit_signature"], migrated.previous_audit_signature)

                    verified = destination_store.verify_audit_chain_status(second.task_id)
                    self.assertEqual((verified.status, verified.anchor_status), ("valid", "verified"), verified.reason)

                    # An independent auditor holding ONLY the destination database and a trust
                    # registry (no source store, no host objects) re-validates the source proof.
                    auditor_registry = TrustRegistry((trusted_identity_for(destination_signer), trusted_identity_for(source_signer)))
                    if backend == "sqlite":
                        auditor_store = SQLiteRuntimeStore(destination_store.path, auditor_registry)
                    else:
                        auditor_store = PostgresRuntimeStore(destination_store.dsn, auditor_registry, schema=destination_store.schema)
                    audited = auditor_store.verify_audit_chain_status(second.task_id)
                    self.assertEqual((audited.status, audited.anchor_status), ("valid", "verified"), audited.reason)

                    # The source key is revoked later: the v1 migration head carries no signing
                    # time, so the anchor can no longer be shown to predate the compromise.
                    revoked = dataclasses.replace(trusted_identity_for(source_signer), revoked=True)
                    revoked_registry = TrustRegistry((trusted_identity_for(destination_signer), revoked))
                    auditor_store.set_audit_head_verifier(revoked_registry)
                    after_revocation = auditor_store.verify_audit_chain_status(second.task_id)
                    self.assertEqual((after_revocation.status, after_revocation.anchor_status), ("invalid", "invalid"))
                    self.assertIn("revoked-key-legacy-v1", after_revocation.reason)

                    # A source key scoped to audit-only cannot stand as a migration proof.
                    audit_only = dataclasses.replace(trusted_identity_for(source_signer), usages=("audit",))
                    auditor_store.set_audit_head_verifier(TrustRegistry((trusted_identity_for(destination_signer), audit_only)))
                    wrong_usage = auditor_store.verify_audit_chain_status(second.task_id)
                    self.assertEqual((wrong_usage.status, wrong_usage.anchor_status), ("invalid", "invalid"))
                    self.assertIn("usage-violation", wrong_usage.reason)

    @contextmanager
    def _migrated_chain_with_anchor(self, prefix, rewrite_anchor):
        # A REAL destination chain (hashed and head-signed by the destination) whose event-0
        # anchor was written by `rewrite_anchor` -- e.g. a pre-Section-10 host's 3-field anchor.
        source_signer, destination_signer = self._migration_signers(prefix)
        original_audit_start = AgentHost._audit_start

        def audit_start(host, envelope, original_task_id):
            previous_hash, start, anchor = original_audit_start(host, envelope, original_task_id)
            return previous_hash, start, (rewrite_anchor(anchor) if anchor is not None else None)

        with self._sqlite_dual_store_case(source_signer, destination_signer) as (backend, source_store, destination_store):
            with patch.object(AgentHost, "_audit_start", audit_start):
                _, _, second = self._migrate_once(backend, source_store, destination_store, source_signer, destination_signer)
            yield destination_store, second, source_signer, destination_signer

    @staticmethod
    def _legacy_anchor(anchor):
        return {key: anchor[key] for key in ("previous_audit_hash", "previous_audit_sequence", "previous_audit_host_id")}

    def test_legacy_migration_anchor_is_unverifiable_by_default_and_valid_only_with_the_override(self):
        # A chain written before Section 10 has the 3-field anchor: no source proof to re-check.
        # Secure default: unverifiable (CLI exit 2). The compatibility override accepts it as valid
        # but keeps anchor_status legacy-anchor and says the proof was NOT reverified. No hash-format
        # bump is needed: the recompute uses the stored details.
        with self._migrated_chain_with_anchor("legacy-anchor", self._legacy_anchor) as (store, second, _, _):
            self.assertNotIn("previous_audit_signature", second.audit[0]["details"]["migration"])
            refused = store.verify_audit_chain_status(second.task_id)
            self.assertEqual((refused.status, refused.anchor_status), ("unverifiable", "legacy-anchor"), refused.reason)
            self.assertIn("cannot be independently reverified", refused.reason)
            self.assertFalse(store.verify_audit_chain(second.task_id))
            allowed = store.verify_audit_chain_status(second.task_id, allow_legacy_anchor=True)
            self.assertEqual((allowed.status, allowed.anchor_status), ("valid", "legacy-anchor"), allowed.reason)
            self.assertIn("NOT independently reverified", allowed.reason)
            self.assertNotEqual(allowed.anchor_status, "verified")

    def test_verify_audit_cli_refuses_legacy_anchor_by_default_and_warns_on_the_override(self):
        with self._migrated_chain_with_anchor("legacy-cli", self._legacy_anchor) as (store, second, source_signer, destination_signer):
            registry_path = Path(store.path).parent / "trust.json"
            registry_path.write_text(json.dumps({"identities": [
                {
                    "key_id": signer.key_id,
                    "issuer": signer.issuer,
                    "public_key_b64": base64.urlsafe_b64encode(signer.public_key_bytes()).decode("ascii").rstrip("="),
                    "allowed_audiences": ["*"],
                }
                for signer in (source_signer, destination_signer)
            ]}), encoding="utf-8")
            argv = ["portmark", "--store-path", str(store.path), "--trust-registry-path", str(registry_path), "verify-audit", "--task-id", second.task_id]

            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(sys, "argv", argv), redirect_stdout(stdout), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    cli_main()
            self.assertEqual(raised.exception.code, 2)
            report = json.loads(stdout.getvalue())
            self.assertEqual((report["status"], report["anchor_status"]), ("unverifiable", "legacy-anchor"))
            self.assertEqual(stderr.getvalue(), "")

            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(sys, "argv", argv + ["--allow-legacy-anchor"]), redirect_stdout(stdout), redirect_stderr(stderr):
                cli_main()  # exit 0: no SystemExit
            report = json.loads(stdout.getvalue())  # stdout stays ONE valid JSON document
            self.assertEqual((report["status"], report["anchor_status"]), ("valid", "legacy-anchor"))
            self.assertIn("NOT independently reverified", report["reason"])
            self.assertIn("WARNING: --allow-legacy-anchor is a temporary migration-compatibility mode", stderr.getvalue())

    def test_override_never_rescues_a_partial_or_malformed_anchor(self):
        # Partial modern proofs (a real, destination-signed chain) stay invalid, exit 1, even with
        # the override: the flag covers only COMPLETE pre-Section-10 anchors.
        partials = {
            "missing-signature": lambda anchor: {k: v for k, v in anchor.items() if k != "previous_audit_signature"},
            "proof-only-key-id": lambda anchor: {**self._legacy_anchor(anchor), "previous_audit_signature_key_id": anchor["previous_audit_signature_key_id"]},
            "legacy-bad-sequence": lambda anchor: {**self._legacy_anchor(anchor), "previous_audit_sequence": True},
            "legacy-extra-key": lambda anchor: {**self._legacy_anchor(anchor), "note": "x"},
            "modern-extra-key": lambda anchor: {**anchor, "note": "unsigned-by-source"},
        }
        for label, rewrite in partials.items():
            with self.subTest(anchor=label):
                with self._migrated_chain_with_anchor(f"partial-{label}", rewrite) as (store, second, _, _):
                    for allow in (False, True):
                        result = store.verify_audit_chain_status(second.task_id, allow_legacy_anchor=allow)
                        self.assertEqual((result.status, result.anchor_status), ("invalid", "invalid"), result.reason)

    def test_stripping_the_anchor_proof_from_a_real_chain_is_tamper_not_legacy(self):
        # Legacy tolerance must not be a downgrade path: removing the proof fields from a real
        # Section 10 chain breaks event 0's hash, so it is reported as tampering, never as
        # `legacy-anchor`.
        source_signer, destination_signer = self._migration_signers("anchor-strip")
        with self._sqlite_dual_store_case(source_signer, destination_signer) as (backend, source_store, destination_store):
            _, _, second = self._migrate_once(backend, source_store, destination_store, source_signer, destination_signer)
            self.assertEqual(destination_store.verify_audit_chain_status(second.task_id).anchor_status, "verified")
            with self._raw_sqlite(destination_store.path) as connection:
                row = connection.execute(
                    "SELECT details_json FROM audit_events WHERE task_id = ? AND sequence = 0", (second.task_id,)
                ).fetchone()
                details = json.loads(row[0])
                for field in ("previous_audit_task_id", "previous_audit_signature_key_id", "previous_audit_signature"):
                    del details["migration"][field]
                connection.execute(
                    "UPDATE audit_events SET details_json = ? WHERE task_id = ? AND sequence = 0",
                    (json.dumps(details), second.task_id),
                )
            for allow in (False, True):
                stripped = destination_store.verify_audit_chain_status(second.task_id, allow_legacy_anchor=allow)
                self.assertEqual((stripped.status, stripped.reason), ("invalid", "audit event hash is invalid"))
                self.assertNotEqual(stripped.anchor_status, "legacy-anchor")

    def test_in_memory_store_reverifies_the_migration_anchor(self):
        source_signer, destination_signer = self._migration_signers("anchor-memory")
        source_store, destination_store = InMemoryRuntimeStore(), InMemoryRuntimeStore()
        _, _, second = self._migrate_once("memory", source_store, destination_store, source_signer, destination_signer)
        destination_store.set_audit_head_verifier(TrustRegistry((trusted_identity_for(destination_signer), trusted_identity_for(source_signer))))
        verified = destination_store.verify_audit_chain_status(second.task_id)
        self.assertEqual((verified.status, verified.anchor_status), ("valid", "verified"), verified.reason)
        revoked = dataclasses.replace(trusted_identity_for(source_signer), revoked=True)
        destination_store.set_audit_head_verifier(TrustRegistry((trusted_identity_for(destination_signer), revoked)))
        after_revocation = destination_store.verify_audit_chain_status(second.task_id)
        self.assertEqual((after_revocation.status, after_revocation.anchor_status), ("invalid", "invalid"))

    def test_migration_anchor_check_rejects_each_altered_or_missing_proof_field(self):
        from portmark.storage import AuditVerificationResult, _check_migration_anchor

        source_signer, destination_signer = self._migration_signers("anchor-fields")
        with self._sqlite_dual_store_case(source_signer, destination_signer) as (backend, source_store, destination_store):
            _, _, second = self._migrate_once(backend, source_store, destination_store, source_signer, destination_signer)
        anchor = second.audit[0]["details"]["migration"]
        registry = TrustRegistry((trusted_identity_for(destination_signer), trusted_identity_for(source_signer)))
        head_ok = AuditVerificationResult("valid", "audit head verified", "valid")
        self.assertEqual(_check_migration_anchor(registry, head_ok, {"migration": anchor}).anchor_status, "verified")
        self.assertEqual(_check_migration_anchor(registry, head_ok, {"agent": "x"}).anchor_status, "none")
        altered = {
            "previous_audit_hash": "0" * 64,
            "previous_audit_sequence": anchor["previous_audit_sequence"] + 1,
            "previous_audit_host_id": "host:destination",
            "previous_audit_task_id": "some-other-task",
            "previous_audit_signature_key_id": destination_signer.key_id,
            "previous_audit_signature": destination_signer.sign_audit_head("t", "host:destination", "0" * 64, 1),
        }
        for field, value in altered.items():
            with self.subTest(altered=field):
                result = _check_migration_anchor(registry, head_ok, {"migration": {**anchor, field: value}})
                self.assertEqual((result.status, result.anchor_status), ("invalid", "invalid"), result.reason)
        for field in ("previous_audit_task_id", "previous_audit_signature_key_id", "previous_audit_signature", "previous_audit_hash"):
            with self.subTest(missing=field):
                partial = {key: value for key, value in anchor.items() if key != field}
                for allow in (False, True):
                    result = _check_migration_anchor(registry, head_ok, {"migration": partial}, allow)
                    self.assertEqual((result.status, result.anchor_status), ("invalid", "invalid"), result.reason)
        for bad_sequence in (True, 0, "3"):
            with self.subTest(sequence=bad_sequence):
                result = _check_migration_anchor(registry, head_ok, {"migration": {**anchor, "previous_audit_sequence": bad_sequence}})
                self.assertEqual(result.status, "invalid")
        # A failing head is never upgraded by the anchor check.
        head_bad = AuditVerificationResult("invalid", "stored audit head does not match audit events")
        self.assertIs(_check_migration_anchor(registry, head_bad, {"migration": anchor}), head_bad)

    def test_migration_payload_is_projected_to_destination_grants(self):
        # Section 4 #6 (payload confidentiality). A tool result carries fields beyond
        # the grant's output_projection ceiling. The provider path already enforces that
        # ceiling, but a migration used to seal the FULL raw state, so the withheld
        # fields crossed the trust boundary to the destination host inside both
        # state.memory["tool_results"] and the tool messages. Per-destination projection:
        # the source reduces the migrated payload to the destination's entitlement (the
        # delegated permit's grants, minted with audience == destination) BEFORE sealing.
        # Here catalog.search returns id/title/SCORE and the grant projects to id/title,
        # so "score" must be absent everywhere in the sealed envelope AND the outbox row.
        source_signer = EnvelopeSigner.generate("conf-source-key", "host:source", ("host:source", "host:destination"))
        destination_signer = trust_signer(
            EnvelopeSigner.generate("conf-destination-key", "host:destination", ("host:destination",)),
            source_signer,
        )
        for context in self._dual_store_case_contexts(source_signer, destination_signer):
            with context as (backend, source_store, destination_store):
                with self.subTest(backend=backend):
                    source = make_host(host_id="host:source", signer=source_signer, store=source_store, allow_ephemeral_signing_key=True)
                    destination = make_host(host_id="host:destination", signer=destination_signer, store=destination_store, allow_ephemeral_signing_key=True)
                    source.policy.migration = MigrationPolicy(allowed=True, destinations=(destination.host_id,))
                    provider = SearchThenMigrateProvider(destination.host_id)
                    source.providers["migrator"] = provider
                    destination.providers["migrator"] = provider
                    envelope = make_demo_envelope(source, f"{backend} confidentiality", "migrator")
                    object.__setattr__(envelope.permit, "delegation_allowed", True)
                    source_signer.seal(envelope)

                    first = source.run(envelope)
                    self.assertEqual(source_store.load_checkpoint(first.task_id)["status"], "ready")
                    self.assertIsNotNone(first.migration_envelope)

                    # The source ran the tool: its OWN durable checkpoint keeps the full,
                    # unprojected result (projection reduces the migrated copy, not the
                    # source's records).
                    source_results = source_store.load_checkpoint(first.task_id)["memory"]["tool_results"]["catalog.search"]
                    self.assertTrue(all("score" in item for item in source_results))

                    # The withheld field must not cross to the destination anywhere in the
                    # sealed envelope (memory["tool_results"] AND the tool messages), and the
                    # granted fields must still be present so the destination can resume.
                    sealed = first.migration_envelope
                    self.assertFalse(_json_contains_key(sealed["state"], "score"))
                    migrated_results = sealed["state"]["memory"]["tool_results"]["catalog.search"]
                    self.assertTrue(all(set(item.keys()) == {"id", "title"} for item in migrated_results))
                    tool_messages = [m for m in sealed["state"]["messages"] if m.get("role") == "tool"]
                    self.assertTrue(tool_messages)
                    self.assertFalse(any(_json_contains_key(m, "score") for m in tool_messages))

                    # The durable outbox row is the same projected bytes (nothing leaks by
                    # the delivery path either).
                    row = source_store.list_pending_migrations()[0]
                    self.assertNotIn("score", row["sealed_envelope_json"])
                    self.assertEqual(row["sealed_envelope_json"], canonical_json(first.migration_envelope).decode("utf-8"))

                    # End-to-end: the projected envelope still admits and completes at the
                    # destination, and its audit chain verifies.
                    migrated = envelope_from_dict(first.migration_envelope)
                    second = destination.run(migrated)
                    self.assertEqual(second.status, "completed")
                    self.assertEqual(destination_store.load_checkpoint(second.task_id)["status"], "completed")
                    self.assertTrue(destination_store.verify_audit_chain(second.task_id))

    def test_project_state_for_migration_branches(self):
        # Section 4 #6 unit pins for project_state_for_migration:
        #  - a GRANTED tool's output is reduced to its projection in BOTH memory and the
        #    tool message;
        #  - a tool with NO destination grant is dropped from both;
        #  - NON-tool (user/assistant) messages are kept in full (resumption continuity);
        #  - a SHARE-NOTHING grant (empty projection) reduces the output to a falsy-but-
        #    present {} rather than dropping the key -- the deliberate, documented
        #    consequence, identical to the provider path.
        state = AgentState(
            task_id="t1",
            goal="do the thing",
            memory={
                "tool_results": {
                    "keep.tool": {"public": "shown", "withheld_field": "not-for-destination"},
                    "drop.tool": {"anything": "ungranted"},
                    "empty.tool": {"whatever": "held-back"},
                },
                "other": "kept-verbatim",
            },
            messages=[
                {"role": "user", "content": "the original prompt"},
                {"role": "assistant", "content": "thinking"},
                {"role": "tool", "name": "keep.tool", "content": {"public": "shown", "withheld_field": "not-for-destination"}},
                {"role": "tool", "name": "drop.tool", "content": {"anything": "ungranted"}},
                {"role": "tool", "name": "empty.tool", "content": {"whatever": "held-back"}},
            ],
        )
        grants = (
            ToolGrant("keep.tool", output_projection=("public",)),
            ToolGrant("empty.tool", output_projection=()),
        )
        projected = project_state_for_migration(state, grants)

        # Granted tool reduced to its ceiling; withheld field gone; ungranted tool dropped.
        self.assertEqual(projected.memory["tool_results"]["keep.tool"], {"public": "shown"})
        self.assertNotIn("drop.tool", projected.memory["tool_results"])
        # Share-nothing keeps the key with a falsy-but-present {} (documented consequence).
        self.assertEqual(projected.memory["tool_results"]["empty.tool"], {})
        # Non-tool_results memory is carried verbatim.
        self.assertEqual(projected.memory["other"], "kept-verbatim")

        # Non-tool messages kept verbatim; granted tool message reduced; ungranted dropped.
        self.assertEqual(projected.messages[0], {"role": "user", "content": "the original prompt"})
        self.assertEqual(projected.messages[1], {"role": "assistant", "content": "thinking"})
        tool_messages = [m for m in projected.messages if m.get("role") == "tool"]
        self.assertEqual({m["name"] for m in tool_messages}, {"keep.tool", "empty.tool"})
        keep_msg = next(m for m in tool_messages if m["name"] == "keep.tool")
        self.assertEqual(keep_msg["content"], {"public": "shown"})
        empty_msg = next(m for m in tool_messages if m["name"] == "empty.tool")
        self.assertEqual(empty_msg["content"], {})

        # The source's own state is untouched (projection returns a copy).
        self.assertIn("withheld_field", state.memory["tool_results"]["keep.tool"])
        self.assertEqual(len(state.messages), 5)

    def test_project_state_for_migration_fails_closed_on_malformed_tool_results(self):
        # Section 4 #6 fail-closed: a confidentiality boundary must not pass unknown
        # shapes through. tool_results is normally a dict, but a signed/imported or
        # legacy state can carry any JSON value. A non-dict tool_results cannot be
        # projected per-grant, so it must be DROPPED (replaced with {}), never crossed
        # unchanged. The KEY presence is preserved (replaced, not deleted) so a resumer
        # sees an empty-but-present results bag rather than a missing one.
        for malformed in ([{"leaked": "not-for-destination"}], "opaque-blob", 42, None):
            with self.subTest(shape=type(malformed).__name__):
                state = AgentState(
                    task_id="t2",
                    goal="malformed",
                    memory={"tool_results": malformed, "other": "kept"},
                    messages=[],
                )
                projected = project_state_for_migration(state, (ToolGrant("any.tool", output_projection=("x",)),))
                self.assertEqual(projected.memory["tool_results"], {})
                self.assertEqual(projected.memory["other"], "kept")

    def test_provider_view_fails_closed_on_malformed_tool_results(self):
        # finding #2/#4: the canonical ProviderView must fail closed on a non-dict
        # tool_results (a captured/crafted wire state), dropping it to {} rather than
        # letting the raw value reach the provider unprojected -- AND it carries no
        # `memory` at all, so the sibling `other` bookkeeping key cannot leak either.
        for malformed in ([{"leaked": "not-for-provider"}], "opaque-blob", 42, None):
            with self.subTest(shape=type(malformed).__name__):
                state = AgentState(
                    task_id="p1",
                    goal="malformed",
                    memory={"tool_results": malformed, "other": "kept"},
                    messages=[],
                )
                view = provider_view(state, (ToolGrant("any.tool", output_projection=("x",)),))
                self.assertEqual(dict(view.tool_results), {})
                self.assertFalse(hasattr(view, "memory"))

    def test_provider_view_detach_identity_under_star_projection(self):
        # finding #2, the subtle half: even under a `*` projection -- where
        # project_tool_output returns the LIVE result object verbatim -- the view must not
        # alias live host state. A top-level copy alone is not enough; a deep detach is.
        live_result = {"id": "1", "detail": "x"}
        state = AgentState("t", "g", memory={"tool_results": {"catalog.search": live_result}})
        view = provider_view(state, (ToolGrant("catalog.search", output_projection=("*",)),))
        # Same VALUE (star reveals everything) ...
        self.assertEqual(dict(view.tool_results["catalog.search"]), live_result)
        # ... but a DIFFERENT object: no alias survives the deep detach.
        self.assertIsNot(view.tool_results["catalog.search"], live_result)
        # Proof it is isolated: mutating the view's copy leaves live state untouched.
        view.tool_results["catalog.search"]["detail"] = "TAMPERED"
        self.assertEqual(state.memory["tool_results"]["catalog.search"]["detail"], "x")

    def test_hostile_provider_cannot_mutate_view_or_live_state(self):
        # finding #2 core: a buggy or hostile IN-PROCESS provider must not corrupt the
        # host's live state. The view is a frozen dataclass (field reassignment raises)
        # with read-only top-level containers (no tool_results key-add, no messages
        # append). Nested mutation of a value DOES succeed -- deliberately: a provider may
        # echo tool output into its own decision content, and the values are plain
        # deep-copies, so that write lands on a THROWAWAY copy, never on live host state.
        # The load-bearing assertion is the last one: live state is byte-identical after.
        state = AgentState(
            "t", "g",
            memory={
                "tool_results": {"catalog.search": {"id": "1"}},
                "used_approval_ids": ["a1"],           # host bookkeeping the old path leaked
                "approvals": {"payments.reserve": {}},  # ... and let a provider mutate
            },
            messages=[{"role": "tool", "name": "catalog.search", "content": {"id": "1"}}],
        )
        before = canonical_json(asdict(state))
        view = provider_view(state, (ToolGrant("catalog.search", output_projection=("*",)),))

        with self.assertRaises(FrozenInstanceError):     # frozen: cannot reassign a field
            view.status = "completed"
        with self.assertRaises(TypeError):               # MappingProxyType: cannot add a key
            view.tool_results["evil"] = {}
        with self.assertRaises(AttributeError):          # tuple: cannot append a message
            view.messages.append({"role": "tool", "name": "x"})

        # The over-exposed bookkeeping the finding is about is simply ABSENT from the view.
        self.assertFalse(hasattr(view, "memory"))
        self.assertFalse(hasattr(view, "used_approval_ids"))
        self.assertFalse(hasattr(view, "approvals"))

        # Nested mutation succeeds on the throwaway copy (correct) ...
        view.tool_results["catalog.search"]["id"] = "TAMPERED"
        # ... and live host state is untouched by everything above.
        self.assertEqual(canonical_json(asdict(state)), before)

    def test_share_nothing_present_but_empty(self):
        # A granted tool with a share-nothing (omitted -> ()) projection keeps its KEY with
        # a falsy {} value -- present, not dropped -- so a provider's `"tool" not in results`
        # re-proposal guard fires EXACTLY once, identical to the pre-view provider path.
        state = AgentState("t", "g", memory={"tool_results": {"catalog.search": {"id": "1", "detail": "x"}}})
        view = provider_view(state, (ToolGrant("catalog.search"),))  # output_projection omitted
        self.assertIn("catalog.search", view.tool_results)               # PRESENT
        self.assertEqual(dict(view.tool_results["catalog.search"]), {})   # but empty

    def test_wire_serializes_the_same_view_every_adapter_sees(self):
        # Section 8 finding (cross-adapter consistency): the remote wire (provider_state)
        # must be a FAITHFUL serialization of the ProviderView the in-process provider gets,
        # so no adapter can make a different decision from the same admitted state. It carries
        # every view field -- including `migrated` and `tool_results`, which earlier versions
        # dropped -- and must be json-serializable (no MappingProxyType leak).
        state = AgentState(
            "t", "g", step=3, tool_calls=1, status="running",
            memory={"migration": {"from": "a", "to": "b"}, "tool_results": {"catalog.search": {"id": "1", "detail": "x"}}},
            messages=[{"role": "tool", "name": "catalog.search", "content": {"id": "1", "detail": "x"}}],
        )
        grants = (ToolGrant("catalog.search", output_projection=("id",)),)
        view = provider_view(state, grants)
        wire = provider_state(view)
        json.dumps(wire)  # must not raise (dict() unwraps the MappingProxyType)
        # Every field the in-process provider reads is present on the wire, with equal values.
        self.assertEqual(wire["migrated"], view.migrated)
        self.assertTrue(wire["migrated"])  # memory["migration"] present -> True on BOTH paths
        self.assertEqual(wire["tool_results"], {k: dict(v) for k, v in view.tool_results.items()})
        self.assertEqual(wire["tool_results"], {"catalog.search": {"id": "1"}})  # projected to id
        self.assertEqual(wire["messages"], list(view.messages))
        for field in ("task_id", "goal", "step", "tool_calls", "status"):
            self.assertEqual(wire[field], getattr(view, field))

    def test_non_dict_message_rejected_at_admission_nothing_stored(self):
        # Section 8 (terminalization, finding 1): a validly signed envelope whose state
        # carries a non-dict message entry must be rejected at admission -- BEFORE the first
        # persist -- so it can never be admitted and then crash view construction (which is
        # outside the provider-failure boundary), stranding the checkpoint as `running`.
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host = make_host(store=store, allow_ephemeral_signing_key=True)
            envelope = make_demo_envelope(host, "malformed messages", "deterministic")
            object.__setattr__(envelope.state, "messages", [42])  # not a dict
            host.signer.seal(envelope)
            with self.assertRaisesRegex(SecurityError, "list of message objects"):
                host.run(envelope)
            # Nothing stored: no checkpoint and no audit head for the rejected task.
            self.assertIsNone(store.load_checkpoint(envelope.state.task_id))
            self.assertIsNone(store.audit_head(envelope.state.task_id))

    def test_view_construction_failure_terminalizes_not_strands(self):
        # Defense in depth (finding 1): even if view construction raises AFTER admission
        # (admission validation makes the messages=[42] path unreachable, so this forces the
        # failure with a patched provider_view), the task must reach a durable terminal
        # `failed` checkpoint with a `provider.failed` event -- never be left as `running`.
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host = make_host(store=store, allow_ephemeral_signing_key=True)
            envelope = make_demo_envelope(host, "view boom", "deterministic")
            host.signer.seal(envelope)
            with patch("portmark.host.provider_view", side_effect=RuntimeError("view boom")):
                with self.assertRaises(RuntimeError):
                    host.run(envelope)
            checkpoint = store.load_checkpoint(envelope.state.task_id)
            self.assertIsNotNone(checkpoint)
            self.assertEqual(checkpoint["status"], "failed")  # durable terminal, not running
            self.assertTrue(store.verify_audit_chain(envelope.state.task_id))  # closed chain intact

    def test_strict_json_rejects_duplicate_keys(self):
        # Section 8 finding #4: a JSON object with duplicate keys parses silently last-wins in
        # stdlib json -- an ambiguity a validator that inspects one copy can be bypassed through.
        from portmark.json_guard import StrictJSONError, strict_json_loads
        with self.assertRaisesRegex(StrictJSONError, "duplicate object key"):
            strict_json_loads('{"a": 1, "a": 2}')
        with self.assertRaises(StrictJSONError):  # nested duplicate too
            strict_json_loads('{"outer": {"b": 1, "b": 2}}')

    def test_strict_json_depth_rejected_cleanly(self):
        # Section 8 finding #4 (unbounded nesting). Adversarial depth must be a clean rejection.
        # The C json scanner on modern CPython parses deep input iteratively, but (a) a pure-Python
        # json build recurses and raises RecursionError, and (b) our OWN downstream processing of an
        # admitted state -- projection._detach, canonical hashing, provider logic -- recurses, so an
        # admitted 5000-deep document would drive THOSE into RecursionError. The depth pre-scan bounds
        # nesting up front so the over-deep input never reaches any of them: a clean StrictJSONError,
        # never a RecursionError leaking past a handler that only catches JSONDecodeError.
        from portmark.json_guard import StrictJSONError, strict_json_loads
        deep = "[" * 5000 + "]" * 5000
        try:
            strict_json_loads(deep)
            self.fail("deep nesting was not rejected")
        except RecursionError:
            self.fail("depth guard let a RecursionError escape")
        except StrictJSONError:
            pass

    def test_strict_json_scanner_string_edges(self):
        # The string-aware scanner must NOT over-count: braces/brackets and escaped quotes INSIDE
        # a string value are legitimate content and must parse, or the guard rejects real traffic.
        from portmark.json_guard import strict_json_loads
        self.assertEqual(strict_json_loads('{"a": "' + "{" * 200 + '"}'), {"a": "{" * 200})
        self.assertEqual(strict_json_loads(r'{"a": "\\"}'), {"a": "\\"})
        self.assertEqual(strict_json_loads(r'{"a": "\""}'), {"a": '"'})

    def test_strict_json_invalid_utf8(self):
        # An invalid-UTF-8 body must be a clean domain rejection, not a raw UnicodeDecodeError.
        from portmark.json_guard import StrictJSONError, strict_json_loads
        with self.assertRaisesRegex(StrictJSONError, "not valid UTF-8"):
            strict_json_loads(b'\xff\xfe{"a": 1}')

    def test_http_provider_rejects_unsafe_json(self):
        # The HTTP decision decode goes through strict parsing: a duplicate-key or deeply-nested
        # (but size-legal) response is a controlled SecurityError, not a silent accept or a crash.
        from portmark.providers import GenericHttpProvider
        from portmark.security import SecurityError
        provider = GenericHttpProvider("https://provider.example/run")
        for raw in (b'{"kind": "complete", "kind": "tool"}', b"[" * 100 + b"]" * 100):
            with self.subTest(raw=raw[:16]):
                with patch.object(provider, "_post", return_value=raw):
                    with self.assertRaisesRegex(SecurityError, "malformed or unsafe JSON"):
                        provider.decide(provider_view(AgentState("t", "g")), ())

    def test_wasm_decision_rejects_unsafe_json(self):
        # The Wasm component decision decode (Python side) goes through strict parsing too.
        from portmark.component_bindings import decode_component_decision
        for raw in ('{"outcome": "completed", "outcome": "tool"}', "[" * 100 + "]" * 100):
            with self.subTest(raw=raw[:16]):
                with self.assertRaisesRegex(RuntimeError, "malformed or unsafe decision JSON"):
                    decode_component_decision(raw, ("catalog.search",))

    def test_strict_json_rejects_non_finite_numbers(self):
        # Section 8 finding #4 follow-up (Medium): stdlib json accepts NaN / Infinity / -Infinity
        # (parse_constant) and overflows 1e999 to +inf (parse_float). Non-finite floats have no safe
        # meaning across the boundary -- comparisons, constraints, and hashing disagree on them -- so
        # the strict decoder must reject them, keyword and overflow forms alike, nested included.
        from portmark.json_guard import StrictJSONError, strict_json_loads
        for token in ("NaN", "Infinity", "-Infinity", "1e999", "[NaN]", '{"x": 1e999}', '{"a": [1, -Infinity]}'):
            with self.subTest(token=token):
                with self.assertRaises(StrictJSONError):
                    strict_json_loads(token)
        # legitimate finite floats still parse
        self.assertEqual(strict_json_loads('{"a": 3.14, "b": [1, 2.0, -5.0]}'), {"a": 3.14, "b": [1, 2.0, -5.0]})

    def test_strict_json_rejects_oversized_integer_as_domain_error(self):
        # An integer past Python's int-string digit limit raises a bare ValueError inside json.loads,
        # NOT a JSONDecodeError -- it must surface as StrictJSONError so a caller catching that one
        # type is not bypassed by an uncaught ValueError.
        from portmark.json_guard import StrictJSONError, strict_json_loads
        with self.assertRaises(StrictJSONError):
            strict_json_loads("1" + "0" * 5000)

    def test_provider_decision_rejects_contradictory_or_unknown_fields(self):
        # Section 8 finding #4 follow-up (Low): the auditor's exact payload -- a `complete` decision
        # also carrying tool/arguments/destination/unknown -- must be rejected, not silently ignored.
        from portmark.providers import _provider_decision
        from portmark.security import SecurityError
        with self.assertRaisesRegex(SecurityError, "unexpected fields"):
            _provider_decision({"kind": "complete", "tool": "payments.reserve", "arguments": {"amount": 999}, "destination": "host:evil", "unknown": True})
        # a tool decision may not carry a destination; a migrate may not carry a tool
        with self.assertRaisesRegex(SecurityError, "unexpected fields"):
            _provider_decision({"kind": "tool", "tool": "catalog.search", "destination": "host:x"})
        with self.assertRaisesRegex(SecurityError, "unexpected fields"):
            _provider_decision({"kind": "migrate", "destination": "host:x", "tool": "payments.reserve"})
        # valid per-kind decisions still decode
        self.assertEqual(_provider_decision({"kind": "complete", "content": {"ok": True}}).kind, "complete")
        self.assertEqual(_provider_decision({"kind": "tool", "tool": "catalog.search", "arguments": {"q": 1}}).tool, "catalog.search")

    def test_wasm_decision_rejects_unknown_fields(self):
        # Equivalent strict schema on Wasm outcomes AND the nested request object.
        from portmark.component_bindings import decode_component_decision
        with self.assertRaisesRegex(RuntimeError, "unexpected fields"):
            decode_component_decision('{"outcome": "completed", "request": {"name": "x"}, "destination": "host:evil", "unknown": true}', ("catalog.search",))
        with self.assertRaisesRegex(RuntimeError, "unexpected fields"):
            decode_component_decision('{"outcome": "tool", "request": {"name": "catalog.search", "arguments_json": "{}", "destination": "evil"}}', ("catalog.search",))

    # --- Section 8 finding #5 (Medium): bounded subprocess output for the Wasm providers ---
    # `subprocess.run(capture_output=True)` buffers ALL output before any size check, so a hostile
    # capsule can OOM the host before the cap runs. `_run_bounded` drains under a hard byte cap and
    # kills the child the instant it overflows. These tests drive the helper directly with a fake
    # Python producer (no Node/wasmtime dependency, so they run on every CI job).

    def _write_producer(self):
        # A controllable child: reads stdin (optional), writes PROD_STDOUT bytes to stdout and
        # PROD_STDERR bytes to stderr in 64 KiB chunks, then -- only if it finished all output --
        # touches PROD_MARKER and exits PROD_EXIT. The marker is the cut-off oracle: if the helper
        # killed it early, the marker never appears.
        script = (
            "import os, sys, time\n"
            # Sleep mode: never read stdin, just wait then exit. Used to prove a large stdin write
            # cannot hold the caller past the deadline (the write must be off the main thread).
            "if os.environ.get('PROD_SLEEP'):\n"
            "    time.sleep(float(os.environ['PROD_SLEEP']))\n"
            "    sys.exit(int(os.environ.get('PROD_EXIT', '0')))\n"
            "chunk = b'x' * 65536\n"
            # Echo mode: read stdin in chunks and write each straight to stdout, INTERLEAVED. This
            # is what makes a large stdin + large stdout deadlock when readers start after the stdin
            # write -- the child blocks writing stdout (no reader) and so stops draining stdin.
            "if os.environ.get('PROD_ECHO') == '1':\n"
            "    while True:\n"
            "        data = sys.stdin.buffer.read(65536)\n"
            "        if not data:\n"
            "            break\n"
            "        try:\n"
            "            sys.stdout.buffer.write(data); sys.stdout.buffer.flush()\n"
            "        except (BrokenPipeError, OSError):\n"
            "            os._exit(0)\n"
            "    marker = os.environ.get('PROD_MARKER')\n"
            "    if marker:\n"
            "        open(marker, 'w').close()\n"
            "    sys.exit(0)\n"
            "if os.environ.get('PROD_READ_STDIN') == '1':\n"
            "    sys.stdin.buffer.read()\n"
            "def emit(stream, total):\n"
            "    written = 0\n"
            "    while written < total:\n"
            "        n = min(len(chunk), total - written)\n"
            "        try:\n"
            "            stream.write(chunk[:n]); stream.flush()\n"
            "        except (BrokenPipeError, OSError):\n"
            "            os._exit(0)\n"
            "        written += n\n"
            "emit(sys.stdout.buffer, int(os.environ.get('PROD_STDOUT', '0')))\n"
            "emit(sys.stderr.buffer, int(os.environ.get('PROD_STDERR', '0')))\n"
            "marker = os.environ.get('PROD_MARKER')\n"
            "if marker:\n"
            "    open(marker, 'w').close()\n"
            "sys.exit(int(os.environ.get('PROD_EXIT', '0')))\n"
        )
        handle = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
        handle.write(script)
        handle.close()
        self.addCleanup(lambda: os.path.exists(handle.name) and os.unlink(handle.name))
        return handle.name

    def test_wasm_bounded_stdout_flood_cut_off(self):
        # A capsule that floods stdout is killed DURING the read: overflow is flagged and the
        # producer never reaches its completion marker. This is the finding #5 fix -- with
        # subprocess.run restored the producer writes all 4 MB and the marker appears (the bite).
        from portmark.providers import _run_bounded
        producer = self._write_producer()
        marker = tempfile.NamedTemporaryFile(delete=False)
        marker.close()
        os.unlink(marker.name)  # the producer creates it only on full completion
        self.addCleanup(lambda: os.path.exists(marker.name) and os.unlink(marker.name))
        env = dict(os.environ, PROD_STDOUT="4000000", PROD_MARKER=marker.name)
        rc, out, err, timed_out, overflowed = _run_bounded(
            [sys.executable, producer], b"", timeout=10.0, max_output_bytes=65_536, env=env
        )
        self.assertTrue(overflowed)
        self.assertFalse(timed_out)
        self.assertFalse(os.path.exists(marker.name), "producer ran to completion -- output was NOT cut off")
        self.assertLessEqual(len(out), 65_536 + 65_536)  # buffered at most cap + one chunk

    def test_wasm_bounded_accepts_exactly_at_limit(self):
        # The cap is a true byte cap: output of exactly max_output_bytes is accepted; one byte over
        # is rejected as overflow. Flipping the comparison in the helper breaks one of these.
        from portmark.providers import _run_bounded
        producer = self._write_producer()
        for total, expect_overflow in ((65_536, False), (65_537, True)):
            with self.subTest(total=total):
                marker = tempfile.NamedTemporaryFile(delete=False)
                marker.close()
                os.unlink(marker.name)
                self.addCleanup(lambda m=marker.name: os.path.exists(m) and os.unlink(m))
                env = dict(os.environ, PROD_STDOUT=str(total), PROD_MARKER=marker.name)
                rc, out, err, timed_out, overflowed = _run_bounded(
                    [sys.executable, producer], b"", timeout=10.0, max_output_bytes=65_536, env=env
                )
                self.assertEqual(overflowed, expect_overflow)
                if not expect_overflow:
                    self.assertEqual(rc, 0)
                    self.assertEqual(len(out), total)
                    self.assertTrue(os.path.exists(marker.name))

    def test_wasm_bounded_stderr_flood(self):
        # stderr is bounded independently: a capsule that exits nonzero with a huge stderr yields a
        # small retained error string (which the decide path interpolates into its message), never
        # a multi-MB string. stdout stays under its cap so this is a clean nonzero-exit, not overflow.
        from portmark.providers import _run_bounded
        producer = self._write_producer()
        env = dict(os.environ, PROD_STDERR="4000000", PROD_EXIT="1")
        rc, out, err, timed_out, overflowed = _run_bounded(
            [sys.executable, producer], b"", timeout=10.0, max_output_bytes=65_536, env=env
        )
        self.assertNotEqual(rc, 0)
        self.assertFalse(overflowed)
        self.assertLessEqual(len(err.encode()), 4096)

    def test_wasm_bounded_large_stdin_concurrent_stdout(self):
        # Readers start BEFORE stdin is written, so a large stdin payload sent while the child is
        # also writing a large stdout cannot deadlock (host blocked on write vs child blocked on
        # write). With the ordering reversed (write stdin fully, THEN start readers) this deadlocks
        # and the call times out -- the bite that ONLY this test catches.
        from portmark.providers import _run_bounded
        producer = self._write_producer()
        request = b"y" * 2_000_000  # >> the ~64 KiB OS pipe buffer
        env = dict(os.environ, PROD_ECHO="1")  # child echoes stdin->stdout, interleaved
        rc, out, err, timed_out, overflowed = _run_bounded(
            [sys.executable, producer], request, timeout=15.0, max_output_bytes=4_000_000, env=env
        )
        self.assertFalse(timed_out, "large stdin + large stdout deadlocked (stdin written before readers started)")
        self.assertFalse(overflowed)
        self.assertEqual(rc, 0)
        self.assertEqual(len(out), 2_000_000)

    def test_wasm_bounded_overflow_message_precedence(self):
        # An overflow kill leaves returncode == -SIGKILL, i.e. nonzero. decide() must report the
        # output-limit (and deadline) outcomes BEFORE the generic "rejected: <stderr>" branch, or a
        # killed-for-overflow capsule is mislabelled a rejection. Drive decide with a stubbed helper
        # so no Node install is needed. Reversing the precedence flips the first assertion.
        from unittest.mock import patch
        from portmark.providers import WasmDecisionProvider
        with patch("portmark.providers.shutil.which", return_value="/usr/bin/node"):
            provider = WasmDecisionProvider(b"component-bytes", max_output_bytes=64)
        view = provider_view(AgentState("task", "goal"))
        cases = (
            ((-9, b"", "some stderr noise", False, True), "exceeded output limit"),
            ((-9, b"", "some stderr noise", True, False), "exceeded its execution deadline"),
            ((1, b"", "boom", False, False), "Wasm capsule rejected: boom"),
        )
        for ret, expected in cases:
            with self.subTest(expected=expected):
                with patch("portmark.providers._run_bounded", return_value=ret):
                    with self.assertRaisesRegex(RuntimeError, expected):
                        provider.decide(view, ("catalog.search",))

    def test_wasm_bounded_stdin_write_does_not_bypass_deadline(self):
        # Round-2 finding (Medium): a large stdin write must NOT hold the caller past the deadline
        # when the child never reads stdin (a wedged / failed-to-start runner). stdin is written on
        # a supervised writer thread, so process.wait enforces the one absolute deadline even while
        # the write blocks; the deadline kill closes the child's stdin read end, unblocking the
        # writer. Neutralizing to a synchronous main-thread stdin write makes this block ~the
        # child's sleep with timed_out=False (the bite: elapsed >> deadline).
        from portmark.providers import _run_bounded
        producer = self._write_producer()
        request = b"z" * 4_000_000  # >> the OS pipe buffer, so a synchronous write blocks
        env = dict(os.environ, PROD_SLEEP="5")  # child sleeps 5s WITHOUT reading stdin
        start = time.monotonic()
        rc, out, err, timed_out, overflowed = _run_bounded(
            [sys.executable, producer], request, timeout=0.5, max_output_bytes=65_536, env=env
        )
        elapsed = time.monotonic() - start
        self.assertTrue(timed_out, "deadline not enforced while the stdin write blocked")
        self.assertLess(elapsed, 3.0, "stdin write bypassed the execution deadline")

    @contextmanager
    def _three_store_context(self, backend):
        # Three stores (2 sources + 1 destination) on one backend, for the section 4 #7
        # cross-host collision tests. make_host sets each store's audit verifier to its
        # host signer, so the stores are constructed without one here. SQLite always;
        # Postgres when a DSN is configured.
        if backend == "sqlite":
            with tempfile.TemporaryDirectory() as d:
                root = Path(d)
                yield (SQLiteRuntimeStore(root / "a.sqlite"),
                       SQLiteRuntimeStore(root / "b.sqlite"),
                       SQLiteRuntimeStore(root / "dest.sqlite"))
        else:
            dsn = os.environ["PORTMARK_TEST_POSTGRES_DSN"]
            schemas = ["portmark_c_" + secrets.token_hex(8) for _ in range(3)]
            stores = [PostgresRuntimeStore(dsn, schema=s) for s in schemas]
            try:
                yield tuple(stores)
            finally:
                for s in schemas:
                    self._drop_postgres_schema(dsn, s)

    def _three_store_backends(self):
        backends = ["sqlite"]
        if os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available():
            backends.append("postgres")
        return backends

    def _two_source_collision_fixture(self, storeA, storeB, dest_store):
        # Two source hosts + one destination, all trusting each other, each able to migrate
        # a task with the SAME caller-chosen task_id to the destination (section 4 #7).
        signerA = EnvelopeSigner.generate("srcA-key", "host:sourceA", ("host:sourceA", "host:destination"))
        signerB = EnvelopeSigner.generate("srcB-key", "host:sourceB", ("host:sourceB", "host:destination"))
        dest_signer = EnvelopeSigner.generate("dest-key", "host:destination", ("host:destination",))
        trust_signer(dest_signer, signerA)
        trust_signer(dest_signer, signerB)
        # Each source must trust the destination's receipt-signing key to settle delivery.
        trust_signer(signerA, dest_signer)
        trust_signer(signerB, dest_signer)
        sourceA = make_host(host_id="host:sourceA", signer=signerA, store=storeA, allow_ephemeral_signing_key=True)
        sourceB = make_host(host_id="host:sourceB", signer=signerB, store=storeB, allow_ephemeral_signing_key=True)
        dest = make_host(host_id="host:destination", signer=dest_signer, store=dest_store, allow_ephemeral_signing_key=True)
        for s in (sourceA, sourceB):
            s.policy.migration = MigrationPolicy(allowed=True, destinations=("host:destination",))
        return sourceA, signerA, storeA, sourceB, signerB, storeB, dest, dest_store

    @staticmethod
    def _migrate_same_task_id(source, signer, task_id, provider):
        source.providers["migrator"] = provider
        env = make_demo_envelope(source, "collide", "migrator")
        env.state.task_id = task_id
        object.__setattr__(env.permit, "delegation_allowed", True)
        signer.seal(env)
        first = source.run(env)
        return envelope_from_dict(first.migration_envelope)

    def test_migration_taskid_namespaced_by_source_two_hosts_coexist(self):
        # Section 4 #7: two source hosts migrate the SAME caller-chosen task_id to one
        # destination. Both must ADMIT and COEXIST as distinct tasks (namespaced by the
        # authenticated source), each with its own verifying audit chain -- neither can
        # squat the other's id. Then each source settles ITS OWN migration, and one
        # source's receipt cannot settle the other's row.
        for backend in self._three_store_backends():
          with self.subTest(backend=backend), self._three_store_context(backend) as (sa, sb, ds):
            sourceA, signerA, storeA, sourceB, signerB, storeB, dest, dest_store = self._two_source_collision_fixture(sa, sb, ds)
            provider = MigrateThenCompleteProvider("host:destination")
            dest.providers["migrator"] = provider

            migratedA = self._migrate_same_task_id(sourceA, signerA, "shared-task-X", provider)
            migratedB = self._migrate_same_task_id(sourceB, signerB, "shared-task-X", provider)

            resA = dest.run(migratedA)
            resB = dest.run(migratedB)  # pre-fix: raises "receipt already exists ... different envelope"
            self.assertEqual(resA.status, "completed")
            self.assertEqual(resB.status, "completed")
            # Two distinct resident tasks, two verifying chains, distinct namespaced ids.
            self.assertNotEqual(resA.task_id, resB.task_id)
            self.assertTrue(dest_store.verify_audit_chain(resA.task_id))
            self.assertTrue(dest_store.verify_audit_chain(resB.task_id))
            self.assertEqual(dest_store.load_checkpoint(resA.task_id)["status"], "completed")
            self.assertEqual(dest_store.load_checkpoint(resB.task_id)["status"], "completed")
            # The original (source-chosen) id is NOT a stored key at the destination.
            self.assertIsNone(dest_store.load_checkpoint("shared-task-X"))

            # A's receipt must NOT settle B's row: the bindings (source/nonce/digest) differ.
            with self.assertRaises(SecurityError):
                sourceB.settle_migration("shared-task-X", resA.migration_receipt)
            self.assertEqual(len(storeB.list_pending_migrations()), 1)

            # Each source settles ITS OWN migration with the destination's receipt (the
            # receipt payload keeps the ORIGINAL task_id so settle_migration matches the
            # source outbox row keyed by that original id).
            sourceA.settle_migration("shared-task-X", resA.migration_receipt)
            sourceB.settle_migration("shared-task-X", resB.migration_receipt)
            self.assertEqual(storeA.list_pending_migrations(), [])
            self.assertEqual(storeB.list_pending_migrations(), [])

    def test_fresh_task_cannot_claim_reserved_migration_namespace(self):
        # Section 4 #7: a local, NON-migration task may not pre-occupy the reserved migration
        # namespace -- otherwise a local caller could squat a migrated task's key and deny a
        # remote peer's migration (the same squat, reached without any credential).
        host = make_host(allow_ephemeral_signing_key=True)
        env = make_demo_envelope(host, "squat")
        env.state.task_id = "mig::squatter"
        host.signer.seal(env)
        with self.assertRaisesRegex(SecurityError, "reserved migration namespace"):
            host.run(env)

    def test_migration_redelivery_is_idempotent_per_source(self):
        # Section 4 #7 + #2: a re-delivery of the SAME source's migrated envelope returns the
        # SAME receipt (idempotent, no re-execution), while a DIFFERENT source's same
        # original task_id is NOT mistaken for that duplicate -- it admits as a distinct task.
        for backend in self._three_store_backends():
          with self.subTest(backend=backend), self._three_store_context(backend) as (sa, sb, ds):
            sourceA, signerA, storeA, sourceB, signerB, storeB, dest, dest_store = self._two_source_collision_fixture(sa, sb, ds)
            provider = MigrateThenCompleteProvider("host:destination")
            dest.providers["migrator"] = provider

            migratedA = self._migrate_same_task_id(sourceA, signerA, "shared-task-X", provider)
            replay = copy.deepcopy(migratedA)  # pristine copy: run() mutates the envelope in place
            r1 = dest.run(migratedA)
            r2 = dest.run(replay)  # re-delivery of A's SAME envelope
            self.assertEqual(r1.migration_receipt, r2.migration_receipt)
            self.assertEqual(r2.status, r1.status)

            migratedB = self._migrate_same_task_id(sourceB, signerB, "shared-task-X", provider)
            rB = dest.run(migratedB)  # same original id, different source -> NOT A's duplicate
            self.assertNotEqual(rB.task_id, r1.task_id)
            self.assertNotEqual(rB.migration_receipt, r1.migration_receipt)

    def test_migrated_task_is_addressable_only_by_namespaced_id(self):
        # Section 4 #7 resume-addressing: a resume looks the task up by task_id
        # (load_checkpoint / audit_head). The resident migrated task must be keyed by the
        # source-namespaced id, and the original (source-chosen) id must resolve to NOTHING
        # -- so a resume addresses the right task and another source's same original id can
        # never resolve to it. (A full run()-based resume of a migrated task is a separate,
        # pre-existing concern: the delegated permit names the SOURCE as issuer, so the
        # destination cannot re-sign a resume envelope -- unrelated to #7.)
        for backend in self._three_store_backends():
          with self.subTest(backend=backend), self._three_store_context(backend) as (sa, sb, ds):
            sourceA, signerA, storeA, sourceB, signerB, storeB, dest, dest_store = self._two_source_collision_fixture(sa, sb, ds)
            provider = MigrateThenCompleteProvider("host:destination")
            dest.providers["migrator"] = provider
            resA = dest.run(self._migrate_same_task_id(sourceA, signerA, "shared-task-X", provider))
            namespaced = resA.task_id
            self.assertTrue(namespaced.startswith("mig::"))
            # The store resolves the resident task ONLY by the namespaced id.
            self.assertIsNotNone(dest_store.load_checkpoint(namespaced))
            self.assertIsNotNone(dest_store.audit_head(namespaced))
            self.assertIsNone(dest_store.load_checkpoint("shared-task-X"))
            self.assertIsNone(dest_store.audit_head("shared-task-X"))

    def test_migration_writes_sealed_envelope_to_outbox_atomically(self):
        # Section 1, finding #2: the sealed destination envelope is stored durably in
        # the source store's migration_outbox in the SAME commit that closes the source
        # checkpoint, so a crash before the caller delivers RunResult.migration_envelope
        # cannot lose the migration. The stored envelope is exactly the one returned.
        source_signer = EnvelopeSigner.generate("outbox-source-key", "host:source", ("host:source", "host:destination"))
        for context in self._store_case_contexts():
            with context as (backend, store):
                with self.subTest(backend=backend):
                    source = make_host(host_id="host:source", signer=source_signer, store=store, allow_ephemeral_signing_key=True)
                    source.policy.migration = MigrationPolicy(allowed=True, destinations=("host:destination",))
                    source.providers["migrator"] = MigrateThenCompleteProvider("host:destination")
                    envelope = make_demo_envelope(source, f"{backend} outbox", "migrator")
                    object.__setattr__(envelope.permit, "delegation_allowed", True)
                    source_signer.seal(envelope)

                    result = source.run(envelope)
                    self.assertIsNotNone(result.migration_envelope)
                    self.assertEqual(store.load_checkpoint(result.task_id)["status"], "ready")

                    pending = store.list_pending_migrations()
                    self.assertEqual(len(pending), 1)
                    row = pending[0]
                    self.assertEqual(row["task_id"], result.task_id)
                    self.assertEqual(row["destination"], "host:destination")
                    self.assertEqual(row["status"], "pending")
                    self.assertEqual(row["attempt_count"], 0)
                    # The durable copy is the canonical serialization of the returned
                    # sealed envelope (byte-for-byte); JSON turns the dataclass tuples
                    # into lists, so compare the canonical encodings, not the raw dict.
                    self.assertEqual(row["sealed_envelope_json"], canonical_json(result.migration_envelope).decode("utf-8"))

                    # Delivery API: attempts increment; settlement (with a verified receipt,
                    # section 4 #2) clears it from pending and records the receipt on the row.
                    store.record_migration_attempt(result.task_id)
                    self.assertEqual(store.list_pending_migrations()[0]["attempt_count"], 1)
                    receipt_json = json.dumps({"type": "portmark.migration-receipt.v1", "task_id": result.task_id})
                    store.mark_migration_delivered(result.task_id, receipt_json)
                    self.assertEqual(store.list_pending_migrations(), [])

    def test_completed_run_writes_no_outbox_row(self):
        # The outbox is written ONLY on a migration close, never on an ordinary run.
        for context in self._store_case_contexts():
            with context as (backend, store):
                with self.subTest(backend=backend):
                    host = make_host(store=store, allow_ephemeral_signing_key=True)
                    result = host.run(make_demo_envelope(host, f"{backend} no-migration"))
                    self.assertEqual(result.status, "completed")
                    self.assertEqual(store.list_pending_migrations(), [])

    def test_oversized_migration_close_still_writes_outbox(self):
        # Section 1, finding #2 x the terminalization path: an over-budget migration
        # closes the source through _terminalize_over_budget (the OTHER close path), not
        # the normal _persist. The outbox write must ride that close too, or the exact
        # data-loss hole reopens on the terminalize branch. (Mirrors the oversized
        # terminalization test's budget setup.)
        source_signer = EnvelopeSigner.generate("outbox-oversize-key", "host:source", ("host:source", "host:destination"))
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            source = make_host(host_id="host:source", signer=source_signer, store=store, allow_ephemeral_signing_key=True)
            source.policy.migration = MigrationPolicy(allowed=True, destinations=("host:destination",))
            source.providers["migrator"] = MigrateThenCompleteProvider("host:destination")
            envelope = make_demo_envelope(source, "M" * 1500, "migrator")
            object.__setattr__(envelope.permit, "delegation_allowed", True)
            running = asdict(envelope.state)
            running["status"] = "running"
            ceiling = len(canonical_json(running)) + 40
            budget = ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=ceiling)
            object.__setattr__(envelope.permit, "budget", budget)
            source.policy.budget = budget
            source_signer.seal(envelope)

            result = source.run(envelope)  # must not raise
            self.assertIsNotNone(result.migration_envelope)
            self.assertEqual(store.load_checkpoint(result.task_id)["status"], "ready")
            self.assertIn("checkpoint.terminalized", [event["event"] for event in result.audit])
            pending = store.list_pending_migrations()
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]["destination"], "host:destination")
            self.assertEqual(pending[0]["sealed_envelope_json"], canonical_json(result.migration_envelope).decode("utf-8"))

    def test_migration_outbox_and_source_close_are_atomic(self):
        # Both-or-neither: if the outbox write fails inside the closing transaction, the
        # source-checkpoint close rolls back with it, so the source stays resumable
        # rather than closing (un-resumable) while the migration was never recorded.
        import portmark.storage as storage_module

        source_signer = EnvelopeSigner.generate("outbox-atomic-key", "host:source", ("host:source", "host:destination"))
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            source = make_host(host_id="host:source", signer=source_signer, store=store, allow_ephemeral_signing_key=True)
            source.policy.migration = MigrationPolicy(allowed=True, destinations=("host:destination",))
            source.providers["migrator"] = MigrateThenCompleteProvider("host:destination")
            envelope = make_demo_envelope(source, "atomic outbox", "migrator")
            object.__setattr__(envelope.permit, "delegation_allowed", True)
            source_signer.seal(envelope)

            def boom(self, task_id, destination, sealed_envelope_json):
                raise RuntimeError("simulated outbox write failure")

            with patch.object(storage_module._SQLiteTransaction, "enqueue_migration", boom):
                with self.assertRaises(RuntimeError):
                    source.run(envelope)

            # Neither effect landed: no outbox row, and the source checkpoint was NOT
            # closed by the rolled-back migrate persist. The accept-persist committed
            # first, so a checkpoint exists and is still open (not "ready"/migrated),
            # so the source can still be recovered rather than lost.
            self.assertEqual(store.list_pending_migrations(), [])
            checkpoint = store.load_checkpoint(envelope.state.task_id)
            self.assertIsNotNone(checkpoint)
            self.assertNotEqual(checkpoint["status"], "ready")

    @unittest.skipUnless(
        os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available(),
        "requires a real PostgreSQL",
    )
    def test_concurrent_cold_initialization_is_race_safe(self):
        # Section 1, finding #1: many independent OS processes opening the same NEW
        # schema at once must ALL succeed. CREATE SCHEMA / CREATE TABLE IF NOT EXISTS
        # are not atomic against concurrent DDL (they race on pg_namespace / pg_type
        # unique indexes); the schema-name advisory lock serialises cold init. Proven
        # only where the postgres-store CI job runs -- skipped otherwise.
        import subprocess  # nosec B404

        dsn = os.environ["PORTMARK_TEST_POSTGRES_DSN"]
        schema = "portmark_race_" + secrets.token_hex(8)
        worker = (
            "import sys;"
            "from portmark.storage import PostgresRuntimeStore;"
            "PostgresRuntimeStore(sys.argv[1], schema=sys.argv[2]);"
            "print('OK')"
        )
        try:
            processes = [
                subprocess.Popen(  # nosec B603
                    [sys.executable, "-c", worker, dsn, schema],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                for _ in range(16)
            ]
            failures = []
            for process in processes:
                out, err = process.communicate(timeout=60)
                if process.returncode != 0:
                    failures.append(err.decode("utf-8", "replace"))
            self.assertEqual(failures, [], msg="\n".join(failures))
        finally:
            self._drop_postgres_schema(dsn, schema)

    @unittest.skipUnless(
        os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available(),
        "requires a real PostgreSQL",
    )
    def test_postgres_store_upgrades_v2_to_v3_adds_migration_outbox(self):
        # An existing pre-outbox (schema v2) deployment must gain migration_outbox and
        # advance to v3 when reopened with this code -- the in-place upgrade path for
        # finding #2, which the fresh-schema tests do not exercise.
        import psycopg
        from psycopg import sql

        dsn = os.environ["PORTMARK_TEST_POSTGRES_DSN"]
        schema = "portmark_upgrade_" + secrets.token_hex(8)
        try:
            PostgresRuntimeStore(dsn, schema=schema)  # fresh store at the current version
            # Simulate a v2 deployment that predates the outbox.
            with psycopg.connect(dsn, autocommit=True) as connection:
                connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
                connection.execute("DROP TABLE migration_outbox")
                connection.execute("UPDATE portmark_schema SET version = 2")
            # Reopening must restore the outbox table and bring the version current.
            PostgresRuntimeStore(dsn, schema=schema)
            with psycopg.connect(dsn, autocommit=True) as connection:
                connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
                version = connection.execute("SELECT version FROM portmark_schema WHERE singleton = TRUE").fetchone()[0]
                regclass = connection.execute("SELECT to_regclass(%s)", (schema + ".migration_outbox",)).fetchone()[0]
            self.assertEqual(version, POSTGRES_SCHEMA_VERSION)  # brought fully current, not just to v3
            self.assertIsNotNone(regclass)
        finally:
            self._drop_postgres_schema(dsn, schema)

    def test_sqlite_store_rejects_replay_after_host_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            signer = EnvelopeSigner.generate("store-key", "host:local-demo", ("host:local-demo",))
            first_host = make_host(signer=signer, store=SQLiteRuntimeStore(path), allow_ephemeral_signing_key=True)
            envelope = make_demo_envelope(first_host, "durable replay")
            result = first_host.run(envelope)
            self.assertEqual(result.status, "completed")

            second_host = make_host(signer=signer, store=SQLiteRuntimeStore(path), allow_ephemeral_signing_key=True)
            replay = copy.deepcopy(envelope)
            replay.state.status = "ready"
            signer.seal(replay)
            # Finding EV-008: the completed task's checkpoint is closed durably, so a
            # brand-new host process opening the same SQLite store rejects the replay
            # at admission -- proving the protection is durable state, not an
            # in-process cache.
            with self.assertRaisesRegex(SecurityError, "closed"):
                second_host.run(replay)
            self.assertTrue(second_host.store.consumed_nonce_exists(replay.permit.nonce))

    def test_captured_suspended_envelope_rejected_after_resume_advances_generation(self):
        # Finding EV-008, the reviewer's adversarial sequence: a suspended envelope
        # captured at generation N must be rejected once a legitimate resume has
        # advanced the stored generation past N -- and rejected at admission, before
        # the provider is ever consulted. Proven on every store backend.
        signer = EnvelopeSigner.generate("ev008-key", "host:local-demo", ("host:local-demo",))
        for context in self._store_case_contexts(signer):
            with context as (backend, store):
                with self.subTest(backend=backend):
                    provider = AlwaysSuspendProvider()
                    host = make_host(signer=signer, store=store, providers={"suspender": provider}, allow_ephemeral_signing_key=True)
                    env = make_demo_envelope(host, f"{backend} adversarial", "suspender")
                    signer.seal(env)

                    first = host.run(env)  # submit -> suspends (checkpoint left open)
                    self.assertEqual(first.status, "awaiting_input")
                    captured_generation = first.checkpoint["checkpoint_generation"]
                    # The run mutates the envelope in place; re-seal the suspended
                    # state so it is a valid, replayable wire envelope, then capture it.
                    host.signer.seal(env)
                    captured = copy.deepcopy(env)  # attacker captures the suspended envelope
                    self.assertEqual(captured.state.checkpoint_generation, captured_generation)

                    second = host.run(env)  # legitimate resume advances the stored generation
                    self.assertEqual(second.status, "awaiting_input")
                    self.assertGreater(second.checkpoint["checkpoint_generation"], captured_generation)
                    decisions_before_replay = provider.decisions

                    # Resubmitting the stale captured envelope is rejected at admission.
                    with self.assertRaisesRegex(SecurityError, "stale checkpoint generation"):
                        host.run(captured)
                    # The provider was never consulted for the rejected replay.
                    self.assertEqual(provider.decisions, decisions_before_replay)

    def test_runtime_store_contract_checkpoint_generation_cas(self):
        # Finding EV-008: the store-owned generation is a compare-and-swap. A fresh
        # create must assert generation 0; a resume advances only from the exact
        # stored generation; two writers at the same generation cannot both win; and
        # a closed checkpoint can never be reopened. Proven on every store backend.
        state = AgentState(task_id="cas-task", goal="cas")
        for context in self._store_case_contexts():
            with context as (backend, store):
                with self.subTest(backend=backend):
                    # A fresh create must assert generation 0.
                    with store.transaction() as txn:
                        with self.assertRaisesRegex(SecurityError, "stale checkpoint generation"):
                            txn.save_checkpoint("cas-task", state, 7)
                    with store.transaction() as txn:
                        self.assertEqual(txn.save_checkpoint("cas-task", state, 0), 1)
                    # One writer at generation 1 advances to 2; a second at 1 is stale.
                    with store.transaction() as txn:
                        self.assertEqual(txn.save_checkpoint("cas-task", state, 1), 2)
                    with store.transaction() as txn:
                        with self.assertRaisesRegex(SecurityError, "stale checkpoint generation"):
                            txn.save_checkpoint("cas-task", state, 1)
                    # Closing the checkpoint bars every later resume.
                    with store.transaction() as txn:
                        self.assertEqual(txn.save_checkpoint("cas-task", state, 2, closed=True), 3)
                    with store.transaction() as txn:
                        with self.assertRaisesRegex(SecurityError, "closed"):
                            txn.save_checkpoint("cas-task", state, 3)

    @contextmanager
    def _inmemory_store_case(self):
        yield "inmemory", InMemoryRuntimeStore()

    def test_runtime_store_contract_checkpoint_generation_cas_under_real_concurrency(self):
        # Finding EV-008: the sequential contract test proves the CAS *logic*, but
        # the guarantee that matters is under contention -- many hosts resuming the
        # same checkpoint at once, exactly one advancing. This exercises that
        # genuinely: N threads released together all try to advance generation 1,
        # and the store must let exactly one win (1 -> 2) and reject the rest as
        # stale, on every backend. InMemory serializes on its lock, SQLite on
        # BEGIN IMMEDIATE, Postgres on an advisory xact lock.
        writers = 8
        state = AgentState(task_id="cas-race", goal="cas")
        contexts = [self._inmemory_store_case()] + self._store_case_contexts()
        for context in contexts:
            with context as (backend, store):
                with self.subTest(backend=backend):
                    with store.transaction() as txn:
                        self.assertEqual(txn.save_checkpoint("cas-race", state, 0), 1)

                    barrier = threading.Barrier(writers)
                    results: list[tuple[str, object]] = []
                    results_lock = threading.Lock()

                    def writer():
                        barrier.wait()  # release all writers at the same instant
                        try:
                            with store.transaction() as txn:
                                outcome: tuple[str, object] = ("won", txn.save_checkpoint("cas-race", state, 1))
                        except SecurityError as error:
                            outcome = ("rejected", str(error))
                        with results_lock:
                            results.append(outcome)

                    threads = [threading.Thread(target=writer) for _ in range(writers)]
                    for thread in threads:
                        thread.start()
                    for thread in threads:
                        thread.join(timeout=60)

                    won = [value for kind, value in results if kind == "won"]
                    rejected = [value for kind, value in results if kind == "rejected"]
                    self.assertEqual(len(results), writers, f"{backend}: every writer must finish")
                    self.assertEqual(won, [2], f"{backend}: exactly one writer advances 1 -> 2")
                    self.assertEqual(len(rejected), writers - 1)
                    self.assertTrue(all("stale checkpoint generation" in message for message in rejected))
                    self.assertEqual(store.load_checkpoint("cas-race")["checkpoint_generation"], 2)

    def test_sqlite_store_persists_checkpoint_and_audit_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host = make_host(store=store, allow_ephemeral_signing_key=True)
            result = host.run(make_demo_envelope(host, "persist me"))
            checkpoint = store.load_checkpoint(result.task_id)
            self.assertIsNotNone(checkpoint)
            self.assertEqual(checkpoint["status"], "completed")
            self.assertEqual(checkpoint["result"], result.result)
            self.assertTrue(store.verify_audit_chain(result.task_id))
            self.assertEqual(store.audit_head(result.task_id), (result.audit[-1]["hash"], result.audit[-1]["sequence"] + 1))

    def test_sqlite_store_closes_connections_after_reads(self):
        # A read must close its SQLite connection, not just commit: sqlite3's own
        # `with connection` commits but never closes, and an open connection holds
        # the database file open -- which breaks temp-file deletion on Windows and
        # leaks descriptors in a long-running host. Spy on every connection the
        # reads open and assert each one is closed (a closed connection raises).
        import sqlite3 as sqlite_module

        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            host = make_host(store=store, allow_ephemeral_signing_key=True)
            result = host.run(make_demo_envelope(host, "leak check"))

            opened: list[sqlite_module.Connection] = []
            real_connect = sqlite_module.connect

            def tracking_connect(*args, **kwargs):
                connection = real_connect(*args, **kwargs)
                opened.append(connection)
                return connection

            with patch("portmark.storage.sqlite3.connect", side_effect=tracking_connect):
                store.consumed_nonce_exists("no-such-nonce")
                store.load_checkpoint(result.task_id)
                store.audit_head(result.task_id)
                store.verify_audit_chain_status(result.task_id)

            self.assertTrue(opened, "reads must open a connection for the close to be provable")
            for connection in opened:
                with self.assertRaises(sqlite_module.ProgrammingError):
                    connection.execute("SELECT 1")

    def test_sqlite_store_sets_schema_version_busy_timeout_and_rejects_future_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            store = SQLiteRuntimeStore(path)
            with self._raw_sqlite(path) as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], SQLITE_SCHEMA_VERSION)
                connection.execute("PRAGMA user_version = 999")
            with store._connection() as connection:
                self.assertEqual(connection.execute("PRAGMA busy_timeout").fetchone()[0], SQLITE_BUSY_TIMEOUT_MS)
            with self.assertRaisesRegex(RuntimeError, "newer than supported"):
                SQLiteRuntimeStore(path)

    def test_sqlite_store_migrates_legacy_v0_database_without_losing_existing_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            with self._raw_sqlite(path) as connection:
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
            with self._raw_sqlite(path) as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], SQLITE_SCHEMA_VERSION)

    def test_sqlite_store_migrates_v1_global_audit_hash_uniqueness(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            with self._raw_sqlite(path) as connection:
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
            first = make_host(signer=signer, store=store, allow_ephemeral_signing_key=True)
            second = make_host(signer=signer, store=SQLiteRuntimeStore(path), allow_ephemeral_signing_key=True)
            self.assertEqual(first.run(make_demo_envelope(first, "first migrated task")).status, "completed")
            self.assertEqual(second.run(make_demo_envelope(second, "second migrated task")).status, "completed")
            with self._raw_sqlite(path) as connection:
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
                    host = make_host(store=store, allow_ephemeral_signing_key=True)
                    result = host.run(make_demo_envelope(host, f"audit tamper {name}"))
                    self.assertTrue(store.verify_audit_chain(result.task_id))
                    with self._raw_sqlite(path) as connection:
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

            with self._raw_sqlite(path) as connection:
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

            host = make_host(signer=signer, store=store, allow_ephemeral_signing_key=True)
            result = host.run(make_demo_envelope(host, "signed history"))
            self.assertTrue(store.verify_audit_chain(result.task_id))
            with self._raw_sqlite(path) as connection:
                connection.execute("UPDATE audit_heads SET signature = 'tampered' WHERE task_id = ?", (result.task_id,))
            self.assertEqual(store.verify_audit_chain_status(result.task_id).status, "invalid")
            self.assertFalse(store.verify_audit_chain(result.task_id))

    def test_sqlite_audit_chain_status_reports_unverifiable_without_trust_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            signer = EnvelopeSigner.generate("audit-status-key", "host:local-demo", ("host:local-demo",))
            signing_store = SQLiteRuntimeStore(path, signer)
            host = make_host(signer=signer, store=signing_store, allow_ephemeral_signing_key=True)
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
            host = make_host(signer=signer, store=store, allow_ephemeral_signing_key=True)
            result = host.run(make_demo_envelope(host, "operator audit"))

            output = io.StringIO()
            with patch.object(sys, "argv", ["portmark", "--store-path", str(path), "--trust-registry-path", str(registry_path), "verify-audit", "--task-id", result.task_id]):
                with redirect_stdout(output):
                    cli_main()
            self.assertEqual(
                json.loads(output.getvalue()),
                {"task_id": result.task_id, "status": "valid", "head_status": "valid", "anchor_status": "none", "floor_status": "no-floor", "remote_status": "no-remote", "reason": "audit head verified"},
            )

            output = io.StringIO()
            with patch.object(sys, "argv", ["portmark", "--store-path", str(path), "verify-audit", "--task-id", result.task_id]):
                with redirect_stdout(output):
                    with self.assertRaises(SystemExit) as raised:
                        cli_main()
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(
                json.loads(output.getvalue()),
                {"task_id": result.task_id, "status": "unverifiable", "head_status": "unverifiable", "anchor_status": "", "floor_status": "no-floor", "remote_status": "no-remote", "reason": "trust registry is not configured"},
            )

            with self._raw_sqlite(path) as connection:
                connection.execute("UPDATE audit_heads SET head_hash = 'tampered' WHERE task_id = ?", (result.task_id,))
            output = io.StringIO()
            with patch.object(sys, "argv", ["portmark", "--store-path", str(path), "--trust-registry-path", str(registry_path), "verify-audit", "--task-id", result.task_id]):
                with redirect_stdout(output):
                    with self.assertRaises(SystemExit) as raised:
                        cli_main()
            self.assertEqual(raised.exception.code, 1)
            self.assertEqual(
                json.loads(output.getvalue()),
                {"task_id": result.task_id, "status": "invalid", "head_status": "", "anchor_status": "", "floor_status": "no-floor", "remote_status": "no-remote", "reason": "stored audit head does not match audit events"},
            )

            output = io.StringIO()
            with patch.object(sys, "argv", ["portmark", "--store-path", str(path), "--trust-registry-path", str(registry_path), "verify-audit", "--task-id", "missing-task"]):
                with redirect_stdout(output):
                    with self.assertRaises(SystemExit) as raised:
                        cli_main()
            self.assertEqual(raised.exception.code, 1)
            self.assertEqual(
                json.loads(output.getvalue()),
                {"task_id": "missing-task", "status": "invalid", "head_status": "", "anchor_status": "", "floor_status": "no-floor", "remote_status": "no-remote", "reason": "audit chain is missing"},
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

    def test_pinned_digest_without_verifiable_provider_fails_closed(self):
        # A manifest that pins content-addressed bytes must not run unverified
        # against a provider that exposes no digest to check (fail closed).
        host = make_host()
        envelope = make_demo_envelope(host, "pinned but unverifiable", "deterministic")
        object.__setattr__(envelope.manifest, "component_digest", "sha256:" + "0" * 64)
        host.signer.seal(envelope)
        with self.assertRaisesRegex(SecurityError, "exposes none to verify"):
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
                # Allow migration to the destination so the migration subtests reach
                # the check each is pinning (e.g. attestation shape); the no-delegation
                # case still fails earlier, on the permit.
                host.policy.migration = MigrationPolicy(allowed=True, destinations=("host:destination",))
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
        # Section 5 #4: a malformed approval in untrusted memory must NOT crash out of run() and
        # strand the admitted task nonterminally -- it is a controlled approval.denied + terminal fail.
        bad_result = host.run(envelope)
        self.assertEqual(bad_result.status, "failed")
        self.assertIn("approval.denied", [event["event"] for event in bad_result.audit])

    def test_stored_audit_head_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "runtime.sqlite")
            signer = EnvelopeSigner.generate("audit-head-key", "host:local-demo", ("host:local-demo",))
            host = make_host(signer=signer, store=store, allow_ephemeral_signing_key=True)
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
            source = make_host(host_id="host:source", signer=source_signer, store=source_store, allow_ephemeral_signing_key=True)
            destination = make_host(host_id="host:destination", signer=destination_signer, store=destination_store, allow_ephemeral_signing_key=True)
            source.policy.migration = MigrationPolicy(allowed=True, destinations=(destination.host_id,))
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
            host = make_host(signer=signer, store=SQLiteRuntimeStore(path), allow_ephemeral_signing_key=True)
            envelope = make_demo_envelope(host, "race")

            def run_once():
                local_host = make_host(signer=signer, store=SQLiteRuntimeStore(path), allow_ephemeral_signing_key=True)
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
                host = make_host(signer=signer, store=SQLiteRuntimeStore(path), allow_ephemeral_signing_key=True)
                envelopes.append(copy.deepcopy(make_demo_envelope(host, f"parallel {index}")))

            def run_envelope(envelope):
                local_host = make_host(signer=signer, store=SQLiteRuntimeStore(path), allow_ephemeral_signing_key=True)
                return local_host.run(envelope)

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                results = list(executor.map(run_envelope, envelopes))

            self.assertEqual([result.status for result in results], ["completed"] * len(envelopes))
            store = SQLiteRuntimeStore(path, signer)
            nonces_by_task = {envelope.state.task_id: envelope.permit.nonce for envelope in envelopes}
            for result in results:
                self.assertTrue(store.verify_audit_chain(result.task_id))
                self.assertTrue(store.consumed_nonce_exists(nonces_by_task[result.task_id]))
            with self._raw_sqlite(path) as connection:
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
        source.policy.migration = MigrationPolicy(allowed=True, destinations=(destination.host_id,))
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

    def test_migration_provenance_cannot_be_spliced_between_trusted_hosts(self):
        # Section 4 finding #1 (High): the destination verified the anchor signature and its
        # "migration" usage, but never bound the anchor host to the permit issuer. A permit
        # delegated + sealed by host:a could therefore carry an audit anchor validly signed by
        # an unrelated but individually-trusted host:c, and the destination would accept it and
        # record host:c as the lineage -- a provenance splice. This uses TWO trusted,
        # migration-capable keys (not a bad signature): the anchor sig is genuinely valid.
        source_signer = EnvelopeSigner.generate("splice-source", "host:a", ("host:a", "host:destination"))
        destination_signer = trust_signer(
            EnvelopeSigner.generate("splice-dest", "host:destination", ("host:destination",)),
            source_signer,
        )
        # host:c: independently trusted at the destination, migration-capable (default unrestricted
        # usages), but NOT the permit issuer.
        other_signer = EnvelopeSigner.generate("splice-other", "host:c", ("host:c", "host:destination"))
        trust_signer(destination_signer, other_signer)

        source = make_host(host_id="host:a", signer=source_signer)
        destination = make_host(host_id="host:destination", signer=destination_signer)
        source.policy.migration = MigrationPolicy(allowed=True, destinations=(destination.host_id,))
        provider = MigrateThenCompleteProvider(destination.host_id)
        source.providers["migrator"] = provider
        destination.providers["migrator"] = provider

        envelope = make_demo_envelope(source, "splice", "migrator")
        object.__setattr__(envelope.permit, "delegation_allowed", True)
        source.signer.seal(envelope)
        first = source.run(envelope)

        # A legit migration envelope binds all three identities together.
        migrated = envelope_from_dict(first.migration_envelope)
        self.assertEqual(migrated.permit.issuer, "host:a")
        self.assertEqual(migrated.previous_audit_host_id, "host:a")

        # Splice: swap the anchor for one validly signed by host:c over a self-consistent payload
        # (host_id=host:c), leaving the permit (issuer host:a) intact, then re-seal with the real
        # permit holder (host:a) so the envelope signature stays valid.
        forged_hash, forged_seq = "c0ffee-head", 5
        spliced = envelope_from_dict(first.migration_envelope)
        spliced.previous_audit_host_id = "host:c"
        spliced.previous_audit_hash = forged_hash
        spliced.previous_audit_sequence = forged_seq
        spliced.previous_audit_signature_key_id = other_signer.key_id
        spliced.previous_audit_signature = other_signer.sign_audit_head(spliced.state.task_id, "host:c", forged_hash, forged_seq)
        source.signer.seal(spliced)

        fresh_destination = make_host(host_id="host:destination", signer=destination_signer)
        fresh_destination.providers["migrator"] = provider
        with self.assertRaisesRegex(SecurityError, "audit host does not match permit issuer"):
            fresh_destination.run(spliced)
        # The finding is about false lineage being RECORDED. Prove the rejection is fail-closed:
        # no checkpoint and no audit chain were persisted for the spliced task at the destination.
        self.assertIsNone(fresh_destination.store.load_checkpoint(spliced.state.task_id))
        self.assertIsNone(fresh_destination.store.audit_head(spliced.state.task_id))

    def test_migration_envelope_digest_roundtrip_is_stable(self):
        # Section 4 finding #2: a migration receipt binds to the sealed envelope by digest.
        # The source digests its stored outbox JSON; the destination digests asdict() of the
        # envelope it reconstructed from the wire. Those MUST match, or a receipt can never
        # settle the delivery it belongs to. Pin the round-trip before anything depends on it.
        from portmark.security import migration_envelope_digest

        source_signer = EnvelopeSigner.generate("dg-source", "host:a", ("host:a", "host:destination"))
        destination_signer = trust_signer(
            EnvelopeSigner.generate("dg-dest", "host:destination", ("host:destination",)),
            source_signer,
        )
        source = make_host(host_id="host:a", signer=source_signer)
        destination = make_host(host_id="host:destination", signer=destination_signer)
        source.policy.migration = MigrationPolicy(allowed=True, destinations=(destination.host_id,))
        provider = MigrateThenCompleteProvider(destination.host_id)
        source.providers["migrator"] = provider
        envelope = make_demo_envelope(source, "digest", "migrator")
        object.__setattr__(envelope.permit, "delegation_allowed", True)
        source.signer.seal(envelope)
        first = source.run(envelope)

        sealed = first.migration_envelope  # source form: asdict(migrated)
        wire = canonical_json(sealed).decode("utf-8")  # what the source enqueues / ships
        reconstructed = asdict(envelope_from_dict(json.loads(wire)))  # destination's dict

        self.assertEqual(migration_envelope_digest(sealed), migration_envelope_digest(reconstructed))
        self.assertEqual(migration_envelope_digest(json.loads(wire)), migration_envelope_digest(reconstructed))

    def test_migration_receipt_sign_verify(self):
        from portmark.security import migration_receipt_payload

        dest = EnvelopeSigner.generate("rcpt-dest", "host:destination", ("host:destination",))
        source = EnvelopeSigner.generate("rcpt-source", "host:a", ("host:a",))
        trust_signer(source, dest)  # the source trusts the destination's receipt key (unrestricted usage)

        payload = migration_receipt_payload(
            task_id="t1", source_host_id="host:a", destination_host_id="host:destination",
            permit_nonce="n1", envelope_digest="deadbeef",
            destination_checkpoint_generation=0, destination_audit_head="head1", accepted_at=1000,
        )
        receipt = dest.sign_migration_receipt(payload)
        source.verify_migration_receipt(receipt)  # valid: trusted key, receipt usage, issuer==destination

        tampered = {**receipt, "destination_checkpoint_generation": 99}
        with self.assertRaisesRegex(SecurityError, "signature is invalid"):
            source.verify_migration_receipt(tampered)

        # a key lacking the 'receipt' usage is rejected
        limited = EnvelopeSigner.generate("rcpt-limited", "host:destination", ("host:destination",))
        source.registry.add(TrustedIdentity(limited.key_id, "host:destination", limited.public_key_bytes(), ("*",), usages=("audit",)))
        with self.assertRaisesRegex(SecurityError, "lacks the required 'receipt' usage"):
            source.verify_migration_receipt(limited.sign_migration_receipt(payload))

        # a signer whose issuer != destination_host_id cannot mint the receipt at all
        wrong = EnvelopeSigner.generate("rcpt-wrong", "host:c", ("host:c",))
        with self.assertRaisesRegex(SecurityError, "destination does not match signing identity"):
            wrong.sign_migration_receipt(payload)

    def _migration_pair(self, directory):
        # A source + destination that trust each other BOTH ways: the destination trusts the
        # source's migration key (anchor), and the source trusts the destination's receipt key.
        source_signer = EnvelopeSigner.generate("mr-source", "host:source", ("host:source", "host:destination"))
        destination_signer = trust_signer(
            EnvelopeSigner.generate("mr-dest", "host:destination", ("host:destination",)),
            source_signer,
        )
        trust_signer(source_signer, destination_signer)  # source trusts the destination's receipt key
        source_store = SQLiteRuntimeStore(Path(directory) / "source.sqlite")
        destination_store = SQLiteRuntimeStore(Path(directory) / "dest.sqlite")
        source = make_host(host_id="host:source", signer=source_signer, store=source_store, allow_ephemeral_signing_key=True)
        destination = make_host(host_id="host:destination", signer=destination_signer, store=destination_store, allow_ephemeral_signing_key=True)
        source.policy.migration = MigrationPolicy(allowed=True, destinations=("host:destination",))
        provider = MigrateThenCompleteProvider("host:destination")
        source.providers["migrator"] = provider
        destination.providers["migrator"] = provider
        envelope = make_demo_envelope(source, "receipt", "migrator")
        object.__setattr__(envelope.permit, "delegation_allowed", True)
        source.signer.seal(envelope)
        return source, destination, destination_signer, envelope

    def test_migration_receipt_issued_on_admission(self):
        from portmark.security import migration_envelope_digest

        with tempfile.TemporaryDirectory() as directory:
            source, destination, _, envelope = self._migration_pair(directory)
            first = source.run(envelope)
            self.assertIsNone(first.migration_receipt)  # the source issues none

            migrated = envelope_from_dict(first.migration_envelope)
            original_id = migrated.state.task_id  # section 4 #7: admission namespaces the stored id
            second = destination.run(migrated)
            self.assertEqual(second.status, "completed")
            receipt = second.migration_receipt
            self.assertIsNotNone(receipt)
            self.assertEqual(receipt["type"], "portmark.migration-receipt.v1")
            # The receipt payload keeps the ORIGINAL (source-chosen) task id so the source
            # settles against its outbox row; the destination stores everything under the
            # source-namespaced id (see below).
            self.assertEqual(receipt["task_id"], original_id)
            self.assertTrue(migrated.state.task_id.startswith("mig::"))
            self.assertNotEqual(migrated.state.task_id, original_id)
            self.assertEqual(receipt["source_host_id"], "host:source")
            self.assertEqual(receipt["destination_host_id"], "host:destination")
            self.assertEqual(receipt["permit_nonce"], migrated.permit.nonce)
            self.assertEqual(receipt["envelope_digest"], migration_envelope_digest(first.migration_envelope))
            # The receipt row is stored under the destination's namespaced id.
            self.assertEqual(destination.store.get_migration_receipt(migrated.state.task_id), receipt)

    def test_migration_settlement_verifies_before_marking_delivered(self):
        from portmark.security import migration_receipt_payload

        with tempfile.TemporaryDirectory() as directory:
            source, destination, destination_signer, envelope = self._migration_pair(directory)
            first = source.run(envelope)
            migrated = envelope_from_dict(first.migration_envelope)
            task_id = migrated.state.task_id  # capture BEFORE run: admission namespaces the id (section 4 #7)
            receipt = destination.run(migrated).migration_receipt
            self.assertEqual(len(source.store.list_pending_migrations()), 1)

            # tampered receipt (bad signature) -> rejected, row stays pending
            with self.assertRaisesRegex(SecurityError, "signature is invalid"):
                source.settle_migration(task_id, {**receipt, "destination_audit_head": "forged"})
            self.assertEqual(len(source.store.list_pending_migrations()), 1)

            # validly-signed receipt whose bindings don't match this row -> rejected, still pending
            mismatched = destination_signer.sign_migration_receipt(migration_receipt_payload(
                task_id=task_id, source_host_id="host:source", destination_host_id="host:destination",
                permit_nonce=migrated.permit.nonce, envelope_digest="wrong-digest",
                destination_checkpoint_generation=1, destination_audit_head="h", accepted_at=1,
            ))
            with self.assertRaisesRegex(SecurityError, "does not match the outbox row"):
                source.settle_migration(task_id, mismatched)
            self.assertEqual(len(source.store.list_pending_migrations()), 1)

            # the genuine receipt settles the row
            source.settle_migration(task_id, receipt)
            self.assertEqual(source.store.list_pending_migrations(), [])

    def test_migration_settlement_names_missing_destination_trust(self):
        with tempfile.TemporaryDirectory() as directory:
            source, destination, _, envelope = self._migration_pair(directory)
            first = source.run(envelope)
            migrated = envelope_from_dict(first.migration_envelope)
            original_id = migrated.state.task_id  # capture BEFORE run (section 4 #7 namespacing)
            receipt = destination.run(migrated).migration_receipt
            # A source that does NOT trust the destination's receipt key cannot settle.
            untrusting_signer = EnvelopeSigner.generate("mr-source", "host:source", ("host:source", "host:destination"))
            untrusting = make_host(host_id="host:source", signer=untrusting_signer, store=source.store, allow_ephemeral_signing_key=True)
            with self.assertRaisesRegex(SecurityError, "signing key is not trusted"):
                untrusting.settle_migration(original_id, receipt)

    def test_migration_duplicate_delivery_returns_receipt(self):
        # Auditor scenario: a lost ack triggers a re-delivery of the SAME envelope. Pre-fix this
        # raised "envelope audit head does not match stored audit head" (an undifferentiated replay
        # error) and the source could not settle. Now the destination returns the SAME receipt
        # without re-executing, so delivery can settle.
        with tempfile.TemporaryDirectory() as directory:
            source, destination, _, envelope = self._migration_pair(directory)
            sealed = source.run(envelope).migration_envelope

            first_receipt = destination.run(envelope_from_dict(sealed)).migration_receipt
            self.assertIsNotNone(first_receipt)

            # re-deliver the identical envelope: SAME receipt, no replay error
            again = destination.run(envelope_from_dict(sealed))
            self.assertEqual(again.migration_receipt, first_receipt)

            # a DIFFERENT envelope squatting the same task id (re-sealed with a new nonce) is rejected
            squatter = envelope_from_dict(sealed)
            object.__setattr__(squatter.permit, "nonce", "squatting-nonce")
            source.signer.seal(squatter)
            with self.assertRaisesRegex(SecurityError, "different envelope"):
                destination.run(squatter)

    def test_migration_lost_ack_settles_instead_of_staying_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            source, destination, _, envelope = self._migration_pair(directory)
            sealed = source.run(envelope).migration_envelope
            task_id = envelope_from_dict(sealed).state.task_id
            self.assertEqual(len(source.store.list_pending_migrations()), 1)  # pending before delivery

            destination.run(envelope_from_dict(sealed))  # destination admits; imagine the ACK is now lost
            self.assertEqual(len(source.store.list_pending_migrations()), 1)  # still pending (no ack)

            # dispatcher retries the exact envelope; the destination returns the same receipt
            receipt = destination.run(envelope_from_dict(sealed)).migration_receipt
            source.settle_migration(task_id, receipt)
            self.assertEqual(source.store.list_pending_migrations(), [])  # settled, not stuck forever

    def _challenge_migration_pair(self, directory, attester=None, require_challenge=True, with_attester=True,
                                  source_store=None, destination_store=None):
        # Section 4 #5 fixture. Like _migration_pair, plus challenge passing: the SOURCE requires a
        # challenge and trusts the DESTINATION's attestation authority; the DESTINATION carries a
        # migration attester (unless with_attester=False, to exercise the fail-closed path).
        source_signer = EnvelopeSigner.generate("mc-source", "host:source", ("host:source", "host:destination"))
        destination_signer = trust_signer(
            EnvelopeSigner.generate("mc-dest", "host:destination", ("host:destination",)),
            source_signer,
        )
        trust_signer(source_signer, destination_signer)  # source trusts the destination's receipt key
        authority = AttestationAuthority.generate("dest-enclave-key", "verifier:enclave")
        if with_attester and attester is None:
            attester = _StubMigrationAttester(authority)
        if not with_attester:
            attester = None
        source_policy = AttestationPolicy(
            (authority.trusted_authority(),),
            ("measurement:enclave",),
            require_migration_challenge=require_challenge,
        )
        if source_store is None:
            source_store = SQLiteRuntimeStore(Path(directory) / "csource.sqlite")
        if destination_store is None:
            destination_store = SQLiteRuntimeStore(Path(directory) / "cdest.sqlite")
        source = make_host(host_id="host:source", signer=source_signer, store=source_store,
                           attestation_policy=source_policy, allow_ephemeral_signing_key=True)
        destination = make_host(host_id="host:destination", signer=destination_signer, store=destination_store,
                                migration_attester=attester, allow_ephemeral_signing_key=True)
        source.policy.migration = MigrationPolicy(allowed=True, destinations=("host:destination",))
        provider = MigrateThenCompleteProvider("host:destination")
        source.providers["migrator"] = provider
        destination.providers["migrator"] = provider
        envelope = make_demo_envelope(source, "challenge", "migrator")
        object.__setattr__(envelope.permit, "delegation_allowed", True)
        source.signer.seal(envelope)
        return source, destination, attester, authority, envelope

    def test_migration_challenge_end_to_end_settles(self):
        # Happy path: challenge mode, a working attester -> migrate, admit, settle succeed and the
        # receipt carries the destination's fresh attestation over the source's challenge.
        with tempfile.TemporaryDirectory() as directory:
            source, destination, attester, _, envelope = self._challenge_migration_pair(directory)
            sealed = source.run(envelope).migration_envelope
            migrated = envelope_from_dict(sealed)
            original_id = migrated.state.task_id
            receipt = destination.run(migrated).migration_receipt
            self.assertIn("destination_attestation", receipt)
            self.assertEqual(receipt["destination_attestation"]["nonce"], migrated.permit.nonce)
            self.assertEqual(receipt["destination_attestation"]["subject"], "host:destination")
            self.assertEqual(receipt["destination_attestation"]["audience"], "host:source")
            source.settle_migration(original_id, receipt)
            self.assertEqual(source.store.list_pending_migrations(), [])

    def test_migration_challenge_end_to_end_on_both_backends(self):
        # G8: the challenge path admits + settles on SQLite AND Postgres. #5 adds no schema/SQL (the
        # attestation rides inside the opaque receipt JSON), so this confirms the receipt with the extra
        # signed field round-trips through both stores' receipt persistence.
        for context in self._dual_store_case_contexts():
            with context as (backend, source_store, destination_store):
                with self.subTest(backend=backend):
                    with tempfile.TemporaryDirectory() as directory:
                        source, destination, _, _, envelope = self._challenge_migration_pair(
                            directory, source_store=source_store, destination_store=destination_store)
                        migrated = envelope_from_dict(source.run(envelope).migration_envelope)
                        original_id = migrated.state.task_id
                        receipt = destination.run(migrated).migration_receipt
                        self.assertEqual(receipt["destination_attestation"]["nonce"], migrated.permit.nonce)
                        source.settle_migration(original_id, receipt)
                        self.assertEqual(source.store.list_pending_migrations(), [])

    def test_migration_challenge_evidence_must_bind_source_challenge(self):
        # CALIBRATED (G1, SOURCE-side defense in depth). A buggy/malicious destination could bypass its
        # own pre-persist check and hand the source a receipt whose evidence binds a nonce the source did
        # NOT mint. The source verifies the evidence against the challenge IT minted at settlement and
        # refuses; the row stays pending. Pre-fix (no settle-time challenge check) it settled. (An HONEST
        # destination's own pre-persist check catches this first -- see
        # test_challenge_invalid_attester_output_does_not_strand_migration.)
        from portmark.security import migration_receipt_payload

        with tempfile.TemporaryDirectory() as directory:
            source, destination, _, authority, envelope = self._challenge_migration_pair(directory)
            migrated = envelope_from_dict(source.run(envelope).migration_envelope)
            original_id = migrated.state.task_id
            good = destination.run(migrated).migration_receipt  # honest receipt -> valid bindings to reuse
            stale = asdict(authority.issue(
                subject="host:destination", audience="host:source", measurement="measurement:enclave",
                expires_at=int(time.time()) + 60, nonce="stale-nonce"))
            forged = destination.signer.sign_migration_receipt(migration_receipt_payload(
                task_id=good["task_id"], source_host_id=good["source_host_id"],
                destination_host_id=good["destination_host_id"], permit_nonce=good["permit_nonce"],
                envelope_digest=good["envelope_digest"],
                destination_checkpoint_generation=good["destination_checkpoint_generation"],
                destination_audit_head=good["destination_audit_head"], accepted_at=good["accepted_at"],
                destination_attestation=stale))
            with self.assertRaisesRegex(SecurityError, "nonce"):
                source.settle_migration(original_id, forged)
            self.assertEqual(len(source.store.list_pending_migrations()), 1)  # stays pending

    def test_migration_challenge_is_fresh_per_migration(self):
        # G2: the challenge the source mints is a fresh value, distinct per migration and never equal to
        # the incoming permit nonce it is replacing.
        with tempfile.TemporaryDirectory() as directory:
            source, destination, attester, _, envelope = self._challenge_migration_pair(directory)
            incoming_nonce = envelope.permit.nonce
            first = envelope_from_dict(source.run(envelope).migration_envelope)
            # A second, independent migration (fresh task) to the same destination.
            second_envelope = make_demo_envelope(source, "challenge-2", "migrator")
            object.__setattr__(second_envelope.permit, "delegation_allowed", True)
            source.signer.seal(second_envelope)
            second = envelope_from_dict(source.run(second_envelope).migration_envelope)
            self.assertNotEqual(first.permit.nonce, second.permit.nonce)          # distinct per migration
            self.assertNotEqual(first.permit.nonce, incoming_nonce)               # fresh, not the reused nonce
            self.assertEqual(attester.challenges, [])                             # attester runs at admission, not here
            destination.run(first)
            destination.run(second)
            self.assertEqual(sorted(attester.challenges), sorted([first.permit.nonce, second.permit.nonce]))

    def test_challenge_required_without_attester_fails_closed_before_persist(self):
        # CALIBRATED (G4, the availability-critical one). A destination that cannot satisfy a
        # challenge-required migration fails admission CLOSED before persisting anything -- no stored
        # evidence-less receipt to strand the row idempotently -- and the source can re-deliver once an
        # attester is available.
        from portmark.host import _namespaced_migration_task_id

        with tempfile.TemporaryDirectory() as directory:
            source, destination, _, authority, envelope = self._challenge_migration_pair(directory, with_attester=False)
            sealed = source.run(envelope).migration_envelope
            original_id = envelope_from_dict(sealed).state.task_id
            namespaced_id = _namespaced_migration_task_id("host:source", original_id)
            # Admission mutates the envelope in place, so each delivery attempt reconstructs from the
            # sealed bytes (exactly what a real re-delivery does).
            with self.assertRaisesRegex(SecurityError, "no attester is configured"):
                destination.run(envelope_from_dict(sealed))
            # Nothing persisted: no checkpoint, no receipt under the destination's namespaced id.
            self.assertIsNone(destination.store.load_checkpoint(namespaced_id))
            self.assertIsNone(destination.store.get_migration_receipt(namespaced_id))
            self.assertEqual(len(source.store.list_pending_migrations()), 1)  # source can still re-deliver
            # Recover: an attester is installed and the SAME sealed envelope now admits + settles.
            destination.migration_attester = _StubMigrationAttester(authority)
            receipt = destination.run(envelope_from_dict(sealed)).migration_receipt
            source.settle_migration(original_id, receipt)
            self.assertEqual(source.store.list_pending_migrations(), [])

    def test_challenge_mode_delegated_permit_shape(self):
        # G5 (advisor #1 pin): in challenge mode the migrated permit carries a FRESH nonce (not the
        # source's incoming nonce) and NO source-provided attestation (which, bound to the incoming
        # nonce, would make the destination's verify_execution raise against the fresh challenge).
        with tempfile.TemporaryDirectory() as directory:
            source, _destination, _, _, envelope = self._challenge_migration_pair(directory)
            migrated = envelope_from_dict(source.run(envelope).migration_envelope)
            self.assertNotEqual(migrated.permit.nonce, envelope.permit.nonce)
            self.assertIsNone(migrated.permit.attestation)
            self.assertTrue(migrated.state.memory["migration"]["challenge_required"])

    def test_challenge_receipt_shape_and_missing_evidence(self):
        # G6: the optional destination_attestation is allowed by the exact-match shape check; an
        # unknown extra field is still rejected; and a challenge-required row whose receipt carries NO
        # attestation is refused at settlement (fail closed).
        with tempfile.TemporaryDirectory() as directory:
            source, destination, _, _, envelope = self._challenge_migration_pair(directory)
            migrated = envelope_from_dict(source.run(envelope).migration_envelope)
            original_id = migrated.state.task_id
            receipt = destination.run(migrated).migration_receipt
            source.signer.verify_migration_receipt(receipt)  # optional field verifies
            with self.assertRaisesRegex(SecurityError, "unexpected fields"):
                source.signer.verify_migration_receipt({**receipt, "surprise": 1})
            # A VALIDLY-SIGNED receipt with NO attestation (e.g. a mixed-version old destination that
            # ignored the challenge marker) cannot settle a challenge-required row: fail closed.
            from portmark.security import migration_receipt_payload
            evidence_less = destination.signer.sign_migration_receipt(migration_receipt_payload(
                task_id=receipt["task_id"], source_host_id=receipt["source_host_id"],
                destination_host_id=receipt["destination_host_id"], permit_nonce=receipt["permit_nonce"],
                envelope_digest=receipt["envelope_digest"],
                destination_checkpoint_generation=receipt["destination_checkpoint_generation"],
                destination_audit_head=receipt["destination_audit_head"], accepted_at=receipt["accepted_at"],
            ))
            with self.assertRaisesRegex(SecurityError, "challenge attestation is required"):
                source.settle_migration(original_id, evidence_less)
            self.assertEqual(len(source.store.list_pending_migrations()), 1)

    def test_challenge_evidence_wrong_audience_refused(self):
        # G7: the destination's evidence must be addressed to the SOURCE. Evidence addressed elsewhere is
        # caught by the destination's own pre-persist check at admission (nothing persisted, source stays
        # pending, so a corrected attester can re-deliver). The source's settle-time check is the same
        # audience rule as defense in depth.
        with tempfile.TemporaryDirectory() as directory:
            source, destination, _, authority, envelope = self._challenge_migration_pair(directory)
            destination.migration_attester = _StubMigrationAttester(authority, audience_override="host:elsewhere")
            with self.assertRaisesRegex(SecurityError, "audience does not match the source"):
                destination.run(envelope_from_dict(source.run(envelope).migration_envelope))
            self.assertEqual(len(source.store.list_pending_migrations()), 1)

    def test_challenge_flaky_attester_fails_closed_as_security_error(self):
        # An attester that raises fails admission CLOSED as a SecurityError (not an uncaught RuntimeError
        # out of run(), the EV-010 defect class), and persists nothing -- so the source can re-deliver.
        from portmark.host import _namespaced_migration_task_id

        with tempfile.TemporaryDirectory() as directory:
            flaky = _StubMigrationAttester(
                AttestationAuthority.generate("dest-enclave-key", "verifier:enclave"), raise_error=True)
            source, destination, _, authority, envelope = self._challenge_migration_pair(directory, attester=flaky)
            sealed = source.run(envelope).migration_envelope
            original_id = envelope_from_dict(sealed).state.task_id
            namespaced_id = _namespaced_migration_task_id("host:source", original_id)
            with self.assertRaisesRegex(SecurityError, "challenge attestation failed"):
                destination.run(envelope_from_dict(sealed))
            self.assertIsNone(destination.store.load_checkpoint(namespaced_id))  # nothing persisted
            self.assertEqual(len(source.store.list_pending_migrations()), 1)
            # Recover: a working attester on the AUTHORITY the source trusts admits + settles.
            destination.migration_attester = _StubMigrationAttester(authority)
            receipt = destination.run(envelope_from_dict(sealed)).migration_receipt
            source.settle_migration(original_id, receipt)
            self.assertEqual(source.store.list_pending_migrations(), [])

    def test_challenge_mode_incompatible_with_required_execution_attestation(self):
        # Documented bound: challenge mode carries NO permit attestation (the destination's proof rides
        # in the receipt, not the permit), so a destination that ALSO requires an execution attestation
        # on the migrated permit refuses -- fail CLOSED, the safe direction. An operator picks ONE of the
        # two attestation mechanisms per destination.
        with tempfile.TemporaryDirectory() as directory:
            authority = AttestationAuthority.generate("dest-enclave-key", "verifier:enclave")
            source, destination, _, _, envelope = self._challenge_migration_pair(directory)
            destination.attestation_policy = AttestationPolicy(
                (authority.trusted_authority(),), ("measurement:enclave",), required_for_execution=True
            )
            with self.assertRaisesRegex(SecurityError, "attestation evidence is required"):
                destination.run(envelope_from_dict(source.run(envelope).migration_envelope))

    def test_challenge_invalid_attester_output_does_not_strand_migration(self):
        # Auditor Medium (CALIBRATED). An attester that returns a valid AttestationEvidence INSTANCE but
        # with a semantically-bad nonce must NOT be persisted -- otherwise the keep-first receipt store
        # freezes it, redelivery returns it idempotently forever, the source rejects it, and even a
        # corrected attester cannot recover (permanent wedge, the auditor's repro). The destination
        # validates its OWN attester output before persist; bad output fails closed with nothing stored,
        # and a corrected attester then admits + settles. CALIBRATED: with the pre-persist check disabled
        # the bad receipt is stored and redelivery-after-repair returns it unchanged (the wedge).
        from portmark.host import _namespaced_migration_task_id

        with tempfile.TemporaryDirectory() as directory:
            bad = _StubMigrationAttester(
                AttestationAuthority.generate("dest-enclave-key", "verifier:enclave"), nonce_override="stale")
            source, destination, _, authority, envelope = self._challenge_migration_pair(directory, attester=bad)
            sealed = source.run(envelope).migration_envelope
            original_id = envelope_from_dict(sealed).state.task_id
            namespaced_id = _namespaced_migration_task_id("host:source", original_id)
            with self.assertRaisesRegex(SecurityError, "nonce does not match the challenge"):
                destination.run(envelope_from_dict(sealed))
            self.assertIsNone(destination.store.get_migration_receipt(namespaced_id))  # NOT persisted
            self.assertEqual(len(source.store.list_pending_migrations()), 1)
            # Recovery: a correct attester on the source-trusted authority admits + settles the same envelope.
            destination.migration_attester = _StubMigrationAttester(authority)
            receipt = destination.run(envelope_from_dict(sealed)).migration_receipt
            source.settle_migration(original_id, receipt)
            self.assertEqual(source.store.list_pending_migrations(), [])

    def test_challenge_attester_timeout_fails_closed(self):
        # Finding 2: the host bounds the attester call, so a hung attester fails admission CLOSED (nothing
        # persisted) instead of holding admission open indefinitely.
        from portmark.host import _namespaced_migration_task_id

        with tempfile.TemporaryDirectory() as directory:
            authority = AttestationAuthority.generate("dest-enclave-key", "verifier:enclave")
            slow = _StubMigrationAttester(authority, sleep_seconds=1.0)
            source, destination, _, _, envelope = self._challenge_migration_pair(directory, attester=slow)
            destination.migration_attester_timeout = 0.2
            sealed = source.run(envelope).migration_envelope
            namespaced_id = _namespaced_migration_task_id("host:source", envelope_from_dict(sealed).state.task_id)
            with self.assertRaisesRegex(SecurityError, "timed out"):
                destination.run(envelope_from_dict(sealed))
            self.assertIsNone(destination.store.get_migration_receipt(namespaced_id))
            self.assertEqual(len(source.store.list_pending_migrations()), 1)

    def test_challenge_wrong_key_evidence_recovers_via_regeneration(self):
        # Auditor round 2 Medium (CALIBRATED). A first attester whose evidence is correct in every
        # dimension the DESTINATION can locally check, but signed by a key the SOURCE does not trust
        # (same key id, different keypair), passes the destination's pre-persist check (the destination
        # is not configured with the authority, so it cannot evaluate the signature) and IS persisted.
        # Keep-first storage would freeze it and the source could never settle. On redelivery the
        # destination REGENERATES the attestation, so a corrected attester's evidence replaces the bad
        # one and the source settles. CALIBRATED: with redelivery regeneration disabled, redelivery
        # returns the frozen bad receipt and settlement still fails (the auditor's WRONG_KEY_PERSISTED
        # wedge).
        with tempfile.TemporaryDirectory() as directory:
            rogue = AttestationAuthority.generate("dest-enclave-key", "verifier:enclave")  # source does NOT trust this keypair
            source, destination, _, authority, envelope = self._challenge_migration_pair(
                directory, attester=_StubMigrationAttester(rogue))
            sealed = source.run(envelope).migration_envelope
            original_id = envelope_from_dict(sealed).state.task_id
            bad_receipt = destination.run(envelope_from_dict(sealed)).migration_receipt  # persisted (dest can't check the key)
            self.assertIsNotNone(bad_receipt)
            with self.assertRaisesRegex(SecurityError, "signature is invalid"):
                source.settle_migration(original_id, bad_receipt)
            self.assertEqual(len(source.store.list_pending_migrations()), 1)  # would be stuck forever pre-fix
            # Install the correct attester (trusted keypair) and REDELIVER: regeneration produces valid evidence.
            destination.migration_attester = _StubMigrationAttester(authority)
            good_receipt = destination.run(envelope_from_dict(sealed)).migration_receipt
            self.assertNotEqual(good_receipt["destination_attestation"], bad_receipt["destination_attestation"])
            source.settle_migration(original_id, good_receipt)
            self.assertEqual(source.store.list_pending_migrations(), [])

    def test_challenge_regenerated_receipt_is_durable_across_lost_ack_and_attester_outage(self):
        # Auditor round 3 Medium (CALIBRATED). A regenerated GOOD receipt must be PERSISTED, so recovery
        # survives a lost acknowledgement followed by an attester outage. Repro: wrong-key first evidence
        # is persisted; a corrected attester regenerates a good receipt on redelivery but the ack is LOST
        # (source still pending); the attester then goes DOWN; a further redelivery must still settle from
        # the durably-stored good receipt. CALIBRATED: without persisting the regenerated receipt the
        # store keeps the bad one and the post-outage redelivery cannot settle. Runs on SQLite AND
        # Postgres so the durable overwrite (replace_migration_receipt) is exercised on both backends.
        from portmark.host import _namespaced_migration_task_id

        for context in self._dual_store_case_contexts():
            with context as (backend, source_store, destination_store):
                with self.subTest(backend=backend):
                    with tempfile.TemporaryDirectory() as directory:
                        rogue = AttestationAuthority.generate("dest-enclave-key", "verifier:enclave")
                        source, destination, _, authority, envelope = self._challenge_migration_pair(
                            directory, attester=_StubMigrationAttester(rogue),
                            source_store=source_store, destination_store=destination_store)
                        sealed = source.run(envelope).migration_envelope
                        original_id = envelope_from_dict(sealed).state.task_id
                        namespaced_id = _namespaced_migration_task_id("host:source", original_id)
                        destination.run(envelope_from_dict(sealed))  # bad receipt persisted (dest cannot check the key)
                        # Corrected attester; redeliver -> regenerates + PERSISTS a good receipt, ack LOST.
                        destination.migration_attester = _StubMigrationAttester(authority)
                        good_receipt = destination.run(envelope_from_dict(sealed)).migration_receipt
                        self.assertEqual(len(source.store.list_pending_migrations()), 1)  # source never got the ack
                        self.assertEqual(
                            destination.store.get_migration_receipt(namespaced_id)["destination_attestation"],
                            good_receipt["destination_attestation"],
                        )  # the stored receipt is now the regenerated GOOD one (durably overwritten)
                        # Attester goes DOWN; a later redelivery falls back to the durably-stored good receipt.
                        destination.migration_attester = None
                        recovered = destination.run(envelope_from_dict(sealed)).migration_receipt
                        source.settle_migration(original_id, recovered)
                        self.assertEqual(source.store.list_pending_migrations(), [])

    def test_challenge_attester_calls_are_bounded_no_thread_explosion(self):
        # Finding 2b: repeated delivery against a hung attester must NOT spawn an unbounded number of
        # worker threads. The host caps concurrent in-flight attester calls; excess calls are refused
        # fail-closed rather than each spawning a thread (the auditor observed 13 threads from 12 calls).
        with tempfile.TemporaryDirectory() as directory:
            authority = AttestationAuthority.generate("dest-enclave-key", "verifier:enclave")
            hung = _StubMigrationAttester(authority, sleep_seconds=3.0)
            source, destination, _, _, envelope = self._challenge_migration_pair(directory, attester=hung)
            destination.migration_attester_timeout = 0.1
            destination._attester_slots = threading.BoundedSemaphore(2)  # tighten the bound for the test
            sealed = source.run(envelope).migration_envelope
            before = threading.active_count()
            refusals = 0
            for _ in range(12):
                try:
                    destination.run(envelope_from_dict(sealed))
                except SecurityError as error:
                    if "capacity" in str(error):
                        refusals += 1
            after = threading.active_count()
            self.assertLessEqual(after - before, 2)  # bounded by the semaphore, not 12
            self.assertGreater(refusals, 0)          # excess calls refused, not spawned

    def test_migration_receipt_rejects_unsigned_fields(self):
        # Auditor follow-up (Medium): the signature covers only the body fields, so an unsigned extra
        # field must NOT ride inside a verified receipt (it would be persisted as if signed). Pre-fix
        # the auditor reproduced UNSIGNED_EXTRA_SETTLED=True with a `completion_status` field.
        from portmark.security import migration_receipt_payload

        dest = EnvelopeSigner.generate("uf-dest", "host:destination", ("host:destination",))
        source = EnvelopeSigner.generate("uf-source", "host:a", ("host:a",))
        trust_signer(source, dest)
        payload = migration_receipt_payload(
            task_id="t", source_host_id="host:a", destination_host_id="host:destination",
            permit_nonce="n", envelope_digest="d", destination_checkpoint_generation=1,
            destination_audit_head="h", accepted_at=1,
        )
        receipt = dest.sign_migration_receipt(payload)
        source.verify_migration_receipt(receipt)  # baseline: exact field set verifies

        with self.assertRaisesRegex(SecurityError, "unexpected fields"):  # extra scalar, signature unchanged
            source.verify_migration_receipt({**receipt, "completion_status": "completed"})
        with self.assertRaisesRegex(SecurityError, "unexpected fields"):  # extra nested object
            source.verify_migration_receipt({**receipt, "extra": {"nested": True}})

        # HMAC path enforces the same exact-shape rule
        hm = HmacEnvelopeSigner(b"k" * 32, "hmac-receipt-key")
        h_receipt = hm.sign_migration_receipt(payload)
        hm.verify_migration_receipt(h_receipt)
        with self.assertRaisesRegex(SecurityError, "unexpected fields"):
            hm.verify_migration_receipt({**h_receipt, "completion_status": "completed"})

        # End-to-end: settle refuses an extra-field receipt and the row stays pending.
        with tempfile.TemporaryDirectory() as directory:
            src_host, dst_host, _, envelope = self._migration_pair(directory)
            migrated = envelope_from_dict(src_host.run(envelope).migration_envelope)
            original_id = migrated.state.task_id  # capture BEFORE run (section 4 #7 namespacing)
            good = dst_host.run(migrated).migration_receipt
            with self.assertRaisesRegex(SecurityError, "unexpected fields"):
                src_host.settle_migration(original_id, {**good, "completion_status": "completed"})
            self.assertEqual(len(src_host.store.list_pending_migrations()), 1)  # still pending
            src_host.settle_migration(original_id, good)  # genuine receipt settles
            self.assertEqual(src_host.store.list_pending_migrations(), [])

    def test_migration_receipt_verify_rejection_branches(self):
        # Exercise every rejection path in receipt verification (Ed25519 + HMAC).
        from portmark.security import migration_receipt_payload

        dest = EnvelopeSigner.generate("br-dest", "host:destination", ("host:destination",))
        pub = dest.public_key_bytes()
        payload = migration_receipt_payload(
            task_id="t", source_host_id="host:a", destination_host_id="host:destination",
            permit_nonce="n", envelope_digest="d", destination_checkpoint_generation=1,
            destination_audit_head="h", accepted_at=1000,
        )
        receipt = dest.sign_migration_receipt(payload)

        def reg(**kw):
            registry = TrustRegistry()
            registry.add(TrustedIdentity("br-dest", "host:destination", pub, ("*",), **kw))
            return registry

        # sign rejects a malformed payload (missing field / unknown type)
        with self.assertRaisesRegex(SecurityError, "missing a required field"):
            dest.sign_migration_receipt({k: v for k, v in payload.items() if k != "accepted_at"})
        with self.assertRaisesRegex(SecurityError, "unknown type"):
            dest.sign_migration_receipt({**payload, "type": "nope"})

        # verify: right key set but wrong type value -> unknown type; empty signature -> missing
        with self.assertRaisesRegex(SecurityError, "unknown type"):
            reg().verify_migration_receipt({**receipt, "type": "nope"})
        with self.assertRaisesRegex(SecurityError, "signature is missing"):
            reg().verify_migration_receipt({**receipt, "signature": ""})
        # untrusted / revoked / not-yet-active / expired / wrong-usage / host-mismatch / bad-sig
        with self.assertRaisesRegex(SecurityError, "not trusted"):
            TrustRegistry().verify_migration_receipt(receipt)
        with self.assertRaisesRegex(SecurityError, "has been revoked"):
            reg(revoked=True).verify_migration_receipt(receipt, now=1000)
        with self.assertRaisesRegex(SecurityError, "not active yet"):
            reg(not_before=5000).verify_migration_receipt(receipt, now=1000)
        with self.assertRaisesRegex(SecurityError, "has expired"):
            reg(expires_at=500).verify_migration_receipt(receipt, now=1000)
        with self.assertRaisesRegex(SecurityError, "'receipt' usage"):
            reg(usages=("audit",)).verify_migration_receipt(receipt, now=1000)
        elsewhere = TrustRegistry()
        elsewhere.add(TrustedIdentity("br-dest", "host:elsewhere", pub, ("*",)))
        with self.assertRaisesRegex(SecurityError, "does not match the destination host"):
            elsewhere.verify_migration_receipt(receipt, now=1000)
        flipped = receipt["signature"][:-2] + ("AA" if not receipt["signature"].endswith("AA") else "BB")
        with self.assertRaisesRegex(SecurityError, "signature is invalid"):
            reg().verify_migration_receipt({**receipt, "signature": flipped}, now=1000)

        # HMAC path: baseline verifies; wrong key and bad signature rejected
        hm = HmacEnvelopeSigner(b"k" * 32, "hk")
        h_receipt = hm.sign_migration_receipt(payload)
        hm.verify_migration_receipt(h_receipt)
        with self.assertRaisesRegex(SecurityError, "not trusted"):
            HmacEnvelopeSigner(b"k" * 32, "other").verify_migration_receipt(h_receipt)
        with self.assertRaisesRegex(SecurityError, "signature is invalid"):
            hm.verify_migration_receipt({**h_receipt, "signature": "00"})

    def test_migration_receipt_write_failure_rolls_back_admission(self):
        # Atomicity: the receipt is written inside the destination's admission transaction, so if the
        # receipt insert fails the WHOLE admission rolls back -- no checkpoint, no consumed nonce, no
        # audit head, no partial receipt.
        import portmark.storage as storage_module

        with tempfile.TemporaryDirectory() as directory:
            source, destination, _, envelope = self._migration_pair(directory)
            migrated = envelope_from_dict(source.run(envelope).migration_envelope)
            task_id = migrated.state.task_id

            def boom(self, task_id, receipt_json):  # noqa: ARG001
                raise RuntimeError("simulated receipt write failure")

            with patch.object(storage_module._SQLiteTransaction, "store_migration_receipt", boom):
                with self.assertRaises(RuntimeError):
                    destination.run(migrated)

            self.assertIsNone(destination.store.load_checkpoint(task_id))
            self.assertIsNone(destination.store.audit_head(task_id))
            self.assertFalse(destination.store.consumed_nonce_exists(migrated.permit.nonce))
            self.assertIsNone(destination.store.get_migration_receipt(task_id))

    # ---- Section 4 part 3a: outbox reliability (#3 claim/lease, #4 dead-letter, #8 conflict) ----

    @contextmanager
    def _memory_outbox_case(self):
        yield "memory", InMemoryRuntimeStore()

    def _outbox_store_contexts(self):
        # All three store implementations of the outbox reliability API. Postgres is included in CI
        # (PORTMARK_TEST_POSTGRES_DSN) and exercises FOR UPDATE SKIP LOCKED / RETURNING.
        return [self._memory_outbox_case(), *self._store_case_contexts()]

    def _seed_outbox(self, store, task_id, sealed="{}", destination="host:destination"):
        with store.transaction() as txn:
            txn.enqueue_migration(task_id, destination, sealed)

    @contextmanager
    def _clocked_outbox_stores(self, clock):
        # The EMBEDDED stores (memory + sqlite) built with an injected clock, so a test controls "now"
        # WITHOUT any per-call time parameter -- time is a construction dependency, never caller-supplied.
        # Postgres is intentionally excluded here: its lease operations use DATABASE time
        # (clock_timestamp()), not the injected clock, precisely so skewed dispatcher hosts can't break
        # exclusivity -- that behavior is covered by test_migration_lease_uses_db_time_not_host_clock.
        with tempfile.TemporaryDirectory() as directory:
            yield [
                ("memory", InMemoryRuntimeStore(clock=clock)),
                ("sqlite", SQLiteRuntimeStore(Path(directory) / "outbox.sqlite", clock=clock)),
            ]

    def test_migration_claim_is_exclusive(self):
        # #3: a claimed row is never handed to a second worker. With two pending rows and limit=1,
        # two workers get DISJOINT rows; a third claim finds nothing left.
        # CALIBRATE: pre-fix there was no claim -- list_pending_migrations() handed the SAME rows to
        # every dispatcher, so both would ship t1 (double-dispatch). Asserted below via disjointness.
        for context in self._outbox_store_contexts():
            with context as (backend, store):
                with self.subTest(backend=backend):
                    self._seed_outbox(store, "t1", sealed='{"n":1}')
                    self._seed_outbox(store, "t2", sealed='{"n":2}')
                    a = store.claim_migrations("worker-a", lease_seconds=60, limit=1)
                    b = store.claim_migrations("worker-b", lease_seconds=60, limit=1)
                    c = store.claim_migrations("worker-c", lease_seconds=60, limit=1)
                    a_ids = {row["task_id"] for row in a}
                    b_ids = {row["task_id"] for row in b}
                    self.assertEqual(len(a), 1)
                    self.assertEqual(len(b), 1)
                    self.assertEqual(a_ids & b_ids, set())  # disjoint: no row claimed twice
                    self.assertEqual(a_ids | b_ids, {"t1", "t2"})  # both rows claimed exactly once
                    self.assertEqual(c, [])  # nothing left to claim
                    self.assertEqual(a[0]["claimed_by"], "worker-a")

    def test_migration_claim_is_race_safe_under_threads(self):
        # #3 on SQLite specifically: BEGIN IMMEDIATE must serialize concurrent claimers so no row is
        # claimed twice even under real thread contention (not just sequential calls).
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(Path(directory) / "race.sqlite")
            for i in range(20):
                self._seed_outbox(store, f"t{i:02d}", sealed=f'{{"n":{i}}}')
            claimed_by_worker = {}
            barrier = threading.Barrier(4)

            def worker(name):
                barrier.wait()
                got = []
                while True:
                    rows = store.claim_migrations(name, lease_seconds=60, limit=1)
                    if not rows:
                        break
                    got.append(rows[0]["task_id"])
                claimed_by_worker[name] = got

            threads = [threading.Thread(target=worker, args=(f"w{n}",)) for n in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            all_claimed = [tid for got in claimed_by_worker.values() for tid in got]
            self.assertEqual(len(all_claimed), 20)  # every row claimed
            self.assertEqual(len(set(all_claimed)), 20)  # each row claimed by exactly one worker

    def test_migration_lease_expiry_and_release(self):
        # #3: a claimed row is not re-claimable until its lease expires; after expiry it is; the
        # holder can release it early; a NON-holder can neither release nor re-claim a live lease.
        # Time is controlled by an injected clock at CONSTRUCTION (mutable dict), not a per-call arg.
        now = {"t": 1000}
        clock = lambda: now["t"]  # noqa: E731
        with self._clocked_outbox_stores(clock) as stores:
            for backend, store in stores:
                with self.subTest(backend=backend):
                    now["t"] = 1000
                    self._seed_outbox(store, "t1", sealed='{"n":1}')
                    claimed = store.claim_migrations("worker-a", lease_seconds=100, limit=1)
                    self.assertEqual(len(claimed), 1)
                    # list_pending is a visibility query, not a queue: it still shows the claimed row,
                    # and exposes who holds it so a caller can't mistake it for unclaimed work.
                    visible = store.list_pending_migrations()
                    self.assertEqual([row["task_id"] for row in visible], ["t1"])
                    self.assertEqual(visible[0]["claimed_by"], "worker-a")
                    # Before expiry, another worker gets nothing.
                    now["t"] = 1050
                    self.assertEqual(store.claim_migrations("worker-b", lease_seconds=100, limit=1), [])
                    # A non-holder cannot release the row (while worker-a's lease is still live).
                    self.assertFalse(store.release_migration("t1", "worker-b"))
                    self.assertEqual(store.claim_migrations("worker-b", lease_seconds=100, limit=1), [])
                    # After the lease expires, it is re-claimable by another worker.
                    now["t"] = 1101
                    later = store.claim_migrations("worker-b", lease_seconds=100, limit=1)
                    self.assertEqual([row["task_id"] for row in later], ["t1"])
                    self.assertEqual(later[0]["claimed_by"], "worker-b")
                    # The holder can release early (within its lease), making it immediately re-claimable.
                    now["t"] = 1150
                    self.assertTrue(store.release_migration("t1", "worker-b"))
                    reclaim = store.claim_migrations("worker-c", lease_seconds=100, limit=1)
                    self.assertEqual([row["task_id"] for row in reclaim], ["t1"])

    def test_migration_dead_letter_and_requeue(self):
        # #4: a row the dispatcher gives up on gets a terminal 'dead' state (leaves the pending
        # queue, appears in list_dead_migrations) and is recoverable via requeue. A non-holder
        # cannot dead-letter. CALIBRATE: pre-fix there was NO terminal state -- a row whose attempts
        # were exhausted stayed pending forever (asserted below before the fix's dead-letter runs).
        for context in self._outbox_store_contexts():
            with context as (backend, store):
                with self.subTest(backend=backend):
                    self._seed_outbox(store, "t1", sealed='{"n":1}')
                    claimed = store.claim_migrations("worker-a", lease_seconds=60, limit=1)
                    self.assertEqual(len(claimed), 1)
                    # Stranding the fix cures: attempts exhaust but the row is still just pending.
                    for _ in range(5):
                        store.record_migration_attempt("t1", "worker-a")
                    self.assertEqual([row["task_id"] for row in store.list_pending_migrations()], ["t1"])
                    self.assertEqual(store.list_dead_migrations(), [])
                    # A non-holder cannot dead-letter the row.
                    self.assertFalse(store.dead_letter_migration("t1", "worker-x", "not yours"))
                    # The holder dead-letters it: it leaves pending and gains a terminal state.
                    self.assertTrue(store.dead_letter_migration("t1", "worker-a", "permit expired"))
                    self.assertEqual(store.list_pending_migrations(), [])
                    dead = store.list_dead_migrations()
                    self.assertEqual([row["task_id"] for row in dead], ["t1"])
                    self.assertEqual(dead[0]["dead_reason"], "permit expired")
                    # Operator recovery returns it to the queue, clearing the dead reason.
                    self.assertTrue(store.requeue_migration("t1"))
                    self.assertEqual([row["task_id"] for row in store.list_pending_migrations()], ["t1"])
                    self.assertEqual(store.list_dead_migrations(), [])
                    self.assertFalse(store.requeue_migration("t1"))  # no longer dead

    def test_migration_outbox_conflict_is_loud(self):
        # #8: same task_id + identical envelope = idempotent no-op (keep-first); a DIFFERENT envelope
        # under the same task_id raises instead of the old ON CONFLICT DO NOTHING silent drop.
        # CALIBRATE: pre-fix the different-envelope enqueue silently succeeded and the FIRST envelope
        # stayed (the new one lost) with no error; post-fix it raises (asserted here).
        for context in self._outbox_store_contexts():
            with context as (backend, store):
                with self.subTest(backend=backend):
                    self._seed_outbox(store, "t1", sealed='{"payload":"A"}')
                    # Identical re-enqueue is an idempotent no-op.
                    self._seed_outbox(store, "t1", sealed='{"payload":"A"}')
                    self.assertEqual(len(store.list_pending_migrations()), 1)
                    # A different envelope under the same task id is a real collision -> raise.
                    with self.assertRaises(SecurityError):
                        self._seed_outbox(store, "t1", sealed='{"payload":"B"}')
                    # The original row is untouched (the conflicting write did not overwrite it).
                    rows = store.list_pending_migrations()
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]["sealed_envelope_json"], '{"payload":"A"}')

    def test_migration_dead_row_still_settles(self):
        # B1 regression guard: dead-lettering a row (#4) must NOT strand a valid late receipt. A
        # dispatcher gives up and dead-letters, then a genuine verified receipt arrives -- it settles
        # the dead row (a verified receipt beats the local give-up). Protects the section 4 #2 fix.
        with tempfile.TemporaryDirectory() as directory:
            source, destination, _, envelope = self._migration_pair(directory)
            sealed = source.run(envelope).migration_envelope
            task_id = envelope_from_dict(sealed).state.task_id
            receipt = destination.run(envelope_from_dict(sealed)).migration_receipt

            # The source dispatcher claims the row and gives up on it (dead-letter).
            claimed = source.store.claim_migrations("dispatcher", lease_seconds=60, limit=1)
            self.assertEqual([row["task_id"] for row in claimed], [task_id])
            self.assertTrue(source.store.dead_letter_migration(task_id, "dispatcher", "gave up"))
            self.assertEqual([row["task_id"] for row in source.store.list_dead_migrations()], [task_id])

            # A genuine receipt still settles the dead row.
            source.settle_migration(task_id, receipt)
            self.assertEqual(source.store.list_pending_migrations(), [])  # settled
            self.assertEqual(source.store.list_dead_migrations(), [])  # no longer dead -> delivered
            # And re-settlement of a delivered row is out of scope (Part 2b): the row is no longer
            # findable for settlement, so a second settle raises rather than double-processing.
            with self.assertRaises(SecurityError):
                source.settle_migration(task_id, receipt)

    def test_migration_claim_rejects_bad_input(self):
        # #3 fix round: exclusivity holds only for well-formed leases, so bad inputs are rejected up
        # front rather than silently defeating it (a zero/negative lease let two workers claim the
        # same row). bool is an int subclass and must be rejected too.
        for context in self._outbox_store_contexts():
            with context as (backend, store):
                with self.subTest(backend=backend):
                    self._seed_outbox(store, "t1", sealed='{"n":1}')
                    for bad in ("", "   "):
                        with self.assertRaises(SecurityError):
                            store.claim_migrations(bad, lease_seconds=60, limit=1)
                    for bad in (0, -5, True, 1.5, "60"):
                        with self.assertRaises(SecurityError):
                            store.claim_migrations("worker", lease_seconds=bad, limit=1)
                    from portmark.storage import MAX_MIGRATION_LEASE_SECONDS
                    with self.assertRaises(SecurityError):
                        store.claim_migrations("worker", lease_seconds=MAX_MIGRATION_LEASE_SECONDS + 1, limit=1)
                    # The ceiling itself is a LEGAL lease (fencepost: MAX accepted, MAX+1 rejected).
                    at_ceiling = store.claim_migrations("worker", lease_seconds=MAX_MIGRATION_LEASE_SECONDS, limit=1)
                    self.assertEqual([row["task_id"] for row in at_ceiling], ["t1"])
                    store.release_migration("t1", "worker")  # unclaim for the assertion below
                    for bad in (0, -1, True, 2.0):
                        with self.assertRaises(SecurityError):
                            store.claim_migrations("worker", lease_seconds=60, limit=bad)
                    # The row was never claimed by any rejected call.
                    self.assertIsNone(store.list_pending_migrations()[0].get("claimed_by"))

    def test_migration_expired_holder_loses_authority(self):
        # #3 fix round: an EXPIRED holder is no longer the logical owner even though its name is still
        # in claimed_by. It must not be able to release, dead-letter, or count an attempt -- both
        # before another worker reclaims AND after. A LIVE holder still can. Injected clock, no _now.
        now = {"t": 1000}
        clock = lambda: now["t"]  # noqa: E731
        with self._clocked_outbox_stores(clock) as stores:
            for backend, store in stores:
                with self.subTest(backend=backend):
                    now["t"] = 1000
                    self._seed_outbox(store, "t1", sealed='{"n":1}')
                    store.claim_migrations("w1", lease_seconds=100, limit=1)  # lease -> 1100
                    # BEFORE reclaim: w1's lease has expired (now=1200 > 1100) -> no authority.
                    now["t"] = 1200
                    self.assertFalse(store.release_migration("t1", "w1"))
                    self.assertFalse(store.dead_letter_migration("t1", "w1", "too late"))
                    store.record_migration_attempt("t1", "w1")
                    self.assertEqual(store.list_pending_migrations()[0]["attempt_count"], 0)  # not counted
                    self.assertEqual(store.list_dead_migrations(), [])  # still pending, not dead
                    # A LIVE holder (within lease) CAN count an attempt...
                    now["t"] = 1050
                    store.record_migration_attempt("t1", "w1")
                    self.assertEqual(store.list_pending_migrations()[0]["attempt_count"], 1)
                    # AFTER another worker reclaims the expired row, w1 has no authority either.
                    now["t"] = 1200
                    reclaimed = store.claim_migrations("w2", lease_seconds=100, limit=1)
                    self.assertEqual([row["task_id"] for row in reclaimed], ["t1"])
                    now["t"] = 1250
                    self.assertFalse(store.release_migration("t1", "w1"))
                    self.assertFalse(store.dead_letter_migration("t1", "w1", "not mine"))
                    # The live new holder can dead-letter it.
                    self.assertTrue(store.dead_letter_migration("t1", "w2", "w2 gives up"))
                    self.assertEqual([row["task_id"] for row in store.list_dead_migrations()], ["t1"])

    def test_migration_clock_not_caller_controllable(self):
        # #3 round 2 (auditor): the lease clock must NOT be a caller-supplied parameter -- a forged
        # future `_now` was used to STEAL a live lease. The clock is now a construction dependency, so
        # the mutation methods reject a `_now=` argument (the parameter no longer exists -> TypeError).
        # CALIBRATE: pre-fix each of these calls was ACCEPTED (keyword-only `_now`), so the TypeError
        # assertions could not pass; a forged future value bypassed another worker's live lease.
        for context in self._outbox_store_contexts():
            with context as (backend, store):
                with self.subTest(backend=backend):
                    self._seed_outbox(store, "t1", sealed='{"n":1}')
                    with self.assertRaises(TypeError):
                        store.claim_migrations("w", lease_seconds=60, limit=1, _now=1)
                    with self.assertRaises(TypeError):
                        store.release_migration("t1", "w", _now=1)
                    with self.assertRaises(TypeError):
                        store.dead_letter_migration("t1", "w", "x", _now=1)
                    with self.assertRaises(TypeError):
                        store.record_migration_attempt("t1", "w", _now=1)

    @unittest.skipUnless(
        os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available(),
        "needs a live Postgres (PORTMARK_TEST_POSTGRES_DSN)",
    )
    def test_migration_lease_uses_db_time_not_host_clock(self):
        # #3 round 3 (auditor): two store instances against the SAME database with DISAGREEING host
        # clocks. Worker B's host clock is far ahead. Under host-clock lease logic, B judged worker A's
        # fresh 60s lease as already expired and reclaimed the row (both then deliver -> exclusivity
        # break). With DB time (clock_timestamp()), eligibility is judged by the one DB clock, so B's
        # ahead host clock is irrelevant and B gets nothing.
        dsn = os.environ["PORTMARK_TEST_POSTGRES_DSN"]
        schema = "portmark_dbtime_" + secrets.token_hex(8)
        normal = PostgresRuntimeStore(dsn, schema=schema, clock=lambda: 1000)
        ahead = PostgresRuntimeStore(dsn, schema=schema, clock=lambda: 1000 + 10_000)  # host clock far ahead
        try:
            with normal.transaction() as txn:
                txn.enqueue_migration("t", "host:dest", '{"n":1}')
            claimed = normal.claim_migrations("worker-a", lease_seconds=60, limit=1)
            self.assertEqual([row["task_id"] for row in claimed], ["t"])
            # CALIBRATE: under the round-2 host-clock code, `ahead` (clock +10000s) saw the 60s lease as
            # expired and reclaimed -> stolen == ["t"]. With DB time the lease is still live.
            stolen = ahead.claim_migrations("worker-b", lease_seconds=60, limit=1)
            self.assertEqual(stolen, [])  # no cross-host takeover of a live lease
            self.assertEqual(normal.list_pending_migrations()[0]["claimed_by"], "worker-a")
        finally:
            self._drop_postgres_schema(dsn, schema)

    @unittest.skipUnless(
        os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available(),
        "needs a live Postgres (PORTMARK_TEST_POSTGRES_DSN)",
    )
    def test_migration_expired_holder_blocked_on_postgres_db_time(self):
        # #3 round 3: the memory/sqlite expired-holder test uses an injected clock, but PG uses DB time
        # (clock_timestamp()) and cannot freeze it -- so this proves the PG release/dead_letter/scoped-
        # attempt `lease_expires_at > clock_timestamp()` clauses actually enforce expiry, using a real
        # 1s lease + a short sleep. A typo in any of those three WHERE clauses would otherwise pass the
        # whole suite silently. (Direction-safe: waiting longer only makes the lease more expired.)
        dsn = os.environ["PORTMARK_TEST_POSTGRES_DSN"]
        schema = "portmark_expiry_" + secrets.token_hex(8)
        store = PostgresRuntimeStore(dsn, schema=schema)
        try:
            with store.transaction() as txn:
                txn.enqueue_migration("t", "host:dest", '{"n":1}')
            self.assertEqual([row["task_id"] for row in store.claim_migrations("w1", lease_seconds=1, limit=1)], ["t"])
            # While the lease is live, the holder can count an attempt.
            store.record_migration_attempt("t", "w1")
            self.assertEqual(store.list_pending_migrations()[0]["attempt_count"], 1)
            time.sleep(1.2)  # the 1s lease has now expired in DB time
            self.assertFalse(store.release_migration("t", "w1"))
            self.assertFalse(store.dead_letter_migration("t", "w1", "too late"))
            store.record_migration_attempt("t", "w1")  # expired holder -> not counted
            self.assertEqual(store.list_pending_migrations()[0]["attempt_count"], 1)  # unchanged
            # A fresh worker can reclaim the now-expired row.
            self.assertEqual([row["task_id"] for row in store.claim_migrations("w2", lease_seconds=60, limit=1)], ["t"])
        finally:
            self._drop_postgres_schema(dsn, schema)

    @unittest.skipUnless(
        os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available(),
        "needs a live Postgres (PORTMARK_TEST_POSTGRES_DSN)",
    )
    def test_migration_outbox_conflict_is_atomic_under_concurrency(self):
        # #8 fix round: the pre-fix SELECT-then-INSERT-DO-NOTHING let two concurrent FIRST enqueues
        # both see no row; one inserted, the other DO-NOTHINGed and silently dropped its different
        # envelope. Two real connections, same task_id + DIFFERENT envelopes, barrier-synchronized:
        # exactly one commits, the other raises (its source-close rolls back), stored == winner.
        dsn = os.environ["PORTMARK_TEST_POSTGRES_DSN"]
        schema = "portmark_conflict_" + secrets.token_hex(8)
        store_a = PostgresRuntimeStore(dsn, schema=schema)
        store_b = PostgresRuntimeStore(dsn, schema=schema)  # same schema -> same outbox, 2 connections
        try:
            barrier = threading.Barrier(2)
            results: dict[str, str] = {}

            def attempt(name, store, sealed):
                barrier.wait()
                try:
                    with store.transaction() as txn:
                        txn.enqueue_migration("shared-task", "host:dest", sealed)
                    results[name] = "committed:" + sealed
                except SecurityError:
                    results[name] = "rejected"

            ta = threading.Thread(target=attempt, args=("a", store_a, '{"payload":"A"}'))
            tb = threading.Thread(target=attempt, args=("b", store_b, '{"payload":"B"}'))
            ta.start()
            tb.start()
            ta.join()
            tb.join()

            outcomes = sorted(results.values())
            # exactly one committed, exactly one rejected -- never two silent successes.
            self.assertEqual(len(outcomes), 2, results)
            self.assertEqual(sum(1 for o in outcomes if o.startswith("committed:")), 1, results)
            self.assertEqual(sum(1 for o in outcomes if o == "rejected"), 1, results)
            # The stored envelope is exactly the winner's; the loser's write rolled back.
            winner_sealed = next(o.split("committed:", 1)[1] for o in outcomes if o.startswith("committed:"))
            pending = store_a.list_pending_migrations()
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]["sealed_envelope_json"], winner_sealed)
        finally:
            self._drop_postgres_schema(dsn, schema)

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
        source.policy.migration = MigrationPolicy(allowed=True, destinations=(destination.host_id,))
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
        source.policy.migration = MigrationPolicy(allowed=True, destinations=("host:destination",))
        source.providers["migrator"] = MigrateThenCompleteProvider("host:destination")
        envelope = make_demo_envelope(source, "move without proof", "migrator")
        object.__setattr__(envelope.permit, "delegation_allowed", True)
        signer.seal(envelope)
        with self.assertRaisesRegex(SecurityError, "required"):
            source.run(envelope)

    # ---- Section 4 #5: migration attestation freshness (nonce binding) ----

    def _attested_migration(self, *, require_migration_nonce, evidence_nonce):
        # Build a source ready to migrate under an attestation policy. `evidence_nonce` is one of
        # "match" (= this migration's permit nonce), "wrong" (a different value), or "empty".
        authority = AttestationAuthority.generate()
        policy = AttestationPolicy(
            (authority.trusted_authority(),),
            ("measurement:destination",),
            required_for_migration=True,
            require_migration_nonce=require_migration_nonce,
        )
        source_signer = EnvelopeSigner.generate("source-key", "host:source", ("host:source", "host:destination"))
        destination_signer = trust_signer(EnvelopeSigner.generate("destination-key", "host:destination", ("host:destination",)), source_signer)
        source = make_host(host_id="host:source", signer=source_signer, attestation_policy=policy)
        destination = make_host(host_id="host:destination", signer=destination_signer, attestation_policy=policy)
        source.policy.migration = MigrationPolicy(allowed=True, destinations=(destination.host_id,))
        envelope = make_demo_envelope(source, "enclave move", "attested-migrator")
        object.__setattr__(envelope.permit, "delegation_allowed", True)
        nonce = {"match": envelope.permit.nonce, "wrong": "nonce-from-another-migration", "empty": ""}[evidence_nonce]
        evidence = authority.issue(
            subject=destination.host_id,
            audience=source.host_id,
            measurement="measurement:destination",
            expires_at=int(time.time()) + 60,
            nonce=nonce,
        )
        provider = AttestedMigrateThenCompleteProvider(destination.host_id, evidence)
        source.providers["attested-migrator"] = provider
        destination.providers["attested-migrator"] = provider
        source_signer.seal(envelope)
        return source, envelope

    def test_migration_attestation_nonce_binds_to_permit(self):
        # #5: with require_migration_nonce, the destination attestation must carry a nonce matching
        # THIS migration's permit nonce. CALIBRATE: pre-fix verify_migration passed no expected_nonce,
        # so both the wrong-nonce and empty-nonce cases were ACCEPTED (the assertRaises can't pass).
        # The "match" evidence carries nonce == envelope.permit.nonce; the host binds verify_migration
        # to effective.nonce. This passing therefore also confirms effective_permit carries the permit
        # nonce through verbatim (the binding compares the right value, not a silently-derived one).
        source, envelope = self._attested_migration(require_migration_nonce=True, evidence_nonce="match")
        self.assertIsNotNone(source.run(envelope).migration_envelope)  # matching nonce -> migrates

        source, envelope = self._attested_migration(require_migration_nonce=True, evidence_nonce="wrong")
        with self.assertRaisesRegex(SecurityError, "nonce does not match"):
            source.run(envelope)

        source, envelope = self._attested_migration(require_migration_nonce=True, evidence_nonce="empty")
        with self.assertRaisesRegex(SecurityError, "nonce is required"):
            source.run(envelope)

    def test_migration_attestation_replay_rejected(self):
        # #5 replay: an attestation minted for a DIFFERENT migration (its nonce belongs to another
        # migration's permit) cannot be reused here -- its nonce won't match this permit nonce.
        source, envelope = self._attested_migration(require_migration_nonce=True, evidence_nonce="wrong")
        with self.assertRaisesRegex(SecurityError, "nonce does not match"):
            source.run(envelope)

    def test_migration_attestation_end_to_end_and_replay(self):
        # Auditor-mandated (round 2): with require_migration_nonce, nonce-bound evidence must not only
        # pass the SOURCE check but ADMIT at the destination, and reuse must be rejected. This fails
        # against the current fresh-delegated-nonce code -- the destination re-verifies the same
        # evidence via verify_execution against the delegated nonce, which differs from the source's.
        authority = AttestationAuthority.generate()
        policy = AttestationPolicy(
            (authority.trusted_authority(),),
            ("measurement:destination",),
            required_for_migration=True,
            require_migration_nonce=True,
        )
        source_signer = EnvelopeSigner.generate("source-key", "host:source", ("host:source", "host:destination"))
        destination_signer = trust_signer(EnvelopeSigner.generate("destination-key", "host:destination", ("host:destination",)), source_signer)
        source = make_host(host_id="host:source", signer=source_signer, attestation_policy=policy)
        destination = make_host(host_id="host:destination", signer=destination_signer, attestation_policy=policy)
        source.policy.migration = MigrationPolicy(allowed=True, destinations=(destination.host_id,))
        envelope = make_demo_envelope(source, "enclave e2e", "attested-migrator")
        object.__setattr__(envelope.permit, "delegation_allowed", True)
        evidence = authority.issue(
            subject=destination.host_id,
            audience=source.host_id,
            measurement="measurement:destination",
            expires_at=int(time.time()) + 60,
            nonce=envelope.permit.nonce,
        )
        provider = AttestedMigrateThenCompleteProvider(destination.host_id, evidence)
        source.providers["attested-migrator"] = provider
        destination.providers["attested-migrator"] = provider
        source_signer.seal(envelope)

        migrated = envelope_from_dict(source.run(envelope).migration_envelope)
        second = destination.run(migrated)  # MUST admit + complete under require_migration_nonce
        self.assertEqual(second.status, "completed")

        # Replay: a second migration reusing the SAME evidence (bound to the first permit nonce) is rejected.
        envelope2 = make_demo_envelope(source, "enclave e2e replay", "attested-migrator")
        object.__setattr__(envelope2.permit, "delegation_allowed", True)
        source_signer.seal(envelope2)
        with self.assertRaisesRegex(SecurityError, "nonce does not match"):
            source.run(envelope2)

    def test_migration_delegated_permit_reuses_incoming_nonce(self):
        # Section 4 #5 (option 2): the delegated permit reuses THIS migration's incoming nonce (not a
        # fresh token), so one attestation binds at both the source and the destination. Pinned so a
        # future change can't silently restore a fresh delegated nonce and reopen the source/destination
        # mismatch. Accepted consequence (Josh): the migrated envelope carries the incoming nonce, so
        # once the destination consumes it the task is not re-migratable to that destination under a new
        # nonce. (An IDENTICAL re-delivery is still idempotent -- section 4 #2 returns the same receipt --
        # so this is a re-migration bound, not a delivery-retry regression.)
        source_signer = EnvelopeSigner.generate("nonce-reuse-key", "host:source", ("host:source", "host:destination"))
        source = make_host(host_id="host:source", signer=source_signer, allow_ephemeral_signing_key=True)
        source.policy.migration = MigrationPolicy(allowed=True, destinations=("host:destination",))
        source.providers["migrator"] = MigrateThenCompleteProvider("host:destination")
        envelope = make_demo_envelope(source, "nonce reuse", "migrator")
        object.__setattr__(envelope.permit, "delegation_allowed", True)
        source.signer.seal(envelope)
        migrated = envelope_from_dict(source.run(envelope).migration_envelope)
        self.assertEqual(migrated.permit.nonce, envelope.permit.nonce)

    def test_migration_attestation_nonce_optional_but_rejects_mismatch(self):
        # #5 back-compat: with require_migration_nonce OFF (default), legitimately-unbound measurement
        # evidence (empty nonce) is still accepted -- BUT a present-but-WRONG nonce is now rejected even
        # when off (strictly safer than before, when any migration nonce was ignored entirely).
        source, envelope = self._attested_migration(require_migration_nonce=False, evidence_nonce="empty")
        self.assertIsNotNone(source.run(envelope).migration_envelope)  # unbound evidence still works

        source, envelope = self._attested_migration(require_migration_nonce=False, evidence_nonce="wrong")
        with self.assertRaisesRegex(SecurityError, "nonce does not match"):
            source.run(envelope)

    def test_host_policy_migration_ceiling_bounds_destinations(self):
        # Finding EV-009: host policy is a ceiling over movement. A migration needs
        # the incoming permit's delegation AND the host's allow AND an allowlisted
        # destination -- all three, or it is refused. The provider always proposes
        # migrating to host:allowed; only the source policy and permit vary.
        source_signer = EnvelopeSigner.generate("ev009-key", "host:source", ("host:source", "host:allowed"))

        def run_migration(destinations, allowed=True, delegation=True):
            source = make_host(host_id="host:source", signer=source_signer)
            source.policy.migration = MigrationPolicy(allowed=allowed, destinations=destinations)
            source.providers["migrator"] = MigrateThenCompleteProvider("host:allowed")
            env = make_demo_envelope(source, "ev009 movement", "migrator")
            object.__setattr__(env.permit, "delegation_allowed", delegation)
            source_signer.seal(env)
            return source.run(env)

        # All three conditions satisfied: migration is authorized.
        self.assertIsNotNone(run_migration(("host:allowed",)).migration_envelope)

        # Destination not on the host allowlist: refused.
        with self.assertRaisesRegex(SecurityError, "does not allow migration to"):
            run_migration(("host:elsewhere",))

        # Host policy disallows migration entirely (the default posture): refused.
        with self.assertRaisesRegex(SecurityError, "host policy does not allow migration"):
            run_migration((), allowed=False)

        # Permit does not delegate: refused regardless of host allowlist.
        with self.assertRaisesRegex(SecurityError, "permit does not allow migration"):
            run_migration(("host:allowed",), delegation=False)

    def test_policy_loader_validates_migration_block(self):
        from portmark.policy import policy_from_dict

        base = {"version": "v1", "tools": {"catalog.search": {"impact": "low"}}}
        # An omitted migration block defaults to deny-all.
        default_policy = policy_from_dict(base, "host:local-demo")
        self.assertFalse(default_policy.migration.allowed)
        self.assertEqual(default_policy.migration.destinations, ())
        # A valid opt-in round-trips.
        opted_in = policy_from_dict({**base, "migration": {"allowed": True, "destinations": ["host:a", "host:b"]}}, "host:local-demo")
        self.assertTrue(opted_in.migration.allowed)
        self.assertEqual(opted_in.migration.destinations, ("host:a", "host:b"))
        # Malformed migration blocks fail closed at load.
        cases = [
            ({"allowed": "yes"}, "allowed must be a boolean"),
            ({"allowed": True, "destinations": "host:a"}, "destinations must be a list"),
            ({"allowed": True, "destinations": [""]}, "non-empty strings"),
            ({"allowed": True}, "lists no destinations"),
            ({"allowed": True, "destinations": ["host:a"], "extra": 1}, "unknown keys"),
        ]
        for migration, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    policy_from_dict({**base, "migration": migration}, "host:local-demo")

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

    def test_a2a_result_artifact_excludes_checkpoint_and_audit(self):
        # Finding #4: the A2A egress must not hand the caller the internal
        # checkpoint or the raw audit chain (cause_message, tool arguments).
        from portmark.models import RunResult
        from portmark.a2a_types import task_from_run_result

        result = RunResult(
            status="completed",
            task_id="task-1",
            result={"answer": 42},
            checkpoint={"memory": {"confidential": "do-not-leak"}, "messages": [{"role": "tool", "content": {"pan": "4111"}}]},
            audit=({"type": "tool.failed", "cause_message": "boom", "arguments": {"pan": "4111"}},),
        )
        task = task_from_run_result(result)
        artifact = task["artifacts"][0]
        self.assertEqual(artifact, {"task_id": "task-1", "status": "completed", "result": {"answer": 42}})
        self.assertNotIn("checkpoint", artifact)
        self.assertNotIn("audit", artifact)
        # Nothing from the checkpoint or audit leaks anywhere in the serialised task.
        blob = json.dumps(task)
        for secret in ("do-not-leak", "boom", "4111"):
            self.assertNotIn(secret, blob)

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
        with patch("portmark.a2a.run_uvicorn") as run:
            with self.assertRaisesRegex(ValueError, "loopback"):
                serve(host, public_bind, 8080)
        run.assert_not_called()

        with patch("portmark.a2a.run_uvicorn") as run:
            with self.assertRaisesRegex(ValueError, "reverse proxy"):
                serve(host, public_bind, 8080, allow_direct_a2a=True)
        run.assert_not_called()

        with patch("portmark.a2a.run_uvicorn") as run:
            serve(host, "127.0.0.1", 8080)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[1]["host"], "127.0.0.1")
        self.assertEqual(run.call_args.args[1]["limit_concurrency"], DEFAULT_MAX_CONCURRENT_REQUESTS)

    def test_serve_warns_when_tls_not_asserted(self):
        host = make_host()
        # HSTS off => TLS not asserted => a loud startup warning must fire.
        with patch("portmark.a2a.run_uvicorn"):
            with self.assertLogs("portmark.a2a", level="WARNING") as captured:
                serve(host, "127.0.0.1", 8080, enable_hsts=False)
        joined = "\n".join(captured.output)
        self.assertIn("TLS NOT asserted", joined)
        self.assertIn("NOT encrypted in transit", joined)
        # HSTS on => operator asserted HTTPS => no false alarm.
        with patch("portmark.a2a.run_uvicorn"):
            with self.assertNoLogs("portmark.a2a", level="WARNING"):
                serve(host, "127.0.0.1", 8080, enable_hsts=True)

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

    def test_forwarded_proto_http_warns_once_of_cleartext(self):
        host = make_host()
        app = make_asgi_app(host)
        headers = {"Content-Type": "application/json", "X-Forwarded-Proto": "http"}
        # A request proven to arrive over plain HTTP must warn.
        with self.assertLogs("portmark.a2a", level="WARNING") as captured:
            self._asgi_call(app, "POST", "/message:send", headers, body=b"{}")
        self.assertIn("PROVEN cleartext", "\n".join(captured.output))
        # Subsequent cleartext requests stay quiet — logged once.
        with self.assertNoLogs("portmark.a2a", level="WARNING"):
            self._asgi_call(app, "POST", "/message:send", headers, body=b"{}")

    def test_forwarded_proto_https_does_not_warn(self):
        host = make_host()
        app = make_asgi_app(host)
        headers = {"Content-Type": "application/json", "X-Forwarded-Proto": "https"}
        with self.assertNoLogs("portmark.a2a", level="WARNING"):
            self._asgi_call(app, "POST", "/message:send", headers, body=b"{}")

    def test_asgi_app_serves_agent_card_with_security_headers(self):
        app = make_asgi_app(make_host())
        status, headers, payload = self._asgi_call(app, "GET", "/.well-known/agent-card.json", {"Host": "127.0.0.1"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["supportedInterfaces"][0]["protocolVersion"], "1.0")
        for header in ("x-content-type-options", "x-frame-options", "content-security-policy", "referrer-policy"):
            self.assertIn(header, headers)

    def test_asgi_agent_card_only_reflects_loopback_host(self):
        # Finding #8 (hardened): a non-loopback Host — even a syntactically clean one
        # (Codex review) — must NOT be reflected into the advertised URL without a
        # configured public_base_url; a loopback Host still is (local development).
        app = make_asgi_app(make_host(), allow_anonymous=True)
        for forged in ("evil.example/@attacker", "attacker.example:443", "svc.internal:8443"):
            with self.subTest(host=forged), self.assertLogs("portmark.a2a", level="WARNING"):
                _, _, payload = self._asgi_call(
                    app, "GET", "/.well-known/agent-card.json", {"Host": forged}
                )
            self.assertEqual(
                json.loads(payload)["supportedInterfaces"][0]["url"], "http://127.0.0.1/message:send"
            )
        # A loopback Host is trusted for local development and still reflected.
        _, _, payload = self._asgi_call(
            app, "GET", "/.well-known/agent-card.json", {"Host": "127.0.0.1:9000"}
        )
        self.assertEqual(
            json.loads(payload)["supportedInterfaces"][0]["url"], "http://127.0.0.1:9000/message:send"
        )

    def test_asgi_agent_card_prefers_configured_public_base_url(self):
        app = make_asgi_app(make_host(), allow_anonymous=True, public_base_url="https://agents.example.com/")
        _, _, payload = self._asgi_call(
            app, "GET", "/.well-known/agent-card.json", {"Host": "evil.example"}
        )
        self.assertEqual(
            json.loads(payload)["supportedInterfaces"][0]["url"], "https://agents.example.com/message:send"
        )

    def test_a2a_router_warns_when_unauthenticated_and_not_opted_in(self):
        # Finding #8: an endpoint with no bearer token warns unless the operator
        # explicitly opts into anonymous access (or configures a token).
        with self.assertLogs("portmark.a2a", level="WARNING") as captured:
            make_asgi_app(make_host())
        self.assertTrue(any("NO bearer token" in message for message in captured.output))
        with self.assertNoLogs("portmark.a2a", level="WARNING"):
            make_asgi_app(make_host(), allow_anonymous=True)
        with self.assertNoLogs("portmark.a2a", level="WARNING"):
            make_asgi_app(make_host(), A2AAuthConfig("secret"))

    def test_asgi_healthz_and_readyz(self):
        app = make_asgi_app(make_host())
        status, _, payload = self._asgi_call(app, "GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {"status": "ok"})
        status, _, payload = self._asgi_call(app, "GET", "/readyz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {"status": "ready"})

    def test_asgi_health_stays_responsive_while_dispatch_blocks(self):
        # Section 2, finding #1 (release blocker): host.run() (via dispatch_post) runs
        # OFF the event loop, so a slow agent run cannot block other endpoints. Park a
        # POST inside a blocking dispatch and prove /healthz still answers promptly.
        import threading

        app = make_asgi_app(make_host(), allow_anonymous=True)
        router = app.a2a_router
        entered = threading.Event()
        release = threading.Event()

        def blocking_dispatch(body):
            entered.set()
            release.wait(5)
            return router.response(200, {"blocked": True})

        router.dispatch_post = blocking_dispatch

        async def drive(method, path, headers=None, body=b""):
            scope = {
                "type": "http",
                "method": method,
                "path": path,
                "client": ("203.0.113.9", 5555),
                "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
            }
            sent = []

            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}

            async def send(message):
                sent.append(message)

            await app(scope, receive, send)
            return next(m["status"] for m in sent if m["type"] == "http.response.start")

        async def scenario():
            body = b'{"jsonrpc":"2.0"}'
            headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
            post = asyncio.create_task(drive("POST", "/message:send", headers, body))
            # Wait until dispatch is actually executing off-loop.
            await asyncio.to_thread(entered.wait, 2)
            self.assertTrue(entered.is_set())
            # If the loop were blocked by the run, this could not complete until the
            # POST finished; it must answer within the timeout while dispatch is stuck.
            status = await asyncio.wait_for(drive("GET", "/healthz"), timeout=1.5)
            self.assertEqual(status, 200)
            release.set()
            self.assertEqual(await post, 200)

        asyncio.run(scenario())

    def test_asgi_rejects_body_that_crosses_declared_content_length(self):
        # Section 2, finding #5: a body longer than the declared Content-Length must be
        # rejected, never executed (auditor: declared 1, actual 1299 -> HTTP 200).
        host = make_host()
        app = make_asgi_app(host, allow_anonymous=True)
        body = self._a2a_request_body(host, "framing overflow")
        status, _, payload = self._asgi_call(
            app,
            "POST",
            "/message:send",
            {"Content-Type": "application/json", "Content-Length": "1"},
            body,
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(payload)["error"]["message"], "invalid request")

    def test_asgi_rejects_body_shorter_than_declared_content_length(self):
        # Section 2, finding #5: an early EOF (fewer bytes than declared) must be
        # rejected rather than executed on a truncated body.
        host = make_host()
        app = make_asgi_app(host, allow_anonymous=True)
        body = self._a2a_request_body(host, "framing underflow")
        status, _, payload = self._asgi_call(
            app,
            "POST",
            "/message:send",
            {"Content-Type": "application/json", "Content-Length": str(len(body) + 50)},
            body,
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(payload)["error"]["message"], "invalid request")

    def test_jsonrpc_request_id_rejects_invalid_types(self):
        # Section 2, finding #5 follow-up: a present-but-malformed id (bool, float,
        # array, object) is a malformed request and must be REJECTED, not coerced to
        # null. String, integer, and null/absent are valid.
        from portmark.a2a_types import A2ARequestError, _valid_request_id

        self.assertEqual(_valid_request_id(7), 7)
        self.assertEqual(_valid_request_id("abc"), "abc")
        self.assertIsNone(_valid_request_id(None))
        for bad in [True, False, 1.5, [1], {"a": 1}]:
            with self.subTest(bad=bad):
                with self.assertRaises(A2ARequestError):
                    _valid_request_id(bad)

    def test_asgi_rejects_request_with_invalid_jsonrpc_id(self):
        # Section 2, finding #5 follow-up: the HTTP request itself must be rejected
        # (400 invalid request), not just have its id dropped. The invalid id is not
        # echoed back.
        host = make_host()
        app = make_asgi_app(host, allow_anonymous=True)
        for bad_id in ["true", "1.5", "[1]", '{"x":1}']:
            body = ('{"jsonrpc":"2.0","id":%s,"method":"message/send","params":{}}' % bad_id).encode()
            status, _, payload = self._asgi_call(
                app,
                "POST",
                "/message:send",
                {"Content-Type": "application/json", "Content-Length": str(len(body))},
                body,
            )
            with self.subTest(bad_id=bad_id):
                self.assertEqual(status, 400)
                decoded = json.loads(payload)
                self.assertEqual(decoded["error"]["message"], "invalid request")
                self.assertIsNone(decoded["id"])

    def test_validate_public_base_url(self):
        # Section 2, finding #2: the advertised Agent Card URL must be an absolute
        # https URL with a host and no credentials.
        from portmark.a2a import validate_public_base_url

        self.assertEqual(validate_public_base_url("https://agents.example.com/"), "https://agents.example.com")
        for bad in ["http://agents.example.com", "https://user:pw@agents.example.com", "https:///nohost", "ftp://x"]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    validate_public_base_url(bad)

    def test_runtime_config_reads_public_base_url_and_trusted_proxies(self):
        # Section 2, findings #2/#3: the ASGI entrypoint's config must surface both.
        env = {
            "PORTMARK_A2A_PUBLIC_BASE_URL": "https://agents.example.com",
            "PORTMARK_A2A_TRUSTED_PROXIES": "10.0.0.0/8, 127.0.0.1",
        }
        with patch.dict(os.environ, env, clear=False):
            config = RuntimeConfig.from_environment()
        self.assertEqual(config.a2a_public_base_url, "https://agents.example.com")
        self.assertEqual(config.a2a_trusted_proxies, "10.0.0.0/8, 127.0.0.1")

    def test_resolve_client_ip_honours_trusted_proxies_only(self):
        # Section 2, finding #3: X-Forwarded-For is trusted ONLY when the direct peer
        # is a configured trusted proxy; then use the rightmost untrusted address.
        from portmark.a2a import parse_trusted_proxies, resolve_client_ip

        trusted = parse_trusted_proxies("127.0.0.0/8")
        # No trusted proxies configured: always the peer, XFF ignored.
        self.assertEqual(resolve_client_ip("203.0.113.9", "1.2.3.4", ()), "203.0.113.9")
        # Peer is a trusted proxy: the real client is the rightmost non-proxy address.
        self.assertEqual(resolve_client_ip("127.0.0.1", "9.9.9.9", trusted), "9.9.9.9")
        self.assertEqual(resolve_client_ip("127.0.0.1", "9.9.9.9, 127.0.0.5", trusted), "9.9.9.9")
        # Peer is NOT trusted: ignore a spoofed XFF entirely.
        self.assertEqual(resolve_client_ip("203.0.113.9", "9.9.9.9", trusted), "203.0.113.9")
        # All forwarded hops are trusted proxies: fall back to the peer.
        self.assertEqual(resolve_client_ip("127.0.0.1", "127.0.0.5", trusted), "127.0.0.1")
        # A malformed forwarded entry is skipped, never returned as raw text (finding
        # #2 follow-up): the real address to its left is used instead.
        self.assertEqual(resolve_client_ip("127.0.0.1", "198.51.100.3, garbage", trusted), "198.51.100.3")
        self.assertEqual(resolve_client_ip("127.0.0.1", "garbage", trusted), "127.0.0.1")

    def test_asgi_rate_limit_is_per_forwarded_client_behind_trusted_proxy(self):
        # Section 2, finding #3: behind a trusted proxy, the per-client window keys on
        # the forwarded client, so one client exhausting its quota does not 429 another.
        from portmark.a2a import parse_trusted_proxies

        host = make_host()
        app = make_asgi_app(
            host,
            allow_anonymous=True,
            rate_limit_per_ip=2,
            rate_limit_window_seconds=60,
            trusted_proxies=parse_trusted_proxies("127.0.0.0/8"),
        )

        def post(xff):
            status, _, _ = self._asgi_call(
                app,
                "POST",
                "/message:send",
                {"Content-Type": "application/json", "Content-Length": "2", "X-Forwarded-For": xff},
                b"{}",
                client=("127.0.0.1", 5555),
            )
            return status

        self.assertNotEqual(post("9.9.9.9"), 429)
        self.assertNotEqual(post("9.9.9.9"), 429)
        self.assertEqual(post("9.9.9.9"), 429)  # third from this client is limited
        self.assertNotEqual(post("8.8.8.8"), 429)  # a different client has its own window

    def test_asgi_rate_limit_ignores_forwarded_for_from_untrusted_peer(self):
        # Section 2, finding #3: with no trusted proxies, X-Forwarded-For is ignored, so
        # a client cannot rotate the header to escape its own per-peer window.
        host = make_host()
        app = make_asgi_app(host, allow_anonymous=True, rate_limit_per_ip=2, rate_limit_window_seconds=60)

        def post(xff):
            status, _, _ = self._asgi_call(
                app,
                "POST",
                "/message:send",
                {"Content-Type": "application/json", "Content-Length": "2", "X-Forwarded-For": xff},
                b"{}",
                client=("203.0.113.9", 5555),
            )
            return status

        self.assertNotEqual(post("1.1.1.1"), 429)
        self.assertNotEqual(post("2.2.2.2"), 429)
        self.assertEqual(post("3.3.3.3"), 429)  # keyed on the peer, not the rotated XFF

    def test_store_check_ready_is_lightweight_and_version_checked(self):
        # Section 2, finding #4: check_ready is a cheap probe + schema sanity, and it
        # fails when the stored schema is newer than supported.
        from portmark.storage import SQLITE_SCHEMA_VERSION

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            store = SQLiteRuntimeStore(path)
            store.check_ready()  # healthy store: no raise
            with self._raw_sqlite(path) as connection:
                connection.execute(f"PRAGMA user_version = {SQLITE_SCHEMA_VERSION + 1}")
            with self.assertRaisesRegex(RuntimeError, "not the supported version"):
                store.check_ready()

    def test_sqlite_check_ready_rejects_missing_or_incomplete_schema(self):
        # Section 2 follow-up: readiness must fail closed on a missing or incomplete
        # store, never silently recreate an empty database and report it ready.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite"
            store = SQLiteRuntimeStore(path)
            store.check_ready()  # healthy
            os.remove(path)
            with self.assertRaises(Exception):
                store.check_ready()
            self.assertFalse(path.exists())  # readiness did NOT recreate the database

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "old.sqlite"
            store = SQLiteRuntimeStore(path)
            with self._raw_sqlite(path) as connection:
                connection.execute("PRAGMA user_version = 1")  # older/incomplete schema
            with self.assertRaisesRegex(RuntimeError, "not the supported version"):
                store.check_ready()
            with self._raw_sqlite(path) as connection:
                connection.execute("PRAGMA user_version = 0")  # empty schema
            with self.assertRaisesRegex(RuntimeError, "not the supported version"):
                store.check_ready()

    @unittest.skipUnless(
        os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available(),
        "requires a real PostgreSQL",
    )
    def test_postgres_check_ready_is_bounded_by_statement_timeout(self):
        # Section 2, finding #4: readiness on Postgres is a cheap probe (no schema
        # init) AND its SET LOCAL statement_timeout genuinely applies -- outside a
        # transaction SET LOCAL is a silent no-op, so prove it bounds a slow query.
        import psycopg

        dsn = os.environ["PORTMARK_TEST_POSTGRES_DSN"]
        schema = "portmark_ready_" + secrets.token_hex(8)
        try:
            store = PostgresRuntimeStore(dsn, schema=schema)
            store.check_ready()  # healthy store: no raise
            with store._connect() as connection:
                connection.execute("SET LOCAL statement_timeout = '300ms'")
                with self.assertRaises(psycopg.errors.QueryCanceled):
                    connection.execute("SELECT pg_sleep(3)")
        finally:
            self._drop_postgres_schema(dsn, schema)

    @unittest.skipUnless(PostgresRuntimeStore.available(), "requires psycopg")
    def test_postgres_check_ready_bounds_connection_establishment(self):
        # Section 2, finding #1 follow-up: statement_timeout only applies AFTER connect
        # succeeds. A blackholed address must be bounded by connect_timeout, not left to
        # hang for the OS default. 192.0.2.1 is TEST-NET-1 (RFC 5737), never routed, so
        # the connect stalls and connect_timeout must fire well under the OS default.
        # Uses __new__ to avoid __init__ dialing the blackhole at construction time.
        store = PostgresRuntimeStore.__new__(PostgresRuntimeStore)
        store.dsn = "postgresql://postgres@192.0.2.1:5432/portmark"
        store.schema = "public"
        store._audit_head_verifier = None
        start = time.monotonic()
        with self.assertRaises(Exception):
            store.check_ready()
        elapsed = time.monotonic() - start
        # connect_timeout is 2s; allow generous margin but far below an OS-default hang.
        self.assertLess(elapsed, 10.0)

    @unittest.skipUnless(
        os.environ.get("PORTMARK_TEST_POSTGRES_DSN") and PostgresRuntimeStore.available(),
        "requires a real PostgreSQL",
    )
    def test_postgres_check_ready_rejects_incomplete_schema(self):
        # Section 2 follow-up: an empty portmark_schema (row=None -> version 0) or an
        # older version must fail readiness, not pass as "ready".
        import psycopg
        from psycopg import sql

        dsn = os.environ["PORTMARK_TEST_POSTGRES_DSN"]
        schema = "portmark_incomplete_" + secrets.token_hex(8)
        try:
            store = PostgresRuntimeStore(dsn, schema=schema)
            store.check_ready()  # healthy: no raise

            def set_version_sql(statement):
                with psycopg.connect(dsn, autocommit=True) as connection:
                    connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
                    connection.execute(statement)

            set_version_sql("UPDATE portmark_schema SET version = 1")  # older
            with self.assertRaisesRegex(RuntimeError, "not the supported version"):
                store.check_ready()
            set_version_sql("DELETE FROM portmark_schema")  # empty version table -> 0
            with self.assertRaisesRegex(RuntimeError, "not the supported version"):
                store.check_ready()
        finally:
            self._drop_postgres_schema(dsn, schema)

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
        # Section 11 #1/#4: the tool pins moved into the hash-locked requirements/bootstrap.txt, the
        # base image is digest-pinned, and the command is the gated, loopback-default entrypoint.
        # Exactly one base image: a patch-pinned tag plus the FULL 64-hex digest. A tag alone, a short
        # digest, `:latest`, or a second FROM all fail here.
        base_images = re.findall(r"^FROM\s+(\S+)", dockerfile, flags=re.MULTILINE)
        self.assertEqual(len(base_images), 1, base_images)
        pinned = re.fullmatch(r"python:3\.(\d+)\.\d+-slim-bookworm@sha256:[0-9a-f]{64}", base_images[0])
        self.assertIsNotNone(pinned, base_images[0])
        # The image's Python minor version must already be tested: in the Linux AND Windows test matrices,
        # and in the classifiers. So a base-image bump to an untested Python cannot merge on its own.
        image_python = f"3.{pinned.group(1)}"
        root = Path(__file__).parents[1]
        ci = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        matrices = re.findall(r'python-version: \[([^\]]*)\]', ci)
        self.assertEqual(len(matrices), 2, matrices)  # `test` and `windows-tests`
        for matrix in matrices:
            self.assertIn(f'"{image_python}"', matrix)
        self.assertIn(
            f'"Programming Language :: Python :: {image_python}"',
            (root / "pyproject.toml").read_text(encoding="utf-8"),
        )
        required = [
            "pip install --require-hashes --no-deps -r requirements/bootstrap.txt",
            "pip install --require-hashes --no-deps -r requirements/runtime.txt",
            "pip install --no-deps --no-build-isolation .",
            "useradd",
            "USER portmark",
            "PORTMARK_BIND_HOST=127.0.0.1",
            'CMD ["python", "-m", "portmark.serve_asgi"]',
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
            # Section 11 #1/#6: no raw uvicorn public bind, no uvicorn proxy-header trust.
            "0.0.0.0",  # nosec B104 -- a string that must NOT appear in the Dockerfile
            "--proxy-headers",
            "--forwarded-allow-ips",
        ]
        for item in forbidden:
            with self.subTest(forbidden=item):
                self.assertNotIn(item, dockerfile)

    def test_container_asgi_entrypoint_builds_app_from_environment(self):
        # Development profile: an empty environment has none of the production requirements (boundary
        # audit NET-02), which test_boundary_production_profile covers. This test is the /healthz shape.
        with patch.dict(os.environ, {"PORTMARK_PROFILE": "development"}, clear=True):
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

    def test_a2a_errors_are_classified_by_who_caused_them(self):
        # Audit plan 007: a server failure is a 5xx, a refused request stays 400, and the body is the same
        # generic error either way. A witness outage (EV-013 F1: the save was refused, nothing committed)
        # is 503 + Retry-After, so a client retries instead of treating it as its own mistake.
        from portmark.a2a import WITNESS_RETRY_AFTER_SECONDS
        from portmark.remote_witness import WitnessUnavailable
        from portmark.witness import FloorError

        sentinel = "SENTINEL-db-password-/var/lib/secret"
        cases = [
            ("a bug or storage fault", RuntimeError(sentinel), 500),
            ("the host's own rollback floor", FloorError("rolled-back", sentinel), 500),
            ("a tool failure", ToolExecutionError(sentinel), 500),
            ("the remote witness is down", WitnessUnavailable(sentinel), 503),
            ("a refused request", SecurityError(sentinel), 400),
        ]
        host = make_host()
        app = make_asgi_app(host, A2AAuthConfig("secret"))
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(host, A2AAuthConfig("secret")))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        body = self._a2a_request_body(host, "classified")
        headers = {"Content-Type": "application/json", "Content-Length": str(len(body)), "Authorization": "Bearer secret"}
        try:
            for label, error, expected in cases:
                with self.subTest(label), patch.object(host, "run", side_effect=error), patch("portmark.a2a.logger.exception"):
                    status, response_headers, payload = self._asgi_call(app, "POST", "/message:send", headers, body)
                    request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}/message:send", data=body, headers=headers)
                    with self.assertRaises(urllib.error.HTTPError) as raised:
                        urllib.request.urlopen(request)  # nosec B310
                    local_status, local_payload = raised.exception.code, raised.exception.read()
                self.assertEqual((status, local_status), (expected, expected))  # both transports share the router
                self.assertNotIn(sentinel.encode(), payload + local_payload)
                decoded = json.loads(payload)["error"]
                if expected == 503:
                    self.assertEqual(decoded, {"code": -32003, "message": "service temporarily unavailable"})
                    self.assertEqual(dict(response_headers).get("retry-after", dict(response_headers).get("Retry-After")),
                                     str(WITNESS_RETRY_AFTER_SECONDS))
                else:
                    self.assertEqual(decoded, {"code": -32000, "message": "message submission failed"})
            # A structurally malformed envelope (valid JSON, past auth) is the CLIENT's fault through the real
            # parser: still 400, never reclassified as a server failure by the 500 default.
            malformed = json.loads(body)
            del malformed["params"]["metadata"]["portmark_envelope"]["signature"]
            malformed_body = json.dumps(malformed).encode()
            status, _, payload = self._asgi_call(app, "POST", "/message:send", {**headers, "Content-Length": str(len(malformed_body))},
                                                 malformed_body)
            self.assertEqual((status, json.loads(payload)["error"]["code"]), (400, -32602))
        finally:
            server.shutdown()
            server.server_close()
        metrics = host.metrics.prometheus_text()
        self.assertIn('reason="witness_unavailable"', metrics)
        self.assertIn('reason="internal"', metrics)

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
                # Section 8 finding #4: unsafe-but-valid JSON must reject as a parse error (-32700),
                # not silently last-wins (dup key) or crash with RecursionError (deep nesting).
                (b'{"a": 1, "a": 2}', {"Content-Type": "application/json"}, 400, -32700),
                (b"[" * 100 + b"]" * 100, {"Content-Type": "application/json"}, 400, -32700),
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

    @unittest.skipIf(
        sys.platform == "win32",
        "connection cap holds on Windows, but a saturated listener aborts the socket "
        "(WinError 10053) instead of returning a clean 503 body; this test asserts the "
        "POSIX rejection shape. The cap itself is Linux-verified.",
    )
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
                # Generous budgets on purpose: the connection-cap logic is
                # race-free (the first request holds its semaphore slot until its
                # thread finishes), so the only way this test fails is a starved
                # runner not scheduling the blocked request in time. Wide timeouts
                # keep it deterministic under a loaded full-suite run; a healthy
                # machine still returns the instant the events fire.
                self.assertTrue(entered.wait(30))
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
            self.assertEqual(future.result(timeout=30)["result"]["status"]["state"], "completed")

    def _busy_rejection(self, port, body):
        sock = socket.create_connection(("127.0.0.1", port), timeout=30)
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
                "class Config:\n"
                "    def __init__(self):\n"
                "        self.consume_fuel = False\n"
                "class Engine:\n"
                "    def __init__(self, config=None):\n"
                "        self.config = config\n"
                "class Store:\n"
                "    def __init__(self, engine=None):\n"
                "        self.engine = engine\n"
                "    def set_fuel(self, fuel):\n"
                "        pass\n"
                "    def set_limits(self, memory_size=-1, table_elements=-1, instances=-1, tables=-1, memories=-1):\n"
                "        pass\n",
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
                    "        wasm = bytes(wasm)[8:]  # strip the binary component header",
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
        _skip_if_declared_no_node_environment()
        capsule = Path(__file__).parents[1] / "capsules" / "research-agent.wasm.b64"
        host = make_host(wasm_component=str(capsule))
        envelope = make_demo_envelope(host, "portable execution", "wasm")
        result = host.run(envelope)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.result["summary"], "Wasm resumed from checkpointed tool result")
        self.assertEqual(result.result["evidence"], ["checkpoint-observed"])
        self.assertEqual([event["event"] for event in result.audit].count("tool.executed"), 1)
        self.assertEqual(result.checkpoint["messages"][0]["content"][0]["title"], "Result 1 for from capsule checkpoint")

    def test_native_wasmtime_subprocess_env_forwards_os_vars_but_no_secrets(self):
        # Finding #6: the native Wasmtime child (a Python importing the arch-specific
        # wasmtime wheel) failed to start on Windows because the parent passed only
        # PYTHONPATH, dropping SYSTEMROOT and the process/arch vars the C runtime and the
        # wheel need. The env is now a fixed allowlist of non-secret OS vars -- forwarded
        # when present, and never a credential-shaped variable.
        from portmark.providers import _wasmtime_subprocess_env

        # A non-literal value for the secret-named keys, so this fixture (whose whole
        # point is that secret-named vars are NOT forwarded) does not itself trip the
        # hardcoded-secret scanner.
        filtered = "filtered-out-value"
        fake_env = {
            "SYSTEMROOT": r"C:\Windows",
            "PYTHONPATH": "/opt/portmark",
            "PROCESSOR_ARCHITECTURE": "AMD64",
            "PATH": "/usr/bin",
            "AWS_SECRET_ACCESS_KEY": filtered,
            "PORTMARK_SIGNING_KEY": filtered,
        }
        with patch.dict(os.environ, fake_env, clear=True):
            env = _wasmtime_subprocess_env()
        self.assertEqual(env["SYSTEMROOT"], r"C:\Windows")
        self.assertEqual(env["PYTHONPATH"], "/opt/portmark")
        self.assertEqual(env["PROCESSOR_ARCHITECTURE"], "AMD64")
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
        self.assertNotIn("PORTMARK_SIGNING_KEY", env)

    def test_native_wasmtime_provider_uses_component_api_in_isolated_worker(self):
        component = FAKE_COMPONENT_HEADER + b"native-component"
        with self._fake_wasmtime_runtime():
            provider = NativeWasmtimeComponentProvider(component)
            decision = provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))
        self.assertEqual(decision.kind, "tool")
        self.assertEqual(decision.tool, "catalog.search")
        self.assertEqual(decision.arguments, {"query": "from native wasmtime", "limit": 2})

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    @_requires_enforced_worker_cap
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
    @_requires_enforced_worker_cap
    def test_real_native_wasmtime_component_traps_on_exhausted_fuel_and_memory(self):
        # Finding #6: a native guest is bounded by fuel (CPU) and a memory limit,
        # not only the wall-clock. Proven with the benign capsule under tiny
        # budgets — it runs fine at the defaults but is rejected when starved.
        capsule = str(Path(__file__).parents[1] / "capsules" / "research-agent.component.wasm.b64")
        state = AgentState("task", "goal")
        starved_fuel = NativeWasmtimeComponentProvider.from_file(capsule, max_fuel=10)
        with self.assertRaisesRegex(RuntimeError, "rejected|fuel"):
            starved_fuel.decide(provider_view(state), ("catalog.search",))
        starved_memory = NativeWasmtimeComponentProvider.from_file(capsule, max_memory_bytes=1)
        with self.assertRaisesRegex(RuntimeError, "rejected|memory"):
            starved_memory.decide(provider_view(state), ("catalog.search",))

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    def test_real_native_wasmtime_component_artifact_matches_source(self):
        from wasmtime import wat2wasm

        root = Path(__file__).parents[1]
        source = (root / "capsules" / "research-agent.component.wat").read_text(encoding="utf-8")
        artifact = base64.b64decode((root / "capsules" / "research-agent.component.wasm.b64").read_bytes().strip(), validate=True)
        self.assertEqual(bytes(wat2wasm(source)), artifact)

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    @_requires_enforced_worker_cap
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
            provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))

        core_provider = NativeWasmtimeComponentProvider(base64.b64decode(WASM_TOOL_REQUEST))
        # A core module is now refused BEFORE any Wasmtime parser runs (binary-component check).
        with self.assertRaisesRegex(RuntimeError, "not a binary Component Model artifact"):
            core_provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))

    def test_native_wasmtime_provider_rejects_unlinkable_or_missing_resume_components(self):
        with self._fake_wasmtime_runtime():
            provider = NativeWasmtimeComponentProvider(FAKE_COMPONENT_HEADER + b"import")
            with self.assertRaisesRegex(RuntimeError, "native Wasmtime component rejected"):
                provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))

        with self._fake_wasmtime_runtime():
            provider = NativeWasmtimeComponentProvider(FAKE_COMPONENT_HEADER + b"missing-resume")
            with self.assertRaisesRegex(RuntimeError, "native Wasmtime component rejected"):
                provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))

    def test_native_wasmtime_provider_enforces_timeout_and_output_limit(self):
        with self._fake_wasmtime_runtime(sleep_seconds=2):
            provider = NativeWasmtimeComponentProvider(FAKE_COMPONENT_HEADER + b"slow", timeout=0.1)
            with self.assertRaisesRegex(RuntimeError, "execution deadline"):
                provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))

        with self._fake_wasmtime_runtime(content="x" * 1024):
            provider = NativeWasmtimeComponentProvider(FAKE_COMPONENT_HEADER + b"large", max_output_bytes=128)
            with self.assertRaisesRegex(RuntimeError, "output limit|rejected"):
                provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))

    def test_native_wasmtime_provider_rejects_oversized_component_files(self):
        capsule = tempfile.NamedTemporaryFile(delete=False)
        try:
            capsule.write(b"x" * 5)
            capsule.close()  # Windows cannot reopen an open NamedTemporaryFile by name
            with self.assertRaisesRegex(RuntimeError, "input limit"):
                NativeWasmtimeComponentProvider.from_file(capsule.name, max_component_bytes=4)
        finally:
            os.unlink(capsule.name)

    def _wasm_providers_under_test(self, component):
        """Build both Wasm providers from `component`; the Node one without needing real node."""
        from portmark.providers import WasmDecisionProvider

        with patch("portmark.providers.shutil.which", return_value="/usr/bin/node"):
            node_provider = WasmDecisionProvider(component)
        return {"node": node_provider, "wasmtime": NativeWasmtimeComponentProvider(component)}

    def test_wasm_providers_execute_the_frozen_bytes_their_digest_names(self):
        # Section 9 finding #2: the digest was computed once but the caller's (mutable) object was
        # re-read on every decide, so a bytearray mutated after construction executed different
        # code under the original signed digest. The provider must freeze a private copy.
        original = b"\x00asm-original-component"
        expected_digest = "sha256:" + hashlib.sha256(original).hexdigest()
        for make_buffer in (bytearray, lambda data: memoryview(bytearray(data))):
            buffer = make_buffer(original)
            providers = self._wasm_providers_under_test(buffer)
            buffer[:] = b"X" * len(original)  # mutate AFTER construction
            for name, provider in providers.items():
                with self.subTest(provider=name, buffer=type(buffer).__name__):
                    sent = []

                    def capture(argv, request, **kwargs):
                        sent.append(base64.b64decode(json.loads(request)["component"]))
                        return 1, b"", "stop after capture", False, False

                    with patch("portmark.providers._run_bounded", side_effect=capture):
                        with self.assertRaises(RuntimeError):
                            provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))
                    self.assertEqual(provider.component_digest, expected_digest)
                    self.assertEqual(sent, [original])
                    self.assertEqual("sha256:" + hashlib.sha256(sent[0]).hexdigest(), provider.component_digest)

    def test_wasm_providers_reject_non_bytes_like_components(self):
        # bytes(5) would silently become five zero bytes and bytes([1, 2]) accepts a list of
        # ints -- neither is a component. Only real byte buffers are accepted: an int array is a
        # buffer, but its raw memory must not be reinterpreted as component bytes.
        import array

        for value in (5, True, "component", [1, 2], array.array("i", [1, 2, 3])):
            for name in ("node", "wasmtime"):
                with self.subTest(provider=name, value=value):
                    with self.assertRaisesRegex(RuntimeError, "bytes-like"):
                        if name == "node":
                            from portmark.providers import WasmDecisionProvider

                            with patch("portmark.providers.shutil.which", return_value="/usr/bin/node"):
                                WasmDecisionProvider(value)
                        else:
                            NativeWasmtimeComponentProvider(value)

    def test_wasm_providers_reject_oversized_buffer_before_copying_it(self):
        # PR #78 review: the size cap must apply BEFORE the private copy, or an oversized buffer
        # forces a second full-size allocation first. Measured, not mocked: peak allocation
        # during construction must stay far below the buffer size.
        import tracemalloc

        from portmark.providers import WasmDecisionProvider

        oversized = bytearray(8 * 1024 * 1024)
        builders = {
            "node": lambda: WasmDecisionProvider(oversized, max_component_bytes=1),
            "wasmtime": lambda: NativeWasmtimeComponentProvider(oversized, max_component_bytes=1),
        }
        for name, build in builders.items():
            with self.subTest(provider=name):
                tracemalloc.start()
                try:
                    with patch("portmark.providers.shutil.which", return_value="/usr/bin/node"):
                        with self.assertRaisesRegex(RuntimeError, "input limit"):
                            build()
                    _current, peak = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()
                self.assertLess(peak, 1024 * 1024)

    def test_wasm_providers_reject_released_memoryview_with_controlled_error(self):
        from portmark.providers import WasmDecisionProvider

        for name in ("node", "wasmtime"):
            with self.subTest(provider=name):
                released = memoryview(bytearray(b"component"))
                released.release()
                with self.assertRaisesRegex(RuntimeError, "bytes-like"):
                    if name == "node":
                        with patch("portmark.providers.shutil.which", return_value="/usr/bin/node"):
                            WasmDecisionProvider(released)
                    else:
                        NativeWasmtimeComponentProvider(released)

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    @_requires_enforced_worker_cap
    def test_real_native_wasmtime_runs_signed_bytes_after_caller_mutates_buffer(self):
        # End to end through the host's signed-manifest digest check (host.py): mutate the
        # caller's buffer after the provider is built; the ORIGINAL signed component must run.
        capsule = Path(__file__).parents[1] / "capsules" / "research-agent.component.wasm.b64"
        buffer = bytearray(base64.b64decode(capsule.read_bytes().strip(), validate=True))
        provider = NativeWasmtimeComponentProvider(buffer)
        buffer[:] = b"X" * len(buffer)
        host = make_host(providers={"wasm": provider})
        result = host.run(make_demo_envelope(host, "portable native component", "wasm"))
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.result["summary"], "Native Wasmtime component resumed from checkpoint")

    # ---- Section 9 PR 2: aggregate resource ceiling + deterministic engine config ----

    @staticmethod
    def _many_instance_component(core_body, instances):
        from wasmtime import wat2wasm

        instantiations = " ".join(["(core instance (instantiate $m))"] * instances)
        return bytes(wat2wasm(f"(component (core module $m {core_body}) {instantiations})"))

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    @_requires_enforced_worker_cap
    def test_real_native_wasmtime_refuses_components_past_store_count_limits(self):
        # Section 9 #1: memory_size is PER MEMORY in Wasmtime, so a component could multiply it by
        # declaring many memories/instances (the auditor's 301-memory, 4 KiB component). The store
        # now caps the counts too; each case must be refused by ITS limit, not incidentally.
        five_tables = " ".join(["(table 1 funcref)"] * 5)
        cases = (
            ("auditor 301 memories", self._many_instance_component("(memory 1)", 301), "memory count too high"),
            ("3 memories", self._many_instance_component("(memory 1)", 3), "memory count too high"),
            ("50 instances", self._many_instance_component("", 50), "instance count too high"),
            ("5 tables", self._many_instance_component(five_tables, 1), "table count too high"),
            ("20000 table elements", self._many_instance_component("(table 20000 funcref)", 1), "table minimum size"),
        )
        for label, component, reason in cases:
            with self.subTest(case=label):
                provider = NativeWasmtimeComponentProvider(component)
                with self.assertRaisesRegex(RuntimeError, reason):
                    provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    @_requires_enforced_worker_cap
    def test_real_native_wasmtime_admits_two_memories_grown_to_the_per_memory_cap(self):
        # The limits are a ceiling, not a ban: two memories (the default max) each grown to the full
        # 64 MiB per-memory cap still fit inside the 512 MiB worker ceiling. Reaching the export
        # check proves instantiation (and both grows) succeeded under the OS cap.
        grow = '(memory 1) (func (drop (memory.grow (i32.const 1023)))) (start 0)'
        provider = NativeWasmtimeComponentProvider(self._many_instance_component(grow, 2))
        with self.assertRaisesRegex(RuntimeError, "does not export resume"):
            provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))

    def test_native_wasmtime_provider_refuses_limits_that_exceed_worker_ceiling(self):
        # The store limits and the OS ceiling must agree or one is only advisory:
        # max_memories x max_memory_bytes + 256 MiB baseline <= worker_memory_limit (512 MiB).
        from portmark.providers import WASMTIME_WORKER_BASELINE_BYTES

        mib = 1024 * 1024
        self.assertEqual(WASMTIME_WORKER_BASELINE_BYTES, 256 * mib)
        NativeWasmtimeComponentProvider(b"component", max_memories=4)  # 4 x 64 + 256 == 512: fits
        with self.assertRaisesRegex(RuntimeError, "do not fit the worker memory ceiling"):
            NativeWasmtimeComponentProvider(b"component", max_memories=5)  # 576 > 512
        with self.assertRaisesRegex(RuntimeError, "do not fit the worker memory ceiling"):
            NativeWasmtimeComponentProvider(b"component", max_memory_bytes=200 * mib)
        for name in ("max_instances", "max_memories", "max_tables", "max_table_elements", "worker_memory_limit"):
            for bad in (0, -1, True, 1.5):
                with self.subTest(name=name, value=bad):
                    with self.assertRaisesRegex(RuntimeError, "positive integer"):
                        NativeWasmtimeComponentProvider(b"component", **{name: bad})

    def _capture_native_request(self, provider):
        sent = []

        def capture(argv, request, **kwargs):
            sent.append((json.loads(request), kwargs))
            return 1, b"", "stop after capture", False, False

        with patch("portmark.providers._run_bounded", side_effect=capture):
            with self.assertRaises(RuntimeError):
                provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))
        return sent[0]

    @unittest.skipIf(sys.platform == "win32", "POSIX worker caps; Windows uses a Job Object")
    def test_native_wasmtime_provider_sends_count_limits_and_os_caps_to_worker(self):
        request, kwargs = self._capture_native_request(NativeWasmtimeComponentProvider(b"component", timeout=2.0))
        self.assertEqual(
            {key: request[key] for key in ("max_memory_bytes", "instances", "memories", "tables", "table_elements")},
            {"max_memory_bytes": 64 * 1024 * 1024, "instances": 8, "memories": 2, "tables": 4, "table_elements": 10_000},
        )
        self.assertEqual(request["rlimits"], {"address_space": 512 * 1024 * 1024, "cpu_seconds": 3})
        self.assertIsNone(kwargs["launch"])

    @unittest.skipUnless(sys.platform == "win32", "Windows Job Object launch path")
    def test_native_wasmtime_decision_runs_in_real_memory_capped_job_on_windows(self):
        # NOT mocked: a real decision (fake wasmtime module, real worker process) goes through the
        # REAL Job Object launcher and _run_bounded's kill/close handoff. The spy only records the
        # call -- it wraps the real launcher, so the worker genuinely runs inside the capped job.
        import portmark.tools as tools_module

        real_launch = tools_module._launch_windows_job_tree
        with self._fake_wasmtime_runtime():
            provider = NativeWasmtimeComponentProvider(FAKE_COMPONENT_HEADER + b"native-component", timeout=10.0)
            with patch.object(tools_module, "_launch_windows_job_tree", wraps=real_launch) as spy:
                decision = provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))
        self.assertEqual(decision.tool, "catalog.search")
        self.assertEqual(spy.call_count, 1)
        self.assertEqual(spy.call_args.kwargs["process_memory_limit"], 512 * 1024 * 1024)

    def test_native_wasmtime_blocks_uncapped_platform_unless_operator_opts_out(self):
        # Owner decision: where no OS memory ceiling can be ENFORCED, refuse by default; an explicit
        # opt-out runs uncapped, warns on every run, and requests no OS caps it cannot apply.
        with patch("portmark.providers._worker_memory_cap_enforceable", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "enforceable OS memory ceiling"):
                NativeWasmtimeComponentProvider(b"component")
            provider = NativeWasmtimeComponentProvider(b"component", allow_uncapped_worker=True)
            with self.assertLogs("portmark.providers", level="WARNING") as logs:
                request, kwargs = self._capture_native_request(provider)
        self.assertIn("WITHOUT an OS memory ceiling", "\n".join(logs.output))
        self.assertEqual(request["rlimits"], {})
        self.assertIsNone(kwargs["launch"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "RLIMIT_AS is enforced on Linux")
    def test_worker_memory_cap_self_check_detects_enforcement_and_can_fail(self):
        from portmark import providers as providers_module

        providers_module._worker_memory_cap_enforceable.cache_clear()
        try:
            self.assertTrue(providers_module._worker_memory_cap_enforceable())
            # Prove the oracle can say no: a self-check whose over-cap allocation is NOT refused.
            providers_module._worker_memory_cap_enforceable.cache_clear()
            with patch.object(providers_module, "_CAP_SELF_CHECK", "import sys\nsys.exit(3)\n"):
                self.assertFalse(providers_module._worker_memory_cap_enforceable())
        finally:
            providers_module._worker_memory_cap_enforceable.cache_clear()

    @unittest.skipUnless(HAS_REAL_WASMTIME and sys.platform != "win32", "requires portmark[wasmtime] on POSIX")
    @_requires_enforced_worker_cap
    def test_real_native_wasmtime_worker_runs_under_the_requested_os_address_space_cap(self):
        # The cap is applied INSIDE the worker before the Engine is built, so compilation runs capped.
        # A 32 MiB cap leaves no room for an Engine: the worker must fail and emit no decision. The
        # same request at the default 512 MiB succeeds -- so the failure is the cap, not the input.
        capsule = (Path(__file__).parents[1] / "capsules" / "research-agent.component.wasm.b64").read_text().strip()
        mib = 1024 * 1024

        def run_worker(address_space):
            request = {
                "component": capsule, "context_json": "{}", "checkpoint_json": "{}",
                "max_output_bytes": 65_536, "max_fuel": 10**9, "max_memory_bytes": 64 * mib,
                "instances": 8, "memories": 2, "tables": 4, "table_elements": 10_000,
                "rlimits": {"address_space": address_space, "cpu_seconds": 5},
            }
            return subprocess.run(  # nosec B603 - fixed argv, host interpreter, no shell
                [sys.executable, "-m", "portmark.wasmtime_component_runner"],
                input=json.dumps(request).encode(), capture_output=True, timeout=60, check=False,
            )

        capped = run_worker(32 * mib)
        self.assertNotEqual(capped.returncode, 0)
        self.assertEqual(capped.stdout, b"")
        normal = run_worker(512 * mib)
        self.assertEqual(normal.returncode, 0, normal.stderr)
        self.assertIn(b'"outcome"', normal.stdout)

    def test_native_wasmtime_worker_slots_bound_concurrency_and_honour_the_deadline(self):
        # Section 9 #3: every decision compiles in a fresh worker, so concurrent decisions are capped
        # separately from request concurrency. Waiting for a slot spends the SAME deadline as the
        # run: a saturated host fails closed on time instead of queueing past the timeout.
        slots = threading.BoundedSemaphore(1)
        with self._fake_wasmtime_runtime(), patch("portmark.providers._WASMTIME_WORKER_SLOTS", slots):
            provider = NativeWasmtimeComponentProvider(FAKE_COMPONENT_HEADER + b"native-component", timeout=0.3)
            self.assertTrue(slots.acquire(blocking=False))  # another decision holds the only slot
            started = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, "capacity exhausted before the execution deadline"):
                provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))
            self.assertLess(time.monotonic() - started, 1.5)
            slots.release()
            generous = NativeWasmtimeComponentProvider(FAKE_COMPONENT_HEADER + b"native-component", timeout=10.0)
            decision = generous.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))
            self.assertEqual(decision.tool, "catalog.search")
            self.assertTrue(slots.acquire(blocking=False), "a finished decision must release its slot")
            slots.release()

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    def test_real_native_wasmtime_engine_config_canonicalizes_nan(self):
        # Section 9 #4. Expected value is HAND-DERIVED from the WebAssembly spec's canonical f32 NaN
        # (sign 0, quiet bit set, zero payload = 0x7fc00000) -- not produced by running this code.
        # Without canonicalization, x86-64 hardware yields 0xffc00000 for 0.0/0.0 (sign bit set),
        # which a guest could observe and branch on differently across architectures.
        from wasmtime import Engine, Instance, Module, Store, wat2wasm

        from portmark.wasmtime_component_runner import _engine_config

        engine = Engine(_engine_config(64 * 1024 * 1024))
        store = Store(engine)
        store.set_fuel(1_000_000)
        module = Module(engine, wat2wasm(
            '(module (func (export "nan") (param f32 f32) (result i32)'
            " local.get 0 local.get 1 f32.div i32.reinterpret_f32))"
        ))
        nan = Instance(store, module, []).exports(store)["nan"]
        self.assertEqual(nan(store, 0.0, 0.0) & 0xFFFFFFFF, 0x7FC00000)

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    def test_real_native_wasmtime_engine_config_locks_default_enabled_proposals(self):
        # Each feature below is ACCEPTED by Wasmtime 48's default Config (the control arm), so its
        # refusal under the hardened config is evidence the lock bites -- not a no-op.
        from wasmtime import Config, Engine, Module, wat2wasm

        from portmark.wasmtime_component_runner import _engine_config

        features = {
            "threads / shared memory": "(module (memory 1 1 shared))",
            "memory64": "(module (memory i64 1))",
            "multi-memory": "(module (memory 1) (memory 1))",
            "gc": "(module (type (struct (field i32))))",
            "exceptions": "(module (tag))",
            "tail call": "(module (func $f (return_call $f)))",
            "typed function references": "(module (type $t (func)) (func (param (ref $t))))",
        }
        hardened = Engine(_engine_config(64 * 1024 * 1024))
        default = Engine(Config())
        for name, source in features.items():
            with self.subTest(feature=name):
                wasm = wat2wasm(source)
                Module(default, wasm)  # control: accepted by default
                with self.assertRaises(Exception):
                    Module(hardened, wasm)

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    def test_real_native_wasmtime_engine_config_assigns_every_proposal_setter(self):
        # PR #79 review: two default-on proposals were left unassigned. Enumerate EVERY proposal
        # setter the installed wasmtime-py exposes and require _engine_config to assign each one,
        # so a proposal added by a Wasmtime upgrade fails this test until it is decided explicitly.
        import inspect

        import wasmtime

        from portmark.wasmtime_component_runner import _engine_config

        def is_proposal_setter(name):
            attribute = inspect.getattr_static(wasmtime.Config, name)
            return (
                (name.startswith("wasm_") or name in {"gc_support", "shared_memory"})
                and isinstance(attribute, property) and attribute.fset is not None
            )

        proposals = {name for name in dir(wasmtime.Config) if is_proposal_setter(name)}
        assigned = set()

        class RecordingConfig(wasmtime.Config):
            def __setattr__(self, name, value):
                assigned.add(name)
                super().__setattr__(name, value)

        with patch.object(wasmtime, "Config", RecordingConfig):
            _engine_config(64 * 1024 * 1024)
        self.assertIn("wasm_tail_call", proposals)  # the enumeration itself is not empty/broken
        self.assertEqual(sorted(proposals - assigned), [])

    # ---- Section 9 PR 3: cross-platform proof (runs in every native-wasmtime CI lane) ----

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    def test_real_native_wasmtime_platform_outcome_matches_cap_enforcement(self):
        # Owner decision: native Wasmtime runs only under an ENFORCED OS memory ceiling. Each CI lane
        # (Linux x86-64, Linux ARM64, Windows, macOS) proves whichever branch its platform takes, and
        # the log line records which one -- so the macOS outcome is observed, not assumed.
        from portmark import providers as providers_module

        providers_module._worker_memory_cap_enforceable.cache_clear()
        enforced = providers_module._worker_memory_cap_enforceable()
        print(f"\n[platform-outcome] {sys.platform}/{platform.machine()}: worker cap enforced={enforced}")
        capsule = base64.b64decode(
            (Path(__file__).parents[1] / "capsules" / "research-agent.component.wasm.b64").read_bytes().strip()
        )
        if enforced:
            provider = NativeWasmtimeComponentProvider(capsule)
        else:
            with self.assertRaisesRegex(RuntimeError, "enforceable OS memory ceiling"):
                NativeWasmtimeComponentProvider(capsule)
            provider = NativeWasmtimeComponentProvider(capsule, allow_uncapped_worker=True)
        decision = provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))
        self.assertEqual(decision.tool, "catalog.search")

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    def test_real_native_wasmtime_engine_config_makes_relaxed_simd_deterministic(self):
        # Section 9 #4. Expected values are HAND-DERIVED from the WebAssembly spec's deterministic
        # relaxed-SIMD semantics, not from running this code: relaxed_swizzle behaves as
        # i8x16.swizzle (an index >= 16 selects 0), and relaxed_trunc_f32x4_s behaves as
        # i32x4.trunc_sat_f32x4_s (NaN -> 0). Native x86-64 lowering instead yields 2 (the index is
        # taken mod 16) and 0x80000000; native AArch64 already yields 0 and 0. Deterministic mode
        # makes every architecture return the spec values.
        from wasmtime import Engine, Instance, Module, Store, wat2wasm

        from portmark.wasmtime_component_runner import _engine_config

        engine = Engine(_engine_config(64 * 1024 * 1024))
        store = Store(engine)
        store.set_fuel(1_000_000)
        exports = Instance(store, Module(engine, wat2wasm("""(module
          (func (export "swizzle_out_of_range") (result i32)
            (i8x16.extract_lane_u 0 (i8x16.relaxed_swizzle
              (v128.const i8x16 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)
              (v128.const i8x16 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0))))
          (func (export "trunc_nan") (param f32) (result i32)
            (i32x4.extract_lane 0 (i32x4.relaxed_trunc_f32x4_s (f32x4.splat (local.get 0))))))""")), []).exports(store)
        self.assertEqual(exports["swizzle_out_of_range"](store) & 0xFF, 0)
        self.assertEqual(exports["trunc_nan"](store, float("nan")) & 0xFFFFFFFF, 0)

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    def test_real_native_wasmtime_decision_vector_is_identical_on_every_platform(self):
        # The same inputs must give the same decisions on every CI lane. The expected vector is
        # HAND-DERIVED from capsules/research-agent.component.wat: resume() returns the tool-request
        # data segment when the checkpoint is shorter than 120 bytes (`i32.lt_u` against 120), and
        # the completed segment otherwise. The boundary lengths 119/120 pin that comparison exactly.
        # Every lane asserts this one oracle, so passing lanes agree with each other by construction.
        capsule = (Path(__file__).parents[1] / "capsules" / "research-agent.component.wasm.b64").read_text().strip()
        tool = {
            "outcome": "tool",
            "request": {
                "name": "catalog.search",
                "arguments_json": '{"query":"from native component checkpoint","limit":2}',
            },
        }
        completed = {
            "outcome": "completed",
            "content_json": '{"summary":"Native Wasmtime component resumed from checkpoint",'
                            '"evidence":["native-checkpoint-observed"]}',
        }
        vector = ((0, tool), (119, tool), (120, completed), (4096, completed))
        for checkpoint_length, expected in vector:
            with self.subTest(checkpoint_length=checkpoint_length):
                request = {
                    "component": capsule, "context_json": "{}", "checkpoint_json": "x" * checkpoint_length,
                    "max_output_bytes": 65_536, "max_fuel": 10**9, "max_memory_bytes": 64 * 1024 * 1024,
                    "instances": 8, "memories": 2, "tables": 4, "table_elements": 10_000, "rlimits": {},
                }
                result = subprocess.run(  # nosec B603 - fixed argv, host interpreter, no shell
                    [sys.executable, "-m", "portmark.wasmtime_component_runner"],
                    input=json.dumps(request).encode(), capture_output=True, timeout=60, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), expected)

    # ---- Section 9 follow-up: malformed-component fuzz campaign (tests/fuzz_wasmtime_components.py) ----

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    @_requires_enforced_worker_cap
    def test_real_native_wasmtime_refuses_webassembly_text_components(self):
        # Fuzz finding: wasmtime.component.Component also parses the WebAssembly TEXT format, so the
        # capsule's .wat SOURCE compiled and ran as a provider. The contract is a binary component;
        # anything without the binary magic + component layer is refused before any Wasmtime parser.
        root = Path(__file__).parents[1]
        text_capsule = (root / "capsules" / "research-agent.component.wat").read_bytes()
        view = provider_view(AgentState("task", "goal"))
        for label, component in (("text capsule", text_capsule), ("minimal text", b"(component)")):
            with self.subTest(case=label):
                with self.assertRaisesRegex(RuntimeError, "not a binary Component Model artifact"):
                    NativeWasmtimeComponentProvider(component).decide(view, ("catalog.search",))
        binary = base64.b64decode((root / "capsules" / "research-agent.component.wasm.b64").read_bytes().strip())
        self.assertEqual(NativeWasmtimeComponentProvider(binary).decide(view, ("catalog.search",)).tool,
                         "catalog.search")  # the same capsule in binary form still runs

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    def test_real_native_wasmtime_parser_still_refuses_core_module_without_the_binary_check(self):
        # Defense in depth: the binary-component check now refuses core modules first, so this pins
        # the SECOND layer -- with that check bypassed, Wasmtime's component parser must still refuse
        # a core module. (Text input, by contrast, IS accepted by Wasmtime -- why the check exists.)
        from wasmtime import wat2wasm

        import portmark.wasmtime_component_runner as runner

        limits = {"instances": 8, "memories": 2, "tables": 4, "table_elements": 10_000}
        core_module = bytes(wat2wasm('(module (func (export "resume") (result i32) i32.const 0))'))
        with patch.object(runner, "_require_binary_component", lambda component: None):
            with self.assertRaisesRegex(Exception, "parse a wasm module|component parser|failed to parse") as caught:
                runner._execute(core_module, "{}", "{}", max_fuel=10**7, max_memory_bytes=64 * 1024 * 1024,
                                count_limits=dict(limits))
            self.assertIsInstance(caught.exception, runner._controlled_errors())
        for empty_or_short in (b"", b"\x00as", b"\x00asm\x0d\x00"):
            with self.subTest(component=empty_or_short):
                with self.assertRaisesRegex(RuntimeError, "not a binary Component Model artifact"):
                    runner._require_binary_component(empty_or_short)

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    def test_real_native_wasmtime_component_fuzz_smoke_campaign_finds_nothing(self):
        # A small slice of the campaign (the CI native-wasmtime job runs a larger one per platform).
        import fuzz_wasmtime_components as fuzz

        inproc = fuzz.run_inproc_arm(400)
        self.assertEqual(inproc["findings"], [])
        self.assertEqual(fuzz.coverage_findings(inproc["records"]), [])
        e2e = fuzz.run_e2e_arm(6)
        self.assertEqual(e2e["findings"], [])

    def test_component_fuzz_oracles_can_fail(self):
        # A checker that never fails proves nothing: each oracle must flag its bad input.
        import fuzz_wasmtime_components as fuzz

        self.assertEqual(fuzz.check_inproc_record({"i": 1, "outcome": "ok", "seconds": 0.01}), [])
        self.assertTrue(fuzz.check_inproc_record({"i": 1, "outcome": "uncontrolled", "type": "KeyError"}))
        self.assertTrue(fuzz.check_inproc_record({"i": 1, "outcome": "controlled", "seconds": 9.0}))
        self.assertEqual(fuzz.check_e2e_result("ok", 0.1, 2.0, RuntimeError("rejected"), None,
                                               {"returncode": 1, "stdout": b""}), [])
        cases = {
            "leaked type": (0.1, KeyError("x"), None, {"returncode": 1, "stdout": b""}),
            "traceback text": (0.1, RuntimeError("Traceback (most recent call last): ..."), None, None),
            "native panic": (0.1, RuntimeError("thread 'main' panicked at src/lib.rs"), None, None),
            "crash signal": (0.1, RuntimeError("rejected"), None, {"returncode": -11, "stdout": b""}),
            "over deadline": (9.0, RuntimeError("rejected"), None, None),
            "stdout on failure": (0.1, RuntimeError("rejected"), None, {"returncode": 1, "stdout": b"{}"}),
            "tool not offered": (0.1, None, ProviderDecision("tool", "payments.reserve", {}), None),
        }
        for label, (elapsed, error, decision, run) in cases.items():
            with self.subTest(case=label):
                self.assertTrue(fuzz.check_e2e_result(label, elapsed, 2.0, error, decision, run))
        header_only = [{"stage": "header"}] * 10
        self.assertTrue(fuzz.coverage_findings(header_only))

    def test_component_fuzz_exit_code_oracle_is_platform_neutral(self):
        # PR #82 review: a Windows native crash exits with a POSITIVE NTSTATUS, which the old
        # "negative code = signal" rule scored as a clean rejection. Only 0 and 1 are legitimate,
        # unless the parent recorded its own deadline/overflow kill.
        import fuzz_wasmtime_components as fuzz

        rejected = RuntimeError("native Wasmtime component rejected: ...")
        must_flag = {
            "Windows access violation 0xC0000005": {"returncode": 0xC0000005},
            "Windows fail-fast 0xC0000409": {"returncode": 0xC0000409},
            "POSIX SIGSEGV": {"returncode": -11},
            "POSIX SIGABRT": {"returncode": -6},
            "unexpected exit 2": {"returncode": 2},
            "SIGKILL without a parent kill": {"returncode": -9},
        }
        for label, run in must_flag.items():
            with self.subTest(case=label):
                findings = fuzz.check_e2e_result(label, 0.1, 2.0, rejected, None, {**run, "stdout": b""})
                self.assertTrue(any("exited abnormally" in finding for finding in findings), findings)
        must_pass = {
            "controlled rejection": {"returncode": 1},
            "POSIX deadline kill": {"returncode": -9, "timed_out": True},
            "Windows deadline kill (TerminateJobObject)": {"returncode": 1, "timed_out": True},
            "overflow kill": {"returncode": -9, "overflowed": True},
        }
        for label, run in must_pass.items():
            with self.subTest(case=label):
                self.assertEqual(fuzz.check_e2e_result(label, 0.1, 2.0, rejected, None, {**run, "stdout": b""}), [])
        self.assertEqual(fuzz.check_e2e_result("decision", 0.1, 2.0, None,
                                               ProviderDecision("tool", "catalog.search", {}),
                                               {"returncode": 0, "stdout": b"{}"}), [])

    def test_component_fuzz_coverage_requires_every_claimed_stage(self):
        # PR #82 review: the coverage check must require every stage the campaign claims, so a corpus
        # regression that loses any one of them fails instead of staying green.
        import fuzz_wasmtime_components as fuzz

        self.assertEqual(set(fuzz.REQUIRED_STAGES),
                         {"ran", "decode", "limits", "link", "run", "export", "call", "outcome"})
        full = [{"stage": stage} for stage in fuzz.REQUIRED_STAGES] * 5
        self.assertEqual(fuzz.coverage_findings(full), [])
        for missing in fuzz.REQUIRED_STAGES:
            with self.subTest(missing=missing):
                findings = fuzz.coverage_findings([record for record in full if record["stage"] != missing])
                self.assertEqual(findings, [f"coverage: no case reached stage {missing!r}"])

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    def test_real_native_wasmtime_component_fuzz_watchdog_records_a_hang_and_resumes(self):
        # PR #82 review: one hanging case must not stall a CI lane. The child hangs at case 10; the
        # per-case watchdog must report exactly that case, kill the child, and run cases 11-19.
        import fuzz_wasmtime_components as fuzz

        started = time.monotonic()
        result = fuzz.run_inproc_arm(20, hang_at=10, watchdog=3.0)
        hung = [finding for finding in result["findings"] if "HUNG" in finding]
        self.assertEqual(len(hung), 1, result["findings"])
        self.assertIn("case 10", hung[0])
        self.assertEqual(sorted(record["i"] for record in result["records"]), [i for i in range(20) if i != 10])
        self.assertLess(time.monotonic() - started, 30)

    @unittest.skipUnless(HAS_REAL_WASMTIME, "requires portmark[wasmtime]")
    def test_real_native_wasmtime_component_fuzz_detects_a_crashing_child_and_resumes(self):
        # Calibration of the crash path: the child aborts (a stand-in for a native crash) at case 20;
        # the campaign must report exactly that case and still run the cases after it.
        import fuzz_wasmtime_components as fuzz

        result = fuzz.run_inproc_arm(40, abort_at=20)
        died = [finding for finding in result["findings"] if "child died" in finding]
        self.assertEqual(len(died), 1, result["findings"])
        self.assertIn("case 20", died[0])
        self.assertEqual(max(record["i"] for record in result["records"]), 39)

    @unittest.skipUnless(sys.platform == "win32", "Windows Job Object memory limit")
    def test_windows_job_process_memory_limit_refuses_allocation_past_the_ceiling(self):
        # Section 9 #1 on Windows: the worker's OS ceiling is the Job Object's per-process memory
        # limit. Same child, with and without the limit, so a refusal can only come from the limit.
        from portmark.tools import _launch_windows_job_tree

        mib = 1024 * 1024
        argv = [sys.executable, "-c", f"bytearray({256 * mib})"]
        common = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        for limit, should_succeed in ((None, True), (128 * mib, False)):
            with self.subTest(limit=limit):
                tree = _launch_windows_job_tree(argv, dict(common), process_memory_limit=limit)
                try:
                    returncode = tree.wait(timeout=30)
                finally:
                    tree.close()
                self.assertEqual(returncode == 0, should_succeed, f"returncode={returncode}")

    def test_factory_selects_optional_native_wasmtime_provider(self):
        with self._fake_wasmtime_runtime():
            capsule = tempfile.NamedTemporaryFile(delete=False)
            try:
                capsule.write(FAKE_COMPONENT_HEADER + b"native-component")
                capsule.close()  # Windows cannot reopen an open NamedTemporaryFile by name
                host = make_host(
                    wasm_component=capsule.name,
                    wasm_engine="wasmtime",
                )
            finally:
                os.unlink(capsule.name)
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
        view = provider_view(state, grants)
        context = component_context(view, ("catalog.search",))
        checkpoint = component_checkpoint(view)

        self.assertEqual(context["state"]["messages"], [{"role": "tool", "name": "catalog.search", "content": {"title": "Visible"}}])
        self.assertEqual(checkpoint["messages"], [{"role": "tool", "name": "catalog.search", "content": {"title": "Visible"}}])
        self.assertNotIn("memory", context["state"])
        self.assertNotIn("result", context["state"])
        self.assertNotIn("memory", checkpoint)
        self.assertNotIn("internal_note", json.dumps(context))
        self.assertNotIn("internal_note", json.dumps(checkpoint))

    def test_wasm_with_ambient_wasi_import_cannot_instantiate(self):
        _skip_if_declared_no_node_environment()
        from portmark.providers import WasmDecisionProvider
        hostile = base64.b64decode(WASM_FORBIDDEN_IMPORT)
        provider = WasmDecisionProvider(hostile)
        with self.assertRaisesRegex(RuntimeError, "ambient imports"):
            provider.decide(provider_view(AgentState("task", "goal")), ())

    def test_wit_world_declares_no_host_imports(self):
        # Invariant tripwire: a Portmark component is a pure decision function.
        # Its WIT world must import nothing, so a component has no ambient host
        # access and can only act by returning a tool-request (which the host
        # then scopes via tool grants + check_constraints). If someone adds an
        # `import` to the world, this fails on purpose — forcing a scoped
        # host-capability design (see issue #23) before the door opens.
        import pathlib
        wit_path = pathlib.Path(__file__).resolve().parent.parent / "wit" / "portmark.wit"
        source = wit_path.read_text(encoding="utf-8")
        world_body = source.split("world portmark", 1)[1]
        world_body = world_body[world_body.index("{") + 1 : world_body.index("}")]
        offending = [
            line.strip()
            for line in world_body.splitlines()
            if line.strip().startswith("import ") or line.strip().startswith("import\t")
        ]
        self.assertEqual(
            offending,
            [],
            "wit/portmark.wit world declares host imports; components must stay "
            "import-free or gain scoped host-capability grants first (issue #23)",
        )

    def test_wasm_component_tool_decision_uses_structured_wit_outcome(self):
        _skip_if_declared_no_node_environment()
        from portmark.providers import WasmDecisionProvider
        provider = WasmDecisionProvider(base64.b64decode(WASM_TOOL_REQUEST))
        # Carry real tool_results (and a prior tool message) so the wire input includes the
        # now-serialized `tool_results` field -- confirms the larger component input (tool
        # output appears in BOTH messages and tool_results after the cross-adapter-consistency
        # fix) round-trips a real Node-Wasm decision without tripping a fuel/memory/output cap.
        state = AgentState(
            "task", "goal",
            memory={"tool_results": {"catalog.search": {"id": "1", "title": "Prior", "score": 0.9}}},
            messages=[{"role": "tool", "name": "catalog.search", "content": {"id": "1", "title": "Prior", "score": 0.9}}],
        )
        view = provider_view(state, (ToolGrant("catalog.search", output_projection=("id", "title")),))
        self.assertTrue(view.tool_results)  # the bigger input is actually present
        decision = provider.decide(view, ("catalog.search",))
        self.assertEqual(decision.kind, "tool")
        self.assertEqual(decision.tool, "catalog.search")
        self.assertEqual(decision.arguments, {"query": "from wasm", "limit": 3})

    def test_wasm_component_unavailable_capability_fails_closed(self):
        _skip_if_declared_no_node_environment()
        from portmark.providers import WasmDecisionProvider
        provider = WasmDecisionProvider(base64.b64decode(WASM_TOOL_REQUEST))
        decision = provider.decide(provider_view(AgentState("task", "goal")), ())
        self.assertEqual(decision.kind, "fail")
        self.assertEqual(decision.content, {"error": "required capability unavailable"})

    def test_wasm_component_malformed_missing_timeout_and_oversized_outputs_are_rejected(self):
        _skip_if_declared_no_node_environment()
        from portmark.providers import WasmDecisionProvider
        cases = [
            (WASM_MALFORMED_JSON, {}, "malformed or unsafe decision JSON"),
            (WASM_MISSING_RESUME, {}, "must export resume"),
            (WASM_TIMEOUT, {"timeout": 0.01}, "deadline"),
            (WASM_TOOL_REQUEST, {"max_output_bytes": 8}, "output limit"),
        ]
        for encoded, kwargs, message in cases:
            provider = WasmDecisionProvider(base64.b64decode(encoded), **kwargs)
            with self.subTest(message=message):
                with self.assertRaisesRegex(RuntimeError, message):
                    provider.decide(provider_view(AgentState("task", "goal")), ("catalog.search",))



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
                "catalog.search": {"impact": "low", "constraints": {"max_limit": 5, "arguments": {"query": {"type": "string"}}}, "output_projection": ["id", "title"]},
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

    def test_host_refuses_to_start_when_an_agent_signing_identity_leaks_into_its_environment(self):
        """The documented quickstart exports an agent key; the host must not adopt it.

        Every run signs an audit head with the host id as issuer, so a host holding an
        agent's PORTMARK_SIGNING_ISSUER could only ever fail on its first request with
        "audit head host does not match signing identity". Fail at boot and name both
        values instead. Regression: the README quickstart eval'd the keygen exports and
        then started the server in the same shell.
        """
        material = generate_signing_material("leaked-agent-key", "user:alice")
        leaked = {
            "PORTMARK_ED25519_PRIVATE_KEY_B64": material["private_key_b64"],
            "PORTMARK_SIGNING_KEY_ID": material["key_id"],
            "PORTMARK_SIGNING_ISSUER": material["issuer"],
        }
        with patch.dict(os.environ, leaked, clear=True):
            with self.assertRaisesRegex(ValueError, "must equal host id"):
                make_host()

        # Control: the same host builds cleanly once the agent key is out of the way.
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNotNone(make_host())

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


class IsolationProfileGateTests(unittest.TestCase):
    """Section 7 PR 2b: the MANDATORY side-effecting startup gate (reconcile + acknowledged,
    platform-appropriate IsolationProfile) and its launch-time re-check. The registration-gate tests
    patch _has_tree_termination_primitive to True so they isolate the 2b logic and run on every
    platform; they never spawn a worker (registration imports nothing and the pre-capability re-check
    raises first). Fake module:function targets ("m:f"/"m:r") are valid at registration because it does
    only a SYNTAX check -- it never imports them (PR 2b round 3 removed the import-based preflight)."""

    def _profile(self, mechanism=IsolationMechanism.EXTERNAL_CONTAINER, by="ops"):
        return IsolationProfile(mechanism=mechanism, acknowledged_by=by)

    def _permit(self, name):
        return Permit(
            issuer="i", subject="s", audience="host", expires_at=int(time.time()) + 60,
            nonce=f"n-{name}", grants=(ToolGrant(name),),
        )

    def test_isolation_profile_rejects_empty_or_non_enum(self):  # G1
        with self.assertRaises(ValueError):
            IsolationProfile(mechanism=IsolationMechanism.EXTERNAL_CONTAINER, acknowledged_by="   ")
        with self.assertRaises(ValueError):
            IsolationProfile(mechanism="external_container", acknowledged_by="ops")  # type: ignore[arg-type]
        p = IsolationProfile(mechanism=IsolationMechanism.EXTERNAL_CONTAINER, acknowledged_by="ops")
        self.assertEqual(p.audit_summary(), {"mechanism": "external_container", "acknowledged_by": "ops"})

    def test_side_effecting_registration_requires_reconcile(self):  # G3 (CALIBRATED)
        with patch("portmark.tools._has_tree_termination_primitive", return_value=True):
            registry = ToolRegistry(isolation_profile=self._profile())
            with self.assertRaisesRegex(SecurityError, "reconcile"):
                registry.register_isolated("pay", "m:f", side_effecting=True)
            self.assertNotIn("pay", registry.names())  # refused registration left no trace
            registry.register_isolated("pay", "m:f", side_effecting=True, reconcile="m:r")
            self.assertTrue(registry.is_side_effecting("pay"))

    def test_side_effecting_registration_requires_acknowledged_profile(self):  # G4 (CALIBRATED)
        with patch("portmark.tools._has_tree_termination_primitive", return_value=True):
            no_profile = ToolRegistry()
            with self.assertRaisesRegex(SecurityError, "IsolationProfile"):
                no_profile.register_isolated("pay", "m:f", side_effecting=True, reconcile="m:r")
            self.assertNotIn("pay", no_profile.names())
            with_profile = ToolRegistry(isolation_profile=self._profile())
            with_profile.register_isolated("pay", "m:f", side_effecting=True, reconcile="m:r")
            self.assertIn("pay", with_profile.names())

    def test_side_effecting_registration_couples_mechanism_to_platform(self):  # G5 (CALIBRATED)
        with patch("portmark.tools._has_tree_termination_primitive", return_value=True):
            # A platform with NO Windows Job Object (POSIX): os_job_object is refused, external ok.
            with patch("portmark.tools._windows_job.available", return_value=False):
                job_reg = ToolRegistry(isolation_profile=self._profile(IsolationMechanism.OS_JOB_OBJECT))
                with self.assertRaisesRegex(SecurityError, "does not contain workers on this platform"):
                    job_reg.register_isolated("pay", "m:f", side_effecting=True, reconcile="m:r")
                ext_reg = ToolRegistry(isolation_profile=self._profile(IsolationMechanism.EXTERNAL_CONTAINER))
                ext_reg.register_isolated("pay", "m:f", side_effecting=True, reconcile="m:r")
                self.assertIn("pay", ext_reg.names())
            # A platform WITH the Job Object (Windows): os_job_object is now genuine and accepted.
            with patch("portmark.tools._windows_job.available", return_value=True):
                job_ok = ToolRegistry(isolation_profile=self._profile(IsolationMechanism.OS_JOB_OBJECT))
                job_ok.register_isolated("pay", "m:f", side_effecting=True, reconcile="m:r")
                self.assertIn("pay", job_ok.names())

    def test_reregistration_cannot_strip_reconcile_while_side_effecting(self):  # G8 (CALIBRATED)
        with patch("portmark.tools._has_tree_termination_primitive", return_value=True):
            registry = ToolRegistry(isolation_profile=self._profile())
            registry.register_isolated("pay", "m:f", side_effecting=True, reconcile="m:r")
            self.assertTrue(registry.is_side_effecting("pay"))
            # Re-register side-effecting WITHOUT reconcile -> refused; prior state untouched.
            with self.assertRaisesRegex(SecurityError, "reconcile"):
                registry.register_isolated("pay", "m:f2", side_effecting=True)
            self.assertTrue(registry.is_side_effecting("pay"))
            self.assertTrue(registry.has_reconcile("pay"))
            # Re-register as NON-side-effecting -> membership cleared (no stale side-effecting flag).
            registry.register_isolated("pay", "m:f2", side_effecting=False)
            self.assertFalse(registry.is_side_effecting("pay"))
            # A plain thread register() of the same name also clears any stale membership.
            registry._side_effecting.add("pay")
            registry.register("pay", lambda arguments: {"ok": True})
            self.assertFalse(registry.is_side_effecting("pay"))

    def test_reregistration_replaces_the_tool_limits_completely(self):
        # Audit plan 006: a registration under an existing name is a complete replacement. A limit it
        # does not name is the registry default, never a leftover of the replaced tool.
        def limits(registry, name):  # what invoke() uses
            return registry._timeouts.get(name, registry.default_timeout), registry._max_output.get(name, registry.max_output_bytes)

        plain = lambda arguments: {"ok": True}  # noqa: E731
        seeded = {
            "plain": lambda registry: registry.register("t", plain, timeout=0.25),
            "isolated": lambda registry: registry.register_isolated("t", "m:f", timeout=0.25, max_output_bytes=10),
        }
        replaced = {
            "plain": lambda registry, **limit: registry.register("t", plain, **limit),
            "isolated": lambda registry, **limit: registry.register_isolated("t", "m:g", **limit),
        }
        for before, seed in seeded.items():
            for after, replace in replaced.items():
                with self.subTest(before=before, after=after):
                    registry = ToolRegistry(default_timeout=7.0, max_output_bytes=4096)
                    seed(registry)
                    replace(registry)
                    self.assertEqual(limits(registry, "t"), (7.0, 4096))
                    replace(registry, timeout=3.0)  # an explicit override of the replacement wins
                    self.assertEqual(limits(registry, "t")[0], 3.0)
        registry = ToolRegistry(default_timeout=7.0, max_output_bytes=4096)
        registry.register_isolated("t", "m:f", max_output_bytes=99)
        registry.register_isolated("t", "m:g", max_output_bytes=55)
        self.assertEqual(limits(registry, "t"), (7.0, 55))
        # A REFUSED replacement changes nothing.
        with self.assertRaises(ValueError):
            registry.register_isolated("t", "not-a-target", timeout=1.0)
        with self.assertRaises(SecurityError):
            registry.register("t", plain, side_effecting=True)
        self.assertEqual(limits(registry, "t"), (7.0, 55))

    def test_invoke_reasserts_side_effecting_contract_at_launch(self):  # G9 (CALIBRATED)
        with patch("portmark.tools._has_tree_termination_primitive", return_value=True):
            # (a) a side-effecting name with NO reconcile target (a stale flag the gate would never
            #     create) fails closed at the launch boundary, before any capability is consumed.
            reg = ToolRegistry(isolation_profile=self._profile())
            reg.register_isolated("iso.x", "m:f", env={})  # non-side-effecting -> no reconcile
            reg._side_effecting.add("iso.x")
            with self.assertRaisesRegex(SecurityError, "reconcile"):
                reg.invoke(self._permit("iso.x"), "iso.x", {}, launch_capability="whatever")
            # (b) reconcile present but the IsolationProfile was dropped after registration.
            reg2 = ToolRegistry(isolation_profile=self._profile())
            reg2.register_isolated("pay", "m:f", side_effecting=True, reconcile="m:r")
            reg2._isolation_profile = None
            with self.assertRaisesRegex(SecurityError, "IsolationProfile"):
                reg2.invoke(self._permit("pay"), "pay", {}, launch_capability="whatever")

    def test_non_side_effecting_isolated_tool_needs_no_profile_or_reconcile(self):  # G10
        registry = ToolRegistry()  # no profile acknowledged
        registry.register_isolated("iso.read", "m:f", env={})  # no reconcile, not side-effecting
        self.assertIn("iso.read", registry.names())
        self.assertFalse(registry.is_side_effecting("iso.read"))
        self.assertIsNone(registry.isolation_profile)

    def test_reconcile_target_must_be_distinct_from_the_tool(self):  # G16 (CALIBRATED)
        # A reconcile is observational; registering the effectful tool as its OWN reconcile target is
        # the auditor's exploit (a reconcile execution then fires the charge). Refused at registration.
        # Neutralize the `reconcile == target` check -> this registration is accepted.
        registry = ToolRegistry(isolation_profile=self._profile())
        with self.assertRaisesRegex(SecurityError, "DISTINCT function"):
            registry.register_isolated(
                "pay", "mytools:charge", side_effecting=True, reconcile="mytools:charge"
            )
        self.assertNotIn("pay", registry.names())
        # A distinct reconcile target is accepted (preflight patched out by setUp).
        registry.register_isolated("pay", "mytools:charge", side_effecting=True, reconcile="mytools:check")
        self.assertIn("pay", registry.names())


class ReconcileAuthorityAndSafetyTests(unittest.TestCase):
    """Section 7 PR 2b: the private reconcile authority (G15) and registration that imports nothing (G21).
    The authority test spawns a real worker, so it needs a process-tree termination primitive."""

    def _env(self):
        import portmark

        src_dir = os.path.dirname(os.path.dirname(os.path.abspath(portmark.__file__)))
        tests_dir = os.path.dirname(os.path.abspath(__file__))
        return {"PYTHONPATH": os.pathsep.join([src_dir, tests_dir])}

    @unittest.skipUnless(_has_tree_termination_primitive(), "reconcile preflight/authority spawn a worker")
    def test_public_reconcile_runner_is_gone_and_authority_validates_the_row(self):  # G15 (CALIBRATED)
        registry = ToolRegistry(isolation_profile=_TEST_ISOLATION_PROFILE)
        registry.register_isolated(
            "iso.charge", "isolated_tool_fixtures:idempotent_charge", side_effecting=True,
            reconcile="isolated_tool_fixtures:reconcile_charge", env=self._env(),
        )
        # The public reconcile RUNNER that let any registry holder execute a target is gone.
        self.assertFalse(hasattr(registry, "reconcile"))
        rows: dict[str, dict] = {}
        authority = registry.attach_effect_ledger(lambda eid: rows.get(eid))
        with tempfile.TemporaryDirectory() as directory:
            args = {"dir": directory, "amount": 5}  # reconcile_charge reads dir + amount
            canonical_args = canonical_json(args).decode("utf-8")
            # (a) fabricated effect_id -> no row -> refused (CALIBRATED: the row validation is what
            #     refuses; neutralize it and a caller-fabricated effect runs the target -- the exploit).
            with self.assertRaisesRegex(SecurityError, "reconciling"):
                authority.run_reconcile("fabricated", "iso.charge", args, "claim-1")
            # (b) row exists but not `reconciling` (never claimed) -> refused
            rows["e-1"] = {"state": "unknown", "reconcile_claim_id": "claim-1", "tool": "iso.charge", "arguments_json": canonical_args}
            with self.assertRaisesRegex(SecurityError, "reconciling"):
                authority.run_reconcile("e-1", "iso.charge", args, "claim-1")
            # (c) `reconciling` but a DIFFERENT owner claim -> refused (unguessable claim_id carries weight)
            rows["e-1"] = {"state": "reconciling", "reconcile_claim_id": "OTHER", "tool": "iso.charge", "arguments_json": canonical_args}
            with self.assertRaisesRegex(SecurityError, "reconciling"):
                authority.run_reconcile("e-1", "iso.charge", args, "claim-1")
            # (d) owned + `reconciling` but the arguments do not match the stored ones -> refused
            rows["e-1"] = {"state": "reconciling", "reconcile_claim_id": "claim-1", "tool": "iso.charge", "arguments_json": canonical_args}
            with self.assertRaisesRegex(SecurityError, "reconciling"):
                authority.run_reconcile("e-1", "iso.charge", {"dir": directory, "amount": 99}, "claim-1")
            # (e) a properly owned, matching `reconciling` row -> the target actually runs and returns its dict.
            outcome = authority.run_reconcile("e-1", "iso.charge", args, "claim-1")
            self.assertIn("landed", outcome)

    def test_registration_does_not_import_the_reconcile_module(self):  # G21 (CALIBRATED)
        # The auditor's round-3 repro, turned into a regression test: registering a side-effecting tool
        # whose reconcile target is a module that WRITES A MARKER at import time must NOT write the marker
        # -- registration executes no untrusted module-level code (module:function is a SYNTAX check only).
        # CALIBRATED: add any import of the reconcile module to register_isolated and the marker appears.
        with tempfile.TemporaryDirectory() as directory:
            marker = os.path.join(directory, "imported.marker")
            with patch.dict(os.environ, {"RECONCILE_IMPORT_MARKER": marker}):
                registry = ToolRegistry(isolation_profile=_TEST_ISOLATION_PROFILE)
                registry.register_isolated(
                    "iso.charge", "isolated_tool_fixtures:idempotent_charge", side_effecting=True,
                    reconcile="reconcile_import_marker:reconcile", env=self._env(),
                )
                self.assertIn("iso.charge", registry.names())  # registration succeeded
                self.assertFalse(
                    os.path.exists(marker),
                    "registration must NOT import the reconcile module (no unledgered code execution)",
                )


def _openat2_available_here() -> bool:
    # Decide openat2 usability by attempting it, once, at import (tests only). POSIX-gated so a
    # non-POSIX box never touches os.uname/openat2.
    if os.name != "posix":
        return False
    from portmark import safe_paths

    directory = tempfile.mkdtemp()
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return safe_paths._openat2_usable(descriptor)
    finally:
        os.close(descriptor)


HAS_OPENAT2 = _openat2_available_here()


def _openat2_gap(system: str, has_openat2: bool, environ) -> str | None:
    """Boundary audit RC-03: why a missing openat2 must FAIL here, or None when the skips are legitimate.

    The SafeRoot tests skip where openat2 is unusable. Off Linux that is correct. On Linux it is correct
    ONLY in an environment that declares it (PORTMARK_TEST_ENV_HAS_NO_OPENAT2=1), exactly like the Node
    declaration: otherwise a Linux runner that lost openat2 (an old kernel, a seccomp profile) would turn
    every capability test into a silent skip and CI would stay green.
    """
    if not system.startswith("linux") or has_openat2:
        return None
    if environ.get("PORTMARK_TEST_ENV_HAS_NO_OPENAT2") == "1":
        return None
    kernel = os.uname().release if hasattr(os, "uname") else "unknown kernel"
    return (
        f"openat2(RESOLVE_BENEATH) is not usable on this Linux ({kernel}), so the SafeRoot "
        "tests would skip. Fix the runner, or declare PORTMARK_TEST_ENV_HAS_NO_OPENAT2=1 on purpose."
    )


class Openat2SkipIsDeclaredOnlyTests(unittest.TestCase):
    def test_this_environment_runs_the_safe_root_tests_or_declares_why_not(self):
        self.assertIsNone(_openat2_gap(sys.platform, HAS_OPENAT2, os.environ))

    def test_a_linux_gap_fails_unless_the_environment_declares_it(self):
        for value in (None, "", "0", "true"):
            environ = {} if value is None else {"PORTMARK_TEST_ENV_HAS_NO_OPENAT2": value}
            with self.subTest(flag=value):
                self.assertIsNotNone(_openat2_gap("linux", False, environ))
        self.assertIsNone(_openat2_gap("linux", False, {"PORTMARK_TEST_ENV_HAS_NO_OPENAT2": "1"}))
        # Where openat2 works, or off Linux, the flag changes nothing: nothing to explain.
        self.assertIsNone(_openat2_gap("linux", True, {}))
        for system in ("win32", "darwin"):
            self.assertIsNone(_openat2_gap(system, False, {}))


class SafePathCapabilityTests(unittest.TestCase):
    """Section 7 PR 3: the capability-based safe-path helper. Unit tests exercise SafeRoot directly;
    end-to-end tests drive it through a real isolated worker that inherits the runtime-provided root
    descriptor. openat2(RESOLVE_BENEATH) is Linux>=5.6 only, so those tests skip where it is absent."""

    def _env(self):
        import portmark

        src_dir = os.path.dirname(os.path.dirname(os.path.abspath(portmark.__file__)))
        tests_dir = os.path.dirname(os.path.abspath(__file__))
        return {"PYTHONPATH": os.pathsep.join([src_dir, tests_dir])}

    def _permit(self, *names):
        return Permit(
            issuer="issuer", subject="agent", audience="host",
            expires_at=int(time.time()) + 60, nonce="nonce-sp",
            grants=tuple(ToolGrant(name) for name in names),
        )

    def _root_under(self, directory):
        # Build a SafeRoot around a dir descriptor and register its close as cleanup, so a mid-test
        # assertion failure never leaks the descriptor (no ResourceWarning).
        from portmark import safe_paths

        root = safe_paths.SafeRoot(os.open(directory, os.O_RDONLY | os.O_DIRECTORY))
        self.addCleanup(root.close)
        return root

    # ---- unit: capability shape ------------------------------------------------------------------

    def test_from_runtime_is_the_only_constructor_and_refuses_without_a_root_fd(self):  # G1 + G2
        from portmark import safe_paths

        # No public PATH-taking constructor -- a tool cannot choose its own root. from_runtime() is
        # the only way in.
        self.assertTrue(hasattr(safe_paths.SafeRoot, "from_runtime"))
        self.assertFalse(hasattr(safe_paths.SafeRoot, "from_path"))
        self.assertFalse(hasattr(safe_paths.SafeRoot, "open"))
        # No runtime root descriptor -> refuse (no ambient filesystem authority).
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(safe_paths.ROOT_FD_ENV, None)
            with self.assertRaises(safe_paths.SafePathUnavailable):
                safe_paths.SafeRoot.from_runtime()

    @unittest.skipUnless(HAS_OPENAT2, "openat2(RESOLVE_BENEATH) not usable here")
    def test_from_runtime_adopts_the_inherited_fd_and_closes_the_raw_one(self):  # G1 + G9 (unit)
        from portmark import safe_paths

        directory = tempfile.mkdtemp()
        raw = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        os.set_inheritable(raw, True)
        with patch.dict(os.environ, {safe_paths.ROOT_FD_ENV: str(raw)}):
            root = safe_paths.SafeRoot.from_runtime()
        self.addCleanup(root.close)
        # The raw inherited descriptor is closed (from_runtime re-opened its own copy).
        with self.assertRaises(OSError):
            os.fstat(raw)
        # The owned descriptor is close-on-exec, so a spawned process does not inherit it.
        self.assertFalse(os.get_inheritable(root._dirfd))
        with root.open_beneath("f", "w") as handle:
            handle.write("ok")

    @unittest.skipUnless(HAS_OPENAT2, "openat2(RESOLVE_BENEATH) not usable here")
    def test_open_beneath_reads_and_writes_a_file_under_the_root(self):  # G3
        directory = tempfile.mkdtemp()
        root = self._root_under(directory)
        with root.open_beneath("sub_created_by_tool.txt", "w") as handle:
            handle.write("payload")
        # The write really landed on disk beneath the root.
        with open(os.path.join(directory, "sub_created_by_tool.txt")) as landed:
            self.assertEqual(landed.read(), "payload")
        with root.open_beneath("sub_created_by_tool.txt", "r") as handle:
            self.assertEqual(handle.read(), "payload")

    @unittest.skipUnless(HAS_OPENAT2, "openat2(RESOLVE_BENEATH) not usable here")
    def test_open_beneath_refuses_escape_and_the_resolve_flags_are_load_bearing(self):  # G4 + G5 (CALIBRATED)
        from portmark import safe_paths

        directory = tempfile.mkdtemp()
        os.mkdir(os.path.join(directory, "sub"))
        os.symlink("/etc/passwd", os.path.join(directory, "link"))
        root = self._root_under(directory)
        # Absolute path and empty path are refused before any syscall.
        with self.assertRaises(safe_paths.SafePathEscape):
            root.open_beneath("/etc/passwd", "r")
        with self.assertRaises(safe_paths.SafePathEscape):
            root.open_beneath("", "r")
        # `..` escape via a real directory, and a symlink out, are refused by the kernel.
        for escaping in ("../escape", "sub/../../x", ".."):
            with self.assertRaises(safe_paths.SafePathEscape):
                root.open_beneath(escaping, "r")
        with self.assertRaises(safe_paths.SafePathEscape):
            root.open_beneath("link", "r")
        # CALIBRATION: the RESOLVE_BENEATH|NO_SYMLINKS flags are what refuse. Neutralize them (0) and
        # the identical symlink now resolves out of the root -- proving the flags carry the guarantee.
        with patch.object(safe_paths, "_SAFE_RESOLVE", 0):
            with root.open_beneath("link", "r") as leaked:
                self.assertIn("root:", leaked.read(4096))  # /etc/passwd content leaked through

    @unittest.skipUnless(HAS_OPENAT2, "openat2(RESOLVE_BENEATH) not usable here")
    def test_openat2_usability_is_decided_by_the_syscall_not_the_version(self):  # G6 (CALIBRATED)
        from portmark import safe_paths

        directory = tempfile.mkdtemp()
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.assertTrue(safe_paths._openat2_usable(descriptor))
            # CALIBRATION: usability is proven by ATTEMPTING the syscall. Point the syscall at a
            # bogus number (as an unknown-arch/blocked kernel would surface via errno) and the SAME
            # probe reports unusable -- no version string is consulted.
            with patch.object(safe_paths, "_syscall_number", lambda: 0xDEAD):
                self.assertFalse(safe_paths._openat2_usable(descriptor))
        finally:
            os.close(descriptor)

    @unittest.skipUnless(os.name == "posix", "opens a directory fd (O_DIRECTORY) -- POSIX only")
    def test_import_touches_no_libc_or_filesystem(self):  # G8 (CALIBRATED)
        import importlib

        from portmark import safe_paths

        boom = lambda *a, **k: (_ for _ in ()).throw(AssertionError("import loaded libc"))  # noqa: E731
        with patch("ctypes.CDLL", boom):
            importlib.reload(safe_paths)  # succeeds: importing the module loads no C library
            # CALIBRATION: the tripwire is armed -- code that DOES load libc raises under this patch,
            # so the reload's success proves import itself performed no such call.
            directory = tempfile.mkdtemp()
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(AssertionError):
                    safe_paths._openat2_usable(descriptor)
            finally:
                os.close(descriptor)
        importlib.reload(safe_paths)  # restore the real module for other tests

    @unittest.skipUnless(os.name == "posix", "opens a directory fd (O_DIRECTORY) -- POSIX only")
    def test_from_runtime_refuses_when_openat2_is_unusable(self):  # G7 + G11
        from portmark import safe_paths

        directory = tempfile.mkdtemp()
        raw = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        os.set_inheritable(raw, True)
        # Simulate a platform/kernel/seccomp where openat2 is not usable: from_runtime REFUSES rather
        # than degrade to a race-vulnerable check.
        with patch.object(safe_paths, "_openat2_usable", lambda fd: False):
            with patch.dict(os.environ, {safe_paths.ROOT_FD_ENV: str(raw)}):
                with self.assertRaises(safe_paths.SafePathUnavailable):
                    safe_paths.SafeRoot.from_runtime()
        # from_runtime closed the raw inherited descriptor itself; do not double-close it here.

    # ---- end-to-end through a real isolated worker ----------------------------------------------

    @unittest.skipUnless(HAS_OPENAT2 and _CAN_KILL_PROCESS_GROUP, "needs POSIX worker + openat2")
    def test_isolated_tool_reaches_the_runtime_root_and_writes_beneath_it(self):  # G9 (e2e)
        with tempfile.TemporaryDirectory() as directory:
            registry = ToolRegistry(filesystem_root=directory)
            registry.register_isolated(
                "iso.safe", "isolated_tool_fixtures:safe_write_read", env=self._env()
            )
            result = registry.invoke(self._permit("iso.safe"), "iso.safe", {"name": "note.txt", "content": "hi-from-tool"})
            self.assertEqual(result["read_back"], "hi-from-tool")
            self.assertEqual(result["mechanism"], "openat2")
            # The tool wrote through the inherited descriptor, so the file exists on the host side.
            with open(os.path.join(directory, "note.txt")) as landed:
                self.assertEqual(landed.read(), "hi-from-tool")

    @unittest.skipUnless(HAS_OPENAT2 and _CAN_KILL_PROCESS_GROUP, "needs POSIX worker + openat2")
    def test_isolated_tool_escape_is_refused_inside_the_worker(self):  # G4 (e2e)
        with tempfile.TemporaryDirectory() as directory:
            os.symlink("/etc/passwd", os.path.join(directory, "link"))
            registry = ToolRegistry(filesystem_root=directory)
            registry.register_isolated(
                "iso.esc", "isolated_tool_fixtures:safe_escape_attempt", env=self._env()
            )
            permit = self._permit("iso.esc")
            for escaping in ("../escape", "link"):
                self.assertEqual(
                    registry.invoke(permit, "iso.esc", {"path": escaping}), {"refused": True}
                )

    @unittest.skipUnless(_CAN_KILL_PROCESS_GROUP, "needs a POSIX worker")
    def test_no_filesystem_root_means_no_ambient_authority(self):  # G10
        # No filesystem_root configured -> the worker inherits no root fd -> from_runtime() refuses.
        registry = ToolRegistry()
        registry.register_isolated(
            "iso.noroot", "isolated_tool_fixtures:safe_no_root_probe", env=self._env()
        )
        self.assertEqual(
            registry.invoke(self._permit("iso.noroot"), "iso.noroot", {}), {"refused": True}
        )

    @unittest.skipUnless(HAS_OPENAT2 and _CAN_KILL_PROCESS_GROUP, "needs POSIX worker + openat2")
    def test_spawned_grandchild_does_not_inherit_the_root_descriptor(self):  # G9 (grandchild)
        with tempfile.TemporaryDirectory() as directory:
            registry = ToolRegistry(filesystem_root=directory)
            registry.register_isolated(
                "iso.gc", "isolated_tool_fixtures:safe_grandchild_cannot_inherit", env=self._env()
            )
            result = registry.invoke(self._permit("iso.gc"), "iso.gc", {})
            # The grandchild could not fstat the root descriptor number: it was closed/close-on-exec.
            self.assertEqual(result["grandchild"], "EBADF")

    @unittest.skipUnless(HAS_OPENAT2 and _CAN_KILL_PROCESS_GROUP, "needs POSIX worker + openat2")
    def test_root_fd_does_not_leak_to_a_child_spawned_before_from_runtime(self):  # G9 (worker hardening)
        # Even a tool that spawns a child WITHOUT calling from_runtime must not leak the root fd: the
        # worker sets it close-on-exec at startup. Without that, pass_fds leaves it inheritable.
        with tempfile.TemporaryDirectory() as directory:
            registry = ToolRegistry(filesystem_root=directory)
            registry.register_isolated(
                "iso.leak", "isolated_tool_fixtures:safe_spawn_without_from_runtime", env=self._env()
            )
            result = registry.invoke(self._permit("iso.leak"), "iso.leak", {})
            self.assertEqual(result["grandchild"], "EBADF")

    # ---- descriptor lifecycle (auditor round 1, finding 1) --------------------------------------

    @unittest.skipUnless(HAS_OPENAT2, "openat2(RESOLVE_BENEATH) not usable here")
    def test_from_runtime_is_one_shot_and_a_reused_fd_cannot_retarget_it(self):  # G19 (CALIBRATED)
        from portmark import safe_paths

        first = tempfile.mkdtemp()
        second = tempfile.mkdtemp()
        with open(os.path.join(second, "SECOND"), "w"):
            pass
        raw = os.open(first, os.O_RDONLY | os.O_DIRECTORY)
        os.set_inheritable(raw, True)
        with patch.dict(os.environ, {safe_paths.ROOT_FD_ENV: str(raw)}):
            root = safe_paths.SafeRoot.from_runtime()  # consumes env (pop) and closes `raw`
            self.addCleanup(root.close)
            # The env var was consumed, and the kernel reuses the closed descriptor number for `second`.
            self.assertIsNone(os.environ.get(safe_paths.ROOT_FD_ENV))
            reused = os.open(second, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, reused)
            self.assertEqual(reused, raw)  # same descriptor number, different directory
            # CALIBRATION (auditor repro): a second from_runtime() must REFUSE, not adopt the reused
            # descriptor. Before the pop fix it read the stale env fd and opened `second`.
            with self.assertRaises(safe_paths.SafePathUnavailable):
                safe_paths.SafeRoot.from_runtime()

    @unittest.skipUnless(HAS_OPENAT2, "openat2(RESOLVE_BENEATH) not usable here")
    def test_closed_safe_root_refuses_even_after_fd_reuse(self):  # G19 (CALIBRATED)
        from portmark import safe_paths

        first = tempfile.mkdtemp()
        second = tempfile.mkdtemp()
        with open(os.path.join(second, "SECOND"), "w"):
            pass
        root = safe_paths.SafeRoot(os.open(first, os.O_RDONLY | os.O_DIRECTORY))
        with root.open_beneath("ok", "w") as handle:
            handle.write("x")
        closed_fd = root._dirfd
        root.close()
        reused = os.open(second, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, reused)
        self.assertEqual(reused, closed_fd)  # the closed number now names `second`
        # CALIBRATION (auditor repro): the closed SafeRoot must refuse, not open into `second`.
        # Before close() nulled _dirfd, open_beneath used the reused descriptor and read `second`.
        with self.assertRaises(safe_paths.SafePathError):
            root.open_beneath("SECOND", "r")

    # ---- filesystem_root identity pinning (auditor round 1, finding 3) --------------------------

    @unittest.skipUnless(HAS_OPENAT2 and _CAN_KILL_PROCESS_GROUP, "needs POSIX worker + openat2")
    def test_filesystem_root_identity_is_pinned_against_a_swap(self):  # G21 (CALIBRATED)
        from portmark.tools import ToolExecutionError

        original = tempfile.mkdtemp()
        replacement = tempfile.mkdtemp()
        root_path = os.path.join(tempfile.mkdtemp(), "root")
        os.symlink(original, root_path)  # registry records `original`'s identity at construction
        registry = ToolRegistry(filesystem_root=root_path)
        registry.register_isolated(
            "iso.pin", "isolated_tool_fixtures:safe_write_read", env=self._env()
        )
        permit = self._permit("iso.pin")
        # Swap the configured path to point at a DIFFERENT directory after construction.
        os.unlink(root_path)
        os.symlink(replacement, root_path)
        # The launch fstats the descriptor and sees a different (st_dev, st_ino) -> refuses.
        with self.assertRaisesRegex(ToolExecutionError, "identity changed"):
            registry.invoke(permit, "iso.pin", {"name": "note.txt", "content": "hi"})
        # CALIBRATION: neutralize the pin (record the post-swap identity) and the SAME swapped invoke
        # now runs against the replacement directory -- proving the identity check is what refuses.
        swapped_stat = os.stat(root_path)
        registry._filesystem_root_identity = (swapped_stat.st_dev, swapped_stat.st_ino)
        result = registry.invoke(permit, "iso.pin", {"name": "note.txt", "content": "hi"})
        self.assertEqual(result["read_back"], "hi")
        with open(os.path.join(replacement, "note.txt")) as landed:  # it really wrote into `replacement`
            self.assertEqual(landed.read(), "hi")


def _docker_available() -> bool:
    import shutil

    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(  # nosec B603 B607
            ["docker", "info"], capture_output=True, timeout=30
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


_PROFILE_IMAGE = os.environ.get("PORTMARK_TEST_IMAGE")
_RUN_PROFILE_TESTS = bool(_PROFILE_IMAGE) and _docker_available()


class DeploymentProfileTests(unittest.TestCase):
    """Section 7 PR 3: the hardened container profile is executable and TESTED. Each property is
    probed inside the running container by attempting the operation it governs (deploy/verify_profile.py),
    and each is CALIBRATED: removing its one flag must flip that property off. Runs only when a built
    image tag is provided (PORTMARK_TEST_IMAGE) and docker is usable -- CI sets both after the build."""

    # The full hardened flag set (mirrors deploy/README.md and deploy/docker-compose.hardened.yml).
    BASE_FLAGS = [
        "--rm",
        "--read-only",
        "--tmpfs", "/work:rw,noexec,nosuid,nodev,size=64m",
        "--env", "PORTMARK_WORKDIR=/work",
        "--user", "1000:1000",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "128",
        "--memory", "512m",
        "--cpus", "1.0",
        "--network", "none",
    ]

    def _probe(self, flags):
        result = subprocess.run(  # nosec B603 B607
            ["docker", "run", *flags, _PROFILE_IMAGE, "python", "/app/deploy/verify_profile.py"],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, f"docker run failed: {result.stderr.strip()}")
        return json.loads(result.stdout.strip().splitlines()[-1])

    @unittest.skipUnless(_RUN_PROFILE_TESTS, "needs docker + PORTMARK_TEST_IMAGE (built image tag)")
    def test_hardened_profile_every_property_holds(self):  # G13 + G15 (present)
        report = self._probe(self.BASE_FLAGS)
        for prop, held in report.items():
            self.assertTrue(held, f"hardened profile property not enforced: {prop} ({report})")

    @unittest.skipUnless(_RUN_PROFILE_TESTS, "needs docker + PORTMARK_TEST_IMAGE (built image tag)")
    def test_each_property_is_calibrated_by_removing_its_flag(self):  # G15 (CALIBRATED)
        # For each property, drop/override exactly the flag that enforces it and assert THAT property
        # flips off -- so a passing full-profile run proves enforcement, not a decorative check.
        def without(*tokens):
            flags = list(self.BASE_FLAGS)
            for token in tokens:
                flags.remove(token)
            return flags

        # read-only rootfs: without --read-only the app root becomes writable.
        self.assertFalse(self._probe(without("--read-only"))["readonly_rootfs"])
        # private writable dir: without the tmpfs mount (root stays read-only) /work is not writable.
        self.assertFalse(
            self._probe(without("--tmpfs", "/work:rw,noexec,nosuid,nodev,size=64m"))["private_writable_dir"]
        )
        # non-root: override the user to root (0:0). The image's default user is already non-root, so
        # merely dropping --user would not flip it -- forcing root is the honest calibration.
        root_flags = list(self.BASE_FLAGS)
        root_flags[root_flags.index("1000:1000")] = "0:0"
        self.assertFalse(self._probe(root_flags)["non_root"])
        # no-new-privileges: without the security-opt the bit is clear.
        self.assertFalse(self._probe(without("--security-opt", "no-new-privileges"))["no_new_privileges"])
        # dropped capabilities: without --cap-drop ALL the bounding set is non-empty.
        self.assertFalse(self._probe(without("--cap-drop", "ALL"))["dropped_capabilities"])
        # pids limit: without --pids-limit the cgroup pids.max is "max".
        self.assertFalse(self._probe(without("--pids-limit", "128"))["pids_limited"])
        # memory limit: without --memory the cgroup memory.max is "max".
        self.assertFalse(self._probe(without("--memory", "512m"))["memory_limited"])
        # cpu limit: without --cpus the cgroup cpu.max quota is "max".
        self.assertFalse(self._probe(without("--cpus", "1.0"))["cpu_limited"])
        # egress: without --network none a non-loopback interface (eth0) appears.
        self.assertFalse(self._probe(without("--network", "none"))["egress_denied"])

    @unittest.skipUnless(_RUN_PROFILE_TESTS, "needs docker + PORTMARK_TEST_IMAGE (built image tag)")
    def test_resource_ceilings_reject_weak_but_set_limits(self):  # G20 (CALIBRATED, ceilings)
        # Finiteness is not a bound: a regression from 512m/1.0 to 16g/8.0 leaves memory.max/cpu.max
        # finite but far above the advertised ceilings. The probe must reject them.
        def replace(old, new):
            flags = list(self.BASE_FLAGS)
            flags[flags.index(old)] = new
            return flags

        report = self._probe(replace("512m", "16g"))
        self.assertFalse(report["memory_limited"], f"16g must exceed the 512 MiB ceiling ({report})")
        # 2.0 (not 8.0) so the flag is accepted on a small CI runner -- docker rejects --cpus above the
        # host's CPU count (a 4-CPU runner caps at 4.00). 2.0 still exceeds the 1.0 ceiling.
        report = self._probe(replace("1.0", "2.0"))
        self.assertFalse(report["cpu_limited"], f"2.0 CPUs must exceed the 1.0 ceiling ({report})")

    @unittest.skipUnless(_RUN_PROFILE_TESTS, "needs docker + PORTMARK_TEST_IMAGE (built image tag)")
    def test_openat2_is_not_blocked_inside_the_hardened_image(self):  # G14
        # The safe-path helper needs openat2; a seccomp profile could block it. Prove the hardened
        # image's default seccomp ALLOWS openat2 by running the usability probe INSIDE the container.
        result = subprocess.run(  # nosec B603 B607
            ["docker", "run", *self.BASE_FLAGS, _PROFILE_IMAGE, "python", "-c",
             "import os;from portmark import safe_paths as s;"
             # Use the private writable dir: the read-only rootfs has no usable temp directory.
             "fd=os.open('/work',os.O_RDONLY|os.O_DIRECTORY);"
             "print('USABLE' if s._openat2_usable(fd) else 'BLOCKED')"],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, f"docker run failed: {result.stderr.strip()}")
        self.assertEqual(result.stdout.strip().splitlines()[-1], "USABLE")


class HttpProviderTransportTests(unittest.TestCase):
    """Section 8 PR 1: SSRF/redirect/DNS-rebind + total-deadline hardening of GenericHttpProvider.
    Address checks unit-test _validated_target with an injected resolver; the transport behaviors
    (redirect, slow-drip, premature EOF, bounded read) run against a real loopback server."""

    # ---- address validation (findings 1) --------------------------------------------------------

    def test_construction_rejects_credentials_fragment_and_bad_host(self):  # G3 (CALIBRATED)
        for bad in (
            "https://user:pass@provider.example/run",   # credentials
            "https://provider.example/run#frag",         # fragment
            "ftp://provider.example/run",                # scheme
            "https:///run",                              # missing host
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    GenericHttpProvider(bad)
        # CALIBRATION: a clean https URL with none of those is accepted.
        GenericHttpProvider("https://provider.example/run")

    def test_validated_target_rejects_internal_addresses(self):  # G4 (CALIBRATED)
        cases = {
            "loopback": "127.0.0.1",
            "private": "10.0.0.5",
            "link_local": "169.254.169.254",   # cloud metadata
            "multicast": "224.0.0.1",
            "unspecified": "0.0.0.0",           # nosec B104
        }
        for label, ip in cases.items():
            with self.subTest(label=label):
                provider = GenericHttpProvider("https://provider.example/run")
                with patch.object(provider, "_resolve", return_value=[(socket.AF_INET, ip)]):
                    with self.assertRaisesRegex(ProviderError, "not permitted"):
                        provider._validated_target()
        # Mixed answer: one public + one loopback must fail closed on the loopback one.
        provider = GenericHttpProvider("https://provider.example/run")
        with patch.object(provider, "_resolve", return_value=[(socket.AF_INET, "93.184.216.34"), (socket.AF_INET, "127.0.0.1")]):
            with self.assertRaisesRegex(ProviderError, "not permitted"):
                provider._validated_target()
        # CALIBRATION: a purely public answer is accepted.
        provider = GenericHttpProvider("https://provider.example/run")
        with patch.object(provider, "_resolve", return_value=[(socket.AF_INET, "93.184.216.34")]):
            self.assertEqual(provider._validated_target(), (socket.AF_INET, "93.184.216.34"))

    def test_ipv4_mapped_ipv6_is_normalized_before_classification(self):  # G5 (CALIBRATED)
        provider = GenericHttpProvider("https://provider.example/run")
        with patch.object(provider, "_resolve", return_value=[(socket.AF_INET6, "::ffff:127.0.0.1")]):
            with self.assertRaisesRegex(ProviderError, "not permitted"):
                provider._validated_target()

    def test_https_required_for_non_loopback(self):  # G7 (CALIBRATED)
        provider = GenericHttpProvider("http://provider.example/run")
        with patch.object(provider, "_resolve", return_value=[(socket.AF_INET, "93.184.216.34")]):
            with self.assertRaisesRegex(ProviderError, "https"):
                provider._validated_target()
        # CALIBRATION: loopback + allow_local_endpoint permits plain http.
        local = GenericHttpProvider("http://127.0.0.1/run", allow_local_endpoint=True)
        self.assertEqual(local._validated_target(), (socket.AF_INET, "127.0.0.1"))

    def test_dns_rebinding_peer_mismatch_is_refused(self):  # G6
        class _FakeSock:
            def getpeername(self):
                return ("8.8.8.8", 0)   # a DIFFERENT address than the validated one
            def settimeout(self, _t):
                pass
        class _FakeConn:
            sock = _FakeSock()
            def close(self):
                pass
        provider = GenericHttpProvider("https://provider.example/run")
        with patch.object(provider, "_resolve", return_value=[(socket.AF_INET, "93.184.216.34")]):
            with patch.object(provider, "_open_connection", return_value=_FakeConn()):
                with self.assertRaisesRegex(ProviderError, "does not match"):
                    provider._post(b"{}")

    # ---- transport against a real loopback server -----------------------------------------------

    def _provider(self, url, **kwargs):
        return GenericHttpProvider(url, allow_local_endpoint=True, **kwargs)

    def test_valid_loopback_response_is_decoded(self):  # G13
        with local_provider_server(_respond_json(b'{"kind":"complete","content":{"ok":true}}')) as (server, url):
            decision = self._provider(url).decide(provider_view(AgentState("task", "goal")), ())
        self.assertEqual(decision.kind, "complete")
        self.assertEqual(server.last_body and json.loads(server.last_body)["available_tools"], [])

    def test_redirect_is_not_followed(self):  # G1 + G2 (CALIBRATED)
        def redirect(handler):
            handler.send_response(302)
            handler.send_header("Location", "http://127.0.0.1:9/evil")
            handler.end_headers()
        with local_provider_server(redirect) as (server, url):
            provider = self._provider(url, bearer_token="SECRET")  # nosec B106 -- test bearer literal
            with self.assertRaisesRegex(ProviderError, "redirect"):
                provider.decide(provider_view(AgentState("task", "goal")), ())
            # The bearer reached only the configured origin; there is no second request to a new origin.
            self.assertEqual(server.last_authorization, "Bearer SECRET")

    def test_total_deadline_aborts_a_slow_drip(self):  # G9 (CALIBRATED)
        def slow_drip(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", "100")
            handler.end_headers()
            for _ in range(100):  # one byte at a time, ~3s total -- far past the 0.3s deadline
                try:
                    handler.wfile.write(b" ")
                    handler.wfile.flush()
                except OSError:
                    return
                time.sleep(0.03)
        with local_provider_server(slow_drip) as (_server, url):
            provider = self._provider(url, timeout=0.3)
            started = time.monotonic()
            with self.assertRaises(ProviderError):
                provider.decide(provider_view(AgentState("task", "goal")), ())
            self.assertLess(time.monotonic() - started, 2.0)  # aborted on the deadline, not after the full drip

    def test_premature_eof_is_a_controlled_failure(self):  # G10
        def truncated(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", "1000")   # promises 1000, sends 5 then closes
            handler.end_headers()
            handler.wfile.write(b"{\"k\":")
            handler.close_connection = True
        with local_provider_server(truncated) as (_server, url):
            with self.assertRaises(ProviderError):
                self._provider(url).decide(provider_view(AgentState("task", "goal")), ())

    def test_response_body_is_bounded(self):  # G11 (CALIBRATED)
        with local_provider_server(_respond_json(b"x" * 200)) as (_server, url):
            with self.assertRaisesRegex(SecurityError, "exceeds output limit"):
                self._provider(url, max_response_bytes=64).decide(provider_view(AgentState("task", "goal")), ())

    def test_provider_failure_persists_a_durable_failed_checkpoint(self):  # G12 (CALIBRATED)
        def truncated(handler):
            handler.send_response(200)
            handler.send_header("Content-Length", "1000")
            handler.end_headers()
            handler.wfile.write(b"{")
            handler.close_connection = True
        with local_provider_server(truncated) as (_server, url):
            host = make_host(provider_endpoint="https://provider.example/run")
            host.providers["http"] = self._provider(url)
            envelope = make_demo_envelope(host, "portable agents", "http")
            with self.assertRaises(ProviderError):
                host.run(envelope)
            # The admitted task must NOT be left as `running`: the durable row is terminal `failed`.
            stored = host.store.load_checkpoint(envelope.state.task_id)
            self.assertIsNotNone(stored)
            self.assertEqual(stored["status"], "failed")

    # ---- round 1 findings ------------------------------------------------------------------------

    def test_dns_resolution_is_bounded_by_the_deadline(self):  # G16 (CALIBRATED)
        # DNS runs inside the transaction, which is bounded by the external watchdog deadline in _post.
        provider = GenericHttpProvider("https://slow.example/run", timeout=0.2)
        real = socket.getaddrinfo

        def slow_getaddrinfo(*args, **kwargs):
            time.sleep(1.5)  # far past the 0.2s deadline
            return real(*args, **kwargs)

        with patch("socket.getaddrinfo", side_effect=slow_getaddrinfo):
            started = time.monotonic()
            with self.assertRaisesRegex(ProviderError, "exceeded the deadline"):
                provider.decide(provider_view(AgentState("task", "goal")), ())
            # Bounded near the deadline, NOT held for the full blocking resolve (calibration: without the
            # external deadline the caller would return only after ~1.5s).
            self.assertLess(time.monotonic() - started, 1.0)

    def test_arm_deadline_rearms_the_socket_to_the_remaining_budget(self):  # G17 (CALIBRATED)
        class _RecordingSock:
            def __init__(self):
                self.timeouts = []
            def settimeout(self, value):
                self.timeouts.append(value)

        provider = GenericHttpProvider("https://provider.example/run", timeout=5.0)
        sock = _RecordingSock()
        deadline = time.monotonic() + 0.5
        provider._arm_deadline(sock, deadline)
        first = sock.timeouts[-1]
        time.sleep(0.05)
        provider._arm_deadline(sock, deadline)
        second = sock.timeouts[-1]
        # The socket timeout is re-armed to the REMAINING deadline each time, so it strictly decreases
        # as time is spent -- an earlier phase's time cannot be re-spent in a later one.
        self.assertLess(second, first)
        self.assertLessEqual(first, 0.5)
        # Past the deadline it fails closed rather than arming a non-positive timeout.
        with self.assertRaisesRegex(ProviderError, "deadline exceeded"):
            provider._arm_deadline(sock, time.monotonic() - 0.01)

    # ---- round 2: slow response headers must not bypass the total deadline ----------------------

    def test_slow_dripped_response_headers_cannot_bypass_the_deadline(self):  # G22 (CALIBRATED)
        # getresponse() reads many times parsing the status line + headers; a socket idle timeout
        # resets on each dribbled byte, so only the external transaction deadline can bound it.
        def drip_headers(handler):
            raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
            for byte in raw:
                try:
                    handler.wfile.write(bytes([byte]))
                    handler.wfile.flush()
                except OSError:
                    return
                time.sleep(0.03)  # ~2s total for the header block, far past the 0.2s deadline
        with local_provider_server(drip_headers) as (_server, url):
            provider = self._provider(url, timeout=0.2)
            started = time.monotonic()
            with self.assertRaises(ProviderError):
                provider.decide(provider_view(AgentState("task", "goal")), ())
            # The CALLER returns at ~the deadline, not after the full header drip (calibration: without
            # the external watchdog the per-phase arm alone lets this run to ~1s+).
            self.assertLess(time.monotonic() - started, 1.0)

    def test_worker_capacity_recovers_after_a_deadline_timeout(self):  # G23
        # After a timed-out transaction, the caller is freed immediately and a subsequent request to a
        # responsive endpoint succeeds -- the abandoned thread's slot is released when its socket read
        # is unblocked by the connection close.
        def drip_headers(handler):
            raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
            for byte in raw:
                try:
                    handler.wfile.write(bytes([byte]))
                    handler.wfile.flush()
                except OSError:
                    return
                time.sleep(0.05)
        with local_provider_server(drip_headers) as (_slow, slow_url):
            with self.assertRaises(ProviderError):
                self._provider(slow_url, timeout=0.2).decide(provider_view(AgentState("task", "goal")), ())
        with local_provider_server(_respond_json(b'{"kind":"complete","content":{"ok":true}}')) as (_fast, fast_url):
            decision = self._provider(fast_url, timeout=2.0).decide(provider_view(AgentState("task", "goal")), ())
        self.assertEqual(decision.kind, "complete")

    def test_healthy_concurrent_calls_are_not_refused_by_the_transaction_pool(self):  # G26
        # The pool bounds LEAKS, not healthy concurrency: many simultaneous healthy calls (far above the
        # A2A default concurrency of 32) all succeed because they complete fast and recycle their slot.
        with local_provider_server(_respond_json(b'{"kind":"complete","content":{"ok":true}}')) as (_server, url):
            provider = self._provider(url, timeout=5.0)

            def call(_i):
                return provider.decide(provider_view(AgentState("task", "goal")), ()).kind

            with concurrent.futures.ThreadPoolExecutor(max_workers=48) as pool:
                results = list(pool.map(call, range(48)))
        self.assertEqual(results, ["complete"] * 48)

    def test_pool_wait_and_worker_share_one_absolute_deadline(self):  # G27 (CALIBRATED)
        # The slot wait and the worker join must draw from ONE absolute deadline: time spent waiting for
        # a slot must not be re-spent in the join, or a contended call takes up to twice its timeout.
        import portmark.providers as providers_module

        def drip(handler):
            # Dribble header bytes forever: the per-phase socket arm resets on each byte, so ONLY the
            # join bounds the worker -- which is where the acquire/join double-spend would show.
            raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
            for byte in raw:
                try:
                    handler.wfile.write(bytes([byte]))
                    handler.wfile.flush()
                except OSError:
                    return
                time.sleep(0.05)

        real_acquire = providers_module._TRANSACTION_SLOTS.acquire

        def slow_acquire(*_args, **_kwargs):
            time.sleep(0.3)  # consume most of the 0.4s budget waiting for a slot
            return real_acquire(blocking=False)  # actually take a slot so the worker's release balances

        with local_provider_server(drip) as (_server, url):
            provider = self._provider(url, timeout=0.4)
            with patch.object(providers_module._TRANSACTION_SLOTS, "acquire", side_effect=slow_acquire):
                started = time.monotonic()
                with self.assertRaises(ProviderError):
                    provider.decide(provider_view(AgentState("task", "goal")), ())
                elapsed = time.monotonic() - started
        # ~one deadline (0.4), NOT acquire(0.3) + a fresh join(0.4) = 0.7 (calibration: the pre-fix code
        # passes self.timeout to the join and lands near 0.7).
        self.assertLess(elapsed, 0.6)

    def test_ipv6_host_header_is_bracketed(self):  # G19
        self.assertEqual(GenericHttpProvider("https://[::1]/run", allow_local_endpoint=True)._host_header, "[::1]")
        self.assertEqual(GenericHttpProvider("http://[::1]:8080/run", allow_local_endpoint=True)._host_header, "[::1]:8080")
        # IPv4 / hostnames are unchanged.
        self.assertEqual(GenericHttpProvider("https://provider.example/run")._host_header, "provider.example")

    def test_allow_local_provider_endpoint_is_wired_through_factory(self):  # G18
        from portmark.config import RuntimeConfig

        # Via the factory argument.
        host = make_host(provider_endpoint="http://127.0.0.1:9/run", allow_local_provider_endpoint=True)
        self.assertTrue(host.providers["http"]._allow_local)
        # Via the environment variable.
        with patch.dict(os.environ, {"PORTMARK_ALLOW_LOCAL_PROVIDER_ENDPOINT": "true"}):
            host = make_host(provider_endpoint="http://127.0.0.1:9/run")
            self.assertTrue(host.providers["http"]._allow_local)
        # Default is off, and the flag permits LOOPBACK only -- a private address is still rejected.
        host = make_host(provider_endpoint="http://127.0.0.1:9/run")
        self.assertFalse(host.providers["http"]._allow_local)
        self.assertTrue(RuntimeConfig.from_environment().allow_local_provider_endpoint in (True, False))
        local = GenericHttpProvider("http://10.0.0.5/run", allow_local_endpoint=True)
        with patch.object(local, "_resolve", return_value=[(socket.AF_INET, "10.0.0.5")]):
            with self.assertRaisesRegex(ProviderError, "not permitted"):
                local._validated_target()


if __name__ == "__main__":
    unittest.main()

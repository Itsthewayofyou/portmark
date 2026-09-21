"""Boundary audit (portmark-boundary-audit.md, main a8c8043): the production profile.

NET-02  -- the ASGI app enforces the public-exposure requirements where it is BUILT, so a launcher other
           than serve_asgi (`uvicorn portmark.asgi:app`, an embedding server) cannot skip them.
DB-01   -- a durable store may not start in production without the audit floor (rollback detection).
ATT-01/02 -- a production host whose policy allows migration needs a platform verifier, approved
           measurements, and the fresh migration challenge -- on the boot load and on every reload.

Owner decision 1A: production is the default; only PORTMARK_PROFILE=development relaxes it.
"""

import contextlib
import json
import os
import subprocess  # nosec B404 -- runs this interpreter on a fixed inline script
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from contextlib import redirect_stderr, redirect_stdout
import io

from portmark.cli import main as cli_main
from portmark.config import parse_allowed_measurements, parse_profile
from portmark.factory import make_host
from portmark.metrics import RuntimeMetrics
from portmark.security import AttestationPolicy, ExternalAttestationVerifier
from portmark.storage import SQLiteRuntimeStore
from test_audit_floor import HOST, Deployment, host_signer

SRC = str(Path(__file__).resolve().parents[1] / "src")
TOKEN = "production-profile-token"  # nosec B105 -- a synthetic test token, not a credential
PUBLIC = {
    "PORTMARK_PUBLIC_MODE": "behind-tls-proxy",
    "PORTMARK_A2A_TOKEN": TOKEN,
    "PORTMARK_A2A_TRUSTED_PROXIES": "10.0.0.0/8",
    "PORTMARK_A2A_PUBLIC_BASE_URL": "https://agents.example.com",
}
NETWORK_NAMES = ("PORTMARK_PUBLIC_MODE", "PORTMARK_A2A_TOKEN", "PORTMARK_A2A_TRUSTED_PROXIES", "PORTMARK_A2A_PUBLIC_BASE_URL")
VERIFIER = [sys.executable, "-c", "raise SystemExit(0)"]


@contextlib.contextmanager
def portmark_env(**values):
    """Only the given PORTMARK_* variables, so an ambient setting cannot decide a test."""
    clean = {key: value for key, value in os.environ.items() if not key.startswith("PORTMARK_")}
    clean.update(values)
    with patch.dict(os.environ, clean, clear=True):
        yield


def create_app():
    from portmark.asgi import create_app as build

    return build()


def write_policy(path, migration):
    document = {
        "version": "boundary-v1",
        "tools": {"catalog.search": {"impact": "low", "constraints": {"max_limit": 5, "arguments": {"query": {"type": "string"}}},
                                        "output_projection": ["title"]}},
    }
    if migration:
        document["migration"] = {"allowed": True, "destinations": ["host:destination"]}
    Path(path).write_text(json.dumps(document), encoding="utf-8")


class ProfileParsingTests(unittest.TestCase):
    def test_unset_or_blank_is_production(self):
        for value in (None, "", "   "):
            with self.subTest(value=value):
                self.assertEqual(parse_profile(value), "production")

    def test_only_the_two_exact_names_are_accepted(self):
        self.assertEqual(parse_profile("development"), "development")
        self.assertEqual(parse_profile("production"), "production")
        # A typo must be refused, never guessed: "dev" must not quietly become either profile.
        for value in ("dev", "Development", "production ", "prod", "off"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "PORTMARK_PROFILE"):
                    parse_profile(value)

    def test_measurement_list_refuses_empty_or_malformed_items(self):
        self.assertEqual(parse_allowed_measurements(None), ())
        self.assertEqual(parse_allowed_measurements(" "), ())
        self.assertEqual(parse_allowed_measurements("sha384:aa, sha384:bb,sha384:aa"), ("sha384:aa", "sha384:bb"))
        for value in ("sha384:aa,,sha384:bb", "sha384:aa,", "sha384:a a"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "PORTMARK_ATTESTATION_ALLOWED_MEASUREMENTS"):
                    parse_allowed_measurements(value)


class AppConstructionGateTests(unittest.TestCase):
    """NET-02: the gate lives in create_app, the one path every launcher goes through."""

    def test_production_app_refuses_without_the_public_controls(self):
        with portmark_env():
            with self.assertRaises(ValueError) as raised:
                create_app()
        message = str(raised.exception)
        self.assertIn("production profile", message)
        for name in NETWORK_NAMES:  # every missing requirement, in ONE refusal
            self.assertIn(name, message)

    def test_production_app_with_every_control_builds(self):
        with portmark_env(**PUBLIC):
            self.assertTrue(callable(create_app()))

    def test_production_names_only_what_is_missing(self):
        for missing in NETWORK_NAMES:
            with self.subTest(missing=missing):
                partial = {key: value for key, value in PUBLIC.items() if key != missing}
                with portmark_env(**partial):
                    with self.assertRaises(ValueError) as raised:
                        create_app()
                for name in NETWORK_NAMES:
                    (self.assertIn if name == missing else self.assertNotIn)(name, str(raised.exception))

    def test_development_app_builds_without_them(self):
        with portmark_env(PORTMARK_PROFILE="development"):
            self.assertTrue(callable(create_app()))

    def test_an_invalid_profile_refuses_to_build(self):
        with portmark_env(PORTMARK_PROFILE="dev", **PUBLIC):
            with self.assertRaisesRegex(ValueError, "PORTMARK_PROFILE"):
                create_app()

    def test_importing_the_app_module_directly_is_refused(self):
        # The NET-02 reproduction: `uvicorn portmark.asgi:app` imports the module; it never runs
        # serve_asgi's bind check. The import itself must refuse.
        env = {key: value for key, value in os.environ.items() if not key.startswith("PORTMARK_")}
        env.update(PYTHONPATH=SRC, PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(  # nosec B603 -- this interpreter, fixed inline script
            [sys.executable, "-c", "import portmark.asgi"], capture_output=True, text=True, timeout=120, env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("production profile", result.stderr)
        self.assertIn("PORTMARK_A2A_TOKEN", result.stderr)


class AuditFloorProductionTests(unittest.TestCase):
    """DB-01: production refuses a durable store with no audit floor; development keeps the warning."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        (self.root / "db").mkdir()
        (self.root / "floor").mkdir()
        self.signer = host_signer()

    def host(self, production, floor=False):
        with portmark_env():
            return make_host(
                host_id=HOST, signer=self.signer, store=SQLiteRuntimeStore(self.root / "db" / "runtime.sqlite"),
                audit_floor_path=str(self.root / "floor" / "audit-floor.json") if floor else None,
                production=production,
            )

    def test_production_refuses_a_durable_store_without_a_floor(self):
        with self.assertRaisesRegex(ValueError, "production profile needs an audit floor"):
            self.host(production=True)

    def test_development_starts_with_the_warning(self):
        with self.assertLogs("portmark", level="WARNING") as logs:
            host = self.host(production=False)
        self.assertTrue(any("will NOT be detected" in line for line in logs.output))
        self.assertIn("portmark_audit_witness_active 0", host.metrics.prometheus_text())

    def test_production_with_a_floor_starts_and_reports_it(self):
        host = self.host(production=True, floor=True)
        self.assertIn("portmark_audit_witness_active 1", host.metrics.prometheus_text())

    def test_production_in_memory_store_needs_no_floor(self):
        # Nothing durable, nothing to roll back: the floor rule is about durable stores only.
        with portmark_env():
            host = make_host(host_id=HOST, signer=self.signer, production=True)
        self.assertIsNone(host.audit_floor)


class MigrationAttestationProductionTests(unittest.TestCase):
    """ATT-01/ATT-02: a production host that may migrate needs verifier + measurements + challenge."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.policy_path = Path(self._dir.name) / "policy.json"
        self.signer = host_signer()

    def host(self, production, migration, verifier=None, measurements=None, reload_policy=False):
        write_policy(self.policy_path, migration)
        with portmark_env():
            return make_host(
                host_id=HOST, signer=self.signer, policy_path=str(self.policy_path), reload_policy=reload_policy,
                attestation_verifier_command=verifier, attestation_allowed_measurements=measurements,
                production=production,
            )

    def test_production_migration_without_attestation_is_refused(self):
        with self.assertRaises(ValueError) as raised:
            self.host(production=True, migration=True)
        message = str(raised.exception)
        self.assertIn("allows migration", message)
        self.assertIn("PORTMARK_ATTESTATION_VERIFIER_COMMAND", message)
        self.assertIn("PORTMARK_ATTESTATION_ALLOWED_MEASUREMENTS", message)

    def test_production_migration_needs_the_measurements(self):
        with self.assertRaises(ValueError) as raised:
            self.host(production=True, migration=True, verifier=VERIFIER)
        self.assertIn("PORTMARK_ATTESTATION_ALLOWED_MEASUREMENTS", str(raised.exception))
        self.assertNotIn("PORTMARK_ATTESTATION_VERIFIER_COMMAND", str(raised.exception))

    def test_production_migration_needs_the_platform_verifier(self):
        with self.assertRaises(ValueError) as raised:
            self.host(production=True, migration=True, measurements=("sha384:approved",))
        self.assertIn("PORTMARK_ATTESTATION_VERIFIER_COMMAND", str(raised.exception))
        self.assertNotIn("PORTMARK_ATTESTATION_ALLOWED_MEASUREMENTS", str(raised.exception))

    def test_production_migration_with_verifier_and_measurements_turns_the_challenge_on(self):
        host = self.host(production=True, migration=True, verifier=VERIFIER, measurements=("sha384:approved",))
        policy = host.attestation_policy
        self.assertTrue(policy.require_migration_challenge)
        self.assertEqual(policy.allowed_measurements, ("sha384:approved",))
        self.assertIsNotNone(policy.external_verifier)
        # Not required_for_migration: with the challenge on, that flag would demand PRE-collected
        # evidence from the provider at migrate time -- the replayable evidence the challenge replaces.
        self.assertFalse(policy.required_for_migration)

    def test_a_caller_policy_without_the_challenge_is_refused_in_production(self):
        # A library caller may pass its own AttestationPolicy; production still needs the challenge.
        verifier = ExternalAttestationVerifier(tuple(VERIFIER))
        write_policy(self.policy_path, migration=True)
        for challenge, refused in ((False, True), (True, False)):
            with self.subTest(challenge=challenge):
                supplied = AttestationPolicy(
                    allowed_measurements=("sha384:approved",), external_verifier=verifier,
                    require_migration_challenge=challenge,
                )
                with portmark_env():
                    build = lambda: make_host(  # noqa: E731
                        host_id=HOST, signer=self.signer, policy_path=str(self.policy_path),
                        attestation_policy=supplied, production=True,
                    )
                    if refused:
                        with self.assertRaisesRegex(ValueError, "migration challenge must be on"):
                            build()
                    else:
                        self.assertIs(build().attestation_policy, supplied)

    def test_production_without_migration_needs_no_attestation(self):
        host = self.host(production=True, migration=False)
        self.assertFalse(host.policy.migration.allowed)

    def test_development_keeps_the_old_behavior(self):
        host = self.host(production=False, migration=True)
        self.assertTrue(host.policy.migration.allowed)
        host = self.host(production=False, migration=True, verifier=VERIFIER, measurements=("sha384:approved",))
        self.assertFalse(host.attestation_policy.require_migration_challenge)
        self.assertEqual(host.attestation_policy.allowed_measurements, ("sha384:approved",))

    def test_a_reload_that_turns_migration_on_is_refused(self):
        host = self.host(production=True, migration=False, reload_policy=True)
        before = host.policy
        write_policy(self.policy_path, migration=True)
        with self.assertRaisesRegex(ValueError, "allows migration"):
            host._active_policy()
        self.assertIs(host.policy, before)  # the refused policy was never adopted
        self.assertFalse(host.policy.migration.allowed)


class CliProductionTests(unittest.TestCase):
    """Auditor round 1 on #104: `portmark demo` / `portmark serve` build the host through the same
    production checks as the ASGI app. (Their network rule is already stricter: loopback only.)"""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.d = Deployment(self._dir.name)

    def run_cli(self, *extra_args, command=("demo", "cli production"), **env):
        argv = ["portmark", "--host-id", HOST, "--store-path", str(self.d.store_path),
                "--trust-registry-path", str(self.d.registry_path), *extra_args, *command]
        stdout = io.StringIO()
        with portmark_env(**self.d.env(), **env), patch.object(sys, "argv", argv), \
                redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            cli_main()
        return stdout.getvalue()

    def test_the_cli_refuses_a_durable_store_without_a_floor(self):
        with self.assertRaisesRegex(ValueError, "production profile needs an audit floor"):
            self.run_cli()

    def test_cli_serve_is_refused_before_it_binds(self):
        with patch("portmark.cli.serve") as serve:
            with self.assertRaisesRegex(ValueError, "production profile needs an audit floor"):
                self.run_cli(command=("serve",))
        serve.assert_not_called()

    def test_the_cli_with_a_floor_starts(self):
        self.assertIn("task_id", self.run_cli("--audit-floor-path", str(self.d.floor_path)))

    def test_the_cli_in_development_starts_without_a_floor(self):
        self.assertIn("task_id", self.run_cli(PORTMARK_PROFILE="development"))

    def test_the_cli_applies_the_migration_attestation_rule(self):
        policy = Path(self._dir.name) / "policy.json"
        write_policy(policy, migration=True)
        floor = ("--audit-floor-path", str(self.d.floor_path), "--policy-path", str(policy))
        with self.assertRaisesRegex(ValueError, "PORTMARK_ATTESTATION_ALLOWED_MEASUREMENTS"):
            self.run_cli(*floor, PORTMARK_ATTESTATION_VERIFIER_COMMAND=" ".join(VERIFIER))
        # The measurement list reaches the host from the environment: with it, the host starts.
        self.assertIn("task_id", self.run_cli(
            *floor, PORTMARK_ATTESTATION_VERIFIER_COMMAND=" ".join(VERIFIER),
            PORTMARK_ATTESTATION_ALLOWED_MEASUREMENTS="sha384:approved",
        ))


class GaugeTests(unittest.TestCase):
    def test_only_fixed_gauge_names_are_accepted(self):
        metrics = RuntimeMetrics()
        with self.assertRaisesRegex(ValueError, "unknown gauge"):
            metrics.set_gauge("anything_else", 1)
        metrics.set_gauge("audit_witness_active", 1)
        text = metrics.prometheus_text()
        self.assertIn("# TYPE portmark_audit_witness_active gauge", text)
        self.assertIn("portmark_audit_witness_active 1", text)


if __name__ == "__main__":
    unittest.main()

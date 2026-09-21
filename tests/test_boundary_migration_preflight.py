"""Boundary audit ATT-01, auditor round 1 on #104 (owner decision 2): attest the destination BEFORE release.

The settle-time challenge was verified only after the signed (not encrypted) migration envelope, with the
projected state, had already been sent. The source now mints a fresh challenge, obtains the destination's
attestation over it through the migration preflight, and verifies it BEFORE the envelope is built. A
refusal therefore releases nothing: no migration envelope, no outbox row. The run-loop handler (PM-004)
closes the task as refused.
"""

import contextlib
import sqlite3
import sys
import tempfile
import time
import unittest
from dataclasses import asdict
from pathlib import Path

from portmark.a2a import envelope_from_dict
from portmark.factory import make_demo_envelope, make_host
from portmark.security import (
    AttestationAuthority,
    AttestationPolicy,
    EnvelopeSigner,
    ExternalMigrationPreflight,
    MigrationPolicy,
    SecurityError,
)
from portmark.storage import SQLiteRuntimeStore
from test_runtime import MigrateThenCompleteProvider, _StubMigrationAttester, trust_signer

SOURCE = "host:source"
DESTINATION = "host:destination"
MEASUREMENT = "measurement:enclave"


class StubPreflight:
    """Stands in for the deployment's preflight command. Knobs forge each dimension the source checks."""

    def __init__(self, authority, store, *, measurement=MEASUREMENT, subject=None, audience=None, nonce=None,
                 expires_in=60, fail=False, raw=None):
        self.authority = authority
        self.store = store
        self.measurement, self.subject, self.audience, self.nonce = measurement, subject, audience, nonce
        self.expires_in, self.fail, self.raw = expires_in, fail, raw
        self.calls = []

    def attest(self, destination, relying_party, challenge):
        # Recorded AT call time: had the state already been released, the outbox row would exist now.
        self.calls.append({
            "destination": destination, "relying_party": relying_party, "challenge": challenge,
            "pending_at_call": len(self.store.list_pending_migrations()),
        })
        if self.fail:
            raise SecurityError("migration preflight command failed")
        if self.raw is not None:
            return self.raw
        evidence = self.authority.issue(
            subject=self.subject or destination, audience=self.audience or relying_party,
            measurement=self.measurement, expires_at=int(time.time()) + self.expires_in,
            nonce=self.nonce if self.nonce is not None else challenge,
        )
        return asdict(evidence)


class MigrationPreflightTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)

    def pair(self, challenge=True, **preflight_knobs):
        source_signer = EnvelopeSigner.generate("pf-source", SOURCE, (SOURCE, DESTINATION))
        destination_signer = trust_signer(EnvelopeSigner.generate("pf-dest", DESTINATION, (DESTINATION,)), source_signer)
        trust_signer(source_signer, destination_signer)
        self.authority = AttestationAuthority.generate("dest-enclave-key", "verifier:enclave")
        self.source_store = SQLiteRuntimeStore(self.root / "source.sqlite")
        self.preflight = StubPreflight(self.authority, self.source_store, **preflight_knobs)
        policy = AttestationPolicy((self.authority.trusted_authority(),), (MEASUREMENT,), require_migration_challenge=challenge)
        source = make_host(host_id=SOURCE, signer=source_signer, store=self.source_store, attestation_policy=policy,
                           migration_preflight=self.preflight, allow_ephemeral_signing_key=True)
        destination = make_host(host_id=DESTINATION, signer=destination_signer,
                                store=SQLiteRuntimeStore(self.root / "destination.sqlite"),
                                migration_attester=_StubMigrationAttester(self.authority), allow_ephemeral_signing_key=True)
        source.policy.migration = MigrationPolicy(allowed=True, destinations=(DESTINATION,))
        provider = MigrateThenCompleteProvider(DESTINATION)
        source.providers["migrator"] = provider
        destination.providers["migrator"] = provider
        return source, destination

    def envelope(self, source, goal="move into the enclave"):
        envelope = make_demo_envelope(source, goal, "migrator")
        object.__setattr__(envelope.permit, "delegation_allowed", True)
        source.signer.seal(envelope)
        return envelope

    def events(self, task_id):
        with contextlib.closing(sqlite3.connect(str(self.root / "source.sqlite"))) as connection:
            rows = connection.execute("SELECT event FROM audit_events WHERE task_id = ? ORDER BY sequence", (task_id,)).fetchall()
        return [row[0] for row in rows]

    def test_the_destination_is_verified_before_the_state_is_released(self):
        source, destination = self.pair()
        envelope = self.envelope(source)
        first = source.run(envelope)
        self.assertEqual(len(self.preflight.calls), 1)
        call = self.preflight.calls[0]
        self.assertEqual((call["destination"], call["relying_party"]), (DESTINATION, SOURCE))
        self.assertEqual(call["pending_at_call"], 0)  # nothing had been released when the check ran
        self.assertEqual(first.checkpoint["memory"]["migration"]["preflight_measurement"], MEASUREMENT)
        migrated = envelope_from_dict(first.migration_envelope)
        # One challenge, verified twice: the destination attests over the same value at admission.
        self.assertEqual(migrated.permit.nonce, call["challenge"])
        original_id = migrated.state.task_id
        receipt = destination.run(migrated).migration_receipt
        source.settle_migration(original_id, receipt)
        self.assertEqual(source.store.list_pending_migrations(), [])

    def test_a_refused_destination_receives_nothing(self):
        cases = {
            "wrong nonce": {"nonce": "a-stale-challenge"},
            "unapproved measurement": {"measurement": "measurement:debug"},
            "another destination": {"subject": "host:elsewhere"},
            "another relying party": {"audience": "host:other-source"},
            "expired evidence": {"expires_in": -5},
            "preflight failure": {"fail": True},
            "malformed evidence": {"raw": {"not": "evidence"}},
        }
        for label, knobs in cases.items():
            with self.subTest(label):
                self.setUp()
                source, _ = self.pair(**knobs)
                envelope = self.envelope(source)
                task_id = envelope.state.task_id
                with self.assertRaises(SecurityError):
                    source.run(envelope)
                self.assertEqual(len(self.preflight.calls), 1)
                # Nothing left the source: no outbox row, so no envelope was ever sealed for delivery.
                self.assertEqual(source.store.list_pending_migrations(), [])
                # PM-004: the refusal is durable and terminal, not a stranded running task.
                checkpoint = self.source_store.load_checkpoint(task_id)
                self.assertEqual(checkpoint["status"], "failed")
                self.assertIn("decision.refused", self.events(task_id))
                self.assertNotIn("agent.migrating", self.events(task_id))

    def test_each_migration_gets_a_fresh_challenge(self):
        source, _ = self.pair()
        first, second = self.envelope(source, "first"), self.envelope(source, "second")
        source.run(first)
        source.run(second)
        challenges = [call["challenge"] for call in self.preflight.calls]
        self.assertEqual(len(set(challenges)), 2)
        self.assertNotIn(first.permit.nonce, challenges)  # never the upstream-chosen permit nonce
        self.assertNotIn(second.permit.nonce, challenges)

    def test_without_challenge_mode_the_preflight_still_runs_first(self):
        source, _ = self.pair(challenge=False, nonce="a-stale-challenge")
        with self.assertRaises(SecurityError):
            source.run(self.envelope(source))
        self.assertEqual(source.store.list_pending_migrations(), [])


# Each bad answer is otherwise VALID, so only the one check under test can refuse it: a refusing exit
# still prints an object, a slow command still answers, and an oversized answer is an object followed by
# whitespace (its first bytes alone still parse).
PREFLIGHT_SCRIPT = r"""
import json, sys
request = json.load(sys.stdin)
mode = sys.argv[1]
if mode == "echo":
    print(json.dumps({"request": request}))
elif mode == "refuse":
    print('{"measurement": "m"}')
    sys.exit(3)
elif mode == "garbage":
    print("not json")
elif mode == "binary":
    sys.stdout.buffer.write(b"\xff\xfe\xfa")
elif mode == "list":
    print("[1, 2]")
elif mode == "huge":
    print('{"measurement": "m"}' + " " * 200000)
elif mode == "slow":
    import time; time.sleep(5)
    print('{"measurement": "m"}')
"""


class ExternalMigrationPreflightTests(unittest.TestCase):
    def preflight(self, mode, **kwargs):
        return ExternalMigrationPreflight((sys.executable, "-c", PREFLIGHT_SCRIPT, mode), **kwargs)

    def test_the_command_gets_the_request_on_stdin_and_returns_an_object(self):
        value = self.preflight("echo").attest(DESTINATION, SOURCE, "challenge-123")
        self.assertEqual(value["request"], {"destination": DESTINATION, "relying_party": SOURCE, "challenge": "challenge-123"})

    def test_every_bad_answer_fails_closed(self):
        cases = {"refuse": {}, "garbage": {}, "binary": {}, "list": {}, "huge": {}, "slow": {"timeout": 0.5}}
        for mode, kwargs in cases.items():
            with self.subTest(mode):
                with self.assertRaises(SecurityError):
                    self.preflight(mode, **kwargs).attest(DESTINATION, SOURCE, "challenge-123")

    def test_the_default_output_limit_fits_a_hardware_quote(self):
        # A SEV-SNP / TDX quote is kilobytes; the verifier's 4 KiB {"valid": true} limit would refuse it.
        self.assertGreaterEqual(ExternalMigrationPreflight((sys.executable,)).max_response_bytes, 32_768)

    def test_bad_construction_is_refused(self):
        for command, kwargs in (((), {}), (("",), {}), ((sys.executable,), {"timeout": 0}), ((sys.executable,), {"max_response_bytes": 1})):
            with self.subTest(command=command, **kwargs):
                with self.assertRaises(ValueError):
                    ExternalMigrationPreflight(command, **kwargs)

    def test_the_command_runs_without_a_shell_or_the_host_environment(self):
        script = "import json, os, sys; json.load(sys.stdin); print(json.dumps({'env': sorted(os.environ)}))"
        value = ExternalMigrationPreflight((sys.executable, "-c", script)).attest(DESTINATION, SOURCE, "c")
        self.assertNotIn("PATH", value["env"])  # env={}: no host secrets reach the command
        self.assertNotIn("HOME", value["env"])


if __name__ == "__main__":
    unittest.main()

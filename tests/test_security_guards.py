import base64
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from portmark.models import AgentEnvelope, AgentManifest, AgentState, Permit, ResourceBudget, ToolGrant
from portmark.policy import load_host_policy
from portmark.security import (
    ApprovalAuthority,
    AttestationAuthority,
    AttestationPolicy,
    EnvelopeSigner,
    HostPolicy,
    SecurityError,
    TrustedApprover,
    TrustedIdentity,
    TrustRegistry,
    check_constraints,
    load_trust_registry,
)


NOW = 2_000_000


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class RejectingExternalVerifier:
    def verify(self, evidence, expected_subject, relying_party, expected_nonce, now):
        raise SecurityError("external verifier rejected evidence")


class SecurityGuardTests(unittest.TestCase):
    def _permit(self) -> Permit:
        return Permit(
            issuer="user:alice",
            subject="agent:demo",
            audience="host:local-demo",
            expires_at=NOW + 300,
            nonce="permit-nonce",
            grants=(ToolGrant("payments.reserve"),),
            budget=ResourceBudget(),
        )

    def _approval_policy(self, authority: TrustedApprover) -> HostPolicy:
        return HostPolicy(
            "host:local-demo",
            (ToolGrant("payments.reserve"),),
            ResourceBudget(),
            "policy-v1",
            "policy-hash",
            {"payments.reserve": "external-payment"},
            (authority,),
        )

    def test_approval_token_validation_guards_are_table_driven(self):
        authority = ApprovalAuthority.generate()
        permit = self._permit()
        arguments = {"amount": 25, "currency": "USD"}
        token = authority.issue(
            "payments.reserve",
            permit.subject,
            permit.audience,
            "task-1",
            permit.nonce,
            arguments,
            "policy-hash",
            NOW + 60,
            issued_at=NOW - 1,
            approval_id="approval-1",
        )
        self._approval_policy(authority.trusted_approver()).verify_approval(
            token, permit, "task-1", "payments.reserve", arguments, now=NOW
        )

        cases = [
            ("approval signer is not trusted", replace(token, signature_key_id="missing-key"), None, arguments, "payments.reserve", "task-1"),
            ("approval signer has been revoked", token, replace(authority.trusted_approver(), revoked=True), arguments, "payments.reserve", "task-1"),
            ("approval signer is not active yet", token, replace(authority.trusted_approver(), not_before=NOW + 1), arguments, "payments.reserve", "task-1"),
            ("approval signer has expired", token, replace(authority.trusted_approver(), expires_at=NOW), arguments, "payments.reserve", "task-1"),
            ("approval signer identity does not match key", replace(token, approved_by="approver:mallory"), None, arguments, "payments.reserve", "task-1"),
            ("approval tool does not match request", replace(token, tool="other.tool"), None, arguments, "payments.reserve", "task-1"),
            ("approval subject does not match permit", replace(token, subject="agent:other"), None, arguments, "payments.reserve", "task-1"),
            ("approval audience does not match permit", replace(token, audience="host:other"), None, arguments, "payments.reserve", "task-1"),
            ("approval task does not match request", replace(token, task_id="task-2"), None, arguments, "payments.reserve", "task-1"),
            ("approval does not match permit nonce", replace(token, permit_nonce="other-nonce"), None, arguments, "payments.reserve", "task-1"),
            ("approval policy hash does not match active policy", replace(token, policy_hash="old-policy"), None, arguments, "payments.reserve", "task-1"),
            ("approval arguments do not match request", token, None, {"amount": 26, "currency": "USD"}, "payments.reserve", "task-1"),
            ("approval is not active yet", replace(token, issued_at=NOW + 1), None, arguments, "payments.reserve", "task-1"),
            ("approval has expired", replace(token, expires_at=NOW), None, arguments, "payments.reserve", "task-1"),
            ("approval signature is invalid", replace(token, signature="bad-signature"), None, arguments, "payments.reserve", "task-1"),
        ]
        for message, mutated_token, mutated_authority, mutated_arguments, tool, task_id in cases:
            with self.subTest(message=message):
                trusted = mutated_authority or authority.trusted_approver()
                with self.assertRaisesRegex(SecurityError, message):
                    self._approval_policy(trusted).verify_approval(
                        mutated_token, permit, task_id, tool, mutated_arguments, now=NOW
                    )

    def test_trust_registry_identity_guards_are_table_driven(self):
        signer = EnvelopeSigner.generate("agent-key", "user:alice", ("host:local-demo",))
        envelope = signer.seal(AgentEnvelope(
            AgentManifest("agent:demo", "1.0.0", "deterministic", ("catalog.search",)),
            self._permit(),
            AgentState("task-1", "goal"),
        ))
        trusted = TrustedIdentity(
            signer.key_id,
            signer.issuer,
            signer.public_key_bytes(),
            ("host:local-demo",),
            not_before=NOW - 1,
            expires_at=NOW + 60,
        )
        TrustRegistry((trusted,)).require_identity(envelope, now=NOW)

        cases = [
            ("agent envelope signature key id is missing", None, replace(envelope, signature_key_id="")),
            ("agent envelope signature key id is not trusted", None, replace(envelope, signature_key_id="missing")),
            ("agent envelope signing key has been revoked", replace(trusted, revoked=True), envelope),
            ("agent envelope signing key is not active yet", replace(trusted, not_before=NOW + 1), envelope),
            ("agent envelope signing key has expired", replace(trusted, expires_at=NOW), envelope),
            ("agent envelope signing key cannot sign for this issuer", replace(trusted, issuer="user:bob"), envelope),
            ("agent envelope signing key cannot sign for this audience", replace(trusted, allowed_audiences=("host:other",)), envelope),
        ]
        for message, identity, candidate in cases:
            with self.subTest(message=message):
                registry = TrustRegistry(() if identity is None else (identity,))
                with self.assertRaisesRegex(SecurityError, message):
                    registry.require_identity(candidate, now=NOW)

    def test_argument_constraint_malformed_schema_guards_are_table_driven(self):
        constraints = {
            "arguments": {"query": {"type": "string", "min_length": 1}, "limit": {"type": "integer", "minimum": 1, "maximum": 5}},
            "required": ["query", "limit"],
            "additional_arguments": False,
        }
        check_constraints(constraints, {"query": "portable", "limit": 3})
        check_constraints(
            {"arguments": {"url": {"type": "string", "scheme": "https", "allowed_domains": ["example.com"]}}},
            {"url": "https://api.example.com/resource"},
        )

        cases = [
            ({"arguments": []}, {"query": "x"}, "argument constraints must be an object"),
            ({"arguments": {"": {"type": "string"}}}, {"": "x"}, "argument constraint names must be non-empty strings"),
            ({"arguments": {"query": []}}, {"query": "x"}, "argument 'query' constraint must be an object"),
            ({"required": "query"}, {"query": "x"}, "required argument constraints must be a list"),
            ({"required": [""]}, {"query": "x"}, "required argument constraints must be non-empty strings"),
            ({"additional_arguments": "false"}, {"query": "x"}, "additional_arguments constraint must be boolean"),
            ({"arguments": {"query": {"type": [1]}}}, {"query": "x"}, "argument type constraints must be strings"),
            ({"arguments": {"query": {"enum": []}}}, {"query": "x"}, "argument 'query' enum constraint must be a non-empty list"),
            ({"arguments": {"limit": {"minimum": True}}}, {"limit": 1}, "argument 'limit' minimum constraint must be numeric"),
            ({"arguments": {"limit": {"maximum": False}}}, {"limit": 1}, "argument 'limit' maximum constraint must be numeric"),
            ({"arguments": {"query": {"min_length": -1}}}, {"query": "x"}, "argument 'query' min_length constraint must be a non-negative integer"),
            ({"arguments": {"query": {"max_length": True}}}, {"query": "x"}, "argument 'query' max_length constraint must be a non-negative integer"),
            ({"arguments": {"query": {"pattern": 1}}}, {"query": "x"}, "argument 'query' pattern constraint must be a string"),
            ({"arguments": {"query": {"pattern": "["}}}, {"query": "x"}, "argument 'query' pattern constraint is invalid"),
            ({"arguments": {"url": {"scheme": 1}}}, {"url": "https://example.com"}, "argument 'url' scheme constraint must be a non-empty string"),
            ({"arguments": {"url": {"allowed_schemes": []}}}, {"url": "https://example.com"}, "argument 'url' allowed_schemes must be a non-empty list"),
            ({"arguments": {"url": {"allowed_hosts": [""]}}}, {"url": "https://example.com"}, "argument 'url' allowed_hosts entries must be non-empty strings"),
            ({"arguments": {"url": {"allowed_domains": "example.com"}}}, {"url": "https://example.com"}, "argument 'url' allowed_domains must be a non-empty list"),
            ({"arguments": {"url": {"scheme": "https"}}}, {"url": "not-a-url"}, "argument 'url' must be an absolute URL"),
            ({"arguments": {"url": {"scheme": "https"}}}, {"url": "https://user@example.com"}, "argument 'url' must not contain userinfo"),
        ]
        for malformed, arguments, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(SecurityError, message):
                    check_constraints(malformed, arguments)

    def test_attestation_evidence_guards_are_table_driven(self):
        authority = AttestationAuthority.generate()
        trusted = replace(authority.trusted_authority(), not_before=NOW - 1, expires_at=NOW + 60)
        evidence = authority.issue(
            "host:local-demo",
            "user:alice",
            "measurement:approved",
            NOW + 60,
            nonce="permit-nonce",
            issued_at=NOW - 1,
        )
        AttestationPolicy((trusted,), ("measurement:approved",)).verify(
            evidence, "host:local-demo", "user:alice", expected_nonce="permit-nonce", now=NOW
        )

        other = AttestationAuthority.generate("other-key", "verifier:other")
        cases = [
            ("attestation evidence is required", None, trusted, None, "host:local-demo", "user:alice", "permit-nonce"),
            ("attestation verifier key is not trusted", replace(evidence, signature_key_id="missing"), None, None, "host:local-demo", "user:alice", "permit-nonce"),
            ("attestation verifier key has been revoked", evidence, replace(trusted, revoked=True), None, "host:local-demo", "user:alice", "permit-nonce"),
            ("attestation verifier key is not active yet", evidence, replace(trusted, not_before=NOW + 1), None, "host:local-demo", "user:alice", "permit-nonce"),
            ("attestation verifier key has expired", evidence, replace(trusted, expires_at=NOW), None, "host:local-demo", "user:alice", "permit-nonce"),
            ("attestation verifier identity does not match key", replace(evidence, verifier="verifier:other"), trusted, None, "host:local-demo", "user:alice", "permit-nonce"),
            ("attestation subject does not match expected host", replace(evidence, subject="host:other"), trusted, None, "host:local-demo", "user:alice", "permit-nonce"),
            ("attestation audience does not match relying party", replace(evidence, audience="user:bob"), trusted, None, "host:local-demo", "user:alice", "permit-nonce"),
            ("attestation evidence is not active yet", replace(evidence, issued_at=NOW + 1), trusted, None, "host:local-demo", "user:alice", "permit-nonce"),
            ("attestation evidence has expired", replace(evidence, expires_at=NOW), trusted, None, "host:local-demo", "user:alice", "permit-nonce"),
            ("attestation measurement is not approved", replace(evidence, measurement="measurement:unknown"), trusted, None, "host:local-demo", "user:alice", "permit-nonce"),
            ("attestation nonce does not match permit", replace(evidence, nonce="other-nonce"), trusted, None, "host:local-demo", "user:alice", "permit-nonce"),
            ("attestation quote is required for external verification", evidence, trusted, RejectingExternalVerifier(), "host:local-demo", "user:alice", "permit-nonce"),
            ("attestation signature is invalid", replace(evidence, signature=other.issue("host:local-demo", "user:alice", "measurement:approved", NOW + 60).signature), trusted, None, "host:local-demo", "user:alice", "permit-nonce"),
        ]
        for message, candidate, candidate_trusted, external, subject, audience, nonce in cases:
            with self.subTest(message=message):
                authorities = () if candidate_trusted is None else (candidate_trusted,)
                policy = AttestationPolicy(authorities, ("measurement:approved",), external_verifier=external)
                with self.assertRaisesRegex(SecurityError, message):
                    policy.verify(candidate, subject, audience, expected_nonce=nonce, now=NOW)

        with self.assertRaisesRegex(SecurityError, "external verifier rejected evidence"):
            AttestationPolicy((), ("measurement:approved",), external_verifier=RejectingExternalVerifier()).verify(
                replace(evidence, quote="quote", signature_key_id="", signature=""),
                "host:local-demo",
                "user:alice",
                expected_nonce="permit-nonce",
                now=NOW,
            )

    def test_policy_and_trust_registry_loader_validation_guards_are_table_driven(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            trust_path = root / "trust.json"
            authority = ApprovalAuthority.generate()
            policy_path.write_text(json.dumps({
                "version": "policy-v1",
                "budget": {"max_steps": 10},
                "approval_authorities": [{
                    "key_id": authority.key_id,
                    "approver": authority.approver,
                    "public_key_b64": authority.public_key_b64(),
                }],
                "tools": {"catalog.search": {"impact": "low", "constraints": {"max_limit": 5}, "output_projection": ["id"]}},
            }), encoding="utf-8")
            signer = EnvelopeSigner.generate("agent-key", "user:alice", ("*",))
            trust_path.write_text(json.dumps({
                "identities": [{
                    "key_id": signer.key_id,
                    "issuer": signer.issuer,
                    "public_key_b64": _b64(signer.public_key_bytes()),
                    "allowed_audiences": ["*"],
                }]
            }), encoding="utf-8")
            self.assertEqual(load_host_policy(policy_path, "host:local-demo").policy_version, "policy-v1")
            self.assertTrue(load_trust_registry(trust_path).has_key("agent-key"))

            policy_cases = [
                ([], "policy root must be an object"),
                ({}, "policy version must be a non-empty string"),
                ({"version": "v1", "tools": []}, "policy tools must be an object"),
                ({"version": "v1", "budget": [] , "tools": {"catalog.search": {}}}, "policy budget must be an object"),
                ({"version": "v1", "budget": {"bad": 1}, "tools": {"catalog.search": {}}}, "policy budget contains unsupported fields"),
                ({"version": "v1", "tools": {"": {}}}, "policy tool names must be non-empty strings"),
                ({"version": "v1", "tools": {"catalog.search": []}}, "policy tool entries must be objects"),
                ({"version": "v1", "tools": {"catalog.search": {"impact": "root"}}}, "invalid impact"),
                ({"version": "v1", "tools": {"catalog.search": {"constraints": []}}}, "constraints must be an object"),
                ({"version": "v1", "tools": {"catalog.search": {"output_projection": "*"}}}, "output_projection must be a list"),
                ({"version": "v1", "tools": {"catalog.search": {"output_projection": ["*", "id"]}}}, "output_projection cannot mix"),
                ({"version": "v1", "tools": {"catalog.search": {}}, "approval_authorities": {}}, "approval_authorities must be a list"),
                ({"version": "v1", "tools": {"catalog.search": {}}, "approval_authorities": [{"key_id": "k", "approver": "a", "public_key_b64": "bad"}]}, "approval public keys must be 32 raw bytes"),
                ({"version": "v1", "tools": {"catalog.search": {}}, "approval_required_impacts": ["root"]}, "approval_required_impacts contains an invalid impact"),
            ]
            for value, message in policy_cases:
                with self.subTest(policy=message):
                    policy_path.write_text(json.dumps(value), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, message):
                        load_host_policy(policy_path, "host:local-demo")

            trust_cases = [
                ([], "trust registry root must be an object"),
                ({}, "trust registry identities must be a list"),
                ({"identities": ["bad"]}, "trust registry identity entries must be objects"),
                ({"identities": [{"issuer": "user:alice", "public_key_b64": _b64(signer.public_key_bytes())}]}, "trust registry key_id must be a non-empty string"),
                ({"identities": [{"key_id": "agent-key", "public_key_b64": _b64(signer.public_key_bytes())}]}, "trust registry issuer must be a non-empty string"),
                ({"identities": [{"key_id": "agent-key", "issuer": "user:alice", "public_key_b64": "bad"}]}, "Ed25519 public keys must be 32 raw bytes"),
                ({"identities": [{"key_id": "agent-key", "issuer": "user:alice", "public_key_b64": _b64(signer.public_key_bytes()), "allowed_audiences": []}]}, "allowed_audiences must be a non-empty list"),
                ({"identities": [
                    {"key_id": "agent-key", "issuer": "user:alice", "public_key_b64": _b64(signer.public_key_bytes())},
                    {"key_id": "agent-key", "issuer": "user:alice", "public_key_b64": _b64(signer.public_key_bytes())},
                ]}, "duplicate signing key id"),
            ]
            for value, message in trust_cases:
                with self.subTest(trust=message):
                    trust_path.write_text(json.dumps(value), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, message):
                        load_trust_registry(trust_path)


if __name__ == "__main__":
    unittest.main()

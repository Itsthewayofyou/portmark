"""Test-side issuers: they sign the attestation evidence and approval tokens that the runtime verifies.

The runtime ships only the verifying half (TrustedAttestationAuthority, TrustedApprover). A deployment's
real attester and approver live outside Portmark; these stand in for them in the tests.
"""

from __future__ import annotations

import secrets
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from portmark.models import ApprovalToken, AttestationEvidence
from portmark.security import (
    TrustedApprover,
    TrustedAttestationAuthority,
    _b64url_encode,
    _decision_time,
    arguments_hash,
    canonical_json,
)


class AttestationAuthority:
    def __init__(self, key_id: str, verifier: str, private_key: Ed25519PrivateKey) -> None:
        self.key_id = key_id
        self.verifier = verifier
        self._private_key = private_key

    @classmethod
    def generate(cls, key_id: str = "demo-attestation-key", verifier: str = "verifier:demo") -> "AttestationAuthority":
        return cls(key_id, verifier, Ed25519PrivateKey.generate())

    def issue(
        self,
        subject: str,
        audience: str,
        measurement: str,
        expires_at: int,
        nonce: str = "",
        claims: dict[str, Any] | None = None,
        issued_at: int | None = None,
    ) -> AttestationEvidence:
        evidence = AttestationEvidence(
            verifier=self.verifier,
            subject=subject,
            audience=audience,
            measurement=measurement,
            issued_at=_decision_time(issued_at),
            expires_at=expires_at,
            nonce=nonce,
            claims=claims or {},
            signature_key_id=self.key_id,
        )
        signature = _b64url_encode(self._private_key.sign(canonical_json(evidence.unsigned_dict())))
        return AttestationEvidence(**{**evidence.unsigned_dict(), "signature": signature})

    def trusted_authority(self) -> TrustedAttestationAuthority:
        return TrustedAttestationAuthority(
            self.key_id,
            self.verifier,
            self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        )


class ApprovalAuthority:
    def __init__(self, key_id: str, approver: str, private_key: Ed25519PrivateKey) -> None:
        self.key_id = key_id
        self.approver = approver
        self._private_key = private_key

    @classmethod
    def generate(cls, key_id: str = "demo-approval-key", approver: str = "approver:demo") -> "ApprovalAuthority":
        return cls(key_id, approver, Ed25519PrivateKey.generate())

    def issue(
        self,
        tool: str,
        subject: str,
        audience: str,
        task_id: str,
        permit_nonce: str,
        arguments: dict[str, Any],
        policy_hash: str,
        expires_at: int,
        checkpoint_generation: int,
        issued_at: int | None = None,
        approval_id: str | None = None,
    ) -> ApprovalToken:
        token = ApprovalToken(
            approval_id=approval_id or secrets.token_hex(16),
            tool=tool,
            subject=subject,
            audience=audience,
            task_id=task_id,
            permit_nonce=permit_nonce,
            checkpoint_generation=checkpoint_generation,
            arguments_hash=arguments_hash(arguments),
            policy_hash=policy_hash,
            approved_by=self.approver,
            issued_at=_decision_time(issued_at),
            expires_at=expires_at,
            signature_key_id=self.key_id,
        )
        signature = _b64url_encode(self._private_key.sign(canonical_json(token.unsigned_dict())))
        return ApprovalToken(**{**token.unsigned_dict(), "signature": signature})

    def trusted_approver(self) -> TrustedApprover:
        return TrustedApprover(
            self.key_id,
            self.approver,
            self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        )

    def public_key_b64(self) -> str:
        return _b64url_encode(self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

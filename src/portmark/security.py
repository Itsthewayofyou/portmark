from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import subprocess  # nosec B404
import tempfile
import time
import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .models import AgentEnvelope, AgentManifest, ApprovalToken, AttestationEvidence, Permit, ResourceBudget, ToolGrant


class SecurityError(RuntimeError):
    pass


class EnvelopeVerifier(Protocol):
    def verify(self, envelope: AgentEnvelope) -> None:
        ...


class EnvelopeSigningIdentity(EnvelopeVerifier, Protocol):
    key_id: str

    def seal(self, envelope: AgentEnvelope) -> AgentEnvelope:
        ...

    def sign_audit_head(self, task_id: str, host_id: str, head_hash: str, sequence: int) -> str:
        ...

    def verify_audit_head(self, key_id: str, payload: dict[str, Any], signature: str) -> None:
        ...


class AuditHeadVerifier(Protocol):
    def verify_audit_head(self, key_id: str, payload: dict[str, Any], signature: str) -> None:
        ...


class ExternalAttestationVerifierProtocol(Protocol):
    def verify(
        self,
        evidence: AttestationEvidence,
        expected_subject: str,
        relying_party: str,
        expected_nonce: str | None,
        now: int,
    ) -> None:
        ...


def audit_head_payload(task_id: str, host_id: str, head_hash: str, sequence: int) -> dict[str, Any]:
    return {
        "type": "portmark.audit-head.v1",
        "task_id": task_id,
        "host_id": host_id,
        "head_hash": head_hash,
        "sequence": sequence,
    }


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


@dataclass(frozen=True)
class TrustedIdentity:
    key_id: str
    issuer: str
    public_key: bytes
    allowed_audiences: tuple[str, ...] = ("*",)
    not_before: int = 0
    expires_at: int | None = None
    revoked: bool = False


@dataclass(frozen=True)
class TrustedAttestationAuthority:
    key_id: str
    verifier: str
    public_key: bytes
    not_before: int = 0
    expires_at: int | None = None
    revoked: bool = False


@dataclass(frozen=True)
class TrustedApprover:
    key_id: str
    approver: str
    public_key: bytes
    not_before: int = 0
    expires_at: int | None = None
    revoked: bool = False


class TrustRegistry:
    def __init__(self, identities: tuple[TrustedIdentity, ...] = ()) -> None:
        self._identities = {identity.key_id: identity for identity in identities}

    def add(self, identity: TrustedIdentity) -> None:
        if identity.key_id in self._identities:
            raise ValueError(f"duplicate signing key id {identity.key_id!r}")
        if len(identity.public_key) != 32:
            raise ValueError("Ed25519 public keys must be 32 raw bytes")
        self._identities[identity.key_id] = identity

    def has_key(self, key_id: str) -> bool:
        return key_id in self._identities

    def identity(self, key_id: str) -> TrustedIdentity | None:
        return self._identities.get(key_id)

    def verify_audit_head(self, key_id: str, payload: dict[str, Any], signature: str, now: int | None = None) -> None:
        identity = self._identities.get(key_id)
        if identity is None:
            raise SecurityError("audit head signing key is not trusted")
        current_time = int(time.time()) if now is None else now
        if identity.revoked:
            raise SecurityError("audit head signing key has been revoked")
        if identity.not_before > current_time:
            raise SecurityError("audit head signing key is not active yet")
        if identity.expires_at is not None and identity.expires_at <= current_time:
            raise SecurityError("audit head signing key has expired")
        if payload.get("host_id") != identity.issuer:
            raise SecurityError("audit head signer identity does not match host")
        try:
            Ed25519PublicKey.from_public_bytes(identity.public_key).verify(
                _b64url_decode(signature),
                canonical_json(payload),
            )
        except (InvalidSignature, ValueError) as error:
            raise SecurityError("audit head signature is invalid") from error

    def require_identity(self, envelope: AgentEnvelope, now: int | None = None) -> TrustedIdentity:
        if not envelope.signature_key_id:
            raise SecurityError("agent envelope signature key id is missing")
        identity = self._identities.get(envelope.signature_key_id)
        if identity is None:
            raise SecurityError("agent envelope signature key id is not trusted")
        if identity.revoked:
            raise SecurityError("agent envelope signing key has been revoked")
        current_time = int(time.time()) if now is None else now
        if identity.not_before > current_time:
            raise SecurityError("agent envelope signing key is not active yet")
        if identity.expires_at is not None and identity.expires_at <= current_time:
            raise SecurityError("agent envelope signing key has expired")
        if not _issuer_matches(identity.issuer, envelope.permit.issuer):
            raise SecurityError("agent envelope signing key cannot sign for this issuer")
        if "*" not in identity.allowed_audiences and envelope.permit.audience not in identity.allowed_audiences:
            raise SecurityError("agent envelope signing key cannot sign for this audience")
        return identity


def load_trust_registry(path: str | Path) -> TrustRegistry:
    with open(path, "rb") as file:
        value = json.load(file)
    if not isinstance(value, dict):
        raise ValueError("trust registry root must be an object")
    identities = value.get("identities")
    if not isinstance(identities, list):
        raise ValueError("trust registry identities must be a list")
    registry = TrustRegistry()
    for item in identities:
        if not isinstance(item, dict):
            raise ValueError("trust registry identity entries must be objects")
        registry.add(
            TrustedIdentity(
                key_id=_required_string(item, "key_id", "trust registry"),
                issuer=_required_string(item, "issuer", "trust registry"),
                public_key=_decode_raw_key(_required_string(item, "public_key_b64", "trust registry"), "Ed25519 public keys"),
                allowed_audiences=_string_tuple(item.get("allowed_audiences", ("*",)), "trust registry allowed_audiences"),
                not_before=int(item.get("not_before", 0)),
                expires_at=int(item["expires_at"]) if item.get("expires_at") is not None else None,
                revoked=bool(item.get("revoked", False)),
            )
        )
    return registry


def _issuer_matches(signing_issuer: str, permit_issuer: str) -> bool:
    return permit_issuer == signing_issuer


def _required_string(value: dict[str, Any], name: str, label: str) -> str:
    result = value.get(name)
    if not isinstance(result, str) or not result:
        raise ValueError(f"{label} {name} must be a non-empty string")
    return result


def _decode_raw_key(value: str, label: str) -> bytes:
    decoded = _b64url_decode(value)
    if len(decoded) != 32:
        raise ValueError(f"{label} must be 32 raw bytes")
    return decoded


def _string_tuple(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ValueError(f"{label} must be a non-empty list")
    if not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{label} entries must be non-empty strings")
    return tuple(value)


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
            issued_at=int(time.time()) if issued_at is None else issued_at,
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


class AttestationPolicy:
    def __init__(
        self,
        authorities: tuple[TrustedAttestationAuthority, ...] = (),
        allowed_measurements: tuple[str, ...] = (),
        required_for_execution: bool = False,
        required_for_migration: bool = False,
        external_verifier: ExternalAttestationVerifierProtocol | None = None,
    ) -> None:
        self._authorities = {authority.key_id: authority for authority in authorities}
        self.allowed_measurements = allowed_measurements
        self.required_for_execution = required_for_execution
        self.required_for_migration = required_for_migration
        self.external_verifier = external_verifier

    def verify_execution(self, permit: Permit, host_id: str, now: int | None = None) -> None:
        if not self.required_for_execution and permit.attestation is None:
            return
        self.verify(
            permit.attestation,
            expected_subject=host_id,
            relying_party=permit.issuer,
            expected_nonce=permit.nonce,
            now=now,
        )

    def verify_migration(self, evidence: AttestationEvidence | None, destination: str, source_host_id: str, now: int | None = None) -> None:
        if not self.required_for_migration and evidence is None:
            return
        self.verify(evidence, expected_subject=destination, relying_party=source_host_id, now=now)

    def verify(
        self,
        evidence: AttestationEvidence | None,
        expected_subject: str,
        relying_party: str,
        expected_nonce: str | None = None,
        now: int | None = None,
    ) -> None:
        if evidence is None:
            raise SecurityError("attestation evidence is required")
        authority = self._authorities.get(evidence.signature_key_id) if evidence.signature_key_id else None
        if authority is None and self.external_verifier is None:
            raise SecurityError("attestation verifier key is not trusted")
        current_time = int(time.time()) if now is None else now
        if authority is not None:
            if authority.revoked:
                raise SecurityError("attestation verifier key has been revoked")
            if authority.not_before > current_time:
                raise SecurityError("attestation verifier key is not active yet")
            if authority.expires_at is not None and authority.expires_at <= current_time:
                raise SecurityError("attestation verifier key has expired")
            if evidence.verifier != authority.verifier:
                raise SecurityError("attestation verifier identity does not match key")
        if evidence.subject != expected_subject:
            raise SecurityError("attestation subject does not match expected host")
        if evidence.audience not in {relying_party, "*"}:
            raise SecurityError("attestation audience does not match relying party")
        if evidence.issued_at > current_time:
            raise SecurityError("attestation evidence is not active yet")
        if evidence.expires_at <= current_time:
            raise SecurityError("attestation evidence has expired")
        if self.allowed_measurements and evidence.measurement not in self.allowed_measurements:
            raise SecurityError("attestation measurement is not approved")
        if expected_nonce is not None and evidence.nonce and not hmac.compare_digest(evidence.nonce, expected_nonce):
            raise SecurityError("attestation nonce does not match permit")
        if self.external_verifier is not None and not evidence.quote:
            raise SecurityError("attestation quote is required for external verification")
        if authority is not None:
            try:
                Ed25519PublicKey.from_public_bytes(authority.public_key).verify(
                    _b64url_decode(evidence.signature),
                    canonical_json(evidence.unsigned_dict()),
                )
            except (InvalidSignature, ValueError) as error:
                raise SecurityError("attestation signature is invalid") from error
        if self.external_verifier is not None:
            self.external_verifier.verify(evidence, expected_subject, relying_party, expected_nonce, current_time)


class ExternalAttestationVerifier:
    """Shell-free adapter for deployment-specific quote verification."""

    def __init__(self, command: tuple[str, ...], timeout: float = 2.0, max_response_bytes: int = 4096) -> None:
        if not command or not all(isinstance(item, str) and item for item in command):
            raise ValueError("attestation verifier command must be a non-empty argv tuple")
        if timeout <= 0:
            raise ValueError("attestation verifier timeout must be positive")
        if max_response_bytes < 2:
            raise ValueError("attestation verifier response limit must be at least 2 bytes")
        self.command = command
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes

    def verify(
        self,
        evidence: AttestationEvidence,
        expected_subject: str,
        relying_party: str,
        expected_nonce: str | None,
        now: int,
    ) -> None:
        payload = canonical_json({
            "evidence": evidence.unsigned_dict(),
            "expected_subject": expected_subject,
            "relying_party": relying_party,
            "expected_nonce": expected_nonce,
            "now": now,
        })
        try:
            with tempfile.TemporaryFile() as stdout:
                # The command is an operator-provided argv tuple and shell execution is disabled.
                process = subprocess.run(  # nosec B603
                    list(self.command),
                    input=payload,
                    stdout=stdout,
                    stderr=subprocess.DEVNULL,
                    timeout=self.timeout,
                    check=False,
                    env={},
                )
                stdout.seek(0, 2)
                response_size = stdout.tell()
                if response_size > self.max_response_bytes:
                    raise SecurityError("external attestation verifier response exceeds output limit")
                stdout.seek(0)
                response = stdout.read(self.max_response_bytes + 1)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SecurityError("external attestation verifier failed") from error
        if process.returncode != 0:
            raise SecurityError("external attestation verifier rejected evidence")
        try:
            value = json.loads(response or b"{}")
        except json.JSONDecodeError as error:
            raise SecurityError("external attestation verifier returned malformed JSON") from error
        if not isinstance(value, dict) or value.get("valid") is not True:
            raise SecurityError("external attestation verifier rejected evidence")


def arguments_hash(arguments: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(arguments)).hexdigest()


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
            arguments_hash=arguments_hash(arguments),
            policy_hash=policy_hash,
            approved_by=self.approver,
            issued_at=int(time.time()) if issued_at is None else issued_at,
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


def generate_signing_material(
    key_id: str,
    issuer: str,
    allowed_audiences: tuple[str, ...] = ("*",),
) -> dict[str, Any]:
    """Mint a signing key together with the trust registry entry that accepts it.

    The two halves are emitted at once on purpose: a private key whose public half
    was never published to a host is unusable, and hand-assembling that registry
    JSON is the step this exists to remove.
    """
    private_key = Ed25519PrivateKey.generate()
    return {
        "key_id": key_id,
        "issuer": issuer,
        "private_key_b64": _b64url_encode(
            private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ),
        "trust_registry": {
            "identities": [
                {
                    "key_id": key_id,
                    "issuer": issuer,
                    "public_key_b64": _b64url_encode(
                        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                    ),
                    "allowed_audiences": list(allowed_audiences),
                }
            ]
        },
    }


def _register_own_identity(
    registry: TrustRegistry,
    key_id: str,
    issuer: str,
    public_key: bytes,
    allowed_audiences: tuple[str, ...],
) -> None:
    """Publish this signer's own public key into the registry it verifies against.

    An operator-supplied registry may already carry the entry, which is the normal
    case. An entry under the same key id holding a *different* public key is a
    misconfiguration that would otherwise surface much later as an unexplained
    signature failure, so it fails closed here.
    """
    existing = registry.identity(key_id)
    if existing is None:
        registry.add(
            TrustedIdentity(
                key_id=key_id,
                issuer=issuer,
                public_key=public_key,
                allowed_audiences=allowed_audiences,
            )
        )
        return
    if existing.public_key != public_key:
        raise SecurityError(f"trust registry key id {key_id!r} holds a different public key")


class EnvelopeSigner:
    """Ed25519 envelope signer and verifier backed by a trust registry."""

    def __init__(self, key_id: str, issuer: str, private_key: Ed25519PrivateKey, registry: TrustRegistry) -> None:
        self.key_id = key_id
        self.issuer = issuer
        self._private_key = private_key
        self.registry = registry

    @classmethod
    def generate(
        cls,
        key_id: str = "demo-ed25519-key",
        issuer: str = "user:demo",
        allowed_audiences: tuple[str, ...] = ("*",),
        registry: TrustRegistry | None = None,
    ) -> "EnvelopeSigner":
        private_key = Ed25519PrivateKey.generate()
        trust = registry if registry is not None else TrustRegistry()
        _register_own_identity(
            trust,
            key_id,
            issuer,
            private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            allowed_audiences,
        )
        return cls(key_id, issuer, private_key, trust)

    @classmethod
    def from_private_key_bytes(
        cls,
        key_id: str,
        issuer: str,
        private_key_bytes: bytes,
        allowed_audiences: tuple[str, ...] = ("*",),
        registry: TrustRegistry | None = None,
    ) -> "EnvelopeSigner":
        if len(private_key_bytes) != 32:
            raise ValueError("Ed25519 private keys must be 32 raw bytes")
        private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        trust = registry if registry is not None else TrustRegistry()
        _register_own_identity(
            trust,
            key_id,
            issuer,
            private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            allowed_audiences,
        )
        return cls(key_id, issuer, private_key, trust)

    def sign(self, envelope: AgentEnvelope) -> str:
        return _b64url_encode(self._private_key.sign(canonical_json(envelope.unsigned_dict())))

    def seal(self, envelope: AgentEnvelope) -> AgentEnvelope:
        envelope.signature_key_id = self.key_id
        envelope.signature = self.sign(envelope)
        return envelope

    def verify(self, envelope: AgentEnvelope) -> None:
        identity = self.registry.require_identity(envelope)
        try:
            Ed25519PublicKey.from_public_bytes(identity.public_key).verify(
                _b64url_decode(envelope.signature),
                canonical_json(envelope.unsigned_dict()),
            )
        except (InvalidSignature, ValueError) as error:
            raise SecurityError("agent envelope signature is invalid") from error

    def private_key_pem(self) -> bytes:
        return self._private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    def private_key_b64(self) -> str:
        return _b64url_encode(self._private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))

    def private_key_bytes(self) -> bytes:
        return self._private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign_audit_head(self, task_id: str, host_id: str, head_hash: str, sequence: int) -> str:
        if host_id != self.issuer:
            raise SecurityError("audit head host does not match signing identity")
        return _b64url_encode(self._private_key.sign(canonical_json(audit_head_payload(task_id, host_id, head_hash, sequence))))

    def verify_audit_head(self, key_id: str, payload: dict[str, Any], signature: str) -> None:
        self.registry.verify_audit_head(key_id, payload, signature)


class HmacEnvelopeSigner:
    """Legacy dependency-free demo signer. Do not use for production trust domains."""

    def __init__(self, key: bytes, key_id: str = "legacy-hmac-demo-key") -> None:
        if len(key) < 32:
            raise ValueError("signing keys must contain at least 32 bytes")
        self.key_id = key_id
        self._key = key

    @classmethod
    def generate(cls) -> "HmacEnvelopeSigner":
        return cls(secrets.token_bytes(32))

    def sign(self, envelope: AgentEnvelope) -> str:
        return hmac.new(self._key, canonical_json(envelope.unsigned_dict()), hashlib.sha256).hexdigest()

    def seal(self, envelope: AgentEnvelope) -> AgentEnvelope:
        envelope.signature_key_id = self.key_id
        envelope.signature = self.sign(envelope)
        return envelope

    def verify(self, envelope: AgentEnvelope) -> None:
        if envelope.signature_key_id != self.key_id:
            raise SecurityError("agent envelope signature key id is not trusted")
        expected = self.sign(envelope)
        if not hmac.compare_digest(expected, envelope.signature):
            raise SecurityError("agent envelope signature is invalid")

    def sign_audit_head(self, task_id: str, host_id: str, head_hash: str, sequence: int) -> str:
        return hmac.new(self._key, canonical_json(audit_head_payload(task_id, host_id, head_hash, sequence)), hashlib.sha256).hexdigest()

    def verify_audit_head(self, key_id: str, payload: dict[str, Any], signature: str) -> None:
        if key_id != self.key_id:
            raise SecurityError("audit head signing key is not trusted")
        expected = hmac.new(self._key, canonical_json(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise SecurityError("audit head signature is invalid")


RESERVED_CONSTRAINT_KEYS = frozenset({"arguments", "required", "additional_arguments"})

# Every key `_check_argument_schema` enforces, and how two of them combine so the
# result admits no more than either input. Anything absent from this table is
# unknown, and an unknown key is refused rather than merged: a future key could
# mean "relax", and merging it blindly would create authority.
_SPEC_NARROWERS: dict[str, str] = {
    "type": "type-intersection",
    "const": "identical",
    "enum": "list-intersection",
    "minimum": "numeric-max",
    "maximum": "numeric-min",
    "min_length": "numeric-max",
    "max_length": "numeric-min",
    "pattern": "identical",
    "required": "either-true",
    "scheme": "identical",
    "allowed_schemes": "list-intersection",
    "allowed_hosts": "list-intersection",
    "allowed_domains": "list-intersection",
}


def _permitted_argument_names(constraints: dict[str, Any]) -> set[str] | None:
    """Argument names this constraint set admits, or None when it admits any.

    Mirrors `check_constraints` exactly: `additional_arguments: False` bounds the
    admitted names whether or not an `arguments` schema is present (finding #4).
    When it is not set to False, the grant admits any argument, so return None.
    """
    if constraints.get("additional_arguments", True) is not False:
        return None
    schema = constraints.get("arguments")
    required = constraints.get("required")
    names = _legacy_constrained_arguments(constraints)
    if isinstance(schema, dict):
        names |= set(schema)
    if isinstance(required, (list, tuple)):
        names |= {item for item in required if isinstance(item, str)}
    return names


def _narrow_argument_spec(left: dict[str, Any], right: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """Combine two specs for the same argument. Returns (merged, failing_key)."""
    result: dict[str, Any] = {}
    for key in left.keys() | right.keys():
        rule = _SPEC_NARROWERS.get(key)
        if rule is None:
            return None, key
        if key not in left:
            result[key] = right[key]
            continue
        if key not in right:
            result[key] = left[key]
            continue
        if left[key] == right[key]:
            result[key] = left[key]
            continue
        if rule == "identical":
            return None, key
        if rule == "either-true":
            result[key] = bool(left[key]) or bool(right[key])
            continue
        if rule in {"numeric-max", "numeric-min"}:
            if not all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in (left[key], right[key])):
                return None, key
            result[key] = max(left[key], right[key]) if rule == "numeric-max" else min(left[key], right[key])
            continue
        if rule == "list-intersection":
            if not isinstance(left[key], list) or not isinstance(right[key], list):
                return None, key
            shared = [item for item in left[key] if item in right[key]]
            if not shared:
                return None, key
            result[key] = shared
            continue
        if rule == "type-intersection":
            # `type` accepts a bare string or a list of them, and a value passes
            # if it matches ANY entry, so intersecting the lists narrows. The
            # intersection is set-based, which means "integer" and "number" come
            # out empty and drop the grant rather than trying to rank the two.
            shared = [item for item in _as_type_list(left[key]) if item in _as_type_list(right[key])]
            if not shared:
                return None, key
            result[key] = shared
            continue
        return None, key
    return result, None


def _as_type_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else [value]


def _constraint_intersection(left: dict[str, Any], right: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """Combine two constraint sets so the result admits no more than either input.

    Returns (merged, None) on success, or (None, failing_key) naming the key that
    could not be combined, which is what the "was not granted" diagnostic reports.

    The load-bearing subtlety is that a constraint set's argument-NAME whitelist
    is derived from its own keys. Copying a key across from the other side can
    therefore enlarge that whitelist, so a plain per-key merge widens authority
    even when every individual key is narrowed correctly. The name set is
    intersected first, and every key is then gated on it.
    """
    permitted = _intersect_permitted_names(left, right)
    result: dict[str, Any] = {}

    for key in left.keys() | right.keys():
        if key in RESERVED_CONSTRAINT_KEYS:
            continue
        argument = _constrained_argument_name(key)
        if permitted is not None and argument not in permitted:
            # Every flat constraint also demands the argument be present, so a
            # constraint on an excluded name makes the set unsatisfiable. Drop
            # the grant rather than silently discarding the requirement.
            return None, key
        if key not in left:
            result[key] = right[key]
        elif key not in right:
            result[key] = left[key]
        elif left[key] == right[key]:
            result[key] = left[key]
        elif key.startswith("max_") and all(isinstance(v, (int, float)) for v in (left[key], right[key])):
            result[key] = min(left[key], right[key])
        elif key.startswith("allowed_") and isinstance(left[key], list) and isinstance(right[key], list):
            shared = [v for v in left[key] if v in right[key]]
            if not shared:
                return None, key
            result[key] = shared
        else:
            return None, key

    merged_schema, failing_key = _merge_argument_schemas(left, right, permitted)
    if failing_key is not None:
        return None, failing_key
    if merged_schema is not None:
        result["arguments"] = merged_schema

    merged_required, failing_key = _merge_required(left, right, permitted)
    if failing_key is not None:
        return None, failing_key
    if merged_required is not None:
        result["required"] = merged_required

    additional, failing_key = _merge_additional_arguments(left, right)
    if failing_key is not None:
        return None, failing_key
    if additional is not None:
        result["additional_arguments"] = additional
    return result, None


def _intersect_permitted_names(left: dict[str, Any], right: dict[str, Any]) -> set[str] | None:
    left_names = _permitted_argument_names(left)
    right_names = _permitted_argument_names(right)
    if left_names is None:
        return right_names
    if right_names is None:
        return left_names
    return left_names & right_names


def _constrained_argument_name(key: str) -> str:
    if key.startswith("max_"):
        return key[4:]
    if key.startswith("allowed_"):
        return key[8:]
    return key


def _merge_argument_schemas(
    left: dict[str, Any], right: dict[str, Any], permitted: set[str] | None
) -> tuple[dict[str, Any] | None, str | None]:
    left_schema = left.get("arguments")
    right_schema = right.get("arguments")
    if left_schema is None and right_schema is None:
        return None, None
    for schema in (left_schema, right_schema):
        if schema is not None and not isinstance(schema, dict):
            return None, "arguments"
    left_schema = left_schema or {}
    right_schema = right_schema or {}

    merged: dict[str, Any] = {}
    for name in left_schema.keys() | right_schema.keys():
        left_spec = left_schema.get(name)
        right_spec = right_schema.get(name)
        for spec in (left_spec, right_spec):
            if spec is not None and not isinstance(spec, dict):
                return None, f"arguments.{name}"
        if permitted is not None and name not in permitted:
            # The name is refused outright by the merged whitelist. Dropping a
            # dead spec is safe; dropping one that demands the argument be
            # present is not, because the set is then unsatisfiable.
            if (left_spec or {}).get("required") is True or (right_spec or {}).get("required") is True:
                return None, f"arguments.{name}"
            continue
        if left_spec is None:
            merged[name] = right_spec
            continue
        if right_spec is None:
            merged[name] = left_spec
            continue
        spec, failing_key = _narrow_argument_spec(left_spec, right_spec)
        if spec is None:
            return None, f"arguments.{name}.{failing_key}"
        merged[name] = spec
    return merged, None


def _merge_required(
    left: dict[str, Any], right: dict[str, Any], permitted: set[str] | None
) -> tuple[list[str] | None, str | None]:
    names: set[str] = set()
    seen = False
    for side in (left, right):
        value = side.get("required")
        if value is None:
            continue
        if not isinstance(value, (list, tuple)):
            return None, "required"
        seen = True
        names |= set(value)
    if not seen:
        return None, None
    if permitted is not None and not names <= permitted:
        return None, "required"
    return sorted(names), None


def _merge_additional_arguments(left: dict[str, Any], right: dict[str, Any]) -> tuple[bool | None, str | None]:
    values = [side["additional_arguments"] for side in (left, right) if "additional_arguments" in side]
    if not values:
        return None, None
    if not all(isinstance(value, bool) for value in values):
        return None, "additional_arguments"
    return all(values), None


def intersect_grants(*grant_sets: tuple[ToolGrant, ...]) -> tuple[ToolGrant, ...]:
    if not grant_sets:
        return ()
    current = {grant.name: grant for grant in grant_sets[0]}
    for grants in grant_sets[1:]:
        incoming = {grant.name: grant for grant in grants}
        next_current: dict[str, ToolGrant] = {}
        for name in current.keys() & incoming.keys():
            constraints, _ = _constraint_intersection(current[name].constraints, incoming[name].constraints)
            if constraints is not None:
                next_current[name] = ToolGrant(
                    name,
                    constraints,
                    _projection_intersection(current[name].output_projection, incoming[name].output_projection),
                )
        current = next_current
    return tuple(current[name] for name in sorted(current))


def _projection_intersection(left: tuple[str, ...] | None, right: tuple[str, ...] | None) -> tuple[str, ...] | None:
    if left is None:
        return right
    if right is None:
        return left
    if not left or not right:
        return ()
    if "*" in left:
        return right
    if "*" in right:
        return left
    return tuple(item for item in left if item in set(right))


class HostPolicy:
    DEFAULT_APPROVAL_REQUIRED_IMPACTS = ("high", "destructive", "external-payment", "credentialed", "data-exfiltration")

    def __init__(
        self,
        audience: str,
        grants: tuple[ToolGrant, ...],
        budget: ResourceBudget,
        policy_version: str = "inline-demo",
        policy_hash: str = "inline-demo",
        tool_impacts: dict[str, str] | None = None,
        approval_authorities: tuple[TrustedApprover, ...] = (),
        approval_required_impacts: tuple[str, ...] = DEFAULT_APPROVAL_REQUIRED_IMPACTS,
    ) -> None:
        self.audience = audience
        self.grants = grants
        self.budget = budget
        self.policy_version = policy_version
        self.policy_hash = policy_hash
        self.tool_impacts = tool_impacts or {}
        self.approval_required_impacts = approval_required_impacts
        self._approval_authorities = {authority.key_id: authority for authority in approval_authorities}

    def effective_permit(self, manifest: AgentManifest, permit: Permit, now: int | None = None) -> Permit:
        current_time = int(time.time()) if now is None else now
        if permit.subject != manifest.agent_id:
            raise SecurityError("permit subject does not match agent")
        if permit.audience != self.audience:
            raise SecurityError("permit is not intended for this host")
        if permit.expires_at <= current_time:
            raise SecurityError("permit has expired")
        requested = tuple(ToolGrant(name) for name in manifest.requested_tools)
        grants = intersect_grants(requested, permit.grants, self.grants)
        return Permit(
            issuer=permit.issuer,
            subject=permit.subject,
            audience=permit.audience,
            expires_at=permit.expires_at,
            nonce=permit.nonce,
            grants=grants,
            budget=permit.budget.intersect(self.budget),
            delegation_allowed=False,
            attestation=permit.attestation,
        )

    def explain_missing_grant(self, manifest: AgentManifest, permit: Permit, tool: str) -> str:
        """Say which stage of the intersection removed a tool, and why.

        `effective_permit` folds three grant sets together and reports only the
        absence, so every misconfiguration produces the same message and points
        the operator at their envelope — the one place that is often not wrong.
        This recomputes the chain on the error path, where the cost does not
        matter, and names the stage that actually dropped the tool.
        """
        if tool not in manifest.requested_tools:
            return (
                f"tool {tool!r} was not granted: the agent manifest does not request it. "
                f"Requested tools are {sorted(manifest.requested_tools) or 'none'}."
            )
        permit_grant = next((grant for grant in permit.grants if grant.name == tool), None)
        if permit_grant is None:
            return (
                f"tool {tool!r} was not granted: it is requested by the manifest but absent "
                f"from the permit. Permit grants are {sorted(grant.name for grant in permit.grants) or 'none'}."
            )
        policy_grant = next((grant for grant in self.grants if grant.name == tool), None)
        if policy_grant is None:
            return (
                f"tool {tool!r} was not granted: host policy {self.policy_version!r} does not "
                f"grant it. Policy grants are {sorted(grant.name for grant in self.grants) or 'none'}. "
                "The host policy is a ceiling, so no permit can add a tool it omits."
            )

        merged: dict[str, Any] = {}
        for stage, grant in (("permit", permit_grant), (f"host policy {self.policy_version!r}", policy_grant)):
            merged_next, failing_key = _constraint_intersection(merged, grant.constraints)
            if merged_next is None:
                return (
                    f"tool {tool!r} was not granted: it is granted by the manifest, the permit and "
                    f"host policy {self.policy_version!r}, but their constraints could not be combined. "
                    f"Constraint {failing_key!r} from the {stage} could not be narrowed against what "
                    "came before it. Portmark refuses a merge it cannot prove is narrower, so the "
                    "grant is dropped rather than widened. Define this constraint in one place — "
                    "usually the host policy — instead of both."
                )
            merged = merged_next
        return (
            f"tool {tool!r} was not granted, and the cause could not be reproduced. "
            "The permit may have expired or been replaced between the check and this message."
        )

    def impact_for_tool(self, tool: str) -> str:
        return self.tool_impacts.get(tool, "low")

    def requires_approval(self, tool: str) -> bool:
        return self.impact_for_tool(tool) in set(self.approval_required_impacts)

    def verify_approval(
        self,
        token: ApprovalToken,
        permit: Permit,
        task_id: str,
        tool: str,
        arguments: dict[str, Any],
        now: int | None = None,
    ) -> None:
        authority = self._approval_authorities.get(token.signature_key_id)
        if authority is None:
            raise SecurityError("approval signer is not trusted")
        current_time = int(time.time()) if now is None else now
        if authority.revoked:
            raise SecurityError("approval signer has been revoked")
        if authority.not_before > current_time:
            raise SecurityError("approval signer is not active yet")
        if authority.expires_at is not None and authority.expires_at <= current_time:
            raise SecurityError("approval signer has expired")
        if token.approved_by != authority.approver:
            raise SecurityError("approval signer identity does not match key")
        if token.tool != tool:
            raise SecurityError("approval tool does not match request")
        if token.subject != permit.subject:
            raise SecurityError("approval subject does not match permit")
        if token.audience != permit.audience:
            raise SecurityError("approval audience does not match permit")
        if token.task_id != task_id:
            raise SecurityError("approval task does not match request")
        if token.permit_nonce != permit.nonce:
            raise SecurityError("approval does not match permit nonce")
        if token.policy_hash != self.policy_hash:
            raise SecurityError("approval policy hash does not match active policy")
        if token.arguments_hash != arguments_hash(arguments):
            raise SecurityError("approval arguments do not match request")
        if token.issued_at > current_time:
            raise SecurityError("approval is not active yet")
        if token.expires_at <= current_time:
            raise SecurityError("approval has expired")
        try:
            Ed25519PublicKey.from_public_bytes(authority.public_key).verify(
                _b64url_decode(token.signature),
                canonical_json(token.unsigned_dict()),
            )
        except (InvalidSignature, ValueError) as error:
            raise SecurityError("approval signature is invalid") from error


class AuditLog:
    def __init__(self, previous_hash: str = "", start_sequence: int = 0) -> None:
        self._head = previous_hash
        self._start_sequence = start_sequence
        self._events: list[dict[str, Any]] = []

    @property
    def head(self) -> str:
        return self._head

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._events)

    def append(self, event: str, details: dict[str, Any]) -> None:
        record = {"sequence": self._start_sequence + len(self._events), "event": event, "details": details, "previous": self._head}
        record_hash = hashlib.sha256(canonical_json(record)).hexdigest()
        record["hash"] = record_hash
        self._events.append(record)
        self._head = record_hash


def check_constraints(constraints: dict[str, Any], arguments: dict[str, Any]) -> None:
    schema = constraints.get("arguments")
    required = _required_arguments(constraints.get("required", ()))
    additional = constraints.get("additional_arguments", True)
    if not isinstance(additional, bool):
        raise SecurityError("additional_arguments constraint must be boolean")
    if schema is not None:
        if not isinstance(schema, dict):
            raise SecurityError("argument constraints must be an object")
        for name in required:
            if name not in arguments:
                raise SecurityError(f"argument {name!r} is required")
        for argument, spec in schema.items():
            if not isinstance(argument, str) or not argument:
                raise SecurityError("argument constraint names must be non-empty strings")
            if not isinstance(spec, dict):
                raise SecurityError(f"argument {argument!r} constraint must be an object")
            if spec.get("required") is True and argument not in arguments:
                raise SecurityError(f"argument {argument!r} is required")
            if argument in arguments:
                _check_argument_schema(argument, arguments[argument], spec)
    if additional is False:
        # Reject unexpected fields even when the grant carries only flat
        # constraints (no `arguments` schema). Previously this was nested under
        # `if schema is not None`, so a flat-only grant silently passed extras
        # like account_id. Finding #4. Kept consistent with
        # `_permitted_argument_names`, which the merge planner uses.
        known = set(required) | _legacy_constrained_arguments(constraints)
        if isinstance(schema, dict):
            known |= set(schema)
        unexpected = set(arguments) - known
        if unexpected:
            raise SecurityError("tool arguments contain unsupported fields")
    for name, expected in constraints.items():
        if name in {"arguments", "required", "additional_arguments"}:
            continue
        if name.startswith("max_"):
            argument = name[4:]
            actual = arguments.get(argument)
            if actual is None or not isinstance(actual, (int, float)) or actual > expected:
                raise SecurityError(f"argument {argument!r} exceeds its permitted maximum")
        elif name.startswith("allowed_"):
            # `expected` must be a collection. A scalar string would make `in` a
            # substring test ("admin" accepting "a"), silently widening authority
            # on a mistyped policy. Fail closed on non-list. Finding #5.
            if not isinstance(expected, (list, tuple, set)):
                raise SecurityError(f"{name} constraint must be a list")
            argument = name[8:]
            if arguments.get(argument) not in expected:
                raise SecurityError(f"argument {argument!r} is outside its allowed set")
        elif arguments.get(name) != expected:
            raise SecurityError(f"argument {name!r} does not match its required value")


def _required_arguments(value: Any) -> tuple[str, ...]:
    if value in (None, ()):
        return ()
    if not isinstance(value, (list, tuple)):
        raise SecurityError("required argument constraints must be a list")
    if not all(isinstance(item, str) and item for item in value):
        raise SecurityError("required argument constraints must be non-empty strings")
    return tuple(value)


def _legacy_constrained_arguments(constraints: dict[str, Any]) -> set[str]:
    result = set()
    for name in constraints:
        if name.startswith("max_"):
            result.add(name[4:])
        elif name.startswith("allowed_"):
            result.add(name[8:])
        elif name not in {"arguments", "required", "additional_arguments"}:
            result.add(name)
    return result


def _check_argument_schema(name: str, value: Any, spec: dict[str, Any]) -> None:
    expected_type = spec.get("type")
    if expected_type is not None and not _matches_type(value, expected_type):
        raise SecurityError(f"argument {name!r} has invalid type")
    if "const" in spec and value != spec["const"]:
        raise SecurityError(f"argument {name!r} does not match its required value")
    enum = spec.get("enum")
    if enum is not None:
        if not isinstance(enum, list) or not enum:
            raise SecurityError(f"argument {name!r} enum constraint must be a non-empty list")
        if value not in enum:
            raise SecurityError(f"argument {name!r} is outside its allowed set")
    if "minimum" in spec:
        if not isinstance(spec["minimum"], (int, float)) or isinstance(spec["minimum"], bool):
            raise SecurityError(f"argument {name!r} minimum constraint must be numeric")
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < spec["minimum"]:
            raise SecurityError(f"argument {name!r} is below its permitted minimum")
    if "maximum" in spec:
        if not isinstance(spec["maximum"], (int, float)) or isinstance(spec["maximum"], bool):
            raise SecurityError(f"argument {name!r} maximum constraint must be numeric")
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value > spec["maximum"]:
            raise SecurityError(f"argument {name!r} exceeds its permitted maximum")
    if "min_length" in spec:
        if not isinstance(spec["min_length"], int) or isinstance(spec["min_length"], bool) or spec["min_length"] < 0:
            raise SecurityError(f"argument {name!r} min_length constraint must be a non-negative integer")
        if not isinstance(value, str) or len(value) < spec["min_length"]:
            raise SecurityError(f"argument {name!r} is shorter than its permitted minimum length")
    if "max_length" in spec:
        if not isinstance(spec["max_length"], int) or isinstance(spec["max_length"], bool) or spec["max_length"] < 0:
            raise SecurityError(f"argument {name!r} max_length constraint must be a non-negative integer")
        if not isinstance(value, str) or len(value) > spec["max_length"]:
            raise SecurityError(f"argument {name!r} exceeds its permitted maximum length")
    pattern = spec.get("pattern")
    if pattern is not None:
        import re

        if not isinstance(pattern, str):
            raise SecurityError(f"argument {name!r} pattern constraint must be a string")
        try:
            matched = re.fullmatch(pattern, value) if isinstance(value, str) else None
        except re.error as error:
            raise SecurityError(f"argument {name!r} pattern constraint is invalid") from error
        if matched is None:
            raise SecurityError(f"argument {name!r} does not match its required pattern")
    _check_url_constraints(name, value, spec)


def _matches_type(value: Any, expected_type: Any) -> bool:
    types = expected_type if isinstance(expected_type, list) else [expected_type]
    if not all(isinstance(item, str) for item in types):
        raise SecurityError("argument type constraints must be strings")
    for item in types:
        if item == "string" and isinstance(value, str):
            return True
        if item == "integer" and isinstance(value, int) and not isinstance(value, bool):
            return True
        if item == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
            return True
        if item == "boolean" and isinstance(value, bool):
            return True
        if item == "object" and isinstance(value, dict):
            return True
        if item == "array" and isinstance(value, list):
            return True
        if item == "null" and value is None:
            return True
    return False


def _check_url_constraints(name: str, value: Any, spec: dict[str, Any]) -> None:
    has_url_constraint = any(key in spec for key in ("scheme", "allowed_schemes", "allowed_hosts", "allowed_domains"))
    if not has_url_constraint:
        return
    if not isinstance(value, str):
        raise SecurityError(f"argument {name!r} URL must be a string")
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.hostname:
        raise SecurityError(f"argument {name!r} must be an absolute URL")
    if parsed.username is not None or parsed.password is not None:
        raise SecurityError(f"argument {name!r} must not contain userinfo")
    host = parsed.hostname.rstrip(".").lower()
    scheme = spec.get("scheme")
    if scheme is not None:
        if not isinstance(scheme, str) or not scheme:
            raise SecurityError(f"argument {name!r} scheme constraint must be a non-empty string")
        if parsed.scheme.lower() != scheme.lower():
            raise SecurityError(f"argument {name!r} URL scheme must be {scheme.lower()}")
    allowed_schemes = spec.get("allowed_schemes")
    if allowed_schemes is not None:
        schemes = _non_empty_string_tuple(allowed_schemes, f"argument {name!r} allowed_schemes")
        if parsed.scheme.lower() not in {item.lower() for item in schemes}:
            raise SecurityError(f"argument {name!r} URL scheme is outside its allowed set")
    allowed_hosts = spec.get("allowed_hosts")
    if allowed_hosts is not None:
        hosts = _normalized_hosts(allowed_hosts, f"argument {name!r} allowed_hosts")
        if host not in hosts:
            raise SecurityError(f"argument {name!r} host is outside its allowed set")
    allowed_domains = spec.get("allowed_domains")
    if allowed_domains is not None:
        domains = _normalized_hosts(allowed_domains, f"argument {name!r} allowed_domains")
        if not any(host == domain or host.endswith(f".{domain}") for domain in domains):
            raise SecurityError(f"argument {name!r} domain is outside its allowed set")


def _non_empty_string_tuple(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise SecurityError(f"{label} must be a non-empty list")
    if not all(isinstance(item, str) and item for item in value):
        raise SecurityError(f"{label} entries must be non-empty strings")
    return tuple(value)


def _normalized_hosts(value: Any, label: str) -> set[str]:
    return {item.rstrip(".").lower() for item in _non_empty_string_tuple(value, label)}

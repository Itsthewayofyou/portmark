from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

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
    ) -> None:
        self._authorities = {authority.key_id: authority for authority in authorities}
        self.allowed_measurements = allowed_measurements
        self.required_for_execution = required_for_execution
        self.required_for_migration = required_for_migration

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
        authority = self._authorities.get(evidence.signature_key_id)
        if authority is None:
            raise SecurityError("attestation verifier key is not trusted")
        current_time = int(time.time()) if now is None else now
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
        try:
            Ed25519PublicKey.from_public_bytes(authority.public_key).verify(
                _b64url_decode(evidence.signature),
                canonical_json(evidence.unsigned_dict()),
            )
        except (InvalidSignature, ValueError) as error:
            raise SecurityError("attestation signature is invalid") from error


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
    ) -> "EnvelopeSigner":
        private_key = Ed25519PrivateKey.generate()
        registry = TrustRegistry()
        registry.add(
            TrustedIdentity(
                key_id=key_id,
                issuer=issuer,
                public_key=private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                allowed_audiences=allowed_audiences,
            )
        )
        return cls(key_id, issuer, private_key, registry)

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
        trust = registry or TrustRegistry()
        if not trust.has_key(key_id):
            trust.add(
                TrustedIdentity(
                    key_id=key_id,
                    issuer=issuer,
                    public_key=private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                    allowed_audiences=allowed_audiences,
                )
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


def _constraint_intersection(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any] | None:
    result: dict[str, Any] = {}
    for key in left.keys() | right.keys():
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
                return None
            result[key] = shared
        else:
            return None
    return result


def intersect_grants(*grant_sets: tuple[ToolGrant, ...]) -> tuple[ToolGrant, ...]:
    if not grant_sets:
        return ()
    current = {grant.name: grant for grant in grant_sets[0]}
    for grants in grant_sets[1:]:
        incoming = {grant.name: grant for grant in grants}
        next_current: dict[str, ToolGrant] = {}
        for name in current.keys() & incoming.keys():
            constraints = _constraint_intersection(current[name].constraints, incoming[name].constraints)
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
    for name, expected in constraints.items():
        if name.startswith("max_"):
            argument = name[4:]
            actual = arguments.get(argument)
            if actual is None or not isinstance(actual, (int, float)) or actual > expected:
                raise SecurityError(f"argument {argument!r} exceeds its permitted maximum")
        elif name.startswith("allowed_"):
            argument = name[8:]
            if arguments.get(argument) not in expected:
                raise SecurityError(f"argument {argument!r} is outside its allowed set")
        elif arguments.get(name) != expected:
            raise SecurityError(f"argument {name!r} does not match its required value")

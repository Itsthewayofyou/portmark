from __future__ import annotations

import hashlib
import os
import shlex
import secrets
import time

from .host import AgentHost
from .metrics import RuntimeMetrics
from .models import AgentEnvelope, AgentManifest, AgentState, Permit, ResourceBudget, ToolGrant
from .policy import load_host_policy
from .providers import DeterministicProvider, GenericHttpProvider, ModelProvider, NativeWasmtimeComponentProvider, WasmDecisionProvider
from .security import AttestationPolicy, EnvelopeSigner, EnvelopeSigningIdentity, ExternalAttestationVerifier, HmacEnvelopeSigner, HostPolicy, load_trust_registry, validate_constraints
from .storage import RuntimeStore, create_runtime_store
from .tools import ToolRegistry, demo_registry


HOST_ID = "host:local-demo"


def signer_from_environment(host_id: str = HOST_ID, trust_registry_path: str | None = None) -> EnvelopeSigningIdentity:
    registry = load_trust_registry(trust_registry_path) if trust_registry_path else None
    raw_private_key = os.environ.get("PORTMARK_ED25519_PRIVATE_KEY_B64")
    if raw_private_key:
        import base64

        padding = "=" * (-len(raw_private_key) % 4)
        private_key = base64.urlsafe_b64decode(raw_private_key + padding)
        return EnvelopeSigner.from_private_key_bytes(
            os.environ.get("PORTMARK_SIGNING_KEY_ID", "env-ed25519-key"),
            os.environ.get("PORTMARK_SIGNING_ISSUER", host_id),
            private_key,
            tuple(os.environ.get("PORTMARK_ALLOWED_AUDIENCES", host_id).split(",")),
            registry,
        )
    if os.environ.get("PORTMARK_ALLOW_LEGACY_HMAC") == "unsafe-test-only":
        raw = os.environ.get("PORTMARK_SIGNING_KEY")
        if not raw:
            raise RuntimeError("legacy HMAC signing requires PORTMARK_SIGNING_KEY")
        return HmacEnvelopeSigner(hashlib.sha256(raw.encode()).digest())
    if os.environ.get("PORTMARK_ALLOW_LEGACY_HMAC"):
        raise RuntimeError("legacy HMAC signing requires PORTMARK_ALLOW_LEGACY_HMAC=unsafe-test-only")
    return EnvelopeSigner.generate(issuer=host_id, allowed_audiences=(host_id,), registry=registry)


def make_host(
    provider_endpoint: str | None = None,
    host_id: str = HOST_ID,
    signer: EnvelopeSigningIdentity | None = None,
    wasm_component: str | None = None,
    wasm_engine: str = "node",
    store: RuntimeStore | None = None,
    attestation_policy: AttestationPolicy | None = None,
    attestation_verifier_command: tuple[str, ...] | str | None = None,
    require_attestation: bool | None = None,
    metrics: RuntimeMetrics | None = None,
    policy_path: str | None = None,
    trust_registry_path: str | None = None,
    reload_policy: bool = False,
    tools: ToolRegistry | None = None,
    providers: dict[str, ModelProvider] | None = None,
) -> AgentHost:
    # Note the asymmetry with `tools`, which REPLACES the demo registry.
    # Providers merge over the constructed defaults instead, so passing an
    # in-process provider does not silently remove `deterministic` and break
    # every envelope that names it. Callers can still shadow a default by
    # reusing its key.
    configured_providers: dict[str, ModelProvider] = {"deterministic": DeterministicProvider()}
    if provider_endpoint:
        configured_providers["http"] = GenericHttpProvider(provider_endpoint, os.environ.get("MODEL_PROVIDER_TOKEN"))
    if wasm_component:
        if wasm_engine == "wasmtime":
            configured_providers["wasm"] = NativeWasmtimeComponentProvider.from_file(wasm_component)
        elif wasm_engine == "node":
            configured_providers["wasm"] = WasmDecisionProvider.from_file(wasm_component)
        else:
            raise ValueError("wasm_engine must be 'node' or 'wasmtime'")
    if providers:
        configured_providers.update(providers)
    configured_policy_path = policy_path or os.environ.get("PORTMARK_POLICY_PATH")
    configured_trust_registry_path = trust_registry_path or os.environ.get("PORTMARK_TRUST_REGISTRY_PATH")
    policy_loader = (lambda: load_host_policy(configured_policy_path, host_id)) if configured_policy_path else None
    policy = policy_loader() if policy_loader else HostPolicy(
        host_id,
        # Finding #1: host policy is the projection ceiling, and an omitted
        # output_projection now means share-nothing. The demo capsule reads the
        # search result back from its projected state, so the host must explicitly
        # grant the fields it is willing to expose (id + title, not score).
        grants=(
            ToolGrant("catalog.search", {"max_limit": 5}, ("id", "title")),
            ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}),
        ),
        budget=ResourceBudget(max_steps=10, max_tool_calls=5, max_output_bytes=65_536),
        tool_impacts={"catalog.search": "low", "payments.reserve": "external-payment"},
    )
    configured_store = store
    if configured_store is None and os.environ.get("PORTMARK_STORE_PATH"):
        audit_verifier = load_trust_registry(configured_trust_registry_path) if configured_trust_registry_path else None
        configured_store = create_runtime_store(
            os.environ.get("PORTMARK_STORE_BACKEND", "sqlite"),
            os.environ["PORTMARK_STORE_PATH"],
            audit_verifier,
        )
    configured_attestation_policy = attestation_policy
    if configured_attestation_policy is None:
        command = attestation_verifier_command or os.environ.get("PORTMARK_ATTESTATION_VERIFIER_COMMAND")
        required = (os.environ.get("PORTMARK_REQUIRE_ATTESTATION") == "1") if require_attestation is None else require_attestation
        if command or required:
            argv = tuple(shlex.split(command)) if isinstance(command, str) else command
            verifier = ExternalAttestationVerifier(argv) if argv else None
            configured_attestation_policy = AttestationPolicy(
                required_for_execution=required,
                required_for_migration=required,
                external_verifier=verifier,
            )
    host_signer = signer or signer_from_environment(host_id, configured_trust_registry_path)
    signing_issuer = getattr(host_signer, "issuer", host_id)
    if signing_issuer != host_id:
        # Every run signs an audit head with the host id as issuer, so this config
        # can only ever fail on the first request. Fail at boot and name both values
        # instead. Usually means an agent's PORTMARK_SIGNING_ISSUER leaked into the
        # server's environment -- keygen exports belong in the client's shell only.
        raise ValueError(
            f"host signing issuer {signing_issuer!r} must equal host id {host_id!r}; "
            "unset PORTMARK_SIGNING_ISSUER/PORTMARK_ED25519_PRIVATE_KEY_B64 for the host process, "
            "or start it with --host-id matching the signing issuer"
        )
    return AgentHost(
        host_id,
        host_signer,
        policy,
        tools if tools is not None else demo_registry(),
        configured_providers,
        configured_store,
        configured_attestation_policy,
        policy_loader,
        reload_policy,
        metrics,
    )


SPEC_FIELDS = frozenset(
    {"agent_id", "version", "provider", "component_digest", "goal", "issuer", "audience", "ttl_seconds", "grants", "budget", "requested_tools"}
)
GRANT_FIELDS = frozenset({"name", "constraints", "output_projection"})
BUDGET_FIELDS = frozenset({"max_steps", "max_tool_calls", "max_output_bytes"})


def _reject_unknown(value: dict, allowed: frozenset[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"unknown {label} fields: {', '.join(unknown)}")


def _grant_from_spec(value: object) -> ToolGrant:
    if not isinstance(value, dict):
        raise ValueError("each entry in 'grants' must be an object")
    _reject_unknown(value, GRANT_FIELDS, "grant")
    name = value.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("each grant requires a non-empty 'name'")
    constraints = value.get("constraints") or {}
    if not isinstance(constraints, dict):
        raise ValueError(f"grant {name!r} constraints must be an object")
    # Finding #5: reject unknown argument-spec keys (typos) at decode, not silently at runtime.
    validate_constraints(constraints)
    projection = value.get("output_projection")
    if projection is not None and not isinstance(projection, list):
        raise ValueError(f"grant {name!r} output_projection must be a list")
    return ToolGrant(name, dict(constraints), tuple(projection) if projection else None)


def build_envelope(spec: dict, signer: EnvelopeSigningIdentity) -> AgentEnvelope:
    """Build and sign an envelope from a plain JSON spec, without constructing a host.

    The signing key belongs to whoever sends the agent; the host that runs it only
    ever verifies. Keeping this host-free is what makes an envelope portable, so
    the spec carries `component_digest` rather than reading it off a live provider.
    """
    if not isinstance(spec, dict):
        raise ValueError("envelope spec must be a JSON object")
    _reject_unknown(spec, SPEC_FIELDS, "envelope spec")
    goal = spec.get("goal")
    if not isinstance(goal, str) or not goal.strip():
        raise ValueError("envelope spec requires a non-empty 'goal'")
    raw_grants = spec.get("grants")
    if not isinstance(raw_grants, list) or not raw_grants:
        raise ValueError("envelope spec requires a non-empty 'grants' list")
    grants = tuple(_grant_from_spec(entry) for entry in raw_grants)
    requested = spec.get("requested_tools")
    if requested is not None and not isinstance(requested, list):
        raise ValueError("envelope spec 'requested_tools' must be a list")
    requested_tools = tuple(requested) if requested is not None else tuple(grant.name for grant in grants)
    budget_spec = spec.get("budget") or {}
    if not isinstance(budget_spec, dict):
        raise ValueError("envelope spec 'budget' must be an object")
    _reject_unknown(budget_spec, BUDGET_FIELDS, "budget")
    budget = ResourceBudget(
        max_steps=int(budget_spec.get("max_steps", 6)),
        max_tool_calls=int(budget_spec.get("max_tool_calls", 2)),
        max_output_bytes=int(budget_spec.get("max_output_bytes", 32_768)),
    )
    agent_id = str(spec.get("agent_id", "agent:portable"))
    manifest = AgentManifest(
        agent_id,
        str(spec.get("version", "1.0.0")),
        str(spec.get("provider", "deterministic")),
        requested_tools,
        str(spec.get("component_digest", "python:reference-agent-v1")),
    )
    permit = Permit(
        issuer=str(spec.get("issuer") or getattr(signer, "issuer", HOST_ID)),
        subject=agent_id,
        audience=str(spec.get("audience", HOST_ID)),
        expires_at=int(time.time()) + int(spec.get("ttl_seconds", 3600)),
        # Always fresh: the host consumes the nonce, so a replayed envelope is refused.
        nonce=secrets.token_hex(16),
        grants=grants,
        budget=budget,
    )
    return signer.seal(AgentEnvelope(manifest, permit, AgentState(secrets.token_hex(8), goal)))


def make_demo_envelope(host: AgentHost, goal: str, provider: str = "deterministic") -> AgentEnvelope:
    configured = host.providers.get(provider)
    digest = getattr(configured, "component_digest", "python:reference-agent-v1")
    manifest = AgentManifest("agent:demo", "1.0.0", provider, ("catalog.search", "payments.reserve"), digest)
    permit = Permit(
        issuer=getattr(host.signer, "issuer", host.host_id), subject=manifest.agent_id, audience=host.host_id,
        expires_at=int(time.time()) + 3600, nonce=secrets.token_hex(16),
        grants=(ToolGrant("catalog.search", {"max_limit": 3}, ("id", "title")),),
        budget=ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=32_768),
    )
    return host.signer.seal(AgentEnvelope(manifest, permit, AgentState(secrets.token_hex(8), goal)))

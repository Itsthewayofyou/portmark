from __future__ import annotations

import hashlib
import os
import secrets
import time

from .host import AgentHost
from .models import AgentEnvelope, AgentManifest, AgentState, Permit, ResourceBudget, ToolGrant
from .policy import load_host_policy
from .providers import DeterministicProvider, GenericHttpProvider, WasmDecisionProvider
from .security import AttestationPolicy, EnvelopeSigner, EnvelopeSigningIdentity, HmacEnvelopeSigner, HostPolicy, load_trust_registry
from .storage import RuntimeStore, SQLiteRuntimeStore
from .tools import demo_registry


HOST_ID = "host:local-demo"


def signer_from_environment(host_id: str = HOST_ID, trust_registry_path: str | None = None) -> EnvelopeSigningIdentity:
    registry = load_trust_registry(trust_registry_path) if trust_registry_path else None
    raw_private_key = os.environ.get("PORTABLE_AGENT_ED25519_PRIVATE_KEY_B64")
    if raw_private_key:
        import base64

        padding = "=" * (-len(raw_private_key) % 4)
        private_key = base64.urlsafe_b64decode(raw_private_key + padding)
        return EnvelopeSigner.from_private_key_bytes(
            os.environ.get("PORTABLE_AGENT_SIGNING_KEY_ID", "env-ed25519-key"),
            os.environ.get("PORTABLE_AGENT_SIGNING_ISSUER", host_id),
            private_key,
            tuple(os.environ.get("PORTABLE_AGENT_ALLOWED_AUDIENCES", host_id).split(",")),
            registry,
        )
    if os.environ.get("PORTABLE_AGENT_ALLOW_LEGACY_HMAC") == "1":
        raw = os.environ.get("PORTABLE_AGENT_SIGNING_KEY", "development-only-signing-key-change-me")
        return HmacEnvelopeSigner(hashlib.sha256(raw.encode()).digest())
    return EnvelopeSigner.generate(issuer=host_id, allowed_audiences=(host_id,))


def make_host(
    provider_endpoint: str | None = None,
    host_id: str = HOST_ID,
    signer: EnvelopeSigningIdentity | None = None,
    wasm_component: str | None = None,
    store: RuntimeStore | None = None,
    attestation_policy: AttestationPolicy | None = None,
    policy_path: str | None = None,
    trust_registry_path: str | None = None,
    reload_policy: bool = False,
) -> AgentHost:
    providers = {"deterministic": DeterministicProvider()}
    if provider_endpoint:
        providers["http"] = GenericHttpProvider(provider_endpoint, os.environ.get("MODEL_PROVIDER_TOKEN"))
    if wasm_component:
        providers["wasm"] = WasmDecisionProvider.from_file(wasm_component)
    configured_policy_path = policy_path or os.environ.get("PORTABLE_AGENT_POLICY_PATH")
    configured_trust_registry_path = trust_registry_path or os.environ.get("PORTABLE_AGENT_TRUST_REGISTRY_PATH")
    policy_loader = (lambda: load_host_policy(configured_policy_path, host_id)) if configured_policy_path else None
    policy = policy_loader() if policy_loader else HostPolicy(
        host_id,
        grants=(ToolGrant("catalog.search", {"max_limit": 5}), ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"})),
        budget=ResourceBudget(max_steps=10, max_tool_calls=5, max_output_bytes=65_536),
        tool_impacts={"catalog.search": "low", "payments.reserve": "external-payment"},
    )
    configured_store = store
    if configured_store is None and os.environ.get("PORTABLE_AGENT_STORE_PATH"):
        configured_store = SQLiteRuntimeStore(os.environ["PORTABLE_AGENT_STORE_PATH"])
    return AgentHost(
        host_id,
        signer or signer_from_environment(host_id, configured_trust_registry_path),
        policy,
        demo_registry(),
        providers,
        configured_store,
        attestation_policy,
        policy_loader,
        reload_policy,
    )


def make_demo_envelope(host: AgentHost, goal: str, provider: str = "deterministic") -> AgentEnvelope:
    configured = host.providers.get(provider)
    digest = getattr(configured, "component_digest", "python:reference-agent-v1")
    manifest = AgentManifest("agent:demo", "1.0.0", provider, ("catalog.search", "payments.reserve"), digest)
    permit = Permit(
        issuer=getattr(host.signer, "issuer", host.host_id), subject=manifest.agent_id, audience=host.host_id,
        expires_at=int(time.time()) + 3600, nonce=secrets.token_hex(16),
        grants=(ToolGrant("catalog.search", {"max_limit": 3}),),
        budget=ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=32_768),
    )
    return host.signer.seal(AgentEnvelope(manifest, permit, AgentState(secrets.token_hex(8), goal)))

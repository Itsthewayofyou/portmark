from __future__ import annotations

import hashlib
import logging
import os
import shlex
import secrets
from pathlib import Path

from .config import ALLOWED_MEASUREMENTS_ENV, DEVELOPMENT_PROFILE, PREFLIGHT_COMMAND_ENV, PROFILE_ENV, parse_allowed_measurements
from .host import AgentHost
from .metrics import RuntimeMetrics
from .models import AgentEnvelope, AgentManifest, AgentState, Permit, ResourceBudget, ToolGrant
from .policy import load_host_policy
from .providers import DeterministicProvider, GenericHttpProvider, ModelProvider, NativeWasmtimeComponentProvider, WasmDecisionProvider
from .security import AttestationPolicy, EnvelopeSigner, EnvelopeSigningIdentity, ExternalAttestationVerifier, ExternalMigrationPreflight, HmacEnvelopeSigner, HostPolicy, MigrationAttesterProtocol, MigrationPreflightProtocol, TrustRegistry, TrustSource, _b64url_decode, normalize_output_projection, validate_constraints
from .storage import RuntimeStore, create_runtime_store
from .tools import ToolRegistry, demo_registry
from ._clock import ClockRollbackError, TimeFloorError, check_time_floor, clock_tolerance_from_environment, configure_default_clock, trusted_now
from .witness import FloorError, LocalFloorWitness, floor_path_inside, open_audit_floor

logger = logging.getLogger(__name__)


HOST_ID = "host:local-demo"


def signer_from_environment(
    host_id: str = HOST_ID,
    trust_registry_path: str | None = None,
    trust: "TrustRegistry | TrustSource | None" = None,
) -> EnvelopeSigningIdentity:
    # Prefer a caller-supplied trust object so the signer and the store share ONE
    # fail-closed source (finding #2 -- two independent loads would let one verifier
    # keep trusting a key the other has stopped trusting). Fall back to loading a
    # fail-closed TrustSource from the path for direct callers (CLI, tests).
    # NOTE: the fallback source is for SINGLE-verifier use (a signer whose registry is the
    # only verifier). Do NOT pair a signer built this way with a store whose audit verifier
    # came from a separate load -- that recreates the two-source split this fix exists to
    # prevent. In make_host, pass the shared `trust` instead; make_host also refuses an
    # explicit signer combined with a trust_registry_path for exactly this reason.
    if trust is not None:
        registry: "TrustRegistry | TrustSource | None" = trust
    elif trust_registry_path:
        registry = TrustSource.from_path(trust_registry_path)
    else:
        registry = None
    raw_private_key = os.environ.get("PORTMARK_ED25519_PRIVATE_KEY_B64")
    if raw_private_key:
        # Strict canonical Base64URL, the same decoder used for signatures and public
        # keys (finding #6) -- a private key from the environment is a key decoder site too.
        private_key = _b64url_decode(raw_private_key)
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
    migration_attester: MigrationAttesterProtocol | None = None,
    migration_attester_timeout: float | None = 5.0,
    migration_attester_max_inflight: int = 8,
    metrics: RuntimeMetrics | None = None,
    policy_path: str | None = None,
    trust_registry_path: str | None = None,
    reload_policy: bool = False,
    tools: ToolRegistry | None = None,
    providers: dict[str, ModelProvider] | None = None,
    allow_ephemeral_signing_key: bool = False,
    allow_local_provider_endpoint: bool | None = None,
    audit_floor_path: str | None = None,
    attestation_allowed_measurements: tuple[str, ...] | None = None,
    migration_preflight_command: str | tuple[str, ...] | None = None,
    migration_preflight: MigrationPreflightProtocol | None = None,
    production: bool = False,
) -> AgentHost:
    # Section 12 #6 (D3): apply the configured clock tolerance BEFORE the first security decision below
    # (the audit-key check, the audit floor, trust loading), and judge the clock once with it. The
    # tolerance is changed in place, keeping the baseline, so a rollback since start-up that the default
    # tolerance allowed but the configured one does not is refused here -- not adopted as the baseline.
    clock = configure_default_clock(clock_tolerance_from_environment())
    try:
        clock.now()
    except ClockRollbackError as error:
        raise ValueError(f"trusted clock refused to start: {error}") from error
    # Note the asymmetry with `tools`, which REPLACES the demo registry.
    # Providers merge over the constructed defaults instead, so passing an
    # in-process provider does not silently remove `deterministic` and break
    # every envelope that names it. Callers can still shadow a default by
    # reusing its key.
    configured_providers: dict[str, ModelProvider] = {"deterministic": DeterministicProvider()}
    if provider_endpoint:
        # The local-gateway escape hatch (loopback-only http): opt in via the CLI flag / this argument
        # or PORTMARK_ALLOW_LOCAL_PROVIDER_ENDPOINT=true. It permits ONLY a loopback address, not
        # arbitrary private networks -- GenericHttpProvider still rejects private/link-local/etc.
        if allow_local_provider_endpoint is None:
            allow_local_provider_endpoint = os.environ.get(
                "PORTMARK_ALLOW_LOCAL_PROVIDER_ENDPOINT", ""
            ).strip().lower() in {"1", "true", "yes"}
        configured_providers["http"] = GenericHttpProvider(
            provider_endpoint, os.environ.get("MODEL_PROVIDER_TOKEN"),
            allow_local_endpoint=allow_local_provider_endpoint,
        )
    if wasm_component:
        if wasm_engine == "wasmtime":
            configured_providers["wasm"] = NativeWasmtimeComponentProvider.from_file(wasm_component)
        elif wasm_engine == "node":
            configured_providers["wasm"] = WasmDecisionProvider.from_file(wasm_component)
        else:
            raise ValueError("wasm_engine must be 'node' or 'wasmtime'")
    if providers:
        configured_providers.update(providers)
    configured_attestation_policy = attestation_policy
    if configured_attestation_policy is None:
        command = attestation_verifier_command or os.environ.get("PORTMARK_ATTESTATION_VERIFIER_COMMAND")
        required = (os.environ.get("PORTMARK_REQUIRE_ATTESTATION") == "1") if require_attestation is None else require_attestation
        measurements = (
            parse_allowed_measurements(os.environ.get(ALLOWED_MEASUREMENTS_ENV))
            if attestation_allowed_measurements is None else tuple(attestation_allowed_measurements)
        )
        if command or required or measurements:
            argv = tuple(shlex.split(command)) if isinstance(command, str) else command
            verifier = ExternalAttestationVerifier(argv) if argv else None
            configured_attestation_policy = AttestationPolicy(
                allowed_measurements=measurements,
                required_for_execution=required,
                required_for_migration=required,
                external_verifier=verifier,
                # Boundary audit ATT-02: in production a migration must settle on the destination's
                # FRESH attestation over a challenge this host mints, never on replayable evidence.
                require_migration_challenge=production,
            )
    configured_preflight = migration_preflight
    if configured_preflight is None:
        preflight_command = migration_preflight_command or os.environ.get(PREFLIGHT_COMMAND_ENV)
        preflight_argv = tuple(shlex.split(preflight_command)) if isinstance(preflight_command, str) else preflight_command
        if preflight_argv:
            configured_preflight = ExternalMigrationPreflight(preflight_argv)
    configured_policy_path = policy_path or os.environ.get("PORTMARK_POLICY_PATH")
    configured_trust_registry_path = trust_registry_path or os.environ.get("PORTMARK_TRUST_REGISTRY_PATH")
    # One fail-closed trust source shared by the signer AND the store's audit verifier
    # (finding #2). Two independent loads would let one verifier keep trusting a key the
    # other has stopped trusting, and would not fail closed together on an on-disk change.
    trust_source = TrustSource.from_path(configured_trust_registry_path) if configured_trust_registry_path else None
    policy_loader = (lambda: load_host_policy(configured_policy_path, host_id)) if configured_policy_path else None
    if production and policy_loader is not None:
        # Boundary audit ATT-01/ATT-02: wrap the loader, so the check runs on the boot load AND on every
        # reload (reload_policy). A reloaded policy that turns migration on without the attestation
        # configuration raises, exactly like any other invalid policy file.
        policy_loader = _production_policy_loader(policy_loader, configured_attestation_policy, configured_preflight)
    policy = policy_loader() if policy_loader else HostPolicy(
        host_id,
        # Finding #1: host policy is the projection ceiling, and an omitted
        # output_projection now means share-nothing. The demo capsule reads the
        # search result back from its projected state, so the host must explicitly
        # grant the fields it is willing to expose (id + title, not score).
        grants=(
            ToolGrant("catalog.search", {"max_limit": 5, "arguments": {"query": {"type": "string"}}}, ("id", "title")),
            ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}),
        ),
        budget=ResourceBudget(max_steps=10, max_tool_calls=5, max_output_bytes=65_536),
        tool_impacts={"catalog.search": "low", "payments.reserve": "external-payment"},
    )
    configured_store = store
    if configured_store is None and os.environ.get("PORTMARK_STORE_PATH"):
        audit_verifier = trust_source
        configured_store = create_runtime_store(
            os.environ.get("PORTMARK_STORE_BACKEND", "sqlite"),
            os.environ["PORTMARK_STORE_PATH"],
            audit_verifier,
        )
    # A caller-supplied signer keeps its OWN trust registry, so a file-backed TrustSource
    # built from trust_registry_path would be constructed and then orphaned -- admission
    # and audit verification would keep using the signer's stale in-memory registry, and a
    # revocation deployed to the file would never take effect. Reject the ambiguous combo;
    # the caller should build the signer already bound to the registry (or omit the signer).
    if signer is not None and configured_trust_registry_path:
        raise ValueError(
            "pass either an explicit signer OR a trust_registry_path, not both: a supplied "
            "signer keeps its own trust registry, so the file-backed trust source would be "
            "ignored and a revocation deployed to that file would not take effect. Build the "
            "signer bound to the registry via signer_from_environment(host_id, trust_registry_path), "
            "or omit the signer and let make_host construct it."
        )
    host_signer = signer or signer_from_environment(host_id, configured_trust_registry_path, trust=trust_source)
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
    # Finding #1: a durable store must not run on an ephemeral (generated, per-restart)
    # signing key -- audit heads signed before a restart would no longer verify, and
    # checkpoint continuation can break. Durability comes from the store's own
    # declaration, not a path/env heuristic. Ephemeral demo/test use must opt in.
    # Stability must be AFFIRMATIVE: only a signer that declares ephemeral=False (a key
    # loaded from stable bytes via from_private_key_bytes) counts as stable. A generated
    # key (ephemeral=True) OR any signer that does not declare its stability (e.g. a
    # randomly-generated HMAC or custom signer, ephemeral absent) is NOT presumed stable,
    # so a durable store refuses it unless the caller explicitly opts in.
    signer_is_stable = getattr(host_signer, "ephemeral", None) is False
    if getattr(configured_store, "is_durable", False) and not signer_is_stable and not allow_ephemeral_signing_key:
        raise ValueError(
            "a durable store requires a signing key with proven stability (loaded from stable "
            "bytes, e.g. PORTMARK_ED25519_PRIVATE_KEY_B64, with the host public key in the trust "
            "registry). A generated key, or a signer that does not declare its key stable, is "
            "refused because such a key can change across restarts and orphan previously-signed "
            "audit heads; pass allow_ephemeral_signing_key=True for ephemeral demo/test use."
        )
    # Finding #2: the host must not START with an audit-signing key it could not itself
    # accept. Readiness reports such a key but does not block work -- a direct client would
    # still submit a request and get back results whose audit head is invalid from birth
    # (signed-after-revocation / expired). Enforce fail-closed at boot against the very
    # trust the signer verifies audit heads with. Legacy HMAC has no key lifecycle or
    # usages, exposes no registry, and is skipped (documented in SIGNING_KEYS.md).
    audit_trust = getattr(host_signer, "registry", None)
    audit_key_id = getattr(host_signer, "key_id", None)
    if audit_trust is not None and audit_key_id is not None and hasattr(audit_trust, "audit_signing_reason"):
        reason = audit_trust.audit_signing_reason(audit_key_id)
        if reason is not None:
            raise ValueError(
                f"host audit-signing key {audit_key_id!r} cannot sign audit heads ({reason}): it must be "
                "currently trusted, active, unexpired, unrevoked, and authorized for the 'audit' usage in "
                "the trust registry that verifies audit heads. Rotate to a usable key before starting the host."
            )
    audit_floor = _open_audit_floor(
        audit_floor_path or os.environ.get("PORTMARK_AUDIT_FLOOR_PATH"), host_id, host_signer, configured_store, trust_source,
        production=production,
    )
    # Section 12 #6 (owner decision D3): refuse to start when the clock is behind the durable time floor --
    # the higher of the database's floor and the audit-floor file's mirror -- by more than the tolerance.
    # A boot ValueError like every neighbouring start-up check; never lowered automatically.
    if getattr(configured_store, "is_durable", False):
        try:
            check_time_floor(configured_store, audit_floor, clock)
        except TimeFloorError as error:
            raise ValueError(f"time floor refused to start ({error.code}): {error}") from error
    host = AgentHost(
        host_id,
        host_signer,
        policy,
        tools if tools is not None else demo_registry(),
        configured_providers,
        store=configured_store,
        attestation_policy=configured_attestation_policy,
        migration_attester=migration_attester,
        migration_attester_timeout=migration_attester_timeout,
        migration_attester_max_inflight=migration_attester_max_inflight,
        migration_preflight=configured_preflight,
        policy_loader=policy_loader,
        reload_policy=reload_policy,
        metrics=metrics,
    )
    host.audit_floor = audit_floor
    # Boundary audit DB-01: whether rollback detection is on, on the authenticated /metrics (not /readyz).
    host.metrics.set_gauge("audit_witness_active", 1 if audit_floor is not None else 0)
    # Section 12 #6: a forward clock jump beyond the tolerance is also a metric, not only a CRITICAL log.
    clock.on_forward_jump(host.metrics.note_clock_forward_jump)
    return host


def _production_policy_loader(loader, attestation_policy: AttestationPolicy | None, preflight: MigrationPreflightProtocol | None):
    def load() -> HostPolicy:
        loaded = loader()
        if loaded.migration.allowed:
            problems = production_migration_problems(attestation_policy, preflight)
            if problems:
                raise ValueError(
                    "host policy allows migration, and the production profile then needs every requirement "
                    f"below (set {PROFILE_ENV}={DEVELOPMENT_PROFILE} to run without them): " + "; ".join(problems)
                )
        return loaded

    return load


def production_migration_problems(policy: AttestationPolicy | None, preflight: MigrationPreflightProtocol | None = None) -> list[str]:
    """Boundary audit ATT-01/ATT-02: what a production host that may migrate is missing. Empty means none.

    Portmark's own Ed25519 attestation proves possession of a key, not hardware state, so production
    needs the deployment's platform verifier; an empty measurement list skips the allowlist; without the
    challenge a valid unexpired attestation can be replayed for another migration; and without the
    preflight the destination is verified only after the signed (not encrypted) state has left.
    """
    problems = []
    if preflight is None:
        problems.append(
            f"{PREFLIGHT_COMMAND_ENV} is required: the destination must attest over a fresh challenge "
            "BEFORE migration state is released"
        )
    if policy is None or policy.external_verifier is None:
        problems.append("PORTMARK_ATTESTATION_VERIFIER_COMMAND is required: the platform (hardware) quote verifier")
    if policy is None or not policy.allowed_measurements:
        problems.append(f"{ALLOWED_MEASUREMENTS_ENV} is required: the approved workload measurements")
    if policy is None or not policy.require_migration_challenge:
        problems.append("the migration challenge must be on (fresh destination attestation at settlement)")
    return problems


def _open_audit_floor(
    floor_path: str | None, host_id: str, signer: EnvelopeSigningIdentity, store: RuntimeStore | None, trust_source: TrustSource | None,
    production: bool = False,
) -> LocalFloorWitness | None:
    """Section 10 PR B: boot-time audit-floor checks. Every refusal is a boot ValueError, like the
    neighbouring signing-key checks, never a lazy failure on the first persist."""
    durable = bool(getattr(store, "is_durable", False))
    if not floor_path:
        marker = store.audit_floor_marker(host_id) if durable and hasattr(store, "audit_floor_marker") else None
        if marker is not None:
            # Once a database has a floor, it cannot be silently dropped: a host started without it
            # would write heads the floor never sees (and could be pointed at a rolled-back copy).
            raise ValueError(
                f"this database has an audit floor for {host_id!r} (epoch {marker[0]}); start the host with "
                "--audit-floor-path / PORTMARK_AUDIT_FLOOR_PATH"
            )
        if durable and production:
            # Boundary audit DB-01: a new production database must not start without rollback
            # detection; development keeps the warning below.
            raise ValueError(
                "the production profile needs an audit floor for a durable store (--audit-floor-path / "
                "PORTMARK_AUDIT_FLOOR_PATH), or a rollback of the database or trust registry will not be "
                f"detected; set {PROFILE_ENV}={DEVELOPMENT_PROFILE} to run without one"
            )
        if durable:
            logger.warning(
                "durable store without an audit floor (--audit-floor-path / PORTMARK_AUDIT_FLOOR_PATH): a rollback of "
                "the database or trust registry to an older consistent copy will NOT be detected"
            )
        return None
    if not durable:
        raise ValueError("an audit floor requires a durable store; an in-memory store has nothing to roll back")
    store_path = getattr(store, "path", None)
    if store_path is not None and floor_path_inside(floor_path, str(Path(store_path).resolve().parent)):
        raise ValueError(
            "the audit floor must live OUTSIDE the store directory (a backup or restore of that directory would "
            "carry the floor with the database, defeating it)"
        )
    if not (hasattr(signer, "sign_audit_floor") and hasattr(signer, "verify_audit_floor")):
        raise ValueError("the host signer cannot sign an audit floor (needs sign_audit_floor/verify_audit_floor)")
    registry_version: int | None = None
    registry_digest: str | None = None
    if trust_source is not None:
        if trust_source.version < 1:
            raise ValueError(
                "an audit floor requires a VERSIONED trust registry (top-level \"version\": an integer >= 1, raised on "
                "every change; `portmark keygen --force` does this) so an older registry can be refused"
            )
        registry_version, registry_digest = trust_source.version, trust_source.digest
    witness = LocalFloorWitness(floor_path, host_id, signer, signer)
    # Boot adoption verifies whole chains, so the store needs its head verifier now (AgentHost sets the
    # same one again at construction).
    if hasattr(store, "set_audit_head_verifier"):
        store.set_audit_head_verifier(signer)  # type: ignore[union-attr]
    try:
        open_audit_floor(witness, store, registry_version, registry_digest)
    except FloorError as error:
        raise ValueError(f"audit floor refused to start ({error.code}): {error}") from error
    return witness


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
    # PM-002: one shared decoder. An explicit [] is share-nothing and must NOT become None
    # (which defers to the host's projection, and can widen to everything).
    projection = normalize_output_projection(value.get("output_projection"), f"grant {name!r}")
    return ToolGrant(name, dict(constraints), projection)


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
        expires_at=trusted_now() + int(spec.get("ttl_seconds", 3600)),
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
        expires_at=trusted_now() + 3600, nonce=secrets.token_hex(16),
        grants=(ToolGrant("catalog.search", {"max_limit": 3, "arguments": {"query": {"type": "string"}}}, ("id", "title")),),
        budget=ResourceBudget(max_steps=6, max_tool_calls=2, max_output_bytes=32_768),
    )
    return host.signer.seal(AgentEnvelope(manifest, permit, AgentState(secrets.token_hex(8), goal)))

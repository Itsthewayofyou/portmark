from __future__ import annotations

import os
import shlex
from dataclasses import dataclass

from .a2a import (
    DEFAULT_AGENT_CARD_RATE_LIMIT_PER_IP,
    DEFAULT_AGENT_CARD_RATE_LIMIT_WINDOW_SECONDS,
    DEFAULT_BODY_READ_TIMEOUT_SECONDS,
    DEFAULT_MAX_CONCURRENT_REQUESTS,
    DEFAULT_RATE_LIMIT_PER_IP,
    DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
    DEFAULT_SHUTDOWN_GRACE_SECONDS,
)


PROFILE_ENV = "PORTMARK_PROFILE"
PRODUCTION_PROFILE = "production"
DEVELOPMENT_PROFILE = "development"
ALLOWED_MEASUREMENTS_ENV = "PORTMARK_ATTESTATION_ALLOWED_MEASUREMENTS"
PREFLIGHT_COMMAND_ENV = "PORTMARK_MIGRATION_PREFLIGHT_COMMAND"


def parse_profile(value: str | None) -> str:
    """Unset or blank is production. Any value other than the two names is refused, never guessed:
    a typo such as "dev" or "prod " must not silently pick a profile."""
    if value is None or not value.strip():
        return PRODUCTION_PROFILE
    if value not in (PRODUCTION_PROFILE, DEVELOPMENT_PROFILE):
        raise ValueError(f"{PROFILE_ENV} must be {PRODUCTION_PROFILE!r} or {DEVELOPMENT_PROFILE!r}, got {value!r}")
    return value


def parse_allowed_measurements(value: str | None) -> tuple[str, ...]:
    """A comma-separated list of exact measurement strings. An empty item or an item with whitespace
    inside is refused: it is a typo, and a typo in an allowlist must not quietly change what it admits."""
    if value is None or not value.strip():
        return ()
    items = [item.strip() for item in value.split(",")]
    for item in items:
        if not item or any(character.isspace() for character in item):
            raise ValueError(f"{ALLOWED_MEASUREMENTS_ENV} has an empty or malformed item: {value!r}")
    return tuple(dict.fromkeys(items))


@dataclass(frozen=True)
class RuntimeConfig:
    host_id: str = "host:local-demo"
    provider_endpoint: str | None = None
    wasm_component: str | None = None
    wasm_engine: str = "node"
    store_backend: str = "sqlite"
    store_path: str | None = None
    policy_path: str | None = None
    # MCP.md: the operator's MCP servers and the tools they may expose, each approved by its pin.
    mcp_config_path: str | None = None
    trust_registry_path: str | None = None
    audit_floor_path: str | None = None
    reload_policy: bool = False
    attestation_verifier_command: tuple[str, ...] | None = None
    require_attestation: bool = False
    allow_local_provider_endpoint: bool = False
    a2a_token: str | None = None
    a2a_adapter: str = "local"
    a2a_public_base_url: str | None = None
    a2a_trusted_proxies: str | None = None
    log_level: str = "INFO"
    log_json: bool = False
    enable_hsts: bool = False
    allow_direct_a2a: bool = False
    a2a_max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS
    a2a_rate_limit_per_ip: int = DEFAULT_RATE_LIMIT_PER_IP
    a2a_rate_limit_window_seconds: int = DEFAULT_RATE_LIMIT_WINDOW_SECONDS
    a2a_agent_card_rate_limit_per_ip: int = DEFAULT_AGENT_CARD_RATE_LIMIT_PER_IP
    a2a_agent_card_rate_limit_window_seconds: int = DEFAULT_AGENT_CARD_RATE_LIMIT_WINDOW_SECONDS
    # Section 12 #2 / #1. Validated (positive, bounded) where the app is built, so a bad value fails
    # the start instead of disabling the bound.
    a2a_body_read_timeout_seconds: float = DEFAULT_BODY_READ_TIMEOUT_SECONDS
    shutdown_grace_seconds: float = DEFAULT_SHUTDOWN_GRACE_SECONDS
    # Boundary audit NET-02/DB-01/ATT-01/ATT-02 (owner decision 1A): the ASGI app is production by
    # default; only an explicit PORTMARK_PROFILE=development relaxes the production start-up checks.
    profile: str = PRODUCTION_PROFILE
    # ATT-02: the approved attestation measurements (exact strings). Empty means Portmark checks none.
    attestation_allowed_measurements: tuple[str, ...] = ()
    # ATT-01 (auditor round 1 on #104): the command that obtains a destination's attestation over a fresh
    # challenge BEFORE migration state is released.
    migration_preflight_command: tuple[str, ...] | None = None

    @classmethod
    def from_environment(cls) -> "RuntimeConfig":
        return cls(
            host_id=os.environ.get("PORTMARK_HOST_ID", "host:local-demo"),
            provider_endpoint=os.environ.get("PORTMARK_PROVIDER_ENDPOINT"),
            wasm_component=os.environ.get("PORTMARK_WASM_COMPONENT"),
            wasm_engine=os.environ.get("PORTMARK_WASM_ENGINE", "node"),
            store_backend=os.environ.get("PORTMARK_STORE_BACKEND", "sqlite"),
            store_path=os.environ.get("PORTMARK_STORE_PATH"),
            policy_path=os.environ.get("PORTMARK_POLICY_PATH"),
            mcp_config_path=os.environ.get("PORTMARK_MCP_CONFIG"),
            trust_registry_path=os.environ.get("PORTMARK_TRUST_REGISTRY_PATH"),
            audit_floor_path=os.environ.get("PORTMARK_AUDIT_FLOOR_PATH"),
            reload_policy=os.environ.get("PORTMARK_RELOAD_POLICY") == "1",
            attestation_verifier_command=_argv(os.environ.get("PORTMARK_ATTESTATION_VERIFIER_COMMAND")),
            require_attestation=os.environ.get("PORTMARK_REQUIRE_ATTESTATION") == "1",
            allow_local_provider_endpoint=os.environ.get("PORTMARK_ALLOW_LOCAL_PROVIDER_ENDPOINT", "").strip().lower() in {"1", "true", "yes"},
            a2a_token=os.environ.get("PORTMARK_A2A_TOKEN"),
            a2a_adapter=os.environ.get("PORTMARK_A2A_ADAPTER", "local"),
            a2a_public_base_url=os.environ.get("PORTMARK_A2A_PUBLIC_BASE_URL"),
            a2a_trusted_proxies=os.environ.get("PORTMARK_A2A_TRUSTED_PROXIES"),
            log_level=os.environ.get("PORTMARK_LOG_LEVEL", "INFO"),
            log_json=os.environ.get("PORTMARK_LOG_JSON") == "1",
            enable_hsts=os.environ.get("PORTMARK_ENABLE_HSTS") == "1",
            allow_direct_a2a=os.environ.get("PORTMARK_ALLOW_DIRECT_A2A") == "1",
            a2a_max_concurrent_requests=int(os.environ.get("PORTMARK_A2A_MAX_CONCURRENT_REQUESTS", DEFAULT_MAX_CONCURRENT_REQUESTS)),
            a2a_rate_limit_per_ip=int(os.environ.get("PORTMARK_A2A_RATE_LIMIT_PER_IP", DEFAULT_RATE_LIMIT_PER_IP)),
            a2a_rate_limit_window_seconds=int(os.environ.get("PORTMARK_A2A_RATE_LIMIT_WINDOW_SECONDS", DEFAULT_RATE_LIMIT_WINDOW_SECONDS)),
            a2a_agent_card_rate_limit_per_ip=int(os.environ.get(
                "PORTMARK_A2A_AGENT_CARD_RATE_LIMIT_PER_IP",
                DEFAULT_AGENT_CARD_RATE_LIMIT_PER_IP,
            )),
            a2a_agent_card_rate_limit_window_seconds=int(os.environ.get(
                "PORTMARK_A2A_AGENT_CARD_RATE_LIMIT_WINDOW_SECONDS",
                DEFAULT_AGENT_CARD_RATE_LIMIT_WINDOW_SECONDS,
            )),
            a2a_body_read_timeout_seconds=float(os.environ.get(
                "PORTMARK_A2A_BODY_READ_TIMEOUT_SECONDS",
                DEFAULT_BODY_READ_TIMEOUT_SECONDS,
            )),
            shutdown_grace_seconds=float(os.environ.get("PORTMARK_SHUTDOWN_GRACE_SECONDS", DEFAULT_SHUTDOWN_GRACE_SECONDS)),
            profile=parse_profile(os.environ.get(PROFILE_ENV)),
            attestation_allowed_measurements=parse_allowed_measurements(os.environ.get(ALLOWED_MEASUREMENTS_ENV)),
            migration_preflight_command=_argv(os.environ.get(PREFLIGHT_COMMAND_ENV)),
        )

    def merged_with_args(self, args) -> "RuntimeConfig":
        return RuntimeConfig(
            host_id=args.host_id or self.host_id,
            provider_endpoint=args.provider_endpoint or self.provider_endpoint,
            wasm_component=args.wasm_component or self.wasm_component,
            wasm_engine=getattr(args, "wasm_engine", None) or self.wasm_engine,
            store_backend=getattr(args, "store_backend", None) or self.store_backend,
            store_path=args.store_path or self.store_path,
            policy_path=args.policy_path or self.policy_path,
            mcp_config_path=getattr(args, "mcp_config", None) or self.mcp_config_path,
            trust_registry_path=args.trust_registry_path or self.trust_registry_path,
            audit_floor_path=getattr(args, "audit_floor_path", None) or self.audit_floor_path,
            reload_policy=bool(args.reload_policy or self.reload_policy),
            attestation_verifier_command=_argv(getattr(args, "attestation_verifier_command", None)) or self.attestation_verifier_command,
            require_attestation=bool(getattr(args, "require_attestation", False) or self.require_attestation),
            allow_local_provider_endpoint=bool(getattr(args, "allow_local_provider_endpoint", False) or self.allow_local_provider_endpoint),
            a2a_token=getattr(args, "a2a_token", None) or self.a2a_token,
            a2a_adapter=getattr(args, "a2a_adapter", None) or self.a2a_adapter,
            a2a_public_base_url=getattr(args, "a2a_public_base_url", None) or self.a2a_public_base_url,
            a2a_trusted_proxies=getattr(args, "a2a_trusted_proxies", None) or self.a2a_trusted_proxies,
            log_level=args.log_level or self.log_level,
            log_json=bool(args.log_json or self.log_json),
            enable_hsts=bool(args.enable_hsts or self.enable_hsts),
            allow_direct_a2a=bool(getattr(args, "allow_direct_a2a", False) or self.allow_direct_a2a),
            a2a_max_concurrent_requests=getattr(args, "a2a_max_concurrent_requests", None) or self.a2a_max_concurrent_requests,
            a2a_rate_limit_per_ip=getattr(args, "a2a_rate_limit_per_ip", None) or self.a2a_rate_limit_per_ip,
            a2a_rate_limit_window_seconds=getattr(args, "a2a_rate_limit_window_seconds", None) or self.a2a_rate_limit_window_seconds,
            a2a_agent_card_rate_limit_per_ip=getattr(
                args,
                "a2a_agent_card_rate_limit_per_ip",
                None,
            ) or self.a2a_agent_card_rate_limit_per_ip,
            a2a_agent_card_rate_limit_window_seconds=getattr(
                args,
                "a2a_agent_card_rate_limit_window_seconds",
                None,
            ) or self.a2a_agent_card_rate_limit_window_seconds,
            a2a_body_read_timeout_seconds=self.a2a_body_read_timeout_seconds,
            shutdown_grace_seconds=self.shutdown_grace_seconds,
            profile=self.profile,
            attestation_allowed_measurements=self.attestation_allowed_measurements,
            migration_preflight_command=self.migration_preflight_command,
        )


def _argv(value: str | None) -> tuple[str, ...] | None:
    if value is None or not value.strip():
        return None
    return tuple(shlex.split(value))

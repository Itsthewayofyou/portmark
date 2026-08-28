from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeConfig:
    host_id: str = "host:local-demo"
    provider_endpoint: str | None = None
    wasm_component: str | None = None
    store_path: str | None = None
    policy_path: str | None = None
    trust_registry_path: str | None = None
    reload_policy: bool = False
    a2a_token: str | None = None
    log_level: str = "INFO"
    log_json: bool = False
    enable_hsts: bool = False

    @classmethod
    def from_environment(cls) -> "RuntimeConfig":
        return cls(
            host_id=os.environ.get("PORTABLE_AGENT_HOST_ID", "host:local-demo"),
            provider_endpoint=os.environ.get("PORTABLE_AGENT_PROVIDER_ENDPOINT"),
            wasm_component=os.environ.get("PORTABLE_AGENT_WASM_COMPONENT"),
            store_path=os.environ.get("PORTABLE_AGENT_STORE_PATH"),
            policy_path=os.environ.get("PORTABLE_AGENT_POLICY_PATH"),
            trust_registry_path=os.environ.get("PORTABLE_AGENT_TRUST_REGISTRY_PATH"),
            reload_policy=os.environ.get("PORTABLE_AGENT_RELOAD_POLICY") == "1",
            a2a_token=os.environ.get("PORTABLE_AGENT_A2A_TOKEN"),
            log_level=os.environ.get("PORTABLE_AGENT_LOG_LEVEL", "INFO"),
            log_json=os.environ.get("PORTABLE_AGENT_LOG_JSON") == "1",
            enable_hsts=os.environ.get("PORTABLE_AGENT_ENABLE_HSTS") == "1",
        )

    def merged_with_args(self, args) -> "RuntimeConfig":
        return RuntimeConfig(
            host_id=args.host_id or self.host_id,
            provider_endpoint=args.provider_endpoint or self.provider_endpoint,
            wasm_component=args.wasm_component or self.wasm_component,
            store_path=args.store_path or self.store_path,
            policy_path=args.policy_path or self.policy_path,
            trust_registry_path=args.trust_registry_path or self.trust_registry_path,
            reload_policy=bool(args.reload_policy or self.reload_policy),
            a2a_token=getattr(args, "a2a_token", None) or self.a2a_token,
            log_level=args.log_level or self.log_level,
            log_json=bool(args.log_json or self.log_json),
            enable_hsts=bool(args.enable_hsts or self.enable_hsts),
        )

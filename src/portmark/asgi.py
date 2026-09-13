from __future__ import annotations

import os

from .a2a import (
    A2AAuthConfig,
    default_readiness_check,
    make_asgi_app,
    parse_trusted_proxies,
    validate_public_base_url,
)
from .config import RuntimeConfig
from .factory import HOST_ID, make_host
from .logging_config import configure_logging
from .policy import load_host_policy
from .security import load_trust_registry
from .storage import create_runtime_store
from .tool_loading import ToolLoaderError, load_tools


def create_app():
    config = RuntimeConfig.from_environment()
    configure_logging(config.log_level, config.log_json)
    tools_path = os.environ.get("PORTMARK_TOOLS")
    if tools_path and not config.policy_path:
        raise RuntimeError("PORTMARK_TOOLS requires PORTMARK_POLICY_PATH")
    try:
        tools = load_tools(tools_path)
    except ToolLoaderError as error:
        raise RuntimeError(str(error)) from error

    audit_verifier = load_trust_registry(config.trust_registry_path) if config.trust_registry_path else None
    store = create_runtime_store(config.store_backend, config.store_path, audit_verifier) if config.store_path else None
    host = make_host(
        config.provider_endpoint,
        host_id=config.host_id or HOST_ID,
        wasm_component=config.wasm_component,
        wasm_engine=config.wasm_engine,
        store=store,
        policy_path=config.policy_path,
        trust_registry_path=config.trust_registry_path,
        reload_policy=config.reload_policy,
        attestation_verifier_command=config.attestation_verifier_command,
        require_attestation=config.require_attestation,
        tools=tools,
    )

    def readiness_check() -> None:
        # Section 2, finding #4: readiness must NOT construct the store or run schema
        # migration (create_runtime_store does DDL + advisory locking). Startup built
        # the store once; readiness re-validates config files and does a bounded store
        # liveness probe via default_readiness_check -> store.check_ready().
        if config.policy_path:
            load_host_policy(config.policy_path, config.host_id or HOST_ID)
        if config.trust_registry_path:
            load_trust_registry(config.trust_registry_path)
        default_readiness_check(host)

    public_base_url = validate_public_base_url(config.a2a_public_base_url) if config.a2a_public_base_url else None

    return make_asgi_app(
        host,
        A2AAuthConfig(config.a2a_token) if config.a2a_token else None,
        config.enable_hsts,
        max_concurrent_requests=config.a2a_max_concurrent_requests,
        rate_limit_per_ip=config.a2a_rate_limit_per_ip,
        rate_limit_window_seconds=config.a2a_rate_limit_window_seconds,
        agent_card_rate_limit_per_ip=config.a2a_agent_card_rate_limit_per_ip,
        agent_card_rate_limit_window_seconds=config.a2a_agent_card_rate_limit_window_seconds,
        a2a_adapter=config.a2a_adapter,
        readiness_check=readiness_check,
        public_base_url=public_base_url,
        trusted_proxies=parse_trusted_proxies(config.a2a_trusted_proxies),
    )


app = create_app()

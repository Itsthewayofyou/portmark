from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from .a2a import A2AAuthConfig, serve
from .config import RuntimeConfig
from .factory import make_demo_envelope, make_host
from .logging_config import configure_logging


def main() -> None:
    parser = argparse.ArgumentParser(description="Provider-neutral portable agent runtime")
    parser.add_argument("--host-id", help="host identity used for permit audience and signing issuer")
    parser.add_argument("--provider-endpoint", help="generic HTTP model-provider endpoint")
    parser.add_argument("--wasm-component", help="Wasm capsule (.wasm or .wat) implementing the WIT resume ABI")
    parser.add_argument("--store-path", help="SQLite path for durable nonces, checkpoints, and audit heads")
    parser.add_argument("--policy-path", help="JSON host policy path")
    parser.add_argument("--trust-registry-path", help="JSON trust registry path for envelope signing keys")
    parser.add_argument("--reload-policy", action="store_true", help="reload the JSON host policy before each run")
    parser.add_argument("--log-level", help="logging level")
    parser.add_argument("--log-json", action="store_true", help="emit structured JSON logs")
    parser.add_argument("--enable-hsts", action="store_true", help="emit HSTS header when served behind HTTPS")
    subparsers = parser.add_subparsers(dest="command", required=True)
    demo = subparsers.add_parser("demo")
    demo.add_argument("goal", nargs="?", default="find portable agent architecture references")
    server = subparsers.add_parser("serve")
    server.add_argument("--bind", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8080)
    server.add_argument("--a2a-token", help="require this bearer token for A2A message/send requests")
    args = parser.parse_args()
    from .storage import SQLiteRuntimeStore

    config = RuntimeConfig.from_environment().merged_with_args(args)
    configure_logging(config.log_level, config.log_json)
    store = SQLiteRuntimeStore(config.store_path) if config.store_path else None
    host = make_host(
        config.provider_endpoint,
        host_id=config.host_id,
        wasm_component=config.wasm_component,
        store=store,
        policy_path=config.policy_path,
        trust_registry_path=config.trust_registry_path,
        reload_policy=config.reload_policy,
    )
    if args.command == "demo":
        provider = "wasm" if config.wasm_component else ("http" if config.provider_endpoint else "deterministic")
        result = host.run(make_demo_envelope(host, args.goal, provider))
        print(json.dumps(asdict(result), indent=2))
    else:
        serve(host, args.bind, args.port, A2AAuthConfig(config.a2a_token) if config.a2a_token else None, config.enable_hsts)


if __name__ == "__main__":
    main()

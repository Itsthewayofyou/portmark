from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from dataclasses import asdict

from .a2a import A2AAuthConfig, serve
from .config import RuntimeConfig
from .factory import HOST_ID, build_envelope, make_demo_envelope, make_host, signer_from_environment
from .logging_config import configure_logging


def _run_keygen(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    from .security import generate_signing_material

    if args.out_registry and os.path.exists(args.out_registry) and not args.force:
        parser.error(f"{args.out_registry} already exists; pass --force to overwrite this trust registry")
    material = generate_signing_material(args.key_id, args.issuer, tuple(args.audience or ("*",)))
    if args.out_registry:
        with open(args.out_registry, "w", encoding="utf-8") as handle:
            json.dump(material["trust_registry"], handle, indent=2)
        print(f"wrote trust registry to {args.out_registry}", file=sys.stderr)
    if args.format == "env":
        # Exported together so the issuer and key id can never drift from the key itself.
        print(f"export PORTMARK_ED25519_PRIVATE_KEY_B64={material['private_key_b64']}")
        print(f"export PORTMARK_SIGNING_KEY_ID={material['key_id']}")
        print(f"export PORTMARK_SIGNING_ISSUER={material['issuer']}")
    else:
        print(json.dumps(material, indent=2))


def _load_spec(parser: argparse.ArgumentParser, path: str | None) -> dict:
    if not path:
        return {}
    try:
        raw = sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()
        spec = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"could not read envelope spec: {exc}")
    if not isinstance(spec, dict):
        parser.error("envelope spec must be a JSON object")
    return spec


def _run_envelope(parser: argparse.ArgumentParser, args: argparse.Namespace, config: RuntimeConfig) -> None:
    spec = _load_spec(parser, args.spec)
    if args.goal:
        spec["goal"] = args.goal
    if args.audience:
        spec["audience"] = args.audience
    if args.tools:
        spec["grants"] = [{"name": name} for name in args.tools]
    if not os.environ.get("PORTMARK_ED25519_PRIVATE_KEY_B64"):
        # No ephemeral fallback: a key the host has never seen produces an envelope
        # that is always rejected, which reads as a Portmark bug rather than setup.
        parser.error(
            "envelope requires PORTMARK_ED25519_PRIVATE_KEY_B64; "
            "run: eval \"$(portmark keygen --format env --out-registry trust.json)\""
        )
    signer = signer_from_environment(config.host_id or HOST_ID, config.trust_registry_path)
    try:
        envelope = build_envelope(spec, signer)
    except ValueError as exc:
        parser.error(str(exc))
    payload = asdict(envelope)
    if args.format == "envelope":
        print(json.dumps(payload, indent=2))
        return
    print(json.dumps({
        "jsonrpc": "2.0",
        "id": secrets.token_hex(8),
        "method": "message/send",
        "params": {
            "message": {
                "messageId": secrets.token_hex(8),
                "role": "user",
                "parts": [{"kind": "text", "text": envelope.state.goal}],
            },
            "metadata": {"portmark_envelope": payload},
        },
    }, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Provider-neutral portable agent runtime")
    parser.add_argument("--host-id", help="host identity used for permit audience and signing issuer")
    parser.add_argument("--provider-endpoint", help="generic HTTP model-provider endpoint")
    parser.add_argument("--wasm-component", help="Wasm capsule (.wasm or .wat) implementing the WIT resume ABI")
    parser.add_argument("--wasm-engine", choices=("node", "wasmtime"), help="Wasm provider engine")
    parser.add_argument("--store-path", help="SQLite path for durable nonces, checkpoints, and audit heads")
    parser.add_argument("--policy-path", help="JSON host policy path")
    parser.add_argument("--trust-registry-path", help="JSON trust registry path for envelope signing keys")
    parser.add_argument("--reload-policy", action="store_true", help="reload the JSON host policy before each run")
    parser.add_argument("--attestation-verifier-command", help="shell-free argv string for an external attestation verifier")
    parser.add_argument("--require-attestation", action="store_true", help="require attestation before execution and migration")
    parser.add_argument("--log-level", help="logging level")
    parser.add_argument("--log-json", action="store_true", help="emit structured JSON logs")
    parser.add_argument("--enable-hsts", action="store_true", help="emit HSTS header when served behind HTTPS")
    parser.add_argument("--allow-direct-a2a", action="store_true", help="deprecated; non-loopback A2A binds are refused")
    subparsers = parser.add_subparsers(dest="command", required=True)
    demo = subparsers.add_parser("demo")
    demo.add_argument("goal", nargs="?", default="find portable agent architecture references")
    server = subparsers.add_parser("serve")
    server.add_argument("--bind", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8080)
    server.add_argument("--a2a-adapter", choices=("local", "sdk"), help="A2A type adapter for Agent Card and request validation")
    server.add_argument("--a2a-token", help="require this bearer token for A2A message/send requests")
    server.add_argument("--a2a-max-concurrent-requests", type=int, help="maximum concurrent A2A message/send requests")
    server.add_argument("--a2a-rate-limit-per-ip", type=int, help="maximum A2A message/send requests per client IP window")
    server.add_argument("--a2a-rate-limit-window-seconds", type=int, help="A2A per-IP rate limit window in seconds")
    server.add_argument("--a2a-agent-card-rate-limit-per-ip", type=int, help="maximum Agent Card GET requests per client IP window")
    server.add_argument("--a2a-agent-card-rate-limit-window-seconds", type=int, help="Agent Card GET per-IP rate limit window in seconds")
    keygen = subparsers.add_parser("keygen", help="mint an envelope signing key plus the trust registry a host needs to accept it")
    keygen.add_argument("--key-id", default="portmark-agent-key", help="signing key id recorded in the trust registry")
    keygen.add_argument("--issuer", default="user:portmark", help="permit issuer this key is allowed to sign for")
    keygen.add_argument("--audience", action="append", help="host id this key may target; repeatable; defaults to any")
    keygen.add_argument("--out-registry", help="write the public trust registry JSON here for the host to load")
    keygen.add_argument("--force", action="store_true", help="overwrite an existing --out-registry file")
    keygen.add_argument("--format", choices=("json", "env"), default="json", help="'env' emits shell exports for eval")
    envelope_parser = subparsers.add_parser(
        "envelope",
        help="build and sign an agent envelope for a running host, without writing Python",
    )
    envelope_parser.add_argument("--spec", help="JSON envelope spec path, or '-' to read stdin")
    envelope_parser.add_argument("--goal", help="agent goal; overrides the spec")
    envelope_parser.add_argument("--tool", action="append", dest="tools", help="grant this tool; repeatable; replaces the spec's grants")
    envelope_parser.add_argument("--audience", help=f"host id that may run this envelope; must equal the host's --host-id (default {HOST_ID})")
    envelope_parser.add_argument("--format", choices=("jsonrpc", "envelope"), default="jsonrpc", help="'jsonrpc' emits a ready-to-POST message/send request")
    verify_audit = subparsers.add_parser("verify-audit")
    verify_audit.add_argument("--task-id", required=True, help="task id whose SQLite audit chain should be verified")
    args = parser.parse_args()
    from .security import load_trust_registry
    from .storage import SQLiteRuntimeStore

    config = RuntimeConfig.from_environment().merged_with_args(args)
    configure_logging(config.log_level, config.log_json)
    # keygen and envelope run agent-side: they need no host, no policy, and no store.
    if args.command == "keygen":
        _run_keygen(parser, args)
        return
    if args.command == "envelope":
        _run_envelope(parser, args, config)
        return
    audit_verifier = load_trust_registry(config.trust_registry_path) if config.trust_registry_path else None
    store = SQLiteRuntimeStore(config.store_path, audit_verifier) if config.store_path else None
    if args.command == "verify-audit":
        if store is None:
            parser.error("verify-audit requires --store-path or PORTMARK_STORE_PATH")
        verification = store.verify_audit_chain_status(args.task_id)
        print(json.dumps({"task_id": args.task_id, "status": verification.status, "reason": verification.reason}, indent=2))
        if verification.status == "invalid":
            raise SystemExit(1)
        if verification.status == "unverifiable":
            raise SystemExit(2)
        return
    host = make_host(
        config.provider_endpoint,
        host_id=config.host_id,
        wasm_component=config.wasm_component,
        wasm_engine=config.wasm_engine,
        store=store,
        policy_path=config.policy_path,
        trust_registry_path=config.trust_registry_path,
        reload_policy=config.reload_policy,
        attestation_verifier_command=config.attestation_verifier_command,
        require_attestation=config.require_attestation,
    )
    if args.command == "demo":
        provider = "wasm" if config.wasm_component else ("http" if config.provider_endpoint else "deterministic")
        result = host.run(make_demo_envelope(host, args.goal, provider))
        print(json.dumps(asdict(result), indent=2))
    else:
        try:
            serve(
                host=host,
                bind=args.bind,
                port=args.port,
                auth=A2AAuthConfig(config.a2a_token) if config.a2a_token else None,
                enable_hsts=config.enable_hsts,
                max_concurrent_requests=config.a2a_max_concurrent_requests,
                rate_limit_per_ip=config.a2a_rate_limit_per_ip,
                rate_limit_window_seconds=config.a2a_rate_limit_window_seconds,
                agent_card_rate_limit_per_ip=config.a2a_agent_card_rate_limit_per_ip,
                agent_card_rate_limit_window_seconds=config.a2a_agent_card_rate_limit_window_seconds,
                allow_direct_a2a=config.allow_direct_a2a,
                a2a_adapter=config.a2a_adapter,
            )
        except ValueError as exc:
            parser.error(str(exc))


if __name__ == "__main__":
    main()

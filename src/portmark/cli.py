from __future__ import annotations

import argparse
import json
import os
import secrets
import shlex
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from .a2a import A2AAuthConfig, serve
from .config import RuntimeConfig
from .factory import HOST_ID, build_envelope, make_demo_envelope, make_host, signer_from_environment
from .logging_config import configure_logging
from .tool_loading import ToolLoaderError, load_tools


def _reject_control_characters(parser: argparse.ArgumentParser, name: str, value: str | None) -> None:
    # Control characters and newlines cannot be safely rendered on a single shell export
    # line even when quoted, and have no legitimate place in a key id or issuer. Reject
    # them; everything else is made safe by shlex.quote below (finding #4).
    if value and any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        parser.error(f"{name} must not contain control characters or newlines")


def _atomic_write_json(path: str, obj: dict) -> None:
    # Atomic replace so a crash mid-write never leaves a half-written trust registry
    # (finding #14). Preserve the existing file's permissions when replacing it.
    directory = os.path.dirname(os.path.abspath(path)) or "."
    try:
        mode: int | None = os.stat(path).st_mode & 0o777
    except OSError:
        mode = None
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".trust-registry-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    # Durability: fsync the parent directory so the rename itself survives a crash, not
    # just the file contents (finding #4). Not all platforms permit opening a directory
    # for fsync (Windows); best-effort there.
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def _acquire_exclusive_lock(fd: int, timeout: float = 30.0) -> None:
    """Take an exclusive, OS-released lock on `fd` (finding #4).

    fcntl (POSIX) and msvcrt (Windows) locks are both released by the kernel when the
    holding process dies, so neither can leave a stale lock the way an O_EXCL lock FILE
    would. POSIX flock blocks; msvcrt has no blocking whole-file primitive, so we spin on
    the non-blocking variant until we win or the timeout elapses (then surface the error).
    On a platform offering neither primitive the lock is a documented no-op.
    """
    try:
        import fcntl
    except ImportError:
        fcntl = None  # type: ignore[assignment]
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return
    try:
        import msvcrt
    except ImportError:
        return  # neither fcntl nor msvcrt: documented no-op (write stays crash-atomic)
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]  # Windows-only; stubs absent on POSIX
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def _release_exclusive_lock(fd: int) -> None:
    # Closing the fd releases either lock, but release explicitly and match the msvcrt
    # locked range (offset 0, 1 byte) so the unlock is well-formed.
    try:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    except ImportError:
        pass
    try:
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]  # Windows-only; stubs absent on POSIX
    except (ImportError, OSError):
        pass


@contextmanager
def _registry_write_lock(path: str):
    """Serialize read -> validate -> merge -> replace across concurrent writers (finding #4).

    Locks a SIDE-CAR file (`<path>.lock`) that is never renamed. Locking `path` itself is
    defeated by the atomic `os.replace`: it swaps the inode, so a second writer locks the
    NEW inode and proceeds concurrently, silently discarding the first writer's rotation
    entry. POSIX uses fcntl.flock, Windows uses msvcrt.locking; on a platform offering
    neither, the write stays crash-atomic but concurrent merges are not serialized.
    """
    lock_path = path + ".lock"
    directory = os.path.dirname(os.path.abspath(lock_path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        _acquire_exclusive_lock(fd)
        yield
    finally:
        try:
            _release_exclusive_lock(fd)
        finally:
            os.close(fd)


def _write_out_registry(parser: argparse.ArgumentParser, path: str, new_registry: dict, merge: bool) -> None:
    with _registry_write_lock(path):
        _write_out_registry_locked(parser, path, new_registry, merge)


def _write_out_registry_locked(parser: argparse.ArgumentParser, path: str, new_registry: dict, merge: bool) -> None:
    # With --force on an existing registry, MERGE the new identity in as a rotation entry
    # rather than clobbering the file (finding #14): losing the other trusted keys on a
    # rotation is a silent trust-downgrade. A duplicate key id carrying a different public
    # key is a conflict, not a merge.
    # Re-check existence INSIDE the lock: two racers that both saw the file absent before
    # locking must not both create-and-clobber. If it exists now, merge regardless of the
    # caller's pre-lock guess (finding #4).
    registry = new_registry
    if merge or os.path.exists(path):
        try:
            existing = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            parser.error(f"could not read existing trust registry {path}: {exc}")
        # Validate the WHOLE existing registry before merging (finding #4): the loose dict
        # build below would silently collapse duplicate ids already in the file and accept
        # malformed entries. _parse_trust_registry enforces strict types, 32-byte keys, and
        # duplicate-id rejection -- fail closed rather than propagate a corrupt registry.
        from .security import _parse_trust_registry

        try:
            _parse_trust_registry(existing)
        except ValueError as exc:
            parser.error(f"existing trust registry {path} is invalid; refusing to merge: {exc}")
        by_id = {entry.get("key_id"): entry for entry in existing["identities"] if isinstance(entry, dict)}
        merged = list(existing["identities"])
        for entry in new_registry.get("identities", []):
            prior = by_id.get(entry["key_id"])
            if prior is not None:
                if prior.get("public_key_b64") != entry.get("public_key_b64"):
                    parser.error(f"trust registry already has key id {entry['key_id']!r} with a different public key")
                continue  # identical entry already present -> no-op
            merged.append(entry)
        registry = {**existing, "identities": merged}
    _atomic_write_json(path, registry)


def _run_keygen(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    from .security import generate_signing_material

    _reject_control_characters(parser, "--key-id", args.key_id)
    _reject_control_characters(parser, "--issuer", args.issuer)
    if args.out_registry and os.path.exists(args.out_registry) and not args.force:
        parser.error(f"{args.out_registry} already exists; pass --force to overwrite this trust registry")
    material = generate_signing_material(args.key_id, args.issuer, tuple(args.audience or ("*",)))
    if args.out_registry:
        _write_out_registry(parser, args.out_registry, material["trust_registry"], merge=os.path.exists(args.out_registry))
        print(f"wrote trust registry to {args.out_registry}", file=sys.stderr)
    if args.format == "env":
        # shlex.quote every value so an operator-chosen key id / issuer cannot inject
        # shell when the output is eval'd (finding #4). shlex.quote is POSIX only, so we
        # say so: on PowerShell/cmd the value must be set another way. Exported together
        # so the issuer and key id can never drift from the key itself.
        print("# POSIX sh/bash only -- on PowerShell/cmd set these manually or use --format json / --out-registry", file=sys.stderr)
        print(f"export PORTMARK_ED25519_PRIVATE_KEY_B64={shlex.quote(material['private_key_b64'])}")
        print(f"export PORTMARK_SIGNING_KEY_ID={shlex.quote(material['key_id'])}")
        print(f"export PORTMARK_SIGNING_ISSUER={shlex.quote(material['issuer'])}")
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
    parser.add_argument("--allow-local-provider-endpoint", action="store_true", help="allow a LOOPBACK http provider endpoint (dev only; non-loopback still requires https and public addresses only)")
    parser.add_argument("--wasm-component", help="Wasm capsule (.wasm or .wat) implementing the WIT resume ABI")
    parser.add_argument("--wasm-engine", choices=("node", "wasmtime"), help="Wasm provider engine")
    parser.add_argument("--store-backend", choices=("sqlite", "postgres"), help="durable store backend")
    parser.add_argument("--store-path", help="SQLite path or Postgres DSN for durable nonces, checkpoints, and audit heads")
    parser.add_argument("--policy-path", help="JSON host policy path")
    parser.add_argument("--tools", dest="tools_loader", help="load installed tools from module:function returning a ToolRegistry")
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
    server.add_argument("--a2a-public-base-url", help="absolute https:// base URL to advertise in the Agent Card behind a reverse proxy")
    server.add_argument("--a2a-trusted-proxies", help="comma/space-separated CIDRs whose X-Forwarded-For is trusted for per-client rate limiting")
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
    verify_audit.add_argument("--task-id", required=True, help="task id whose audit chain should be verified")
    args = parser.parse_args()
    from .security import load_trust_registry
    from .storage import create_runtime_store

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
    store = create_runtime_store(config.store_backend, config.store_path, audit_verifier) if config.store_path else None
    if args.command == "verify-audit":
        if store is None:
            parser.error("verify-audit requires --store-path or PORTMARK_STORE_PATH")
        verification = store.verify_audit_chain_status(args.task_id)
        print(json.dumps({"task_id": args.task_id, "status": verification.status, "head_status": verification.head_status, "reason": verification.reason}, indent=2))
        if verification.status == "invalid":
            raise SystemExit(1)
        if verification.status == "unverifiable":
            raise SystemExit(2)
        return
    if args.tools_loader and not config.policy_path:
        parser.error("--tools requires --policy-path or PORTMARK_POLICY_PATH")
    try:
        tools = load_tools(args.tools_loader)
    except ToolLoaderError as exc:
        parser.error(str(exc))
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
        allow_local_provider_endpoint=config.allow_local_provider_endpoint,
        tools=tools,
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
                public_base_url=config.a2a_public_base_url,
                trusted_proxies=config.a2a_trusted_proxies,
            )
        except ValueError as exc:
            parser.error(str(exc))


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import errno
import json
import math
import os
import secrets
import shlex
import stat
import sys
import time
from dataclasses import asdict, replace
from pathlib import Path

from .a2a import A2AAuthConfig, serve
from .config import PRODUCTION_PROFILE, RuntimeConfig
from .factory import HOST_ID, build_envelope, make_demo_envelope, make_host, signer_from_environment
from ._durable_file import (  # noqa: F401 -- re-exported names kept for keygen callers/tests
    _acquire_exclusive_lock,
    _release_exclusive_lock,
    atomic_write_bytes,
    sidecar_lock as _registry_write_lock,
)
from .logging_config import configure_logging
from .storage import DEFAULT_ADMIN_PAGE_SIZE, DEFAULT_EXPORT_EVENTS, MAX_PRUNE_BATCH
from .tool_loading import ToolLoaderError, load_tools


def _reject_control_characters(parser: argparse.ArgumentParser, name: str, value: str | None) -> None:
    # Control characters and newlines cannot be safely rendered on a single shell export
    # line even when quoted, and have no legitimate place in a key id or issuer. Reject
    # them; everything else is made safe by shlex.quote below (finding #4).
    if value and any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        parser.error(f"{name} must not contain control characters or newlines")


def _atomic_write_json(path: str, obj: dict) -> None:
    # Atomic replace so a crash mid-write never leaves a half-written trust registry
    # (finding #14); file + parent-directory fsync and permission preservation live in
    # _durable_file, shared with the Section 10 audit floor.
    atomic_write_bytes(path, json.dumps(obj, indent=2).encode("utf-8"), prefix=".trust-registry-")


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
        # Section 10 PR B: every rewrite raises the registry's monotonic version, so an audit
        # floor that recorded the newer registry refuses an older copy restored later.
        prior_version = existing.get("version", 0)
        registry = {**existing, "identities": merged, "version": (prior_version if isinstance(prior_version, int) else 0) + 1}
    else:
        registry = {**new_registry, "version": 1}
    _atomic_write_json(path, registry)


def _registry_identity(path: str | None) -> tuple[int | None, str | None]:
    """(version, digest) of the trust registry FILE, as the audit floor records them."""
    if not path:
        return None, None
    from .security import TrustSource

    source = TrustSource.from_path(path)
    return source.version, source.digest


def _apply_audit_floor(parser, config, store, audit_verifier, task_id, verification):
    from .witness import FloorError, LocalFloorWitness, apply_floor

    if not config.audit_floor_path:
        return apply_floor(verification, None, store, task_id, None, None)
    if audit_verifier is None:
        return replace(verification, status="invalid" if verification.status == "invalid" else "unverifiable",
                       floor_status="floor-unverifiable")
    try:
        witness = LocalFloorWitness.for_verification(config.audit_floor_path, audit_verifier)
    except FloorError as error:
        return replace(verification, status="invalid", reason=verification.reason if verification.status == "invalid" else str(error),
                       floor_status=error.code)
    if witness is None:
        # No file at the given path: apply_floor distinguishes "never created" from "lost" via the marker,
        # but needs the host id -- which is the configured one.
        witness = LocalFloorWitness(config.audit_floor_path, config.host_id, None, audit_verifier)
    version, digest = _registry_identity(config.trust_registry_path)
    return apply_floor(verification, witness, store, task_id, version, digest)


def _apply_remote_witness(parser, config, store, verification):
    """EV-013: compare this database's last witness receipt with the remote witness. The request is signed
    as PORTMARK_REMOTE_WITNESS_SIGNER (an enrolled auditor) or, by default, as the host id."""
    from .remote_witness import WITNESS_UNAVAILABLE
    from .witness_binding import (
        ANCHORED,
        NO_REMOTE,
        REMOTE_WITNESS_SIGNER_ENV,
        WITNESS_UNCONFIGURED,
        HostWitness,
        client_from_environment,
        stored_receipt,
    )

    signer = (os.environ.get(REMOTE_WITNESS_SIGNER_ENV) or "").strip() or config.host_id
    try:
        client = client_from_environment(signer)
    except ValueError as error:
        parser.error(str(error))
    if client is None:
        if stored_receipt(store, config.host_id) is None:
            return verification, NO_REMOTE
        # Remote witnessing was on for this database (the host refuses to start this way too). Without the
        # witness, a restore of the database AND its local floor together cannot be ruled out.
        if verification.status == "invalid":
            return verification, WITNESS_UNCONFIGURED
        return replace(verification, status="unverifiable", reason=(
            "this database holds a remote-witness receipt, but no remote witness is configured "
            "(PORTMARK_REMOTE_WITNESS_URL); rollback cannot be ruled out")), WITNESS_UNCONFIGURED
    status = HostWitness(client, config.host_id).status(store)
    if status == ANCHORED:
        return verification, status
    if verification.status == "invalid":
        return verification, status
    if status == WITNESS_UNAVAILABLE:
        return replace(verification, status="unverifiable", reason="the remote witness could not be asked; rollback cannot be ruled out"), status
    return replace(verification, status="invalid", reason=f"the remote witness does not accept this database ({status})"), status


def _remote_recovery(parser: argparse.ArgumentParser, args: argparse.Namespace, config):
    """EV-013, for an operator recovery (`floor-reset`, `time-floor reset`): the host's binding to the remote
    witness (None when none is configured) and the operator's client (None without --operator-id)."""
    from .witness_binding import HostWitness, client_from_environment

    if bool(args.operator_id) != bool(args.operator_key_file):
        parser.error("--operator-id and --operator-key-file go together")
    try:
        host_client = client_from_environment(config.host_id)
        operator = client_from_environment(args.operator_id, key_file=args.operator_key_file) if args.operator_id else None
    except ValueError as error:
        parser.error(str(error))
    if args.operator_id and (host_client is None or operator is None):
        parser.error("--operator-key-file rebaselines the remote witness, which needs PORTMARK_REMOTE_WITNESS_URL")
    return (None if host_client is None else HostWitness(host_client, config.host_id)), operator


def _registry_body(trust) -> dict | None:
    """The trust registry a rebaseline names: {version, digest} of a versioned registry, else None."""
    return {"version": trust.version, "digest": trust.digest} if trust is not None and trust.version else None


def _database_heads(store, host_id: str) -> dict:
    return {task_id: {"sequence": sequence, "head_hash": head_hash} for task_id, head_hash, sequence in store.audit_heads_for_host(host_id)}


_FLOOR_RESET_COMMAND = "`portmark floor-reset --reason <text> --confirm --operator-id <id> --operator-key-file <file>`"


def _rebaseline_note(error, local: str) -> str:
    """What the operator does next after a rebaseline failed. `local` says what already changed locally."""
    from .witness_binding import REBASELINE_INCOMPLETE, REBASELINE_UNCONFIRMED

    if error.code == REBASELINE_UNCONFIRMED:
        return (f"{local} The witness did not confirm the rebaseline and may have accepted it, so this database may no longer "
                f"match it. Run {_FLOOR_RESET_COMMAND}: it rebaselines from this database either way.")
    if error.code == REBASELINE_INCOMPLETE:
        return (f"{local} The witness WAS rebaselined (its floor is set), but not every task head was sent; the host can start, "
                f"and those tasks are witnessed again from their next save. To send every head, run {_FLOOR_RESET_COMMAND}.")
    return f"{local} The witness refused the rebaseline and did not change: fix the cause and run the same command again."


def _refuse_remote(result: dict, error) -> None:
    print(json.dumps({**result, "remote_status": "refused", "remote_code": error.code, "reason": str(error)}, indent=2))
    raise SystemExit(1) from error


def _run_floor_reset(parser: argparse.ArgumentParser, args: argparse.Namespace, config, store) -> None:
    from .security import TrustSource
    from .witness import FloorError, LocalFloorWitness, reset_audit_floor
    from .witness_binding import stored_receipt

    if not args.confirm:
        parser.error("floor-reset accepts the CURRENT database as truth; re-run with --confirm once the cause is understood")
    if store is None or not config.audit_floor_path or not config.trust_registry_path:
        parser.error("floor-reset requires --store-path, --audit-floor-path, and --trust-registry-path")
    trust = TrustSource.from_path(config.trust_registry_path)
    signer = signer_from_environment(config.host_id, config.trust_registry_path, trust=trust)
    if getattr(signer, "ephemeral", None) is not False:
        parser.error("floor-reset must sign with the host's stable audit key (PORTMARK_ED25519_PRIVATE_KEY_B64), not a generated one")
    store.set_audit_head_verifier(trust)
    remote, operator = _remote_recovery(parser, args, config)
    if operator is not None:
        # Before anything local changes: the witness answers and knows this host.
        try:
            remote.state()
        except FloorError as error:
            _refuse_remote({"host_id": config.host_id, "status": "refused"}, error)
    witness = LocalFloorWitness(config.audit_floor_path, config.host_id, signer, signer)
    try:
        epoch = reset_audit_floor(witness, store, args.reason, trust.version or None, trust.digest, allow_legacy_anchor=args.allow_legacy_anchor)
    except FloorError as error:
        print(json.dumps({"host_id": config.host_id, "status": "refused", "floor_status": error.code, "reason": str(error)}, indent=2))
        raise SystemExit(1) from error
    print(f"WARNING: audit floor for {config.host_id} was reset to epoch {epoch}; the current database is now the baseline.", file=sys.stderr)
    result: dict = {"host_id": config.host_id, "status": "reset", "epoch": epoch}
    if operator is not None and remote is not None:
        # EV-013: the local reset above re-verified every chain first, so a tampered chain is never
        # rebaselined into the witness either. The heads go in pages that each fit one request.
        try:
            remote_epoch = remote.rebaseline(operator, store, _database_heads(store, config.host_id), args.reason, _registry_body(trust),
                                             int(store.time_floor()))
        except FloorError as error:
            _refuse_remote({**result, "note": _rebaseline_note(error, "The local floor was reset.")}, error)
        print(f"WARNING: the remote witness for {config.host_id} was rebaselined to epoch {remote_epoch}.", file=sys.stderr)
        result.update(remote_status="rebaselined", remote_epoch=remote_epoch)
    elif stored_receipt(store, config.host_id) is not None:
        # The witness keeps its own chain: a database it does not accept stays refused at start.
        print("WARNING: the remote witness was NOT rebaselined (no --operator-id); the host starts only if the witness "
              "accepts this database.", file=sys.stderr)
        result["remote_status"] = "not-rebaselined"
    print(json.dumps(result, indent=2))


def _floor_reader(config, audit_verifier):
    """A read-only audit-floor handle when one is configured (for the mirrored time floor), else None."""
    from .witness import LocalFloorWitness

    if not config.audit_floor_path:
        return None
    if audit_verifier is None:
        raise SystemExit("reading the audit floor needs --trust-registry-path (its signature is verified)")
    return LocalFloorWitness(config.audit_floor_path, config.host_id, None, audit_verifier)


def _finite_seconds(value: str) -> float:
    """A finite, POSITIVE number of seconds.

    `type=float` accepts `nan` and `inf`, and a deadline built from either is never reached: `now >= nan`
    is false for ever, and `now >= inf` never becomes true. The flag would then switch off the one thing it
    exists to set. A non-number is left to argparse, whose own message already names the option."""
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError(
            f"must be a finite positive number of seconds, not {value!r}"
        )
    return parsed


def _mcp_token_refresher(config):
    """A background refresher for the configured MCP servers, or None when there is nothing to renew.

    Only `serve` gets one: it is the only launcher that runs a host for longer than one call AND installs
    MCP tools. `portmark.asgi:create_app` -- the other long-lived entry point -- does not touch MCP at all,
    and `demo` is a single run. Starting a thread for a one-shot command would be noise."""
    if not config.mcp_config_path:
        return None
    from .mcp import TokenRefresher  # noqa: PLC0415 - only a host with MCP servers pays for this
    from .mcp_config import load_config  # noqa: PLC0415 - as above

    refresher = TokenRefresher(load_config(config.mcp_config_path))
    return refresher if refresher.wanted else None


def _run_mcp(parser: argparse.ArgumentParser, args: argparse.Namespace, config) -> None:
    """`portmark mcp pin | login | logout`."""
    from .mcp import dumps, pin_report, refresh_oauth_tokens
    from .mcp_config import McpConfigError, load_config
    from .mcp_oauth import McpOAuthError
    from .mcp_token_store import TokenStoreError

    if not config.mcp_config_path:
        parser.error(f"mcp {args.mcp_command} requires --mcp-config or PORTMARK_MCP_CONFIG")
    path = config.mcp_config_path
    try:
        if args.mcp_command == "login":
            from .mcp_login import login  # noqa: PLC0415 - only this command pays for the SDK import

            print(dumps(login(path, args.server, manual=args.manual,
                              redirect_uri=args.redirect_uri or "", total_seconds=args.timeout)))
            return
        if args.mcp_command == "logout":
            from .mcp_login import logout  # noqa: PLC0415 - as above

            print(dumps(logout(path, args.server)))
            return
        # `pin` probes each server, and an OAuth server's probe carries the stored access token. Renewing it
        # first is what makes `mcp pin` usable an hour after logging in; it is a convenience and not a
        # guard, because a stale token makes the worker refuse rather than send an unauthenticated request.
        # SCOPED to what is about to be probed. Renewing every server would let one unrelated OAuth
        # server -- never logged in to, or with its client id unset -- stop the operator pinning a server
        # that is perfectly well configured.
        refresh_oauth_tokens(load_config(path), only=args.server)
        print(dumps(pin_report(path, args.server)))
    except (McpConfigError, McpOAuthError, TokenStoreError) as error:
        parser.error(str(error))


def _install_mcp_tools(parser: argparse.ArgumentParser, path: str, tools):
    """Check every pin against the live servers, then register the approved tools. Fails closed on drift."""
    from .mcp import check_pins, refresh_oauth_tokens, register_mcp_tools
    from .mcp_config import McpConfigError, load_config
    from .mcp_oauth import McpOAuthError
    from .mcp_token_store import TokenStoreError
    from .security import SecurityError
    from .tools import ToolRegistry

    registry = tools if tools is not None else ToolRegistry()
    try:
        mcp_config = load_config(path)
        # BEFORE the pin check, because a pin check probes every server and an OAuth server's probe needs a
        # usable access token. Renewing drives the SDK, so it happens here in the host and never inside the
        # isolated worker, which only reads the string this leaves in the store.
        refresh_oauth_tokens(mcp_config)
        check_pins(mcp_config)
        names = register_mcp_tools(registry, mcp_config)
    except (McpConfigError, SecurityError, McpOAuthError, TokenStoreError) as error:
        parser.error(str(error))
    print(f"MCP tools registered: {', '.join(names)}", file=sys.stderr)
    return registry


def _run_audit(parser: argparse.ArgumentParser, args: argparse.Namespace, store, audit_verifier) -> None:
    """`portmark audit export` and `portmark audit verify-export` (MCP/SIEM plan PR 1, owner decision D3c).

    Both report on stderr, so stdout can carry the exported records (`export --no-cursor` without --out)."""
    from ._durable_file import sidecar_lock
    from .audit_export import (
        ExportConfigError, ExportCursor, Keyring, ProjectionPolicy, Projector, VerifyReport,
        encode_record, ocsf_encoder, read_export, run_export, verify_against_store, verify_records,
    )
    from .ocsf import product_version

    try:
        if args.audit_command == "export":
            if store is None:
                parser.error("audit export requires --store-path or PORTMARK_STORE_PATH")
            if args.no_cursor and args.cursor_file:
                parser.error("--no-cursor and --cursor-file cannot be combined")
            if not args.no_cursor and not (args.out and args.cursor_file):
                # A cursor may advance only past records that are durably written; a pipe cannot confirm that.
                parser.error("audit export needs --out FILE and --cursor-file FILE (or --no-cursor to print all history)")
            projector = Projector(ProjectionPolicy.load(args.projection_policy), Keyring.load(args.projection_keyring))
            encode = encode_record if args.format == "native" else ocsf_encoder(product_version(), int(time.time()))
            report = _export_with_cursor(
                args, store, audit_verifier, projector, run_export, ExportCursor, sidecar_lock, encode
            )
            print(json.dumps({
                "events": report.events, "heads": report.heads, "tasks_completed": report.tasks,
                "integrity_failures": report.integrity_failures,
            }, indent=2, sort_keys=True), file=sys.stderr)
            if not report.ok:
                raise SystemExit(1)
            return
        verification = VerifyReport()
        with open(args.input, "rb") as handle:
            records = read_export(handle, verification)
        verify_records(records, audit_verifier, verification)
        if args.against_store:
            if store is None:
                parser.error("verify-export --against-store requires --store-path or PORTMARK_STORE_PATH")
            if not args.projection_keyring:
                parser.error("verify-export --against-store requires --projection-keyring")
            verify_against_store(
                records, store, ProjectionPolicy.load(args.projection_policy), Keyring.load(args.projection_keyring), verification
            )
    except ExportConfigError as error:
        parser.error(str(error))
    except OSError as error:
        parser.error(f"{error.filename or 'file'}: {error.strerror}")
    print(json.dumps(verification.as_dict(), indent=2, sort_keys=True))
    if verification.status == "invalid":
        raise SystemExit(1)
    if verification.status == "unverifiable":
        raise SystemExit(2)


def _export_with_cursor(args, store, audit_verifier, projector, run_export, cursor_type, sidecar_lock, encode):
    if args.no_cursor:
        cursor = cursor_type(None)
        if args.out:
            with _open_append(args.out) as out:
                return run_export(
                    store, cursor, projector, out, verifier=audit_verifier, page_size=args.page_size,
                    max_events=args.max_events, encode=encode,
                )
        return run_export(
            store, cursor, projector, sys.stdout.buffer, verifier=audit_verifier, durable=False,
            page_size=args.page_size, max_events=args.max_events, encode=encode,
        )
    # One exporter per cursor: a second concurrent run would export the same records and race the cursor.
    with sidecar_lock(args.cursor_file):
        cursor = cursor_type.load(args.cursor_file)
        with _open_append(args.out) as out:
            return run_export(
                store, cursor, projector, out, verifier=audit_verifier, page_size=args.page_size,
                max_events=args.max_events, encode=encode,
            )


def _open_append(path: str):
    # O_NOFOLLOW: a redirected link cannot send projected audit data somewhere else. A new file is 0600;
    # an existing file keeps its mode, because a log shipper often reads it as another user (OPERATIONS.md).
    # O_NONBLOCK: a FIFO with no reader fails at once instead of hanging the export (a regular file ignores it).
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags, 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(errno.EINVAL, "export output must be a regular file", path)
    return os.fdopen(fd, "ab")


def _run_store(parser: argparse.ArgumentParser, args: argparse.Namespace, config, store, audit_verifier) -> None:
    """Section 12 #4: `portmark store stats` and `portmark store prune` (owner decision D2)."""
    from ._clock import TimeFloorError
    from .maintenance import parse_cutoff, run_prune

    if store is None:
        parser.error(f"store {args.store_command} requires --store-path or PORTMARK_STORE_PATH")
    if args.store_command == "stats":
        print(json.dumps(store.capacity_report(), indent=2, sort_keys=True))
        return
    if args.store_command == "encrypt-checkpoints":
        from .security import SecurityError

        if not hasattr(store, "encrypt_checkpoints"):
            parser.error("encrypt-checkpoints needs a durable store (sqlite or postgres)")
        try:
            report = store.encrypt_checkpoints(apply=args.apply)
        except ValueError as error:
            parser.error(str(error))
        except SecurityError as error:
            print(json.dumps({"status": "refused", "reason": str(error)}, indent=2))
            raise SystemExit(1) from error
        if not args.apply:
            print("DRY RUN: nothing was written. Re-run with --apply to encrypt the checkpoints.", file=sys.stderr)
        print(json.dumps(report, indent=2, sort_keys=True))
        return
    try:
        before = parse_cutoff(args.before)
    except ValueError as error:
        parser.error(str(error))
    try:
        report = run_prune(store, _floor_reader(config, audit_verifier), before, apply=args.apply, batch_size=args.batch_size)
    except TimeFloorError as error:
        print(json.dumps({"status": "refused", "time_floor_status": error.code, "reason": str(error)}, indent=2))
        raise SystemExit(1) from error
    except ValueError as error:
        parser.error(str(error))
    if not args.apply:
        print("DRY RUN: nothing was deleted. Re-run with --apply to delete the eligible rows.", file=sys.stderr)
    print(json.dumps(report, indent=2, sort_keys=True))


def _run_time_floor(parser: argparse.ArgumentParser, args: argparse.Namespace, config, store, audit_verifier) -> None:
    """Section 12 #6: `portmark time-floor show` and the explicit operator recovery `time-floor reset`."""
    import time as _time

    from .maintenance import reset_time_floor, time_floor_status
    from .witness import FloorError, LocalFloorWitness

    if store is None:
        parser.error(f"time-floor {args.time_floor_command} requires --store-path or PORTMARK_STORE_PATH")
    from .security import TrustSource
    from .witness_binding import REMOTE_WITNESS_URL_ENV, stored_receipt

    if args.time_floor_command == "show":
        report = time_floor_status(store, _floor_reader(config, audit_verifier))
        try:
            from .witness_binding import host_witness_from_environment

            remote = host_witness_from_environment(config.host_id)
        except ValueError as error:
            parser.error(str(error))
        if remote is not None:
            # EV-013: the witness keeps its own copy of the floor, and the boot clock check uses it too.
            try:
                report["remote_floor"] = int(remote.state()["time_floor"])
            except FloorError as error:
                report.update(remote_floor=None, remote_status=error.code)
        elif stored_receipt(store, config.host_id) is not None:
            from .witness_binding import WITNESS_UNCONFIGURED

            report.update(remote_floor=None, remote_status=WITNESS_UNCONFIGURED)
        print(json.dumps(report, indent=2, sort_keys=True))
        return
    if not args.confirm:
        parser.error("time-floor reset changes the durable time floor, which may LOWER it; re-run with --confirm once the clock is known to be right")
    witness = trust = None
    if config.audit_floor_path:
        if not config.trust_registry_path:
            parser.error("time-floor reset with an audit floor needs --trust-registry-path (the mirrored floor is signed)")
        trust = TrustSource.from_path(config.trust_registry_path)
        signer = signer_from_environment(config.host_id, config.trust_registry_path, trust=trust)
        if getattr(signer, "ephemeral", None) is not False:
            parser.error("time-floor reset must sign the audit floor with the host's stable audit key (PORTMARK_ED25519_PRIVATE_KEY_B64)")
        witness = LocalFloorWitness(config.audit_floor_path, config.host_id, signer, signer)
    # EV-013: the remote witness keeps its own time floor, and the boot clock check takes the highest one.
    # Everything about it is checked BEFORE the local floors change, so a refusal changes nothing.
    remote, operator = _remote_recovery(parser, args, config)
    rebaseline = False
    if remote is None and stored_receipt(store, config.host_id) is not None:
        parser.error(f"this database holds a remote-witness receipt, and the witness keeps its own time floor; set {REMOTE_WITNESS_URL_ENV}, "
                     "PORTMARK_REMOTE_WITNESS_PUBLIC_KEY and PORTMARK_REMOTE_WITNESS_KEY_FILE")
    if remote is not None:
        try:
            # Only a database the witness accepts: the rebaseline below takes this database's heads as they
            # are, so a restored database must go through `floor-reset` (which re-verifies every chain).
            state = remote.check_boot(store)
        except FloorError as error:
            _refuse_remote({"status": "refused", "note": "Nothing was changed. The witness does not accept this database (it was "
                            "restored, or an earlier rebaseline was not confirmed to this database): recover it with "
                            f"{_FLOOR_RESET_COMMAND}."}, error)
        rebaseline = int(state["time_floor"]) > args.to
        if rebaseline and operator is None:
            parser.error(f"the remote witness holds a time floor of {state['time_floor']}, above --to; lowering it is an operator "
                         "rebaseline: add --operator-id and --operator-key-file")
        if rebaseline and trust is None:
            if not config.trust_registry_path:
                parser.error("lowering the remote witness's time floor needs --trust-registry-path (the rebaseline names the registry)")
            trust = TrustSource.from_path(config.trust_registry_path)
    try:
        outcome = reset_time_floor(store, witness, args.to, args.reason, int(_time.time()))
    except (ValueError, FloorError) as error:
        print(json.dumps({"status": "refused", "reason": str(error)}, indent=2))
        raise SystemExit(1) from error
    print(f"WARNING: the durable time floor was set to {args.to} by an operator ({args.reason!r}).", file=sys.stderr)
    if rebaseline:
        try:
            remote_epoch = remote.rebaseline(operator, store, _database_heads(store, config.host_id), args.reason, _registry_body(trust), args.to)
        except FloorError as error:
            _refuse_remote({"status": "reset", **outcome, "note": _rebaseline_note(error, "The local floors were reset.")}, error)
        print(f"WARNING: the remote witness for {config.host_id} was rebaselined to epoch {remote_epoch} to lower its time floor.", file=sys.stderr)
        outcome.update(remote_status="rebaselined", remote_epoch=remote_epoch)
    elif remote is not None:
        outcome["remote_status"] = "unchanged"
    print(json.dumps({"status": "reset", **outcome}, indent=2, sort_keys=True))


def _run_witness(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """EV-013: the reference remote witness. It needs no host, store, or trust registry."""
    from .remote_witness import generate_key_file, key_id_for
    from .security import _b64url_encode

    if args.witness_command == "keygen":
        try:
            public_key = generate_key_file(args.out)
        except FileExistsError:
            parser.error(f"{args.out} exists; a witness key is never overwritten")
        except OSError as error:
            parser.error(f"cannot write {args.out}: {error}")
        print(json.dumps({"key_id": key_id_for(public_key), "public_key_b64": _b64url_encode(public_key)}, indent=2))
        return
    if args.witness_command == "serve":
        from .witness_server import serve_witness

        try:
            serve_witness(args.db, args.key_file, args.enrolment, args.bind, args.port, args.public_mode)
        except ValueError as error:
            print(json.dumps({"status": "refused", "reason": str(error)}, indent=2))
            raise SystemExit(2) from error
        return
    from .remote_witness import decode_public_key, http_transport, load_private_key_file
    from .witness_conformance import run_witness_conformance

    try:
        transport = http_transport(args.url, args.timeout)
        pinned = decode_public_key(args.witness_public_key)
        host_key = load_private_key_file(args.host_key_file)
        report = run_witness_conformance(transport, pinned, args.host_id, host_key)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(report.to_dict(), indent=2))
    if not report.passed:
        raise SystemExit(1)


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


def _run_attest_conformance(parser: argparse.ArgumentParser, args: argparse.Namespace, config: RuntimeConfig) -> None:
    from .security import ExternalAttestationVerifier
    from .verifier_conformance import load_base_request, run_conformance

    if not config.attestation_verifier_command:
        parser.error("attest-conformance requires --attestation-verifier-command or PORTMARK_ATTESTATION_VERIFIER_COMMAND")
    try:
        with open(args.evidence, encoding="utf-8") as handle:
            base = load_base_request(json.load(handle))
    except (OSError, ValueError) as error:
        parser.error(f"--evidence: {error}")
    report = run_conformance(ExternalAttestationVerifier(config.attestation_verifier_command), base)
    print(json.dumps(report.to_dict(), indent=2))
    if not report.passed:
        raise SystemExit(1)


def _run_preflight_conformance(parser: argparse.ArgumentParser, args: argparse.Namespace, config: RuntimeConfig) -> None:
    from .security import AttestationPolicy, ExternalAttestationVerifier, ExternalMigrationPreflight
    from .verifier_conformance import run_preflight_conformance

    # The same three settings the production profile requires for a host that migrates.
    missing = [
        name for name, value in (
            ("PORTMARK_MIGRATION_PREFLIGHT_COMMAND", config.migration_preflight_command),
            ("PORTMARK_ATTESTATION_VERIFIER_COMMAND (or --attestation-verifier-command)", config.attestation_verifier_command),
            ("PORTMARK_ATTESTATION_ALLOWED_MEASUREMENTS", config.attestation_allowed_measurements),
        ) if not value
    ]
    if missing:
        parser.error("preflight-conformance requires " + ", ".join(missing))
    policy = AttestationPolicy(
        allowed_measurements=config.attestation_allowed_measurements,
        external_verifier=ExternalAttestationVerifier(config.attestation_verifier_command),
        require_migration_challenge=True,
    )
    report = run_preflight_conformance(
        ExternalMigrationPreflight(config.migration_preflight_command), policy, args.destination, config.host_id or HOST_ID
    )
    print(json.dumps(report.to_dict(), indent=2))
    if not report.passed:
        raise SystemExit(1)


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
    parser.add_argument(
        "--mcp-config",
        help="JSON file naming the MCP servers and the tools they may expose, each approved by its pin (MCP.md)",
    )
    parser.add_argument("--trust-registry-path", help="JSON trust registry path for envelope signing keys")
    parser.add_argument(
        "--audit-floor-path",
        help="this host's signed audit floor file (Section 10), OUTSIDE the store directory; detects rollback of the "
        "database or trust registry relative to the surviving floor file (PORTMARK_AUDIT_FLOOR_PATH)",
    )
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
    floor_reset = subparsers.add_parser(
        "floor-reset",
        help="OPERATOR RECOVERY: accept the current database as truth and start a new audit-floor epoch",
    )
    floor_reset.add_argument("--reason", required=True, help="why the floor is being reset (recorded in the floor)")
    floor_reset.add_argument("--confirm", action="store_true", help="required: acknowledge that the current database is accepted as truth")
    floor_reset.add_argument(
        "--allow-legacy-anchor", action="store_true", help="accept complete pre-Section-10 migration anchors while re-verifying chains"
    )
    floor_reset.add_argument("--operator-id", help="EV-013: an operator id enrolled with the remote witness (rebaselines it too)")
    floor_reset.add_argument("--operator-key-file", help="EV-013: that operator's Ed25519 private key file (the host never holds it)")
    store_parser = subparsers.add_parser("store", help="inspect store capacity or prune provably-unneeded rows (Section 12)")
    store_commands = store_parser.add_subparsers(dest="store_command", required=True)
    store_commands.add_parser("stats", help="row counts, oldest pending migration, database size, free space, time floor")
    prune = store_commands.add_parser(
        "prune",
        help="delete expired nonces and delivered migrations older than --before (a DRY RUN unless --apply)",
    )
    prune.add_argument("--before", required=True, help="retention cutoff: epoch seconds or ISO-8601 (UTC if no offset)")
    prune.add_argument("--apply", action="store_true", help="actually delete (default: report only)")
    prune.add_argument("--batch-size", type=int, default=MAX_PRUNE_BATCH, help=f"rows per transaction (1..{MAX_PRUNE_BATCH})")
    encrypt = store_commands.add_parser(
        "encrypt-checkpoints",
        help="EV-006: seal every plaintext checkpoint with the checkpoint keyring in one transaction (stop the host first)",
    )
    encrypt.add_argument("--apply", action="store_true", help="actually write (default: report only)")
    time_floor = subparsers.add_parser("time-floor", help="show the durable time floor, or reset it (OPERATOR RECOVERY)")
    time_floor_commands = time_floor.add_subparsers(dest="time_floor_command", required=True)
    time_floor_commands.add_parser("show", help="database floor, mirrored floor, host and database clocks")
    floor_set = time_floor_commands.add_parser(
        "reset",
        help="OPERATOR RECOVERY: set the durable time floor (may lower it) after a wrong clock moved it forward",
    )
    floor_set.add_argument("--to", type=int, required=True, help="the new floor, in epoch seconds")
    floor_set.add_argument("--reason", required=True, help="why (recorded in the maintenance log and the audit floor)")
    floor_set.add_argument("--confirm", action="store_true", help="required: acknowledge that this may lower the floor")
    floor_set.add_argument("--operator-id", help="EV-013: an operator id enrolled with the remote witness (lowers ITS time floor too)")
    floor_set.add_argument("--operator-key-file", help="EV-013: that operator's Ed25519 private key file (the host never holds it)")
    conformance = subparsers.add_parser(
        "attest-conformance",
        help="run the EV-004 conformance kit against the external attestation verifier command (before production use)",
    )
    conformance.add_argument(
        "--evidence",
        required=True,
        help="a real, known-good verifier request (JSON, the stdin shape of the verifier contract) with a fresh platform quote",
    )
    preflight_kit = subparsers.add_parser(
        "preflight-conformance",
        help="check that PORTMARK_MIGRATION_PREFLIGHT_COMMAND attests a destination the way migration verifies it",
    )
    preflight_kit.add_argument("--destination", required=True, help="the destination host id to attest (a real one)")
    witness_parser = subparsers.add_parser("witness", help="EV-013: run or check a remote witness (the reference server)")
    witness_commands = witness_parser.add_subparsers(dest="witness_command", required=True)
    witness_keygen = witness_commands.add_parser("keygen", help="write a new Ed25519 private key (mode 600) and print its public key")
    witness_keygen.add_argument("--out", required=True, help="private key file to create (never overwritten)")
    witness_serve = witness_commands.add_parser("serve", help="run the reference remote witness (on a machine OUTSIDE the host's failure domain)")
    witness_serve.add_argument("--db", required=True, help="the witness SQLite file (created mode 600)")
    witness_serve.add_argument("--key-file", required=True, help="the witness's own Ed25519 private key file (`portmark witness keygen`)")
    witness_serve.add_argument("--enrolment", required=True, help="JSON: the host, operator, and auditor public keys (portmark.witness.enrolment.v1)")
    witness_serve.add_argument("--bind", default="127.0.0.1", help="listen address (default loopback)")
    witness_serve.add_argument("--port", type=int, default=8787)
    witness_serve.add_argument(
        "--public-mode", help="behind-tls-proxy: required for a non-loopback bind (a reverse proxy terminates TLS in front)"
    )
    witness_kit = witness_commands.add_parser(
        "conformance", help="check that a deployed witness enforces the chain rules (uses a dedicated conformance: host id)"
    )
    witness_kit.add_argument("--url", required=True, help="the witness base URL (https, or http on loopback)")
    witness_kit.add_argument("--host-id", required=True, help="an enrolled host id starting with 'conformance:' (never a real host's id)")
    witness_kit.add_argument("--host-key-file", required=True, help="that host id's Ed25519 private key file")
    witness_kit.add_argument("--witness-public-key", required=True, help="the witness's public key (base64url), pinned for every answer")
    witness_kit.add_argument("--timeout", type=float, default=5.0, help="seconds per request (default 5)")
    mcp_parser = subparsers.add_parser("mcp", help="inspect the tools an MCP server offers, and their pins")
    mcp_commands = mcp_parser.add_subparsers(dest="mcp_command", required=True)
    mcp_pin = mcp_commands.add_parser(
        "pin", help="print each tool an MCP server offers now, with the pin to approve it (it never approves)"
    )
    mcp_pin.add_argument("--server", help="one server from the config (default: every server)")
    from .mcp_login import DEFAULT_LOGIN_SECONDS as MCP_LOGIN_SECONDS  # noqa: PLC0415 - parser text only
    from .mcp_login import DEFAULT_REDIRECT as MCP_DEFAULT_REDIRECT  # noqa: PLC0415 - parser text only

    mcp_login = mcp_commands.add_parser(
        "login", help="authorize Portmark against one OAuth MCP server, and store what it grants"
    )
    mcp_login.add_argument("server", help="the server from the config to authorize")
    mcp_login.add_argument(
        "--manual", action="store_true",
        help="print the url and read the redirect you paste back, for a machine with no browser",
    )
    mcp_login.add_argument(
        "--redirect-uri",
        help=f"the redirect registered with the provider (default {MCP_DEFAULT_REDIRECT}); "
             "without --manual it must be a loopback http address, which is what is listened on",
    )
    mcp_login.add_argument(
        "--timeout", type=_finite_seconds, default=MCP_LOGIN_SECONDS,
        help=f"seconds for the WHOLE login, including your time in the browser (default {MCP_LOGIN_SECONDS:g})",
    )
    mcp_logout = mcp_commands.add_parser("logout", help="delete the stored authorization for one server")
    mcp_logout.add_argument("server", help="the server from the config to forget")
    audit_parser = subparsers.add_parser("audit", help="export the audit chains for a SIEM, or verify an export")
    audit_commands = audit_parser.add_subparsers(dest="audit_command", required=True)
    export_parser = audit_commands.add_parser(
        "export", help="append new audit records, as a policy-controlled projection, to a JSON Lines file"
    )
    export_parser.add_argument("--out", help="JSON Lines file to append to (fsynced before the cursor advances)")
    export_parser.add_argument("--cursor-file", help="per-task export cursor (created on first run)")
    export_parser.add_argument("--no-cursor", action="store_true", help="export all history and save no cursor")
    export_parser.add_argument("--projection-policy", help="JSON projection policy (default: built-in, host-written fields only)")
    export_parser.add_argument(
        "--projection-keyring", required=True, help="dedicated HMAC keyring for digests (mode 600; never a signing key)"
    )
    export_parser.add_argument(
        "--format", choices=("native", "ocsf"), default="native",
        help="record shape: Portmark's own, or OCSF 1.9.0 class 6003 (verify-export reads either)",
    )
    export_parser.add_argument("--page-size", type=int, default=DEFAULT_ADMIN_PAGE_SIZE, help="task heads per page")
    export_parser.add_argument("--max-events", type=int, default=DEFAULT_EXPORT_EVENTS, help="events per page")
    verify_export = audit_commands.add_parser("verify-export", help="verify an exported JSON Lines file (level 1, or 2 with --against-store)")
    verify_export.add_argument("--in", dest="input", required=True, help="exported JSON Lines file")
    verify_export.add_argument(
        "--against-store", action="store_true",
        help="level 2: recompute every exported event from the store (needs --store-path and --projection-keyring)",
    )
    verify_export.add_argument("--projection-policy", help="the projection policy the export used (default: built-in)")
    verify_export.add_argument("--projection-keyring", help="the keyring the export used (level 2)")
    verify_audit = subparsers.add_parser("verify-audit")
    verify_audit.add_argument("--task-id", required=True, help="task id whose audit chain should be verified")
    verify_audit.add_argument(
        "--allow-legacy-anchor",
        action="store_true",
        help=(
            "TEMPORARY migration compatibility: accept a complete pre-Section-10 migration anchor (no kept source "
            "proof) as valid instead of unverifiable. The source proof is NOT reverified; not an equivalent security mode"
        ),
    )
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
    if args.command == "witness":
        _run_witness(parser, args)
        return
    if args.command == "attest-conformance":
        _run_attest_conformance(parser, args, config)
        return
    if args.command == "preflight-conformance":
        _run_preflight_conformance(parser, args, config)
        return
    audit_verifier = load_trust_registry(config.trust_registry_path) if config.trust_registry_path else None
    try:
        store = create_runtime_store(config.store_backend, config.store_path, audit_verifier) if config.store_path else None
    except ValueError as error:
        parser.error(str(error))
    if args.command == "verify-audit":
        if store is None:
            parser.error("verify-audit requires --store-path or PORTMARK_STORE_PATH")
        if args.allow_legacy_anchor:
            # stderr, so stdout stays one valid JSON document for automation.
            print(
                "WARNING: --allow-legacy-anchor is a temporary migration-compatibility mode, NOT an equivalent "
                "security mode: a legacy migration anchor is accepted without independently reverifying the "
                "source proof. Check anchor_status in the output.",
                file=sys.stderr,
            )
        verification = store.verify_audit_chain_status(args.task_id, allow_legacy_anchor=args.allow_legacy_anchor)
        verification = _apply_audit_floor(parser, config, store, audit_verifier, args.task_id, verification)
        verification, remote_status = _apply_remote_witness(parser, config, store, verification)
        print(json.dumps({
            "task_id": args.task_id,
            "status": verification.status,
            "head_status": verification.head_status,
            "anchor_status": verification.anchor_status,
            "floor_status": verification.floor_status,
            "remote_status": remote_status,
            "reason": verification.reason,
        }, indent=2))
        if verification.status == "invalid":
            raise SystemExit(1)
        if verification.status == "unverifiable":
            raise SystemExit(2)
        return
    if args.command == "mcp":
        _run_mcp(parser, args, config)
        return
    if args.command == "audit":
        _run_audit(parser, args, store, audit_verifier)
        return
    if args.command == "floor-reset":
        _run_floor_reset(parser, args, config, store)
        return
    if args.command == "store":
        _run_store(parser, args, config, store, audit_verifier)
        return
    if args.command == "time-floor":
        _run_time_floor(parser, args, config, store, audit_verifier)
        return
    if args.tools_loader and not config.policy_path:
        parser.error("--tools requires --policy-path or PORTMARK_POLICY_PATH")
    if config.mcp_config_path and not config.policy_path:
        parser.error("--mcp-config requires --policy-path or PORTMARK_POLICY_PATH: an MCP tool needs a host grant")
    try:
        tools = load_tools(args.tools_loader)
    except ToolLoaderError as exc:
        parser.error(str(exc))
    if config.mcp_config_path:
        tools = _install_mcp_tools(parser, config.mcp_config_path, tools)
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
        audit_floor_path=config.audit_floor_path,
        attestation_allowed_measurements=config.attestation_allowed_measurements,
        migration_preflight_command=config.migration_preflight_command,
        # Boundary audit (auditor round 1 on #104): the CLI is a supported launcher, so it gets the same
        # production host checks as the ASGI app (audit floor, migration attestation). Its network rule
        # is stricter already: `serve` refuses any non-loopback bind.
        production=config.profile == PRODUCTION_PROFILE,
    )
    if args.command == "demo":
        provider = "wasm" if config.wasm_component else ("http" if config.provider_endpoint else "deterministic")
        result = host.run(make_demo_envelope(host, args.goal, provider))
        print(json.dumps(asdict(result), indent=2))
    else:
        # Started BEFORE `serve` blocks and stopped in `finally`, so an interrupt out of `serve` -- which is
        # how a host normally ends -- still goes through the stop. The daemon flag is a backstop for a hard
        # exit, not a way of saying the thread was shut down.
        refresher = _mcp_token_refresher(config)
        if refresher is not None:
            refresher.start()
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
                shutdown_grace_seconds=config.shutdown_grace_seconds,
                body_read_timeout_seconds=config.a2a_body_read_timeout_seconds,
            )
        except ValueError as exc:
            parser.error(str(exc))
        finally:
            if refresher is not None:
                refresher.stop()


if __name__ == "__main__":
    main()

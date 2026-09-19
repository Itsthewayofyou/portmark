# Operations Runbook

This runbook covers production operations for the reference runtime.

## Configuration

Runtime configuration can come from environment variables or CLI flags:

- `PORTMARK_HOST_ID` / `--host-id`
- `PORTMARK_ED25519_PRIVATE_KEY_B64`
- `PORTMARK_SIGNING_KEY_ID`
- `PORTMARK_SIGNING_ISSUER`
- `PORTMARK_ALLOWED_AUDIENCES`
- `PORTMARK_TRUST_REGISTRY_PATH` / `--trust-registry-path`
- `PORTMARK_AUDIT_FLOOR_PATH` / `--audit-floor-path` (see Audit Floor below)
- `PORTMARK_POLICY_PATH` / `--policy-path`
- `PORTMARK_RELOAD_POLICY` / `--reload-policy`
- `PORTMARK_ATTESTATION_VERIFIER_COMMAND` / `--attestation-verifier-command`
- `PORTMARK_REQUIRE_ATTESTATION` / `--require-attestation`
- `PORTMARK_STORE_PATH` / `--store-path`
- `PORTMARK_STORE_BACKEND` / `--store-backend`
- `PORTMARK_PROVIDER_ENDPOINT` / `--provider-endpoint`
- `PORTMARK_WASM_COMPONENT` / `--wasm-component`
- `PORTMARK_WASM_ENGINE` / `--wasm-engine`
- `PORTMARK_A2A_ADAPTER` / `--a2a-adapter`
- `PORTMARK_A2A_TOKEN` / `--a2a-token`
- `PORTMARK_A2A_MAX_CONCURRENT_REQUESTS` / `--a2a-max-concurrent-requests`
- `PORTMARK_A2A_RATE_LIMIT_PER_IP` / `--a2a-rate-limit-per-ip`
- `PORTMARK_A2A_RATE_LIMIT_WINDOW_SECONDS` / `--a2a-rate-limit-window-seconds`
- `PORTMARK_A2A_AGENT_CARD_RATE_LIMIT_PER_IP` /
  `--a2a-agent-card-rate-limit-per-ip`
- `PORTMARK_A2A_AGENT_CARD_RATE_LIMIT_WINDOW_SECONDS` /
  `--a2a-agent-card-rate-limit-window-seconds`
- `PORTMARK_ALLOW_DIRECT_A2A` / `--allow-direct-a2a` (deprecated no-op;
  non-loopback binds are refused)
- `PORTMARK_LOG_LEVEL` / `--log-level`
- `PORTMARK_LOG_JSON` / `--log-json`
- `PORTMARK_ENABLE_HSTS` / `--enable-hsts`

## Trust Registry

Trust registries are JSON files:

```json
{
  "version": 3,
  "identities": [
    {
      "key_id": "issuer-key",
      "issuer": "host:issuer",
      "public_key_b64": "base64url-raw-ed25519-public-key",
      "allowed_audiences": ["host:destination"],
      "not_before": 1800000000,
      "expires_at": 1800086400,
      "revoked": false
    }
  ]
}
```

Use unique key IDs, short key lifetimes, and explicit `allowed_audiences` where possible. For emergency revocation, set `revoked: true`, deploy the trust registry, and restart hosts or use the deployment's config reload mechanism.

`version` is a monotonic integer (>= 1). **Raise it on every change** (`portmark keygen --force` does).
A host with an audit floor records it and refuses to start on a registry with a LOWER version (for
example an old copy that still trusts a revoked key) or the same version with different content.
A floor requires a versioned registry.

Ed25519 is the default signer. The legacy HMAC signer is blocked unless
`PORTMARK_ALLOW_LEGACY_HMAC=unsafe-test-only` and a non-empty
`PORTMARK_SIGNING_KEY` are both set. Treat that path as a dependency-free test
fixture only; do not use it for a production trust domain.

## Policy Updates

Policy changes should be reviewed, versioned, and deployed with a rollback plan. Approval tokens are bound to policy hashes, so tokens issued before a policy update will be rejected once hosts reload the new policy.

Tool argument constraints can use legacy exact/`max_`/`allowed_` keys or the
schema subset under `constraints.arguments`. Supported schema checks are
`type`, `const`, `enum`, `minimum`, `maximum`, `min_length`, `max_length`,
`pattern`, per-argument `required`, top-level `required`, and
`additional_arguments: false`.

## Attestation Verifier

Production deployments can attach a platform quote verifier without using a
shell:

```bash
portmark --attestation-verifier-command "/opt/portmark/verify-quote --json" \
  --require-attestation \
  serve --port 8080
```

The verifier command receives canonical JSON on stdin containing the unsigned
attestation evidence, expected subject, relying party, expected nonce, and host
time. Attestation evidence must include a non-empty `quote` when an external
verifier is configured. The verifier must exit 0 and return `{"valid": true}`
on stdout. Non-zero exits, timeouts, malformed JSON, oversized stdout, and any
response other than `{"valid": true}` reject the run. Keep the verifier
executable and trust roots owned by the deployment control plane.

## Network Boundary

`portmark serve` runs the A2A boundary on **uvicorn**, an ASGI server, so a slow
or stalled client costs a suspended coroutine rather than a blocked OS thread.
Connection concurrency is bounded by `--max-concurrent-requests`, which is passed
to uvicorn as `limit_concurrency`.

Expose the A2A listener behind a production HTTP stack for public deployments.
TLS termination remains the proxy's responsibility. Run the reference listener on
loopback:

```bash
portmark serve --bind 127.0.0.1 --port 8080
```

Then front it with a production proxy. The repository includes an Nginx example
at `deploy/nginx/portmark.conf` with TLS termination, HTTPS redirect,
`client_max_body_size 1m`, security headers, and proxy-side rate/connection
limits for `/.well-known/agent-card.json`, `/message:send`, and `/metrics`.

`portmark serve` refuses non-loopback binds such as `0.0.0.0`; public exposure
must go through the production proxy boundary. The legacy `--allow-direct-a2a`
flag and `PORTMARK_ALLOW_DIRECT_A2A=1` environment variable are retained only
for configuration compatibility and do not bypass the loopback requirement.
Even when fronted, the reference server still enforces its own
network controls: public Agent Card GETs are rate-limited separately from
message submission, concurrent `/message:send` requests are capped, accepted
submissions are rate-limited per client IP, and oversized submissions are
rejected from `Content-Length` without reading the request body.

The default A2A adapter is `local`. Use `--a2a-adapter sdk` or
`PORTMARK_A2A_ADAPTER=sdk` only when `portmark[a2a]` is installed and you want
Agent Card plus `message/send` request validation through the official
`a2a-sdk` 1.0 protobuf types.

## Audit Verification

For SQLite-backed hosts, run:

```bash
portmark --store-path runtime.sqlite --trust-registry-path trust.json verify-audit --task-id TASK_ID
```

For Postgres-backed hosts, install the optional extra and use the same audit
command with a DSN:

```bash
portmark --store-backend postgres --store-path postgresql://user:pass@db/portmark --trust-registry-path trust.json verify-audit --task-id TASK_ID
```

The command prints `{"status": "valid"}` and exits 0 for an intact chain whose stored audit head is signed by a trusted host key. It prints `{"status": "invalid"}` and exits 1 when the task is missing or when event sequence, previous hash, event hash, stored audit-head validation, missing signature material, trust-registry rejection, or audit-head signature validation fails. It prints `{"status": "unverifiable"}` and exits 2 when the local verifier cannot prove the signed head because no trust registry is configured. Treat invalid results as tampered or corrupted task history; treat unverifiable results as an operator configuration failure and re-run with `--trust-registry-path`.

## Audit Floor

A signed audit head is stored in the same database as the events it signs, so an older, internally
consistent copy of the database verifies as current. The **audit floor** is a small signed file,
kept **outside** the store directory, that remembers the newest audit head this host wrote for each
task and the trust-registry version it runs with. Configure it with `--audit-floor-path` /
`PORTMARK_AUDIT_FLOOR_PATH` (a durable store is required; the path must not be inside the store
directory). A durable store without a floor logs a warning at start.

- **At start** the host refuses to run (and names the reason) if the database or registry is older
  than the floor (`rolled-back`, `registry-rolled-back`), diverges from it (`forked`,
  `registry-forked`), the floor is corrupt or signed by the wrong key (`floor-corrupt`), a floor this
  database recorded is gone (`floor-missing` -- it is **never** rebuilt automatically), the database
  predates the floor (`db-older-than-floor`), or they come from different reset epochs
  (`epoch-mismatch`).
- **On every save** the chain is compared with the floor inside the database transaction, before
  signing, and the floor is advanced as the LAST step inside that transaction, **before** the commit.
  No commit is ever acknowledged that the floor has not already recorded. If the floor write fails,
  the transaction rolls back and nothing is committed.
- **If the commit fails after the floor was written** (a crash in that instant, or a database error),
  the floor is AHEAD of the database. That is indistinguishable from "committed, then the database was
  rolled back", so the task is refused (`rolled-back`) and the floor is never lowered automatically.
  The host logs this as CRITICAL. Recovery is `floor-reset` (below), after confirming the cause.
- **At start**, heads this host signed that the floor has not seen (tasks from before the floor
  existed, or a floor restored from an older copy) are adopted only if their WHOLE chain verifies
  strictly and the head is unchanged right before the write. If ANY such head fails, the host
  **refuses to start** (`unverified-head`, naming the tasks) -- skipping it would let a later save
  write that invalid head into the floor. Investigate the database first; `floor-reset` re-verifies
  every chain and refuses invalid ones too.
- **On every save**, a task that already has a chain but that the floor has never witnessed (for
  example another host's task in a shared database) must verify strictly before the floor records it;
  otherwise the save is refused and nothing is committed.
- **Legacy migration anchors.** Adoption and the save check verify strictly: a complete
  pre-Section-10 migration anchor (`legacy-anchor`) is not accepted silently. To bring such tasks under
  the floor, run `floor-reset --allow-legacy-anchor` (explicit, recorded).
- **A database with a floor cannot be started without it.** Once a floor exists for a host, starting
  that host without `--audit-floor-path` is refused, so the floor cannot be switched off silently.
- **`verify-audit --audit-floor-path FLOOR`** adds `floor_status`: `anchored` (exit 0), `not-anchored`
  (the floor never saw this task; exit 2), or a refusal code (exit 1). Without the flag it reports
  `no-floor` and cannot detect rollback.

**Where to put it.** On storage that is NOT restored together with the database: a separate volume,
ideally append-only or WORM (write once, read many) storage. Do not include it in the database backup.

**What it guarantees, exactly.** It detects rollback or divergence of the database or trust registry **relative to the surviving
authoritative floor file**. It does **not** detect:

1. whole-machine rollback that restores both the database and the floor;
2. copying the database and the floor together (or running clones with independent floor copies);
3. forks across separate hosts;
4. heads signed by a compromised host;
5. backdated signing before compromise.

Also: a database rolled back to before the floor was first created, combined with deleting the
floor, looks like a first run (the "floor exists" marker lives in that database).

**Recovery (operator only).** When a refusal is understood -- for example you deliberately restored a
database backup after losing the disk -- accept the current database as the new baseline:

```bash
portmark --host-id HOST --store-path runtime.sqlite --trust-registry-path trust.json \
  --audit-floor-path /var/lib/portmark-floor/audit-floor.json \
  floor-reset --reason "restored 2026-09-18 nightly backup after disk loss" --confirm
```

`floor-reset` re-verifies every chain this host signed (it refuses to launder a tampered chain), writes
a new floor at the current heads with the next epoch, and records the time, reason, prior epoch, and
the prior floor file's SHA-256 in the floor. It needs the host's stable signing key in the
environment. It is never run automatically: work done after the backup is lost and the reset says so.

## Metrics

`AgentHost` owns an in-process `RuntimeMetrics` instance. Embedders can pass
their own metrics object and export `metrics.snapshot()` through the deployment
telemetry pipeline. The reference A2A server publishes the same snapshot at
`GET /metrics` only when `PORTMARK_A2A_TOKEN` or `--a2a-token` is configured;
requests must include `Authorization: Bearer <token>`. The endpoint is still
served only from the loopback origin and should be exposed publicly only
through the same authenticated production proxy boundary as `/message:send`.
JSON remains the default response. Prometheus scrapers can request
`Accept: text/plain` to receive counters, refusal counts, and latency
histograms. Refusal labels are bounded reason codes only; tool arguments,
user input, task IDs, and other request-controlled values are intentionally
excluded from metric labels.

## Backup And Restore

Back up these assets together:

- runtime database
- active policy file
- trust registry
- attestation verifier roots
- approval authority roots

Restore them as a consistent set. Restoring an old database with a newer policy is allowed, but old approval tokens may fail policy-hash validation.

**Do not back up or restore the audit floor with this set.** Restoring the floor together with the
database defeats it (non-detection 1 above). After restoring an older database, a host with a floor
refuses to start (`rolled-back`); run `floor-reset` deliberately, with the reason, once the restore is
understood. Restoring an older trust registry is refused the same way (`registry-rolled-back`).

## File Permissions

The SQLite store holds checkpoints, messages, tool arguments and results, migration envelopes and
receipts, and audit details. It must be readable by the host's own user only.

- **New stores are owner-only.** On POSIX, the host creates a new database file with mode `0600`
  before SQLite opens it. SQLite then creates the `-wal` and `-shm` side files with the same mode. A
  store directory that the host creates gets mode `0700`.
- **Loose stores are refused.** At start, the host refuses a database, `-wal`, or `-shm` file that has
  any group or other permission bit, and prints the fix, for example `chmod 600 /var/lib/portmark/runtime.sqlite`.
  There is no warning-only mode. Fix the mode, then start again.
- **The store directory is checked too.** A 0600 database in a directory that other users can write is
  not protected: they can delete or rename it and plant its `-wal`/`-shm` files. The host refuses a
  store directory that is group- or other-writable, even with the sticky bit (fix: `chmod 700 <directory>`),
  or that is owned by a user other than the host user or root.
- **Every directory above it is checked, up to `/`.** Renaming a directory needs write access only to
  ITS parent, so a `0700` store directory inside a directory that other users can write can be renamed
  away and replaced between connections. Every component from `/` down must be owned by the host user or
  root, and must not be group- or other-writable (fix: `chmod go-w <directory>`). The one exception is a
  **sticky** directory such as `/tmp`: there, only an entry's owner, the directory owner, or root can
  rename or delete the entry, and every entry on the path is itself required to be owned by the host user
  or root. The existing part of the chain is checked BEFORE the host creates anything; missing directories
  are then created one by one with mode `0700`.
- **The store directory must not be a symlink.** A symlink there lets whoever can replace it redirect the
  store. To put the store on another volume, use a bind mount (or point the store path at the real
  directory). A symlink ABOVE the store directory (for example macOS `/var` -> `/private/var`) is allowed,
  because the walk has already shown that only a trusted user can replace it, and its target is walked
  with the same rules.
- **Container note.** Do not place the database directly in a shared sticky mount (a tmpfs mounted
  `1777`): use a `0700` subdirectory owned by the host user.
- **Store files must be plain files owned by the host user.** The database, `-wal`, and `-shm` are read
  with `lstat`: a symlink, a non-regular file (a FIFO, a device), or a file owned by another user is
  refused. A new database is created with `O_EXCL`, so an existing file or a planted (even dangling)
  symlink at that path is never followed.
- **The check runs when the store is opened.** A running host reconnects by pathname and does not
  re-check the path on every transaction. With the whole chain proven owned by trusted users and not
  writable by others, only the host user or root can change the path afterwards. Portmark does not pin
  a directory handle (SQLite opens files by path), so do not widen any directory on the path while a
  host is running.
- **Backups.** A backup of the store holds the same data. Keep backup files `0600` (or in a `0700`
  directory), and restore them with mode `0600`; a restored file with a wider mode is refused.
- **Audit floor.** The floor is rewritten with mode `0600` on every write, even if a restore widened it.
  Keep the floor directory writable by the host user only: the floor is signed, but a user who can
  delete it can force the `floor-missing` refusal.
- **Windows.** There are no mode bits to check. Put the store, its backups, and the floor in a directory
  whose ACL (access control list) grants access only to the host's account and administrators.
- **PostgreSQL.** Protect the database with its own roles and network rules; the DSN is a secret (see
  "Hygiene And Supply Chain").

## Storage Migrations

SQLite runtime databases (current version 12) carry their schema version in `PRAGMA user_version`. Hosts migrate version `0` stores to the current baseline on open and refuse to open databases with a newer schema version than the runtime supports. Postgres stores (current version 10) keep their schema version in the `portmark_schema` table in the configured schema. Back up the runtime database before deploying runtime versions that include storage migrations, and validate representative task IDs with `verify-audit` after migration.

## Incident Response

For suspected key compromise:

1. Revoke the signing, attestation, or approval key in the corresponding trust file.
2. Rotate affected private keys.
3. Restart or reload hosts.
4. Search audit logs for the compromised key ID.
5. Re-run audit-chain verification for impacted task IDs.
6. Invalidate outstanding approvals from the compromised approver.

For suspected policy bypass:

1. Preserve the runtime database and logs.
2. Verify audit chains for affected task IDs.
3. Check `agent.accepted` events for policy version and hash.
4. Check approval events for request, approval, denial, expiry, and use.
5. Rotate approval keys if token signing is implicated.

## Hygiene And Supply Chain

Both log formats (plain text and `--log-json`) redact the complete rendered output
before emission: the message and its arguments, exception text, tracebacks, and stack
information. Redaction covers bearer credentials, token/secret-like environment
values, private keys, passwords, signatures, the user-info part of a URI
(`postgres://user:password@db` becomes `postgres://[REDACTED]@db`; also Redis,
HTTP, and other schemes), credential query parameters (`token`, `api_key`,
`password`, `secret`, `signature`, `sig`, ...), `api_key=` / `access_key=` style
values, and credential headers: the whole value of `Authorization` and
`Proxy-Authorization` (any scheme; `Bearer` keeps its scheme word), `Cookie` and
`Set-Cookie` (to the end of the line), and `X-API-Key` / `API-Key` / `X-Auth-Token`.
Uvicorn's own loggers are routed through the same redacting handler, both when
Uvicorn configures logging before the app loads and under `portmark serve`, where
`uvicorn.run(log_config=None)` keeps it from reinstalling its own handlers.
Redaction is pattern-based: do not rely on it for a secret in an unusual format
(for example a raw header tuple `(b"cookie", b"...")`). Still treat runtime
logs as sensitive operational data because task IDs, key IDs, policy versions,
host IDs, and audit event structure remain visible by design.

CI runs the regression suite across Python 3.11, 3.12, and 3.13, executes the A2A
parser fuzz target, runs Bandit, and audits installed dependencies with
`pip-audit --strict`. Runtime package dependencies should stay pinned in
`pyproject.toml` and refreshed in `uv.lock` together.

## Native Wasmtime Components

The default Wasm engine is the Node JSON-lowered runner. Native Wasmtime is
optional and requires `portmark[wasmtime]` plus a Component Model artifact:

```bash
portmark --wasm-component capsules/research-agent.component.wasm.b64 \
  --wasm-engine wasmtime \
  demo "goal"
```

Use `capsules/research-agent.wasm.b64` only with the default Node runner; it is
a core Wasm module and native Wasmtime rejects it with a component parser
diagnostic. Use `capsules/research-agent.component.wasm.b64` for the checked-in
native Component Model example.

The runtime instantiates the signed component bytes through an empty
`wasmtime.component.Linker`, runs them in a short-lived Python worker with a
deadline, and passes only projected context and checkpoint JSON.

The worker runs under an OS memory ceiling (512 MiB by default) and the store limits listed in
[WASM_COMPONENTS.md](WASM_COMPONENTS.md). At most two native Wasmtime workers run at once; a
decision that cannot get a worker slot before its deadline fails with "worker capacity exhausted".
On a platform that cannot enforce the OS ceiling (the provider checks this at start-up), the native
engine refuses to start. On POSIX that start-up check runs one short child Python process, once
per host process, the first time a native Wasmtime provider is built; seeing it at start-up is expected. To run it uncapped anyway, build the provider yourself with
`NativeWasmtimeComponentProvider(..., allow_uncapped_worker=True)` and pass it to
`make_host(providers={"wasm": ...})`; every run then logs an "uncapped" warning.

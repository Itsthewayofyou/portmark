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
must go through the production proxy boundary. The container entrypoint
(`python -m portmark.serve_asgi`) is loopback by default too, and binds publicly only
in public mode: `PORTMARK_PUBLIC_MODE=behind-tls-proxy`, `PORTMARK_A2A_TOKEN`,
`PORTMARK_A2A_TRUSTED_PROXIES`, and an `https://` `PORTMARK_A2A_PUBLIC_BASE_URL`, all
together (see DEPLOYMENT.md). Both server paths run uvicorn with `proxy_headers=False`,
so `PORTMARK_A2A_TRUSTED_PROXIES` is the only setting that decides whose
`X-Forwarded-For` is believed. If you start uvicorn yourself instead, pass
`--no-proxy-headers` (uvicorn's default trusts `X-Forwarded-For` from 127.0.0.1). The legacy `--allow-direct-a2a`
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

## MCP Servers

`--mcp-config mcp.json` (or `PORTMARK_MCP_CONFIG`) names the MCP servers this host may call and the tools each
may expose. Every tool is approved by its pin, and the file needs a host policy too: an MCP tool is a tool, so
it needs a grant like any other.

```bash
# 1. list what a server offers now, with the pin that would approve each tool
portmark --mcp-config mcp.json mcp pin --server files
# 2. paste the pins into mcp.json, then start the host
portmark --mcp-config mcp.json --policy-path policy.json --store-path runtime.sqlite serve --port 8080
```

- **Start-up fails closed.** Every server is probed in a bounded child process and every pin is compared. A
  changed or missing definition stops the host with the tool that changed. The same check runs again inside
  the worker on every call.
- `mcp pin` **never approves anything**: it prints `approved`, `CHANGED` or `not-configured` per tool, and the
  operator edits the file.
- A tool without `read_only: true` is side-effecting: it needs a `reconcile` target and an acknowledged
  `IsolationProfile` on the registry (TOOLS.md), because MCP cannot say whether a tool changes the world.
- A failed MCP call records `error_code` in its `tool.failed` audit event. Alert on `mcp_pin_drift` (a server
  changed a tool under you) and on `mcp_transport_error` (the effect state is unknown and needs reconciling).
- Only the variables named in `secret_env` reach the server process.

## Audit Export To A SIEM

`portmark audit export` copies the audit chains into a JSON Lines file. A log shipper (Vector, Fluent Bit,
an OpenTelemetry collector) sends that file to the SIEM. Portmark itself opens no network connection
for the export and holds no SIEM credential.

The SIEM is a downstream observer, not the source of truth. The store keeps the full, authoritative
record. The export is a **projection**: it copies only the fields a projection policy allows, and
replaces every other field with a keyed digest of the original value.

```bash
portmark --store-path runtime.sqlite --trust-registry-path trust.json audit export \
  --format ocsf \
  --out /var/log/portmark/audit.jsonl --cursor-file /var/lib/portmark/export-cursor.json \
  --projection-policy siem-projection.json --projection-keyring /etc/portmark/siem-keyring.json
```

Run it from a timer (for example every minute). Each run exports what is new since the cursor and exits.

- **Delivery is at-least-once.** A run appends records to `--out`, calls `fsync`, and only then saves the
  cursor. A crash between the two repeats those records on the next run; it never loses one. Every
  record has a `key` (`<task_id>:<sequence>:<hash>`), so the SIEM can remove duplicates.
- **The cursor needs a durable file.** `--out` is required when a cursor is saved. `--no-cursor` writes the
  whole history to standard output and saves nothing, because a pipe cannot confirm that a record arrived.
- **No clock is trusted.** Each run reads every task head in `task_id` order and compares its sequence with
  the cursor. A slow transaction or a skewed host clock cannot make the export skip a record.
- **The export checks before it copies.** For each record it recomputes the event hash and the link to the
  previous event. The last exported event of a task must hash to the stored head. On any mismatch it writes
  an export-control record (`portmark.audit.export.control.v1`, `kind: integrity_failure`), stops that task,
  and exits 1. It never repairs or skips history.
- **The export never changes audit data** (it only reads audit rows) and needs no signing key. A failed export
  does not affect the host. Point `--store-path` at the real store: like `verify-audit`, opening a path that
  holds no store creates an empty one.
- Only one export runs per cursor file: a lock beside the cursor (`<cursor>.lock`) makes a second run wait.
- `--out` must be a regular file; a symbolic link is refused. A new file is created with mode `600`. An existing
  file keeps its mode, so you can give a log shipper that runs as another user group read access.
- The export is not a rollback check. It finds a head that moved backwards or was rewritten only relative to
  its own cursor; a restored older database with a new cursor exports without complaint. Use the audit floor
  and the remote witness for rollback detection.

### Projection policy

The policy is a JSON file. Unknown keys are refused. With no policy file, the built-in defaults apply.

```json
{
  "schema": "portmark.siem.projection.v1",
  "events": {
    "approval.approved": {"include": ["approval_id", "tool"], "redact": ["approved_by"]}
  },
  "tool_arguments": {
    "default": "hash_only",
    "tools": {
      "catalog.search": {"include": ["query", "limit"]},
      "payments.reserve": {"include": ["amount", "currency"], "redact": ["account"]},
      "secrets.get": {"mode": "hash_only"}
    }
  }
}
```

- **Every event kind is default-deny, not only tool arguments.** Model output and user data also appear in
  `agent.completed`, `agent.failed`, `agent.awaiting_input`, `approval.requested`, and `content.rejected`.
  The built-in defaults copy only fields the host writes itself: tool names, host-written reasons and error
  codes, effect status, policy version and hash, approval ids. A field that is not included is left out of
  `details`, and its name and keyed digest go in `omitted`. An `events` entry in the policy **replaces**
  the built-in entry for that event kind; it is not merged.
- **Tool arguments** follow `tool_arguments`. `include` copies a value, `redact` writes `"[REDACTED]"`, and an
  argument that is not listed is left out. Every tool event carries `arguments_hmac` (a digest of the complete
  original arguments). A tool the policy names also carries `argument_keys`. A tool the policy does not name,
  including every future MCP tool, is `hash_only`: it exports only `argument_count` and `arguments_hmac`,
  because argument **names** are chosen by the model just as the values are. `default` accepts only
  `hash_only`, so raw arguments are never the default.
- The approval record's `arguments_hash` is a plain SHA-256 of the arguments. Low-entropy arguments can be
  guessed from it, so it is never copied by default.
- Each record carries `policy_digest` (the SHA-256 of the policy file), so a reader can see which rules
  produced it.

### Keyed digests and the keyring

A digest is `hmac-sha256:` + HMAC-SHA-256(key, canonical JSON of the **original, unredacted** value). A plain
SHA-256 of a value like `{"amount": 50}` can be found by hashing likely values; the key prevents that.

```json
{"active": "siem-2026-09", "keys": {"siem-2026-09": "<base64 of at least 32 random bytes>"}}
```

- Use a key made only for this. It is never the Ed25519 audit or envelope key. The host never reads it.
- Keep the keyring outside the repository and the store, read-only, mode `600`. On POSIX the export refuses a
  keyring that the group or others can read.
- Each record names its `hmac_key_id`. To rotate, add a new key and change `active`. Keep old keys for as long
  as you need to verify old records.
- **Known property:** the digest is deterministic. The same original value under the same key gives the same
  digest, so a SIEM reader can see that two calls had equal arguments without seeing them. This helps
  correlation. If it is too revealing, use separate keyrings per tenant or per time period.

### Verifying an export

`portmark audit verify-export` has two levels. They prove different things:

```bash
# Level 1: the SIEM copy alone
portmark --trust-registry-path trust.json audit verify-export --in audit.jsonl
# Level 2: against the authoritative store
portmark --store-path runtime.sqlite --trust-registry-path trust.json audit verify-export --in audit.jsonl \
  --against-store --projection-policy siem-projection.json --projection-keyring /etc/portmark/siem-keyring.json
```

- **Level 1** proves, per task, that the exported events link without a gap from sequence 0 and that each
  exported head matches them and carries a valid host signature. So no event was dropped, added, or
  reordered, and the chain is the host's. Events that no signed head covers make the result
  `unverifiable`, never `valid`: a run still in progress leaves them, but so would removed head records or a
  forged task. An empty file is `unverifiable` too. It does **not** prove the projected values. The projection is
  not inside the signed hash, so a person who can write to the SIEM could change `"amount": 78` to `7`
  and Level 1 would not see it.
- **Level 2** (`--against-store`) re-reads each exported event from the store, recomputes its hash and its projection, and
  requires a byte-identical match. This proves the values. It needs the store, the policy, and the keyring.
- Duplicate records from at-least-once delivery are accepted only when they are byte-identical.
- A record made under another projection policy, or with a key that is not in the keyring, is
  **unverifiable** at Level 2, not invalid: changing the policy or rotating a key is not tampering.
- Exit codes follow `verify-audit`: 0 valid, 1 invalid, 2 unverifiable (for example, no trust registry).
- `audit export` exits 0 when all is exported, 1 when it wrote an `integrity_failure` record, and 2 when a
  policy, keyring, cursor, or argument is refused (then nothing is written).

### Record format

`audit export` writes Portmark's own record shape by default. `--format ocsf` writes the same records as
**OCSF 1.9.0**, class `api_activity` (`class_uid` 6003, category "Application Activity"), read from
`https://schema.ocsf.io/` on 2026-09-23. `verify-export` reads either shape without being told which, so
turning the flag on changes nothing about how an export is checked.

What the mapping does, and what it deliberately does not:

- A Portmark audit event is not one of the CRUD activities this class enumerates, so `activity_id` is `99`
  ("Other") and `activity_name` carries the event kind (`tool.executed`, `approval.denied`, …), which is what
  the specification requires at 99. `type_uid` is `600399`, computed as `class_uid * 100 + activity_id`.
- `time` is a UTC epoch in **milliseconds**, as OCSF requires. Portmark stores seconds, so it is converted.
- `status_id` is `Success` or `Failure` for an outcome, and `Unknown` for an event that reports a STATE
  rather than a result (`agent.awaiting_input`, `agent.migrating`). An event kind Portmark does not know is
  `Unknown`, never `Success`.
- **A signed head is a `Success` only when its signature verified.** An export made without a trust registry
  records the head as `unchecked`, which maps to `Unknown`; a head that failed its check maps to `Failure` at
  `High` severity. Calling an unverified head a success would tell a SIEM that Portmark vouched for a chain
  nobody looked at, and would hide the one alarm an export exists to raise.
- **`verify-export` checks the OCSF fields too, not only the record inside them.** It re-projects the native
  record it finds under `unmapped` and requires the result to equal the record presented, so a file whose
  `status`, `time`, `severity` or `activity_name` was rewritten is refused even though the carried record is
  untouched. Two values cannot be derived from the record and are taken as presented: the producer's version
  string, and the exporter's clock, which reaches a record only when it carries no time of its own. Because
  the projection constants take part in that check, changing one (the OCSF version, a class or status label)
  makes files exported by an earlier Portmark read as altered -- treat it as a format change.
- `severity_id` is `Informational` normally, `Medium` for a refusal or a denied or expired approval (the gate
  working as designed, but worth seeing), and `High` for a failure, a kill or a rejected result.
- `src_endpoint` and `actor.application` name the Portmark host. An audit event has no network peer, and
  neither object needs one: both accept a name and a uid instead of an address.
- **The hash chain travels under `unmapped.portmark`**, which is where OCSF puts a mapper's source-specific
  data. It carries the whole native record, so nothing is lost.
- **`attestation_list` is deliberately left empty.** Its `chain_uid` / `prev_event` / `fingerprint` fields
  look like a perfect home for the chain, but OCSF defines that fingerprint as covering *the OCSF record's*
  canonical bytes, while Portmark's hash covers the *original* audit event before projection. Putting one
  where the other belongs would state something false, and a verifier following the specification would
  recompute, find a mismatch, and read an honest export as tampered with.
- The `ai_operation` profile is not applied. Its `ai_agent` object wants an agent identity that is not on
  every record — the projection policy decides what survives — and emitting the profile empty, or inventing
  an identity, would both be worse than leaving it out.

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

## Remote Witness (EV-013)

The reference witness (`portmark witness serve`, see DEPLOYMENT.md "Remote Witness") keeps a hash chain
of advances per host, and a host with `PORTMARK_REMOTE_WITNESS_URL` advances it on every save.

- **The witness is down.** Hosts refuse every save (and refuse to start) with `witness-unavailable`
  (owner decision F1). Nothing is committed and nothing is wedged: bring the witness back and the same
  saves go through. `verify-audit` reports `remote_status: witness-unavailable` (exit 2).
- **`verify-audit` reports `witness-unconfigured`** (exit 2). The database holds a witness receipt, but
  the command ran without the `PORTMARK_REMOTE_WITNESS_*` settings. Set them and run it again.
- **A recovery reports `rebaseline-unconfirmed`.** The witness gave no answer to the rebaseline, and it
  may have accepted it. Do not repeat `time-floor reset`. Run `floor-reset --reason ... --confirm
  --operator-id <id> --operator-key-file <file>`: it works whether the witness moved or not.
- **A host refuses to start with `rolled-back`.** Its database is older than the witness: it was restored,
  or it is a stale copy. If the restore was deliberate, run `floor-reset ... --operator-id
  --operator-key-file` (DEPLOYMENT.md "Remote Witness", Recovery). Work after the backup is lost.
- **`forked`.** Another copy of this host advanced the chain (a clone). Stop every copy but one; the
  copy the witness refused must not write again. Then rebaseline the one you keep.
- **`witness-behind`.** The witness has less than this database: it was wiped or restored, or the host
  points at the wrong witness. Never adopt it silently: check the witness and its backups first, then
  rebaseline with the operator key.

- **Health.** `GET /healthz` answers `ok`. For a real check, run `portmark witness conformance` with the
  `conformance:` host id (exit 0 = the witness enforces every rule).
- **Refusal codes** (signed answers): `rolled-back` (the host builds on an older receipt: restored or
  cloned), `forked` (on a discarded or unknown receipt: two copies of the host, or a chain from
  elsewhere), `sequence-mismatch`, `registry-rolled-back` / `registry-forked` / `registry-missing`,
  `stale-rebaseline`, `unauthenticated`, `wrong-witness`, `malformed`, `too-large`, `rate-limited`.
- **Log.** `witness_log` in the witness database is the record: every advance, discard, and rebaseline
  with the signed request and the signed answer. It is append-only (UPDATE and DELETE are refused). The
  `witness_hosts` and `witness_task_heads` tables are an index derived from it.
- **Backups.** Back the witness database up on its own schedule, never with a host's backup. Restoring
  the witness to an older copy makes hosts look ahead of it; treat that as an incident, not routine.
- **Enrolment changes** (new host, rotated key, removed operator): edit the enrolment file and restart
  the witness. A host id must never be reused by a second host.

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

Alert when `portmark_tool_threads_overdue` is above 0. It counts thread-path
tools that passed their deadline and are still running. The host already
recorded those calls as failed, but the tool code can still act. Find the tool,
fix its deadline or its upstream, and move it to `register_isolated()` so the
host can stop it at the deadline. If the count reaches `max_inflight_threaded`
(default 64), every thread-path tool call fails closed until threads finish.

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

The durable time floor (Section 12) is mirrored in the audit floor too, so a restored older database
does not bring back an older time floor. If the host then refuses to start with `clock-behind-floor`,
check the clock first. Lower the floor with `time-floor reset` only when the clock is known to be right.

## Retention And The Time Floor

- **Checkpoint encryption** (see `DEPLOYMENT.md`). To turn it on, or to rotate the key, stop the hosts
  and run `portmark store encrypt-checkpoints` as a dry run, then with `--apply`. A refusal changes
  nothing: it names the row that cannot be read. A task that fails with `checkpoint is not encrypted`
  or `checkpoint is encrypted but no checkpoint keyring is configured` means the host and the store
  disagree about the keyring; fix the setting, do not edit rows.
- **Pruning.** Run `portmark store prune --before <cutoff>` first as a dry run. Read the counts and the
  kept rows, then repeat with `--apply`. Each run is recorded in the maintenance log. Pick a cutoff that
  your incident-response process can live with: pruned nonces and delivered outbox rows are gone for
  good. Take a backup first if you need them as evidence.
- **Clock rolled back** (the host logs `wall clock moved back` and security decisions fail). Fix the
  clock and restart. Do not lower the time floor to make a wrong clock work.
- **Clock jumped forward by mistake** (a `CRITICAL` `jumped FORWARD` line and a rising
  `clock.forward_jumps`). Correct the clock at once. If the time floor already followed it, start-up
  refuses with `clock-behind-floor`. Then run
  `time-floor reset --to <the correct epoch> --reason "<what happened>" --confirm`, with the same
  `--audit-floor-path` and `--trust-registry-path` the host uses. With a remote witness, check
  `time-floor show`: if `remote_floor` is above the correct epoch, also add `--operator-id <id>
  --operator-key-file <operator.key>` (the witness is rebaselined; a refusal changes nothing).

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

SQLite runtime databases (current version 15) carry their schema version in `PRAGMA user_version`. Hosts migrate version `0` stores to the current baseline on open and refuse to open databases with a newer schema version than the runtime supports. Postgres stores (current version 13) keep their schema version in the `portmark_schema` table in the configured schema. Back up the runtime database before deploying runtime versions that include storage migrations, and validate representative task IDs with `verify-audit` after migration.

**Crash safety.** Each SQLite step is one transaction with its version bump, so a crash or kill during
an upgrade leaves the complete old version or the complete new one. Just start the host again: it
continues from the version that was committed. A database that an older runtime left half-migrated (for
example `duplicate column name: generation` at start) also continues, because every step checks what
already exists. This does not protect against disk corruption or power loss on storage that ignores
`fsync`; that is what the backup is for.

**Many hosts starting at once.** Hosts that cold-start together on one new SQLite store (for example a
scaled-out deployment) are safe: the one that loses the race to create a store directory accepts it after
the full permission check, and a host that loses the race to switch the new database to WAL mode retries
within the busy timeout. The upgrade itself is serialized by SQLite's write lock.

**Repair and restore.**
1. Stop every host that uses the store.
2. Keep the failed database and its `-wal`/`-shm` files together (copy all three, or none).
3. Try one start of the current runtime. If it still refuses, check the database with
   `sqlite3 <path> "PRAGMA integrity_check"`.
4. If the check fails, restore the last backup, with mode `0600` (see "File Permissions"). A host with
   an audit floor then refuses with `rolled-back`; run `floor-reset` deliberately, as described in
   "Audit Floor".
5. Run `verify-audit` on representative task IDs before you allow new work.

## Incident Response

For suspected key compromise:

1. Revoke the signing, attestation, or approval key in the corresponding trust file.
2. Rotate affected private keys.
3. Restart or reload hosts.
4. Search audit logs for the compromised key ID.
5. Re-run audit-chain verification for impacted task IDs.
6. Invalidate outstanding approvals from the compromised approver.

After a shutdown that logged `shutdown grace ... expired with a run unfinished` (Section 12):

1. Treat each named run like a crash. Its checkpoint is the last one logged
   (`checkpoint_generation`); nothing was written for it after the deadline.
2. For a run in phase `side_effecting_tool`, the external effect may or may not have landed.
   Reconcile each logged effect id with `AgentHost.reconcile_effect(effect_id, task_id)`. Do not
   resend the task: the effect ledger refuses to re-run an `unknown` effect, by design.
3. If this happens often, raise `PORTMARK_SHUTDOWN_GRACE_SECONDS` together with the orchestrator's
   termination grace (DEPLOYMENT.md, "Shutdown, Request Deadlines, And Database Timeouts").

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

CI runs the regression suite across Python 3.11, 3.12, 3.13, and 3.14 on Linux and
Windows, executes the A2A parser fuzz target, runs Bandit, and audits installed
dependencies with `pip-audit --strict`. The `container` job builds the shipped image
(Python 3.14) and runs the suite inside it. Python 3.14 is supported, not required:
`requires-python` is `>=3.11`.

**Locked, reproducible builds.**
- Every dependency pin lives in `pyproject.toml` (runtime, extras, and the `bootstrap`, `ci`, and
  `release` tool groups) and is resolved with hashes in `uv.lock`.
- `requirements/*.txt` are generated, hash-pinned exports of `uv.lock`. Docker, every CI job, and the
  release job install ONLY from them, with `pip install --require-hashes --no-deps`, then build Portmark
  itself with `--no-build-isolation` using the locked setuptools. Nothing is resolved at build time.
- After changing any pin (including a Dependabot PR): run `uv lock`, then
  `python scripts/lock_requirements.py`, and commit all three. CI's `lockfile` job fails until you do,
  and it also proves that a tampered hash is refused.
- The Docker base image and the CI Postgres service image are pinned by `@sha256:` digest. Dependabot
  proposes Dockerfile digest bumps; refresh the service image by hand (see the comment at its pin).
- The one deliberate exception is the weekly, non-blocking Wasmtime canary, which floats `wasmtime`
  itself to warn before the pin is raised. It builds and publishes nothing.

**Releases.** The release workflow refuses a tag whose commit is not on `main`. It builds from the
locked environment, publishes a CycloneDX SBOM (the `sbom` artifact), and records signed provenance twice:
PEP 740 attestations on PyPI, and GitHub build-provenance and SBOM attestations. To check a downloaded
distribution:

```bash
gh attestation verify portmark-X.Y.Z-py3-none-any.whl --repo Itsthewayofyou/portmark
```

For a stronger guarantee, also protect `v*` tags on GitHub (a tag ruleset that allows only maintainers
to create them), and keep the `pypi` environment's required reviewers on. Those are repository settings,
not files in this repository.

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

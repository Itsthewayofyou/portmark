# Deployment

Portmark's production-shaped path is the ASGI app served by uvicorn from the
container. The reference CLI server still refuses non-loopback binds and should
not be published directly.

## Build And Run

Build the image:

```bash
docker build -t portmark:local .
```

The image's command is `python -m portmark.serve_asgi`. It listens on **loopback only** by default
(`PORTMARK_BIND_HOST=127.0.0.1`), so a container started without further settings is reachable only from
inside itself, even if a port is published with `-p`.

The app is in the **production profile** by default (see [Production Profile](#production-profile)), so a
container started with no settings at all **refuses to start** and lists what is missing. For a local
trial, set `PORTMARK_PROFILE=development`.

### Public mode (a reverse proxy in another container or host)

To accept connections from a reverse proxy, the listener must bind a non-loopback address. The entrypoint
then refuses to start unless **all four** of these are set; it reports every missing one at once, and the
acknowledgement alone never lowers any other requirement:

| Setting | Why |
|---|---|
| `PORTMARK_PUBLIC_MODE=behind-tls-proxy` | You acknowledge that a trusted reverse proxy terminates TLS in front of this listener. Portmark itself speaks plain HTTP. |
| `PORTMARK_A2A_TOKEN` | A bearer token for transport authentication (no whitespace). |
| `PORTMARK_A2A_TRUSTED_PROXIES` | The proxy's CIDRs. Portmark reads `X-Forwarded-For` only from these peers; uvicorn's own proxy-header handling is off, so this setting is the only one that decides. Without it every client would be identified (and rate-limited) as the proxy. |
| `PORTMARK_A2A_PUBLIC_BASE_URL` | The `https://` URL clients use (no credentials, query, or fragment). |

Run it on a private network behind a reverse proxy:

```bash
docker run --rm --name portmark \
  --network portmark-private \
  --env-file ./portmark.env \
  -e PORTMARK_BIND_HOST=0.0.0.0 \
  -e PORTMARK_PUBLIC_MODE=behind-tls-proxy \
  -e PORTMARK_A2A_TRUSTED_PROXIES=172.18.0.0/16 \
  -e PORTMARK_A2A_PUBLIC_BASE_URL=https://agents.example.com \
  -e PORTMARK_POLICY_PATH=/config/host-policy.json \
  -e PORTMARK_TRUST_REGISTRY_PATH=/config/trust.json \
  -e PORTMARK_STORE_BACKEND=sqlite \
  -e PORTMARK_STORE_PATH=/data/runtime.sqlite \
  -e PORTMARK_AUDIT_FLOOR_PATH=/floor/audit-floor.json \
  -v "$PWD/examples/host-policy.json:/config/host-policy.json:ro" \
  -v "$PWD/trust.json:/config/trust.json:ro" \
  -v portmark-data:/data \
  -v portmark-floor:/floor \
  portmark:local
```

The audit floor lives on its own volume, outside the store directory, so a restore of the database does
not carry the floor with it.

Put `PORTMARK_A2A_TOKEN` in `portmark.env` (mode `0600`), not on the command line. Use the proxy
network's real CIDR for `PORTMARK_A2A_TRUSTED_PROXIES`. Do not publish the container's port to the
internet with `-p`: only the proxy should reach it.

If you load custom tools, set `PORTMARK_TOOLS=module:function` and provide a
matching `PORTMARK_POLICY_PATH`. Tool modules must be present in the image or on
the Python import path.

## Production Profile

`PORTMARK_PROFILE` selects the profile: `production` (the default, also when unset or blank) or
`development`. Any other value refuses to start, so a typo cannot pick a profile.

The production checks run **where the app is built** (`portmark.asgi`), not only in the `serve_asgi`
launcher. So `uvicorn portmark.asgi:app`, gunicorn, or a server that embeds the app gets the same checks.
The app cannot see the address it will be bound to, so production applies them on loopback too. Every
refusal lists all missing items at once.

| Production requires | When | Why |
|---|---|---|
| `PORTMARK_PUBLIC_MODE=behind-tls-proxy`, `PORTMARK_A2A_TOKEN`, `PORTMARK_A2A_TRUSTED_PROXIES`, an `https://` `PORTMARK_A2A_PUBLIC_BASE_URL` | always | The same four public-mode requirements as above. |
| `PORTMARK_AUDIT_FLOOR_PATH` | a durable store (`PORTMARK_STORE_PATH`) | Without the floor, a rollback of the database or trust registry to an older copy is not detected. |
| `PORTMARK_ATTESTATION_VERIFIER_COMMAND`, `PORTMARK_ATTESTATION_ALLOWED_MEASUREMENTS` and `PORTMARK_MIGRATION_PREFLIGHT_COMMAND` | the host policy allows migration | See [Migration Attestation Freshness](#migration-attestation-freshness). The destination is verified before any state is released, and the migration challenge is turned on automatically. |

The migration rule is checked on the first policy load **and on every reload** (`PORTMARK_RELOAD_POLICY=1`).
A reloaded policy that turns migration on without the attestation settings is refused like any other
invalid policy file.

`PORTMARK_PROFILE=development` keeps the older behavior: warnings instead of refusals. Use it only for
local work.

`portmark_audit_witness_active` on `/metrics` is `1` when the audit floor is active and `0` when it is
not. `/readyz` does not report it, because `/readyz` needs no token.

What the production profile does **not** do: it cannot contain a hostile tool. The isolated tool worker
is a resource-bounded, hard-deadline worker, not a sandbox. It runs as the same user, with the same
filesystem and network access. If a tool may be hostile, the deployment must contain it: a dedicated
unprivileged user, a read-only root filesystem, one narrow writable mount, PID and cgroup limits, dropped
capabilities, no host credential mounts, and egress denied by default (see
[Tool Isolation Requirement](#tool-isolation-requirement) and `deploy/README.md`).

## Tool Isolation Requirement

Portmark's isolated tool executor is a **resource-bounded, hard-deadline worker — not a
hostile-code sandbox** (see THREAT_MODEL.md, "Tool Execution Isolation Contract"). It enforces
deadlines and defense-in-depth kernel resource caps, but a tool runs as the **same OS user** with
normal filesystem and network access. **Containing an untrusted or hostile tool is the
deployment's job.** Run the runtime under an OS/container isolation profile:

- a **dedicated non-root user**, distinct from anything that owns host secrets;
- a **read-only root filesystem** with a single **private writable** working directory per run;
- application/config/key paths mounted **read-only or not at all**;
- **dropped Linux capabilities** and **`no-new-privileges`**;
- **PID, memory, and CPU limits** (cgroups) and a **restricted `/proc`**;
- **default-deny egress** (network namespace / firewall / egress proxy), allowlisting only the
  destinations a tool legitimately needs.

Portmark applies POSIX `setrlimit` caps (address space, CPU time, file size, open files) inside
each isolated worker as **defense in depth** — configurable via `ToolRegistry(resource_limits=...)`
(`RLIMIT_NPROC` is off by default because it is per-uid; enable it only under a dedicated uid).
These caps do not replace the container profile above and do not constrain the network.

`resource_limits` overrides are **validated at construction and merged over the defaults** (an
unknown key or non-positive value fails startup, and setting one key keeps the other default caps);
pass `disable_resource_limits=True` to turn the exhaustion caps off explicitly. The caps are applied
**before the tool module is imported**, so a hostile tool's module-scope code runs already capped —
which also means `address_space` (virtual memory) now bounds module *import*: raise it for a tool
whose module reserves large mmap-backed address space at import, or the worker will fail to load it.
Applying the caps is **fail-closed**: if a configured cap cannot be put in force (an unsupported
limit on the platform, or a rejected `setrlimit`), the worker refuses the tool with
`worker could not apply resource limits: <names>` instead of running it under weaker caps than you
set. On Linux all of these limits apply.

A tool registered `side_effecting=True` additionally requires Portmark's idempotency/reconciliation
contract and an acknowledged isolation profile. **The executable, tested container profile is in
`deploy/`** — the `Dockerfile`, `deploy/docker-compose.hardened.yml`, the exact `docker run` flag set
in `deploy/README.md`, and `deploy/verify_profile.py`, which runs inside the container and confirms each
property (read-only rootfs, private writable dir, non-root, `no-new-privileges`, dropped capabilities,
PID limit, default-deny egress) by attempting the operation it governs. A CI test runs that probe with
the full flags (every property must hold) and again with each flag removed (that property must flip), so
the profile is proven, not merely written down. This `deploy/` profile is the concrete meaning of the
`IsolationMechanism.EXTERNAL_CONTAINER` you acknowledge via `ToolRegistry(isolation_profile=...)`.

### Capability-based safe paths for isolated tools

Grant an isolated tool a filesystem workspace with `ToolRegistry(filesystem_root="/work")`. The runtime
pre-opens that directory and hands the worker its open descriptor; the tool reaches it **only** through
`portmark.safe_paths.SafeRoot.from_runtime()` and opens files with `root.open_beneath("rel/path", "w")`.
The tool never names the root, and `openat2(RESOLVE_BENEATH)` refuses any `..`, absolute, or symlink
escape race-free. With no `filesystem_root` configured, `from_runtime()` refuses — the default is no
ambient filesystem authority. This needs Linux ≥ 5.6 and a **seccomp policy that permits `openat2`**;
Docker's and Kubernetes' `RuntimeDefault` seccomp profiles allow it, and the `deploy/` profile keeps it
available. If you install a custom seccomp profile it must allow `openat2`, or `from_runtime()` fails
closed (it never degrades to a race-vulnerable path check). See `deploy/README.md` and TOOLS.md.

## Reverse Proxy Requirement

Do not publish the container port directly to the public internet. Put nginx,
Envoy, Caddy, a cloud load balancer, or an ingress controller in front of it.
The proxy must provide:

- TLS termination
- request body cap of 1 MiB or lower
- connection and request-rate limits
- forwarding of the `Authorization` header
- routing only for `/.well-known/agent-card.json`, `/message:send`, `/metrics`,
  `/healthz`, and `/readyz`

### Multiple Replicas

**Requirement: with more than one Portmark replica, the rate limit must be enforced at a shared edge.**
Portmark's own limits (`PORTMARK_A2A_RATE_LIMIT_PER_IP`, default 120 requests per 60 s, and the Agent Card
and concurrency limits) are kept in each process's memory. They are not shared. With N replicas behind a
load balancer, one client can get up to N times the limit, and a restart resets the count. They stay on as
a second layer, but they are not the control for a scaled deployment.

- Put every replica behind one edge that limits per client: the reference nginx file
  (`deploy/nginx/portmark.conf`) limits every route it forwards (`limit_req`, plus `limit_conn` on
  `/message:send`).
- An nginx `limit_req` zone is shared only inside one nginx instance. If the edge itself runs as several
  instances, use a limiter with shared state (for example a cloud load balancer or API-gateway rate
  limit, or Envoy's global rate-limit service), or divide each instance's rate by the number of
  instances.
- Key the limit on the real client address, and set `PORTMARK_A2A_TRUSTED_PROXIES` to the edge's
  addresses so each replica also sees the real client.
- Alert on `portmark_refusals_total{reason="rate_limited"}` summed across all replicas.

The included reference CLI server keeps its loopback-only bind rule:

```bash
portmark serve --bind 127.0.0.1 --port 8080
```

Do not attempt to expose it directly with `0.0.0.0`; Portmark rejects that mode.

## Health And Readiness

`GET /healthz` is a cheap static liveness response:

```json
{"status": "ok"}
```

`GET /readyz` re-validates the configured policy and trust registry and runs a
bounded store liveness probe (a cheap query plus a schema-version check with a
short database timeout) off the event loop. It does NOT construct the store or
run schema migrations — those happen once at startup. It returns:

```json
{"status": "ready"}
```

or, on failure, a generic:

```json
{"status": "not_ready"}
```

The response intentionally omits file paths, exception text, SQL details, and
secret material.

While the server is shutting down (below), `/readyz` returns `not_ready`, so a
load balancer stops sending it work. `/healthz` stays `ok`.

## Shutdown, Request Deadlines, And Database Timeouts

**Bounded shutdown.** On `SIGTERM` (or `SIGINT`), Portmark does this:

1. It stops admitting work at once. A new `POST /message:send` gets `503 server shutting down`, and
   `/readyz` reports `not_ready`.
2. It waits for the runs already admitted, for at most `PORTMARK_SHUTDOWN_GRACE_SECONDS` (default 25).
   uvicorn's own graceful-shutdown wait uses the same value and the same start time, so the total is about
   one grace, not two.
3. If every run finished, shutdown completes normally.
4. If any run is still active at the deadline, Portmark logs one `CRITICAL` line per run and reports the
   shutdown as failed (ASGI `lifespan.shutdown.failed`). Each line names only the task id, the last durable
   checkpoint generation, the execution phase, and the effect ids. It never logs arguments, state,
   results, or secrets. The run is then **abandoned, as in a crash**: it launches no further tool and
   writes no further checkpoint, and the process may exit without waiting for it.

**What to do after an abandoned run.** Treat it like a crash. A run whose phase was `side_effecting_tool`
may have landed its external effect, so its status is unknown. Resolve it through the effect ledger
(`AgentHost.reconcile_effect(effect_id, task_id)`, using the logged effect id), never by resending the
task. A run in any other phase has launched no effect that the
ledger does not already record.

**Termination is the orchestrator's job.** Portmark can report a failed shutdown. It cannot force the
process to exit. Set the orchestrator's termination grace slightly **above** Portmark's grace, so the
report is written before a hard kill:

| Platform | Setting | With the default 25 s grace |
|---|---|---|
| Kubernetes | `terminationGracePeriodSeconds` | 30 (the default) or more |
| Docker | `docker stop --time` / `stop_grace_period` | 30 or more (Docker's default of 10 is too short) |
| systemd | `TimeoutStopSec` | 30 or more |

**Request-body deadline.** A request body must arrive completely within
`PORTMARK_A2A_BODY_READ_TIMEOUT_SECONDS` (default 30). This is one absolute deadline for the whole body,
including the time between chunks, so a client that sends a byte now and then cannot hold an admission
slot. When it expires, the client gets `408` (the connection is closed) and the slot is released. Keep
the reverse proxy's own body timeout (nginx `client_body_timeout`) at or below this value.

**PostgreSQL timeouts.** Every connection Portmark opens to PostgreSQL gets these bounds, whatever the DSN
says. A DSN may set a smaller `connect_timeout`. It cannot disable or raise any bound, because Portmark
sets them after connecting.

| Bound | Default | Variable |
|---|---|---|
| Connect (includes an unreachable or silent host) | 5 s | `PORTMARK_POSTGRES_CONNECT_TIMEOUT_SECONDS` |
| One statement | 30 000 ms | `PORTMARK_POSTGRES_STATEMENT_TIMEOUT_MS` |
| Waiting for a row, table, or advisory lock | 10 000 ms | `PORTMARK_POSTGRES_LOCK_TIMEOUT_MS` |
| Idle inside an open transaction | 60 000 ms | `PORTMARK_POSTGRES_IDLE_IN_TRANSACTION_TIMEOUT_MS` |

Each must be a positive integer (maximum 300 s for connect, 3 600 000 ms for the others). Zero is
refused, because it would disable the bound. Schema setup at startup uses longer, still finite bounds
(10 minutes per statement, 5 minutes to wait for another process's migration). A timeout fails the
operation and rolls its transaction back, as any other database error does.

**When the network goes silent after a query was sent.** The bounds above are enforced by the server. If
the network between Portmark and PostgreSQL stops delivering packets after a query was sent, the server
may cancel the statement, but its reply never arrives. For that case every connection also enables TCP
failure detection, again whatever the DSN says:

- TCP keepalives: a probe after 10 s of silence, then every 5 s; 3 missed probes end the connection
  (about 25 s).
- `tcp_user_timeout` of 30 s: a send that stays unacknowledged for 30 s ends the connection.

A live server answers keepalive probes at the TCP level, so a long but healthy statement is not affected.
These are operating-system mechanisms, not an exact client-side deadline: on a dead network an operation
fails after roughly the larger of its database bound and about 30 s. `tcp_user_timeout` has no effect
where the operating system lacks `TCP_USER_TIMEOUT` (for example Windows); keepalives still apply there.

## Clock And The Durable Time Floor

Portmark decides permit, approval, key, receipt, and attestation expiry with the host clock. Treat
correct time as part of the trusted computing base: run NTP (or your platform's time sync) on every host
and on the PostgreSQL server.

- **Tolerance.** `PORTMARK_CLOCK_TOLERANCE_SECONDS` (default 300, from 1 to 3600) is the largest clock
  error Portmark accepts. Expiry decisions can be wrong by at most this much. It is in force from the
  first start-up check. A rollback larger than it since the process started refuses start-up.
- **Issuing permits.** `portmark envelope` and the demo set permit expiry with the same clock. While the
  clock has failed closed, they issue nothing.
- **While running.** The wall clock is compared with a monotonic clock that never jumps.
  - If the wall clock moves **back** by more than the tolerance, every security decision fails closed
    until the clock is fixed and the host restarts.
  - If it moves **forward** by more than the tolerance, Portmark logs one `CRITICAL` line and counts
    `clock.forward_jumps` in `/metrics`. Correct a wrong forward jump at once (see below).
- **Across restarts.** A durable time floor records how far time has progressed.
  - It advances with checkpoint saves and approval redemptions, at most once a minute.
  - It lives in the database. When an audit floor is configured (`PORTMARK_AUDIT_FLOOR_PATH`), it is also
    mirrored into that signed file, outside the database.
  - On PostgreSQL, the floor uses the database clock.
- **Start-up refusals.** The host refuses to start (the container entrypoint exits with code 2) when:
  - the host clock plus the tolerance is still behind the floor;
  - on PostgreSQL, the database clock is behind its own floor;
  - on PostgreSQL, the host and database clocks differ by more than the tolerance.
- **Without an audit floor,** restoring an older database snapshot also restores its older time floor. So
  a restored database, with a clock set back to match it, is **not** detected. Configure the audit floor
  to close that gap.
- **After a wrong forward jump.** The floor follows the clock and is never lowered by Portmark. Once the
  clock is corrected, start-up refuses until an operator runs:
  ```
  portmark --store-path <db> [--audit-floor-path <floor> --trust-registry-path <registry>] \
    time-floor reset --to <epoch-seconds> --reason "<why>" --confirm
  ```
  The reset is recorded in the maintenance log and in the audit floor. `portmark ... time-floor show`
  prints both floors and both clocks.

## Retention And Capacity

Portmark never deletes on its own. `portmark store prune` removes only rows that are provably no longer
needed, and only when you ask:

- **Expired nonces.** A consumed nonce blocks a replay until its authorization expires. The expiry is
  stored with the nonce when it is consumed. A nonce is prunable once that expiry is older than your
  cutoff **and** older than now minus the clock tolerance. Nonces written before this version have no
  stored expiry and are always kept.
- **Delivered migrations.** An outbox row is prunable once it is delivered, carries the verified
  destination receipt, and was delivered before your cutoff. Pending and dead rows are always kept, and
  so are delivered rows from before this version (no delivery time).
- **Everything else is evidence and is never pruned:** audit events and heads, checkpoints, tool
  effects, cancellations, receipts, and the maintenance log itself.

```
portmark --store-path <db> store prune --before 2026-06-01T00:00:00Z            # dry run: counts only
portmark --store-path <db> store prune --before 2026-06-01T00:00:00Z --apply    # delete
```

A prune reports, for each class, how many rows are eligible and deleted, and the oldest and newest
timestamp. It also counts the rows it kept, by reason. It deletes in batches of at most 1000 rows
(`--batch-size`), one transaction each. It writes a maintenance-log record per batch plus a summary.
It refuses a cutoff in the future, and it refuses to run while the clock is behind the time floor. It
never runs `VACUUM`: run it (SQLite) or let autovacuum work (PostgreSQL) at a time you choose.

**Watching growth.** `portmark --store-path <db> store stats` prints row counts per table, the oldest
pending migration, the database size, free disk space (SQLite only; watch the PostgreSQL server's disk
yourself), and the time floor. The same values are gauges on `/metrics` (`portmark_store_rows{table=...}`,
`portmark_store_database_bytes`, `portmark_store_free_bytes`,
`portmark_store_oldest_pending_migration_age_seconds`, `portmark_store_time_floor`). They refresh at most
once a minute. Alert on low free space and on a growing oldest-pending age.

**Administrative listings are paged.** `list_pending_migrations` and `list_dead_migrations` return at most
`limit` rows (default 500, maximum 1000) in `task_id` order. Pass the last `task_id` as `after` for the
next page. `claim_migrations` claims at most 100 rows per call.

## Checkpoint Encryption

A checkpoint row holds the task state as JSON: the goal, tool results and model outputs. By default it is
plaintext, and only the storage controls protect it. **Checkpoint encryption is optional** (EV-006). Disk
or volume encryption of the database is still a valid control on its own. Checkpoint encryption adds a
second layer: a copy of the database file or a database dump shows no task state without the key.

With a keyring, the store seals each checkpoint with AES-256-GCM before it writes the row, and opens it
when it reads the row. The sealed value also authenticates the task id, the row generation, the key id,
and the `closed` and owner columns that the store checks before a write. The `status` column is compared
with the sealed state on every read. So each of these is **refused**:

- a changed byte, or a wrong key;
- a sealed value moved to another task or generation;
- a closed task reopened by editing `closed`, or an owner rewritten by editing the owner columns;
- a `status` column that does not match the sealed state.

The run stops with an error (`CheckpointCryptoError`) before it writes anything. Nothing is guessed.
A completed or failed task counts as closed whatever its `closed` column says, so the schema step that
closes such rows leaves them valid, and editing the column cannot reopen them.

Set the keyring with **one** of these (not both):

- `PORTMARK_CHECKPOINT_KEYS`: `key-id:base64-key`, for example `ck-2026-09:<32 random bytes, base64>`.
- `PORTMARK_CHECKPOINT_KEYS_FILE`: a file with the same text. On POSIX it must not be readable by group or
  others (`chmod 600`). Mount it from your orchestrator's secret store.

Make a key with `python -c "import portmark.checkpoint_crypto as c; print(c.generate_key())"`. Keep a copy
in your secret store: **a lost key makes every sealed checkpoint unreadable.** The CLI, the ASGI app and
`make_host` all read the same settings.

**Reads are strict.** With a keyring, a plaintext row is refused. Without a keyring, a sealed row is
refused. There is no setting that reads both. To turn encryption on for a store that already has
checkpoints, stop every host that uses the store, then run the one-time migration with the keyring set:

```bash
PORTMARK_CHECKPOINT_KEYS=... portmark --store-path <db> store encrypt-checkpoints            # dry run: counts only
PORTMARK_CHECKPOINT_KEYS=... portmark --store-path <db> store encrypt-checkpoints --apply    # seal every row
```

It works in **one** transaction. It seals every plaintext row, re-seals a row sealed with an older key,
and opens every other row to prove it. If any row cannot be read, it changes nothing and exits 1. Each
applied run is recorded in the maintenance log as `checkpoint-encrypt`. Then start the hosts with the
same keyring.

**Key rotation.** Put the new key first and keep the old key after it
(`PORTMARK_CHECKPOINT_KEYS=new:...,old:...`). New writes use the first key, and reads accept both. Run
`store encrypt-checkpoints --apply` to re-seal every row with the new key, and then remove the old key.
Each write uses a random 96-bit nonce, so rotate a key well before 2^32 checkpoint writes.

`portmark_checkpoint_encryption_active` on the authenticated `/metrics` is `1` when the keyring is set and
`0` when it is not. `checkpoint_encryption_active` never blocks startup. Alert on `0` if your policy
requires this control.

**Residual risk:** these points are not covered by checkpoint encryption.

- The `status`, `generation`, `closed` and owner columns stay **readable** (the store queries them).
  They are authenticated, not hidden. The audit log, the migration outbox and receipts are not sealed
  by this key.
- A restore of a whole older row (its old sealed value **and** its old generation) still authenticates.
  That is a rollback, which the audit floor and the remote witness (EV-013, "Remote Witness" below) address.
- A process that holds the key (the host) can read every checkpoint. The key must not be stored with the
  database or its backups.
- `verify-audit` stays an integrity check and does not need the key.

## Remote Witness (EV-013, server side)

The audit floor lives on the host's own storage. A restore of the database **and** the floor together,
or two clones of the pair, stays internally consistent and passes it. A **remote witness** on another
machine closes that gap: it keeps, per host, a hash chain of every advance the host made, and each
advance names the witness receipt of the one before it. A restored host names an old receipt and is
refused (`rolled-back`); two clones that share a receipt are refused (`forked`) at the latest on the
second one's next commit.

**Status.** This release ships the witness protocol, a reference server, and a conformance kit. The
host does not call the witness yet: that is the second EV-013 change (the local floor stays the second
layer). Deploy and check the server now; the host settings follow with that change.

**Where to run it.** On a machine **outside the host's failure domain**: a different machine and a
different backup set, so no restore of the host can also restore the witness. One small, always-on
process. It needs no vendor and no GPU. Storage is about 300 bytes per commit (one million commits is
about 300 MB).

**Keys.** The witness signs every answer with its own Ed25519 key, which hosts pin. Each host signs its
requests with a key the witness has enrolled. A rebaseline (the remote side of `floor-reset`) needs an
**operator** key that the host does not hold, so a compromised host cannot erase its own history.

```bash
portmark witness keygen --out /etc/portmark-witness/witness.key     # prints key_id + public_key_b64
portmark witness keygen --out ./conformance.key                      # a key for the conformance host id
```

**Enrolment** (`portmark.witness.enrolment.v1`; restart the witness after a change). One host id and
key per deployment: two hosts must never share an id. Each id appears in one role only.

```json
{
  "format": "portmark.witness.enrolment.v1",
  "hosts": {"host:prod-1": {"public_key_b64": "..."}, "conformance:ci": {"public_key_b64": "..."}},
  "operators": {"operator:alice": {"public_key_b64": "..."}},
  "auditors": {"auditor:siem": {"public_key_b64": "..."}}
}
```

**Run.**

```bash
portmark witness serve --db /var/lib/portmark-witness/witness.sqlite \
  --key-file /etc/portmark-witness/witness.key --enrolment /etc/portmark-witness/enrolment.json \
  --bind 0.0.0.0 --port 8787 --public-mode behind-tls-proxy
```

- The bind is loopback by default. A non-loopback bind needs `--public-mode behind-tls-proxy`: a reverse
  proxy must terminate TLS in front of it (requests name tasks). Clients accept `https://`, or plain
  `http://` only to a loopback address.
- Every endpoint except `GET /healthz` needs an Ed25519-signed request from an enrolled key. There is
  no bearer token: the per-request signatures authenticate more than a shared token would.
- **Deadlines are absolute.** The server reads a whole request body within one 10 s deadline (not per
  chunk), and it answers 503 above 256 open connections. The client's timeout is one deadline for the
  whole call: connect, TLS, headers and body. A witness that answers slowly cannot hold the caller past it.
  uvicorn has no timeout for slow request *headers*: set one on the TLS proxy (for nginx,
  `client_header_timeout 10s;`).
- The database file is created mode 600; a looser file is refused. Key files must be mode 600.
- The same container image runs it: override the command with `portmark witness serve ...` and mount a
  volume for `--db`.

**Check it before use.** Enrol a dedicated `conformance:` host id and run the kit against the deployed
URL. It drives that id through advance, confirm, retry, a restored host, a lost commit, a clone's
discarded receipt, split and older task heads, an older registry, and an unenrolled key, then reads the
state back. Every answer must be signed by the pinned key and bound to its request. It refuses any id
that does not start with `conformance:`, because it moves that host's chain.

```bash
portmark witness conformance --url https://witness.internal:8443 --host-id conformance:ci \
  --host-key-file ./conformance.key --witness-public-key=<public_key_b64 of witness.key>
# Use the `=` form: a base64url key can start with "-", which a separate argument would read as an option.
# exit 0: pass; exit 1: fail (the JSON names the failing case); exit 2: usage error
```

**Residual risk:** these points are not covered by the remote witness.

- A compromised host can still send valid advances. The witness orders history; it does not judge it.
- A restore to exactly the last **confirmed** state loses at most **one** unconfirmed commit without
  detection (the newest advance stays pending until the next one builds on it).
- When the host integration lands, the witness becomes a dependency of every write: a host refuses to
  save while its witness is unreachable (owner decision F1).
- The reference server is append-only at the application level (SQLite triggers refuse UPDATE and
  DELETE on its log), not WORM storage. For WORM, put the database file or its backups on object-lock
  storage.
- The wrong choice above about 50 commits per second per host, or above about 50 ms round trip (the host
  holds its database write lock during the call). Then batch advances or use a real transparency log.

## Metrics

`GET /metrics` requires the same bearer token as `/message:send`. Without an
`Accept` header it returns the existing JSON snapshot. Prometheus-compatible
scrapers should send:

```http
Accept: text/plain
Authorization: Bearer <token>
```

The text response includes runtime counters, bounded refusal counters, and
latency histograms for total runs, provider decisions, tool invocation, and A2A
requests. Refusal labels are fixed reason codes so user input, tool arguments,
task IDs, and other request-controlled values cannot create high-cardinality or
secret-bearing labels.

## Secrets And Environment

Set secrets through your orchestrator's secret store, not the image or
Dockerfile. Common configuration:

- `PORTMARK_A2A_TOKEN`: bearer token for `/message:send` and `/metrics`
- `PORTMARK_A2A_PUBLIC_BASE_URL`: absolute `https://` base URL advertised in the Agent Card behind a reverse proxy (required for a correct public card)
- `PORTMARK_A2A_TRUSTED_PROXIES`: comma/space-separated CIDRs of proxy peers whose `X-Forwarded-For` is trusted for per-client rate limiting (e.g. `127.0.0.1/32`); unset ignores `X-Forwarded-For`
- `PORTMARK_ED25519_PRIVATE_KEY_B64`: host signing key
- `PORTMARK_SIGNING_KEY_ID`: signing key identifier
- `PORTMARK_SIGNING_ISSUER`: host signing issuer
- `PORTMARK_POLICY_PATH`: mounted host policy JSON
- `PORTMARK_TRUST_REGISTRY_PATH`: mounted trust registry JSON
- `PORTMARK_STORE_BACKEND`: `sqlite` by default, or `postgres` when the image includes `portmark[postgres]`
- `PORTMARK_STORE_PATH`: SQLite runtime store path or Postgres DSN
- `PORTMARK_CHECKPOINT_KEYS` or `PORTMARK_CHECKPOINT_KEYS_FILE`: optional checkpoint keyring (see "Checkpoint Encryption")
- `PORTMARK_TOOLS`: optional custom tool registry loader, `module:function`
- `PORTMARK_CLOCK_TOLERANCE_SECONDS`: see "Clock And The Durable Time Floor"
- `PORTMARK_SHUTDOWN_GRACE_SECONDS`, `PORTMARK_A2A_BODY_READ_TIMEOUT_SECONDS`, and the
  `PORTMARK_POSTGRES_*_TIMEOUT*` bounds: see "Shutdown, Request Deadlines, And Database Timeouts"

Do not bake tokens, private keys, policy files containing local secrets, or
runtime stores into the container image.

## Migration Attestation Freshness

In the **production profile**, a host whose policy allows migration must have a platform verifier
(`PORTMARK_ATTESTATION_VERIFIER_COMMAND`), approved measurements
(`PORTMARK_ATTESTATION_ALLOWED_MEASUREMENTS`, a comma-separated list of exact strings), and a migration
preflight command (`PORTMARK_MIGRATION_PREFLIGHT_COMMAND`), and the challenge-passing protocol below is
turned on for it. Portmark's own Ed25519 attestation proves only that a key was held, not hardware
state. The verifier command must check the vendor chain, the quote signature, debug status, the
TCB/security version, the workload measurement, the report-data binding to the host identity and
challenge, and revocation and freshness data.

**Requirement: run the verifier conformance kit before production use.** Portmark checks the claimed
evidence fields itself, but only the verifier can prove that the quote binds the same values. Capture one
real, fresh verifier request on the target platform (a quote the verifier has never seen), then run:

```bash
PORTMARK_ATTESTATION_VERIFIER_COMMAND='...' portmark attest-conformance --evidence known-good-request.json
```

It must print `"status": "pass"` and exit 0. Run it again after each change to the verifier, its trust
roots or the platform. See [ATTESTATION.md](ATTESTATION.md#verifier-conformance-kit) for the cases.

**The destination is verified before any state is released.** The migration envelope is signed, not
encrypted, so it must not reach a destination that has not proved itself. At the migrate decision the
source mints a fresh challenge and runs the preflight command. The command obtains the destination's
attestation over that challenge and prints it. The source verifies it with the same checks it uses at
settlement (platform verifier, approved measurement, subject = the destination, audience = this host,
nonce = the challenge, validity window). Only then does it build, seal and release the envelope. The same
challenge becomes the delegated permit nonce, so the destination attests over it again at admission and
the source checks that proof in the receipt at settlement. A refusal releases nothing, and the task is
closed as refused (`decision.refused`); submit it again once the destination is fixed.

Preflight command contract: it is run without a shell and with an empty environment, with a 10 s timeout
and a 64 KiB output limit. It receives `{"destination", "relying_party", "challenge"}` as JSON on stdin
and must print the destination's `AttestationEvidence` object (the fields in `ATTESTATION.md`) as JSON
on stdout, and exit 0. How it reaches the destination (for example an authenticated call to the
destination's attestation agent) is deployment-supplied, like the verifier command. Before production
use, check the whole chain with `portmark preflight-conformance --destination <host>` (see
[ATTESTATION.md](ATTESTATION.md#preflight-conformance-kit)).

`PORTMARK_REQUIRE_ATTESTATION=1` is not needed with the preflight. It also sets
`required_for_execution`, which a destination that receives challenge migrations must not set (see the
notes below), and `required_for_migration`, which asks the model provider to supply destination evidence
in the migrate decision in addition to the preflight.

In the development profile, and for hosts that do not migrate, freshness is **opt-in**. To require that a
destination proves itself with fresh, non-replayable evidence before a source considers a migration
delivered, enable the **challenge-passing protocol**:

- On the **source** host: `AttestationPolicy(require_migration_challenge=True)`, and the source must
  trust the destination's attestation authority (add it to the policy's `authorities`). The source mints
  a fresh challenge per migration and verifies the destination's evidence in the delivery receipt before
  settling.
- On the **destination** host: pass a `migration_attester` (implements `MigrationAttesterProtocol`) that
  produces the destination's own attestation over the challenge. The host runs it on a daemon thread with
  a timeout (`migration_attester_timeout`, default 5s) so a hung attester fails admission closed rather
  than holding it open, and caps concurrent in-flight attester calls (`migration_attester_max_inflight`,
  default 8) so a flood of deliveries cannot spawn unbounded threads; the attester should still bound its
  own work (a leaked daemon thread from a truly-hung attester is not reclaimed and holds one of the
  in-flight slots). Set the timeout to `None` to opt out of the host time bound.

Operational notes:

- A destination that receives a challenge-required migration but has **no** working attester — or whose
  attester returns **semantically-invalid** evidence (wrong nonce/subject/audience/expiry) — refuses
  admission (fail-closed) and persists nothing, so the source can re-deliver once the attester is fixed.
  The destination validates its own attester's output before persisting so a defective attester cannot
  freeze a bad receipt into the idempotent receipt store. A destination whose `attestation_policy` is
  configured with the trusted authority and allowed measurements gets a complete pre-persist check.
- Even for a bad first evidence the destination could **not** locally detect (signed by a key or bearing
  a measurement only the source's policy rejects), redelivery of the identical envelope **regenerates**
  the attestation, so once a correct attester is in place the next delivery settles. Recovery therefore
  never requires deleting or editing stored state — just redelivering after fixing the attester.
- The regenerated receipt is **persisted durably**, and a redelivery whose attester is unavailable falls
  back to the stored receipt. So after a correct attester has produced one good receipt, settlement still
  recovers across a lost acknowledgement, a destination restart, or a later attester outage.
- Challenge mode is **mutually exclusive** with `required_for_execution=True` on the same destination:
  in challenge mode the migrated permit carries no execution attestation (the proof travels in the
  receipt), so a destination that also requires an execution attestation will refuse challenge
  migrations. Pick one mechanism per destination.
- A migrated task's challenge nonce is consumed at the destination on first admission, so a task
  migrates to a given destination once (identical re-delivery remains idempotent).

## Upgrading

### Task ownership (new schema: SQLite v14, Postgres v12)

A task now belongs to the sender that started it: the **issuer and subject of the permit that first
admitted it**. Every later save of that task must present the same pair, checked in the same
transaction as the checkpoint compare-and-swap. A sender may rotate its signing key and still resume
its own task, because the key id is not what binds.

**Before you upgrade, let open tasks finish.** Rows written by an older Portmark carry no owner, and
it cannot be reconstructed (the audit trail records the agent, never the issuer). So:

- an **open** task with no stored owner refuses to resume, with: `legacy checkpoint has no stored
  owner and cannot be resumed safely after upgrade. Submit it as a new task.` Adopting the first
  caller as the owner instead would keep exactly the takeover this closes;
- a **closed** task is untouched. It stays readable and its audit chain still verifies.

Anything still suspended (`awaiting_input`) at upgrade time must be re-submitted as a new task.

### Time floor and retention (new schema: SQLite v13, Postgres v11; audit floor format 2)

The upgrade runs automatically at start-up:
- It adds each nonce's stored expiry, each migration's delivery time, a maintenance log, and the durable
  time floor.
- It starts the time floor at the newest past timestamp already in the database, not at zero. So a
  clock that is wrong at the first start after the upgrade is still caught.
- Existing nonces and delivered migrations get no expiry or delivery time, so `store prune` keeps them
  (they cannot be proven safe to delete).
- An audit-floor file in format 1 is still read (its time floor is 0) and is rewritten in format 2 on the
  next write. An older Portmark cannot read format 2, so after the upgrade a downgrade needs the backup
  of the floor file taken before it.

### Approvals now carry a required checkpoint generation (breaking approval format)

From this release a signed `ApprovalToken` includes a required `checkpoint_generation` and the host
verifies it (finding #1). Any approval **issued before the upgrade** — or issued by an approver that
does not set the generation — is refused at the gate as malformed or generation-mismatched. This is
fail-closed and intended: a held, not-yet-redeemed approval must be re-issued after the upgrade.

The generation to bind is the suspended checkpoint's generation, which the host returns on the
awaiting-input run (`RunResult.checkpoint["checkpoint_generation"]`). An approver reads that value from
the suspended task and seals it into the approval. **Before upgrading, drain or plan to re-issue any
approvals that are outstanding (issued but not yet redeemed).** They cannot be honored after the upgrade.

### Task cancellation (new schema: SQLite v9, Postgres v7)

This release adds durable task cancellation (`AgentHost.cancel_task`, finding #3), backed by a new
`task_cancellations` table. The store schema version advances (SQLite 8 → 9, Postgres 6 → 7). Schema
creation is automatic at startup: SQLite runs a forward-only migration, and Postgres creates the table
idempotently (`CREATE TABLE IF NOT EXISTS`) and bumps its recorded version. No data migration is needed
and the change is additive. As with any schema bump, upgrade the code before pointing it at a store, and
do not run an older Portmark against a store a newer one has already upgraded (the store refuses a schema
version newer than it supports).

**Cancellation is best-effort before launch, not a kill switch.** A cancel is fully enforced before an
approval is redeemed and while racing the redemption; after redemption it is caught only if it commits
before the pre-launch re-check. A cancel that lands later — in the check→launch window or once the tool
is already running — does **not** stop the effect: the tool runs and its effect happens even though the
task is now cancelled. Do not rely on `cancel_task` to prevent an in-flight external side effect;
guaranteeing that requires per-tool idempotency keys and reconciliation (a later tool-boundary change).

### Reserved migration task-id namespace (`mig::`)

A destination namespaces a **migrated** task's stored identity by the source host it
authenticates at admission, so two source hosts can migrate a task with the same
caller-chosen id to one destination without collision. The stored identity uses the
reserved prefix `mig::`. From this release, a **fresh, non-migration** task whose
`task_id` begins with `mig::` is refused at admission (this prevents a local caller
from pre-occupying a migrated task's key).

The guard applies to new admissions only; it cannot retroactively remove a collision
that already exists in a store written by an earlier version. **Before upgrading, check
every runtime store for a pre-existing task id that begins with `mig::`.** Such ids are
not produced by normal use (the prefix is internal), so a match is unexpected and should
be resolved before upgrading.

```bash
# SQLite
sqlite3 /data/runtime.sqlite \
  "SELECT task_id FROM checkpoints WHERE task_id LIKE 'mig::%';"

# Postgres (per schema)
psql "$PORTMARK_STORE_PATH" -c \
  "SELECT task_id FROM checkpoints WHERE task_id LIKE 'mig::%';"
```

If either query returns rows, migrate or rename those tasks (they were created under a
caller-chosen id that now collides with the reserved namespace) before rolling out the
new version.

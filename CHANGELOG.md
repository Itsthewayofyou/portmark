# Changelog

All notable changes to Portmark are recorded here. Versions follow [semantic versioning](https://semver.org/).

## Unreleased

### Changed

- **Portmark moves from MIT to the Elastic License 2.0**, and gains a trademark policy, contribution
  terms and an abandonment pledge. Nothing about the code changed. You may still use, modify and
  redistribute Portmark, ship it inside your own commercial product, and deploy it inside your own
  organization at any scale, free and without asking — there is no revenue threshold and no paid
  tier. The one thing withheld is offering Portmark itself to third parties as a hosted or managed
  service. This is a source-available license, not an OSI-approved open-source one, and Portmark says
  so rather than calling itself open source. **Every version up to the `last-mit` tag stays MIT
  permanently**, including PyPI releases 0.1.0 through 0.9.2; that grant is not withdrawn and the
  text is kept in `LICENSE-MIT`. Alongside it, an irrevocable pledge: if twelve consecutive months
  pass with no commit on the default branch, the most recent release becomes additionally available
  under Apache-2.0. See `NOTICE`, `TRADEMARKS.md` and `CONTRIBUTING.md`.

- **The MCP scope decisions are written down rather than merely true.** `portmark.asgi:create_app` installs
  no MCP tools, and that is now stated as a decision with its reason: it is an importable factory, and
  reading ambient configuration there would make a deployment's authority implicit. An embedded deployment
  that needs MCP will get a named opt-in factory instead. MCP.md also records why resources, prompts and
  sampling are deferred, the order they would have to arrive in, and why Portmark-as-an-MCP-server waits for
  a concrete consumer. Documentation only -- no behaviour changed.

### Added

- **MCP OAuth tokens are renewed for as long as the host runs.** `portmark serve` now keeps every `oauth`
  server's stored access token current in the background, renewing further ahead of expiry than the margin
  the isolated worker refuses at -- so the renewal is always ahead of the refusal rather than racing it. It
  removes the previous ceiling, where a host running longer than one access-token lifetime began refusing
  calls until it was restarted. It is not a guard and cannot become one: if it stops, the worker still
  refuses a stale token rather than sending one. A refusal from the authorization server is final for that
  server -- many servers rotate the refresh token on use, so retrying a refused refresh spends a credential
  that is already dead -- and everything else is retried. `portmark demo` is a single run and starts no
  refresher; `portmark.asgi:create_app` installs no MCP tools at all. See MCP.md, and OPERATIONS.md for the
  paired `mcp` / `mcp-types` version bump an upgrade needs.

- **OAuth for HTTP MCP servers.** An `oauth` block on an HTTP server delegates the operator's own access to
  a service such as GitHub, Linear or Notion. Portmark does not implement OAuth: the official `mcp` SDK is
  an exactly pinned optional extra (`pip install 'portmark[mcp-oauth]'`, owner decision D1) and Portmark
  performs every request itself, so each one keeps the resolve-once address pinning, verified TLS, byte caps
  and deadline that an MCP request has. A redirect from an OAuth endpoint is refused rather than followed.
  `portmark mcp login <server>` runs the authorization-code flow -- collecting the redirect on a loopback
  listener, or with `--manual` from a url you paste, for a machine with no browser -- and
  `portmark mcp logout <server>` deletes what it stored. The store is `0600` and is refused if anyone else
  can read it. Renewal runs in the host, where the SDK lives; the isolated worker only READS the store, so
  the extra's 28 packages never enter the sandboxed process, and an expired token there is a refusal rather
  than an unauthenticated call. Tokens are bound to their issuer and client, and the endpoints discovered at
  login are pinned, because the SDK's refresh path would otherwise post the refresh token to the resource
  server. See MCP.md.

- **`portmark audit export --format ocsf`** writes each exported record as OCSF 1.9.0 class `api_activity`
  (`class_uid` 6003), read from the live schema on 2026-09-23, so a SIEM can read an export without a custom
  parser. `verify-export` reads either shape without being told which, and both verification levels are
  unchanged: the native record travels intact under `unmapped.portmark`, and the round trip is exact.
  `attestation_list` is deliberately left empty — OCSF defines its fingerprint as covering the OCSF record,
  while Portmark's hash covers the original audit event, so filling it would state something false. A head is
  reported as a success only when its signature actually verified, and `verify-export` re-projects each record
  to confirm the OCSF fields describe the record they carry, so a rewritten `status` or `time` is refused. See
  OPERATIONS.md.

External-audit remediation, held unreleased (no version bump / tag) until the full audit is complete.

### Tooling and dependency updates (supersedes Dependabot #120)

- **Five transitive pins raised:** `anyio` 4.14.2 -> 4.15.1, `google-api-core` 2.34.0 -> 2.38.0, `google-auth`
  2.57.0 -> 2.58.0, `googleapis-common-protos` 1.75.2 -> 1.75.3, `pyparsing` 3.3.2 -> 3.3.3. All are
  transitive, so they moved with `uv lock --upgrade-package` rather than a change to `pyproject.toml`.
- **Two of the seven were refused, by the resolver rather than by preference.** `a2a-sdk` 1.1.4 declares
  `protobuf>=5.29.5,<7`, so the proposed protobuf 7.36.2 cannot be installed beside it; `pydantic` 2.13.5
  pins `pydantic-core` to exactly 2.46.5, so 2.49.0 cannot be either. Dependabot proposed both anyway,
  because it edits the exported requirements files directly and never resolves them against the packages
  that depend on them.
- **That is worth stating plainly: the bot's proposal was not merely incomplete, it was unsatisfiable.**
  Every install path uses `pip --require-hashes --no-deps`, and `--no-deps` means pip would have installed a
  protobuf its own sibling forbids without a word. What catches it is `pip check` in the `official-a2a-sdk`
  lane added above -- the gate earned its place on the first Dependabot PR after it landed.
- **One new transitive dependency arrives:** `google-api-core` 2.38.0 now requires
  `opentelemetry-api>=1.44.0,<2.0.0` (the official package, from `open-telemetry/opentelemetry-python`). It
  enters `requirements/a2a.txt` only -- the optional `[a2a]` extra -- so the default install, the runtime
  export and the Docker image are untouched.
- **Verified the way the lane will:** the regenerated `requirements/a2a.txt` was installed under
  `pip --require-hashes`, `pip check` reported no broken requirements, and the 23 A2A tests plus the two
  official-SDK conformance tests ran and passed with no skips.

### Tooling and dependency updates (supersedes Dependabot #112)

- **Pins raised, with the lock and the hash exports regenerated together:** `a2a-sdk` 1.1.2 -> 1.1.4,
  `psycopg[binary]` 3.3.5 -> 3.3.6, `uv` 0.12.15 -> 0.12.17, and the transitive `idna` 3.19 -> 3.20.
  Dependabot cannot do this on its own -- it edits `pyproject.toml` and the exports but cannot run `uv lock`,
  so its PR fails the `lockfile` gate by design. `uv lock` and `scripts/lock_requirements.py` were run and all
  five files committed together, which is what that gate exists to require.
- **The new export was proved, not assumed.** The regenerated `requirements/release.txt` was used to install
  uv 0.12.17 under `pip --require-hashes`, and that uv then re-ran `lock_requirements.py --check`: the hashes
  verify against the real artifacts, and the files agree with the lock under the exact version CI will use.
  CI's negative control was run too -- a copy with every hash replaced is refused by the hash check, and the
  untampered export still installs.
- **The a2a-sdk bump was actually exercised.** `tests/test_runtime.py` gates two tests on the real SDK being
  importable, and neither CI nor the default install had it, so both skipped everywhere. The SDK was
  installed at 1.1.4 and the file run against it: `test_local_agent_card_parses_under_strict_official_schema`
  and `test_local_and_sdk_agent_cards_are_identical` ran and passed, so the strict-schema agent card still
  parses and both adapters still serve the same card. 1.1.4 also carries upstream SSRF hardening on
  push-notification URLs, which Portmark does not rely on but does not lose by taking.
- **That check is now a gate, not a habit.** New CI job `official-a2a-sdk` installs the `[a2a]` extra at its
  hash-locked pin on the oldest and newest supported Python (3.11 and 3.14; `requires-python` is `>=3.11`)
  and runs every A2A test with the SDK present, since importing it switches which branch of
  `src/portmark/official_a2a.py` executes. The extra had no hash-pinned export at all, so
  `requirements/a2a.txt` is new and `scripts/lock_requirements.py` now generates it like every other set.
  The lane is scoped to A2A deliberately: it installs no Node and no Wasmtime, so the capsule tests living
  in the same file would measure its cold start rather than the SDK. The `test` lanes own those.
- **A skip fails that lane.** A skipped test still reports `OK (skipped=n)`, so a lane whose install quietly
  failed would have gone green having proved nothing -- which is precisely how the gap stayed invisible. The
  job asserts the SDK is importable, that exactly two tests were selected, and that the final line is a bare
  `OK`. The guard was checked both ways before it was committed: it passes with the SDK installed and fails
  with `OK (skipped=2)` without it.

### MCP tools over stdio (MCP/SIEM plan, PR 2)

- **Portmark can call tools in an MCP server**, as an MCP **client**: `--mcp-config mcp.json` registers each
  approved tool in the ordinary `ToolRegistry`, so it passes the same permit, policy, constraint, budget,
  effect-ledger and audit gates as any other tool. New modules `mcp_client`, `mcp_config`, `mcp_worker`, `mcp`;
  new docs `MCP.md`. No new dependency: the wire surface is a handful of methods.
- **Both protocol eras.** The modern revision (2026-07-28: no `initialize`, per-request `_meta`,
  `server/discover`) and the legacy `initialize` handshake of 2025-11-25 and earlier. The era probe follows
  the specification's stdio rules, and the fallback is not keyed to one error code.
- **Nothing the server says is authority.** Each tool is approved by the operator as the SHA-256 of its whole
  definition, re-checked at start-up **and** at every call; the server's annotations are ignored, and only the
  operator's `read_only: true` marks a tool free of side effects -- every other MCP tool registers as
  side-effecting, which requires a reconcile target and an acknowledged IsolationProfile. Tool descriptions and
  schemas never reach the model: providers still receive names only.
- **Containment.** A stdio server is launched per call **inside** the isolated worker, so the existing deadline
  and process-tree kill cover it. `secret_env` names the only environment variables it inherits.
- **Failure codes.** An isolated tool may attach a machine-readable `error_code` to its failure, and may report
  only the codes its registration allows (`register_isolated(error_codes=...)`), so no other tool can forge one.
  The host records it in `tool.failed`: `mcp_tool_error` (the server said `isError`), `mcp_transport_error`
  (effect unknown), `mcp_pin_drift`, `mcp_config_drift`, `mcp_protocol_error`.
- **MCP tools over Streamable HTTP.** A server is configured with `url` instead of `command`. One message is
  one POST on its own connection, and a failed POST is never resent -- resending a `tools/call` could double a
  real effect. The endpoint's host is resolved once and the connection goes to the literal that was checked,
  with the certificate verified against the name; `allow_private: true` widens that to loopback and private
  answers only and is logged at start-up. A static bearer token is named by `bearer_env`; a configured
  variable that is missing fails closed, and a bearer over plain `http` is refused outright. Both protocol
  eras are spoken, with the era decided by the body of a `400` rather than by the status alone. An event
  stream is read only until the answer to the request arrives. Per the specification, an argument a server
  annotates with `x-mcp-header` is mirrored into an HTTP header -- see MCP.md for what that exposes -- and a
  tool whose annotations break the rules is excluded with a reason.
- **`portmark mcp pin`** prints what each server offers now, with the pin to approve it. It never approves. The
  probe runs in a killable process tree, so a server that never answers dies with the probe rather than being
  orphaned, and it reports both outcomes as JSON on stdout. A probe that ends NORMALLY sweeps its own process
  group before exiting, so a background child of the MCP server does not outlive it either.
- A legacy server that **exits** on the modern probe (some do) is restarted and handshaken on a fresh process,
  and an `initialize` answer naming a revision Portmark does not speak is refused instead of accepted.
- Not included: Streamable HTTP (and therefore OAuth servers), MCP resources/prompts/sampling, and Portmark as
  an MCP server.

### Tool names are identifiers, checked where authority is defined

- **A tool name must now be 1 to 192 characters**, letters, digits and inner `.`, `_` or `-`, starting and
  ending on a letter or digit (`portmark.models.validate_tool_name`). The character set is the one the MCP
  specification (revision 2026-07-28) says SHOULD be the only allowed one; the length leaves room for the
  `mcp.<server>.` prefix on top of a 128-character MCP tool name. The limit applies to the final registered
  name, after namespacing (owner decision, 2026-09-22): a generated name over the limit is refused, never shortened. Whitespace, control characters (a
  newline in a name is log injection), look-alike Unicode, path and URL separators, and the empty string are
  refused. Before this, any non-empty string was accepted.
- The check runs at every door that **defines** tool authority: a permit grant (so an incoming A2A envelope is
  refused at decode with `invalid params`), a manifest's `requested_tools`, a policy tool entry, and
  `ToolRegistry.register` / `register_isolated`. A name a provider merely **proposes** needs no new check: it
  matches no grant, so the existing refusal path closes the run.
- **Compatibility:** a deployment whose policy, permits or registry use a tool name outside this set now fails
  closed at load, decode or registration. Every name Portmark ships or documents already fits.

### Audit export to a SIEM (MCP/SIEM plan, PR 1)

- **`portmark audit export`** appends the audit chains to a JSON Lines file for a log shipper (Vector,
  Fluent Bit, an OpenTelemetry collector). Portmark opens no network connection and holds no SIEM credential.
  Delivery is at-least-once: the per-task cursor is saved only after the output is fsynced, and every record
  carries a deduplication `key`. No clock is trusted: each run scans every task head.
- **The export is a projection, not a copy (owner decision D3c).** The authoritative audit record does not
  change. Each record keeps the authoritative `hash` and `previous`, but its `details` hold only the fields a
  projection policy allows: default-deny for every event kind, with a per-tool argument policy whose default
  is keys + digest only. Other fields become their name plus an HMAC-SHA-256 digest of the original value,
  under a dedicated keyring (`--projection-keyring`, mode 600, rotatable, `hmac_key_id` in every record).
- **The exporter checks before it copies:** each event's hash and link, and each head against its last event.
  A damaged, rolled-back, or rewritten chain produces an export-control `integrity_failure` record and exit 1.
- **`portmark audit verify-export`**: Level 1 proves, from the SIEM copy alone, that each task's events link
  without a gap and match a validly signed head. It cannot prove the projected values. Level 2
  (`--against-store`) recomputes every exported record from the store and proves them.
- New store read `audit_export_page` (in-memory, SQLite, Postgres), from one snapshot, never writing.
- Not included yet: an OCSF record mapping.

### Runtime audit (2026-09-22): SSRF in the fetch example, stale tool limits, A2A error statuses

- **The example `http.fetch` tool refuses a name that resolves to a non-public address**, and connects
  only to the address it checked (DNS rebinding), with TLS still verifying the original name. It now
  uses the provider's pinned connection (`portmark.providers.PinnedHTTPSConnection`, public) and a new
  `portmark.providers.resolve_public_address`.
- **Re-registering a tool replaces its limits completely**: an omitted timeout or output cap reverts to
  the registry default instead of keeping the replaced tool's value.
- **A2A submission failures report who caused them.** A server failure is HTTP 500 (it was 400), including
  any failure after the request was admitted (the configured provider's answer or decision); a request
  refused at admission, or whose permit expired during the run, stays 400; an unreachable remote witness is 503 with `Retry-After` and the new refusal metric
  reason `witness_unavailable`. The body stays the same generic error.

### External validation — EV-013 resolved: every save is witnessed by the optional remote witness

- **The host advances the remote witness on every save** (new module `portmark.witness_binding`), inside
  the database transaction, and stores the witness's receipt in the same commit. A whole-host restore
  (database and floor together) and a clone of the pair are refused. Configure it with
  `PORTMARK_REMOTE_WITNESS_URL`, `PORTMARK_REMOTE_WITNESS_PUBLIC_KEY`, `PORTMARK_REMOTE_WITNESS_KEY_FILE`
  (and optionally `PORTMARK_REMOTE_WITNESS_TIMEOUT`).
- **Fail closed (owner decision F1):** a refusal or an unreachable witness refuses the save and the start.
  **Optional (F3):** gauge `portmark_remote_witness_active`.
- **Boot check** of the database's last receipt against the witness; `verify-audit` reports
  `remote_status` (`witness-unconfigured`, exit 2, when a database that holds a receipt is verified without
  the witness settings); `floor-reset --operator-id --operator-key-file` rebaselines the witness, and
  `time-floor reset` takes the same arguments to lower the witness's time floor. A rebaseline sends the
  heads in pages that each fit one request, and every witness request is measured before it is sent. The
  witness is asked before anything local changes. A lost rebaseline answer is healed by sending the same
  signed request again (the reference witness replays an identical rebaseline); if no answer arrives, the
  result is `rebaseline-unconfirmed` and the operator is sent to `floor-reset`, which recovers either way.
- **Schema:** SQLite v15 / Postgres v13 add `witness_receipts`. **Upgrade note:** a database that holds a
  receipt refuses to start without its witness.

### External validation — EV-013 part 1: remote witness protocol, reference server, conformance kit

- **New module `portmark.remote_witness`**: the protocol for a remote witness on another machine. Per
  host, a hash chain of advances (`prev` = the receipt of the one before), pending until the next advance
  confirms it or discards it, per-task heads that never go back or split, a registry that never goes
  back, a time floor that only rises. Requests and answers are Ed25519-signed; the client accepts only
  answers signed by the pinned witness key and bound to the request, and fails closed otherwise.
- **New command `portmark witness keygen|serve`**: the reference witness (`portmark.witness_server`). An
  append-only SQLite log, signed requests from enrolled host, operator, and auditor keys, loopback by
  default and `--public-mode behind-tls-proxy` for a public bind.
- **New command `portmark witness conformance`**: checks that a deployed witness enforces the chain rules,
  with a dedicated `conformance:` host id.
- **Witness seam** (no behaviour change): `MonotonicWitness` gains `host_id` and `witnessed_head` and a
  written failure rule (raise when the witness cannot answer; `None` only for "never witnessed"). New
  `LocalFloorStore` protocol for the floor file and its epoch. The host does not use the remote witness
  yet: that is EV-013 part 2, and EV-013 stays open until it lands.

### Preflight conformance kit

- **New command `portmark preflight-conformance --destination <host>`** (library:
  `run_preflight_conformance`). It runs `PORTMARK_MIGRATION_PREFLIGHT_COMMAND` over two fresh challenges
  and verifies each answer with `verify_migration_challenge`, like the runtime does, then checks that a
  destination the command cannot honestly attest is refused. A readiness check, not a new control: the
  runtime already verifies every preflight answer before it releases state.

### External validation — EV-006 resolved: optional checkpoint encryption

- **Checkpoints can be sealed at the storage boundary** (new module `portmark.checkpoint_crypto`). Set
  `PORTMARK_CHECKPOINT_KEYS` (`key-id:base64-key[,...]`) or `PORTMARK_CHECKPOINT_KEYS_FILE` (mode 600).
  The SQLite and Postgres stores then seal each checkpoint with AES-256-GCM, bound to the task id,
  generation, key id and the `closed` and owner columns; the `status` column is checked against the
  sealed state. A changed byte, a wrong key, a row moved to another task or generation, a reopened task,
  a rewritten owner or an edited status is refused, and the run stops before it writes. No schema change.
- **Optional (owner decision D1).** New gauge `portmark_checkpoint_encryption_active` on the authenticated
  `/metrics`. Disk or volume encryption remains a valid deployment-level control.
- **Strict reads and a one-time migration (owner decision D2).** With a keyring a plaintext row is refused;
  without one a sealed row is refused. `portmark store encrypt-checkpoints [--apply]` seals every
  plaintext row in one transaction (and re-seals rows under an older key, for rotation). A row that
  cannot be read aborts the whole run. **Upgrade note:** setting a keyring on a store with existing
  checkpoints makes those tasks fail until the migration has run.

### External validation — EV-004 resolved: verifier conformance kit

- **New command `portmark attest-conformance --evidence <file>`** (library: `portmark.verifier_conformance`).
  It takes one real, known-good verifier request and sends it, plus 8 negative cases built from it
  (wrong subject, audience, measurement and nonce; stale; corrupted, truncated and garbage quote),
  straight to `PORTMARK_ATTESTATION_VERIFIER_COMMAND`, then the known-good request again. In each
  negative case the claims and the request agree, so only the verifier's quote binding can refuse it.
  One lie goes first, while the quote is new: a verifier that remembers the quote instead of comparing
  fields fails (a first-use association cache accepts that lie; a replay cache refuses the repeats). Exit 0 = pass, 1 = a case failed,
  2 = bad input. It needs no store and no policy.
- DEPLOYMENT.md and ATTESTATION.md now require a pass before production use.

### External validation — EV-001 and EV-007 resolved

- **EV-001:** DEPLOYMENT.md "Multiple Replicas" states that a multi-replica deployment must enforce the
  rate limit at a shared edge (Portmark's own limits are per process), including the caveat that an nginx
  zone is shared only inside one nginx instance. A test asserts the text, and a route-coverage test
  requires every route the reference nginx front forwards to carry a per-client `limit_req` on a
  defined zone.
- **EV-007:** mutation tests pin the rest of both decision schemas: wrong types, missing required keys,
  and an unsupported kind or outcome (HTTP provider and Wasm component decoders). No code changed.

### Boundary audit — release gates (RC-03, RC-02)

- **The SafeRoot tests can no longer skip silently on Linux (RC-03).** The `openat2` (SafeRoot) tests skip
  where `openat2(RESOLVE_BENEATH)` is unusable. On Linux that now FAILS the suite unless the
  environment declares `PORTMARK_TEST_ENV_HAS_NO_OPENAT2=1`, the same pattern as the no-Node
  declaration. No workflow may declare it (a supply-chain test checks this), so a CI runner that loses
  `openat2` (old kernel, seccomp profile) turns red instead of green. The in-image check under the
  hardened profile (G14) already ran in the `container` job.
- **Timed-out thread-path tools are visible (RC-02).** New gauge `portmark_tool_threads_overdue`: tools
  past their deadline and still running. Such a thread can still perform an effect after the host
  recorded the timeout. Owner decision 2A: the default execution path is **not** changed; `register()`
  keeps its behavior until isolated execution has a deliberate migration path. TOOLS.md now says that
  `PORTMARK_TOOLS` loads trusted code and recommends `register_isolated()` for external or effectful
  tools; OPERATIONS.md adds the alert.

### Boundary audit — production profile (NET-02, DB-01, ATT-01, ATT-02)

- **BREAKING: the ASGI app is production by default.** `PORTMARK_PROFILE` is `production` (default,
  also when unset or blank) or `development`; any other value refuses to start. A container or
  `portmark.asgi` import with no configuration now refuses to start and lists what is missing. Set
  `PORTMARK_PROFILE=development` for local work. The CLI (`portmark demo` / `serve`) gets the same
  production host checks; its network rule is unchanged, because it is already loopback-only.
- **The public-exposure gate moved into app construction (NET-02).** `serve_asgi` checked the four
  public-mode requirements only before it started uvicorn, so `uvicorn portmark.asgi:app --host 0.0.0.0`
  or an embedding server skipped them. `create_app()` now applies the same four checks (one shared
  function, `network_problems`) in production, whatever the bind: the app cannot see where it is bound.
- **A durable store needs the audit floor in production (DB-01).** A new database could start without
  rollback detection and only log a warning. Production now refuses; development keeps the warning.
  New gauge `portmark_audit_witness_active` on the authenticated `/metrics` (not on `/readyz`).
- **A production host that may migrate needs real attestation (ATT-01, ATT-02).** When the host policy
  allows migration, production requires `PORTMARK_ATTESTATION_VERIFIER_COMMAND` (a platform quote
  verifier), the new `PORTMARK_ATTESTATION_ALLOWED_MEASUREMENTS` and the new
  `PORTMARK_MIGRATION_PREFLIGHT_COMMAND` (below), and turns on the source-minted migration challenge. The
  check runs on the boot policy load and on every policy reload. `required_for_migration` is not set: it
  asks the model provider for destination evidence, and the preflight has the source obtain it itself.
- **The documented container run works with named volumes.** The image ran as `portmark` but `/data`
  did not exist, so a named volume mounted there was owned by root and the store failed with
  `Permission denied` (also on main). The image now creates `/data` and `/floor` owned by `portmark`,
  mode `0700`; a new named volume copies that owner. The DEPLOYMENT.md example was run end to end:
  ready, `portmark_audit_witness_active 1`, and refused (exit 2) without the floor.
- **The destination is verified BEFORE migration state is released (auditor round 1, owner decision 2).**
  The challenge was verified only at settlement, after the signed (not encrypted) envelope with the
  projected state had been sent. New `PORTMARK_MIGRATION_PREFLIGHT_COMMAND` (shell-free, empty
  environment, 10 s timeout, 64 KiB output limit): at the migrate decision the source mints a fresh
  challenge, the command returns the destination's evidence over it, and the source verifies it with
  `verify_migration_challenge` before it builds and seals the envelope. The same challenge becomes the
  delegated permit nonce, so the receipt proof at settlement stays. A refusal releases nothing (no
  envelope, no outbox row) and closes the task as refused. Production requires the command when the
  policy allows migration.
- **The CLI gets the production host checks (auditor round 1).** `portmark demo` / `serve` built the host
  with `production=False`; they now pass the profile, the measurement list and the preflight command.
- **Not changed (recorded):** hostile-tool containment stays a deployment control (RC-01, see the new
  DEPLOYMENT.md "Production Profile" section); the remote witness is open as EV-013 (DB-02).

### Completeness review — a task belongs to the sender that started it (PM-001, High)

- **Cross-sender task takeover is closed.** The resume path found a checkpoint by caller-supplied
  task id alone and adopted its counters. An envelope signature proves the sender is *a* trusted
  identity; it said nothing about this task. So any trusted sender that learned or guessed an open
  task's id and generation could resume, drive, and close another sender's task.
- **Owner = `(permit issuer, permit subject)`** of the admission that created the task (owner
  decision A). It is recorded on the create and compared on every later save, **inside the same
  transaction as the generation compare-and-swap**, in all three stores. Binding the pair rather
  than the signing key id lets an issuer rotate its key and still resume its own task. A migrated
  task is owned by its delegated permit's issuer (the source host) and the agent subject.
- **Schema SQLite v14 / PostgreSQL v12**: two nullable columns, `owner_issuer` and `owner_subject`.
- **Upgrades.** Existing rows keep no owner, because it cannot be reconstructed (the audit trail
  records the agent, never the issuer). An **open** ownerless task refuses to resume — "legacy
  checkpoint has no stored owner and cannot be resumed safely after upgrade. Submit it as a new
  task." — rather than letting the first caller claim it, which would preserve the very takeover
  this closes. A **closed** legacy task is untouched: it is evidence, and stays readable and
  verifiable. Let open tasks finish before upgrading, or re-submit them afterwards.

### Completeness review — authority during a run (PM-003, PM-004, Medium)

- **A permit's lifetime is re-read while the run is in flight (PM-003).** Expiry was checked once,
  when the effective permit was built at admission, so an admitted run kept that authority for its
  whole life: a provider that answered after the permit ended could still launch a tool, redeem an
  approval, or complete. `security.require_unexpired` now runs after the provider decision, again
  immediately before a tool launch, and again before an approval is burned durably. It raises
  `PermitExpiredError` (a `SecurityError`), and the run terminalizes as `permit.expired`.
- **A provider decision is checked for SHAPE before it is read anywhere.** `kind`, `tool` and
  `destination` must be strings, `arguments` an object that can be recorded. Without this, a `tool`
  that is not a string but compares equal to a granted name passed the grant check and became a KEY
  in the saved state; encoding that checkpoint then raised in `_persist`, outside every handler, and
  stranded the task at `running`. `content` keeps its existing, gentler treatment (a clean
  `content.rejected` result that does not raise).
- **Reading the provider's result is inside that boundary too.** A provider that returns something
  that is not a `ProviderDecision` raised on attribute access, outside every handler, and left the
  checkpoint at `running` — the same class PM-004 closes.
- **The last authority check sits immediately before the call, and a late expiry tells the truth.**
  Every earlier position can go stale: the ledger's `prepared` -> `started` transition and the
  launch-capability check are both store round trips that can block. At the final position the host
  KNOWS the tool has not run — `invoke` has not been called and its one-use capability is still
  armed — so an expiry settles the row back to `prepared` ("intent recorded, never launched"), which
  a later run may simply re-run. It is never left at `started` ("may have landed"), which would make
  an operator reconcile an effect that never happened. A separate check before the ledger keeps an
  already-expired decision from writing anything at all.
- **Every refused decision reaches a durable CLOSED checkpoint (PM-004).** `_apply_decision` ran
  outside every failure boundary, so a decision that failed host authorization — a tool with no
  grant, an exhausted tool-call budget, a missing tool name, a migration with no destination or an
  off-allowlist one, an expired permit, or any unexpected error from a tool — raised straight out of
  `run()` and left the admitted checkpoint open at `running`: resumable, and claiming the agent was
  still working. It now records a bounded `decision.refused` (or `permit.expired`) event, persists a
  closed `failed` checkpoint, and re-raises. The record carries identifiers only, never arguments or
  state. The **effect ledger** stays the authority on side effects: a tool that had already started
  keeps its own row for the reconcile pass, and this closure neither settles nor retries it.

### Completeness review — output projection (PM-002 High, PM-005 Low)

- **An explicit empty `output_projection` is share-nothing again.** `build_envelope` collapsed `[]`
  to `None` with a falsy test. `None` means "no opinion" in the projection intersection, so a sender
  that explicitly asked to share no fields was widened to whatever the host policy allowed (`["*"]`
  meant full tool output reached the model provider). Absent stays `None`; `[]` stays `()`.
- **One decoder for every source.** `security.normalize_output_projection` is now used by the policy
  loader, `build_envelope` and the A2A permit decoder, so they cannot drift apart. The A2A path did
  not have the widening bug (`ToolGrant.__post_init__` keeps `[]` as `()`), but it had no projection
  validation at all; it now rejects a non-list, an empty or non-string entry, and `*` mixed with
  field names, like the other two. The policy loader keeps its behaviour and its error type.
- **EV-002 Windows text corrected (PM-005).** `EXTERNAL_VALIDATION.md` still said Windows refuses
  side-effecting isolated tools. Windows has used a kill-on-close Job Object since 0.9.0, and the
  refusal now applies only to a platform with no tree-termination primitive at all.

### Section 12 — capacity and clock (PR B): retention, paging, metrics, clock-rollback protection (findings #4, #6 Medium)

- **Clock rollback can no longer revive expired authorization (#6, owner decision D3).**
  - All security expiry decisions (permits, approvals, keys, receipts, attestations), permit issuance
    (`portmark envelope` and the demo), and audit-head signing times now use one trusted clock. While
    that clock has failed closed, no permit is issued.
  - The configured tolerance applies from the first start-up check. It changes the running clock in
    place, so a rollback since the process started is judged with it and refuses start-up.
  - It compares the wall clock with a monotonic baseline. A backward jump beyond
    `PORTMARK_CLOCK_TOLERANCE_SECONDS` (default 300) fails security decisions closed until a restart. A
    forward jump is allowed but reported with a `CRITICAL` line and the `clock.forward_jumps` metric.
- **A durable time floor.**
  - It advances with checkpoint saves and approval redemptions, at most once a minute.
  - Every update is a compare-and-swap that only moves the floor forward.
  - On PostgreSQL it uses the database clock, and it never waits on or fails the save it rides in
    (`SKIP LOCKED`).
  - It is mirrored into the signed audit-floor file (format 2), so restoring an older database snapshot
    does not restore an older floor.
- **Start-up refusals.** Start-up refuses when the clock plus the tolerance is behind the floor, and (on
  PostgreSQL) when the host and database clocks disagree by more than the tolerance. The container
  entrypoint now exits with code 2 and a plain message for every start-up refusal.
- **Recovery is manual only:** `portmark time-floor reset --to <epoch> --reason <text> --confirm`,
  recorded in the maintenance log and in the audit floor. A `floor-reset` of the audit floor keeps the
  time floor.
- **Safe pruning, only on request (#4, owner decision D2).** `portmark store prune --before <cutoff>`:
  - It is a dry run unless `--apply`.
  - It deletes only nonces whose authorization expiry is stored with them and is older than the cutoff
    and the clock tolerance.
  - It also deletes delivered migration rows that carry a verified receipt and were delivered before the
    cutoff.
  - It keeps legacy rows without an expiry or delivery time, and all pending and dead migrations.
  - It selects and deletes in bounded, cursor-ordered batches, re-checking the rule inside the delete.
  - It writes a maintenance-log record per batch plus a summary.
  - It refuses a future cutoff, or a clock behind the time floor, and never runs `VACUUM`.
- **Capacity visibility.**
  - `portmark store stats`, and `/metrics` gauges refreshed at most once a minute, report row counts per
    table, the oldest pending migration, database size, free space (SQLite), and the time floor.
  - `/metrics` now runs off the event loop, like `/readyz`.
- **Paged admin listings and a claim ceiling.** `list_pending_migrations` and `list_dead_migrations` take
  `limit` (at most 1000) and an `after` cursor, and return rows in `task_id` order. `claim_migrations`
  takes at most 100 rows per call.
- **Schema.** SQLite v13 and Postgres v11. An upgraded database starts its time floor at the newest past
  timestamp it already holds. The v13 schema reference in `tests/sqlite_schema_versions.json` is
  hand-derived from v12.

### Section 12 — runtime limits (PR A): bounded shutdown, body deadline, PostgreSQL timeouts, thread-start permits (findings #1, #2, #3 Medium; #5 Low)

- **Shutdown is bounded (#1, owner decision D1).** Before this change, the ASGI app reported shutdown
  complete while admitted runs were still executing. uvicorn waited for them with no time limit.
  Shutdown now works like this:
  - Admission stops at once. A new submission gets `503`, and `/readyz` reports `not_ready`.
  - The app waits for the admitted runs, for at most `PORTMARK_SHUTDOWN_GRACE_SECONDS` (default 25).
    uvicorn's own wait shares the same grace and start time.
  - When the grace expires, the app logs each unfinished run by task id, checkpoint generation, phase and
    effect ids only. It then replies `lifespan.shutdown.failed`.
  - The unfinished run is abandoned, as in a crash. It launches no further tool and writes no further
    checkpoint.
  - Runs execute on daemon threads, so a stuck run no longer holds the process open.
  - A side-effecting tool abandoned mid-call has an effect of unknown status. It is resolved through the
    existing effect ledger (`AgentHost.reconcile_effect`).
- **No operation can start after the shutdown deadline (auditor, PR #97 round 1).** The first version
  checked "is the run still live?" and then, in a separate step, recorded the phase and acted. The
  deadline could land between the two, so a tool could start after the shutdown was reported, and the
  report could name the previous phase without the effect id. Each operation (provider call, approval
  redemption, tool launch, checkpoint write) now starts through one atomic `begin()` under the same lock
  that `abandon()` takes, and `abandon()` takes the report snapshot under that lock. Either the deadline
  comes first and the operation never starts, or the operation comes first and the report names it as in
  flight. A side-effecting tool begins before its effect-ledger write, so an abandoned run records no
  intent and launches nothing. Approval redemption, which consumes a nonce, is fenced too.
- **PostgreSQL connections detect a silent network (auditor, round 1).** Every connection enables TCP
  keepalives (10 s idle, 5 s interval, 3 probes) and a 30 s `tcp_user_timeout`, whatever the DSN says.
  This bounds the wait when the network stops delivering packets after a query was sent. It is an
  operating-system mechanism, not an exact client-side deadline, and DEPLOYMENT.md says so.
- **Capacity stays honest when a request task is cancelled (#1).** The admission slot was released
  when the request task ended, even though its run kept executing on a worker thread. The run thread
  now owns the slot until the run ends.
- **One absolute request-body deadline (#2).** A body must arrive completely within
  `PORTMARK_A2A_BODY_READ_TIMEOUT_SECONDS` (default 30), including the time between chunks. When it
  expires, the client gets `408`, the connection closes, and the admission slot is released. The auditor's
  repro no longer starves the server: two stalled requests against a limit of two used to force a `503`
  on a valid third one. The same deadline applies to the loopback reference `http.server`, which read the
  body with no time limit.
- **Every PostgreSQL connection is time-bounded (#3).** Before this change, only readiness was bounded.
  Every connection now has these limits, including the schema-setup connection, which waited on a
  blocking advisory lock:

  | Limit | Default |
  |---|---|
  | Connect | 5 s |
  | Statement | 30 s |
  | Lock wait (row, table or advisory) | 10 s |
  | Idle in an open transaction | 60 s |

  - Each limit can be changed with a `PORTMARK_POSTGRES_*` variable. Zero is refused, because it would
    turn the limit off.
  - The limits are set after connecting, so a DSN cannot disable or raise them. A DSN may only lower
    `connect_timeout`.
  - Schema setup uses longer limits that are still finite.
  - A timeout fails the transaction and rolls it back, like any other database error.
- **A thread that fails to start no longer leaks capacity (#5).** The HTTP provider's transaction slot
  and the migration attester's slot are released, and the call fails closed, when `Thread.start()`
  raises. The new ASGI run thread follows the same rule. I checked every other thread-start site: none
  of them reserves a slot.

### Tooling and dependency updates (Dependabot #89-#93, one PR)

- **Tool pins:** coverage 7.16.0 → 7.16.1 (`ci`), twine 6.2.0 → 7.0.0 and uv 0.10.11 → 0.12.15
  (`release`). **Transitive:** urllib3 2.7.0 → 2.8.0, tzdata 2026.3 → 2026.4 (Windows only). No runtime
  dependency changes.
- Relocked for these five packages only (`uv lock --upgrade-package`), then the hash-pinned exports were
  regenerated. uv 0.12 also drops lock markers that repeat a parent's marker (for example `wrapt` under
  `aiologic`, which is itself only used below Python 3.14). The exports are unchanged apart from the five
  versions and their hashes.
- Checked with the new tools: twine 7 still has `check --strict`, and uv 0.12.15 still exports the
  CycloneDX 1.5 SBOM the release workflow attests.
- **Dependabot now groups routine bumps:** one weekly PR for pip and one for GitHub Actions, so the relock
  is done once per week. Security updates are not grouped and still arrive at once.

### Python 3.14: newly tested and supported (not required)

- **Python 3.14 is now tested and supported.** CI runs the full suite on 3.14 on Linux and Windows,
  installing from the same hash-locked `requirements/*.txt` sets, with no prerelease interpreter and no
  relaxed hashes. The classifier `Python :: 3.14` is added.
- **Nothing is newly required.** `requires-python` stays `>=3.11`, and 3.11, 3.12, and 3.13 stay in the
  CI matrix.
- **The container image moves to Python 3.14.6.** The base is `python:3.14.6-slim-bookworm`, still
  pinned by its full multi-arch digest (checked against Docker Hub on 2026-09-19).
- **CI now tests the exact shipped image.** A new `container` job builds the image once and checks that
  its Python is the Dockerfile's pinned version. It then runs the whole suite inside that image, against
  the Portmark the image installed (the checkout is mounted read-only and its `src/` is hidden), and
  runs the deployment-profile tests against it. Before, each Linux test job built the image and only
  ran the profile tests.
- **The image test pins the base image by shape, not by one version.** It requires exactly one `FROM`,
  a patch-pinned tag, and a full 64-hex digest. The image's Python minor version must also be in both
  CI test matrices and the classifiers, so an image on an untested Python cannot merge.
- **Dependabot proposes Python patch releases only.** A new Python minor or major version is a manual
  change, because CI must test it first.

### Section 11 — deployment hardening (PR C): public-mode gate, one proxy authority, locked builds (findings #1, #4 Medium; #6 Low)

- **The container is loopback by default (#1).** The image ran raw uvicorn on `0.0.0.0` with no token,
  no TLS assertion, and uvicorn's proxy handling. Its command is now `python -m portmark.serve_asgi`,
  which binds `127.0.0.1` unless told otherwise. A public bind refuses to start unless ALL of
  `PORTMARK_PUBLIC_MODE=behind-tls-proxy`, `PORTMARK_A2A_TOKEN`, `PORTMARK_A2A_TRUSTED_PROXIES`, and an
  `https://` `PORTMARK_A2A_PUBLIC_BASE_URL` are set; every missing one is reported at once, and the
  acknowledgement alone never lowers another requirement. **Operator action:** a container that must
  accept connections from another container or host needs these settings (DEPLOYMENT.md).
- **Portmark is the only proxy authority (#6).** Both the container entrypoint and `portmark serve` run
  uvicorn with `proxy_headers=False` (uvicorn's default trusted `X-Forwarded-For` from 127.0.0.1 and
  rewrote the peer before Portmark's policy ran).
- **Locked builds (#4).** Tool pins moved into `pyproject.toml` dependency groups; `uv.lock` was
  refreshed (it was stale: `psycopg` / `psycopg-binary` 3.3.4 -> 3.3.5, which `pyproject.toml` already
  pinned). `requirements/*.txt` are hash-pinned exports (`scripts/lock_requirements.py`); Docker, every
  CI job, and the release install only from them with `--require-hashes --no-deps` and build Portmark
  with `--no-build-isolation`. A new CI `lockfile` job fails on a stale lock or export and proves a
  tampered hash is refused. The Docker base image and the CI Postgres image are pinned by digest;
  Dependabot now covers the Dockerfile.
- **Found on the way:** CI and Docker pinned `setuptools==83.0.0` while `[build-system]` required
  84.0.0 (a Dependabot bump); the isolated build silently fetched 84.0.0 unhashed. The bootstrap group
  now matches, and `lock_requirements.py --check` fails if they diverge again.
- **Releases (#4).** The tag's commit must be on `main` (and be the checked-out commit); the build runs
  in the locked environment; a CycloneDX SBOM is published as an artifact; a separate `attest` job
  records GitHub build-provenance and SBOM attestations; PyPI PEP 740 attestations (already on by
  default) are now set explicitly.

### Section 11 — deployment hardening (PR B): crash-safe, restart-idempotent SQLite migrations (finding #3 Medium)

- **Each migration step is one transaction (#3).** Steps ran through `executescript()`, which commits
  first and then runs each statement in autocommit. A crash after `ALTER TABLE checkpoints ADD COLUMN
  generation`, before `closed` and the version bump, left a database that every later start refused
  (`duplicate column name: generation`). Each step now runs its statements with `execute()` inside one
  `BEGIN IMMEDIATE` transaction together with its `PRAGMA user_version` bump. A crash leaves the
  complete old or the complete new version.
- **Concurrent first opens queue.** The version is read inside the write transaction, so two processes
  opening the same old database no longer run the same step at once.
- **Restart-idempotent steps.** `ADD COLUMN` checks `PRAGMA table_info` first; the v2 `audit_events`
  rebuild finishes a copy stranded after `DROP` (rename) and discards one stranded before it. A
  database already half-migrated by the old runner now continues.
- **Tests.** A child process is killed with `os._exit` before every statement of the upgrade (from a
  legacy v0 database and from v3); each reopen must show a complete schema matching
  `tests/sqlite_schema_versions.json` (generated from the pre-rewrite code) with every seeded row
  intact, then continue to v12. OPERATIONS.md gains crash-safety and repair/restore steps.
- **Cold start of many hosts on one new store (auditor round 2, availability).** Hosts that start
  together on a store whose directories do not exist yet all created the same components; the losers
  failed with `FileExistsError`. Losing the `mkdir` race is now accepted, and the full directory-chain
  check that follows judges whatever exists (a raced-in symlink, file, wider mode, or other owner is
  still refused). The real 32-process cold-start test then exposed a second race: switching a new
  database to WAL can return `SQLITE_BUSY` at once (no busy handler, to avoid a lock-escalation
  deadlock), so some hosts failed with `database is locked`. The switch is skipped when the file is
  already WAL, and `SQLITE_BUSY` alone is retried within the existing busy timeout.

### Section 11 — deployment hardening (PR A): log redaction and owner-only storage (findings #2, #5 Medium)

- **Plain-text logs are redacted too (#2).** Redaction ran only in the JSON formatter, so the default
  text format wrote bearer tokens, passwords, and DSNs verbatim. Both formats now redact the fully
  rendered output (message, arguments, exception text, traceback, stack information).
- **URI credentials and query credentials are redacted (#2).** No pattern matched URI user-info, so
  `postgres://alice:password@db` leaked even in JSON mode. User-info is now replaced with `[REDACTED]`
  for any scheme, and so are credential query parameters (`token`, `api_key`, `password`, `secret`, ...).
- **Uvicorn's loggers go through the redacting handler (#2).** Uvicorn installs its own non-propagating
  handlers, so its "Exception in ASGI application" traceback bypassed redaction.
- **SQLite stores are owner-only (#5).** A new database is created `0600` before SQLite opens it (so
  `-wal`/`-shm` are `0600` too), in a `0700` directory when the host creates it. An existing database,
  `-wal`, or `-shm` file with any group or other permission bit is refused at start, with the exact
  `chmod 600 <path>` fix. POSIX only; Windows ACL guidance is in OPERATIONS.md.
- **The audit floor is rewritten `0600` on every write**, even if a restore widened its mode.
- **Auditor round 2.**
  - `portmark serve` leaked through Uvicorn: `uvicorn.run()` re-applied Uvicorn's default logging
    after `configure_logging()`. It now passes `log_config=None`; an integration test drives the real
    CLI startup order.
  - The store directory is refused if group/other-writable (`chmod 700 <dir>`) or owned by another
    user (checked before anything is created in it). Store files are checked with `lstat`: symlinks,
    non-regular files, and files owned by another user are refused.
  - More credential forms are redacted: any-scheme `Authorization` / `Proxy-Authorization`, `Cookie` /
    `Set-Cookie`, `X-API-Key` / `API-Key` / `X-Auth-Token`, and `api_key=` / `access_key=` values.
- **Auditor round 3.** Every directory from `/` down to the store directory is checked with `lstat`:
  owned by the host user or root, and not group/other-writable unless sticky (like `/tmp`); the store
  directory itself gets no sticky exception. A `0700` store directory inside a writable, non-sticky
  parent could be renamed away and replaced between connections. The existing chain is checked before
  any missing directory is created (each created `0700`). **Reversed from round 2:** a symlinked store
  directory is now refused (use a bind mount); a symlink above it is walked to its target.
- **Operator action:** an existing store created under a `022` umask is refused until you run the printed
  `chmod 600` command (and the same for its `-wal`/`-shm` files, if present).

### Section 10 — audit chain (PR B): local audit floor behind a monotonic-witness contract (findings #1 High, #4 Medium)

- **Rollback is detected relative to a signed floor outside the database (High, #1).** A restored older,
  internally consistent SQLite snapshot verified as `valid`. Each host now keeps one signed audit floor
  (`--audit-floor-path` / `PORTMARK_AUDIT_FLOOR_PATH`, outside the store directory): format version,
  host ID, epoch, trust-registry version + digest, and the highest sequence + head per task, signed by
  the host's audit key (`audit` purpose; a revoked key is refused). Writes: cross-process sidecar lock
  -> read -> verify -> merge -> sign -> temp file -> fsync -> replace -> parent-directory fsync.
- **Compare-before-use, advance-before-commit.** At start the host compares every witnessed task with
  the database; inside every save transaction, before signing, it compares the task's chain. Behind =
  `rolled-back`, different content = `forked`: refused, nothing committed. The floor is advanced as
  the LAST step inside the transaction, BEFORE the commit (auditor round 2, High: advancing after the
  commit let "commit N+1, crash, restore N" boot as anchored). A floor write failure rolls the
  transaction back. A commit failure after the floor write leaves the floor ahead: refused until
  `floor-reset`, never lowered automatically, logged CRITICAL.
- **Adoption at start is verified (auditor rounds 2 and 3, Medium).** Heads new to or ahead of the floor
  are adopted only if their whole chain verifies STRICTLY and the head is unchanged right before the
  write. Any failing candidate FAILS STARTUP (`unverified-head`) -- round 2 logged and continued, and a
  later save could then write the invalid head into the floor. On every save, a task the floor has never
  witnessed must also verify strictly before the floor records it. Adoption no longer applies the
  legacy-anchor override; `floor-reset --allow-legacy-anchor` is the explicit path.
- **`advance_registry` enforces its own contract (auditor round 2, Low):** one version, two digests is
  refused (`registry-forked`) by the mutator itself.
- **The floor cannot be switched off silently:** a database that has a floor for a host refuses to
  start that host without `--audit-floor-path`.
- **Refusal, not reconstruction.** A database marker (`audit_floor_markers`, SQLite schema 12 /
  PostgreSQL 10) records that a floor exists and its epoch. A missing floor the database recorded is
  refused (`floor-missing`), never rebuilt; a database older than the floor (`db-older-than-floor`)
  or from another epoch (`epoch-mismatch`) is refused. A pending marker state makes creation and reset
  crash-safe.
- **Trust-registry rollback floor (Medium, #4; closes deferred #13).** Registries carry a monotonic
  top-level `version` (keygen writes 1, `keygen --force` raises it). The floor records version + digest
  and refuses a lower version (an old copy that still trusts a revoked key) or one version with two
  digests. A floor requires a versioned registry.
- **Operator recovery:** `portmark floor-reset --reason TEXT --confirm` re-verifies every chain this
  host signed (never launders a tampered one), writes the next epoch at the current heads, and records
  time, reason, prior epoch, and the prior floor's SHA-256. Never automatic.
- **`verify-audit --audit-floor-path`** adds `floor_status`: `anchored` (0), `not-anchored` (2), or a
  refusal code (1). Without a floor: `no-floor` (rollback not detectable); a durable store without a
  floor logs a warning at start.
- **Exact guarantee, documented in OPERATIONS.md and THREAT_MODEL.md:** rollback or divergence relative
  to the surviving authoritative floor file. NOT detected: whole-machine rollback of database + floor;
  copying database + floor together (or clones with independent floor copies); forks across hosts;
  a compromised host's signing; backdating before compromise. The remote transparency witness stays
  deferred; it would plug in behind the same `MonotonicWitness` contract.
- Backup guidance changed: do NOT back up or restore the floor with the database set.

### Section 10 — audit chain (PR A): one-snapshot verification, migration proof kept, storage doc (findings #2 local half, #3, #5)

- **Verification reads one snapshot (Medium, #3).** `verify_audit_chain_status` read the events and the
  head in two separate queries. A writer committing between them made a healthy chain report
  `stored audit head does not match audit events` (a false tamper alarm under load). Both reads now run
  in one read transaction: SQLite `BEGIN DEFERRED` (WAL, writers not blocked); PostgreSQL
  `REPEATABLE READ, READ ONLY`. New test commits a real writer between the two reads on both backends.
- **The destination keeps the source's migration proof (High, #2 local half).** The migration anchor in
  event 0 now also stores the original task ID, the source key ID, and the source signature, not only
  the head hash, sequence, and host. `verify-audit` re-verifies that source signature against the
  trust registry (for the `migration` purpose), so an auditor with only the destination database can
  re-validate the handoff. New `anchor_status` in the result and CLI output: `none`, `verified`,
  `legacy-anchor`, or `invalid`. No hash-format change.
- **Secure default for old anchors (auditor round 2, Low/Policy).** A pre-Section-10 3-field anchor
  has no source proof, so it is now `status: unverifiable` (CLI exit 2), not `valid`.
  `verify-audit --allow-legacy-anchor` is a TEMPORARY compatibility override: a complete legacy anchor
  becomes `valid` (exit 0) but keeps `anchor_status: legacy-anchor`, its `reason` says the source proof
  was not reverified, and a warning goes to stderr (stdout stays valid JSON). It is never relabelled
  `verified`, and it never rescues a partial or malformed anchor: an anchor must have exactly the legacy
  key set or exactly the full key set, with well-formed values, or it is `invalid` (exit 1).
  `evaluate_audit_head` gains `required_usage` (default `audit`). A source key revoked after the handoff
  makes the anchor `invalid`: the v1 handoff head has no signing time to prove it came first.
- **RUNTIME_STORAGE.md was stale (Low, #5).** It said SQLite schema v3; the code is at SQLite 11 and
  PostgreSQL 9. It now lists every migration step and every current table, and says plainly that
  verification does not detect a rollback to an older consistent database (that is PR B).
- Not in this PR: rollback/fork detection and the trust-registry floor (Section 10 PR B, local audit
  floor behind a general monotonic-witness contract).

### Section 9 follow-up: malformed-component fuzz campaign

- **New `tests/fuzz_wasmtime_components.py`**, deterministic (seeded), in two parts:
  - an **in-process part**, thousands of cases per second, through the exact function the worker
    runs (`_execute`, which the worker's `main()` now calls);
  - an **end-to-end part**, through `NativeWasmtimeComponentProvider` and the real worker.
  - Inputs: the real capsule and 11 structured hostile seeds (import, re-exported import, too many
    memories, wrong `resume` signature, endless start, trapping start, huge memory, huge table, core
    module, no `resume`, non-JSON outcome), damaged by 10 mutators (bit flips, boundary bytes,
    truncation, insert, delete, duplicate, LEB128 length bombs, splice, swap, header damage).
  - Rules checked: only controlled error types; no worker crash signal; no traceback or native
    panic text reaching the host; inside the deadline; no stdout on failure; no leftover worker;
    decisions only for offered tools.
  - A **coverage check** fails a corpus that mostly dies at the header, and every case is reported
    by the stage where it stopped.
  - It runs in the `native-wasmtime` CI job on all four platforms (3000 + 30 cases).
  - Review round 2: the worker exit-code rule is now **platform-neutral**. Only 0 (decision) and 1
    (controlled rejection) are legitimate, unless the parent killed the worker for its deadline or
    an overflow. A positive Windows NTSTATUS crash (0xC0000005, 0xC0000409) is no longer scored as
    a clean rejection.
  - The in-process child runs under the same **512 MiB OS cap** as the worker: `RLIMIT_AS` on
    POSIX, and a Job Object launched by the parent on Windows. The cap is printed with every run,
    and `UNCAPPED` is printed where none is enforceable (macOS). A **per-case watchdog** (20 s)
    records a hang as a finding naming its case, kills the child, and resumes, so one input can no
    longer stall a CI lane.
  - The coverage check now requires every claimed stage: ran, decode, limits, link, run, export,
    call, outcome.
- **Finding, fixed: the native provider accepted WebAssembly TEXT.** `wasmtime.component.Component`
  also parses the `.wat` text format, so the capsule's source compiled and ran as a provider. The
  worker now refuses anything that is not a **binary Component Model artifact** (Wasm magic +
  component layer) before any Wasmtime parser runs. This is not an integrity bypass (the signed
  digest still pins the exact bytes), but it removed an unneeded untrusted-input parser. Core
  modules are now refused at the same check, earlier than before.
- Campaign result after the fix: 3 seeds × 20,000 in-process cases + 140 end-to-end cases, **0
  findings**, with cases reaching every stage (decode, limits, link, guest run, export, call, outcome,
  successful run).
- Test support: the fake-wasmtime tests now prefix their made-up component bytes with a real binary
  component header, so each one still reaches the check it names (one of them would otherwise have
  passed for the wrong reason).

### CI: fix the recurring Node-deadline flake in postgres-store

- `test_real_wasm_capsule_completes_inside_deadline_limited_sandbox` (and on one run
  `test_wasm_component_malformed_missing_timeout_and_oversized_outputs_are_rejected`) failed
  intermittently, only in `postgres-store`, always as the first Node start of the run (exactly
  2.00 s, the production deadline), while later Node tests in the same run took about 0.03 s.
  `postgres-store` was the only job without `setup-node`: it ran the Node tests on the runner
  image's own Node, with the first start paying a one-time start-up cost inside a test deadline.
- The job now installs the same pinned Node 24 as every other job, and `RuntimeTests` starts
  `node --version` once in `setUpClass`, so no test pays process start-up inside its deadline.
  **No deadline, timeout, or assertion changed**, and the production 2.0 s Node deadline is
  untouched.
- The earlier hypothesis that Section 8 PR 4's bounded-drain threads caused it was ruled out by
  measurement: under load, decisions take 126 ms (before PR 4) vs 129 ms (after).

### Section 9 — native Wasmtime sandbox (PR 3): cross-platform proof (finding #4, CI)

- **The real Wasmtime engine now runs in CI on Linux x86-64, Linux ARM64, Windows, and macOS**
  (new `native-wasmtime` job, at the `wasmtime==48.0.0` release pin). Before, only Linux x86-64
  ran it, and the Windows jobs did not install the extra. The old single-lane step is moved into
  this job, not duplicated.
- **Every lane asserts the same hand-derived results**, so the lanes agree with each other:
  - the real capsule's decision vector at checkpoint lengths 0/119/120/4096, derived from the
    `i32.lt_u 120` branch in `capsules/research-agent.component.wat`;
  - canonical NaN `0x7fc00000`;
  - deterministic relaxed SIMD from the spec (`relaxed_swizzle` out-of-range lane is 0, and
    `relaxed_trunc` of NaN is 0). On x86-64 the native results are 2 and `0x80000000`.
- **Each lane proves its platform's worker-cap outcome** and logs it: capped and running, or
  blocked by default (the provider refuses; the explicit opt-out still runs the real capsule).
  macOS is decided by the runtime self-check, not assumed. Tests that need a running capped
  worker skip with a named reason where the engine is blocked by design.
- **Wasmtime upgrade canary** (`.github/workflows/wasmtime-canary.yml`): weekly and on demand, the
  same suite runs against the latest Wasmtime on x86-64 and ARM64. It is separate from CI and does
  not block merges. A red canary means "decide before bumping the pin". A new proposal setter
  surfaces there through the setter-completeness test.

### Section 9 — native Wasmtime sandbox (PR 2): real aggregate ceiling, bounded compilation, deterministic engine (findings #1, #3, #4)

- **The native Wasmtime memory limit is no longer only per memory (finding #1, High).** Wasmtime
  applies `memory_size` to each linear memory separately; a small component declaring many memories
  multiplied it (the audit instantiated 301 memories under a 64 KiB setting). The store now also
  caps instances (8), memories (2), tables (4), and table elements (10,000). The per-memory default
  drops from 256 MiB to **64 MiB**.
- **The whole worker process now runs under an OS memory ceiling (#1, #3).** 512 MiB by default:
  `RLIMIT_AS` on POSIX, applied inside the worker after its trusted imports and before the Engine
  is built, so JIT compilation, which fuel does not meter, is capped too. On Windows the worker is
  launched inside a Job Object (the isolated-tool executor's race-free suspended-assign-resume
  launch) with a new per-process memory limit. `RLIMIT_CPU` also bounds compilation CPU on POSIX.
  Wasmtime's reservations are sized to the guest limit so that the cap is usable at all: with
  default reservations, the worker fails under a 1 GiB address-space cap.
- **The limits must agree, or the provider refuses to start:**
  `max_memories × max_memory_bytes + 256 MiB worker baseline ≤ worker_memory_limit`.
- **Fail closed where no OS ceiling can be enforced.** The provider proves enforcement at start-up
  (POSIX: a child caps itself and must fail to allocate past the cap; Windows: Job Objects
  available). Without it, construction fails unless the operator passes
  `allow_uncapped_worker=True`; every uncapped run is then logged as a warning.
- **Bounded concurrent compilation (#3).** Single-threaded compilation (`parallel_compilation`
  off), and at most two native workers at once. Waiting for a worker slot spends the decision's
  own deadline, so a saturated host fails closed ("worker capacity exhausted") and never queues
  past the timeout.
- **Deterministic, explicit engine configuration (#4).** Deterministic relaxed SIMD and NaN
  canonicalization, so results match across x86-64 and AArch64. Every Wasm proposal is set
  explicitly instead of inheriting Wasmtime's changing defaults: threads, shared memory, memory64,
  multi-memory, GC (proposal and runtime), exceptions, tail calls, typed function references, stack
  switching, wide arithmetic, custom page sizes, and component-model map types are off. A test
  enumerates every proposal setter wasmtime-py exposes and fails if one is left unassigned, so a
  proposal added by a Wasmtime upgrade cannot silently inherit a default (review round 2: tail
  calls and typed function references were still default-on).
  (Cross-architecture and Windows CI lanes follow in the next Section 9 PR.)
- Docs: README, WASM_COMPONENTS.md, OPERATIONS.md, and THREAT_MODEL.md now describe per-memory versus
  aggregate limits accurately. The README previously said native Wasmtime "bounds guest memory".
- Tests: the auditor's 301-memory component plus instance, memory, table, and table-element
  overflows refused by their own limits; two full-size memories still admitted; limit-invariant
  refusal; OS caps sent to and enforced inside the worker (a 32 MiB cap fails, 512 MiB succeeds);
  the self-check can report "not enforced"; uncapped-platform block and opt-out; worker-slot
  deadline; canonical NaN `0x7fc00000` (hand-derived from the Wasm spec); five default-enabled
  proposals refused, against a default-config control; Windows Job Object memory limit (Windows
  CI). Each defense was confirmed to make its test fail when neutralized.

### Section 9 — native Wasmtime sandbox (PR 1): executed bytes always match the signed digest (finding #2)

- **Wasm providers now freeze the component bytes before anything else.** Both
  `NativeWasmtimeComponentProvider` and the Node `WasmDecisionProvider` computed `component_digest`
  once at construction but kept the caller's object and re-read it on every `decide`. A mutable
  `bytearray` (or a `memoryview` over one) changed after construction therefore executed different
  code while the provider still presented the original digest — and passed the host's
  signed-manifest digest check. The providers now take a private immutable copy first, then
  size-check, hash, and execute that one copy (the auditor reported the native provider; the Node
  provider had the same bug and is fixed in the same change).
- **Only real byte buffers are accepted.** The copy uses `memoryview`, not plain `bytes(value)`:
  `bytes(5)` silently yields five zero bytes and `bytes([1, 2])` accepts a list of ints. The buffer
  must also be one-dimensional with one-byte items, so an `array('i', ...)` is not reinterpreted as
  its raw memory. The input-size cap is checked on the view **before** the copy (review round 2), so
  an oversized buffer no longer forces a second full-size allocation before it is rejected; the view
  is held across check and copy, which locks a `bytearray` against resizing in between. A released
  `memoryview` gets the same controlled error instead of an incidental `ValueError`. A non-bytes
  component (int, bool, str, list, int array, released view) is now refused with `RuntimeError("Wasm component must be
  bytes-like")` instead of an incidental `TypeError`. `from_file` paths were never affected
  (`_read_component_file` returns immutable `bytes`).
- Tests: mutate-after-construction for both providers with `bytearray` and `memoryview` (the bytes
  sent to the worker must hash to the published digest), non-bytes rejection, and a real-Wasmtime
  end-to-end run through `host.run` that must execute the original signed component after the
  caller's buffer is overwritten. Each was confirmed to fail with the freeze neutralized.

### Section 8 — provider boundary (PR 4): bounded Wasm subprocess output (finding #5)

- **Wasm provider output is now bounded DURING the read, not after buffering.** Both the Node
  (`WasmDecisionProvider`) and native Wasmtime (`NativeWasmtimeComponentProvider`) providers replaced
  `subprocess.run(capture_output=True)` — which reads the child's entire stdout/stderr into memory
  before any size check — with a stdlib `_run_bounded` helper that drains stdout on a reader thread
  under a hard byte cap and **kills the child the instant it overflows**. A hostile capsule can no
  longer exhaust host memory before the post-hoc cap runs. Specifics:
  - **stderr is bounded independently** (retained up to 4 KiB but kept draining past it, so the pipe
    never blocks the child) — a multi-megabyte stderr can no longer flow unbounded into the
    "Wasm capsule rejected: …" error string;
  - **stdin is written on a supervised writer thread** (reader threads start before it), so a large
    stdin payload (base64 component + context, well past the OS pipe buffer) cannot deadlock against
    the child's stdout write, and — the round-2 audit fix — a child that never reads stdin (a wedged
    or failed-to-start runner) can no longer hold the caller past the deadline: `process.wait`
    supervises the one absolute deadline even while the write blocks, and the deadline kill closes the
    child's stdin read end so the writer unblocks with `BrokenPipeError`;
  - **one monotonic deadline** bounds the whole call; every wait derives its remaining budget from it,
    so no phase can re-spend the full timeout;
  - **overflow/deadline outcomes take precedence over the non-zero-exit branch** — an overflow kill
    leaves `returncode == -SIGKILL`, so the output-limit / deadline errors are reported instead of a
    misleading "rejected" message. Existing error strings and the accept-at-exactly-the-limit boundary
    are preserved.
  - Tree-kill is deliberately not used here: the Wasm guest receives no imports (it cannot spawn) and
    the node/runner executable paths are host-controlled — marked with a `debt:` upgrade trigger for if
    the runner ever gains spawn capability. Evidence: `src/portmark/providers.py` (`_run_bounded`).

### Section 8 — provider boundary (PR 3): strict JSON at untrusted decode boundaries (finding #4)

- **Untrusted JSON is now parsed strictly** wherever it crosses a trust boundary: the HTTP provider
  response, the Wasm component decision (Python-side decode, including the nested `arguments_json` /
  `content_json` strings, and the native `wasmtime` runner's in-subprocess outcome decode), and the
  inbound A2A request body. A new stdlib-only `portmark.json_guard.strict_json_loads` helper:
  - **rejects duplicate object keys** — stdlib `json` silently keeps the last value, an ambiguity that
    lets a second copy of a key slip past a validator that inspected the first;
  - **bounds nesting depth** (cap 64) with a string-aware pre-scan *before* parsing — an admitted,
    over-deep document would otherwise drive the host's own recursive processing (e.g. the projection
    deep-copy, canonical hashing) into `RecursionError`, and a pure-Python `json` build recurses in the
    parser itself; the guard makes over-deep input a clean rejection instead;
  - **rejects non-finite numbers** — `NaN` / `Infinity` / `-Infinity` (via `parse_constant`) and the
    overflow form `1e999`→`inf` (via `parse_float`); non-finite floats have no safe meaning across the
    boundary (comparisons, constraints, and hashing disagree on them);
  - **enforces an optional byte cap** and turns invalid UTF-8 / malformed / over-limit input — and an
    integer past Python's int-string digit limit (~4300 digits), which is a bare `ValueError`, not a
    `JSONDecodeError` — into a single `StrictJSONError` that each caller maps to its own error (HTTP →
    `SecurityError`, Wasm → `RuntimeError`, A2A → JSON-RPC `-32700` parse error).
- **Strict per-kind decision schemas.** `_provider_decision` and the Wasm `decode_component_decision`
  now reject fields that do not belong to the decision's kind (and the nested Wasm `request` object),
  so a `complete` cannot also carry a `tool`/`destination`/unknown key and a validator keying off `kind`
  stays unambiguous. Allowed shapes: tool = `{kind, tool, optional arguments}`; migrate = `{kind,
  destination, optional content}`; terminal (`complete`/`await_input`/`fail`) = `{kind, optional content}`;
  Wasm tool request = `{name, arguments_json}`. Wasm migrate `content_json` is accepted by the schema
  but not currently propagated (pre-existing, unchanged here). Well-formed decisions are unaffected.
- Out of scope, stated explicitly: `tools.py` subprocess output is **operator-trusted host code**, not an
  untrusted provider/adapter boundary, so it is not covered by finding #4.

### Section 8 — provider boundary (PR 2): canonical detached ProviderView

- **BREAKING API — providers now receive a `ProviderView`, not `AgentState`.** `ModelProvider.decide`
  changed from `decide(self, state: AgentState, available_tools, grants=())` to
  `decide(self, view: ProviderView, available_tools)`. `ProviderView` is a frozen dataclass carrying only
  `task_id, goal, step, tool_calls, status, migrated, messages, tool_results` — third-party in-process
  providers must update their signature and read `view.tool_results` / `view.goal` instead of
  `state.memory[...]`.
- **BREAKING API — `grants` is no longer passed to `decide`.** The host applies every grant's projection
  when it builds the view; a provider never receives grants, so it cannot widen its own projection.
  `provider_state(view)` and `component_context(view, available_tools)` / `component_checkpoint(view)`
  changed signatures accordingly, and `projection.project_state_for_provider` was **removed**.
- **Fixes finding #2 (High): the in-process provider was over-exposed AND could mutate live host state.**
  The old path handed the in-process provider a whole mutable `AgentState` (via a shallow-copying
  `project_state_for_provider`), so it saw host bookkeeping in `memory` — `approvals`,
  `used_approval_ids`, `migration` — that the remote adapters never got, and could corrupt the host's
  live state through aliased nested containers (e.g. `state.memory["used_approval_ids"].clear()`,
  defeating replay prevention). The canonical view **drops `memory` entirely** (closing the
  over-exposure) and is **deeply detached** into plain, json-safe copies (closing the mutation — no
  object reachable from the view aliases live state, even under a `*` output projection). Top-level
  containers are read-only (a `tuple` of messages, a `MappingProxyType` of tool_results) and the
  dataclass is frozen. `checkpoint_generation` (store-owned) and `result` (host-owned) are dropped too.
- **`migrated` replaces raw `memory["migration"]` inspection.** A provider that needs to know it resumed
  after a migration reads the single derived boolean `view.migrated` (present iff the host set
  `memory["migration"]`), instead of the old leak of the whole `memory` dict.
- No behavior change to what a well-behaved provider decides: tool-output projection and the
  share-nothing "present-but-empty" re-proposal semantic are preserved.
- **Cross-adapter consistency (audit follow-up, Medium).** `provider_state` — the json wire payload for
  the HTTP/Wasm adapters — now serializes EVERY `ProviderView` field, including `migrated` and
  `tool_results` (which earlier drafts dropped). Previously the in-process provider read `migrated` /
  `tool_results` while the wire omitted them and re-derived tool output from `messages`, so a crafted
  state whose `memory` and `messages` disagreed could make adapters decide differently (re-migration /
  tool re-proposal). Every adapter now receives a faithful serialization of the same view. `WIT_ABI` is
  unchanged (`portmark-json-lowered-v1`); the two fields are additive to the component input.
- **Malformed message list can no longer strand a checkpoint (audit follow-up, Medium).** A validly
  signed envelope whose `state.messages` contains a non-dict entry (e.g. `[42]`) used to be admitted and
  then crash view construction with `AttributeError`, leaving the checkpoint `running` (view construction
  was outside the provider-failure boundary). The host now rejects a non-dict-shaped messages list at
  admission with `SecurityError` — before the first persist, so nothing is stored — and, defense in depth,
  builds the view inside the terminalization boundary so any view-construction error closes the task to a
  durable `failed` checkpoint instead of stranding it.

### Section 8 — provider boundary (PR 1): HTTP transport safety (SSRF / redirects / DNS-rebinding / total deadline)

- **`GenericHttpProvider` no longer follows redirects and validates the endpoint address.** The provider
  was rewritten onto `http.client` so the transport is under Portmark's control. A 3xx response is now a
  controlled failure (not followed) — following it was an SSRF vector and would have forwarded the bearer
  token to another origin. The endpoint is resolved and every A/AAAA answer is rejected if it is loopback,
  private, link-local, multicast, reserved, or unspecified (a mixed public+internal answer fails closed),
  unless the new `allow_local_endpoint=True` is set for a loopback provider. IPv4-mapped IPv6
  (`::ffff:127.0.0.1`) is normalized before classification. URL credentials, fragments, and malformed
  hosts are rejected at construction; non-loopback endpoints must use https.
- **DNS-rebinding defense.** The connection is made to the pre-validated IP literal (no re-resolution at
  connect time), and the connected peer is verified to match before the request body is sent. TLS
  certificate validation stays bound to the hostname (`server_hostname`) even though the socket connects
  to the IP.
- **Total end-to-end deadline.** `timeout` is now a monotonic deadline across connect, headers, and body,
  re-armed before every read (via `read1`) — a slow-drip response that trickles within the socket idle
  timeout can no longer hold the worker indefinitely. The response body is bounded during the read, and a
  premature EOF / reset / malformed framing is raised as a controlled `ProviderError`.
- **BEHAVIOR CHANGE — a provider failure now closes the task.** A provider failure after admission
  (transport error, deadline, or malformed response) persists a **durable terminal `failed` checkpoint**
  and a `provider.failed` audit event, then re-raises — an admitted task is never left represented only as
  `running`. The task is closed; **a retry is a fresh call**, not a resume of the same task id. Previously
  such a failure propagated out of `run()` leaving the checkpoint resumable as `running`.
- **The whole transaction is behind one external deadline.** The entire synchronous request — DNS, TCP,
  TLS handshake, request send, response status line + headers, and body — runs in a pool-capped worker
  thread joined on the deadline, so the caller returns at the timeout regardless of what the transaction
  is blocked on. A socket idle timeout resets on every dribbled byte, so it cannot bound `getresponse()`
  or the TLS handshake (which read many times while parsing) — a slow-dripped status line or header block
  would otherwise hold the worker far past the advertised timeout. The socket timeout is still re-armed to
  the remaining budget before each phase/read as a secondary bound (it also unblocks an abandoned thread
  faster). An IPv6 endpoint's `Host` header is correctly bracketed (`[::1]:8080`).
- **Local-gateway escape hatch is reachable again.** A loopback `http://127.0.0.1:...` provider endpoint
  now requires the explicit opt-in `--allow-local-provider-endpoint` (or
  `PORTMARK_ALLOW_LOCAL_PROVIDER_ENDPOINT=true`), wired through `make_host`. It permits **loopback only** —
  private/link-local/etc. addresses are still rejected.

### Section 7 — tool execution isolation (PR 3): capability-based safe paths + tested container profile

### Section 7 — tool execution isolation (PR 3): capability-based safe paths + tested container profile

- **Capability-based safe-path helper (`portmark.safe_paths.SafeRoot`).** An isolated tool that must
  touch the filesystem now does so only through a runtime-provided capability. Configure a workspace
  with `ToolRegistry(filesystem_root="/work")`; the runtime pre-opens that directory and hands the
  worker its open descriptor (via `pass_fds` + `PORTMARK_ROOT_FD`), and the tool calls
  `SafeRoot.from_runtime()` — it never names the root, so it cannot widen its own filesystem authority.
  `root.open_beneath("rel/path", mode)` resolves through `openat2(2)` with
  `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, so a `..`, absolute, or symlink escape
  is refused by the kernel **race-free** (`SafePathEscape`). A `resolve()`-then-prefix-compare is
  forbidden (TOCTOU-vulnerable); the strictly-weaker component-wise `O_NOFOLLOW` walk is **not** shipped
  as a fallback.
- **Fails closed where `openat2` is unavailable.** `openat2(RESOLVE_BENEATH)` needs Linux ≥ 5.6 and a
  seccomp policy that permits it. Where it is absent (old kernel, non-Linux, or blocked by seccomp),
  `SafeRoot.from_runtime()` **refuses** rather than degrade to a race-vulnerable path check. Usability is
  decided by *attempting the syscall and reading errno*, never a version string. The descriptor is
  close-on-exec, so a process the tool spawns does not inherit filesystem authority. With no
  `filesystem_root` configured, `from_runtime()` refuses — the default is no ambient filesystem authority.
- **Executable, tested deployment container profile (`deploy/`).** The hardened profile ships as
  `deploy/README.md` (the exact `docker run` flags), `deploy/docker-compose.hardened.yml`, and
  `deploy/verify_profile.py` — an in-container probe that checks each property (read-only rootfs, private
  writable dir, non-root, `no-new-privileges`, dropped capabilities, PID limit, default-deny egress) by
  attempting the operation it governs. A CI test runs the probe inside the built image with the full
  flags (every property must hold) and again with each flag removed (that property must flip), and proves
  `openat2` is **not** blocked by the image's seccomp profile. This `deploy/` profile is the concrete
  meaning of the `IsolationMechanism.EXTERNAL_CONTAINER` an operator acknowledges (PR 2b).
- **Descriptor lifecycle is safe against reuse.** `SafeRoot.from_runtime()` **consumes**
  `PORTMARK_ROOT_FD` (pops it), so it is one-shot: a second call cannot read a descriptor number the
  first already closed and the kernel has reused for another directory. `SafeRoot.close()` invalidates
  the descriptor, so a closed capability refuses `open_beneath()` rather than operate on a reused
  descriptor number. The configured `filesystem_root`'s identity `(st_dev, st_ino)` is pinned at
  construction and re-verified on the exact descriptor each launch hands the worker, so a path swapped
  or redirected after startup is refused instead of silently redirecting the tool.
- The tested container profile also verifies the advertised `--memory` and `--cpus` limits (cgroup
  `memory.max` / `cpu.max`), each calibrated by flag removal — so "every property is tested" holds.
- Claim boundary (unchanged stance): `SafeRoot` removes the *accidental* filesystem escape; it does not
  stop a tool from calling `open("/etc/passwd")` directly. The deployment's mount namespace / read-only
  rootfs is what makes the SafeRoot the only reachable path.

### Section 7 — tool execution isolation (PR 2b): mandatory side-effecting startup gate

- **BREAKING API change.** Registering a side-effecting tool now REQUIRES two things it did not before,
  both enforced when `register_isolated(side_effecting=True)` is called (fail closed at startup, not at
  the first effect):
  1. a **`reconcile=<module:function>` target** (optional in 2a, now mandatory) — 2a's whole
     failure→`unknown`→reconcile machinery is dead unless every side-effecting tool declares one, so an
     effect that fails to a known-unknown state can be resolved instead of silently retried or dropped;
  2. an **operator-acknowledged `IsolationProfile`** passed once as
     `ToolRegistry(isolation_profile=IsolationProfile(mechanism=..., acknowledged_by=...))`. The runtime
     cannot contain a hostile tool by itself (on POSIX the deadline sweep is only a cooperative
     process-group signal a `setsid()` descendant escapes), so the operator must affirm HOW workers are
     contained. There is **no default** that satisfies the gate. Existing callers that register a
     side-effecting tool must add both; non-side-effecting isolated tools are unaffected.
- **The profile's mechanism is cross-checked against the platform.** `IsolationMechanism.EXTERNAL_CONTAINER`
  (the operator runs workers inside a container/VM/sandbox) is valid everywhere; `IsolationMechanism.OS_JOB_OBJECT`
  (the platform's kill-on-close job) is genuine ONLY where the Windows Job Object exists and is **refused
  on POSIX**, where the operator must affirm external containment instead.
- **The thread path refuses side-effecting tools at registration.** `register(side_effecting=True)` now
  raises immediately (previously it was refused only at the first invoke) — that path cannot cancel a
  running tool or carry an effect ledger, and letting a name into the side-effecting set with no
  contract was a gate bypass. A re-registration can no longer strip the reconcile target while keeping a
  tool side-effecting: side-effecting membership is reconciled on **every** registration path.
- **The gate is re-asserted at the launch boundary, not only at startup.** `invoke()` re-checks the
  reconcile target and a platform-valid profile at the moment it would consume a launch capability, so a
  mutated-set edge case fails closed before any external effect fires (a startup-only check over a
  mutable set is advisory, not a gate).
- **The acknowledged containment is recorded in the audit trail.** When a side-effecting effect settles
  `unknown` — on a deadline kill (`tool.killed`), a clean tool error (`tool.failed`), or a
  non-serializable result (`content.rejected`) — the audit event carries the profile's `mechanism` +
  `acknowledged_by`, so an incident responder resolving the unknown effect sees what containment was
  claimed at registration — the profile is a real downstream consumer, not a gate input nothing reads.
- **Reconcile execution is now private host authority (round 2 — closes a High-severity public-API bypass).**
  The public `ToolRegistry.reconcile()` method is **removed**. It ran a reconcile *target* with
  caller-chosen tool, arguments and effect_id and no gate — so registering the effectful tool as its own
  reconcile target let any registry holder execute the effect with a fabricated effect_id, no ledger row,
  no claim and no launch capability. Reconcile execution now lives behind the same private handle as the
  launch armer (`run_reconcile`), runs a target only for an effect the host has already **claimed** under
  its owned lease, and only when the row's recorded tool and arguments match. The reconcile target must be
  **distinct** from the tool (the self-target exploit is refused at registration), and it must be
  observational/read-only — a contract the runtime documents but cannot verify.
- **Registration executes NO reconcile-target code (round 3 — fixes an unintended consequence of round 2).**
  Round 2 preflighted the reconcile target by importing it in a worker at registration, but importing
  arbitrary module code runs untrusted top-level code before any ledger/permit/claim exists (a
  filesystem/network effect that resource caps and process-tree kill do not prevent). That automatic
  import is **removed**. Registration keeps only the `module:function` **syntax** check and the
  tool-≠-reconcile **distinctness** check (both pure, no import). The reconcile is a **declared** target;
  its semantic/read-only correctness is the operator's own integration test, run in a credential-free,
  egress-denied environment — not a runtime import.
- **Reconcile renews its owned claim immediately before running (round 3).** `run_reconcile` validated
  ownership but not lease liveness, so a holder paused past its 5-minute lease could execute concurrently
  with a reclaimer. The host now calls a new `renew_effect_claim(effect_id, claim_id, lease_seconds)`
  (all three backends; database time on Postgres) right before running the reconcile and proceeds only if
  it succeeds — whichever of renew and a reclaim reaches the row first wins atomically, so no two
  reconcile functions run concurrently. A reconcile that itself outruns the renewed lease remains a
  documented liveness bound, not a double-execution hole.
- **`effect_status:"unknown"` is recorded on all three effect-unknown audit events (round 2).** Previously
  only `tool.killed` carried it; `tool.failed` and `content.rejected` now do too when a side-effecting
  effect settled unknown, so incident analysis is self-contained.
- **Scope (unchanged from 2a).** This closes the public-API path into a side-effecting launch OR reconcile
  without the contract; it is **not** protection against arbitrary malicious in-process Python. The
  `IsolationProfile` records a CLAIM about the deployment; it cannot verify the container is actually
  running. Containment of a hostile tool remains the deployment substrate's job (see THREAT_MODEL.md).

### Section 7 — tool execution isolation (PR 2a): idempotency/reconciliation effect ledger

- **Side-effecting isolated tools now run under a durable effect ledger** (new `tool_effects` table;
  SQLite schema v10, Postgres schema v8) so a crash-and-resume never re-applies an external effect it
  cannot be sure landed. The host derives an **effect id** — `hash(task_id, tool, canonical arguments,
  per-call sequence)` — records a `prepared` row before launch, advances it to `started` immediately
  before the tool runs, and settles it afterward: `confirmed` on success (the result is stored and a
  later identical call **replays** it instead of re-running), `unknown` on a deadline kill, a clean
  tool error, or a non-serializable result (the effect may have landed before the failure). On resume
  the host replays a `confirmed` effect, proceeds for a `prepared` one (never launched), and **refuses**
  a `started`/`unknown`/`reconciled` one — it **never auto-retries** an unknown effect.
- **The effect id identifies the logical call POSITION — `hash(task_id, per-call sequence)` — and
  nothing else.** The sequence is `state.tool_calls`, monotonic per task, never reset, and rebound from
  the durable checkpoint on resume, so the same position re-derives the same id and a distinct call
  cannot collide with it. It is bound to neither the checkpoint generation (which identifies the *run*,
  not the call) **nor the tool/arguments**: binding those would let a provider that re-proposes the
  same position with different arguments (or a different tool) mint a NEW id and run a **second** effect
  while the first at that position is unresolved. The invariant is **at most one effect per position**.
  Because the id excludes the tool and arguments, the host does **not** silently replay a drifted
  position: `_effect_pre_launch` compares the current decision's (tool, arguments) against the ledger
  row's recorded values and **refuses on any drift** — it never replays another call's result and never
  re-runs at a bound position. A deterministic resume re-proposes the same tool+args and replays
  cleanly; a drifted re-proposal hard-fails the task, and reconcile (or a fresh call) resolves it. The
  ledger row records the tool and arguments for exactly this drift check plus reconcile and audit.
- **Launch authority is a one-use capability, not knowledge of the effect_id.** An effect_id is
  deterministic (`hash(task_id, sequence)`) and not a secret, so knowing one must not authorize a
  launch. Right before the call the host **arms** a random, one-use capability bound to
  `(effect_id, tool, canonical arguments)` — arming first validates that a durable `started` ledger row
  matches, so a fabricated id cannot be armed — and `ToolRegistry.invoke` **consumes** it atomically,
  only on an exact `(tool, arguments)` match. A fabricated capability, a reused one, one armed for a
  different tool, or one armed with different arguments all fail closed. **Arming is not a public
  method:** `attach_effect_ledger` (called once, not re-attachable) returns a private armer handle only
  `AgentHost` holds, so no caller with a registry reference can mint a capability — and the handle
  refuses a *second* outstanding capability for one `started` effect, so one started effect authorizes
  at most one launch. This closes the public-API bypass and defends against a fabricated/guessed/replayed
  *value*; a caller that runs arbitrary in-process code against the registry object is outside this gate
  (the deployment sandbox's job) — it is not claimed as protection against arbitrary in-process Python.
  Supersedes the earlier public `arm_effect_launch` (repeatable minting) and the round-2 "is it started?"
  predicate (a holder of a `started` id could reuse it, transfer it to another tool, or replay it).
- **Side-effecting tools receive the effect id as an idempotency key.** The isolated worker calls a
  side-effecting tool as `tool(arguments, effect_id)` (the id travels in the request envelope, outside
  `arguments`, so the argument-name allowlist does not reject it); the tool must use it as its external
  idempotency key. A tool that does not accept the parameter is failed with a controlled
  `tool does not accept effect_id` and is never called (never called twice).
- **Reconciliation API.** `AgentHost.reconcile_effect(effect_id, task_id)` (task-scoped) resolves an
  `unknown` effect by running the tool's registered `reconcile` function
  (`reconcile(arguments, effect_id) -> {"landed": bool, "result"?: ...}`): a landed effect settles to
  `confirmed`, a not-landed effect to `reconciled`. The host never auto-retries; the operator drives it.
  Reconciliation is concurrency-safe, using the migration outbox's owned-lease shape: the effect is
  **claimed** atomically (`unknown → reconciling`) under a random **owner id**, and a terminal settle
  requires that owner id **and** a live lease — so two operators cannot clobber each other, and a
  stale/expired reconciler can neither overwrite a recorded `confirmed` nor reset a newer holder's claim
  (a reclaim mints a *different* owner id). The claim is **leased**: a `reconciling` row left by a crashed
  reconciler is reclaimable after the window, so a mid-reconcile crash never strands the effect; a
  failing reconcile releases the claim (owner-id match only, so an expired holder can always relinquish).
  Lease creation and expiry use **database time** on Postgres (and the store's injected clock on the
  embedded backends), so a fast host clock cannot steal a live claim. The store validates its own claim
  inputs (non-empty owner id, positive integer lease) rather than trusting the caller. New store columns
  `reconcile_claim_id` + `reconcile_lease_expires_at` (SQLite v11, Postgres v9). The tool registry is
  **immutable after host construction** — the private armer binds to the registry given at construction,
  so swapping `host.tools` afterward fails closed for side-effecting tools (configure it before, not after).
- Making the `reconcile` contract and an acknowledged isolation profile **mandatory** at registration
  for `side_effecting=True` is the immediately following change (Section 7 PR 2b).

### Section 7 — tool execution isolation (PR 1b)

- **The normal-exit background-child leak is closed at the source.** A tool that spawned a background
  child (not `setsid`) and then returned normally used to leave that child running: the worker exited
  cleanly, and the parent's process-group kill early-returns once the leader is reaped (signalling a
  reaped pid could hit an unrelated reused pid). The **trusted worker now `SIGKILL`s its own process
  group before it exits** (`tool_subprocess_runner._sweep_own_process_group`), after its reply is
  written and flushed to the host — so the child dies with it. This runs on every post-tool reply path
  (success, tool error, over-budget, the fail-closed rlimit refusal). A successful isolated tool now
  exits by `SIGKILL` **by design**; the host reads the JSON response from the pipe, never the exit
  status. The sweep is guarded to fire **only when the worker leads its own process group** (the
  `start_new_session` launch path), so a worker run inside another process's group never signals it.
- **The host verifies the self-sweep before accepting a reply.** On a self-sweep (POSIX) backend the
  host confirms the worker exited by `SIGKILL` before accepting its reply — success or tool error
  alike; if it exited any other way the sweep did not run, so the host **fails closed**
  (`worker did not self-terminate its process group … sweep unconfirmed`) rather than silently
  accepting a result whose descendant containment is unconfirmed. This is the normal-exit analogue of
  the timeout "process tree could not be confirmed terminated" check.
- Three residuals remain, documented (the escape residual is **tested**): a child that moves to its
  own process group — via `setsid()`/`start_new_session()` (new session) **or** `setpgid()`/`setpgrp()`
  (new group, same session) — escapes the sweep; a worker that dies before reaching the sweep cannot
  run it; and the sweep is only effective because the parent launches with `start_new_session` (a
  launch path that omits it gets no sweep — the guard makes that safe, not a foreign-group kill).
  POSIX only; on Windows the kill-on-close Job Object already contains the whole tree.

### Section 7 — tool execution isolation (PR 1 of 3)

- **Honest contract: the isolated executor is a resource-bounded, hard-deadline worker — NOT a
  hostile-code sandbox.** THREAT_MODEL.md and DEPLOYMENT.md now state that a tool runs as the same OS
  user with normal filesystem/network access, and that containing an untrusted or hostile tool is the
  **deployment's** job (separate uid, mounts, PID/cgroup isolation, restricted `/proc`, default-deny
  egress). TOOLS.md's "Isolated Tools" section was corrected: on POSIX the deadline termination is
  **cooperative/best-effort** (a `setsid()` descendant escapes the group signal; a background child can
  outlive a clean exit), genuine whole-tree termination is Windows (Job Object) only, and the
  termination is verified for the worker **root**, not asserted for the tree. `ToolKilledError` and
  `register_isolated` docstrings no longer claim POSIX whole-tree containment.
- **Resource caps and stdout redirect now apply BEFORE the untrusted tool is imported (High).** Python
  runs a module's top-level code at import, so a hostile tool's **module scope** — not just its
  function — is attacker-controlled. Previously the worker imported the tool first and applied the caps
  and stdout sink afterward, so module-scope code ran uncapped and could write straight into the
  response protocol. The worker now applies the caps and redirects stdout to a discard sink before
  importing the tool. A cap that fires during import (or any module-scope failure) is caught and
  reported as a controlled `tool import raised <Error>`, never a crashed, response-less worker.
  Consequence: `address_space` and `cpu_seconds` now also bound module import — a heavy tool module may
  need `address_space` raised.
- **`resource_limits` is validated and merged, not silently replaced (Medium).**
  `ToolRegistry(resource_limits=...)` now **fails startup** on an unknown key (catching a typo like
  `adress_space` that used to silently disable a cap) or a non-positive/non-int value, and **merges**
  overrides over the defaults so supplying one key no longer drops the others. `cpu_seconds` cannot be
  set by an operator (it is derived per invocation from each tool's timeout). To turn the caps off,
  pass the explicit `disable_resource_limits=True` — an empty `resource_limits={}` now means "defaults",
  not "disabled".
- **Bounded stdout, in-child `setrlimit`, explicit `close_fds`.** The worker discards Python-level
  stdout via an `os.devnull` sink (not an unbounded buffer); the POSIX resource caps are applied
  in-child (never via the parent's threaded `preexec_fn`); the launch sets `close_fds=True` explicitly.
- **Applying the resource caps is fail-closed, not best-effort.** Previously a requested cap that
  could not be put in force (an unsupported limit on the platform, or a rejected `setrlimit`) was
  silently skipped and the tool ran anyway — running under weaker caps than configured, with no
  signal. The worker now **refuses to run the tool** and reports which caps failed
  (`worker could not apply resource limits: <names>`), so a tool never runs believing it is capped
  when it is not. This is POSIX-scoped: on Windows the Job Object is the containment mechanism and
  the POSIX caps do not apply there (a documented platform limitation, not a fail-open). On Linux
  (the supported POSIX target) all of these limits apply.
- Still deferred to later PRs (documented, not silently done): the POSIX background-child /
  `setsid()`-escape termination gap (PR 1b), mandatory idempotency/reconciliation + the
  `side_effecting` startup gate (PR 2), and the capability-based path API plus an executable/tested
  container profile (PR 3).

### Section 5 — approvals

- **An approval is now bound to the checkpoint generation it was issued for (finding #1, High —
  BREAKING approval format).** Previously an approval minted for a task's suspended state at
  generation N could be redeemed after the task legitimately advanced to a later generation M, as
  long as the tool, arguments, permit nonce, and policy hash were unchanged — a stale authorization
  taking effect in a context it never approved. The signed `ApprovalToken` now carries a required
  `checkpoint_generation`, verified at the gate against the **durable store generation** captured at
  admission (never the caller-asserted envelope value, which the admission persist advances before the
  gate runs). The generation an approval must bind is the suspended checkpoint's generation, returned
  to the operator on the awaiting-input run's checkpoint. This is a breaking change to the signed
  approval format: any approval issued before the upgrade, or built without a generation, is refused.
- **A malformed approval in mutable memory is now a controlled denial, not an uncaught crash (finding
  #4, Low).** An approval token — and the `used_approval_ids` list — are read from untrusted wire
  memory. A missing/extra key, a wrong-typed field, or a non-list id set used to raise out of `run()`
  and strand the admitted task in a non-terminal state. The token is now validated against an exact
  schema with type checks, and any malformation becomes a bounded `approval.denied` with a fixed reason
  code (no attacker-chosen key names or exception text in the audit).
- **A task can now be durably cancelled, with best-effort-before-launch enforcement (finding #3,
  Medium).** `AgentHost.cancel_task(task_id)` records a durable cancellation (new `task_cancellations`
  table; SQLite schema v9, Postgres schema v7). Cancellation is enforced in **three tiers**:
  1. **Before an approval is redeemed** — refused **inside the same transaction that consumes the
     approval nonce**, so nothing is burned (fully enforced).
  2. **Racing the redemption transaction** — serialized (SQLite `BEGIN IMMEDIATE`; Postgres per-task
     advisory lock); if the cancel wins, the redemption rolls back (fully enforced).
  3. **After redemption** — a **best-effort** pre-launch re-check catches a cancel that has *already
     committed* before the check. A cancel that commits **after** that read — in the read→launch
     window, or once the tool is running — does **not** prevent the side effect: **the tool runs and
     its effect happens even though the task is now cancelled.** This is deliberately not atomic with
     the effect.

  So cancellation of an already-redeemed approval is **best-effort before launch, not a guarantee that
  the effect is prevented.** Guaranteeing "no effect after cancel" requires per-tool idempotency keys
  and a reconciliation pass, which is **Section 7 (tool boundary)** — not provided here. The supported
  entry point is the host method; a network-triggered cancel endpoint (with its own auth) is future
  work.
- **Approval expiry is a redemption deadline.** Expiry is checked when the approval is redeemed at the
  gate; the tool then runs. Portmark does not cap the tool's execution to the remaining approval
  lifetime — even doing so could not roll back an external effect already committed after expiry. Keep
  approval lifetimes short relative to expected tool duration.
- Policy is an **immutable per-run snapshot**: it is loaded once at the start of a run and not
  re-read at the approval gate, so a policy file changed mid-run does not affect the in-flight decision.

### Section 4 — migration challenge-passing protocol (finding #5 follow-up)

- **Migration attestation freshness can now be closed with a source-verified challenge (finding #5,
  opt-in).** #5's first step bound migration attestation to the migration's permit nonce, but that nonce
  is the source's *incoming* (upstream-chosen) nonce and the source's provider produced the "destination
  attestation" — so a source could present pre-collected evidence. With the new opt-in, the source mints
  a **fresh challenge** at migrate time (carried as the delegated permit nonce), the destination attests
  to **its own** identity over that challenge with an injected `migration_attester`, and the evidence
  rides back in the signed delivery receipt where the **source verifies it** before marking the migration
  delivered. Because the source chose the challenge, pre-collected or stale evidence cannot satisfy it.
  Enable it with `AttestationPolicy(require_migration_challenge=True)` on the source and a
  `migration_attester` on the destination; both default off, so existing migrations are unchanged.
- **A challenge-required migration fails admission closed when the destination cannot produce valid
  evidence.** The source's demand rides inside the sealed envelope, and a destination with no attester, a
  failing attester, or an attester that returns **semantically-invalid** evidence (wrong nonce, subject,
  audience, or expiry) refuses admission **before persisting anything** — so no bad or evidence-less
  receipt is ever stored. This matters because receipts are idempotent: a stored bad receipt would be
  returned unchanged on every redelivery, stranding the outbox row forever even after a corrected
  attester is installed. Because nothing is persisted, the source re-delivers and settles once a working
  attester is in place. A failing attester surfaces as a `SecurityError`, not an uncaught error out of
  `run()`. The source's settlement check remains the trust authority (a malicious destination that
  persists bad evidence anyway is still rejected there).
- **A corrected attester always recovers — the invalid-evidence wedge is fully closed.** The destination
  can only locally check the dimensions it owns (nonce, subject, audience, expiry, and — when its own
  policy is configured — measurement and signature); a first evidence wrong only in a dimension it cannot
  evaluate (a signing key or measurement policy only the *source* trusts) would still pass the destination
  and, under keep-first receipt storage, be frozen and rejected by the source forever. So on **redelivery**
  of an identical envelope the destination **regenerates** the receipt attestation — re-running the
  attester while keeping the admission's checkpoint / audit / generation bindings unchanged — so a
  corrected attester's evidence replaces the bad one and the source settles. No re-execution of the task.
- **Regeneration is durable.** The regenerated receipt is atomically **persisted** (overwriting the stored
  one; only the attestation and signature change, every binding is carried over), and a redelivery whose
  attester is unavailable **falls back** to the stored receipt instead of failing. So once a correct
  attester has produced one good receipt, recovery survives a lost acknowledgement, a restart, or a later
  attester outage — the durable lost-ack guarantee holds. First admission still fails closed (there is no
  stored receipt to fall back to).
- **The attester call is host-bounded and rate-bounded.** The destination runs the attester on a daemon
  thread with a configurable timeout (`migration_attester_timeout`, default 5s); a hung attester fails
  admission closed rather than holding it open. Concurrent in-flight attester calls are capped
  (`migration_attester_max_inflight`, default 8) so a flood of deliveries against a slow or hung attester
  cannot spawn unbounded threads — excess calls are refused fail-closed. Set the timeout to `None` to opt
  out of the host time bound.
- **Supersedes #64's reuse only when enabled.** In challenge mode the delegated permit carries a fresh
  challenge nonce and **no** source-provided attestation (a source attestation bound to the incoming
  nonce would make the destination's `verify_execution` reject the fresh challenge); freshness moves from
  the source-side `verify_migration` check to the receipt-verify step at settlement. With challenge mode
  off, #64's incoming-nonce reuse is byte-identical. The evidence is an **optional** signed receipt field,
  so pre-#5 receipts and both directions of mixed-version delivery still validate. No schema change.
  Documented bound: a destination that also sets `required_for_execution=True` refuses challenge
  migrations (the two attestation mechanisms are mutually exclusive per destination).

### Section 4 — migration task-id namespacing (finding #7)

- **A destination no longer lets one source squat another source's task id (finding #7).** Checkpoints,
  audit heads and receipts keyed on a bare, caller-chosen `task_id`, which is only unique within its
  originating host — so a trusted host that migrated a task with an id another source was already using
  at the destination denied that peer's delivery (the second migration was rejected as a receipt
  collision). The destination now namespaces a **migrated** task's stored identity by the source it has
  cryptographically authenticated at admission (`previous_audit_host_id == permit.issuer == signing
  identity.issuer`), so two sources' same-named tasks admit and coexist as distinct tasks. The namespace
  comes from the verified source, not the id the source chose, so it holds against a deliberately
  squatting trusted host. The source-facing receipt keeps the original task id (the source settles its
  outbox row by it); only the destination's stored identity is namespaced. A fresh, non-migration task
  may not claim the reserved migration namespace. No schema change; the store API is unchanged.
  - Scope bound: this closes the squat at the migration-admission boundary, where it occurs. A full
    resume of a migrated task that suspends is governed by the existing delegated-permit auth model
    (the permit names the source as issuer) and is unaffected by this change.

### Section 4 (part 3b) — provider projection fail-closed parity

- **The provider projection now fails closed on a malformed `tool_results`, matching the migration
  path.** `project_state_for_provider` (the finding #4 confidentiality ceiling) previously passed a
  non-dict `tool_results` (a list/string/number/null from a captured or crafted wire state) through
  unprojected; it is now dropped to `{}`, the same fail-closed handling shipped for
  `project_state_for_migration` in #6. Consistency hardening flagged by the #65 auditor review; no
  behavior change for the normal dict shape.

### Section 4 (part 3b) — migration payload confidentiality

- **A migration no longer ships the source's full raw state to the destination (finding #6).** A
  tool's `output_projection` is the confidentiality ceiling on what that tool's output may reveal, and
  the provider path already enforced it — but a migration sealed the complete unprojected state, so a
  tool's withheld fields crossed the trust boundary to the destination host inside both
  `memory["tool_results"]` and the tool messages. The source now projects the migrated payload to the
  destination's entitlement (`project_state_for_migration`) **before sealing**: each granted tool's
  output is reduced to its projection ceiling in both places, a tool the destination has no grant for is
  dropped, and user/assistant messages cross in full so the task can still be resumed. Because the
  delegated permit is minted with `audience == destination` and carries exactly these grants, projecting
  to them is per-destination projection by construction. The source's own checkpoint keeps the full,
  unprojected state. The projection **fails closed**: `tool_results` is always replaced when present, so
  a non-dict value (a list/string/number/null from signed, imported, or legacy state) is dropped to `{}`
  rather than crossing the boundary unprojected.
  - **Bounds (unchanged behavior, stated):** the ceiling governs tool *output*; user/assistant message
    content is out of its scope and crosses unchanged. A share-nothing grant (empty projection) reduces
    a tool's output to a falsy-but-present `{}`, exactly as the provider path does today, so a
    truthiness-based "already ran this tool?" provider check may re-propose that tool at the destination
    — migration merely stops bypassing the ceiling; it adds no new leak or re-run semantics.
    Non-`tool_results` memory keys (`migration`, `used_approval_ids`, `approvals`) cross verbatim by
    design: they are source-side control data, not tool output, and dropping the approval bookkeeping
    would weaken migration replay prevention. Projecting approval-token contents is a separate concern,
    not part of #6.

### Section 4 (part 3b) — migration attestation freshness

- **A migration attestation can no longer be replayed across migrations (finding #5).**
  `AttestationPolicy.verify_migration` bound no nonce, so a valid, unexpired destination attestation
  could be reused for a different migration to the same destination (the expiry window was the only
  bound). It now binds to the migration's permit nonce (the same nonce execution attestation already
  binds to), mirroring `require_execution_nonce`: a new `require_migration_nonce` (opt-in, off by
  default) makes a non-empty nonce matching this migration's permit nonce mandatory, so evidence
  minted for one migration is rejected for another — verified end-to-end (source proposes AND the
  destination admits the same evidence, then a reuse is rejected). Even with the flag OFF a
  present-but-wrong nonce is now rejected (previously any migration nonce was ignored); an absent
  nonce stays allowed off, so legitimately-unbound measurement evidence keeps working.
- **The delegated permit reuses this migration's incoming nonce** instead of minting a fresh one, so a
  single destination attestation is verified against the SAME nonce at both the source
  (`verify_migration`) and the destination (`verify_execution` on the migrated permit). Without this,
  the strict path passed at the source but the destination re-checked the same evidence against a
  different (fresh) nonce and refused admission, making the opt-in unusable. The nonce is still unique
  per migration (so cross-migration replay is rejected) and unseen at the destination (so first
  admission stays nonce-guarded); the deliberate consequence is that a task migrates to a given
  destination **once** — its nonce is consumed there — rather than being re-migratable to the same
  destination after a rollback/re-run.
- **Why opt-in (off by default):** an operator may run destinations that provide legitimately-unbound
  measurement evidence; `require_migration_nonce=True` opts into the strict binding, which now works
  end-to-end. Scope: #5 only — #6 (payload confidentiality, decided: per-destination projection) and
  #7 (task-id namespacing, a whole-store re-key) remain, each as its own PR.

### Section 4 (part 3a) — migration outbox reliability

- **Concurrent dispatchers can no longer double-ship a migration (finding #3).** A dispatcher now
  CLAIMS outbox rows under a time-bounded lease via `store.claim_migrations(worker_id, lease_seconds,
  limit)`; a row is claimable only if pending AND (unclaimed OR its lease expired), so two dispatchers
  never receive the same row and a worker that dies mid-delivery has its rows reclaimed once the lease
  lapses. Claiming is race-safe — `FOR UPDATE SKIP LOCKED` on Postgres, `BEGIN IMMEDIATE` on SQLite.
  `release_migration(task_id, worker_id)` frees a claim; both it and dead-lettering are HOLDER-SCOPED,
  so a stale (expired-lease) worker cannot disturb the row a new worker now owns.
- **A stranded migration now has a terminal state and a recovery path (finding #4).** A dispatcher that
  gives up on a row (permit expired, destination gone, attempts exhausted) calls
  `dead_letter_migration(task_id, worker_id, reason)` to move it to a terminal `dead` state with a
  reason, out of the pending queue and visible via `list_dead_migrations()`; `requeue_migration(task_id)`
  returns it to the queue for a retry. Crucially, a later VERIFIED destination receipt still settles a
  dead-lettered row — a verified receipt beats the local give-up — so this does not regress the section 4
  #2 lost-ack fix (`settle_migration` now looks up pending-or-dead rows).
- **A conflicting outbox enqueue is now loud instead of silent (finding #8).** `enqueue_migration`
  keeps-first only for an exact re-enqueue of the SAME sealed envelope (an idempotent retry); a
  same-task-id enqueue with a DIFFERENT envelope raises `SecurityError` and rolls back the atomic source
  close, instead of the old `ON CONFLICT DO NOTHING` silently dropping it. NOTE: a same-task-id collision
  ACROSS source hosts stays possible until #7 namespaces the key by `(source_host_id, task_id)`; #8 only
  makes a collision loud rather than silent.
- Schema: SQLite v8 / Postgres v6 add nullable `migration_outbox.claimed_by`, `lease_expires_at`,
  `dead_reason`; old stores migrate. Portmark still ships the outbox mechanism, not a dispatcher — the
  embedder owns delivery policy (max attempts, when to dead-letter). Still open in Section 4: #5
  attestation freshness, #6 payload confidentiality (decided: per-destination projection), #7 task-id
  namespacing.
- **Fix round (concurrency hardening):**
  - **#8 is now atomic under concurrency.** The conflict check was a SELECT followed by a separate
    `INSERT ... ON CONFLICT DO NOTHING`, so two concurrent FIRST enqueues could both see no row and the
    loser silently dropped its different envelope. Replaced with ONE conflict-validating upsert
    (`ON CONFLICT DO UPDATE ... WHERE existing envelope = incoming`, `RETURNING`/rowcount): a fresh or
    identical enqueue keeps-first, a different envelope raises. Proven with a two-connection,
    barrier-synchronized Postgres test (calibrated: the old code produced two silent commits).
  - **Lease inputs are validated.** `claim_migrations` rejects an empty worker id, a non-int/bool or
    non-positive `lease_seconds`, a lease past a 7-day ceiling, and a non-positive limit — a zero or
    negative lease would otherwise let two workers hold the same row.
  - **An expired holder loses authority.** `release_migration`, `dead_letter_migration`, and scoped
    `record_migration_attempt` now require `lease_expires_at > now`, so a worker whose lease lapsed
    can no longer dead-letter or inflate the attempt count on a row it no longer owns. (An expired
    holder's *release* is a harmless no-op — the lapsed lease already made the row reclaimable.)
  - The lease clock is injected at store CONSTRUCTION (default: the wall clock), never a per-call
    parameter — so a caller of claim/release/dead-letter/attempt cannot supply a forged `now` to
    steal or bypass another worker's live lease. (An earlier iteration exposed a keyword-only `_now`;
    that was NOT private — a caller could pass it — and has been removed from the public API. Tests
    control time via a constructor-injected clock.) `record_migration_attempt` with no worker id still
    counts unscoped (single-dispatcher back-compat).
  - **Postgres leases use DATABASE time, closing a cross-host exclusivity break.** Judging a committed
    lease against each dispatcher's own host clock is not safe: a host whose clock runs ahead classifies
    a still-live lease as expired and reclaims a row another worker holds — `FOR UPDATE SKIP LOCKED`
    serializes the two claim statements but not the clock each reads, so two workers could deliver the
    same migration. All five Postgres lease operations (claim eligibility, new-lease expiry, release,
    dead-letter, scoped attempt) now compute time from `EXTRACT(EPOCH FROM clock_timestamp())::bigint`,
    so every dispatcher shares the one database clock and host skew cannot break exclusivity. The
    embedded stores (SQLite/InMemory) are single-process, so their construction-injected clock is the
    only clock and needs no change. (This supersedes an earlier note that mischaracterised the skew as
    a mere liveness window.)

### Section 4 (part 2) — signed migration delivery receipts + reconciliation

- **Migration delivery can now be settled, not just attempted (finding #2, High).** A destination that
  admits a migrated task issues a signed `portmark.migration-receipt.v1` in the SAME transaction that
  commits the admission checkpoint, bound to the task id, source/destination hosts, the delegated permit
  nonce, the sealed-envelope digest (stable across the a2a round-trip), and the destination's committed
  generation + audit head. `RunResult.migration_receipt` and the a2a artifact carry it back to the source.
- **The source settles only against a verified receipt.** `AgentHost.settle_migration(task_id, receipt)`
  verifies the receipt's signature (against the destination's trusted key, `receipt` usage) and every
  binding against the outbox row, then `mark_migration_delivered(task_id, receipt_json)` records it and
  flips the row to delivered. An unverifiable or mismatched receipt raises and the row stays pending, so a
  bad receipt can never settle a migration. The store's `mark_migration_delivered` now REQUIRES the
  receipt (its old task-id-only form is gone).
- **Lost acknowledgements reconcile safely.** A duplicate delivery of the same envelope returns the SAME
  receipt (no re-execution) instead of the old undifferentiated replay error, so a source whose ack was
  lost can still settle; a different envelope squatting the same task id is rejected.
- **Deployment prerequisite (documented):** the source must trust the destination's receipt key, or its
  rows stay pending with a clear "signing key is not trusted" error. `accepted_at` is destination-set and
  recorded, never gated on.
- **Receipt verification rejects unsigned fields.** The signature covers only the body, so verification
  now requires the receipt's keys to be EXACTLY the signed body plus `signature`/`signature_key_id` — an
  unknown field (e.g. an unsigned `completion_status`) is rejected rather than verified and then persisted
  as if signed. Enforced on both the Ed25519 and legacy-HMAC paths. Atomic receipt issuance has a
  fault-injection regression test (a failed receipt insert rolls back the whole admission).
- Schema: SQLite v7 / Postgres v5 add a `migration_receipts` table and a nullable
  `migration_outbox.receipt_json`; old stores migrate. Still open in Section 4: #3 outbox claim/lease,
  #4 expiry/dead-letter, #5 attestation freshness, #6 payload confidentiality, #7 task-id namespacing,
  #8 outbox conflict auditing.

### Section 4 (part 1) — migration provenance binding

- **Migration provenance can no longer be spliced between trusted hosts (finding #1, High).** When a
  destination accepts a migrated task onto a fresh local chain, it verifies the previous-audit-head
  anchor's signature and its `migration` usage — but it now also requires
  `previous_audit_host_id == permit.issuer`. Combined with the existing binding of the anchor key's
  `identity.issuer` to `previous_audit_host_id`, the recorded lineage is tied to the issuer that
  actually delegated the migration: `previous_audit_host_id == permit.issuer == identity.issuer`.
  Without this, an anchor validly signed by a *different* individually-trusted, migration-capable host
  could be attached to another host's permit and recorded as false lineage.
- Note: the legacy `HmacEnvelopeSigner` verifies neither `host_id` nor `usages`, so on that
  demo/non-production path the new `permit.issuer` equality is the only provenance binding.
- Still open in Section 4 (future PRs): signed idempotent destination receipts + delivery
  reconciliation (#2, High), outbox claim/lease (#3), expiry/dead-letter recovery (#4), attestation
  freshness (#5), migration-payload confidentiality boundary (#6), task-id namespacing (#7), and
  outbox conflict auditing (#8).

### Section 3 (part 2) — historical audit validity + key-purpose completion

- **Audit heads are signed as `portmark.audit-head.v2` with an attested `signed_at`, and verified
  at signing time (finding #3, Option B).** Ordinary key rotation/expiry no longer retroactively
  invalidates a head that was validly signed; the trust registry retains rotated/expired keys (with
  their validity intervals) as the key archive. A nullable `signed_at` column was added to
  `audit_heads` (SQLite schema v6, Postgres v4; old stores migrate).
- **Four-way verification status.** `verify-audit` now reports a precise `head_status` alongside the
  coarse status: `valid` / `valid-key-expired` / `valid-key-revoked` (cryptographically valid, key
  later revoked — reported prominently) / `signed-after-revocation`, plus `valid-legacy-v1` and the
  rejection reasons. `TrustedIdentity` gained `revoked_at` (revocation effective time) to distinguish
  pre- from post-revocation heads.
- **v1 legacy policy (documented).** A v1 head verifies as `valid-legacy-v1` when the key is not
  revoked; a v1 head from a now-revoked key is rejected, since pre-compromise cannot be established
  without a signing time. `signed_at` is signer-set and cannot alone prove pre-compromise — an
  external witness is required for that (deferred, below).
- **Migration purpose is now enforced (finding #2/#5).** `verify_audit_head` takes a `required_usage`;
  the migration-handoff verification requires the `migration` usage, so a key scoped to audit-only
  cannot mint migration handoffs. (Supersedes the part-1 "migration not enforced" note.)
- **`keygen --force` merges instead of clobbering (finding #14).** It now merge-adds a rotation entry
  into an existing trust registry, writes atomically (temp + fsync + `os.replace`), and preserves the
  file's permissions; a duplicate key id with a different public key is rejected.

Hardening from the PR review round on the above:

- **Signing-time validity is now judged in strict order (High).** `evaluate_audit_head` checks
  at/after-expiry *before* the revocation branch, so a head signed after its key expired stays
  `signed-after-expiry` and a later revocation can no longer upgrade it into accepted
  `valid-key-revoked` evidence.
- **Future-dated `signed_at` is rejected (`signed-in-future`).** A `signed_at` beyond a 300s clock-skew
  allowance (`AUDIT_HEAD_CLOCK_SKEW_SECONDS`), or a negative one, is no longer reported as `valid`.
- **Host audit-signing key enforced at boot and at every signing (High).** `make_host` fails closed at
  startup unless the host's own key is trusted, active, unexpired, unrevoked, and `audit`-authorized in
  the registry it verifies against; the same check re-runs before each audit head is signed, so a key
  that becomes unusable mid-process fails the run closed instead of writing invalid evidence. Enforcement
  no longer depends on readiness.
- **`keygen --force` rotation is concurrency-safe on POSIX and Windows.** read → validate → merge →
  replace runs under a sidecar lock (`<file>.lock`) — `fcntl` on POSIX, `msvcrt.locking` on Windows,
  both OS-released on process death — so racing rotations cannot lose a key; the whole existing registry
  is validated before merge (duplicate ids rejected, not collapsed) and the parent directory is fsynced
  after the rename.

Still deferred (a further follow-up, needs its own auditor review): the **registry rollback floor**
(#13 — a durable minimum-accepted registry version) and the **transparency-log anchor** (external
witness for compromise-sensitive "signed before time T" proof).

### Section 3 (part 1) — signing & key lifecycle

- **A durable store now refuses to start on an ephemeral signing key (finding #1, release blocker).**
  When no operator key was configured, the host generated a fresh Ed25519 key on every start but
  reused a constant key id, so after a restart a durable store's previously-signed audit heads no
  longer verified. `make_host()` now refuses a durable store (the store declares `is_durable`;
  SQLite/Postgres are durable, in-memory is not) unless a stable key is configured
  (`PORTMARK_ED25519_PRIVATE_KEY_B64`) — or `allow_ephemeral_signing_key=True` is passed for
  demo/test use. Generated key ids are now derived from the public-key fingerprint
  (`ed25519:<digest>`) so two generated keys can never collide. Stability is affirmative: only a key
  loaded from stable bytes (`from_private_key_bytes`) counts as stable, so a randomly-generated
  custom/HMAC signer is refused on a durable store rather than presumed stable. `make_host` also
  rejects an explicit `signer` combined with a `trust_registry_path`, because the supplied signer
  keeps its own registry and the file-backed trust source (hence revocation via that file) would be
  silently ignored.
- **Deployed key revocation now takes effect without trusting a stale registry (finding #2, release blocker).**
  The trust registry was loaded once at boot, so a revocation file deployed to a running host was
  not applied until restart while `/readyz` still reported ready. The signer and the store's audit
  verifier now share ONE fail-closed trust source: every verification re-reads the on-disk registry
  and, if it changed (or was removed), rejects admission and audit verification until the host is
  restarted with the new file — it never adopts the unauthenticated new bytes. Readiness now applies
  the full validity predicate (trusted AND not-revoked AND active AND not-expired), not bare key
  membership.
- **`keygen --format env` output is shell-injection-safe (finding #4).** Every exported value is
  `shlex.quote`d and control characters/newlines in `--key-id`/`--issuer` are rejected, so a crafted
  key id or issuer cannot execute shell when the output is eval'd. The output is labelled POSIX-only;
  on PowerShell/cmd use `--format json` / `--out-registry` or set the variables manually. URI-style
  issuers (`user:portmark`, `https://…`) are still accepted.
- **Key-purpose usages primitive added (finding #5 — primitive only, not full key separation).** A
  registry entry may list `usages`; the `envelope` purpose is enforced in envelope verification and
  the `audit` purpose in audit-head verification, so an envelope-only key cannot sign an audit head.
  Empty/absent `usages` = unrestricted (backward compatible), and the host's own self-registered key
  is unrestricted, so existing registries and the default host still allow one key to span purposes.
  (At part-1 time the `migration` purpose was not yet enforced; **Section 3 part 2 above now enforces
  it** and adds the historical-audit model.)
- **Stricter Base64URL and trust-registry parsing (findings #6, #15).** Signature and public-key
  decoding is now strict canonical Base64URL — non-alphabet characters, added padding, and
  non-canonical trailing bits are rejected at every decoder site, including the
  `PORTMARK_ED25519_PRIVATE_KEY_B64` environment key. Registry `not_before`/`expires_at`
  must be real integers (a boolean is rejected, not coerced) and `revoked` a real boolean; a
  duplicate key id in a `TrustRegistry` is rejected rather than silently collapsed.

(Deferred at part-1 time and now delivered in **Section 3 part 2** above: Option B historical
audit-head validity, `audit-head.v2` + verify-at-signing-time, the key archive, the four-way status,
migration-purpose enforcement, and the atomic `keygen --force` merge. Still deferred: the registry
rollback floor and the transparency-log anchor.)

### Section 2 — A2A network boundary

- **Agent execution no longer blocks the ASGI event loop (finding #1, release blocker).**
  `POST /message:send` ran `host.run()` synchronously on the event-loop thread, so one
  slow provider, database call, approval, or agent run stalled every endpoint including
  health probes. Message dispatch now runs off the loop in a bounded worker pool sized to
  the concurrency guard, with the admission permit held across it; `/readyz` also runs off
  the loop. Health and other endpoints stay responsive during a long run.
- **The public Agent Card URL is now configurable (finding #2, release blocker).**
  `PORTMARK_A2A_PUBLIC_BASE_URL` / `--a2a-public-base-url` (validated absolute `https://`,
  host present, no credentials) is now plumbed through the config, ASGI entrypoint, CLI,
  and `serve()`. Without it a reverse-proxied card advertised the forwarded loopback origin.
- **Per-client rate limiting is proxy-aware (finding #3).** `PORTMARK_A2A_TRUSTED_PROXIES` /
  `--a2a-trusted-proxies` (CIDRs) makes the per-IP window key on the real forwarded client
  when the direct peer is a trusted proxy (rightmost untrusted `X-Forwarded-For`).
  `X-Forwarded-For` from any non-trusted peer is ignored, so it cannot be spoofed; unset
  keeps the prior peer-only behaviour. Previously all users behind a proxy shared one window.
  A malformed forwarded hop (not a syntactically valid IP) is skipped, never returned as a
  raw rate-limit identity.
- **Readiness is a bounded probe, not schema initialization (finding #4).** `/readyz` no
  longer calls `create_runtime_store()` (DDL + advisory locking) on every refresh. A new
  `store.check_ready()` does a cheap query plus a schema-version check, off the event loop;
  startup still performs migration once. It is fully time-bounded: Postgres uses
  `connect_timeout` for connection establishment (a blackholed host cannot hang past it)
  plus `statement_timeout` for the query; SQLite uses a short readiness busy timeout, not
  the 30s transactional budget. Readiness also fails closed on a missing or incomplete
  store: it requires the EXACT current schema version (an empty version-0 or older schema
  is not ready), and the SQLite probe opens the existing file read-write (`mode=rw`) so a
  deleted database is not silently recreated empty and reported ready.
- **ASGI body framing and JSON-RPC ids are enforced (finding #5).** A body that crosses or
  falls short of the declared `Content-Length` is rejected (400) rather than executed; the
  absolute 1 MiB cap is retained. A present-but-malformed JSON-RPC id (bool, float, array,
  object) now rejects the request as invalid rather than being coerced to null and processed.

### Section 1 — PostgreSQL under real failure conditions

### Fixed

- **Concurrent cold initialization is now race-safe (section 1, finding #1).** Many
  processes opening the same new schema at once could crash with a `UniqueViolation`
  because `CREATE SCHEMA` / `CREATE TABLE IF NOT EXISTS` are not atomic against
  concurrent DDL. Cold init now runs the whole DDL block on one connection behind a
  session-level advisory lock derived from the schema name, acquired **before**
  `CREATE SCHEMA` (schema creation itself races). The lock releases when the
  connection closes — no hand-rolled `pg_advisory_unlock` that could mask a DDL error
  in an aborted transaction. Verified: 16 independent processes against a fresh schema
  all succeed; with the lock removed the race reproduces every run.

### Added

- **Durable migration delivery via a transactional outbox (section 1, finding #2).** A
  migration's sealed destination envelope is now written to a `migration_outbox` row
  in the **same transaction** that closes the source checkpoint, so a crash after the
  source closes can no longer lose the migration (previously it lived only in the
  returned `RunResult`). Covers both close paths — the normal persist and the
  over-budget terminalization. New store API — `list_pending_migrations()`,
  `mark_migration_delivered(task_id)`, `record_migration_attempt(task_id)` — lets a
  delivery dispatcher retry and acknowledge; duplicate delivery is safe (destination
  nonce/CAS reject replays). SQLite schema v5, Postgres schema v3 (both upgrade in
  place). **Scope:** this provides the durable outbox and its state API, **not a
  running dispatcher** — production delivery still requires the embedder to run one
  (enumerate pending rows, retry, record attempts, mark acknowledgement). Without a
  dispatcher a migration stays durably pending and is never delivered.

## 0.9.2 — 2026-09-12

Reliability: the isolated-tool executor now releases its worker fully on every exit path. Containment (the hard-kill) was already correct; this fixes parent-side resource cleanup so a killed or failed launch cannot leak a `Popen` or open pipe handles.

### Fixed

- **A terminated worker is now reaped, not just killed.** `_ProcessTree.close()` previously
  closed only stdout: the `Popen` was never `wait()`ed (leaving a zombie and a
  `ResourceWarning: subprocess ... is still running`) and stdin stayed open. `close()` now
  kills the worker if still alive, reaps it with a bounded `wait()`, closes both pipes, and
  is idempotent. Observed on the unconfirmed-kill path, which is cross-platform.
- **A failed Windows launch no longer leaks the suspended worker.** When
  `AssignProcessToJobObject` or `ResumeThread` fails, the cleanup path now also reaps the
  process and closes its pipes (best-effort, so a secondary error cannot mask the primary
  launch failure) instead of leaving the killed worker un-`wait()`ed.

### Notes

- The normal-completion and timeout paths still issue the tree-kill through the executor's
  own `finally` (on Windows the CI-proven `TerminateJobObject`); `close()`'s kill-if-alive
  is the launch-failure / standalone-close safety net, not a replacement for it.

## 0.9.1 — 2026-09-11

Security: the Windows Job Object executor no longer overstates containment. Unchecked Win32 return values could let a failed termination pass silently; the kill is now verified and fails closed when it cannot be confirmed.

### Fixed

- **A failed `TerminateJobObject` is no longer ignored.** A raw ctypes call does not raise
  when a Win32 `BOOL` returns false, so the old `try/except OSError` around
  `TerminateJobObject` never fired — a failed termination was silent, and the host could
  report a clean kill it had not achieved. The Win32 return values are now checked
  explicitly (`TerminateJobObject`, `CloseHandle`, `ResumeThread`), and the isolated
  executor **verifies** termination: after the deadline kill it waits for the tree to
  exit, and if the kill cannot be issued or the process outlives the wait it raises
  `ToolExecutionError("isolated tool process tree could not be confirmed terminated")`
  instead of a clean `ToolKilledError`. The post-kill wait is no longer swallowed.
- **`ResumeThread` failure now fails the launch closed.** A `(DWORD)-1` return is no longer
  miscounted as a successful resume, so a worker that could not be resumed is reaped and
  the launch fails closed instead of proceeding.
- **No job-handle leak on a configuration failure.** If `SetInformationJobObject` fails,
  the newly created job handle is closed before raising. Launch-failure cleanup
  (`AssignProcessToJobObject` / resume failures) is best-effort so a secondary Win32 error
  cannot mask the primary one.
- `Thread32First` / `Thread32Next` argument and return types are declared explicitly, like
  the other Win32 bindings.

### Added

- Failure-injection tests: a kill that cannot be confirmed fails closed (cross-platform);
  and on Windows, an injected `ResumeThread` failure and an injected
  `AssignProcessToJobObject` failure each fail the launch closed rather than running an
  unmanaged worker.

## 0.9.0 — 2026-09-11

Feature: real cross-platform process-tree hard-kill. The isolated-tool executor now enforces the same "kill the worker and every descendant at the deadline" guarantee on Windows (via Job Objects) that it already had on POSIX (process groups), so Windows is no longer a weaker execution mode.

### Added

- **Windows Job Object executor for isolated tools.** Isolated tools launched on Windows
  now run inside a Job Object created with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. The
  worker is created **suspended**, assigned to the job before it can spawn anything
  (closing the launch-to-assignment race), then resumed; `TerminateJobObject` reaps the
  worker and every descendant as one unit, and closing the last job handle reaps the tree
  as a safety net. Descendant-kill, race resistance (validated over hundreds of
  immediate-spawn iterations), and kill-on-close were verified on Windows.
- **`register_isolated(side_effecting=True)` is now supported on Windows.** The
  side-effecting refusal is driven by an actual tree-kill capability check
  (`_can_hard_kill_process_tree()`), which is now true on Windows as well as POSIX. It
  still fails closed on any platform that has neither primitive.

### Changed

- The isolated executor talks to a platform-neutral `ProcessTree` interface
  (`_PosixProcessTree` / `_WindowsJobProcessTree` / `_UnmanagedProcessTree`) instead of
  branching on the platform inline. No behavior change on POSIX.
- The isolated-tool descendant-kill, side-effecting-runs, and kill-audit tests now run on
  both POSIX and Windows CI (a `windows-latest` matrix job was added) instead of being
  skipped off-POSIX.

## 0.8.7 — 2026-09-11

Hardening: the thread-timeout tool path now caps in-flight executions so a timed-out tool cannot leak unbounded threads (Codex audit finding #5).

### Fixed

- **A timed-out thread-path tool can no longer leak unbounded daemon threads.** The
  thread + queue-timeout path cannot cancel a tool once it starts, so a tool that exceeds
  its deadline leaves its daemon thread running. `ToolRegistry` now holds a bounded
  semaphore (`max_inflight_threaded`, default 64): a slot is acquired before the worker
  thread starts and released only when that thread actually finishes — so a leaked,
  timed-out thread keeps its slot. Once the cap fills with leaked threads, a new
  invocation fails closed with a clear error instead of spawning another leak. The error
  points operators at `register_isolated`, whose process-based executor the host *can*
  hard-kill; long-running or side-effecting tools belong there.



Fixed: the native Wasmtime provider now starts on Windows (Codex audit finding #6).

### Fixed

- **Native Wasmtime no longer fails to start on Windows.** The provider launched its
  child Python (which imports the arch-specific `wasmtime` wheel) with `env={"PYTHONPATH":
  ...}` only, stripping `SYSTEMROOT`, `PATH`, and the Windows process/arch variables the C
  runtime and the wheel read at import — so the child could not start. The subprocess now
  inherits a fixed allowlist of non-secret OS variables (the tool runner's
  `PYTHONPATH`/`PATH`/locale/`SYSTEMROOT` set plus `SYSTEMDRIVE`, `WINDIR`,
  `PROCESSOR_ARCHITECTURE`/`PROCESSOR_ARCHITEW6432`, `COMSPEC`, `PATHEXT`,
  `NUMBER_OF_PROCESSORS`, `TEMP`/`TMP`), forwarded only when present. No credential-shaped
  variable is forwarded, so the trust boundary is unchanged.



Security: tool-output projection is now enforced at the host boundary for every provider, not just remote adapters (Codex audit finding #4).

### Fixed

- **A grant's `output_projection` is now enforced for in-process providers too.**
  Projection was applied only on the adapter path (`provider_state` / projected
  messages), so an in-process provider that read `state.memory["tool_results"]`
  directly saw the full, un-projected tool result — including fields the grant
  deliberately withheld (the demo `catalog.search` grant declares `id, title`, but the
  raw result also carried `score`; an `http.fetch` grant that declared
  `url, status, content_type` still leaked the response `body`). The host now builds a
  projected copy of the state — reducing `memory["tool_results"]` and messages to each
  effective grant's `output_projection` — and passes that to `provider.decide`, so no
  provider sees more than the policy granted. The host keeps the full result in its own
  durable state; only the provider's view is reduced. Host policy remains the ceiling:
  an omitted policy projection shares nothing.

### Note for provider authors

- The projected `tool_results` keeps each tool's **key** with a reduced value, so a
  `"tool" not in results` guard still fires exactly once. A value projected to `{}`/`[]`
  is falsy, though — test key **presence**, not truthiness, or a `if not
  results.get("tool")` re-proposal guard can loop. See TOOLS.md.



Security: an oversized *migration* close now terminalizes the source instead of stranding it, extending the 0.8.1 terminalization guarantee to migration (Codex audit finding #1, migration case).

### Fixed

- **An oversized migration-close no longer strands the source as resumable.** 0.8.1
  bounded every *terminal* (completed/failed) over-budget persist, but a `migrate` closes
  the source with `status="ready"` — neither `completed`/`failed` nor a tool step — so it
  fell through to a raising `_persist`. When the source-close checkpoint (goal + the
  migration memory + the destination result) tipped over the budget, `run()` raised and
  left the source checkpoint `status="running"` and resumable **while a sealed migrated
  envelope already existed** — the source could resume *and* the destination run the same
  work (double effect). The terminalization trigger now fires on any closed persist
  (`tool_ran or closed`), so an over-budget migrate-close drops the source's now-redundant
  working state (it moved to the already-snapshotted migrated envelope) and lands a closed
  source checkpoint with a `checkpoint.terminalized` audit event; the migrated envelope is
  still returned. `await_input` remains excluded by design: it is an *open* checkpoint, and
  approval gates *before* the tool runs, so an oversized suspend is a liveness bug, not a
  double-effect one.



Security: non-finite numbers (`NaN`/`Infinity`) and booleans can no longer slip past numeric limits, JSON is now strict, and un-encodable provider content fails cleanly instead of stranding a running task (Codex audit findings #2 and #7).

### Fixed

- **`NaN`/`Infinity` and booleans no longer bypass numeric limits.** Every comparison
  with `NaN` is false, so a `NaN` argument sailed through `actual > max` and `value <
  min` / `value > max`; a `bool` is an `int` subclass, so `True` was silently treated as
  `1`. Both the legacy `max_<arg>` path and the schema `minimum`/`maximum` path now
  require a real *finite* number (`math.isfinite`, `bool` excluded) on the value **and**
  the constraint — a non-finite policy bound fails closed as a misconfiguration.
- **`canonical_json` is now strict (`allow_nan=False`).** `NaN`/`Infinity` are not valid
  JSON; emitting them broke round-tripping through a strict parser (and therefore the
  hash-chained audit) and let non-finite values through the limits above. They now raise.
- **Un-encodable provider content fails cleanly instead of stranding the task.** With
  strict JSON, a provider that completes/suspends/fails with `NaN` (or a reference cycle,
  or an unserializable object) would raise inside `_persist` — leaving the prior
  checkpoint `status="running"` and resumable, the exact class 0.8.1 eliminated for
  over-budget persists. The host now checks encodability at the `_apply_decision`
  boundary and, on failure, lands a small bounded terminal failure with a
  `content.rejected` audit event. In-process tool output is already rejected at the tool
  boundary (`_checked_output` now raises on non-finite output); the host check is
  defense in depth for any path that bypasses it.



Security: fresh-task admission no longer trusts caller-supplied budget counters, closing a budget bypass via negative starting counters (Codex audit finding #3).

### Fixed

- **A fresh task can no longer be admitted with a negative (or `bool`/`float`) step or
  tool-call counter.** Budget accounting (`max_steps` / `max_tool_calls`) trusted the
  `step` and `tool_calls` on the incoming state, so a fresh envelope that started at
  `tool_calls=-3` under a 1-call budget executed the tool four times (`-3, -2, -1, 0`)
  before the counter climbed to the limit. Admission now rejects a non-nonnegative-`int`
  counter at the door — before the loop runs a single tool call and before anything
  durable is written. Only the counter's type and sign are constrained: a fresh
  admission legitimately carries *positive* counters (a suspended `awaiting_input`
  envelope resumes by presenting its own signed wire state; a migration arrives with the
  source run's counters). On a **local resume** the exact `step`/`tool_calls` are now
  re-bound from the durable checkpoint, so a captured resume envelope cannot under-report
  consumed budget to win extra calls. `state.memory` stays caller-visible on resume by
  design — approval input is injected there and is already treated as untrusted wire
  state (approvals are consumed via a namespaced store nonce, EV-005).



Security: every post-admission terminal-checkpoint persist is now bounded, generalizing the EV-010 fix so a killed side-effecting tool near the ceiling can no longer leave a resumable checkpoint.

### Fixed

- **A terminal failure near the output-budget ceiling no longer leaves a resumable
  checkpoint.** The 0.7.2 EV-010 handling only collapsed the checkpoint when a tool
  had *succeeded* (`tool_calls` incremented). A tool exception, a hard
  `ToolKilledError`, step-exhaustion, or an oversized completion does **not**
  increment `tool_calls`, so when the small terminal-failure state tipped a
  near-ceiling checkpoint over the budget, `_persist` raised out of `run()` and the
  durable checkpoint stayed `status="running"` — resumable. For a **killed
  side-effecting tool** that meant the effect may have landed *and* the provider
  could re-propose it on resume. Every closed (terminal) persist that would exceed
  the budget is now collapsed to a bounded terminal tombstone (memory and messages
  dropped; result kept when it fits, else nulled) that is provably ≤ the admitted
  checkpoint, so it always lands `closed`. The cause survives in the audit chain —
  `tool.killed` with `effect_status: "unknown"` is preserved — and a new
  `checkpoint.terminalized` event records that working state was dropped under budget
  pressure. `await_input` and `migrate` are deliberately excluded: an open or
  relocating checkpoint cannot be shrunk without losing resume state, so those still
  raise. Admission itself is unchanged — a fresh task whose first checkpoint already
  exceeds the budget still raises and commits nothing (nothing to resume). See
  EXTERNAL_VALIDATION.md (EV-011).

## 0.8.0 — 2026-09-11

Security: a host-policy grant that constrains no argument now denies unnamed arguments by default (B-lite). **Breaking** behavioral change. Builds on the 0.7.4 name-filter separation.

### Security

- **A bare host-policy grant is deny-by-default on argument names.** After 0.7.0
  closed the gap for a policy that bounds *some* arguments, a policy that bounded
  *nothing* — `{"payments.reserve": {}}` — remained a passthrough and let any field
  (a prompt-injected `recipient`/`memo`) reach a side-effecting tool: the lazy-policy
  version of the same hole. A host-policy grant that names no argument now admits
  none by default. The tool stays callable, but only with arguments the host names
  (or after an explicit `additional_arguments: true`). Normalized once at
  `HostPolicy` construction — a bare policy grant is rewritten to carry
  `additional_arguments: false` — so `effective_permit` and `explain_missing_grant`
  enforce the same shape. This was safe to make only after 0.7.4 removed the
  manifest's empty grants from the intersection; every empty grant now originates
  from a permit or the host policy.

### Changed (breaking)

- **This is B-lite: only the host tightens its own default.** A *permit's* bare
  grant is left untouched — it stays a passthrough — because a permit is the
  visitor's voice, not the host's ceiling. A host policy remains the ceiling either
  way.
- **A host policy that relied on a bare `{}` grant to pass arguments must change.**
  Name the tool's legitimate arguments in policy, or set `additional_arguments: true`
  for a deliberate passthrough. Because a bare policy grant now admits no arguments,
  an argument a *permit* legitimately bounds is refused unless the *policy* also
  names it — define bound arguments in one place, usually the host policy. The
  bundled demo/default policy grants already declare their arguments and are
  unaffected. See POLICY.md / TOOLS.md and EXTERNAL_VALIDATION.md.

## 0.7.4 — 2026-09-11

Structural: the manifest is now a pure name filter in the permit intersection, separated from argument-constraint merging. No behavior change.

### Changed

- **`effective_permit` no longer folds the manifest in as empty-constraint grants.**
  It built each requested tool as a bare `ToolGrant(name)` with `{}` constraints and
  intersected those alongside the permit and policy grants. An empty grant reads as an
  argument *passthrough*, so the manifest's role ("this tool may exist") travelled on
  the same shape that means "any argument is allowed" — conflating name-filtering with
  constraint-intersection. The manifest is now passed as a name filter
  (`intersect_grants(..., allow=frozenset(requested_tools))`); argument policy comes
  entirely from the permit and host grants. This matches what `explain_missing_grant`
  already assumed, and is **behavior-preserving** — the full suite is unchanged, and a
  new `ManifestNameFilterTest` pins that the `allow` filter changes membership only,
  never a grant's constraints. It also isolates every empty grant in the intersection
  to a permit or policy origin, the precondition for a future deny-by-default default
  on bare policy/permit grants (see EXTERNAL_VALIDATION.md).

## 0.7.3 — 2026-09-11

Consistency: the checkpoint output ceiling is now the host minimum, and a dead size guard is removed. Both surfaced during the EV-010 review.

### Fixed

- **The checkpoint output-budget ceiling now uses `effective.budget` (`min(permit,
  host)`), not the visitor's permit alone.** `_persist`, `_checkpoint_fits`, and the
  `output.refused` audit detail sized the checkpoint against
  `permit.budget.max_output_bytes`, but tool output is capped against
  `effective.budget` at invoke. When a host policy set a *narrower* output budget
  than the visiting permit, the checkpoint ceiling silently followed the looser
  permit — against "budgets take the minimum," and material because a migration can
  transport the checkpoint to a peer host. The ceiling is now the host minimum in
  every spot; the replay nonce still binds to the incoming permit. A new test proves
  a checkpoint the permit would allow is refused at the host's smaller number.
- **Removed an unreachable size guard in `_result`.** `_result` runs only right after
  a `_persist` that already sized the same state against the same budget, so its
  `checkpoint exceeds output budget` raise could never fire — and had it ever become
  reachable, it would have raised out of `run()`, the exact uncaught-raise EV-010
  removed. Enforcement stays solely in `_persist`.

## 0.7.2 — 2026-09-10

Audit honesty: an oversized checkpoint after a tool runs is now a recorded terminal event, not an uncaught raise.

### Fixed

- **A tool result that overflows the checkpoint budget no longer erases the record
  that the tool ran.** A tool result is capped at invoke time, but it is then
  recorded in the checkpoint *twice* — under `memory["tool_results"]` and in
  `messages` — so a result comfortably under the output cap can still push the
  checkpoint over it. The size check in `_persist` fired *before* the store
  transaction, so it raised `SecurityError` straight out of `run()`: this step's
  audit events (including `tool.executed`) were rolled back, and the durable
  checkpoint was left `status="running"` — resumable, so a resume could re-propose
  the same tool and land its side effect a second time. The host now detects this
  case at the loop and records a bounded, terminal, **closed** refusal instead: a
  durable `output.refused` audit event carrying `effect_status: "unknown"` (the
  same honesty marker as a hard-killed tool, EV-002), followed by `agent.failed`.
  `run()` returns a failed `RunResult` rather than raising, and the closed
  checkpoint can never be resumed. The oversized payload is dropped from durable
  state (replaced by a small `__refused__` marker); the hash-chained audit, not the
  checkpoint, is the record of what happened. See EXTERNAL_VALIDATION.md (EV-010).

## 0.7.1 — 2026-09-10

Cleanup: remove demo residue from the enforcement core.

### Changed

- **The host no longer derives demo-shaped memory keys from tool names.**
  `_apply_decision` previously stored a tool's result under a munged key
  (stripping a `.search` suffix, dots to underscores) and carried a hardcoded
  `catalog.search` branch — demo wiring living in the enforcement core. Results
  are now recorded generically under `state.memory["tool_results"][<tool name>]`,
  keyed by the exact tool name; the core names no specific tool. Providers that
  consulted the old top-level keys (e.g. `state.memory["catalog"]`) should read
  `state.memory.get("tool_results", {}).get("<tool name>")` instead.

## 0.7.0 — 2026-09-10

Security: argument names are now deny-by-default. **Breaking** behavioral change.

### Security

- **A grant that constrains any argument now whitelists the names it mentions.**
  Previously `additional_arguments` defaulted to `true`, so a grant of
  `{max_amount, allowed_currency}` let an unknown `recipient`/`memo` field ride
  straight through to a side-effecting tool — the exact gap a prompt injection
  would find, and inconsistent with a runtime whose pitch is that the host is the
  ceiling on everything. Now an undeclared field is rejected without needing an
  explicit `additional_arguments: false`. Set `additional_arguments: true` to opt
  a grant back out. Enforced at `check_constraints`, in `_permitted_argument_names`,
  and in the intersection merge together, so no single-grant or merged path leaks.

### Changed (breaking)

- **A grant that constrains no argument at all is a pure capability grant** and
  still passes any argument through — this is the shape the manifest produces from
  a bare tool name, so the change does not break tool routing. But a policy that
  bounds only *some* of a tool's arguments will now reject the unbounded-but-
  legitimate ones: **list every argument name the tool legitimately takes**, or set
  `additional_arguments: true`. The bundled demo/default policy grants were updated
  to declare `query` alongside the existing `limit` bound. See TOOLS.md / POLICY.md.

## 0.6.2 — 2026-09-10

Portability fix from the Windows test review: close SQLite connections after use.

### Fixed

- **SQLite read/query methods leaked their connections.** They used sqlite3's own
  `with connection:`, which commits or rolls back but never *closes* the
  connection. An open connection holds the database file open, so on Windows temp
  files could not be deleted (breaking test cleanup) and a long-running host could
  exhaust descriptors. Reads now go through a `_connection()` context manager that
  closes in a `finally`. Postgres already closed via psycopg's context manager;
  the transaction paths already closed explicitly. No security content. A
  regression test spies on every connection a read opens and asserts it is closed.

## 0.6.1 — 2026-09-10

Follow-up to EV-002 (0.6.0): fail closed on platforms without process-group kill.
A Windows test run showed the isolated worker's grandchild survived the deadline.

### Security

- **Fail-closed where the hard-kill guarantee cannot hold.** The process-group
  kill needs `os.killpg`, which POSIX has and Windows does not (a Windows kill
  leaves a grandchild running). `register_isolated(..., side_effecting=True)` is
  now **refused at registration** on a platform without process groups, rather
  than run without the guarantee. Non-side-effecting isolated tools still run
  there (a leaked grandchild is a resource concern, not an effect-safety one).
  The kill and the refusal are gated on one positive-capability constant.

## 0.6.0 — 2026-09-10

Closes EV-002 (isolated tool executor). Untrusted or side-effecting tools can now
run in a hard-killable subprocess instead of the host process.

### Added

- **`ToolRegistry.register_isolated(name, "module:function", ...)`.** Runs a tool
  in a fresh worker process (`portmark.tool_subprocess_runner`) that imports the
  target itself and speaks one JSON document each way. The host can hard-kill it
  at the deadline — killing the whole process group (`start_new_session` +
  `killpg`), so a grandchild the tool spawned dies too. The thread path could
  never cancel a started tool; this one can.
- The worker inherits only a **default-deny env allowlist** (`PYTHONPATH`,
  `PATH`, locale, `SYSTEMROOT`) — host secrets in the environment never reach an
  untrusted tool unless the operator names them via `env=`. Its stdout is caged so
  `print()` (or a forged JSON line) cannot corrupt the protocol, and the host
  reads bounded and re-checks output size.

### Security

- **Side-effecting tools now have a sanctioned path.** A `side_effecting=True`
  tool, still refused on the thread path, may run isolated — because the host can
  hard-kill it. The kill is audited honestly: `tool.killed` with
  `effect_status: "unknown"` (a `ToolKilledError`), distinct from a clean
  `tool.failed`. Hard-kill stops any *new* effect but cannot roll back one already
  in flight at the deadline; it narrows the race, it does not eliminate it.

## 0.5.1 — 2026-09-10

Closes EV-009 (host-side migration destination ceiling). PR 2 of the two EV-008/
EV-009 follow-ups; EV-008 shipped in 0.5.0.

### Security

- **Host policy is now a ceiling over movement, not only over tools.** Previously
  a migration was authorized on the incoming permit's `delegation_allowed` alone,
  so the host could not say "I will run this agent but I will not send it to
  host:foo." `HostPolicy` gains a `migration` field (`MigrationPolicy`), and
  `authorize_migration` enforces all three conditions at the migration decision:
  the incoming permit delegates migration, the host policy allows it, and the
  destination is on the host's allowlist. The default is **deny-all** — a host
  that says nothing about migration sends agents nowhere.
- The policy loader parses and validates a `migration` block
  (`{"allowed": bool, "destinations": [host-id, ...]}`), failing closed on a
  malformed value, an unknown key, or `allowed: true` with no destinations. An
  omitted block is deny-all.

## 0.5.0 — 2026-09-10

Closes EV-008 (stale-checkpoint resume rollback). PR 1 of the two follow-ups; the
migration-destination ceiling (EV-009) follows separately.

### Security

- **The durable store now owns a monotonic checkpoint generation, admitted by
  compare-and-swap.** Previously the host ran from the state carried in the signed
  envelope and only checked that a checkpoint existed, so a captured suspended
  checkpoint (generation N) could be re-submitted as a resume after the task had
  advanced and re-run from stale state. Now every stored checkpoint carries a
  store-owned generation and a terminal `closed` flag. A fresh task must carry
  generation 0 and consumes the permit nonce; a resume is admitted only by
  advancing the exact stored generation (`generation == expected AND NOT closed`,
  in one store statement), and a completed, failed, or migrated-away checkpoint is
  closed and can never reopen. The comparison and the advance commit together with
  the nonce consumption and audit append in the first `_persist`, so a stale or
  replayed resume is rejected at admission — before any provider decision, tool
  call, approval, or migration. `AgentState.checkpoint_generation` carries the
  assertion on the wire; the store, never the caller, sets the value.
- Migration resets the destination's generation to 0 (it starts its own lineage,
  guarded by a fresh delegated nonce) and closes the source task, so neither side
  is left with a resumable lineage.

### Storage

- `RuntimeStore.save_checkpoint(task_id, state, expected_generation, closed=False)
  -> int` replaces the previous fire-and-forget signature and performs the CAS on
  all three backends: InMemory (under its lock), SQLite (`UPDATE ... WHERE
  generation = ? AND closed = 0`, rowcount checked), and Postgres (`UPDATE ...
  RETURNING`). SQLite schema **v4** and Postgres schema **v2** add the `generation`
  and `closed` columns; the migration is idempotent and closes any pre-existing
  terminal checkpoint so an old envelope cannot re-run it.
- New tests run on every backend (SQLite + Postgres in CI): the reviewer's
  adversarial capture/resume/replay sequence (rejected before the provider is
  consulted), the compare-and-swap contract (fresh requires generation 0, exactly
  one writer at a generation wins, a closed checkpoint bars resume), and a durable
  cross-restart rejection.

## 0.4.1 — 2026-09-10

### Documented

- **Two open security follow-ups are now tracked on the threat ledger** so they
  don't fall off after the 0.4.0 release: `EV-008` (stale-checkpoint resume
  rollback → checkpoint-generation CAS) and `EV-009` (host-side migration
  destination ceiling). 0.4.0 fixed the immediately exploitable form of each
  finding; these rows record the architectural work that remains. Docs only.

## 0.4.0 — 2026-09-03

Focused security release from an independent code-review pass. No new features.

### Security

- **Host policy is now the projection ceiling (Finding #1).** An omitted
  `output_projection` in a host policy parsed to `None`, which the intersection
  treated as "defer to the other side", so an incoming permit granting `["*"]`
  could widen the effective projection to the full tool output — the opposite of
  what `POLICY.md`/`TOOLS.md` promised ("omit or `[]` to share nothing"). An
  omitted host-policy projection now means deny-all. The bundled default policy
  explicitly grants `catalog.search` the `id` and `title` fields, since the demo
  Wasm capsule reads its own result back from projected state.
- **Permit-nonce consumption no longer trusts caller-supplied status (Finding
  #2).** Whether to spend a permit's one-time nonce was decided by
  `state.status == "ready"`, a field that rides in on the signed envelope; an
  issuer could set it to `"running"` on a first submission to skip consumption
  entirely and replay the permit. A run is now treated as a resume only when a
  checkpoint already exists for the task, so a first submission consumes the nonce
  regardless of the status it claims. (Replaying a suspended checkpoint as a resume
  still needs a checkpoint-generation CAS, tracked as a 0.4.x follow-up.)
- **Side-effecting tools fail closed on the thread-timeout path (Finding #3).**
  `ToolRegistry.register(..., side_effecting=True)` marks a tool whose effects
  cannot be undone. Such a tool is refused on the daemon-thread + queue-timeout
  path, which cannot cancel a started tool — a deadline there would record failure
  while the effect still lands. A hard-kill isolated executor is the follow-up that
  will let these tools run.
- **The A2A egress no longer returns internal state (Finding #4).**
  `task_from_run_result` returned `asdict(result)` — the entire internal checkpoint
  and audit log, including `cause_message` and tool arguments. It now releases only
  the run status, task id, the agent's declared result, and a migration envelope
  when present. The checkpoint and raw audit chain stay host-internal.
- **Malformed constraints fail at load, not silently at runtime (Finding #5).** An
  unknown key inside an argument spec (a `maxium` typo for `maximum`) was ignored
  by the enforcer, so a mistyped policy looked enforced and did nothing.
  `validate_constraints` now rejects unknown argument-spec keys — derived from the
  same `_SPEC_NARROWERS` table the intersection planner uses — at policy load,
  envelope build, and A2A decode.

### Documented

- `EXTERNAL_VALIDATION.md`: approval-replay tracking is durable (not
  checkpoint-only); the in-process side-effecting-tool risk now fails closed
  pending the isolated executor.
- `.coverage` is untracked and git-ignored.

## 0.3.1 — 2026-09-02

### Changed

- **Package metadata now names an author** (`Itsthewayofyou`), so the PyPI project
  page shows a maintainer instead of "None".

### Documented

- **README links now resolve on the PyPI project page.** Every in-repo link
  (`LICENSE`, the `*.md` guides, `src/…`, `deploy/…`, `wit/…`) was relative, so it
  worked on GitHub but 404'd on PyPI, which resolves relative links against
  `pypi.org`. They now point at absolute `github.com/.../blob/main/…` URLs. No code
  change.

## 0.3.0 — 2026-09-02

Two waves of hardening. The first came out of running Portmark against a real agent for the first
time. The second was a security audit of the enforcement path — a manual red-team pass, an
independent Codex audit of the live source, and a second Codex review of the fixes themselves. The
suite grew from 145 to 186 tests, and every guard added below was proven by tampering: neutering it
turns exactly the test that names it red.

### Security

- **A captured, approved, suspended envelope could replay a side-effecting tool** (Critical).
  The permit nonce was consumed only for a `ready` envelope; an `awaiting_input` envelope skipped
  it, and approval reuse was tracked in attacker-controlled wire state, so replaying a captured
  signed envelope could re-run `payments.reserve` (or any approved tool) until permit expiry.
  Approvals are now consumed durably in the runtime store, keyed by `(task_id, approval_id)`, so
  exactly one legitimate resume is admitted and a replay is refused.
- **Attestation nonce could fail open** (High). A bound attestation with an empty `nonce` was
  accepted against any permit nonce because the check short-circuited on the empty field. An
  opt-in `require_execution_nonce` now rejects a missing nonce when a binding is expected, without
  breaking migration evidence that legitimately carries none.
- **`additional_arguments: false` was ignored without an `arguments` schema.** A grant carrying only
  flat constraints silently passed unexpected fields (e.g. `account_id`) to the tool. The whitelist
  now applies with or without a schema, and the grant-merge planner mirrors it so enforcer and
  planner cannot diverge.
- **A scalar `allowed_*` constraint became a substring allowlist.** A mistyped policy
  `"allowed_role": "admin"` accepted `role: "a"` via Python `in`. Non-list `allowed_*` values are
  now rejected, fail-closed.
- **Audit-event `host_id` was outside the per-event hash**, so historical host attribution could be
  rewritten while the chain still verified. `host_id` is now covered by the hash in every store
  backend, and the hash format carries an explicit `hash_version` so future format changes stay
  backward compatible.
- **A migrated audit chain dropped its prior continuity.** The verified prior head (hash, sequence,
  host) is now recorded in the first audit event of the destination chain — inside the hashed,
  tamper-evident record — instead of being discarded when the local sequence restarts.
- **A native Wasm guest had no CPU or memory bound** beyond a 2-second wall clock. The Wasmtime
  engine now runs guests under a fuel (instruction) budget and a memory limit, both configurable.
- **The A2A agent card trusted the `Host` header** and could advertise an attacker-supplied URL.
  The card now uses a configured `public_base_url`, else reflects only a loopback `Host`
  (local development) and warns loudly otherwise. A2A also warns when it runs with no bearer token,
  since transport auth is optional and only envelope signatures gate task submission.
- **A signed manifest that pinned a component digest could run unverified** when the selected
  provider exposed no digest. It now fails closed rather than running an unverified component under
  a pinned manifest.
- **Components run with no host imports**, now pinned by a test asserting the WIT world declares
  none, so the import-free sandbox boundary cannot regress unnoticed.
- **A permit could widen a strict host policy's argument whitelist** ([#19](https://github.com/Itsthewayofyou/portmark/issues/19)).
  `additional_arguments: false` turns a constraint set's argument-name list into a whitelist, and
  that list is derived from the set's own keys — including flat `allowed_*`/`max_*` keys. Because
  the intersection copied a one-sided key straight across, a flat key arriving from the permit
  enlarged the whitelist the policy had closed. Reachable end to end: an argument the policy never
  listed reached the tool body. Grant merging now intersects the permitted argument names first and
  gates every key on the result. Affects 0.2.0.

### Changed

- **`serve()` warns loudly at startup when TLS is not asserted** (`--enable-hsts` off): envelopes
  are signed (tamper- and replay-proof) but not encrypted, so an interceptor can read a request in
  transit. Terminate TLS at the reverse proxy before public exposure.

### Fixed

- **A permit can now narrow a nested argument schema** ([#15](https://github.com/Itsthewayofyou/portmark/issues/15)).
  Previously any difference inside `arguments` dropped the grant, so an envelope asking for *less*
  than the policy allowed lost the tool entirely. The merge recurses per key with an explicit
  narrowing rule for each, documented in `TOOLS.md`. Unrecognised keys still drop the grant.
- **`"was not granted"` now says which stage refused the tool** ([#16](https://github.com/Itsthewayofyou/portmark/issues/16)).
  One sentence covered four different causes and pointed at the envelope, which is frequently the
  only correct part. `HostPolicy.explain_missing_grant` distinguishes a tool missing from the
  manifest, from the permit, from the host policy, and one whose constraints could not be
  combined — naming the failing key in the last case.

### Added

- **`make_host(providers=...)`** ([#18](https://github.com/Itsthewayofyou/portmark/issues/18)) —
  pass an in-process `ModelProvider` instead of running an HTTP adapter. Merges over the built-in
  providers rather than replacing them, so `deterministic` survives. No CLI flag: a dotted-path
  loader would add an arbitrary-code-execution surface for a case `--provider-endpoint` covers.
- **`tests/test_constraint_intersection.py`** — a seeded property test asserting that merged
  constraints never accept what either input rejects, with its own control: the same generator is
  run against a deliberately naive union merge and must find a violation. #19 was found by this
  test on the day it was written.

### Documented

- `TOOLS.md` — how two constraint sets combine, key by key, including the three cases that are
  deliberately conservative and drop a mergeable grant.
- `THREAT_MODEL.md` — a recorded decision that a failing tool ends the whole run
  ([#17](https://github.com/Itsthewayofyou/portmark/issues/17)), with the shape any future opt-out
  must take.

## 0.2.0 — 2026-09-01

The first release with usable content. `0.1.0` reserved the name and predates every feature below.

### Added

- **`portmark keygen`** — mints an Ed25519 signing key together with the trust registry a host
  needs to accept it. The two halves are emitted at once because a private key whose public half
  was never published is unusable.
- **`portmark envelope`** — builds and signs an agent envelope from a JSON spec and prints a
  ready-to-POST `message/send` request. Constructs no host: the signing key belongs to whoever
  sends the agent, and the host only verifies. Unknown spec fields are rejected rather than
  ignored. Sending an agent is now three commands and no Python.
- **`--tools module:function`** — install your own `ToolRegistry` instead of the demo stubs.
  Refuses to start without `--policy-path`, because host policy is a hard ceiling and a tool the
  policy does not grant would be silently dropped from the effective permit. See `TOOLS.md`.
- **URL argument constraints** — `scheme`, `allowed_schemes`, `allowed_hosts`, `allowed_domains`,
  enforced host-side through the permit rather than inside the tool, with userinfo and
  trailing-dot handling.
- **Container support** — a `Dockerfile` running non-root against `portmark.asgi:app`, plus
  `GET /healthz` and `GET /readyz`. `serve()` still refuses non-loopback binds; containers use the
  ASGI entrypoint behind a reverse proxy. See `DEPLOYMENT.md`.
- **Prometheus metrics** — `/metrics` content-negotiates between JSON and Prometheus text, with
  latency histograms and per-refusal-reason counters.
- **Optional Postgres store** (`portmark[postgres]`) behind the existing `RuntimeStore` protocol,
  with contract tests run against both backends in CI.
- **`THREAT_MODEL.md`** — trust boundaries, attacker capabilities, abuse paths, and residual risks.
- Packaging metadata: long description, project URLs, classifiers and keywords. The `0.1.0` page
  carried none of these.

### Changed

- **A2A boundary moved to ASGI/uvicorn** from `ThreadingHTTPServer`. Admission control now wraps
  the body read, so a rate-limited request is refused before its body is buffered.
- **Agent Card is now conformant to the canonical `a2a.proto`** and byte-identical to the official
  SDK's, asserted by a test. Six fields that a strict client rejected were removed or restructured.
- Request validation is deliberately **stricter than the official SDK** — it rejects missing
  `messageId`, missing `role`, and empty `parts`, which proto3 cannot distinguish from defaults.
- CI runs one matrix per push instead of two, and the concurrency test now has margin between
  offered load and the server cap.

### Fixed

- **`--trust-registry-path` was silently ignored** whenever no operator private key was set: the
  loaded registry was discarded and replaced with a fresh one, so an explicitly configured trust
  anchor did nothing.
- Registering a signer's own key now **fails closed** when the registry already holds that key id
  with a different public key, instead of producing signatures that verify nowhere.
- `verify-audit` distinguishes `valid` / `invalid` / `unverifiable` with exit codes 0 / 1 / 2,
  rather than conflating a forged chain with missing configuration.

### Security

- Fail-closed guard coverage in `security.py` raised from 82% to **98%**, with the count of
  security guards that no test exercises reduced from 62 to 2 — both remaining ones are input-type
  validation, not security decisions. Verified by tampering: neutering a guard turns exactly the
  test that names it red.
- 144 regression tests, green on Python 3.11, 3.12 and 3.13.

## 0.1.0 — 2026-08-28

Name reservation only. Not recommended for use.

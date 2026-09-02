# Changelog

All notable changes to Portmark are recorded here. Versions follow [semantic versioning](https://semver.org/).

## 0.3.1 — 2026-09-02

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

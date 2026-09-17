# Changelog

All notable changes to Portmark are recorded here. Versions follow [semantic versioning](https://semver.org/).

## Unreleased

External-audit remediation, held unreleased (no version bump / tag) until the full audit is complete.

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

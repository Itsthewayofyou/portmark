# Changelog

All notable changes to Portmark are recorded here. Versions follow [semantic versioning](https://semver.org/).

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

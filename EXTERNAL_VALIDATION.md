# External Validation Review

This file records the Phase 7 independent review pass and converts residual
findings into concrete tasks. These are not vague hardening themes; each item
has a target, acceptance criteria, and the threat IDs it addresses.

## Review Scope

Reviewed areas:

- A2A network boundary: `src/portmark/a2a.py`, `src/portmark/asgi.py`, `deploy/nginx/portmark.conf`
- custom tool loading: `src/portmark/tool_loading.py`, `src/portmark/tools.py`, `TOOLS.md`
- provider projection and response validation: `src/portmark/providers.py`, `src/portmark/projection.py`
- audit chain signing: `src/portmark/storage.py`, `src/portmark/security.py`, `src/portmark/host.py`
- attestation external verifier: `src/portmark/security.py`, `ATTESTATION.md`
- approval tokens: `src/portmark/security.py`, `src/portmark/host.py`

## Findings Converted To Tasks

| Task ID | Priority | Finding | Concrete Task | Acceptance Criteria | Related Threats |
| --- | --- | --- | --- | --- | --- |
| EV-001 | Medium | In-process rate limiting is per process and does not coordinate across horizontally scaled replicas. | Add deployment guidance and tests for a shared edge limiter requirement in multi-replica deployments. | `DEPLOYMENT.md` includes a multi-replica rate-limit requirement; nginx or equivalent config has a tested example; tests assert the requirement text and config route coverage. | TM-001 |
| EV-002 | Resolved | ~~Custom Python tools run in the host process with ambient privileges.~~ Tools can now be registered isolated, running in a hard-killable subprocess with a minimal allowlist env and JSON-only IPC. | Add an optional isolated tool executor interface for untrusted tools. | A tool can be registered to execute in a subprocess with empty/minimal env, timeout, output cap, and JSON-only IPC; tests prove timeout, exception, and oversized output fail closed. **Resolved (0.6.0):** `ToolRegistry.register_isolated(name, "module:function", ...)` runs the tool in a fresh process (`portmark.tool_subprocess_runner`); the worker sees only a default-deny env allowlist (no host secrets unless the operator passes `env=`), its stdout is caged so it cannot corrupt the JSON protocol, and the host reads bounded and re-checks the size. A deadline kills the whole **process group** (start_new_session + killpg), so a spawned grandchild dies too. Tests cover happy path, stdout contamination, env isolation, timeout hard-kill, grandchild reachability, tool exception, and oversized output. A side-effecting tool may now run **only** on this path; the thread path still refuses it. **Residual, by design:** hard-kill stops any *new* effect but cannot roll back one already in flight at the deadline, so the host audits a kill as `tool.killed` with `effect_status: "unknown"` (a `ToolKilledError`), distinct from a clean `tool.failed`. It narrows the window from "effects can start arbitrarily later" to "effects in flight at kill time"; it does not eliminate it. **Platform:** the process-group kill needs `os.killpg`, so on Windows (no process groups) a grandchild survives the kill; `register_isolated(side_effecting=True)` is refused at registration there rather than run without the guarantee, and non-side-effecting isolated tools still run. CI is Linux. | TM-003 |
| EV-003 | Medium | Production use of non-loopback HTTP provider endpoints can send projected state without transport security. | Add an opt-in enforcement mode that rejects plain HTTP provider endpoints unless loopback. | `GenericHttpProvider` rejects `http://` non-loopback endpoints when enforcement is enabled; CLI/env expose the setting; tests cover loopback allowed and remote HTTP denied. | TM-006 |
| EV-004 | High | Attestation relies on deployment-supplied external verifier correctness. | Add a conformance harness for external attestation verifier commands. | A CLI or test helper sends valid, malformed, stale, wrong-subject, wrong-audience, and wrong-measurement fixtures to a verifier command; docs require running it before production use. | TM-007 |
| EV-005 | Resolved | ~~Approval replay tracking is kept in checkpoint state, not a dedicated immutable store index.~~ Approval IDs are now consumed in durable runtime state, not trusted from the checkpoint. | Add durable approval-use records to `RuntimeStore`. | SQLite and Postgres store approval IDs transactionally; replay is rejected even if checkpoint memory is corrupted; shared store contract tests cover rollback and replay. **Resolved:** durable approval-use records land in the store transaction. | TM-008 |
| EV-006 | Medium | Checkpoint confidentiality depends on deployment storage controls. | Add optional checkpoint encryption and authentication at the storage boundary. | Store implementations can wrap checkpoint JSON with authenticated encryption; key source is operator-provided; `verify-audit` remains integrity-focused; tests prove tamper and wrong key fail closed. | TM-005 |
| EV-007 | Medium | Provider schema validation is custom and may drift from official A2A/provider schema adoption. | Add a schema compatibility test for provider decisions and A2A message validation. | A checked-in JSON schema or typed validator covers every accepted provider decision kind; mutation tests prove unsupported fields and wrong types are rejected. | TM-002, TM-006 |
| EV-008 | Resolved | ~~Stale-checkpoint resume rollback: a captured suspended checkpoint (generation N) could be re-submitted as a resume after the task advanced.~~ The store now owns a monotonic checkpoint generation, consumed via compare-and-swap; the host admits a resume only by advancing the exact stored generation, and a terminal checkpoint is `closed` so it can never reopen. | Add a monotonic `checkpoint_generation` to `RuntimeStore`, consumed via compare-and-swap: resuming generation N atomically advances to N+1 and rejects a re-submitted N. | All three stores (InMemory/SQLite/Postgres) persist and CAS a checkpoint generation; resuming the same generation twice is rejected even across a host restart; shared store contract tests cover concurrent and stale resume. **Resolved (0.5.0):** `save_checkpoint` is a CAS across all three backends (SQLite schema v4, Postgres schema v2); admission happens in the first `_persist`, before any provider/tool/approval/migration; the store-contract and adversarial replay tests run on every backend, and migration resets the destination generation while closing the source. | TM-008 |
| EV-010 | Resolved | ~~An oversized checkpoint after a tool executed raised out of `run()`, rolling back the step's audit and leaving a resumable checkpoint.~~ The host now records a bounded, terminal, closed refusal with `effect_status: "unknown"`. | Turn the post-execution checkpoint-budget failure into an honest terminal event instead of an uncaught raise, matching the EV-002 residual pattern. | A tool result that passes the invoke cap but overflows the checkpoint budget (recorded in both `memory` and `messages`) produces a durable `output.refused` audit event with `effect_status: "unknown"` then `agent.failed`; `run()` returns failed rather than raising; the checkpoint is closed so a resume is refused; a test asserts all of this against the durable store, not the in-memory audit list. **Resolved (0.7.2):** the run loop detects a tool-step whose checkpoint would exceed the budget and calls `_refuse_oversized_checkpoint`, which collapses state to a fixed-shape terminal checkpoint (payloads replaced by a `__refused__` marker so it fits by construction), appends `output.refused`/`agent.failed`, and persists `closed=True` in one transaction. **Residual, by design:** the tool already ran, so any side effect it performed has landed and cannot be undone — the audit marks the effect status unknown, exactly like `tool.killed` (EV-002). It records the truth; it does not repair the effect. | TM-003 |
| EV-011 | Resolved | ~~EV-010 only bounded the checkpoint after a *successful* tool; a tool exception, a hard kill, step-exhaustion, or an oversized completion near the ceiling still raised out of `run()` and left a resumable `status="running"` checkpoint.~~ Every post-admission terminal persist is now bounded. | Generalize the EV-010 terminalization to every closed (terminal) persist, not only successful tool results, so an admitted task can always reach a durable closed checkpoint. | A hard-killed side-effecting tool with a near-ceiling goal produces a durable, closed, `status="failed"` checkpoint (a resume is refused), the durable audit still carries `tool.killed` with `effect_status: "unknown"` plus a `checkpoint.terminalized` event, and `run()` returns rather than raising — proven against the durable store. **Resolved (0.8.1):** the loop and the step-exhaustion path collapse an over-budget terminal state via `_terminalize_over_budget`, which empties memory/messages and nulls the result only if still over, giving a tombstone provably ≤ the admitted checkpoint. **Scope, by design:** `await_input` and `migrate` are excluded — an open or relocating checkpoint cannot be shrunk without losing resume state — and admission is unchanged (a first checkpoint over budget still raises and commits nothing, so nothing is resumable). Discovered by a Windows boundary review of 0.8.0. (The `migrate` exclusion noted here was subsequently lifted — see EV-012.) | TM-003 |
| EV-012 | Resolved | ~~EV-011 excluded `migrate` from terminalization; an oversized source-close (goal + migration memory + destination result over budget) raised out of `run()` and left the source `status="running"` and resumable **while a sealed migrated envelope existed** — the source could resume *and* the destination run the same work.~~ An over-budget migrate-close now terminalizes the source. | Extend terminalization to the migrate-close, since the source's working state has moved to the already-snapshotted migrated envelope; dropping the source copy is correct. | An oversized migration-close produces a durable, closed, `status="ready"` source checkpoint with emptied `memory` and a `checkpoint.terminalized` audit event, the migrated envelope is still returned, `run()` returns rather than raising, and the audit chain verifies — proven against the durable store. **Resolved (0.8.4):** the loop's terminalization trigger widened from `tool_ran or completed/failed` to `tool_ran or closed` (closed = migrate or completed/failed), and the return threads the migration envelope. **Scope, by design:** `await_input` stays excluded — it is an open checkpoint and approval gates *before* the tool runs, so an oversized suspend is a liveness bug, not a double-effect one. | TM-003 |
| EV-009 | Resolved | ~~No host-side migration destination ceiling: the migration path authorized only on the incoming permit's `delegation_allowed`, so the host could not bound which destinations an agent may migrate to.~~ `HostPolicy.migration` (a `MigrationPolicy` allowlist) is now enforced at the migration decision by `authorize_migration`. | Add a host-policy migration allowlist (`allowed` plus `destinations`) enforced at the migration decision, so the host bounds movement the way it bounds tools. | Host policy can declare a migration allowlist; a migration to a destination not on the list is refused regardless of the incoming permit; tests cover an allowed and a denied destination. **Resolved (0.5.1):** migration requires all three of permit delegation, host `migration.allowed`, and the destination on the host allowlist; default is deny-all; the policy loader validates and fail-closes the `migration` block; host-level (allowed/denied/default-deny/no-delegation) and loader-validation tests added. | TM-002, TM-007 |

## Review Notes

- No public unauthenticated mutation endpoint was found. `/message:send` and
  `/metrics` require bearer auth when configured, and `/metrics` is not served
  open when message auth is disabled.
- The host, not the provider, enforces tool grants, budget intersections,
  approvals, attestation, and argument constraints.
- Audit verification is meaningful only when a trust registry or verifier is
  configured. The current three-state result distinguishes valid, invalid, and
  unverifiable.
- The current example side-effecting tool has SSRF-relevant controls: HTTPS
  only, no userinfo, redirects disabled, host/domain policy constraints,
  timeout, and output cap.
- The highest remaining review concern is not a known bypass in the current
  code. It is the operational trust boundary around host-loaded Python tools
  and deployment-supplied attestation verifiers.
- **Argument names are deny-by-default (0.7.0), and the lazy-policy residual is now
  closed for host policy (B-lite, 0.8.0).** 0.7.0 closed the gap for a grant that
  bounds *some* arguments; a grant that bounded *nothing* (`{"payments.reserve": {}}`)
  stayed a passthrough and admitted any field — the lazy-policy version of the same
  scenario. **Structural precondition (0.7.4):** the manifest was made a pure name
  filter (`intersect_grants(..., allow=)`), separated from constraint intersection,
  so every empty grant in the intersection now originates from a permit or the host
  policy — never the manifest. **Resolved for host policy (0.8.0, B-lite):** a bare
  host-policy grant is normalized at `HostPolicy` construction to
  `additional_arguments: false`, so it admits no arguments by default; the tool stays
  callable, but only with arguments the host names (or after an explicit
  `additional_arguments: true`). One normalized shape is seen by both
  `effective_permit` and `explain_missing_grant`. A *permit's* bare grant is
  deliberately left as a passthrough — only the host tightens its own default, the
  host policy being the ceiling regardless. **Consequence, by design:** because a
  bare policy grant admits no arguments, an argument a permit legitimately bounds is
  refused unless the policy also names it — bound arguments belong in one place,
  usually the policy. **Optional further step (owner decision, not taken):** B-full
  would extend the same default to a permit's bare grant. It is a larger breaking
  change with no host-ceiling benefit (the host already bounds everything), so it is
  left as a deliberate choice, not a pending defect.
- **Resolved (0.7.3, found during EV-010): the checkpoint output-budget ceiling now
  honors the host minimum.** `_persist`/`_checkpoint_fits` and the `output.refused`
  audit detail sized the checkpoint against `envelope.permit.budget.max_output_bytes`,
  but tool output is capped at invoke against `effective.budget.max_output_bytes`
  (`= min(permit, host)`). When host policy set a *narrower* output budget than the
  visiting permit, the checkpoint ceiling followed the looser permit — against
  "budgets take the minimum," and material because a migration can transport the
  checkpoint to a peer host. **Resolved:** all three spots now size against
  `effective.budget`; the replay nonce still binds to the incoming `envelope.permit`.
  A regression test proves a checkpoint the permit would allow is refused at the
  host's smaller number. Kept separate from EV-010 so an audit-honesty change did not
  silently move a ceiling.
- **Resolved (0.7.3, found during EV-010): the unreachable size guard in `_result`
  was removed.** `_result` runs only immediately after a `_persist` that passed on the
  same state against the same budget, so its raise could never fire — and had a future
  path reached it, it would have raised out of `run()`, the exact uncaught-raise
  EV-010 removed. It was a decorative guard, not defense-in-depth; enforcement stays
  solely in `_persist`.

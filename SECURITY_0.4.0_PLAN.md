# Portmark 0.4.0 — Security Fix Plan (findings #1–#5)

_Verified against live source on 2026-09-03. One focused security release, no new features._

## Context Summary

An external code review of `main` surfaced six items; five are code fixes (this plan) and one
is doc/hygiene. All five were re-verified line-by-line against the worktree source, not taken on
the reviewer's word:

- **#1 output_projection widening (High).** `policy.py:109` parses an *omitted* host-policy
  `output_projection` to `None`. `security.py:930` (`_projection_intersection`) treats `None` as
  "no opinion" (`if left is None: return right`), so an incoming permit carrying `["*"]` widens
  the effective projection to full tool output. `POLICY.md:62` and `TOOLS.md:143` promise the
  opposite: "omit it or set it to `[]` to share no tool output." The operator's safe-looking
  choice (omit) is the leaky one. The `[]` case is already safe (`()` → deny-all in
  `projection.py:29`); only the omitted/`None` case breaks the ceiling.
- **#2 replay via caller-supplied status (High).** `host.py:91`:
  `consume_nonce = envelope.permit.nonce if state.status == "ready" else None`. `state` comes
  straight from the signed envelope (`state = envelope.state`, `host.py:89`), and the host runs
  from that carried state, not from the stored checkpoint. A resent envelope whose state is
  marked `"running"`/`"awaiting_input"` skips nonce consumption and re-runs. There is no
  per-task monotonic generation in the store (`storage.py` checkpoints key on `task_id` only).
- **#3 timed-out tool keeps running (High).** `tools.py:invoke` starts the tool in a daemon
  thread and waits on a queue with a timeout. On timeout it raises `ToolExecutionError`, but the
  thread is never stopped — a slow side-effecting tool (e.g. `payments.reserve`) can still
  complete after the host has recorded failure. Already listed as a known residual in
  `EXTERNAL_VALIDATION.md`.
- **#4 A2A egress dumps the whole RunResult (Med).** `a2a_types.py:196 task_from_run_result`
  puts `asdict(result)` — which includes the full `checkpoint` and the full `audit` event list
  (with `cause`, `cause_message`, `arguments`) — into the A2A task artifacts. The model provider
  is carefully denied raw checkpoint memory (`projection.provider_state`), but the A2A caller is
  not. The egress boundary is weaker than the model boundary.
- **#5 unknown constraint keys are silent no-ops (Med).** `_check_argument_schema`
  (`security.py:1217`) only evaluates a fixed set of keys (`type`, `const`, `enum`, `minimum`,
  `maximum`, `min_length`, `max_length`, `pattern`). An unknown key such as `{"maxium": 100}` is
  ignored — the constraint looks enforced and does nothing. `check_constraints` runs at
  invoke-time; there is no validation pass at policy-load or envelope-decode time, so a typo'd
  policy loads clean and under-enforces silently at runtime.

Existing conventions the fixes must honor: fail-closed everywhere; three storage backends
(InMemory / SQLite / Postgres) each re-implement the same transaction surface and must stay in
lockstep; `SecurityError` is the one refusal type; every behavior-pinning test lives across
`test_security_guards`, `test_constraint_intersection`, `test_runtime`, `test_factory_providers`,
`test_grant_diagnostics`. Stack: Python 3.11+, `pytest`.

Two items are hygiene, folded into this release but not code-logic changes: `.coverage` is tracked
and absent from `.gitignore`; stale wording in `EXTERNAL_VALIDATION.md` still calls approval-replay
"checkpoint-only" though it was fixed durably. The Agent Card `version: "0.1.0"`
(`a2a_types.py:160`, `official_a2a.py:16`) is **left alone on purpose** — it mirrors the official
A2A SDK's card version; the byte-identical-card property is deliberate and must not be traded for
cosmetic version-matching without confirming the SDK value.

## Gap Analysis

- **#1 — where to normalize is the one real design decision.** The ceiling must default to
  deny-all *for the host policy side only*; manifest and permit `None` must keep meaning "defer"
  (identity), or every agent that omits projection loses the ability to ever see output. Two
  candidate fix sites: (a) `policy.py:_output_projection` returns `()` instead of `None` for an
  omitted value — isolated, but only covers **parsed** policies, not `HostPolicy(...)` built
  inline (factory default policy, tests, demos); (b) normalize at the point host policy enters
  the intersection in `effective_permit`, which covers both parsed and programmatic policies.
  **Recommendation: (b)** — normalize the host-policy grants' `output_projection` (`None → ()`)
  where `effective_permit` folds policy in, so inline policies are covered too. Confirm the fold
  order in `HostPolicy.effective_permit` before writing.
- **#2 — minimal vs complete.** Minimal fix: stop trusting `state.status`; decide fresh-start
  vs resume from durable store state (`store.load_checkpoint(task_id) is None` ⇒ fresh ⇒ consume
  nonce). Closes the "sign status=running to skip the nonce" hole with no schema change.
  Complete fix: a per-task monotonic `checkpoint_generation` the store consumes atomically
  (compare-and-swap), which also closes resume-rollback (re-sending a captured generation-N
  envelope). The complete fix touches `models.py` (state field), `host.py`, and a schema/column
  in all three backends. **Recommendation: ship the minimal fix in 0.4.0 as the security-visible
  gate, and land the generation CAS as its own PR (it is the larger, migration-bearing change).**
  Flag: the minimal fix does NOT fully close resume-rollback — say so in the changelog.
- **#3 — phased.** Full `IsolatedToolExecutor` (subprocess, empty env, JSON IPC, hard kill,
  rlimits) is a real subsystem. Minimal, honest fix for 0.4.0: classify tools as
  `side_effecting` at registration; refuse to run a side-effecting tool under the thread-timeout
  path (it must declare its own hard-kill executor), so the host never records "failed" while a
  side effect may still land. This converts a silent lie into an explicit, fail-closed refusal.
  Full subprocess executor is a follow-up. No new dependency — `subprocess`/`multiprocessing` are
  stdlib.
- **#4 — needs an explicit releasable shape.** Introduce a sanitized external result:
  `status`, `task_id`, `result` (the agent's declared output only), and a continuation handle if
  present — never `checkpoint`, never raw `audit`. `RunResult` stays the internal record.
  Decision to confirm: is the audit chain head (hash + sequence) releasable for verification, or
  fully withheld? Default: withhold detail, expose only what a caller needs to continue/verify.
- **#5 — one canonical validator, run early.** Add `validate_constraints(constraints)` that
  walks the whole structure and rejects any unknown key (in the top level and in each argument
  spec), then call it at policy-load (`policy.py`) and envelope-decode (`factory.py` /
  wherever permits are parsed). Keep `check_constraints` as the runtime enforcer. Typos become
  fatal at load, not silent at runtime.
- No new managed service, vendor, hosted DB, or paid API is introduced. No external-library
  liveness claim is load-bearing (all fixes use stdlib + existing deps).

## Implementation Phases

**Phase 1 — #1 projection ceiling (smallest, highest-value, do first).**
Goal: an omitted host-policy projection means share-nothing, matching the docs.
Files: `security.py` (or `policy.py`) at the host-policy fold in `effective_permit`; `POLICY.md`
+ `TOOLS.md` (clarify omit vs `[]` now behave identically); new regression test.
Order: independent, first.
Risk: behavior change — policies that omitted projection and relied on the permit/manifest value
to reach the model will now share nothing. Intended (fail-closed, matches docs), but call it out.
Regression test (reviewer-named): `test_host_omitted_projection_cannot_be_widened_by_permit` —
host policy omits projection, permit grants `["*"]`, assert effective projection is `()` and
`provider_state` shares no tool content.

**Phase 2 — #5 constraint validator (small, independent).**
Goal: typo'd constraint keys fail at load, not silently at runtime.
Files: `security.py` (new `validate_constraints`), `policy.py` (call at load), permit-decode
site in `factory.py`; tests in `test_security_guards`.
Order: independent; do early — it hardens the surface the other fixes touch.
Risk: an existing policy/permit with a stray key now fails to load. Desired. Grep the repo's own
fixtures/docs for non-canonical keys first so we don't break our own examples.
Conflict: `_legacy_constrained_arguments` and the flat `max_`/`allowed_` handling in
`check_constraints` define the canonical key shapes — the validator must accept exactly those and
nothing else, or it will reject valid flat constraints.

**Phase 3 — #4 A2A egress membrane (small–medium, independent).**
Goal: the A2A caller receives only an explicitly releasable result, never checkpoint/raw audit.
Files: `a2a_types.py` (`task_from_run_result` builds a sanitized artifact); `a2a.py:510` caller
unchanged; tests in `test_runtime` (or an a2a-focused test).
Order: independent.
Risk: an A2A client that today reads `checkpoint`/`audit` out of the artifact breaks. Since this
is the leak being closed, that is the point — note in changelog. Confirm no internal caller
(CLI, examples) depends on the fat artifact.
Conflict: `_task_state`/`Task.to_dict` shape must stay A2A-valid; only the `artifacts` content
changes.

**Phase 4 — #2 replay, minimal gate (medium).**
Goal: fresh-vs-resume decided by durable store state, not caller-supplied `state.status`.
Files: `host.py` (`_run` around 89–104 — derive `consume_nonce` from
`store.load_checkpoint(task_id) is None`), possibly a read within the same transaction as
`_persist` to avoid TOCTOU; tests in `test_runtime`.
Order: after Phase 2 (clean constraint surface), independent of 1/3.
Risk: the fresh-vs-resume read must be inside the persist transaction, or two concurrent fresh
sends race. Use the existing `store.transaction()`; check-and-consume atomically.
Conflict: legitimate resume flows (`awaiting_input` → resume) must still run without re-consuming
the original nonce — verify the approval/resume path (`host.py` ~239–281) still works.

**Phase 5 — #3 side-effecting tool guard (medium) + hygiene.**
Goal: never record "failed" while a side effect may still be in flight.
Files: `tools.py` (`register(..., side_effecting=False)`; refuse thread-timeout path for
side-effecting tools); `THREAT_MODEL.md`/`EXTERNAL_VALIDATION.md` (update residual-risk wording);
tests in `test_security_guards`.
Order: last of the code fixes; independent.
Risk: demo tools (`catalog.search`, `payments.reserve`) are pure/instant today, so nothing in
the suite currently exercises a real side-effecting deadline — add a test tool that sleeps past
its timeout and assert the fail-closed refusal fires.
Hygiene (same release, trivial): `git rm --cached .coverage` + add `.coverage` (and `htmlcov/`,
`.coverage.*`) to `.gitignore`; fix the "checkpoint-only" approval-replay wording in
`EXTERNAL_VALIDATION.md`.

**Deferred to follow-up PRs (named here so the scope stays honest):**
`checkpoint_generation` CAS (full #2 resume-rollback), full `IsolatedToolExecutor` subprocess
sandbox (full #3), and a host-side migration destination ceiling (review finding #6).

## Files to Modify

- `src/portmark/security.py` — normalize host-policy `None` projection to `()` at the
  `effective_permit` fold (#1); add canonical `validate_constraints` rejecting unknown keys (#5).
- `src/portmark/policy.py` — call `validate_constraints` at policy load (#5); (if fix site (a) is
  chosen instead) `_output_projection` omit → `()` (#1).
- `src/portmark/factory.py` — call `validate_constraints` when decoding permit/manifest grants (#5).
- `src/portmark/host.py` — derive `consume_nonce` from durable checkpoint presence, not
  `state.status`, inside the persist transaction (#2).
- `src/portmark/a2a_types.py` — `task_from_run_result` emits a sanitized, explicitly releasable
  artifact instead of `asdict(result)` (#4).
- `src/portmark/tools.py` — `side_effecting` flag on `register`; refuse thread-timeout path for
  side-effecting tools (#3).
- `POLICY.md`, `TOOLS.md` — clarify omit == `[]` == share-nothing (#1).
- `EXTERNAL_VALIDATION.md`, `THREAT_MODEL.md` — update #2/#3 residual-risk wording.
- `.gitignore` — add `.coverage`, `.coverage.*`, `htmlcov/`; untrack `.coverage`.
- `CHANGELOG.md` — 0.4.0 section listing all five + the two deferred follow-ups.
- `tests/` — one regression per finding: `test_host_omitted_projection_cannot_be_widened_by_permit`
  (#1), unknown-key-rejected (#5), a2a-artifact-has-no-checkpoint (#4), resent-running-envelope-
  refused (#2), side-effecting-tool-deadline-refused (#3).

## Verification

Run the full suite (the behavior-pinning tests live across five modules, not just one):

```
cd /home/josh/roots/portmark/.claude/worktrees/https-warning
python -m pytest tests/test_security_guards.py tests/test_constraint_intersection.py \
  tests/test_runtime.py tests/test_factory_providers.py tests/test_grant_diagnostics.py -q
```

Passing looks like: all existing tests green **plus** the five new regressions green, and each
new regression must FAIL against the pre-fix code (prove the guard bites — a tamper/negative test,
not a tautology). Then `python -m pytest -q` for the whole tree, and confirm `.coverage` no longer
shows in `git status`/`git ls-files`. Before merge, run the two demo scripts
(`demo_send_agent.py`, `demo_untrusted_agent.py`) to confirm the projection and egress changes did
not alter the demo output the launch artifacts depend on.

# Production Hardening Plan

Sections needing expansion and the tasks to close each, to move Portmark from
reference-complete to production-grade.

- Written 2026-08-29, against commit `8eb7edd`.
- Repo: `~/roots/portmark` (renamed from `portmark` 2026-08-29).
- Derived from a deep read of the live source, not from the existing task docs.
- Companion to [[Milestones]], which records what is already done.

## Context

3,311 lines total: 1,712 source, 939 test, 43 tests. **Zero** TODO/FIXME/debt
markers, so the gaps below are *absences*, not known-bad code.

Ranking principle: Portmark's whole value is that a host can accept a stranger's
agent safely. A hole in **containment** or **provability** attacks the core claim.
A missing feature does not. That drives the order.

Already tracked as GitHub issues, not repeated here:

- [#1](https://github.com/Itsthewayofyou/portmark/issues/1) native Wasm Component Model bindings
- [#2](https://github.com/Itsthewayofyou/portmark/issues/2) adopt the official `a2a-sdk`
- [#3](https://github.com/Itsthewayofyou/portmark/issues/3) replace `ThreadingHTTPServer`

## Assumptions challenged against source

| Assumption | Verdict | Evidence |
| --- | --- | --- |
| The hash-chained audit log proves what an agent did | **False as it stands** | `verify_audit_chain` at `src/portmark/storage.py:207` is asserted `True` in three tests and **never** asserted `False`. No test tampers with a chain. |
| The host enforces output limits | **Partially** | `max_output_bytes` is checked at `src/portmark/host.py:221,245`, but only against the finished checkpoint. A huge tool result is executed and stored first, then measured. |
| Tool calls are mediated, so tools are contained | **Partially** | Authority is mediated; resources are not. `src/portmark/tools.py:31` calls `tool(arguments)` with no timeout, output cap, or exception isolation. |
| The provider only proposes, so it cannot hurt the host | **False** | `GenericHttpProvider` does an unbounded `json.load(response)` at `src/portmark/providers.py:55`. The Wasm provider *does* cap output (`providers.py:105`). Same boundary, one side unguarded. |
| SQLite with WAL is fine for now | **Partially** | `foreign_keys` and `journal_mode=WAL` set at `storage.py:147-148`, but no `busy_timeout` and no `user_version`. No migration path exists. |

## Irreducible truths

1. **A guarantee you cannot demonstrate failing is not a guarantee.**
2. **Containment must bound resources, not just authority.** Deciding *who may*
   call a tool says nothing about *how much* it may consume.
3. **Untrusted input crosses three boundaries, not one:** the network
   (envelopes), the provider (responses), and tools (outputs). Only the first is
   currently hardened.

## Sections, ranked

| # | Section | Hole | Severity |
| --- | --- | --- | --- |
| A | Audit integrity | verifier never proven to fail; no operator CLI | **critical** |
| B | Resource containment | no tool timeout; output capped too late; provider response unbounded | **critical** |
| C | Network surface | `ThreadingHTTPServer`; no rate limit; no connection cap | high |
| D | Provider trust boundary | unvalidated response shape; full `state.__dict__` sent upstream | high |
| E | Storage operations | no schema version; no `busy_timeout`; concurrency untested at load | high |
| F | Secret hygiene and observability | no log redaction; no metrics | medium |
| G | Supply chain and compatibility | CI tests only 3.12 while claiming >=3.11; no fuzzing; no dep pinning | medium |

## Phase 1 - Prove the guarantees can fail (Section A)

Goal: every fail-closed path has a test that makes it fail.

- [x] Tamper tests for `verify_audit_chain`: mutate an event payload; break a
      `previous_hash` link; delete a middle event; reorder sequence numbers.
      Each must return `False`.
- [x] Audit the whole implied surface, not just this one. Enumerate every
      `raise SecurityError` in `security.py` and `host.py` and confirm each has a
      test that triggers it. Record any with no test.
- [x] Add `portmark verify-audit --store-path X --task-id Y` to `cli.py`.
      `OPERATIONS.md:52` already tells operators to call `verify_audit_chain`,
      but the CLI has only `demo` and `serve`, so today an incident responder
      must write Python.

Completion note: implemented with SQLite tamper regressions for payload mutation,
broken previous hash, deleted middle event, reordered sequence, stale audit head,
and missing task chains. Added direct host guard regressions for previously
implicit `SecurityError` paths and an operator-facing `verify-audit` CLI.

Risk: may reveal guards unreachable in the current runtime shape. Those need
their reachability documented, not a fake test.

Conflicts: none. Tests and CLI only; no behaviour change.

## Phase 2 - Bound resources at the point of production (Section B)

Goal: nothing unbounded crosses a boundary.

- [x] Cap tool output **inside** `ToolRegistry.invoke`, before it reaches
      `state.memory`.
- [x] Add a per-tool timeout with a configurable default. A hung tool must fail
      the step, not the host.
- [x] Wrap `tool(arguments)` so a tool exception becomes a `SecurityError`-family
      failure: generic message to the client, full detail in the audit log.
- [x] Replace `len(str(checkpoint).encode())` at `host.py:221,245` with a size
      measured on the **serialised JSON**. `str()` is a repr, so today's number
      does not match what is actually stored, and it materialises a second full
      copy of the checkpoint to measure it.
- [x] Bound `GenericHttpProvider`'s read: `response.read(N)` instead of
      `json.load(response)`.

Completion note: implemented `ToolRegistry` timeouts, exception isolation,
JSON-serializability checks, and output caps before host state mutation. Host
checkpoint budget checks now measure canonical serialized JSON, and
`GenericHttpProvider` reads at most `max_response_bytes + 1` before parsing.
Regression tests cover timeout, exception, non-JSON output, oversized tool
output before checkpointing, and bounded HTTP provider reads.

Conflicts: changing the size computation shifts where existing budget tests trip.
`tests/test_runtime.py::test_wasm_component_malformed_missing_timeout_and_oversized_outputs_are_rejected` asserts a Wasm output-limit case at
`max_output_bytes: 8`, so expect retuning.

## Phase 3 - Validate the provider response (Section D)

Goal: a hostile gateway cannot inject a decision.

- [x] Schema-validate the provider response. `providers.py:57` reads
      `value["kind"]` raw and `value.get("tool")` unchecked. A malformed response
      is an uncaught `KeyError`; an unexpected `kind` reaches `_apply_decision`.
- [x] Review what `state.__dict__` sends upstream (`providers.py:50`). It ships
      the full agent state, memory included, to a third-party endpoint. Decide
      deliberately what the provider needs and send only that.

Completion note: `GenericHttpProvider` now sends a minimal state projection
(`task_id`, `goal`, `step`, `tool_calls`, `status`) instead of `state.__dict__`,
and validates provider responses before constructing `ProviderDecision`.
Regression tests cover malformed JSON, non-object roots, missing/unsupported
kind, invalid tool names, non-object arguments, invalid migration destinations,
bad migration content, and upstream payload minimization.

Conflicts: `host.py:84` `_apply_decision` branches on `decision.kind`. Tightening
upstream may make its fallback path unreachable. Confirm rather than assume.

## Phase 4 - Storage operations (Section E)

- [x] Add `PRAGMA user_version` and a migration runner. Without it the first
      schema change breaks every existing store.
- [x] Add `PRAGMA busy_timeout`. Without it, concurrent writers get
      "database is locked" instead of waiting.
- [x] Add a concurrency test with real parallel writers, asserting no lost nonce
      consumption and no audit-sequence gaps.
- [x] Document the `RuntimeStore` protocol as the supported extension point for a
      shared database.

Completion note: `SQLiteRuntimeStore` now sets `PRAGMA busy_timeout`, tracks
schema version `2` in `PRAGMA user_version`, migrates legacy version `0`
stores, migrates version `1` audit hashes from global uniqueness to
`(task_id, hash)` uniqueness, and refuses newer unsupported schemas.
Regression tests cover schema versioning, legacy migration without losing
existing rows, v1 audit-hash migration, busy-timeout configuration, and real
parallel writers with unique nonce consumption and gap-free audit sequences.
`RUNTIME_STORAGE.md` now documents `RuntimeStore` as the supported
shared-database extension point.

Conflicts: `storage.py:42` (protocol) and `storage.py:72` (in-memory) also define
`verify_audit_chain`. All three implementations must stay behaviourally identical.

## Phase 5 - Network surface (Section C)

Tracked in [#3](https://github.com/Itsthewayofyou/portmark/issues/3). Add there:

- [x] Connection caps and per-IP rate limiting.
- [x] Keep the existing correct behaviour of rejecting on `Content-Length` alone
      without reading the body.

Completion note: `POST /message:send` now has configurable concurrent request
caps and per-IP rate limiting, exposed through environment variables and serve
flags. Regression tests cover rate-limit exhaustion, saturated request capacity,
and the existing `Content-Length`-only oversized rejection path.

## Phase 6 - Hygiene and supply chain (Sections F, G)

- [x] Add redaction to `JsonLogFormatter`. `logging_config.py:15` passes
      `record.getMessage()` through raw, so any envelope or token logged anywhere
      lands in the log verbatim.
- [x] Expand the CI matrix to 3.11, 3.12, 3.13. `pyproject.toml:11` claims
      `>=3.11`; CI tests only 3.12, so the claim is unverified.
- [x] Add a fuzz target for the envelope parser, which parses attacker-controlled
      input before any policy decision is reached.
- [x] Pin dependencies and add `pip-audit` to CI.

Completion note: JSON logs now redact bearer tokens, secret-like environment
values, private keys, passwords, and signatures from messages and exception
payloads. CI now tests Python 3.11, 3.12, and 3.13, runs the A2A parser fuzz
target, pins Bandit and pip-audit, and runs a strict dependency vulnerability
audit. Runtime dependency resolution is pinned to `cryptography==50.0.1`.

## Files to modify

| File | Change |
| --- | --- |
| `src/portmark/tools.py` | output cap, timeout, exception isolation inside `invoke` |
| `src/portmark/host.py` | JSON-based size measurement at lines 221 and 245 |
| `src/portmark/providers.py` | bounded read, response-schema validation, review `state.__dict__` payload |
| `src/portmark/storage.py` | `user_version` + migration runner, `busy_timeout` |
| `src/portmark/cli.py` | new `verify-audit` subcommand |
| `src/portmark/logging_config.py` | redaction filter |
| `src/portmark/a2a.py` | rate limiting, connection caps (with #3) |
| `tests/test_runtime.py` | tamper tests, guard-reachability audit, concurrency test |
| `.github/workflows/ci.yml` | Python matrix, `pip-audit` |
| `pyproject.toml` | dependency pinning |
| `OPERATIONS.md` | document the new CLI command and the migration procedure |

## Verification

```bash
cd ~/roots/portmark
PYTHONPATH=src python -m unittest discover -s tests -v \
  && uv run --with bandit --no-project bandit -q -r src tests \
  && PYTHONPATH=src python -m compileall -q src tests
```

Passing means all three exit 0.

**A green suite is not sufficient for Phase 1.** That phase exists precisely
because a passing suite currently proves nothing about the audit verifier. Its
real gate is a mutation check: break `verify_audit_chain` so it always returns
`True`, and confirm the suite goes red. If it stays green, the tamper tests are
decorative.

Same rule for Phase 2: raise a limit on purpose and confirm the budget tests go
red, exactly as the `MAX_REQUEST_BYTES` tamper check did on 2026-08-28.

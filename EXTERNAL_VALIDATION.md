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
| EV-002 | High | Custom Python tools run in the host process with ambient privileges. | Add an optional isolated tool executor interface for untrusted tools. | A tool can be registered to execute in a subprocess with empty/minimal env, timeout, output cap, and JSON-only IPC; tests prove timeout, exception, and oversized output fail closed. **Partial (0.4.0):** a tool marked `side_effecting=True` is now refused on the thread-timeout path (which cannot cancel a started tool), failing closed instead of recording a false failure while the effect lands; the subprocess executor remains the follow-up. | TM-003 |
| EV-003 | Medium | Production use of non-loopback HTTP provider endpoints can send projected state without transport security. | Add an opt-in enforcement mode that rejects plain HTTP provider endpoints unless loopback. | `GenericHttpProvider` rejects `http://` non-loopback endpoints when enforcement is enabled; CLI/env expose the setting; tests cover loopback allowed and remote HTTP denied. | TM-006 |
| EV-004 | High | Attestation relies on deployment-supplied external verifier correctness. | Add a conformance harness for external attestation verifier commands. | A CLI or test helper sends valid, malformed, stale, wrong-subject, wrong-audience, and wrong-measurement fixtures to a verifier command; docs require running it before production use. | TM-007 |
| EV-005 | Resolved | ~~Approval replay tracking is kept in checkpoint state, not a dedicated immutable store index.~~ Approval IDs are now consumed in durable runtime state, not trusted from the checkpoint. | Add durable approval-use records to `RuntimeStore`. | SQLite and Postgres store approval IDs transactionally; replay is rejected even if checkpoint memory is corrupted; shared store contract tests cover rollback and replay. **Resolved:** durable approval-use records land in the store transaction. | TM-008 |
| EV-006 | Medium | Checkpoint confidentiality depends on deployment storage controls. | Add optional checkpoint encryption and authentication at the storage boundary. | Store implementations can wrap checkpoint JSON with authenticated encryption; key source is operator-provided; `verify-audit` remains integrity-focused; tests prove tamper and wrong key fail closed. | TM-005 |
| EV-007 | Medium | Provider schema validation is custom and may drift from official A2A/provider schema adoption. | Add a schema compatibility test for provider decisions and A2A message validation. | A checked-in JSON schema or typed validator covers every accepted provider decision kind; mutation tests prove unsupported fields and wrong types are rejected. | TM-002, TM-006 |

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

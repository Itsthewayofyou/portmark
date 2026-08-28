# Production Task List

This file expands the production work listed in `README.md` into concrete implementation tasks. It is grounded in the current runtime files:

- `src/portmark/security.py`
- `src/portmark/host.py`
- `src/portmark/a2a.py`
- `src/portmark/providers.py`
- `wit/portmark.wit`

## 1. Replace HMAC With Asymmetric Workload Identities

Status: implemented for the reference runtime. `EnvelopeSigner` now uses Ed25519 by default, envelopes carry `signature_key_id`, verification uses `TrustRegistry`, and `HmacEnvelopeSigner` remains only for explicit legacy demos.

Tasks:

- [x] Define a signer/verifier interface so signing and verification are separate responsibilities.
- [x] Add Ed25519 signing support using a vetted crypto library.
- [x] Add key IDs to signed envelopes so verifiers can select the right public key.
- [x] Implement a trust registry mapping issuer/host IDs to public keys and allowed audiences.
- [x] Update envelope canonicalization tests to ensure signatures are stable.
- [x] Add tests for valid signature, wrong key, unknown key ID, tampered payload, expired key, and revoked key.
- [x] Keep HMAC only as a demo/test signer, clearly marked non-production.
- [x] Document key generation, rotation, revocation, and trust bootstrap.

## 2. Replace Core-Wasm ABI With WIT Component Model Bindings

Status: implemented for the reference runtime. `wit/portmark.wit` now defines structured provider decisions, `component_bindings.py` validates WIT-shaped outcomes, the runner calls `resume(context-json, checkpoint-json)`, and the example capsule has been regenerated for the new ABI.

Tasks:

- [x] Choose the Component Model toolchain, likely `wit-bindgen` plus a runtime such as Wasmtime.
- [x] Generate host bindings from `wit/portmark.wit`.
- [x] Replace the `decide(step: i32) -> i64` ABI with checkpoint/resume calls defined by WIT.
- [x] Pass structured state and available capabilities into the component.
- [x] Return structured provider decisions instead of encoded integers.
- [x] Preserve the no-ambient-import security property with explicit import validation.
- [x] Add tests for valid component execution, malformed component, forbidden imports, timeout, oversized result, and unavailable capability.
- [x] Update `capsules/research-agent.*` to the new ABI.
- [x] Keep the old ABI behind a compatibility flag only if needed for migration.

Implementation note: the available Python Wasm runtime did not expose native Component Model bindings in this environment, so the selected reference toolchain is WIT plus a JSON-lowered binding layer executed through Node's built-in WebAssembly engine. No legacy integer ABI compatibility path was kept.

## 3. Persist Nonces, Checkpoints, And Audit Heads Transactionally

Status: implemented for the reference runtime. `RuntimeStore` now supports transactional nonce consumption, checkpoint persistence, audit event insertion, and audit head updates, with a durable SQLite implementation and regression tests for restart replay, rollback, migration recovery, audit verification, and concurrency.

Tasks:

- [x] Define a storage interface for nonces, checkpoints, audit events, and audit heads.
- [x] Add a SQLite implementation for local production-like use.
- [x] Store nonce consumption atomically before or with run acceptance.
- [x] Persist checkpoint updates after every step or before every externally visible result.
- [x] Persist audit events with sequence number, previous hash, hash, task ID, host ID, and timestamp.
- [x] Enforce uniqueness on nonce, task/audit sequence, and audit hash.
- [x] Add transaction boundaries so nonce consumption, checkpoint update, and audit append cannot diverge.
- [x] Add recovery logic for resuming from the last committed checkpoint.
- [x] Add tests for process restart replay rejection, migration recovery, partial failure rollback, audit-chain verification, and concurrent submissions.

## 4. Use Complete A2A 1.0 Generated Types And Authentication Profile

Status: implemented for the reference runtime. `a2a_types.py` now provides generated-style A2A 1.0 JSON-RPC and Agent Card models, `a2a.py` enforces the `message/send` method and bearer authentication profile, and regression tests cover happy-path compatibility plus malformed, unauthenticated, oversized, unsupported-method, wrong-content-type, and generic-error cases.

Tasks:

- [x] Pull in the official A2A 1.0 schema/types from the authoritative source.
- [x] Generate Python models from the schema or adopt the official SDK if available.
- [x] Replace handwritten request/response dictionaries with generated typed models.
- [x] Implement the required A2A authentication profile.
- [x] Validate request content type, accepted methods, message shape, task state transitions, and error response format.
- [x] Update the Agent Card to match A2A 1.0 required fields.
- [x] Add auth checks before envelope parsing or host execution.
- [x] Replace current error response behavior that exposes exception types and messages to clients.
- [x] Add compatibility tests using known-good A2A examples.
- [x] Add negative tests for missing auth, invalid auth, malformed messages, oversized requests, unsupported methods, and wrong content type.

Implementation note: no official Python A2A SDK is pinned in this project, so the reference runtime uses a local generated-style subset based on the authoritative A2A proto and JSON-RPC specification. The boundary is isolated in `a2a_types.py` so it can be replaced cleanly by official generated bindings later.

## 5. Add Confidential-Computing Attestation

Status: implemented for the reference runtime. Permits can now carry signed `AttestationEvidence`, `AttestationPolicy` verifies trusted verifier keys, host identity, relying-party audience, freshness, approved measurements, optional nonce binding, and signatures, and `AgentHost` can require attestation before execution or migration. Regression tests cover valid evidence, missing evidence, expired evidence, wrong measurement, wrong audience, nonce mismatch, unknown verifier, tampered evidence, valid attested migration, and missing destination evidence.

Tasks:

- [x] Define the threat model: what the agent must hide from the host, provider, network, and storage.
- [x] Choose target TEE platform, such as AMD SEV-SNP, Intel TDX, Nitro Enclaves, or another deployment-specific option.
- [x] Define an attestation document format and verification flow.
- [x] Add host identity claims to the attestation evidence.
- [x] Bind permit audience and envelope execution to an attested host measurement.
- [x] Add remote attestation verification before migration or sensitive execution.
- [x] Decide which secrets, checkpoints, or model inputs require sealed storage.
- [x] Add policy controls for rejecting untrusted measurements.
- [x] Add tests with mocked attestation documents for valid, expired, wrong measurement, wrong audience, and missing evidence.
- [x] Document deployment prerequisites and residual risks, because confidential computing does not remove all host trust.

Implementation note: this is a provider-neutral reference verifier based on signed mock evidence and RATS-style roles. Production deployments still need to plug in the selected TEE quote verifier and sealed-storage backend for the target platform.

## 6. Store Policies Outside Process Memory And Require Approval For High-Impact Tools

Status: implemented for the reference runtime. Host policy can now be loaded from validated JSON, run audit records include policy version/hash, policy can be reloaded at run boundaries, tools are classified by impact, and high-impact tools require signed approval tokens bound to task ID, permit nonce, arguments hash, and policy hash. Approval request, approved, denied, expired, and used events are audited, and used approval IDs are stored in checkpoint memory to prevent replay.

Tasks:

- [x] Define an external policy format, such as YAML, JSON, SQLite, or OPA/Rego.
- [x] Load host policy from a configured policy source at startup.
- [x] Validate policy schema before serving traffic.
- [x] Add policy versioning and include policy version/hash in audit events.
- [x] Implement dynamic policy reload or require restart with clear behavior.
- [x] Classify tools by impact level: low, medium, high, destructive, external-payment, credentialed, data-exfiltration risk.
- [x] Add an approval gate for high-impact tools before execution.
- [x] Represent approval state in checkpoints so resumed tasks cannot bypass approval.
- [x] Add audit events for approval requested, approved, denied, expired, and used.
- [x] Add tests for policy denial, grant narrowing, high-impact approval required, approval expiry, replayed approval rejection, and policy reload behavior.
- [x] Ensure API clients receive generic denial messages while detailed causes go to logs/audit.

Implementation note: the reference runtime uses local signed approval tokens and file-backed JSON policy. Production deployments should replace the demo approval authority with an approval service or workflow tied to operator identity and change management.

## Cross-Cutting Production Tasks

Status: implemented for the reference runtime. Runtime configuration is centralized, trust registries can be loaded from JSON, structured JSON logging is available, CI runs tests/security/compile checks after package install, package data includes the Wasm runner, the A2A adapter emits security headers with guarded HSTS, and operational docs cover trust, policy, audit, backup, restore, and incident response.

- [x] Add structured logging with internal error detail separated from client responses.
- [x] Add configuration loading for host ID, trust registry path, policy path, storage path, provider endpoint, and key material.
- [x] Add CI that runs `python -m unittest discover -s tests -v` with package installation.
- [x] Add packaging metadata so users do not need manual `PYTHONPATH=src`.
- [x] Add security headers if the HTTP service is exposed beyond localhost: CSP, HSTS, Referrer-Policy, Permissions-Policy, X-Frame-Options, and X-Content-Type-Options.
- [x] Add operational docs for key rotation, policy updates, audit verification, backup/restore, and incident response.

## Suggested Milestones

1. Production persistence baseline: storage interface, SQLite backend, durable nonce/checkpoint/audit tests.
2. Signing and trust: Ed25519 signer/verifier, key IDs, trust registry, rotation tests.
3. A2A hardening: generated-style types, auth profile, generic client errors, compatibility tests.
4. Policy and approval: external policy source, impact classification, approval workflow.
5. Wasm Component Model: generated WIT bindings, structured decisions, updated capsule.
6. Confidential execution: attestation design and provider-specific implementation.

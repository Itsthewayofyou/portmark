# Operations Runbook

This runbook covers production operations for the reference runtime.

## Configuration

Runtime configuration can come from environment variables or CLI flags:

- `PORTMARK_HOST_ID` / `--host-id`
- `PORTMARK_ED25519_PRIVATE_KEY_B64`
- `PORTMARK_SIGNING_KEY_ID`
- `PORTMARK_SIGNING_ISSUER`
- `PORTMARK_ALLOWED_AUDIENCES`
- `PORTMARK_TRUST_REGISTRY_PATH` / `--trust-registry-path`
- `PORTMARK_POLICY_PATH` / `--policy-path`
- `PORTMARK_RELOAD_POLICY` / `--reload-policy`
- `PORTMARK_ATTESTATION_VERIFIER_COMMAND` / `--attestation-verifier-command`
- `PORTMARK_REQUIRE_ATTESTATION` / `--require-attestation`
- `PORTMARK_STORE_PATH` / `--store-path`
- `PORTMARK_PROVIDER_ENDPOINT` / `--provider-endpoint`
- `PORTMARK_WASM_COMPONENT` / `--wasm-component`
- `PORTMARK_WASM_ENGINE` / `--wasm-engine`
- `PORTMARK_A2A_ADAPTER` / `--a2a-adapter`
- `PORTMARK_A2A_TOKEN` / `--a2a-token`
- `PORTMARK_A2A_MAX_CONCURRENT_REQUESTS` / `--a2a-max-concurrent-requests`
- `PORTMARK_A2A_RATE_LIMIT_PER_IP` / `--a2a-rate-limit-per-ip`
- `PORTMARK_A2A_RATE_LIMIT_WINDOW_SECONDS` / `--a2a-rate-limit-window-seconds`
- `PORTMARK_A2A_AGENT_CARD_RATE_LIMIT_PER_IP` /
  `--a2a-agent-card-rate-limit-per-ip`
- `PORTMARK_A2A_AGENT_CARD_RATE_LIMIT_WINDOW_SECONDS` /
  `--a2a-agent-card-rate-limit-window-seconds`
- `PORTMARK_ALLOW_DIRECT_A2A` / `--allow-direct-a2a` (deprecated no-op;
  non-loopback binds are refused)
- `PORTMARK_LOG_LEVEL` / `--log-level`
- `PORTMARK_LOG_JSON` / `--log-json`
- `PORTMARK_ENABLE_HSTS` / `--enable-hsts`

## Trust Registry

Trust registries are JSON files:

```json
{
  "identities": [
    {
      "key_id": "issuer-key",
      "issuer": "host:issuer",
      "public_key_b64": "base64url-raw-ed25519-public-key",
      "allowed_audiences": ["host:destination"],
      "not_before": 1800000000,
      "expires_at": 1800086400,
      "revoked": false
    }
  ]
}
```

Use unique key IDs, short key lifetimes, and explicit `allowed_audiences` where possible. For emergency revocation, set `revoked: true`, deploy the trust registry, and restart hosts or use the deployment's config reload mechanism.

Ed25519 is the default signer. The legacy HMAC signer is blocked unless
`PORTMARK_ALLOW_LEGACY_HMAC=unsafe-test-only` and a non-empty
`PORTMARK_SIGNING_KEY` are both set. Treat that path as a dependency-free test
fixture only; do not use it for a production trust domain.

## Policy Updates

Policy changes should be reviewed, versioned, and deployed with a rollback plan. Approval tokens are bound to policy hashes, so tokens issued before a policy update will be rejected once hosts reload the new policy.

Tool argument constraints can use legacy exact/`max_`/`allowed_` keys or the
schema subset under `constraints.arguments`. Supported schema checks are
`type`, `const`, `enum`, `minimum`, `maximum`, `min_length`, `max_length`,
`pattern`, per-argument `required`, top-level `required`, and
`additional_arguments: false`.

## Attestation Verifier

Production deployments can attach a platform quote verifier without using a
shell:

```bash
portmark --attestation-verifier-command "/opt/portmark/verify-quote --json" \
  --require-attestation \
  serve --port 8080
```

The verifier command receives canonical JSON on stdin containing the unsigned
attestation evidence, expected subject, relying party, expected nonce, and host
time. Attestation evidence must include a non-empty `quote` when an external
verifier is configured. The verifier must exit 0 and return `{"valid": true}`
on stdout. Non-zero exits, timeouts, malformed JSON, oversized stdout, and any
response other than `{"valid": true}` reject the run. Keep the verifier
executable and trust roots owned by the deployment control plane.

## Network Boundary

`portmark serve` runs the A2A boundary on **uvicorn**, an ASGI server, so a slow
or stalled client costs a suspended coroutine rather than a blocked OS thread.
Connection concurrency is bounded by `--max-concurrent-requests`, which is passed
to uvicorn as `limit_concurrency`.

Expose the A2A listener behind a production HTTP stack for public deployments.
TLS termination remains the proxy's responsibility. Run the reference listener on
loopback:

```bash
portmark serve --bind 127.0.0.1 --port 8080
```

Then front it with a production proxy. The repository includes an Nginx example
at `deploy/nginx/portmark.conf` with TLS termination, HTTPS redirect,
`client_max_body_size 1m`, security headers, and proxy-side rate/connection
limits for `/.well-known/agent-card.json`, `/message:send`, and `/metrics`.

`portmark serve` refuses non-loopback binds such as `0.0.0.0`; public exposure
must go through the production proxy boundary. The legacy `--allow-direct-a2a`
flag and `PORTMARK_ALLOW_DIRECT_A2A=1` environment variable are retained only
for configuration compatibility and do not bypass the loopback requirement.
Even when fronted, the reference server still enforces its own
network controls: public Agent Card GETs are rate-limited separately from
message submission, concurrent `/message:send` requests are capped, accepted
submissions are rate-limited per client IP, and oversized submissions are
rejected from `Content-Length` without reading the request body.

The default A2A adapter is `local`. Use `--a2a-adapter sdk` or
`PORTMARK_A2A_ADAPTER=sdk` only when `portmark[a2a]` is installed and you want
Agent Card plus `message/send` request validation through the official
`a2a-sdk` 1.0 protobuf types.

## Audit Verification

For SQLite-backed hosts, run:

```bash
portmark --store-path runtime.sqlite --trust-registry-path trust.json verify-audit --task-id TASK_ID
```

The command prints `{"status": "valid"}` and exits 0 for an intact chain whose stored audit head is signed by a trusted host key. It prints `{"status": "invalid"}` and exits 1 when the task is missing or when event sequence, previous hash, event hash, stored audit-head validation, missing signature material, trust-registry rejection, or audit-head signature validation fails. It prints `{"status": "unverifiable"}` and exits 2 when the local verifier cannot prove the signed head because no trust registry is configured. Treat invalid results as tampered or corrupted task history; treat unverifiable results as an operator configuration failure and re-run with `--trust-registry-path`.

## Metrics

`AgentHost` owns an in-process `RuntimeMetrics` instance. Embedders can pass
their own metrics object and export `metrics.snapshot()` through the deployment
telemetry pipeline. The reference A2A server publishes the same snapshot at
`GET /metrics` only when `PORTMARK_A2A_TOKEN` or `--a2a-token` is configured;
requests must include `Authorization: Bearer <token>`. The endpoint is still
served only from the loopback origin and should be exposed publicly only
through the same authenticated production proxy boundary as `/message:send`.

## Backup And Restore

Back up these assets together:

- runtime database
- active policy file
- trust registry
- attestation verifier roots
- approval authority roots

Restore them as a consistent set. Restoring an old database with a newer policy is allowed, but old approval tokens may fail policy-hash validation.

## Storage Migrations

SQLite runtime databases carry their schema version in `PRAGMA user_version`. Hosts migrate version `0` stores to the current baseline on open and refuse to open databases with a newer schema version than the runtime supports. Back up the runtime database before deploying runtime versions that include storage migrations, and validate representative task IDs with `verify-audit` after migration.

## Incident Response

For suspected key compromise:

1. Revoke the signing, attestation, or approval key in the corresponding trust file.
2. Rotate affected private keys.
3. Restart or reload hosts.
4. Search audit logs for the compromised key ID.
5. Re-run audit-chain verification for impacted task IDs.
6. Invalidate outstanding approvals from the compromised approver.

For suspected policy bypass:

1. Preserve the runtime database and logs.
2. Verify audit chains for affected task IDs.
3. Check `agent.accepted` events for policy version and hash.
4. Check approval events for request, approval, denial, expiry, and use.
5. Rotate approval keys if token signing is implicated.

## Hygiene And Supply Chain

JSON logs redact bearer credentials, token/secret-like environment values,
private keys, passwords, and signatures before emission. Still treat runtime
logs as sensitive operational data because task IDs, key IDs, policy versions,
host IDs, and audit event structure remain visible by design.

CI runs the regression suite across Python 3.11, 3.12, and 3.13, executes the A2A
parser fuzz target, runs Bandit, and audits installed dependencies with
`pip-audit --strict`. Runtime package dependencies should stay pinned in
`pyproject.toml` and refreshed in `uv.lock` together.

## Native Wasmtime Components

The default Wasm engine is the Node JSON-lowered runner. Native Wasmtime is
optional and requires `portmark[wasmtime]` plus a Component Model artifact:

```bash
portmark --wasm-component capsules/research-agent.component.wasm.b64 \
  --wasm-engine wasmtime \
  demo "goal"
```

Use `capsules/research-agent.wasm.b64` only with the default Node runner; it is
a core Wasm module and native Wasmtime rejects it with a component parser
diagnostic. Use `capsules/research-agent.component.wasm.b64` for the checked-in
native Component Model example.

The runtime instantiates the signed component bytes through an empty
`wasmtime.component.Linker`, runs them in a short-lived Python worker with a
deadline, and passes only projected context and checkpoint JSON.

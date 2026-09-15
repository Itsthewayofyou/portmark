# Deployment

Portmark's production-shaped path is the ASGI app served by uvicorn from the
container. The reference CLI server still refuses non-loopback binds and should
not be published directly.

## Build And Run

Build the image:

```bash
docker build -t portmark:local .
```

Run it on a private network behind a reverse proxy:

```bash
docker run --rm --name portmark \
  --network portmark-private \
  --env-file ./portmark.env \
  -e PORTMARK_POLICY_PATH=/config/host-policy.json \
  -e PORTMARK_TRUST_REGISTRY_PATH=/config/trust.json \
  -e PORTMARK_STORE_BACKEND=sqlite \
  -e PORTMARK_STORE_PATH=/data/runtime.sqlite \
  -v "$PWD/examples/host-policy.json:/config/host-policy.json:ro" \
  -v "$PWD/trust.json:/config/trust.json:ro" \
  -v portmark-data:/data \
  portmark:local
```

If you load custom tools, set `PORTMARK_TOOLS=module:function` and provide a
matching `PORTMARK_POLICY_PATH`. Tool modules must be present in the image or on
the Python import path.

## Reverse Proxy Requirement

Do not publish the container port directly to the public internet. Put nginx,
Envoy, Caddy, a cloud load balancer, or an ingress controller in front of it.
The proxy must provide:

- TLS termination
- request body cap of 1 MiB or lower
- connection and request-rate limits
- forwarding of the `Authorization` header
- routing only for `/.well-known/agent-card.json`, `/message:send`, `/metrics`,
  `/healthz`, and `/readyz`

The included reference CLI server keeps its loopback-only bind rule:

```bash
portmark serve --bind 127.0.0.1 --port 8080
```

Do not attempt to expose it directly with `0.0.0.0`; Portmark rejects that mode.

## Health And Readiness

`GET /healthz` is a cheap static liveness response:

```json
{"status": "ok"}
```

`GET /readyz` re-validates the configured policy and trust registry and runs a
bounded store liveness probe (a cheap query plus a schema-version check with a
short database timeout) off the event loop. It does NOT construct the store or
run schema migrations — those happen once at startup. It returns:

```json
{"status": "ready"}
```

or, on failure, a generic:

```json
{"status": "not_ready"}
```

The response intentionally omits file paths, exception text, SQL details, and
secret material.

## Metrics

`GET /metrics` requires the same bearer token as `/message:send`. Without an
`Accept` header it returns the existing JSON snapshot. Prometheus-compatible
scrapers should send:

```http
Accept: text/plain
Authorization: Bearer <token>
```

The text response includes runtime counters, bounded refusal counters, and
latency histograms for total runs, provider decisions, tool invocation, and A2A
requests. Refusal labels are fixed reason codes so user input, tool arguments,
task IDs, and other request-controlled values cannot create high-cardinality or
secret-bearing labels.

## Secrets And Environment

Set secrets through your orchestrator's secret store, not the image or
Dockerfile. Common configuration:

- `PORTMARK_A2A_TOKEN`: bearer token for `/message:send` and `/metrics`
- `PORTMARK_A2A_PUBLIC_BASE_URL`: absolute `https://` base URL advertised in the Agent Card behind a reverse proxy (required for a correct public card)
- `PORTMARK_A2A_TRUSTED_PROXIES`: comma/space-separated CIDRs of proxy peers whose `X-Forwarded-For` is trusted for per-client rate limiting (e.g. `127.0.0.1/32`); unset ignores `X-Forwarded-For`
- `PORTMARK_ED25519_PRIVATE_KEY_B64`: host signing key
- `PORTMARK_SIGNING_KEY_ID`: signing key identifier
- `PORTMARK_SIGNING_ISSUER`: host signing issuer
- `PORTMARK_POLICY_PATH`: mounted host policy JSON
- `PORTMARK_TRUST_REGISTRY_PATH`: mounted trust registry JSON
- `PORTMARK_STORE_BACKEND`: `sqlite` by default, or `postgres` when the image includes `portmark[postgres]`
- `PORTMARK_STORE_PATH`: SQLite runtime store path or Postgres DSN
- `PORTMARK_TOOLS`: optional custom tool registry loader, `module:function`

Do not bake tokens, private keys, policy files containing local secrets, or
runtime stores into the container image.

## Migration Attestation Freshness (optional)

Migration attestation freshness is **opt-in** and off by default. To require that a destination proves
itself with fresh, non-replayable evidence before a source considers a migration delivered, enable the
**challenge-passing protocol**:

- On the **source** host: `AttestationPolicy(require_migration_challenge=True)`, and the source must
  trust the destination's attestation authority (add it to the policy's `authorities`). The source mints
  a fresh challenge per migration and verifies the destination's evidence in the delivery receipt before
  settling.
- On the **destination** host: pass a `migration_attester` (implements `MigrationAttesterProtocol`) that
  produces the destination's own attestation over the challenge. The host runs it on a daemon thread with
  a timeout (`migration_attester_timeout`, default 5s) so a hung attester fails admission closed rather
  than holding it open, and caps concurrent in-flight attester calls (`migration_attester_max_inflight`,
  default 8) so a flood of deliveries cannot spawn unbounded threads; the attester should still bound its
  own work (a leaked daemon thread from a truly-hung attester is not reclaimed and holds one of the
  in-flight slots). Set the timeout to `None` to opt out of the host time bound.

Operational notes:

- A destination that receives a challenge-required migration but has **no** working attester — or whose
  attester returns **semantically-invalid** evidence (wrong nonce/subject/audience/expiry) — refuses
  admission (fail-closed) and persists nothing, so the source can re-deliver once the attester is fixed.
  The destination validates its own attester's output before persisting so a defective attester cannot
  freeze a bad receipt into the idempotent receipt store. A destination whose `attestation_policy` is
  configured with the trusted authority and allowed measurements gets a complete pre-persist check.
- Even for a bad first evidence the destination could **not** locally detect (signed by a key or bearing
  a measurement only the source's policy rejects), redelivery of the identical envelope **regenerates**
  the attestation, so once a correct attester is in place the next delivery settles. Recovery therefore
  never requires deleting or editing stored state — just redelivering after fixing the attester.
- Challenge mode is **mutually exclusive** with `required_for_execution=True` on the same destination:
  in challenge mode the migrated permit carries no execution attestation (the proof travels in the
  receipt), so a destination that also requires an execution attestation will refuse challenge
  migrations. Pick one mechanism per destination.
- A migrated task's challenge nonce is consumed at the destination on first admission, so a task
  migrates to a given destination once (identical re-delivery remains idempotent).

## Upgrading

### Reserved migration task-id namespace (`mig::`)

A destination namespaces a **migrated** task's stored identity by the source host it
authenticates at admission, so two source hosts can migrate a task with the same
caller-chosen id to one destination without collision. The stored identity uses the
reserved prefix `mig::`. From this release, a **fresh, non-migration** task whose
`task_id` begins with `mig::` is refused at admission (this prevents a local caller
from pre-occupying a migrated task's key).

The guard applies to new admissions only; it cannot retroactively remove a collision
that already exists in a store written by an earlier version. **Before upgrading, check
every runtime store for a pre-existing task id that begins with `mig::`.** Such ids are
not produced by normal use (the prefix is internal), so a match is unexpected and should
be resolved before upgrading.

```bash
# SQLite
sqlite3 /data/runtime.sqlite \
  "SELECT task_id FROM checkpoints WHERE task_id LIKE 'mig::%';"

# Postgres (per schema)
psql "$PORTMARK_STORE_PATH" -c \
  "SELECT task_id FROM checkpoints WHERE task_id LIKE 'mig::%';"
```

If either query returns rows, migrate or rename those tasks (they were created under a
caller-chosen id that now collides with the reserved namespace) before rolling out the
new version.

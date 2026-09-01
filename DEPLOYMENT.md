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

`GET /readyz` verifies the configured policy, trust registry, SQLite store, and
host readiness path can be used. It returns:

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

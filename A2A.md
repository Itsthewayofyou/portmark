# A2A 1.0 HTTP Boundary

The HTTP adapter exposes a typed A2A-style JSON-RPC boundary for submitting signed Portmark agent envelopes.

## Agent Card

`GET /.well-known/agent-card.json` returns an Agent Card with:

- `protocolVersion: "1.0"`
- `supportedInterfaces` for JSON-RPC over HTTP
- default JSON input and output modes
- the `portmark` skill
- bearer security metadata when A2A auth is enabled

The card remains public so clients can discover the endpoint and required auth scheme. Do not place secrets or deployment-private topology in the card.

## Message Submission

Clients submit work to the card `url`, currently `/message:send`, using JSON-RPC:

```json
{
  "jsonrpc": "2.0",
  "id": "req-1",
  "method": "message/send",
  "params": {
    "message": {
      "messageId": "msg-1",
      "role": "user",
      "parts": [{"kind": "text", "text": "run this agent"}]
    },
    "metadata": {
      "portmark_envelope": {
        "manifest": {},
        "permit": {},
        "state": {},
        "previous_audit_hash": "",
        "previous_audit_sequence": 0,
        "previous_audit_host_id": "",
        "previous_audit_signature_key_id": "",
        "previous_audit_signature": "",
        "signature_key_id": "key-id",
        "signature": "base64url-signature"
      }
    }
  }
}
```

The signed envelope remains the security boundary. The A2A message fields provide protocol interoperability, while the host still verifies the envelope signature, issuer, audience, expiry, nonce, grants, budgets, and audit chain before execution.

## Authentication

Set `PORTMARK_A2A_TOKEN` or pass `--a2a-token` to require:

```http
Authorization: Bearer <token>
```

Authentication is checked before JSON parsing, envelope deserialization, or host execution. Missing or invalid credentials receive a generic JSON-RPC error with HTTP 401.

## Network Limits

The Python `ThreadingHTTPServer` adapter is a loopback origin, not a production
edge server. By default `portmark serve` refuses non-loopback binds such as
`0.0.0.0`; expose it publicly through a production HTTP front end such as
Nginx. See `deploy/nginx/portmark.conf` for a TLS-terminating reference front
that preserves the A2A routes, caps request body size, and adds proxy-side
rate/connection limits. The Agent Card is public discovery metadata, but it is
still rate-limited separately from message submission so anonymous GET traffic
cannot be left unbounded. Use `--allow-direct-a2a` or
`PORTMARK_ALLOW_DIRECT_A2A=1` only for an explicitly accepted direct-exposure
deployment.

`GET /.well-known/agent-card.json` is bounded independently:

- `PORTMARK_A2A_AGENT_CARD_RATE_LIMIT_PER_IP` /
  `--a2a-agent-card-rate-limit-per-ip` caps Agent Card GETs per client IP.
- `PORTMARK_A2A_AGENT_CARD_RATE_LIMIT_WINDOW_SECONDS` /
  `--a2a-agent-card-rate-limit-window-seconds` sets the Agent Card per-IP
  rate-limit window.

`POST /message:send` is bounded before envelope parsing and host execution:

- `PORTMARK_A2A_MAX_CONCURRENT_REQUESTS` / `--a2a-max-concurrent-requests`
  caps concurrent message submissions. Saturated servers return HTTP 503 with a
  generic JSON-RPC error.
- `PORTMARK_A2A_RATE_LIMIT_PER_IP` / `--a2a-rate-limit-per-ip` caps accepted
  message submissions per client IP.
- `PORTMARK_A2A_RATE_LIMIT_WINDOW_SECONDS` /
  `--a2a-rate-limit-window-seconds` sets the per-IP rate-limit window.

Oversized submissions are still rejected from `Content-Length` alone before the
server reads the request body.

## Rejection Behavior

The adapter fails closed for:

- missing or invalid bearer auth
- saturated concurrent request capacity
- per-IP rate-limit exhaustion
- wrong content type
- malformed JSON
- unsupported JSON-RPC methods
- invalid message shape
- oversized requests
- envelope verification or execution failure

Client errors use JSON-RPC error envelopes and generic messages. Internal exception details are logged server-side only.

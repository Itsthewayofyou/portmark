# A2A 1.0 HTTP Boundary

The HTTP adapter exposes a typed A2A-style JSON-RPC boundary for submitting signed portable-agent envelopes.

## Agent Card

`GET /.well-known/agent-card.json` returns an Agent Card with:

- `protocolVersion: "1.0"`
- `supportedInterfaces` for JSON-RPC over HTTP
- default JSON input and output modes
- the `portable-agent` skill
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
      "portable_agent_envelope": {
        "manifest": {},
        "permit": {},
        "state": {},
        "previous_audit_hash": "",
        "signature_key_id": "key-id",
        "signature": "base64url-signature"
      }
    }
  }
}
```

The signed envelope remains the security boundary. The A2A message fields provide protocol interoperability, while the host still verifies the envelope signature, issuer, audience, expiry, nonce, grants, budgets, and audit chain before execution.

## Authentication

Set `PORTABLE_AGENT_A2A_TOKEN` or pass `--a2a-token` to require:

```http
Authorization: Bearer <token>
```

Authentication is checked before JSON parsing, envelope deserialization, or host execution. Missing or invalid credentials receive a generic JSON-RPC error with HTTP 401.

## Rejection Behavior

The adapter fails closed for:

- missing or invalid bearer auth
- wrong content type
- malformed JSON
- unsupported JSON-RPC methods
- invalid message shape
- oversized requests
- envelope verification or execution failure

Client errors use JSON-RPC error envelopes and generic messages. Internal exception details are logged server-side only.

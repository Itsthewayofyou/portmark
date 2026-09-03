# External Policy And Approvals

Host policy can be loaded from a JSON file instead of being hard-coded in process construction.

## Policy Format

```json
{
  "version": "policy-v1",
  "budget": {
    "max_steps": 10,
    "max_tool_calls": 5,
    "max_output_bytes": 65536
  },
  "approval_required_impacts": [
    "high",
    "destructive",
    "external-payment",
    "credentialed",
    "data-exfiltration"
  ],
  "approval_authorities": [
    {
      "key_id": "approval-key",
      "approver": "approver:ops",
      "public_key_b64": "base64url-raw-ed25519-public-key"
    }
  ],
  "tools": {
    "catalog.search": {
      "impact": "low",
      "constraints": {
        "arguments": {
          "query": {"type": "string", "min_length": 1, "max_length": 200},
          "limit": {"type": "integer", "minimum": 1, "maximum": 5}
        },
        "required": ["query", "limit"],
        "additional_arguments": false
      },
      "output_projection": ["id", "title"]
    },
    "payments.reserve": {
      "impact": "external-payment",
      "constraints": {"max_amount": 100, "currency": "USD"}
    }
  }
}
```

The loader validates the root object, policy version, tool entries, impact levels, constraints, output projections, budget fields, and approval public keys before constructing `HostPolicy`.

Constraints are enforced immediately before tool invocation. Legacy constraints
remain supported: `max_limit` means argument `limit` must be numeric and no
larger than the configured value, `allowed_currency` means argument `currency`
must be in the allowed list, and a plain key such as `currency: "USD"` requires
exact equality. Rich constraints can be placed under `constraints.arguments`
with `type`, `const`, `enum`, `minimum`, `maximum`, `min_length`, `max_length`,
and `pattern`. Use top-level `required` or per-argument `required: true` for
mandatory arguments, and `additional_arguments: false` to reject undeclared
fields.

`output_projection` controls what tool output, if any, is sent back to a model provider on later steps. Omit it or set it to `[]` to share no tool output. Use a list of top-level JSON object fields, such as `["id", "title"]`, to share only those fields from dict outputs or lists of dicts. Use `["*"]` only when the provider is allowed to see the full output for that tool. Projection is intersected across the manifest request, incoming permit, and local host policy; the effective projection can only narrow. Host policy is the ceiling: omitting `output_projection` on a policy tool shares nothing, and no incoming permit can widen it — to expose fields you must list them (or `["*"]`) in the policy itself.

## Loading And Reloading

Use a policy file:

```powershell
$env:PYTHONPATH = "src"
python -m portmark.cli --policy-path host-policy.json demo "research mobile agents"
```

Or set `PORTMARK_POLICY_PATH`.

By default the policy is loaded at startup and changes require restart. Pass `--reload-policy` to reload the file before each run. Approval tokens are bound to the policy hash, so a token issued for an older policy is rejected after reload.

## Approval Tokens

High-impact tools are those whose impact is one of:

- `high`
- `destructive`
- `external-payment`
- `credentialed`
- `data-exfiltration`

When a provider proposes one of those tools without approval, the host pauses with `awaiting_input` and stores an approval request in the checkpoint. A signed `ApprovalToken` must then be placed in `state.memory.approvals[tool_name]` before resuming.

Approval tokens are signed Ed25519 objects bound to:

- approval ID
- tool name
- agent subject
- host audience
- task ID
- permit nonce
- canonical arguments hash
- active policy hash
- approver identity
- validity window

Used approval IDs are recorded in checkpoint memory as `used_approval_ids`, so a resumed task cannot reuse the same approval token.

## Audit Events

The host emits these approval events:

- `approval.requested`
- `approval.approved`
- `approval.denied`
- `approval.expired`
- `approval.used`

The `agent.accepted` event includes `policy_version` and `policy_hash` so every run can be tied back to the policy that authorized it.

## Client Errors

The HTTP A2A layer continues to return generic JSON-RPC errors for execution failures. Detailed approval outcomes are recorded in checkpoints and audit events.

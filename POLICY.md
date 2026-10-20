# External Policy And Approvals

Host policy can be loaded from a JSON file instead of being hard-coded in process construction.

## Policy Format

A tool name must be 1 to 192 characters, letters, digits and inner `.`, `_` or `-`, starting and ending on a
letter or digit (for example `catalog.search`, `payments.reserve`, `mcp.files.read_file`). A name is an
identifier, not free text: it is compared against grants, written into the audit chain and exported to a
SIEM, so whitespace, control characters, look-alike Unicode, path or URL separators, and the empty string
are refused where authority is defined -- in a permit grant, a manifest's `requested_tools`, a policy tool
entry, and `register` / `register_isolated`. The character set is MCP's; the length leaves room for the
`mcp.<server>.` prefix on top of a 128-character MCP tool name. The limit applies to the FINAL registered
name, after any namespacing: a generated name that would exceed it is refused, not shortened. An operator
alias stays optional, for a collision or for readability, not as routine setup.

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
  "migration": {
    "allowed": false,
    "destinations": []
  },
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

**Set `impact` on every tool.** A tool with no `impact` used to run silently as `low`, so a payment tool whose entry forgot it ran with no approval. Now:

- The **production** profile refuses a policy with any tool that has no explicit `impact`, at start-up and on every reload. A reload that drops one fails the runs in flight, like any invalid policy.
- The **development** profile (`PORTMARK_PROFILE=development`) keeps the tool at `low` and logs one warning each time the policy file content changes (keyed on its hash, not on `version`).
- In both profiles, a **side-effecting** tool (registered `side_effecting=True`, or an MCP tool that is not `read_only`) with no explicit `impact` is treated as `high`, which needs approval under the default `approval_required_impacts` (a policy that drops `high` from that list drops this too).

An explicit `"impact": "low"` is always honored: it is the operator's decision, and now a visible one. To migrate an existing policy, add `"impact"` to each tool entry (`"low"` for read-only tools, the matching high-impact level for the rest).

Constraints are enforced immediately before tool invocation. Legacy constraints
remain supported: `max_limit` means argument `limit` must be numeric and no
larger than the configured value, `allowed_currency` means argument `currency`
must be in the allowed list, and a plain key such as `currency: "USD"` requires
exact equality. Rich constraints can be placed under `constraints.arguments`
with `type`, `const`, `enum`, `minimum`, `maximum`, `min_length`, `max_length`,
and `pattern`. Use top-level `required` or per-argument `required: true` for
mandatory arguments. Top-level `required` is enforced for every grant, with or
without an `arguments` schema.

Values compare as JSON values: a boolean never matches a number, so a policy that
allows `[1]` refuses `true`, and `const: 0` refuses `false`. Lists and objects
compare element by element under the same rule. Numbers compare by value, so `1`
matches `1.0` (as in JSON Schema `enum` and `const`). A plain key such as
`currency: "USD"`, and an `allowed_*` list, also require the argument to be
present.

**Argument names are deny-by-default.** A grant that constrains any argument
(a schema, `required`, or a legacy `max_`/`allowed_`/exact key) admits only the
names it mentions — an undeclared field is rejected without setting
`additional_arguments: false`. This is the host's ceiling on argument names, so a
prompt-injected `recipient`/`memo` cannot ride through to a side-effecting tool.
Set `additional_arguments: true` to opt a grant back out and allow any field. A
**host-policy** grant that constrains no argument at all now admits **no**
arguments (deny-by-default): the tool is callable, but only with arguments you
name — a bare policy grant is no longer an argument passthrough. This closes the
lazy-policy hole where `{"payments.reserve": {}}` let any field reach the tool.
To allow arguments, name them (or set `additional_arguments: true` for a
deliberate passthrough). A permit's bare grant is unaffected — it stays a
passthrough, and the host policy remains the ceiling either way. Because a policy
grant with no argument constraints admits none, an argument the *permit*
legitimately bounds is still refused unless the *policy* also names it: bound
arguments live in one place, usually the host policy. Practical rule: when you
grant a tool that takes arguments, list its legitimate argument names in policy,
or the host will reject them.

`output_projection` controls what tool output, if any, is sent back to a model provider on later steps. Omit it or set it to `[]` to share no tool output. Use a list of top-level JSON object fields, such as `["id", "title"]`, to share only those fields from dict outputs or lists of dicts. Use `["*"]` only when the provider is allowed to see the full output for that tool. Projection is intersected across the manifest request, incoming permit, and local host policy; the effective projection can only narrow. Host policy is the ceiling: omitting `output_projection` on a policy tool shares nothing, and no incoming permit can widen it — to expose fields you must list them (or `["*"]`) in the policy itself.

`migration` is the host-side ceiling on where an agent may move. It defaults to deny-all: omit it, or set `"allowed": false`, and the host refuses every migration regardless of what the incoming permit delegates. To permit migration, set `"allowed": true` and list the exact destination host ids under `"destinations"`; a migration proceeds only when the incoming permit delegates it, the host allows it, and the destination is on this list. `"allowed": true` with an empty `"destinations"` is rejected at load, since it would allow migration to nowhere.

## Loading And Reloading

Use a policy file:

```powershell
$env:PYTHONPATH = "src"
python -m portmark.cli --policy-path host-policy.json demo "research mobile agents"
```

Or set `PORTMARK_POLICY_PATH`.

By default the policy is loaded at startup and changes require restart. Pass `--reload-policy` to reload the file before each run, and twice in each step of a run in flight: before the provider's view is built, and after the provider answers but before the host acts (and once more after a migration preflight, before anything is sealed). Replace the policy file atomically (write a temporary file, then rename it over the old one): a reload that cannot read a valid policy fails every run in flight, not only new ones. A change that lands mid-run can only narrow that run: its grants, output projections and budget become what both policies allow (a step budget that drops below the current step stops the run), its expiry takes the earlier, a tool needs approval if either policy requires it, and a migration must pass both. Which approvers are trusted, and the policy hash an approval is bound to, come from the current policy. The change is recorded as a `policy.reloaded` audit event, and a reload that fails ends the task as failed. A reload is honored at the next of those two checks; it is not synchronized with them, so a reload that lands in the gap after a check does not stop the view or action that check already cleared. That gap includes the host's own store writes before a tool launches (approval redemption, the effect ledger), which can wait on a database lock. If a reload shrinks the output budget below the checkpoint as it stands, the task fails and its closing record is stored under the last budget that admitted it. The narrowing lasts for one `run()` call: a task that pauses (for example for approval) and is resumed later is admitted under the policy current at that time, like any other run. Approval tokens are bound to the policy hash, so a token issued for an older policy is rejected after reload.

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

# WebAssembly Component Binding Contract

Portmark uses `wit/portmark.wit` as the source contract for Wasm decision providers. The current executable adapter uses a JSON-lowered binding for the WIT `resume(context-json, checkpoint-json)` export so the reference runtime can execute offline with Node's built-in WebAssembly engine.

## Toolchain

- Contract: `wit/portmark.wit`
- Host bindings: `src/portmark/component_bindings.py`
- Runner: `src/portmark/wasm_runner.mjs`
- Example capsule source: `capsules/research-agent.wat`
- Example capsule artifact: `capsules/research-agent.wasm.b64`

The Python host constructs structured context and checkpoint JSON from runtime state, sends it to the runner over stdin, and validates the returned WIT outcome before converting it into `ProviderDecision`.

## Capsule ABI

A capsule must export:

- `memory`: WebAssembly memory used for string exchange.
- `resume(context_ptr: i32, context_len: i32, checkpoint_ptr: i32, checkpoint_len: i32) -> i64`

The returned `i64` is `(result_ptr << 32) | result_len`. The pointed-to bytes must be UTF-8 JSON matching one of the WIT outcomes.

## Context JSON

The host passes:

```json
{
  "wit": {
    "package": "portable:agent@1.0.0",
    "world": "portmark",
    "abi": "portmark-json-lowered-v1"
  },
  "state": {
    "task_id": "...",
    "goal": "...",
    "step": 1,
    "tool_calls": 1,
    "status": "running",
    "messages": [
      {"role": "tool", "name": "catalog.search", "content": [{"id": "doc-1", "title": "..."}]}
    ]
  },
  "available_tools": ["catalog.search"]
}
```

`state` is the same projected provider state used for remote HTTP providers. It includes scalar run
metadata and host-policy-projected tool messages only. Raw checkpoint `memory` and `result` are not
sent to the capsule. `available_tools` is already narrowed by the effective host permit.

## Checkpoint JSON

The host passes:

```json
{
  "task_id": "...",
  "step": 1,
  "tool_calls": 1,
  "messages": [
    {"role": "tool", "name": "catalog.search", "content": [{"id": "doc-1", "title": "..."}]}
  ]
}
```

Native stacks, threads, sockets, file descriptors, full memory, and process state do not cross hosts.
Capsules resume from explicit, projected checkpoint data only.

## Outcome JSON

Tool request:

```json
{
  "outcome": "tool",
  "request": {
    "name": "catalog.search",
    "arguments_json": "{\"query\":\"portable agents\",\"limit\":3}"
  }
}
```

Completion:

```json
{
  "outcome": "completed",
  "content_json": "{\"summary\":\"done\",\"evidence\":[]}"
}
```

Other supported outcomes:

- `awaiting-input`
- `migrate`
- `failed`
- `suspended`

The host rejects malformed JSON, unknown outcomes, missing `resume`, missing `memory`, oversized output, and unavailable tool capabilities.

## Security Boundary

The runner rejects every Wasm module declaring imports. Capsules therefore have no ambient filesystem, network, process, environment, clock, randomness, or credential access. Tool requests returned by the capsule still pass through the same host permit, argument constraints, budgets, and audit log as any model-provider proposal.

The host sends component input through stdin rather than process arguments to avoid command-line exposure and argument-length limits.

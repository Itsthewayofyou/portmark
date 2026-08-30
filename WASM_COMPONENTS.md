# WebAssembly Component Binding Contract

Portmark uses `wit/portmark.wit` as the source contract for Wasm decision providers. The default executable adapter uses a JSON-lowered binding for the WIT `resume(context-json, checkpoint-json)` export so the reference runtime can execute offline with Node's built-in WebAssembly engine. Deployments can also opt into native Wasmtime Component Model bindings with `--wasm-engine wasmtime`.

## Toolchain

- Contract: `wit/portmark.wit`
- Host bindings: `src/portmark/component_bindings.py`
- Runner: `src/portmark/wasm_runner.mjs`
- Optional native runner: `src/portmark/wasmtime_component_runner.py`
- Example capsule source: `capsules/research-agent.wat`
- Example capsule artifact: `capsules/research-agent.wasm.b64`

The Python host constructs structured context and checkpoint JSON from runtime state, sends it to the runner over stdin, and validates the returned WIT outcome before converting it into `ProviderDecision`.

## Native Wasmtime Provider

Install the optional dependency:

```bash
python -m pip install -e '.[wasmtime]'
```

Run the provider with:

```bash
portmark --wasm-component path/to/component.wasm \
  --wasm-engine wasmtime \
  demo "research modern mobile agents"
```

The native provider still runs in a short-lived Python worker with a deadline,
minimal environment, output cap, and generic client-facing failures. It
instantiates the same component bytes whose SHA-256 digest is recorded in the
signed manifest, so provider selection does not introduce a second artifact that
can drift from the signature.

## Default JSON-Lowered Capsule ABI

The default Node adapter expects a core Wasm module that exports:

- `memory`: WebAssembly memory used for string exchange.
- `resume(context_ptr: i32, context_len: i32, checkpoint_ptr: i32, checkpoint_len: i32) -> i64`

The returned `i64` is `(result_ptr << 32) | result_len`. The pointed-to bytes must be UTF-8 JSON matching one of the WIT outcomes.

The native Wasmtime provider expects a Component Model artifact for
`wit/portmark.wit` and calls the exported `resume(context-json, checkpoint-json)`
function through `wasmtime.component`.

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

The checked-in research capsule demonstrates that resume model: on the first
call it requests `catalog.search`; once the checkpoint includes projected
catalog output, it completes. If no output projection is granted, the capsule
cannot inspect raw tool results and must continue from metadata only.

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

The default Node runner rejects every Wasm module declaring imports. Capsules therefore have no ambient filesystem, network, process, environment, clock, randomness, or credential access. Native Wasmtime deployments instantiate components through an empty `wasmtime.component.Linker`, so components requiring imports fail to instantiate. Tool requests returned by either capsule path still pass through the same host permit, argument constraints, budgets, and audit log as any model-provider proposal.

The host sends component input through stdin rather than process arguments to avoid command-line exposure and argument-length limits.

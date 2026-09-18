# WebAssembly Component Binding Contract

Portmark uses `wit/portmark.wit` as the source contract for Wasm decision providers. The default executable adapter uses a JSON-lowered binding for the WIT `resume(context-json, checkpoint-json)` export so the reference runtime can execute offline with Node's built-in WebAssembly engine. Deployments can also opt into native Wasmtime Component Model bindings with `--wasm-engine wasmtime`.

## Toolchain

- Contract: `wit/portmark.wit`
- Host bindings: `src/portmark/component_bindings.py`
- Runner: `src/portmark/wasm_runner.mjs`
- Optional native runner: `src/portmark/wasmtime_component_runner.py`
- Example core capsule source: `capsules/research-agent.wat`
- Example core capsule artifact for the Node runner: `capsules/research-agent.wasm.b64`
- Example Component Model capsule source: `capsules/research-agent.component.wat`
- Example Component Model artifact for native Wasmtime: `capsules/research-agent.component.wasm.b64`

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
instantiates the component bytes whose SHA-256 digest is recorded in the signed
manifest. Use `capsules/research-agent.component.wasm.b64` for the checked-in
example. The default `capsules/research-agent.wasm.b64` file is a core Wasm
module for the Node runner and native Wasmtime rejects it with a component
parser error.

### Native Wasmtime resource limits

Wasmtime applies its memory limit to **each linear memory separately**, not to their total. The
native provider therefore enforces three layers, and refuses at construction if they do not fit:

| Layer | Default | Enforced by |
|---|---|---|
| Size of each linear memory | 64 MiB (`max_memory_bytes`) | Wasmtime store limit |
| Instances / memories / tables / table elements | 8 / 2 / 4 / 10,000 | Wasmtime store limits |
| Whole worker process (Python, Wasmtime, JIT compiler, guest) | 512 MiB (`worker_memory_limit`) | `RLIMIT_AS` (POSIX) or a Job Object per-process memory limit (Windows) |
| Guest CPU | 1,000,000,000 fuel units | Wasmtime fuel |
| Worker CPU, including compilation | deadline + `RLIMIT_CPU` (POSIX) | OS |
| Workers running at once | 2 | provider-wide semaphore; waiting spends the same deadline |

The provider checks `max_memories × max_memory_bytes + 256 MiB worker baseline ≤ worker_memory_limit`.
The real example capsule needs 1 instance, 1 memory, 0 tables, and 64 KiB.

The OS ceiling is applied inside the worker after its trusted imports and **before** the Wasmtime
engine is built, so compilation runs capped. On POSIX the provider first proves that the platform
*enforces* the cap (a child caps itself and must fail to allocate past it). Where no enforced
ceiling is available, construction fails unless the operator passes
`allow_uncapped_worker=True`; each run is then logged as uncapped.

The engine configuration is explicit, not inherited from Wasmtime's defaults: single-threaded
compilation, deterministic relaxed SIMD, NaN canonicalization (results match across x86-64 and
AArch64), and threads, shared memory, memory64, multi-memory, GC, exceptions, stack switching, wide
arithmetic, and custom page sizes switched off.

## Default JSON-Lowered Capsule ABI

The default Node adapter expects a core Wasm module that exports:

- `memory`: WebAssembly memory used for string exchange.
- `resume(context_ptr: i32, context_len: i32, checkpoint_ptr: i32, checkpoint_len: i32) -> i64`

The returned `i64` is `(result_ptr << 32) | result_len`. The pointed-to bytes must be UTF-8 JSON matching one of the WIT outcomes.

The native Wasmtime provider expects a Component Model artifact and calls the
exported `resume(context-json, checkpoint-json)` function through
`wasmtime.component`. The checked-in component exports a lifted string-returning
`resume` function whose JSON output uses the same outcome decoder as the Node
path.

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

The default Node runner rejects every Wasm module declaring imports. Capsules therefore have no ambient filesystem, network, process, environment, clock, randomness, or credential access. Native Wasmtime deployments instantiate components through an empty `wasmtime.component.Linker`, so components requiring imports fail to instantiate. The regression suite proves both sides separately: the native component artifact runs successfully, and a different valid component that imports a host function is rejected after component parsing. Tool requests returned by either capsule path still pass through the same host permit, argument constraints, budgets, and audit log as any model-provider proposal.

The host sends component input through stdin rather than process arguments to avoid command-line exposure and argument-length limits.

# Portmark Runtime

This is a provider-neutral reference implementation of the architecture discussed in the accompanying conversation: an agent carries a signed manifest, permit, state checkpoint, and component identity; the destination host independently verifies it, intersects its authority with local policy, and mediates every tool invocation.

It runs entirely offline by default. The deterministic provider is for demonstrations and tests. `GenericHttpProvider` can connect the same runtime to llama.cpp, Ollama through an adapter, a hosted model gateway, or another provider that implements the small decision contract below.

## Security boundary

```text
A2A request / local CLI
        |
signed agent envelope
        v
Host verification -> permit intersection -> provider proposal
                                             |
                                 host validates every action
                                             v
                                  capability-scoped tools
```

The provider proposes actions but never receives host credentials and never authorizes its own tool calls. The host enforces subject, audience, expiry, replay nonce, tool grants, argument constraints, step budgets, tool-call budgets, output limits, and a hash-chained audit log.

Migration requires `delegation_allowed` on the incoming permit. The source host can then create only a narrower, one-hop, destination-bound permit: the effective grants and budgets cannot increase, the audience changes to the named destination, the replay nonce is replaced, and further delegation is disabled. Both hosts must belong to the same configured trust domain in this reference implementation.

Envelopes are signed with Ed25519 by default and verified through a key-ID-based trust registry. The legacy HMAC signer is retained only for explicit dependency-free demos and should not be used for production trust domains.

## Run it

No installation is required:

```powershell
$env:PYTHONPATH = "src"
python -m portmark.cli demo "research modern mobile agents"
```

Execute the included real Wasm capsule using Node's built-in WebAssembly engine:

```powershell
$env:PYTHONPATH = "src"
python -m portmark.cli --wasm-component capsules/research-agent.wasm.b64 demo "research modern mobile agents"
```

The host executes each capsule in a short-lived worker with a strict deadline and rejects every module declaring an import. The guest therefore has no filesystem, network, process, environment, clock, randomness, or credential access. Its signed SHA-256 digest is checked before execution. Tool actions returned by the capsule still pass through the same host permit and argument enforcement as model-provider proposals.

Run tests:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

Run the A2A-facing HTTP service:

```powershell
$env:PYTHONPATH = "src"
python -m portmark.cli serve --port 8080
```

The Agent Card is available at `/.well-known/agent-card.json`; signed envelopes are submitted to `/message:send`.

## Generic provider contract

Start the CLI with `--provider-endpoint URL`. The runtime sends:

```json
{"state": {"goal": "..."}, "available_tools": ["catalog.search"]}
```

The provider responds with one decision:

```json
{"kind": "tool", "tool": "catalog.search", "arguments": {"query": "...", "limit": 3}}
```

or:

```json
{"kind": "complete", "content": {"answer": "..."}}
```

`MODEL_PROVIDER_TOKEN` optionally supplies a bearer token. It is held by the host adapter, not included in the portable envelope.

## WebAssembly component boundary

[`wit/portmark.wit`](wit/portmark.wit) defines the Wasm Component Model interface. The capsule imports only `host-tools.invoke` and exports a checkpoint-based `resume` operation. A compiled capsule therefore cannot directly acquire filesystem, network, process, database, or credential access; the host must explicitly provide a mediated interface.

The runnable Node WebAssembly adapter uses the JSON-lowered WIT binding documented in [WASM_COMPONENTS.md](WASM_COMPONENTS.md). Strong migration is implemented as checkpoint-and-resume: native stacks, threads, sockets, and file descriptors never cross hosts.

## Production status

Portmark is reference-complete with six named substitution points. Signing and trust, transactional persistence, the A2A 1.0 surface, external policy with approval gates, WIT-shaped Wasm execution, and confidential-computing attestation are all implemented and covered by the regression suite. [PRODUCTION_TASKS.md](PRODUCTION_TASKS.md) holds the task-level record.

It is a reference implementation, not a drop-in production dependency. Production deployments should substitute environment-specific systems at these boundaries:

- Trust registry: replace the JSON registry with PKI- or KMS-backed key distribution and rotation.
- Storage: replace `SQLiteRuntimeStore` with a shared database for multi-host deployments.
- Wasm bindings: replace the JSON-lowered adapter with native Component Model bindings when the target runtime supports them.
- A2A types: replace the local generated-style subset with the official SDK when a Python package is published.
- Attestation: replace signed mock evidence with the target platform's TEE quote verifier and sealed-storage backend.
- Approvals: replace local signed approval tokens with an approval service tied to operator identity and change management.

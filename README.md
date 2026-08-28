# Portable Agent Runtime

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

Host policy can be loaded from JSON and every run records the active policy version and hash in the audit log. High-impact tools such as external payments, destructive actions, credentialed access, and data-exfiltration-risk actions require signed approval tokens bound to the task, permit nonce, tool arguments, and active policy hash. See [POLICY.md](POLICY.md) for the policy format, reload behavior, approval-token contract, and audit events.

Migration requires `delegation_allowed` on the incoming permit. The source host can then create only a narrower, one-hop, destination-bound permit: the effective grants and budgets cannot increase, the audience changes to the named destination, the replay nonce is replaced, and further delegation is disabled. Both hosts must belong to the same configured trust domain in this reference implementation.

Hosts can require signed confidential-computing attestation evidence before sensitive execution or delegated migration. The reference verifier binds the attested host identity, relying-party audience, approved measurement, freshness window, optional nonce, and verifier signature before the host runs the agent or emits a migration envelope. See [ATTESTATION.md](ATTESTATION.md) for the evidence format, verification flow, sealed-storage decision, and residual risks.

Envelopes are signed with Ed25519 by default and verified through a key-ID-based trust registry. See [SIGNING_KEYS.md](SIGNING_KEYS.md) for key generation, rotation, revocation, and trust bootstrap guidance. The legacy HMAC signer is retained only for explicit dependency-free demos.

## Run it

No installation is required:

```powershell
$env:PYTHONPATH = "src"
python -m portable_agent.cli demo "research modern mobile agents"
```

For normal package usage without setting `PYTHONPATH`, install the project:

```powershell
python -m pip install -e .
portable-agent demo "research modern mobile agents"
```

Execute the included Wasm capsule using the WIT-shaped `resume(context-json, checkpoint-json)` binding:

```powershell
$env:PYTHONPATH = "src"
python -m portable_agent.cli --wasm-component capsules/research-agent.wasm.b64 demo "research modern mobile agents"
```

The host executes each capsule in a short-lived worker with a strict deadline and rejects every module declaring an import. The guest therefore has no filesystem, network, process, environment, clock, randomness, or credential access. Its signed SHA-256 digest is checked before execution. Tool actions returned by the capsule still pass through the same host permit and argument enforcement as model-provider proposals. See [WASM_COMPONENTS.md](WASM_COMPONENTS.md) for the WIT binding contract.

Run tests:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

Run the A2A-facing HTTP service:

```powershell
$env:PYTHONPATH = "src"
python -m portable_agent.cli serve --port 8080
```

Require bearer authentication for A2A message submission:

```powershell
$env:PYTHONPATH = "src"
$env:PORTABLE_AGENT_A2A_TOKEN = "change-me"
python -m portable_agent.cli serve --port 8080
```

The Agent Card is available at `/.well-known/agent-card.json`; signed envelopes are submitted to `/message:send` with the A2A JSON-RPC `message/send` method. See [A2A.md](A2A.md) for the Agent Card fields, request shape, authentication profile, and error behavior.

Persist replay nonces, checkpoints, and audit heads with SQLite:

```powershell
$env:PYTHONPATH = "src"
python -m portable_agent.cli --store-path runtime.sqlite demo "research modern mobile agents"
```

See [RUNTIME_STORAGE.md](RUNTIME_STORAGE.md) for the storage schema, transaction guarantees, and recovery behavior.

Load policy from JSON:

```powershell
$env:PYTHONPATH = "src"
python -m portable_agent.cli --policy-path host-policy.json --reload-policy demo "research modern mobile agents"
```

See [OPERATIONS.md](OPERATIONS.md) for runtime configuration, trust registry format, policy updates, audit verification, backup/restore, and incident response.

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

[`wit/portable-agent.wit`](wit/portable-agent.wit) defines the Wasm Component Model decision interface. The capsule exports a checkpoint-based `resume` operation that receives structured context and checkpoint JSON and returns a structured outcome. A compiled capsule therefore cannot directly acquire filesystem, network, process, database, or credential access; the host must explicitly validate and mediate every requested action.

The runnable Node WebAssembly adapter uses the JSON-lowered WIT binding documented in [WASM_COMPONENTS.md](WASM_COMPONENTS.md). Strong migration is implemented as checkpoint-and-resume: native stacks, threads, sockets, and file descriptors never cross hosts.

## Production work still required

- Replace the in-memory demo trust registry with an externally managed production trust registry.
- Replace the JSON-lowered WIT adapter with native Component Model runtime bindings when the selected Python runtime exposes them.
- Replace the local SQLite storage backend with a production database for multi-host deployments.
- Replace the local A2A 1.0 generated-style type subset with an official generated SDK when the Python package is selected.
- Replace the reference mock attestation authority with the selected production TEE quote verifier.
- Replace demo approval authorities with production approval service integration.

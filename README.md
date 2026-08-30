# Portmark

[![CI](https://github.com/Itsthewayofyou/portmark/actions/workflows/ci.yml/badge.svg)](https://github.com/Itsthewayofyou/portmark/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Run someone else's AI agent on your machine without trusting it.**

An agent arrives as a signed envelope carrying its manifest, permit, state checkpoint, and
component identity. Your host verifies the signature itself, intersects the agent's requested
authority with your local policy, and mediates every single tool call. The agent's model
proposes actions; it never executes them and never sees your credentials.

## What the host is guaranteed

These are enforced by the host, not requested politely from the agent:

- **Your policy is a hard ceiling.** `effective_permit` intersects three sets: what the agent's
  manifest asks for, what its permit grants, and what your host policy allows. An agent arriving
  with a permit for `*` still gets only what you allow.
  ([`security.py`](src/portmark/security.py), `intersect_grants`)
- **Budgets take the minimum.** Steps, tool calls, and output bytes are each `min(agent, host)`.
  A visitor cannot raise its own limits. ([`models.py`](src/portmark/models.py), `ResourceBudget.intersect`)
- **Wasm capsules declaring any import are refused, not sandboxed.** The guest therefore has no
  filesystem, network, process, environment, clock, randomness, or credential access at all.
  ([`wasm_runner.mjs`](src/portmark/wasm_runner.mjs))
- **Permits can only narrow on migration.** One hop, bound to the named destination, grants and
  budgets cannot increase, and further delegation is disabled. A visiting agent cannot accept a
  narrow permit at your door and widen it on the next hop.
- **Every run is auditable.** A hash-chained audit log records the accepted agent, the active
  policy version and hash, each proposal, and each executed tool call.

Portmark runs entirely offline by default. The deterministic provider is for demonstrations and
tests. `GenericHttpProvider` connects the same runtime to llama.cpp, Ollama through an adapter, a
hosted model gateway, or anything implementing the small decision contract below.

## Quickstart

```bash
git clone https://github.com/Itsthewayofyou/portmark.git
cd portmark
PYTHONPATH=src python -m portmark.cli demo "research modern mobile agents"
```

No installation and no network access required. Examples below use bash; on PowerShell, write
`$env:PYTHONPATH = "src"` on its own line instead of the inline prefix.

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

The provider proposes actions but never receives host credentials and never authorizes its own
tool calls. The host enforces subject, audience, expiry, replay nonce, tool grants, argument
constraints, step budgets, tool-call budgets, output limits, and a hash-chained audit log.

Host policy can be loaded from JSON and every run records the active policy version and hash in
the audit log. High-impact tools such as external payments, destructive actions, credentialed
access, and data-exfiltration-risk actions require signed approval tokens bound to the task,
permit nonce, tool arguments, and active policy hash. See [POLICY.md](POLICY.md) for the policy
format, reload behavior, approval-token contract, and audit events.

Migration requires `delegation_allowed` on the incoming permit. The source host can then create
only a narrower, one-hop, destination-bound permit: the effective grants and budgets cannot
increase, the audience changes to the named destination, the replay nonce is replaced, and
further delegation is disabled. Both hosts must belong to the same configured trust domain in
this reference implementation.

Hosts can require signed confidential-computing attestation evidence before sensitive execution
or delegated migration. The reference verifier binds the attested host identity, relying-party
audience, approved measurement, freshness window, optional nonce, and verifier signature before
the host runs the agent or emits a migration envelope. Deployments can also configure a bounded,
shell-free external verifier command for platform quotes. See [ATTESTATION.md](ATTESTATION.md) for
the evidence format, verification flow, external-verifier contract, sealed-storage decision, and
residual risks.

Envelopes are signed with Ed25519 by default and verified through a key-ID-based trust registry.
See [SIGNING_KEYS.md](SIGNING_KEYS.md) for key generation, rotation, revocation, and trust
bootstrap guidance. The legacy HMAC signer is retained only behind
`PORTMARK_ALLOW_LEGACY_HMAC=unsafe-test-only` plus an explicit `PORTMARK_SIGNING_KEY`.

## Run it

Install the project for normal package usage:

```bash
python -m pip install -e .
portmark demo "research modern mobile agents"
```

Execute the included Wasm capsule using the WIT-shaped `resume(context-json, checkpoint-json)`
binding:

```bash
PYTHONPATH=src python -m portmark.cli --wasm-component capsules/research-agent.wasm.b64 demo "research modern mobile agents"
```

Deployments that install the optional native Wasmtime extra can select
`--wasm-engine wasmtime` to instantiate the signed component bytes through
`wasmtime.component` instead of the default Node runner:

```bash
python -m pip install -e '.[wasmtime]'
PYTHONPATH=src python -m portmark.cli \
  --wasm-component capsules/research-agent.component.wasm.b64 \
  --wasm-engine wasmtime \
  demo "research modern mobile agents"
```

The Node runner consumes `capsules/research-agent.wasm.b64`, which is a core
Wasm module. Native Wasmtime consumes
`capsules/research-agent.component.wasm.b64`, which is a Component Model
artifact.

The host executes each capsule in a short-lived worker with a strict deadline and rejects every
module declaring an import. Its signed SHA-256 digest is checked before execution. Tool actions
returned by the capsule still pass through the same host permit and argument enforcement as
model-provider proposals. See [WASM_COMPONENTS.md](WASM_COMPONENTS.md) for the WIT binding
contract. The included example capsule performs a projected `catalog.search` step and then
completes from checkpointed tool output.

Run tests:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Run the A2A-facing HTTP service (served by uvicorn on loopback; front it with a reverse proxy for TLS):

```bash
PYTHONPATH=src python -m portmark.cli serve --port 8080
```

Require bearer authentication for A2A message submission:

```bash
PORTMARK_A2A_TOKEN=change-me PYTHONPATH=src python -m portmark.cli serve --port 8080
```

The reference A2A server is loopback-only for public deployments.
Front it with a production HTTP proxy such as the Nginx example in
[`deploy/nginx/portmark.conf`](deploy/nginx/portmark.conf). Public interface
binds are refused; the legacy `--allow-direct-a2a` flag is accepted only for
configuration compatibility and does not bypass the loopback requirement. The
public Agent Card route is rate-limited separately from `/message:send`.

The Agent Card is available at `/.well-known/agent-card.json`; signed envelopes are submitted to
`/message:send` with the A2A JSON-RPC `message/send` method. See [A2A.md](A2A.md) for the Agent
Card fields, request shape, authentication profile, metrics endpoint, and error behavior.

To validate the Agent Card and request shape through the official SDK types,
install `portmark[a2a]` and run `serve --a2a-adapter sdk`. The local adapter
remains the default so base installs do not pull the SDK dependency tree.

Persist replay nonces, checkpoints, and signed audit heads with SQLite:

```bash
PYTHONPATH=src python -m portmark.cli --store-path runtime.sqlite demo "research modern mobile agents"
```

See [RUNTIME_STORAGE.md](RUNTIME_STORAGE.md) for the storage schema, transaction guarantees,
signed-head audit verification, and recovery behavior.

Load policy from JSON:

```bash
PYTHONPATH=src python -m portmark.cli --policy-path examples/host-policy.json --reload-policy demo "research modern mobile agents"
```

See [OPERATIONS.md](OPERATIONS.md) for runtime configuration, trust registry format, policy
updates, audit verification, backup/restore, and incident response.

## Generic provider contract

Start the CLI with `--provider-endpoint URL`. The runtime sends:

```json
{
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

`state.messages` contains only host-policy-projected tool output from prior steps. The host never
sends raw checkpoint `memory` or `result` fields to remote providers. Configure per-tool sharing
with `output_projection` in host policy; omit it or set `[]` to share no output, use top-level
field names such as `["id", "title"]` for dict outputs or lists of dicts, and use `["*"]` only
for tools whose full output may be sent to the provider.

The provider responds with one decision:

```json
{"kind": "tool", "tool": "catalog.search", "arguments": {"query": "...", "limit": 3}}
```

or:

```json
{"kind": "complete", "content": {"answer": "..."}}
```

`MODEL_PROVIDER_TOKEN` optionally supplies a bearer token. It is held by the host adapter, not
included in the portable envelope.

## WebAssembly component boundary

[`wit/portmark.wit`](wit/portmark.wit) defines the Wasm Component Model decision interface. The
capsule exports a checkpoint-based `resume` operation that receives structured context and
checkpoint JSON and returns a structured outcome. A compiled capsule therefore cannot directly
acquire filesystem, network, process, database, or credential access; the host must explicitly
validate and mediate every requested action.

The default runnable Node WebAssembly adapter uses the JSON-lowered WIT binding documented in
[WASM_COMPONENTS.md](WASM_COMPONENTS.md). An optional native Wasmtime provider can execute
the signed Component Model artifact in a short-lived Python worker when `portmark[wasmtime]` is
installed. Strong migration is implemented as checkpoint-and-resume: native stacks, threads,
sockets, and file descriptors never cross hosts.

## Production status

Portmark is **reference-complete with six named substitution points**. Signing and trust,
transactional persistence, the A2A 1.0 surface, external policy with approval gates, WIT-shaped
Wasm execution, and confidential-computing attestation are all implemented and covered by the
regression suite. [PRODUCTION_TASKS.md](PRODUCTION_TASKS.md) holds the task-level record.

It is a reference implementation: read it, fork it, and substitute the seams below. It is not
intended as a drop-in production dependency.

## Deployment integration points

Portmark is provider-neutral by design. The following are deliberate seams for the deploying
environment to fill, not unfinished work. Each has a working reference implementation and a
stable interface to substitute against.

| Seam | Reference implementation | What a production deployment supplies |
| --- | --- | --- |
| Trust registry | JSON registry loaded from `PORTMARK_TRUST_REGISTRY_PATH`, with key IDs, issuers, audiences, validity windows, and revocation | PKI- or KMS-backed key distribution and rotation |
| Storage | `SQLiteRuntimeStore` behind the `RuntimeStore` protocol | a shared database for multi-host deployments |
| Wasm bindings | WIT contract executed through a JSON-lowered adapter on Node, with optional native Wasmtime Component Model execution | deployment-selected Wasmtime version and component build pipeline |
| A2A types | generated-style A2A 1.0 subset isolated in `a2a_types.py`, with optional `a2a-sdk` validation | deployment-selected official SDK/server integration |
| Attestation | signed mock evidence and optional external verifier command checked by `AttestationPolicy` against RATS-style roles | the target platform's TEE quote verifier and sealed-storage backend |
| Approvals | locally signed approval tokens bound to task, nonce, arguments, and policy hash | an approval service tied to operator identity and change management |
| Metrics | in-process `RuntimeMetrics` counters attached to `AgentHost`, exposed on authenticated loopback `GET /metrics` | deployment metrics/export pipeline and authenticated proxy policy |

## License

MIT. See [LICENSE](LICENSE).

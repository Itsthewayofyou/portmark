# MCP Tools

Portmark can call tools that live in an **MCP server** (Model Context Protocol). It is an MCP
**client**, not a gateway: an MCP tool is registered in the ordinary `ToolRegistry` and passes the same
gates as any other tool — the permit, the host policy, the argument constraints, the budgets, the effect
ledger, and the audit chain. There is no second enforcement path.

This page is the wire contract and the trust model. Operator steps are in OPERATIONS.md; the tool
contract itself is in TOOLS.md.

Spec facts below were read from the Model Context Protocol specification on **2026-09-23**.

## What Portmark trusts

An MCP server is a **remote party**, even when it runs as a local subprocess. Nothing it says is authority:

- **Tool definitions are pinned.** The operator approves a tool once, as the SHA-256 of its canonical
  definition. A definition that changes later (the "rug pull") is refused at startup **and** at every call.
- **The launch configuration is pinned too.** A pin approves a tool *definition*, not the program that reports
  it. The host records a digest of each server's `command`, `args`, `secret_env` and timeout at start-up, and
  the worker re-checks it, so editing the config file afterwards cannot make an approved pin launch something
  else.
- **Annotations are ignored.** The MCP specification says a client "MUST consider tool annotations to be
  untrusted unless they come from trusted servers", so `readOnlyHint` and friends never affect anything.
  Only the operator's own `read_only: true` marks a tool as free of side effects.
- **Descriptions never reach the model.** Portmark's providers receive tool **names** only
  (`decide(view, available_tools)`), so a poisoned description or schema cannot steer the model.
- **The server gets no credential** the operator did not name in `secret_env`. It does inherit a small
  baseline so an ordinary program can run at all: `PATH`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TMPDIR`, `TEMP`,
  `HOME`, `USERPROFILE`, `SYSTEMROOT`. Nothing else of Portmark's environment reaches it — not its store path,
  its keys, or even the pin it is being checked against.
- **A tool result is data, not instructions.** It is capped, encoded, and handed back exactly like any
  other tool's output.

## Which protocol versions Portmark speaks

MCP changed shape in revision **2026-07-28** ("modern"): there is no `initialize` handshake, every request
carries its own metadata, and servers **MUST** implement `server/discover`. Revisions **2025-11-25** and
earlier ("legacy") use the `initialize` handshake. Portmark speaks both, and asks a legacy server for the
revision it advertised — or, when the probe said nothing, for the newest legacy revision Portmark speaks
(2025-11-25), never the oldest.

Every modern request carries:

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {
  "io.modelcontextprotocol/protocolVersion": "2026-07-28",
  "io.modelcontextprotocol/clientInfo": {"name": "portmark", "version": "0.9.2"},
  "io.modelcontextprotocol/clientCapabilities": {}
}}}
```

`io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities` are required on
every request; a missing field is answered with `-32602`.

**Era probe (stdio), as the specification prescribes.** Portmark sends `server/discover` first:

- a `DiscoverResult` → the server is modern; Portmark picks a version from `supportedVersions`;
- `UnsupportedProtocolVersionError` (`-32022`) → modern; Portmark retries with a version from `data.supported`;
- any other error, or no answer in time → legacy; Portmark falls back to `initialize` +
  `notifications/initialized`;
- **the server exits** (some legacy servers do, on an unknown pre-`initialize` request) → Portmark starts a
  **fresh** process and goes straight to `initialize`, because the dead one cannot answer anything.

If the server answers `initialize` with a revision Portmark does not speak, Portmark disconnects rather than
continue — the 2025-11-25 schema requires exactly that.

The fallback is never keyed to one error code, because legacy servers answer an unknown pre-`initialize`
method with whatever they like. A result with no `resultType` is treated as `"complete"`, which is what the
specification requires for older servers.

## Transport: stdio

- Newline-delimited JSON-RPC, one message per line, no embedded newlines. A message is bounded **as it
  arrives**: a server that never sends a newline is cut off at 1 MiB, not read until memory runs out.
- `stdout` carries MCP messages only; `stderr` is logging and is **not** treated as an error signal.
- Portmark never writes a JSON-RPC **response** to the server, and refuses any JSON-RPC **request** the
  server writes to `stdout` (the specification forbids it). A server-to-client interaction arrives as an
  `input_required` result instead, and Portmark treats that as a tool failure: a mediated tool call has no
  side channel to a human.
- Shutdown is the specification's: close stdin, wait, then terminate the process tree.

Streamable HTTP servers are **not** in this release; see "Not included" below.

## How an MCP tool runs

A stdio MCP server is launched **per call, inside Portmark's isolated tool worker**, so the existing
deadline and process-tree kill cover the server process too. The worker:

1. reads the operator config, the approved pin and the approved launch digest from its environment;
2. launches the server, probes the era, and calls `tools/list`;
3. re-checks the pin of the tool it is about to call, and refuses on any drift;
4. calls `tools/call`, maps the result, and exits.

The cost is one server start and one handshake per call. That is deliberate: a long-lived server would
outlive the deadline that makes a side-effecting tool safe to run. (`debt:` about 0.3–2 s per call; upgrade
to a pooled session, outside the effect path, when a real workload shows the handshake above 20% of run time.)

## Side effects

The MCP protocol cannot tell Portmark whether a tool changes the world, and a network call cannot be
cancelled once it is in flight. So:

- a tool is treated as **side-effecting** unless the operator sets `read_only: true` for it;
- a side-effecting tool needs a `reconcile` target, as every side-effecting tool does (TOOLS.md), and the
  registry refuses to register one without it;
- a timeout, a killed worker, or a broken connection settles the effect as **unknown**, and the reconcile
  pass resolves it.

A reconcile target is a `module:function` the operator writes. An MCP tool cannot be one directly: the
host's reconcile contract is `{"landed": bool, "result"?: …}`, and a foreign tool answers with free content,
so an adapter has to turn one into the other. The adapter may of course ask the MCP server. As with every
reconcile, the runtime cannot prove that the target only observes; keeping it read-only is the operator's
contract, and the registry only enforces that it is a different function from the tool.

## Names

A tool is registered as `mcp.<server>.<tool>`, or under the operator's `alias`. The final registered name
obeys Portmark's tool-name rule (POLICY.md): 1 to 192 characters, letters, digits and inner `.`, `_`, `-`,
starting and ending on a letter or digit. A server label is at most 32 characters and MCP allows at most 128
for a tool name, so a generated name is at most 165 — length never forces an alias. What does is a server
tool whose name starts or ends on `.`, `_` or `-`: MCP permits it, Portmark does not, and such a name is
**refused, never trimmed**. Give that tool an `alias`.
A name that collides with a tool already registered is refused too, so a server cannot shadow a built-in tool.

## Configuration

`--mcp-config mcp.json`. Unknown keys are refused.

```json
{
  "schema": "portmark.mcp.config.v1",
  "servers": {
    "files": {
      "command": "/usr/local/bin/mcp-files",
      "args": ["--root", "/srv/data"],
      "secret_env": ["FILES_API_TOKEN"],
      "timeout_seconds": 20,
      "tools": {
        "read_file": {"pin": "sha256:…", "read_only": true},
        "write_file": {"pin": "sha256:…", "reconcile": "my_adapters:file_written", "alias": "files.write"}
      }
    }
  }
}
```

`portmark mcp pin` and the start-up check both run the probe in a **killable process tree**, so a server that
never answers is stopped with the probe instead of being left behind.

- `pin` is the SHA-256 of the tool's canonical definition: the WHOLE definition object the server reports,
  minus protocol `_meta`. Not a chosen list of fields, because a list would silently ignore any field a
  later MCP revision adds -- which is the drift a pin exists to catch. A cosmetic change (a description, an
  icon) therefore needs the operator to approve the tool again. `portmark mcp pin --mcp-config mcp.json`
  prints the current definitions and their hashes to paste in. It never writes them itself: approving a
  tool is a human act.
- `read_only: true` is the operator's own statement, never the server's annotation.
- `reconcile` names a `module:function` (see "Side effects"). It is required unless `read_only` is true.
- `secret_env` names host environment variables to pass to the server process, on top of the small baseline
  listed under "What Portmark trusts". Nothing else of Portmark's environment is inherited.
- A tool that is not listed is not registered. There is no "expose everything" switch.

## Audit and export

An MCP tool produces the same events as any other tool (`provider.proposed`, `tool.executed`,
`tool.failed`, `tool.killed`, `tool.refused`, `tool.replayed`). There are no new event kinds, so there is
one source of truth per run. A failed MCP call adds one field to `tool.failed`: `error_code`. The server
name and the pin are not repeated in the audit chain -- the registered tool name already identifies the
server, and the pin is in the operator's config.

A tool may report only the codes its **registration** allows (`register_isolated(error_codes=...)`), so no
other installed tool can forge an MCP failure into the audit chain or into whatever alerts on it.

`error_code` separates failures that look alike from outside:

| code | meaning |
| --- | --- |
| `mcp_tool_error` | the server answered `isError: true` — the tool ran and failed |
| `mcp_transport_error` | the connection, framing or protocol failed — the effect is **unknown** |
| `mcp_pin_drift` | the tool's definition no longer matches its approved pin |
| `mcp_config_drift` | the config file changed after start-up: another pin, or another program to launch |
| `mcp_protocol_error` | a malformed or forbidden message, including a server-to-client request |

Server start-up and pin checks happen outside any task, so they are not audit events: they are startup log
lines, and `portmark mcp pin` reports them.

For the SIEM export (OPERATIONS.md), every MCP tool is `hash_only` until the operator names it in the
projection policy: argument names of a foreign tool are as model-chosen as the values.

## Not included in this release

- **Streamable HTTP servers** (and therefore OAuth-protected remote servers). The native client covers
  stdio first; HTTP with a static bearer token follows, and OAuth only through the official SDK as an
  optional extra (owner decision D1).
- MCP resources, prompts, sampling, subscriptions, and `notifications/tools/list_changed`: a pin is
  re-checked at every call, so a changed list is an error rather than an event to follow.
- Portmark as an MCP **server**.

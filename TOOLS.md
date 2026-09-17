# Installing Tools

Portmark tools are host-side capabilities. An agent or provider can ask for a
tool, but only the host installs it, grants it through policy, checks its
arguments, enforces budgets, and decides what output a remote provider may see.

## Register A Tool

Create a Python module that returns a `ToolRegistry`:

```python
# my_tools.py
from portmark.tools import ToolRegistry


def registry() -> ToolRegistry:
    tools = ToolRegistry()

    def search(arguments: dict) -> list[dict]:
        query = str(arguments["query"])
        limit = int(arguments["limit"])
        return [{"id": "doc-1", "title": f"Result for {query}"}][:limit]

    tools.register("catalog.search", search, timeout=2.0)
    return tools
```

Load it with `--tools module:function`:

```bash
PYTHONPATH=src:. python -m portmark.cli \
  --policy-path host-policy.json \
  --tools my_tools:registry \
  demo "find records"
```

The loader is a Python import path, not a shell command. The named object may be
a `ToolRegistry` or a zero-argument function that returns one. Anything else is
rejected before the host starts.

## Example HTTP Fetch Tool

Portmark includes one opt-in side-effecting example:
`examples.tools.http_fetch:registry`. It installs `http.fetch`, a bounded HTTPS
GET tool. It is not loaded by default.

```bash
PYTHONPATH=src:. python -m portmark.cli \
  --policy-path examples/http-fetch-policy.json \
  --tools examples.tools.http_fetch:registry \
  demo "fetch an allowlisted page"
```

The example tool enforces a fixed GET method, HTTPS URLs, no URL userinfo, no
redirect following, a two-second network timeout, and a 65 KiB response cap. The
allowlist belongs in host policy with URL constraints such as `scheme`,
`allowed_hosts`, or `allowed_domains`; provider-supplied arguments cannot expand
that allowlist.

## Grant Tools In Policy

Installing a tool does not grant it. The host still intersects the agent
manifest, signed permit, and local host policy before every call. If a custom
tool is not present in policy, the effective permit drops it and the host denies
the call.

Example policy:

```json
{
  "version": "policy-v1",
  "budget": {"max_steps": 10, "max_tool_calls": 5, "max_output_bytes": 65536},
  "tools": {
    "catalog.search": {
      "impact": "low",
      "constraints": {
        "arguments": {
          "query": {"type": "string", "max_length": 200},
          "limit": {"type": "integer", "minimum": 1, "maximum": 5}
        },
        "required": ["query", "limit"],
        "additional_arguments": false
      },
      "output_projection": ["id", "title"]
    }
  }
}
```

`--policy-path` is required when `--tools` is used so custom capabilities cannot
be loaded under the demo-only default policy by accident.

## How Two Constraint Sets Combine

When the manifest, the permit, and the host policy all constrain the same tool,
their constraints are merged. The merge only ever narrows: anything the merged
constraints accept is accepted by every input. A merge that cannot be proven
narrower drops the grant rather than guessing.

Per key:

| Key | Combined as |
| --- | --- |
| `minimum`, `min_length` | the larger of the two |
| `maximum`, `max_length` | the smaller of the two |
| `enum`, `allowed_schemes`, `allowed_hosts`, `allowed_domains` | set intersection; empty drops the grant |
| `const`, `pattern`, `scheme` | must be identical, or the grant is dropped |
| `type` | set intersection of the type lists; empty drops the grant |
| `required` | required if either side requires it |
| `additional_arguments` | permissive only if BOTH sides admit extra names; a bounded side wins |
| flat `max_x` | the smaller of the two |
| flat `allowed_x` | set intersection; empty drops the grant |
| anything else | drops the grant |

An argument named by only one side keeps that side's constraint — more
constraint is narrower.

**Deny-by-default on argument names.** A grant that constrains *any* argument
(an `arguments` schema, `required`, or a legacy `max_`/`allowed_`/exact key)
thereby turns the set of argument **names** into a whitelist: only the names it
mentions may reach the tool, and an unknown field (a `recipient` slipped in by a
prompt injection) is rejected — no `additional_arguments: false` needed. Set
`additional_arguments: true` to opt a grant back out and admit any name. A
constraint set that constrains *nothing* means one of two things by origin: from a
**host policy** it now denies unnamed arguments (a bare policy grant admits no
arguments — name them, or set `additional_arguments: true`); from a **permit** it
stays a pure capability passthrough that never bounds the intersection. (The
manifest's requested tools are a name filter, not grants of this shape: they gate
which tool names may run without contributing any argument policy, so every empty
grant in the intersection comes from a permit or the host policy — and a policy's
is normalized to an explicit deny at construction.) When names are bounded, they are intersected first and every
key is gated on the result; a constraint naming an argument the other side would
have refused drops the grant, because every flat constraint also requires its
argument to be present, and the combination is then unsatisfiable.

**One consequence worth stating:** if a policy bounds only *some* of a tool's
arguments, the unbounded-but-legitimate ones are now rejected too. List every
argument name the tool legitimately takes (in the `arguments` schema, or via the
legacy keys), or set `additional_arguments: true` — otherwise a valid call is
refused as an unsupported field.

Three cases are deliberately conservative, and drop a grant that could in
principle have been merged:

- `"integer"` against `"number"` intersects to empty. Ranking the numeric tower
  is not worth the risk of getting the direction backwards.
- `allowed_domains: ["example.com"]` against `["api.example.com"]` intersects to
  empty, even though the second is a subdomain of the first.
- An unrecognised key drops the grant. A key added in a later version could mean
  "relax", and copying it across would create authority.

**Practical advice: constrain each argument in one place.** Putting the same
argument's bounds in both the permit and the host policy works only when the two
narrow cleanly; putting them in one place always works. If a grant disappears,
the host's error names the key that failed to combine.

## Output Projection

Tool return values are stored in the full local checkpoint, but the host applies
the grant's `output_projection` before the state reaches **any** provider — a
remote adapter and an in-process provider alike. A provider reading
`state.memory["tool_results"]` therefore sees only the projected fields, never
the full stored result:

- omit `output_projection`, or set it to `[]`, to share no tool output
- use field names such as `["id", "title"]` for dict outputs or lists of dicts
- use `["*"]` only when the full output is acceptable provider input

Projection is configured in host policy because the operator, not the agent,
owns the data-sharing decision. Host policy is the ceiling: a policy grant that
omits `output_projection` shares nothing, regardless of what the permit requests.

**Provider authors:** the projected `tool_results` keeps each tool's key with a
reduced value, so `"tool" not in results` remains a correct "have I run this yet"
check. But a value projected to `{}` (or `[]`) is *falsy* — test key **presence**,
not truthiness, or a re-proposal guard like `if not results.get("tool")` can loop.

## Isolated Tools (Resource-Bounded, Hard-Deadline Executor)

> **What this executor is, and is not.** The isolated executor is a
> **resource-bounded, hard-deadline worker. It is NOT a hostile-code sandbox.**
> It runs the tool as the **same OS user**, in the host's working directory, with
> normal filesystem and network access, so a hostile tool can still read
> host-accessible files (including the parent's `/proc/<pid>/environ`) and open
> sockets. What isolation buys you is a hard wall-clock deadline, a separate
> process to terminate at that deadline, a minimal inherited environment, bounded
> output, and defense-in-depth kernel resource caps — **not** containment of
> attacker code. **Running an untrusted or hostile tool safely requires an
> OS/container isolation profile supplied by the deployment** (a separate uid,
> filesystem namespaces, a PID namespace + cgroup, a network policy, restricted
> `/proc`). See THREAT_MODEL.md and the "Tool Isolation Requirement" in
> DEPLOYMENT.md. Isolating a tool is *not*, by itself, the answer to "this tool is
> untrusted."

By default a tool runs in-process on a worker thread. That path cannot cancel a
tool once it has started: if the deadline fires, the host records failure but the
thread keeps running. To keep such leaked threads bounded, `ToolRegistry` caps how
many thread-path executions may be in flight at once (`max_inflight_threaded`,
default 64); beyond the cap a tool invocation fails closed. Any tool with a side
effect, or any tool that may run long, must be registered isolated so the host can
enforce its deadline in a separate process — and an untrusted tool must ALSO run
under the deployment isolation profile above, because the isolated worker alone
does not contain it:

```python
tools.register_isolated(
    "http.fetch",
    "examples.tools.http_fetch:fetch",   # module:function, resolved in the worker
    timeout=3.0,
    side_effecting=True,
    env={"HTTPS_PROXY": "http://proxy.internal:8080"},  # optional, off by default
)
```

An isolated tool is named by an import path, not a callable, because it runs in a
fresh Python process (`portmark.tool_subprocess_runner`) that imports the target
itself. The process talks to the host with one JSON document each way and nothing
else. What this buys you:

- **Deadline termination.** At the deadline the host terminates the worker's
  process tree -- the thread path cannot do this at all. **The strength of that
  termination is platform-dependent, and on POSIX it is best-effort, not a
  guarantee** (see "Platform support" below). Keep this in mind for what the tool
  may spawn.
- **Minimal *inherited* environment.** The worker inherits only a small allowlist
  (`PYTHONPATH`, `PATH`, locale, `SYSTEMROOT`). Host secrets in the environment
  (API keys, tokens, database URLs) are **not** passed as the child's environment.
  Add exactly what the tool needs with `env=`; nothing else crosses. This is not
  secrecy: because the worker runs under the same uid, a hostile tool can still
  read the parent's `/proc/<pid>/environ` and any credential file on disk. Only
  OS-level isolation (a separate uid, restricted `/proc`) hides those.
- **Bounded output.** The worker refuses output over the budget before sending it,
  and the host reads bounded, so a tool cannot balloon host memory.
- **Defense-in-depth resource caps.** On POSIX the worker applies kernel `setrlimit`
  caps (address space, CPU time, file size, open files) handed to it by the host --
  a backstop against runaway memory / CPU / disk / fd use. These are POSIX-only and
  do not constrain the network, so they are defense in depth, not a boundary. They
  now also bound the tool's *module import* (see the note under "Configuring the
  caps"), so a heavy tool module may need `address_space` raised.

Only an isolated tool may be `side_effecting=True`. A side-effecting tool
registered on the plain thread path is refused, because that path cannot be
cancelled.

**Platform support — and the honest difference between the two backends.** Deadline
termination needs *some* primitive to reach the worker's descendants. The two
platforms are NOT equivalent:

- **Windows (genuine whole-tree termination).** A Job Object
  (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`): the worker is created suspended, assigned
  to the job before it can spawn anything, then resumed, so a descendant **cannot**
  break away, and `TerminateJobObject` reaps the whole tree as one unit.
- **POSIX (cooperative, best-effort — NOT containment).** A session +
  `os.killpg` signals the worker's process group. A well-behaved descendant that
  stays in the group is reached; but a descendant that calls
  `setsid()`/`start_new_session()` moves to its own group and **escapes the signal
  and keeps running**. A background child left in the group after a **normal** worker
  exit is swept at the source — the worker `SIGKILL`s its own process group before it
  exits — so it no longer outlives a clean exit; the residual escapees are a `setsid()`
  child and a worker that dies before it can sweep. So on POSIX the host still does
  **not** guarantee the tool and everything it spawned actually stop.

`register_isolated(..., side_effecting=True)` is allowed on both platforms because
*a* termination primitive exists on both; it is **refused at registration** only on
a platform with neither. That gate is about primitive existence, **not** a promise
of hostile-tool containment — which POSIX does not provide. Real containment of an
untrusted side-effecting tool comes from the deployment isolation profile plus the
tool's own idempotency/reconciliation, covered in DEPLOYMENT.md and THREAT_MODEL.md.
CI runs the isolated-tool descendant-kill, side-effecting, and kill-audit tests on
both Linux and Windows.

**Two honest limits.** (1) *Escape:* on POSIX a descendant that moves to its own
process group — via `setsid()`/`start_new_session()` or `setpgid()`/`setpgrp()` —
escapes the group signal (a background child of a *normally-exiting* worker is swept
by the worker itself, and the host verifies that self-sweep ran before accepting the
reply, so the residual escapees are a new-group child and a worker that dies before
its sweep). (2) *In-flight effect:* even where termination reaches the tool, it cannot undo a
side effect already sent when the deadline fires — a payment request already sent is
already sent. When the host terminates a tool it audits `tool.killed` with
`effect_status: "unknown"`, distinct from a clean `tool.failed`, so the audit trail
never claims an effect did not happen when it might have. Keep tool deadlines
comfortably above normal completion time so termination is the rare exception.

Termination is **verified only for the root, not asserted for the tree**: after
issuing the terminate the host waits for the worker (the root) to exit, and if that
cannot be confirmed it raises `ToolExecutionError` ("process tree could not be
confirmed terminated") rather than reporting a clean kill. On Windows the Job Object
makes root-exit equivalent to tree-exit; on POSIX it does not — an escaped `setsid()`
descendant can still be running after the root is confirmed dead. The host confirms
what it can (the root) and does not overclaim the rest.

**Configuring the caps.** `ToolRegistry(resource_limits={...})` overrides the
POSIX resource caps applied inside each worker. Keys: `address_space` (RLIMIT_AS,
virtual memory), `file_size` (RLIMIT_FSIZE), `open_files` (RLIMIT_NOFILE), and
`processes` (RLIMIT_NPROC — off by default because it is *per-uid*: a fixed cap
breaks `fork()` on a busy shared host; set it only when tools run under a dedicated
uid). Overrides are **validated at construction and MERGED over the defaults** — an
unknown key (e.g. a typo `adress_space`) or a non-positive value raises immediately,
and setting one key keeps the other default caps rather than silently dropping them.
`cpu_seconds` cannot be set here; it is derived per invocation from each tool's own
timeout as a deadline backstop. To turn the exhaustion caps OFF entirely, pass
`ToolRegistry(disable_resource_limits=True)` — an explicit switch, not an overloaded
empty dict; the CPU-time backstop still applies.

> **Behavior note:** the caps are applied **before the tool's module is imported**
> (so a hostile module body runs already capped), which means `address_space` and
> `cpu_seconds` now also bound module *import*. A tool whose module reserves a lot of
> virtual address space at import (large mmap-backed libraries) may need
> `address_space` raised. An AS/CPU limit that fires during import surfaces to the
> host as a worker that produced no response — raise the cap if a heavy tool module
> fails to load.
>
> **Fail-closed, not best-effort:** applying the caps is fail-closed. If a requested
> cap cannot be put in force — an unsupported limit on this platform, or a `setrlimit`
> that is rejected — the worker **refuses to run the tool** and returns
> `worker could not apply resource limits: <names>`, rather than silently running it
> under weaker caps than you configured. On Linux (the supported POSIX target) all of
> these limits apply, so this refusal only fires on a genuinely unsupported platform
> or an impossible value.

## Side-Effecting Tools And The Effect Ledger

A tool registered `side_effecting=True` (which must be isolated) runs under a durable **effect
ledger** so a crash-and-resume never re-applies an external effect it cannot be sure landed.

**How it works.** Before the tool launches, the host derives an **effect id** — a hash of
`(task_id, per-call sequence)`, i.e. the logical call **position** (deliberately *not* the tool or
arguments, so the invariant is **at most one effect per position** and provider drift cannot mint a
second effect at a position whose first effect is unresolved) — and records a `prepared` row, then
advances it to `started` immediately before launch. After the call it settles the row:

- **success → `confirmed`** (the result is stored; a later call at the same position with the **same
  tool and arguments** *replays* it instead of running the tool again). A call that re-proposes the
  position with a **different tool or different arguments** is **drift**: the host **refuses** it — it
  never replays another call's recorded result and never re-runs at a bound position. A deterministic
  resume re-proposes the same tool+args and replays cleanly; a drifted re-proposal hard-fails the task,
  and reconcile (or a fresh call) resolves it;
- **killed at the deadline → `unknown`**, and a **clean tool error → `unknown` too** — because the
  effect may have landed before the tool reported failure;
- a non-serializable result → `unknown`.

On a resume, the same logical call re-derives the **same** effect id (the sequence is the
per-task `tool_calls`, rebound from the durable checkpoint, monotonic and never reset — it is
deliberately **not** bound to the checkpoint generation, which identifies the run, not the call).
The host then: replays a `confirmed` effect; proceeds for a `prepared` row (a prior attempt never
launched); and **refuses** a `started`/`unknown`/`reconciled` row — it **never auto-retries** an
effect whose status is unknown, because a second run could double a real effect. On a `confirmed` or
`prepared` row the host also checks the current decision's tool + arguments against the row's recorded
tool + arguments and **refuses on any drift** — it never replays another call's result or re-runs at a
bound position.

**The invoke gate is un-forgeable.** `ToolRegistry.invoke` runs a side-effecting tool only for an
`effect_id` the host has recorded and marked `started` in the ledger — it checks that at the gate via
a host-injected predicate (`bind_effect_ledger`), so a **caller-fabricated id cannot authorize a
side-effecting call**. No id, an unbound registry, or an id that names no started row all fail closed.

**The tool contract.** A side-effecting tool is called as `tool(arguments, effect_id)` and **must
use the `effect_id` as its idempotency key** with the external system (e.g. a payment idempotency
key), so that even a retry it does see cannot double the effect. A tool that does not accept a
second parameter is failed with a controlled `tool does not accept effect_id` and never called.

```python
def charge(arguments: dict, effect_id: str) -> dict:
    return payment_api.charge(arguments["amount"], idempotency_key=effect_id)

tools.register_isolated(
    "billing.charge", "mytools:charge",
    side_effecting=True,
    reconcile="mytools:reconcile_charge",  # queries whether the effect landed
)
```

**Reconciliation.** An `unknown` effect is resolved by `AgentHost.reconcile_effect(effect_id,
task_id)` (task-scoped: the effect must belong to that task). It runs the tool's registered
`reconcile` function — `reconcile(arguments, effect_id) -> {"landed": bool, "result"?: ...}` —
which asks the external system whether the effect landed: a landed effect settles to `confirmed`
(with the reconciled result), a not-landed effect to `reconciled` (terminal; a retry is a fresh
call). The host never auto-retries; the operator drives reconciliation.

> **Known cost.** The `started` state is settled `unknown` on resume even if the tool never
> actually launched (a crash in the microsecond window between the durable `started` write and the
> launch). That is the conservative choice — an operator pays one reconcile round-trip for an
> effect that did not happen, rather than the host silently assuming it did not and re-running.

> **Not yet enforced here.** PR 2a ships the ledger and the reconcile mechanism; making the
> `reconcile` contract and an acknowledged isolation profile **mandatory** at registration for
> `side_effecting=True` is the immediately following change (Section 7 PR 2b). Until then a
> side-effecting tool may be registered without a `reconcile` function, and its `unknown` effects
> cannot be reconciled.

## Credential Handling

Tools may use local credentials internally, but returned data is audit material
and may become provider context if policy projects it. Do not return secrets,
tokens, connection strings, raw authorization headers, cookies, or credentialed
client objects from a tool. Return stable identifiers or redacted summaries, and
keep credentials inside the tool implementation.

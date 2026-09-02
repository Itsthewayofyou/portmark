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
| `additional_arguments` | `false` if either side says `false` |
| flat `max_x` | the smaller of the two |
| flat `allowed_x` | set intersection; empty drops the grant |
| anything else | drops the grant |

An argument named by only one side keeps that side's constraint — more
constraint is narrower. But `additional_arguments: false` turns the set of
argument **names** into a whitelist, so those names are intersected first and
every key is gated on the result. A constraint naming an argument the other side
would have refused drops the grant, because every flat constraint also requires
its argument to be present, and the combination is then unsatisfiable.

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

Tool return values are stored in the local checkpoint, but remote providers do
not automatically receive that full checkpoint. Provider context is built from
projected tool messages:

- omit `output_projection`, or set it to `[]`, to share no tool output
- use field names such as `["id", "title"]` for dict outputs or lists of dicts
- use `["*"]` only when the full output is acceptable provider input

Projection is configured in host policy because the operator, not the agent,
owns the data-sharing decision.

## Credential Handling

Tools may use local credentials internally, but returned data is audit material
and may become provider context if policy projects it. Do not return secrets,
tokens, connection strings, raw authorization headers, cookies, or credentialed
client objects from a tool. Return stable identifiers or redacted summaries, and
keep credentials inside the tool implementation.

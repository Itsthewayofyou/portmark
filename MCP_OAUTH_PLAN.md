# MCP OAuth for HTTP servers — plan (decision D1, user-delegated flow)

Owner decision, unchanged: **Portmark does not write OAuth.** The official SDK arrives as an exactly-pinned
optional extra (MCP_SIEM_PLAN.md, D1, 2026-09-22). Owner input 2026-09-24: the target is a **user-delegated**
service (GitHub / Linear / Notion class), so the authorization-code flow, not `client_credentials`.

Everything below was read from the live specification on 2026-09-24 and from the unpacked `mcp` 2.2.0 wheel,
not from memory. Claims marked VERIFIED were executed or grepped in this session.

---

## 1. The shape, in one paragraph

An operator runs `portmark mcp login <server>` once, at a terminal, on a machine with a browser. That command
performs the OAuth authorization-code flow and writes a token file. From then on the **host** refreshes the
access token when it is near expiry and passes the current access token into the isolated worker exactly the
way `bearer_env` already does today. The worker is unchanged in kind: it receives a token *string* and puts it
in `Authorization: Bearer`. The SDK never runs inside the worker.

## 2. Why the SDK can be used without losing Portmark's transport

VERIFIED by grep on the unpacked wheel: `mcp/client/auth/` contains **no HTTP client and performs no I/O**.
`grep -rnE 'AsyncClient|httpx2?\.(get|post|request|Client)|\.send\(|await client' mcp/client/auth/` → no
matches. The OAuth code is an `httpx2.Auth`: `async_auth_flow(request)` is an async generator that YIELDS
`httpx2.Request` objects and CONSUMES `httpx2.Response` objects. The caller performs the network.

So Portmark drives the generator itself and performs each yielded request on `mcp_http.HttpTransport`. Every
existing defence therefore covers the OAuth requests too: resolve-once anti-rebinding with `getpeername()`,
pinned TLS, no redirects, byte caps, and the wall-clock watchdog. `httpx2` is used as a **data type**, never as
a network stack.

Three hazards exist, and all three are hazards of letting the SDK DRIVE, which this design never does:

| Hazard | When it fires | Why it cannot fire here |
| --- | --- | --- |
| `RedirectAwareAuth` follows redirects on flow-internal requests (`_httpx_utils.py:202-214`) | only when an `httpx2.AsyncClient` drives | Portmark drives; a 3xx is never handed back into the generator |
| `truststore` hooks the OS trust store into TLS | only inside `httpx2`/`httpcore2` SSL config | VERIFIED: `mcp/` never imports it, and no httpx2 connection is ever opened |
| **The sync path fails OPEN, silently** | attaching the provider to a synchronous `httpx2.Client` | VERIFIED: there is no `sync_auth_flow` override in the SDK, and the httpx2 base `auth_flow` is `yield request` unchanged, so a sync client sends the request UNAUTHENTICATED and raises nothing. Portmark must never attach it to a sync client, and a test must prove the rule. |

## 3. Owner decisions already settled, restated so they are not re-litigated

- **D1 stands.** SDK as an exactly-pinned optional extra. Not hand-written OAuth.
- **Dynamic Client Registration is out of scope** (MCP_SIEM_PLAN.md #16). This is also where the specification
  now points: DCR is marked **deprecated**, and pre-registration is priority **1** in the spec's own ordering
  ("Use pre-registered client information for the server if the client has it available").
- **Client ID Metadata Documents are out of scope.** They require Portmark to HOST a public HTTPS JSON
  document whose URL is the `client_id`. A self-hosted runtime generally cannot, and it would be a new public
  surface. Pre-registration is the correct mechanism here, not a shortcut.
- VERIFIED: DCR is skippable. `_initialize()` loads `client_info` from `TokenStorage`, and step 4 is guarded by
  `if not self.context.client_info:`, so a pre-seeded `OAuthClientInformationFull` means no `/register` request
  is ever made.

## 4. What the specification REQUIRES (read 2026-09-24, exact rules)

Discovery of the protected-resource metadata:
1. If the `401` carries `WWW-Authenticate: Bearer resource_metadata="..."`, clients **MUST** use that URL.
2. Otherwise **MUST** fall back to the well-known URIs *in order*: path-aware
   `https://host/.well-known/oauth-protected-resource/<path>` first, then root
   `https://host/.well-known/oauth-protected-resource`.

Discovery of the authorization-server metadata — clients **MUST** try, in this priority order. With a path
component on the issuer:
1. `https://as/.well-known/oauth-authorization-server/<path>`
2. `https://as/.well-known/openid-configuration/<path>`
3. `https://as/<path>/.well-known/openid-configuration`

Without a path: `oauth-authorization-server` then `openid-configuration`.

Then: *"the `issuer` value in the document **MUST** be identical to the issuer identifier used to construct the
well-known URL. If they differ, the client **MUST NOT** use the metadata."* The spec gives the attack it stops:
a document served from `attacker.example` claiming `"issuer": "https://honest.example"`.

The `resource` parameter (RFC 8707) **MUST** be on BOTH the authorization request and the token request, **MUST**
be the canonical URI of the MCP server, and **MUST** be sent regardless of whether the AS supports it. Canonical
means no fragment; prefer no trailing slash.

`iss` validation (RFC 9207) is a **MUST** before the code is sent to any token endpoint, with this exact table:

| `authorization_response_iss_parameter_supported` | `iss` present | action |
| --- | --- | --- |
| true | yes | compare to the recorded issuer |
| true | no | **reject** |
| false/absent | yes | compare to the recorded issuer |
| false/absent | no | proceed |

and the comparison **MUST NOT** apply case folding, default-port elision, trailing-slash or percent-encoding
normalisation first. It applies to error responses too: on mismatch the client **MUST NOT** act on or display
`error`/`error_description`/`error_uri`.

Credential binding is a **MUST**: credentials are keyed by the authorization server's `issuer`; when the AS
changes, clients **MUST NOT** reuse credentials from a different AS and **SHOULD** surface an error. This is the
same shape as Portmark's existing tool pin: record it, and refuse on drift.

`Authorization: Bearer` **MUST** be on every request; tokens **MUST NOT** appear in a query string.

Authorization is **OPTIONAL** in MCP, and stdio clients **SHOULD NOT** use it — credentials come from the
environment. Portmark's stdio behaviour is already correct and does not change.

## 5. The finding the specification does NOT cover

OAuth makes the client fetch URLs the **server chooses**: the `resource_metadata` URL arrives in a response
header, and the authorization-server URL arrives inside that document. That is a server-controlled request
surface — request forgery and confused-deputy — and the specification says nothing about restraining it.
Portmark already defends its MCP endpoint against exactly this, so the rule here is Portmark's own:

**Every server-supplied URL goes through the same address checks as the MCP endpoint itself** —
`resolve_endpoint_address`, loopback/private refusal unless `allow_private`, connect to the literal, confirm
`getpeername()`, no redirects, byte caps, and under the same wall-clock deadline. And every one of them **MUST**
be `https` (the specification mandates HTTPS for OAuth endpoints, unlike the MCP endpoint itself).

## 6. Configuration

New optional `oauth` block on an http server. Names only, never values — the existing `_ENV_NAME` rule:

```json
{
  "url": "https://mcp.example.com/mcp",
  "oauth": {
    "client_id_env": "EXAMPLE_MCP_CLIENT_ID",
    "client_secret_env": "EXAMPLE_MCP_CLIENT_SECRET",
    "token_store": "/var/lib/portmark/example-mcp-token.json",
    "scopes": ["files:read"]
  }
}
```

Rules, matching the existing config discipline:
- `oauth` and `bearer_env` are **mutually exclusive** — two answers to one question is a configuration error.
- `oauth` on a stdio server is refused (the spec says stdio SHOULD NOT use this).
- `oauth` with an `http://` URL is refused, exactly as `bearer_env` already is.
- `client_secret_env` is optional: a public client uses PKCE alone.
- The token VALUE never enters `server_digest`; only the variable names and the store path, as `bearer_env`
  does today. Rotating a token must not look like server drift.

## 7. The token store

- One JSON file per server, written atomically through `_durable_file.py`, mode `0600`, path validated through
  `safe_paths.py`.
- Contents: `issuer`, `client_id`, `access_token`, `refresh_token`, `expires_at`, `scopes`, `token_store_version`.
- `issuer` is the **binding** the specification requires: if protected-resource metadata later names a different
  AS, the host refuses and tells the operator to log in again. It does not silently re-authorize.
- The file is never logged. The existing redaction patterns already cover bearer values; the new fields join them.
- Reading it needs no SDK — it is a JSON file. That is what keeps the worker dependency-free.

## 8. Where each piece runs — the load-bearing separation

| Step | Process | Needs the SDK? |
| --- | --- | --- |
| `portmark mcp login <server>` — full authorization-code flow | CLI, operator's terminal | yes |
| Refresh a near-expiry access token before dispatch | host process | yes |
| Read the current access token, send `Authorization: Bearer` | **isolated worker** | **no** |

The worker keeps receiving a token string, as `mcp_worker.py:141-142` does now. `starlette`, `uvicorn`,
`opentelemetry` and `cryptography` therefore never enter the sandboxed worker process. This is the whole reason
the extra's weight is acceptable.

## 9. The login command

`portmark mcp login <server>` and `portmark mcp logout <server>`.

- Default: bind a **loopback** listener on `127.0.0.1` for the redirect, print the authorization URL, open it if
  a browser exists. This is the native-app pattern the specification's own example uses
  (`http://127.0.0.1:3000/callback`).
- `--manual`: print the URL, let the operator paste the full redirected URL back. Needed because a Portmark box
  is often reached over SSH and has no browser at all.
- VERIFIED that the SDK supports both without imposing either: `redirect_handler(authorization_url: str)` simply
  hands Portmark a string, and `callback_handler()` returns `code`/`state`/`iss` from wherever Portmark got them.
  No browser and no listener are required *by the SDK*.
- PKCE S256 is always applied by the SDK (VERIFIED in the executed flow).
- The command prints what was granted — issuer, client id, scopes, expiry — and never the tokens.

## 10. The dependency extra

`pyproject.toml`: `mcp-oauth = ["mcp==2.2.0"]`, pinned exactly, never a range, because `lock_requirements.py
--check` and the hash-locked installs require it (D1 amendment).

Measured cost, VERIFIED by `pip download mcp -d ...` → **28 wheels**: anyio, attrs, cffi, click, cryptography,
h11, httpcore2, httpx2, idna, jsonschema, jsonschema-specifications, mcp, mcp-types, opentelemetry-api,
pycparser, pydantic, pydantic-core, pyjwt, python-multipart, referencing, rpds-py, sse-starlette, starlette,
truststore, typing-extensions, typing-inspection, uvicorn, annotated-types.

- **Four platform-specific binary wheels** (pydantic-core, rpds-py, cryptography, cffi) — the export carries
  per-platform hashes, as `requirements/a2a.txt` already does.
- **`mcp` pins `mcp-types==2.2.0` internally**, so every `mcp` bump forces a paired bump. Worth a note in
  OPERATIONS.md so a future Dependabot PR is not a surprise.
- New `requirements/mcp-oauth.txt`, generated by adding `"mcp-oauth"` to `EXPORTS` in
  `scripts/lock_requirements.py`. `--check` then keeps it current for free.
- An extra with no CI lane is untested by construction — that was the exact gap the `official-a2a-sdk` job
  closed. This extra gets the same treatment (phase 5).

---

## Implementation phases

**Phase 1 — config and store, no network.** `oauth` block in `mcp_config.py` with the mutual-exclusion and
transport rules; the token store module (atomic, `0600`, issuer binding, redaction). Pure unit tests. Risk: low.
Conflict to watch: `server_digest` must not change shape for servers that do not use `oauth`, or every existing
pin drifts — a test must pin the digest of an unchanged config.

**Phase 2 — the driver.** The generator-driving loop: run `provider.async_auth_flow(...)` under one bounded
`asyncio.run`, perform each yielded request on `HttpTransport`, convert the reply into an `httpx2.Response`, and
never hand back a 3xx. Every request goes through the address checks of §5 and the same deadline. Risk: this is
the novel part. Conflict: `HttpTransport` is built around a single POST to one endpoint; the OAuth requests are
GETs to *other* hosts, so it needs a general "one checked request" entry point rather than a second transport.

**Phase 3 — the spec's MUSTs.** `iss` validation with the exact table and no normalisation; `resource` on both
requests; AS-metadata `issuer` equality; discovery order; credential-to-issuer binding and refusal on drift.
Each one gets a test and a mutant. Risk: these are the rules that are easy to implement almost-right.

**Phase 4 — CLI and host refresh.** `portmark mcp login/logout`, loopback and `--manual`; host-side refresh
before dispatch; the worker reads the store and gets a string. Risk: the refresh path must fail closed — an
expired token with no usable refresh token is a clear operator error, never a silent unauthenticated call.

**Phase 5 — the gate.** `requirements/mcp-oauth.txt`, an `EXPORTS` entry, and a CI lane on the oldest and newest
Python that installs the extra and runs the OAuth tests, with the same *a skip is a failure* guard as
`official-a2a-sdk`. Plus the **never attach to a sync client** test: assert the SDK still has no
`sync_auth_flow`, so if a future version adds one the assumption is re-examined rather than silently inherited.

## Files to modify

- `src/portmark/mcp_config.py` — the `oauth` block, mutual exclusion with `bearer_env`, https-only, digest shape.
- `src/portmark/mcp_oauth.py` — **new.** The generator driver, discovery, `iss`/`resource`/issuer rules, refresh.
- `src/portmark/mcp_token_store.py` — **new.** Atomic `0600` store with issuer binding.
- `src/portmark/mcp_http.py` — a general "perform one checked request" entry point for the OAuth fetches.
- `src/portmark/mcp.py` — host-side refresh before dispatch; capture the access token into the worker env.
- `src/portmark/mcp_worker.py` — read the access token from the store or env; no SDK import.
- `src/portmark/cli.py` — `mcp login` / `mcp logout`.
- `scripts/lock_requirements.py` — add `"mcp-oauth"` to `EXPORTS`.
- `pyproject.toml`, `uv.lock`, `requirements/mcp-oauth.txt` — the exactly-pinned extra.
- `.github/workflows/ci.yml` — the `mcp-oauth` lane, skip-fails-the-lane.
- `MCP.md`, `OPERATIONS.md`, `CHANGELOG.md` — including removing the "not included: OAuth" note in MCP.md.
- `tests/test_mcp_oauth.py` — **new**, plus a fake authorization server in `tests/`.

## Verification

```
python3 -m unittest discover -s tests      # on 3.12 and 3.14
bash <gates>                               # bandit, compileall, lockfile --check, git diff --check, ruff
```

Passing looks like: both Python versions green; bandit, compileall, the lockfile check and `git diff --check`
exit 0; ruff clean except the pre-existing `E741`; every new test proven by a mutant that fails that test and
no other; and the new CI lane green on 3.11 and 3.14 with its tests proven to have RUN, not skipped.

The negative controls that matter most, because each protects a rule that is invisible when it works:
- a metadata document whose `issuer` disagrees with its URL is refused;
- an `iss` that differs only by trailing slash or case is a MISMATCH, not a match;
- a `resource_metadata` URL pointing at a private address is refused;
- a `401` after refresh does not loop;
- a stored token whose issuer no longer matches the protected-resource metadata is refused, not re-used.

# Contributing to Portmark

Contributions are welcome. Portmark is a security boundary, so the bar for a change is higher than
for ordinary application code, and this file says what that bar is before you spend time on a patch.

## Sign the CLA first

**A pull request is not merged until a Contributor License Agreement is on record for you.** The
agreement is [CLA.md](CLA.md). You sign once, and it covers everything you contribute afterwards.

You keep the copyright in your own work — the CLA is a licence to the project, not an assignment.
What it adds is the right to distribute your contribution under terms that may change later,
including more permissive ones. Without that, a single unreachable contributor can freeze Portmark's
licensing permanently.

**If you are contributing for your employer, sign as the entity** — an individual signature does not
bind a company.

### How to sign

Open a pull request that adds you to `.cla-signatures.json` and **changes nothing else**:

```json
{
  "login": "your-github-username",
  "name": "Your Full Legal Name",
  "kind": "individual",
  "agreement_version": "1.0",
  "date": "2026-09-29"
}
```

Use `"kind": "corporate"` if your employer owns the work, and add an `"entity"` field naming it.

A signature-only pull request is the one case the CLA check lets through unsigned, because otherwise
nobody could ever sign. The Project Owner reviews it and confirms you are who the signature says before
merging, so that review is the real check. Prefer a paper signature? Ask, and send a signed copy of
`CLA.md` instead.

Your signature is then a plain file in this repository, with git history behind it. No third-party
service holds it.

### Sign your commits off too

The CLA records who agreed. The sign-off records who wrote each commit. Both are wanted. Every commit
must carry a `Signed-off-by` line certifying the
[Developer Certificate of Origin](https://developercertificate.org/):

```
git commit -s -m "your message"
```

## Before you open a pull request

Portmark's tests are the specification. A change without tests will not be merged, and a change that
weakens a refusal will not be merged at all.

* **Every new test must be proven.** Write a deliberate bug that makes your new test fail — and
  makes **no other test** fail. A test that passes whether or not the code is correct is worse than
  no test, because it looks like coverage.
* **Refusals are features.** Portmark fails closed on purpose. If your change makes something
  previously refused now succeed, say so explicitly in the pull request and explain why it is safe.
* **No new dependencies without discussion.** Every dependency is pinned and hash-locked. Adding one
  widens the supply-chain surface of a security boundary. Open an issue first.
* **Do not silence a gate.** A `# nosec`, a `# noqa`, or a skipped test needs a comment saying why.

## Run the gates locally

CI runs these. Run them before you push:

```bash
python -m unittest discover -s tests -v
bandit -q -r src tests
python tests/fuzz_a2a_parser.py
python scripts/audit_dependencies.py
python -m compileall -q src tests
```

If you changed dependencies, the lock and the hash exports must be regenerated and must match.

## Documentation

If your change alters behaviour a user can see, update the relevant document in the same pull
request — `README.md`, `MCP.md`, `POLICY.md`, `OPERATIONS.md`, `SECURITY.md` or `THREAT_MODEL.md` —
and add a `CHANGELOG.md` entry under **Unreleased**. A behaviour change with no changelog entry is
incomplete.

## Security problems

Do **not** open a public issue for a vulnerability. Follow `SECURITY.md`.

## Deliberate shortcuts

If you take a shortcut on purpose, mark it at the site:

```python
# debt: <what breaks first>; upgrade when <observable trigger>
```

Both halves are required. A marker with no trigger becomes permanent.

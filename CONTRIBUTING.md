# Contributing to Portmark

Contributions are welcome. Portmark is a security boundary, so the bar for a change is higher than
for ordinary application code, and this file says what that bar is before you spend time on a patch.

## Contribution terms

**Please read this section before opening a pull request.** By submitting a contribution you agree
to it.

1. **You own what you send.** You confirm that you wrote the contribution, or that you have the
   right to submit it, and that submitting it does not breach an agreement with an employer or
   anyone else. If your employer has rights in your work, get their sign-off first.

2. **Copyright license.** You grant the licensor named in NOTICE a perpetual, worldwide,
   non-exclusive, royalty-free, irrevocable license to use, reproduce, modify, prepare derivative
   works of, publicly display, sublicense and distribute your contribution and derivative works of
   it, **under any license terms**, including the Elastic License 2.0, a commercial license, or a
   future open-source license.

3. **Patent license.** You grant the licensor and every recipient of Portmark a perpetual,
   worldwide, non-exclusive, royalty-free, irrevocable patent license to make, have made, use, offer
   to sell, sell, import and otherwise transfer Portmark, covering only those patent claims you own
   or control that are necessarily infringed by your contribution alone or by its combination with
   Portmark. If you start patent litigation alleging that Portmark infringes a patent, this grant to
   you ends.

4. **You keep your copyright.** This is a license to the licensor, not an assignment. You may
   continue to use your own contribution however you like.

5. **No warranty.** You provide the contribution as is, without warranties of any kind.

Point 2 exists for one reason, stated plainly: it keeps it possible to change Portmark's licensing
later — including moving to a more permissive license — without having to track down every past
contributor. Without it, a single unreachable contributor can freeze the project's licensing
permanently.

### Sign your commits off

Every commit must carry a `Signed-off-by` line certifying the
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

# Releasing

Portmark publishes to PyPI through **Trusted Publishing**. GitHub proves this repository's
identity to PyPI with a short-lived token minted for a single workflow run. There is no API
token to store, rotate, or leak — the credential does not exist outside the few seconds of the
upload.

## One-time setup on PyPI

On <https://pypi.org/manage/project/portmark/settings/publishing/>, add a GitHub Actions
publisher with exactly these values:

| Field | Value |
| --- | --- |
| Repository owner | `Itsthewayofyou` |
| Repository name | `portmark` |
| Workflow filename | `release.yml` |
| Environment name | `pypi` |

The environment name is optional to PyPI but used here on purpose: it lets GitHub apply a
manual-approval rule to publishing without changing the workflow. To add that rule, go to
**Settings → Environments → pypi → Required reviewers** in the repository.

Any API tokens for this project can be deleted once a release has published successfully
through this path.

## Cutting a release

1. Update `version` in `pyproject.toml`.
2. Add the section to `CHANGELOG.md`.
3. Merge that to `main` with CI green.
4. Tag the merged commit and push the tag:

```bash
git checkout main && git pull
git tag v0.3.0
git push origin v0.3.0
```

A pushed tag is the **only** trigger. `workflow_dispatch` is deliberately absent: it would run
this workflow from any branch, where `github.ref` is not a tag, skipping the tag/version check
and publishing whatever that branch contains. To retry a failed publish, re-run the original
tag's run from the Actions tab.

Every action is pinned to a commit SHA rather than a moving tag such as `@release/v1` or `@v7`.
The publish job holds `id-token: write`, which is enough to release under this project's name, so
a compromised action tag would be a supply-chain path straight to PyPI. Dependabot bumps the pins
weekly — see `.github/dependabot.yml`. When updating a pin by hand, verify the SHA belongs to the
tag in its trailing comment.

The tag push triggers `.github/workflows/release.yml`, which:

- reinstalls and **re-runs the full test suite against the exact tagged tree**, because a tag can
  point at any commit and publishing is irreversible;
- **fails if the tag disagrees with the version in `pyproject.toml`**, so `v0.3.0` cannot ship a
  package that calls itself `0.2.0`;
- builds the source distribution and wheel, and runs `twine check --strict`;
- publishes from a second job whose only permission is `id-token: write` — it cannot read the
  repository and holds nothing that outlives the run.

## Verifying a release

Install from the index, not from a local build. A local build only proves your machine works.

```bash
uv venv /tmp/pm && uv pip install --no-cache --python /tmp/pm/bin/python "portmark==0.3.0"
/tmp/pm/bin/portmark keygen --issuer user:alice --out-registry /tmp/trust.json --format env > /tmp/agent.env
```

Then follow the quickstart in `README.md` and confirm the host accepts a signed envelope and
refuses the same request replayed.

## If a release is wrong

PyPI does not allow re-uploading a version. Yank the bad release on PyPI, fix the problem, bump
to the next patch version, and tag again. Yanking hides it from resolvers while leaving it
installable for anyone who pinned it exactly.

"""Export uv.lock to the hash-pinned requirements files that Docker, CI, and release install.

Section 11 #4: every install path uses `pip install --require-hashes --no-deps -r requirements/<set>.txt`,
so two builds of one commit resolve the same packages with the same bytes. These files are generated,
never edited by hand:

    python scripts/lock_requirements.py            # rewrite requirements/*.txt from uv.lock
    python scripts/lock_requirements.py --check    # fail if uv.lock or any export is stale (CI)

After changing a dependency pin in pyproject.toml (including a Dependabot bump): run `uv lock`, then
this script, and commit all three together. Needs uv (pinned in the `release` dependency group).
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 -- runs uv with fixed arguments
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS = ROOT / "requirements"

# name -> uv export selection. Every set is universal: platform and Python-version markers are kept,
# so one file serves Linux, macOS, and Windows on every supported Python.
EXPORTS = {
    "bootstrap": ["--only-group", "bootstrap"],  # pip + setuptools, installed first
    "runtime": ["--no-default-groups"],  # the package's own dependencies (the Docker image)
    "ci": ["--no-default-groups", "--group", "ci"],  # runtime + test/scan tooling
    "a2a": ["--no-default-groups", "--extra", "a2a"],  # the official A2A SDK, for the conformance lane
    # The file is `mcp_oauth.txt` while the extra is `mcp-oauth`: the extra name is fixed by PEP 685
    # normalisation, the export name is not, so it stays inside the supply-chain check's `\w+`.
    "mcp_oauth": ["--no-default-groups", "--extra", "mcp-oauth"],  # the official MCP SDK, for the OAuth lane
    "postgres": ["--no-default-groups", "--extra", "postgres"],
    "wasmtime": ["--no-default-groups", "--extra", "wasmtime"],
    "release": ["--only-group", "release"],  # build, twine, uv (for the SBOM)
}
COMMON = ["export", "--frozen", "--format", "requirements.txt", "--no-emit-project", "--no-header"]


def uv() -> str:
    found = shutil.which("uv")
    if not found:
        raise SystemExit("uv is required: pip install --require-hashes --no-deps -r requirements/release.txt")
    return found


def export_all(target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for name, selection in EXPORTS.items():
        subprocess.run(  # nosec B603 -- uv, fixed arguments
            [uv(), *COMMON, *selection, "--output-file", str(target / f"{name}.txt")],
            cwd=ROOT, check=True, stdout=subprocess.DEVNULL,
        )


def build_system_mismatch() -> str | None:
    """The bootstrap group must install exactly the setuptools that [build-system] requires.

    The package is built with --no-build-isolation from the bootstrap install. A Dependabot bump of
    [build-system].requires once left CI pinning a different setuptools than the build declared, which
    only worked because the isolated build quietly fetched the declared one, unhashed.
    """
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = sorted(pyproject["build-system"]["requires"])
    bootstrap = sorted(pin for pin in pyproject["dependency-groups"]["bootstrap"] if not pin.startswith("pip=="))
    if declared != bootstrap:
        return f"[build-system].requires {declared} != bootstrap group {bootstrap}"
    return None


def check() -> int:
    mismatch = build_system_mismatch()
    if mismatch:
        print(f"build tooling pins disagree: {mismatch}", file=sys.stderr)
        return 1
    lock = subprocess.run([uv(), "lock", "--check"], cwd=ROOT, capture_output=True, text=True)  # nosec B603
    if lock.returncode != 0:
        print(f"uv.lock is stale; run `uv lock`:\n{lock.stderr}", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as scratch:
        fresh = Path(scratch)
        export_all(fresh)
        stale = [
            name for name in EXPORTS
            if not (REQUIREMENTS / f"{name}.txt").is_file()
            or (REQUIREMENTS / f"{name}.txt").read_bytes() != (fresh / f"{name}.txt").read_bytes()
        ]
        extra = sorted(path.name for path in REQUIREMENTS.glob("*.txt") if path.stem not in EXPORTS)
    if stale or extra:
        print(f"requirements exports are stale {stale} or unexpected {extra}; run python scripts/lock_requirements.py", file=sys.stderr)
        return 1
    print("uv.lock and requirements/*.txt are current")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--check"]:
        return check()
    if argv:
        raise SystemExit("usage: lock_requirements.py [--check]")
    export_all(REQUIREMENTS)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

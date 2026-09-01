"""Dependency vulnerability gate that fails closed on anything it could not audit.

`pip-audit --strict` cannot be used directly here. It audits the whole environment,
which includes portmark installed with `-e .`, and a bumped version does not exist on
PyPI until it is released -- so every version bump deadlocks the gate.

Dropping `--strict` fixes the deadlock but opens a hole: a dependency that fails to
collect for any other reason is then reported as skipped and the audit still exits 0.

So this runs pip-audit without `--strict` and reimposes the strict behaviour with one
named exemption: portmark's own editable install. Any other skipped distribution, and
any vulnerability, fails the build.

Run: python scripts/audit_dependencies.py
"""

from __future__ import annotations

import json
import subprocess  # nosec B404
import sys

# The only distribution allowed to go unaudited, and only for this reason.
ALLOWED_SKIPS = {("portmark", "distribution marked as editable")}


def main() -> int:
    command = [
        sys.executable,
        "-m",
        "pip_audit",
        "--skip-editable",
        "--progress-spinner",
        "off",
        "--format",
        "json",
    ]
    # Fixed argv, no shell, no user input.
    process = subprocess.run(command, capture_output=True, text=True, check=False)  # nosec B603

    try:
        report = json.loads(process.stdout)
    except json.JSONDecodeError:
        print("audit failed: pip-audit did not return JSON", file=sys.stderr)
        print(process.stdout[-2000:], file=sys.stderr)
        print(process.stderr[-2000:], file=sys.stderr)
        return 1

    dependencies = report.get("dependencies", [])
    if not dependencies:
        # An empty report is indistinguishable from "audited nothing". Fail closed.
        print("audit failed: pip-audit reported no dependencies at all", file=sys.stderr)
        return 1

    vulnerable = [d for d in dependencies if d.get("vulns")]
    skipped = [(d.get("name"), d.get("skip_reason")) for d in dependencies if d.get("skip_reason")]
    unexpected = [s for s in skipped if s not in ALLOWED_SKIPS]

    print(f"audited {len(dependencies) - len(skipped)} distributions, skipped {len(skipped)}")

    for name, reason in skipped:
        marker = "ALLOWED" if (name, reason) in ALLOWED_SKIPS else "UNEXPECTED"
        print(f"  skipped [{marker}] {name}: {reason}")

    for dependency in vulnerable:
        ids = ", ".join(v.get("id", "?") for v in dependency["vulns"])
        print(f"  VULNERABLE {dependency.get('name')} {dependency.get('version')}: {ids}", file=sys.stderr)

    if unexpected:
        print(
            "audit failed: a distribution was skipped that is not the local editable package",
            file=sys.stderr,
        )
        return 1
    if vulnerable:
        print("audit failed: known vulnerabilities present", file=sys.stderr)
        return 1

    print("audit passed: no vulnerabilities, nothing unexpectedly skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

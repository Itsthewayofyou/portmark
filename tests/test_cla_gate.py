"""The CLA workflow's refuse path, driven directly.

`.github/workflows/cla.yml` is a fail-closed gate: a contribution may not be merged until its author
has signed CLA.md. GitHub will not run the refusing cases for us -- CI only ever exercises the passing
one -- so the step's shell is extracted from the workflow and run here under bash with a stub `gh`.

The two cases worth the most are the attacks. A pull request must not be able to add its own author to
the record it is checked against, and a record that cannot be read or parsed must refuse rather than
wave the contribution through.
"""
from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - runs bash on a script read from this repository
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "cla.yml")
RECORD = ".cla-signatures.json"

SIGNED = {
    "agreement": "CLA.md",
    "current_version": "1.0",
    "signatures": [{"login": "has-signed", "name": "A Person", "kind": "individual",
                    "agreement_version": "1.0", "date": "2026-09-29"}],
}

_STUB = """#!/bin/bash
# A stand-in for `gh`: the changed-file list for a pulls/*/files call, the record for a contents/ call.
for arg in "$@"; do
  case "$arg" in
    *"/files") cat %(dir)s/files.txt; exit 0;;
    *"contents/"*) [ -f %(dir)s/record ] || { echo "Not Found" >&2; exit 1; }
                   cat %(dir)s/record; exit 0;;
  esac
done
echo "stub gh: unexpected call: $*" >&2
exit 3
"""


def _step_script() -> str:
    """The workflow's single `run:` block, dedented into runnable bash."""
    raw = open(WORKFLOW, encoding="utf-8").read()
    marker = "        run: |\n"
    if raw.count(marker) != 1:
        raise AssertionError("expected exactly one run: block in the CLA workflow")
    lines = []
    for line in raw.split(marker, 1)[1].split("\n"):
        if line.strip() == "":
            lines.append("")
            continue
        if not line.startswith(" " * 10):
            raise AssertionError(f"the run: block is no longer one indented block: {line!r}")
        lines.append(line[10:])
    return "\n".join(lines)


class ClaGateTests(unittest.TestCase):
    """Every branch of the gate, including the ones GitHub never runs."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.script = _step_script()
        # If the gate stops being able to refuse, these tests are watching nothing. Raised rather than
        # asserted so the check survives `python -O`, which strips assertions.
        if "exit 1" not in cls.script:
            raise AssertionError("the CLA step no longer has a refusing path")
        if "BASE_SHA" not in cls.script:
            raise AssertionError("the CLA step no longer reads the record at the base commit")

    def gate(self, *, files, record=SIGNED, author="a-stranger", author_type="User",
             raw_record=None, owner="Itsthewayofyou") -> int:
        """Run the step and return its exit status. `record=None` makes reading the record fail."""
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = os.path.join(tmp, "bin")
            os.makedirs(bin_dir)
            with open(os.path.join(tmp, "files.txt"), "w", encoding="utf-8") as handle:
                handle.write("".join(f"{name}\n" for name in files))
            if raw_record is not None:
                with open(os.path.join(tmp, "record"), "w", encoding="utf-8") as handle:
                    handle.write(raw_record)
            elif record is not None:
                with open(os.path.join(tmp, "record"), "w", encoding="utf-8") as handle:
                    json.dump(record, handle)
            stub = os.path.join(bin_dir, "gh")
            with open(stub, "w", encoding="utf-8") as handle:
                handle.write(_STUB % {"dir": tmp})
            os.chmod(stub, 0o755)  # nosec B103 - a stub inside a temporary directory, for this test
            env = dict(
                os.environ,
                PATH=bin_dir + os.pathsep + os.environ["PATH"],
                # No GH_TOKEN: the stub needs none, and the step only passes it through to `gh`.
                REPO="Itsthewayofyou/portmark", OWNER=owner,
                PR="1", AUTHOR=author, AUTHOR_TYPE=author_type, BASE_SHA="0" * 40, RECORD=RECORD,
            )
            done = subprocess.run(  # nosec B603 B607 - bash on this repository's own workflow step
                ["bash", "-c", self.script],
                capture_output=True, text=True, env=env, timeout=120, check=False,
            )
            return done.returncode

    def test_an_author_who_has_not_signed_is_refused(self):
        """The whole point: an unsigned contribution must not be mergeable."""
        self.assertEqual(self.gate(files=["src/portmark/mcp.py"]), 1)

    def test_an_author_who_has_signed_passes(self):
        self.assertEqual(self.gate(files=["src/portmark/mcp.py"], author="has-signed"), 0)

    def test_a_pull_request_cannot_sign_itself(self):
        """Editing the record ALONGSIDE code must not pass.

        The record is read at the base commit, so adding yourself in the same pull request changes
        nothing the check looks at. Only a pull request that touches the record and NOTHING else is
        treated as a signature, and that one still has to be merged by the Project Owner.
        """
        self.assertEqual(self.gate(files=[RECORD, "src/portmark/mcp.py"]), 1)

    def test_a_signature_on_its_own_is_allowed_through(self):
        """Signing cannot require a signature first, or nobody could ever sign."""
        self.assertEqual(self.gate(files=[RECORD]), 0)

    def test_a_record_that_cannot_be_read_refuses(self):
        """A gate that passes when it cannot see the record is not a gate."""
        self.assertEqual(self.gate(files=["src/portmark/mcp.py"], author="has-signed", record=None), 1)

    def test_a_record_that_cannot_be_parsed_refuses(self):
        self.assertEqual(
            self.gate(files=["src/portmark/mcp.py"], author="has-signed",
                      record=None, raw_record="{ not json"),
            1,
        )

    def test_a_record_with_no_signatures_refuses(self):
        self.assertEqual(
            self.gate(files=["src/portmark/mcp.py"], author="has-signed",
                      record={"agreement": "CLA.md"}),
            1,
        )

    def test_automation_needs_no_agreement(self):
        """Dependabot holds no copyright, so it has nothing to license."""
        self.assertEqual(self.gate(files=["uv.lock"], author="dependabot[bot]", author_type="Bot"), 0)

    def test_a_human_named_like_a_bot_still_needs_to_sign(self):
        """The exemption is on the account type the API reports, not on a name anyone can choose."""
        self.assertEqual(
            self.gate(files=["src/portmark/mcp.py"], author="dependabot[bot]", author_type="User"),
            1,
        )

    def test_the_project_owner_needs_no_agreement(self):
        """The licensor does not sign an agreement with himself."""
        self.assertEqual(self.gate(files=["README.md"], author="Itsthewayofyou"), 0)

    def test_a_login_differing_only_in_case_is_the_same_person(self):
        """GitHub logins are case-insensitive; refusing over case would be a false refusal."""
        self.assertEqual(self.gate(files=["src/portmark/mcp.py"], author="HAS-SIGNED"), 0)


class ClaRecordTests(unittest.TestCase):
    """The record the gate reads has to be readable by the gate."""

    def test_the_record_parses_and_has_a_signatures_list(self):
        with open(os.path.join(ROOT, RECORD), encoding="utf-8") as handle:
            record = json.load(handle)
        self.assertIsInstance(record.get("signatures"), list)

    def test_every_signature_names_a_login_and_an_agreement_version(self):
        """A signature the gate cannot match, or cannot date to a version, records nothing useful."""
        with open(os.path.join(ROOT, RECORD), encoding="utf-8") as handle:
            record = json.load(handle)
        for entry in record["signatures"]:
            self.assertTrue(entry.get("login"), entry)
            self.assertTrue(entry.get("agreement_version"), entry)


if __name__ == "__main__":
    unittest.main()

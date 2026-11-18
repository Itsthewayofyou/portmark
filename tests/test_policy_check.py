"""`portmark policy check`: read a host policy file and say, in plain words, what it allows.

Roadmap item "configuration validator": an operator must be able to see what a policy does without reading
Portmark's code. The check loads the file with the SAME strict loader the host uses (so it can never accept a
file the host would refuse), describes every tool's approval rule and the spend budget, and warns about
settings that are valid but almost certainly not what the operator meant.

The expected descriptions and warnings below are written by hand from the policy's meaning, not generated
from the implementation.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from authority_fixtures import ApprovalAuthority
from portmark.policy import load_host_policy
from portmark.policy_check import check_policy

PAY = "payments.reserve"
AUTHORITY = ApprovalAuthority.generate()
POLICY = {
    "version": "buy-v1",
    "approval_authorities": [
        {"key_id": AUTHORITY.key_id, "approver": AUTHORITY.approver, "public_key_b64": AUTHORITY.public_key_b64()}
    ],
    "tools": {
        PAY: {"impact": "medium", "constraints": {"max_amount": 100, "allowed_currency": ["USD"], "allowed_vendor": ["acme"]}},
        "catalog.search": {"impact": "low", "constraints": {"max_limit": 5}},
        "admin.delete_records": {"impact": "destructive"},
    },
    "spend_budgets": {
        "period": "day", "limits": {"USD": 100}, "approval_above": {"USD": 50},
        "tools": {PAY: {"amount": "amount", "currency": "currency"}},
    },
}


def _with(**changes) -> dict:
    value = copy.deepcopy(POLICY)
    for dotted, new in changes.items():
        target = value
        *parents, last = dotted.split("__")
        for key in parents:
            target = target[key]
        if new is None:
            target.pop(last, None)
        else:
            target[last] = new
    return value


def _edit(change) -> dict:
    """A copy of POLICY with `change(copy)` applied (for tool entries, whose names contain dots)."""
    value = copy.deepcopy(POLICY)
    change(value)
    return value


def _tool(report: dict, name: str) -> dict:
    return next(tool for tool in report["tools"] if tool["name"] == name)


class PolicyCheckReportTests(unittest.TestCase):
    def test_a_valid_policy_is_described_in_plain_words(self):
        report = check_policy(POLICY)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["policy_version"], "buy-v1")
        self.assertEqual(_tool(report, PAY)["approval"], "over 50 USD")
        self.assertIs(_tool(report, PAY)["budgeted"], True)
        self.assertEqual(_tool(report, "catalog.search")["approval"], "never")
        self.assertEqual(_tool(report, "admin.delete_records")["approval"], "always (impact destructive)")
        budget = report["spend_budgets"]
        self.assertEqual(budget["period"], "day")
        self.assertEqual(budget["limits"], {"USD": "100"})
        self.assertEqual(budget["approval_above"], {"USD": "50"})
        self.assertEqual(report["approval_authorities"], 1)
        self.assertEqual(report["warnings"], [])

    def test_amounts_are_shown_exactly(self):
        report = check_policy(_with(spend_budgets__limits={"USD": 99.99}, spend_budgets__approval_above={"USD": 0.5}))
        self.assertEqual(report["spend_budgets"]["limits"], {"USD": "99.99"})
        self.assertEqual(report["spend_budgets"]["approval_above"], {"USD": "0.5"})

    def test_the_hash_is_the_one_the_host_reports(self):
        # Approval requests carry the host's policy_hash; the operator must be able to match it to this file.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps(POLICY), encoding="utf-8")
            self.assertEqual(check_policy(POLICY)["policy_hash"], load_host_policy(path, "host:any").policy_hash)

    def test_a_policy_the_host_would_refuse_is_invalid_with_the_loader_reason(self):
        for label, bad, reason in (
            ("typo in spend_budgets", _with(spend_budgets__perod="day"), "unknown keys"),
            ("budget on an ungranted tool", _with(spend_budgets__tools={"payments.reserv": {"amount": "amount", "currency": "currency"}}), "does not grant"),
            ("threshold without a limit", _with(spend_budgets__approval_above={"EUR": 5}), "has no limit"),
            ("bad impact", _edit(lambda v: v["tools"]["catalog.search"].update(impact="huge")), "invalid impact"),
        ):
            with self.subTest(label):
                report = check_policy(bad)
                self.assertEqual(report["status"], "invalid")
                self.assertIn(reason, report["error"])

    def test_every_shipped_example_policy_loads(self):
        examples = sorted((Path(__file__).resolve().parent.parent / "examples").glob("*policy*.json"))
        self.assertTrue(examples)
        for path in examples:
            with self.subTest(path.name):
                report = check_policy(json.loads(path.read_text(encoding="utf-8")))
                self.assertEqual(report["status"], "ok", report.get("error"))

    def test_the_purchasing_example_describes_the_pilot_rules(self):
        path = Path(__file__).resolve().parent.parent / "examples" / "purchasing-policy.json"
        report = check_policy(json.loads(path.read_text(encoding="utf-8")))
        self.assertEqual(_tool(report, PAY)["approval"], "over 50 USD")
        self.assertEqual(report["spend_budgets"]["limits"], {"USD": "100"})

    def test_a_policy_with_no_spend_budget_says_so(self):
        report = check_policy(_with(spend_budgets=None))
        self.assertIsNone(report["spend_budgets"])
        self.assertEqual(_tool(report, PAY)["approval"], "never")
        self.assertIs(_tool(report, PAY)["budgeted"], False)


class PolicyCheckWarningTests(unittest.TestCase):
    def assert_warning(self, value: dict, *needles: str) -> None:
        warnings = check_policy(value)["warnings"]
        self.assertTrue(any(all(needle in warning for needle in needles) for warning in warnings), warnings)

    def test_a_threshold_on_a_tool_that_always_needs_approval_does_nothing(self):
        self.assert_warning(_edit(lambda v: v["tools"][PAY].update(impact="external-payment")), PAY, "every amount")

    def test_approval_with_no_trusted_approver_can_never_be_given(self):
        self.assert_warning(_with(approval_authorities=None), "no approval authority")

    def test_approvers_count_only_when_the_host_would_accept_their_signature(self):
        # Codex review: count approvers the way the host does. The same key_id twice keeps the LAST entry,
        # and a revoked, expired or not-yet-valid key approves nothing.
        entry = POLICY["approval_authorities"][0]
        for label, authorities in {
            "revoked later entry": [entry, {**entry, "revoked": True}],
            "expired": [{**entry, "expires_at": 1}],
            "not yet valid": [{**entry, "not_before": 2**40}],
        }.items():
            with self.subTest(label):
                value = _with(approval_authorities=authorities)
                self.assertEqual(check_policy(value)["approval_authorities"], 0)
                self.assert_warning(value, "no approval authority")

    def test_a_threshold_at_or_above_the_limit_can_never_be_used(self):
        self.assert_warning(_with(spend_budgets__approval_above={"USD": 100}), "USD", "limit")

    def test_a_zero_limit_refuses_every_call(self):
        self.assert_warning(_with(spend_budgets__limits={"USD": 0}, spend_budgets__approval_above=None), "USD", "every call")

    def test_a_tool_with_no_impact_is_flagged(self):
        value = _edit(lambda v: v["tools"]["catalog.search"].pop("impact"))
        self.assert_warning(value, "catalog.search", "no impact")
        # The host treats a side-effecting tool with no impact as "high", so "never" alone would be wrong.
        self.assertIn("side-effecting", _tool(check_policy(value), "catalog.search")["approval"])


class PolicyCheckCliTests(unittest.TestCase):
    def _cli(self, *argv):
        from portmark import cli

        out, err = io.StringIO(), io.StringIO()
        code = 0
        with patch("sys.argv", ["portmark", *argv]), patch.dict(os.environ, {}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                cli.main()
            except SystemExit as exit_:
                code = exit_.code if isinstance(exit_.code, int) else 1
        return code, out.getvalue(), err.getvalue()

    def _file(self, value) -> str:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "policy.json"
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
        return str(path)

    def test_text_output_and_exit_zero_for_a_valid_policy(self):
        code, out, err = self._cli("policy", "check", self._file(POLICY))
        self.assertEqual(code, 0, err)
        self.assertIn(PAY, out)
        self.assertIn("over 50 USD", out)
        self.assertIn("OK", out)

    def test_json_output(self):
        code, out, _ = self._cli("policy", "check", "--json", self._file(POLICY))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["status"], "ok")

    def test_exit_one_for_an_invalid_or_unreadable_policy(self):
        for label, path in (
            ("invalid", self._file(_with(spend_budgets__perod="day"))),
            ("not json", self._file("{not json")),
            ("missing", str(Path(tempfile.gettempdir()) / "no-such-portmark-policy.json")),
        ):
            with self.subTest(label):
                code, out, err = self._cli("policy", "check", path)
                self.assertEqual(code, 1)
                self.assertIn("INVALID", out)
                self.assertNotIn("Traceback", err)


if __name__ == "__main__":
    unittest.main()

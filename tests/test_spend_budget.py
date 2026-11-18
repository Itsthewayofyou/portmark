"""PM-AUTH-015: a host-enforced cumulative spend budget.

Before this, monetary limits were per call only: two 99 USD payments under a 100 USD cap were each allowed,
and nothing limited spending across permits. Host policy `spend_budgets` now names the amount and currency
arguments of a tool and a limit per currency; the host charges every call against a running total per
permit signer (permit.issuer) per UTC day or month, and refuses a call that would go over.

Oracles: a recording tool (what really ran) and the store's running total -- never the host's own refusal
message alone.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
import threading
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest import mock

from authority_fixtures import ApprovalAuthority
from portmark._clock import trusted_now
from portmark.factory import make_host
from portmark.models import AgentEnvelope, AgentManifest, AgentState, Permit, ProviderDecision, ResourceBudget, ToolGrant
from portmark.policy import policy_from_dict
from portmark.providers import ModelProvider
from portmark.security import SecurityError
from portmark.spend import parse_spend_budgets, period_key, to_minor_units
from portmark.storage import InMemoryRuntimeStore, PostgresRuntimeStore, SQLiteRuntimeStore
from portmark.tools import ToolRegistry
from test_audit_floor import HOST, host_signer
from test_boundary_production_profile import portmark_env

PAY = "payments.reserve"
U = 1_000_000  # storage units per currency unit (amounts are stored in millionths)
CONSTRAINTS = {"max_amount": 100, "allowed_currency": ["USD"], "allowed_vendor": ["acme"]}
SPEND = {"period": "day", "scale": 2, "limits": {"USD": 100}, "tools": {PAY: {"amount": "amount", "currency": "currency"}}}


def _policy(spend: dict | None = SPEND) -> dict:
    policy = {
        "version": "t1",
        "budget": {"max_steps": 8, "max_tool_calls": 5, "max_output_bytes": 65536},
        "tools": {PAY: {"impact": "medium", "constraints": CONSTRAINTS}},
    }
    if spend is not None:
        policy["spend_budgets"] = spend
    return policy


def _pay(amount, vendor: str = "acme", currency: str = "USD") -> dict:
    return {"amount": amount, "currency": currency, "vendor": vendor}


class _Pays(ModelProvider):
    """Proposes each payment in turn, then completes."""

    def __init__(self, payments: list[dict]) -> None:
        self.payments = payments

    def decide(self, view, tools, grants=()):
        if view.step < len(self.payments):
            return ProviderDecision("tool", PAY, self.payments[view.step])
        return ProviderDecision("complete", content="done")


class _Recorder:
    """The oracle: what the payment tool really received."""

    def __init__(self, fail: bool = False) -> None:
        self.calls: list[dict] = []
        self.fail = fail
        self._lock = threading.Lock()

    def __call__(self, arguments):
        with self._lock:
            self.calls.append(dict(arguments))
        if self.fail:
            raise RuntimeError("vendor timed out after charging")
        return {"ok": True}


# --- policy parsing and amounts -------------------------------------------------------------------


class SpendPolicyParsingTests(unittest.TestCase):
    def test_a_valid_block_parses_to_minor_units(self):
        parsed = parse_spend_budgets(SPEND)
        self.assertEqual(parsed.limits, {"USD": 100 * U})
        self.assertEqual(parsed.period, "day")

    def test_unknown_keys_and_bad_values_are_refused(self):
        for bad in (
            {**SPEND, "perod": "day"},
            {**SPEND, "period": "hour"},
            {**SPEND, "scale": True},
            {**SPEND, "scale": 9},
            {**SPEND, "limits": {}},
            {**SPEND, "limits": {"USD": -1}},
            {**SPEND, "limits": {"USD": 1.001}},
            {**SPEND, "tools": {}},
            {**SPEND, "tools": {PAY: {"amount": "amount"}}},
            {**SPEND, "tools": {PAY: {"amount": "x", "currency": "x"}}},
            {**SPEND, "tools": {PAY: {"amount": "amount", "currency": "currency", "extra": "y"}}},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_spend_budgets(bad)

    def test_a_budget_on_a_tool_the_policy_does_not_grant_is_refused(self):
        spend = {**SPEND, "tools": {"payments.reserv": {"amount": "amount", "currency": "currency"}}}
        with self.assertRaisesRegex(ValueError, "does not grant"):
            policy_from_dict(_policy(spend), HOST)

    def test_the_policy_carries_the_budget(self):
        self.assertEqual(policy_from_dict(_policy(), HOST).spend_budgets.limits, {"USD": 100 * U})
        self.assertIsNone(policy_from_dict(_policy(None), HOST).spend_budgets)


class AmountTests(unittest.TestCase):
    def test_exact_decimal_conversion(self):
        self.assertEqual(to_minor_units(99.99, 2), 99_990_000)  # float arithmetic would give 99.989999...
        self.assertEqual(to_minor_units(100, 2), 100 * U)
        self.assertEqual(to_minor_units(0.29, 2), 290_000)

    def test_unusable_amounts_are_refused(self):
        for bad in (True, False, "99", None, [1], float("nan"), float("inf"), -1, 0, 0.1 + 0.2, 1.005, 10**20):
            with self.subTest(bad=bad), self.assertRaises(SecurityError):
                to_minor_units(bad, 2)

    def test_period_keys_are_utc_calendar_periods(self):
        moment = 1792713599  # 2026-10-22 23:59:59 UTC
        self.assertEqual(period_key(moment, "day"), "2026-10-22")
        self.assertEqual(period_key(moment + 1, "day"), "2026-10-23")
        self.assertEqual(period_key(moment, "month"), "2026-10")


# --- the store's atomic check-and-add, on every backend ------------------------------------------


class _StoreContract:
    def make_store(self):  # pragma: no cover - each backend defines it
        raise NotImplementedError

    def test_reserve_within_and_over_the_limit(self):
        store = self.make_store()
        self.assertTrue(store.reserve_spend("r1", "t1", "alice", "USD", "2026-10-22", 9900, 10000))
        self.assertFalse(store.reserve_spend("r2", "t2", "alice", "USD", "2026-10-22", 9900, 10000))
        self.assertTrue(store.reserve_spend("r3", "t3", "alice", "USD", "2026-10-22", 100, 10000))
        self.assertEqual(store.spend_total("alice", "USD", "2026-10-22"), 10000)

    def test_owners_currencies_and_periods_are_separate(self):
        store = self.make_store()
        self.assertTrue(store.reserve_spend("r1", "t", "alice", "USD", "2026-10-22", 10000, 10000))
        self.assertTrue(store.reserve_spend("r2", "t", "bob", "USD", "2026-10-22", 10000, 10000))
        self.assertTrue(store.reserve_spend("r3", "t", "alice", "EUR", "2026-10-22", 10000, 10000))
        self.assertTrue(store.reserve_spend("r4", "t", "alice", "USD", "2026-10-23", 10000, 10000))
        self.assertEqual(store.spend_total("alice", "USD", "2026-10-22"), 10000)

    def test_release_gives_back_once(self):
        store = self.make_store()
        self.assertTrue(store.reserve_spend("r1", "t", "alice", "USD", "p", 6000, 10000))
        self.assertTrue(store.release_spend("r1"))
        self.assertFalse(store.release_spend("r1"))
        self.assertFalse(store.release_spend("never-reserved"))
        self.assertEqual(store.spend_total("alice", "USD", "p"), 0)

    def test_racing_reservations_never_pass_the_limit(self):
        store = self.make_store()
        results: list[bool] = []
        barrier = threading.Barrier(20)

        def reserve(index: int) -> None:
            barrier.wait()
            results.append(store.reserve_spend(f"race-{index}", "t", "alice", "USD", "p", 1000, 10000))

        threads = [threading.Thread(target=reserve, args=(index,)) for index in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count(True), 10)
        self.assertEqual(store.spend_total("alice", "USD", "p"), 10000)


class InMemorySpendStoreTests(_StoreContract, unittest.TestCase):
    def make_store(self):
        return InMemoryRuntimeStore()


class SQLiteSpendStoreTests(_StoreContract, unittest.TestCase):
    def make_store(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return SQLiteRuntimeStore(Path(directory.name) / "spend.sqlite3")


@unittest.skipUnless(os.environ.get("PORTMARK_TEST_POSTGRES_DSN"), "needs PORTMARK_TEST_POSTGRES_DSN")
class PostgresSpendStoreTests(_StoreContract, unittest.TestCase):
    def make_store(self):
        schema = "spend_" + secrets.token_hex(6)
        store = PostgresRuntimeStore(os.environ["PORTMARK_TEST_POSTGRES_DSN"], schema=schema)
        self.addCleanup(self._drop, schema)
        return store

    @staticmethod
    def _drop(schema: str) -> None:
        import psycopg

        with psycopg.connect(os.environ["PORTMARK_TEST_POSTGRES_DSN"], autocommit=True) as connection:
            connection.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


# --- the AgentHost path -----------------------------------------------------------------------------


class HostSpendBudgetTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.policy_path = Path(self._dir.name) / "policy.json"
        self.policy_path.write_text(json.dumps(_policy()), encoding="utf-8")
        self.store = SQLiteRuntimeStore(Path(self._dir.name) / "store.sqlite3")
        self.recorder = _Recorder()

    def host(self, payments: list[dict], recorder: _Recorder | None = None):
        tools = ToolRegistry()
        tools.register(PAY, recorder or self.recorder)
        with portmark_env():
            return make_host(
                host_id=HOST, signer=host_signer(), policy_path=str(self.policy_path),
                store=self.store, tools=tools, providers={"p": _Pays(payments)},
            )

    @staticmethod
    def envelope(host) -> AgentEnvelope:
        manifest = AgentManifest("agent:buyer", "1.0.0", "p", (PAY,))
        permit = Permit(
            host.signer.issuer, "agent:buyer", host.host_id, trusted_now() + 600, secrets.token_hex(16),
            (ToolGrant(PAY, CONSTRAINTS),), ResourceBudget(8, 5, 32768),
        )
        return host.signer.seal(AgentEnvelope(manifest, permit, AgentState(secrets.token_hex(8), "buy toner")))

    def run_payments(self, payments: list[dict], recorder: _Recorder | None = None):
        """(host, outcome): the RunResult, or the SecurityError a refused decision raises out of run()."""
        host = self.host(payments, recorder)
        try:
            return host, host.run(self.envelope(host))
        except SecurityError as error:
            return host, error

    def total(self, host) -> int:
        return self.store.spend_total(host.signer.issuer, "USD", period_key(trusted_now(), "day"))

    @staticmethod
    def events(result) -> list[str]:
        return [record["event"] for record in result.audit]

    def test_a_split_payment_is_refused_within_one_permit(self):
        # The A13 attack: two 99 USD payments under a 100 USD/day budget.
        host, outcome = self.run_payments([_pay(99), _pay(99)])
        self.assertIsInstance(outcome, SecurityError)
        self.assertIn("spend budget exceeded", str(outcome))
        self.assertEqual(len(self.recorder.calls), 1)
        self.assertEqual(self.total(host), 99 * U)

    def test_a_split_payment_is_refused_across_permits(self):
        # Per-permit limits already existed (max_tool_calls); the budget spans permits of one signer.
        host, first = self.run_payments([_pay(99)])
        _, second = self.run_payments([_pay(99)])
        self.assertEqual(first.status, "completed")
        self.assertIn("spend.reserved", self.events(first))
        self.assertIsInstance(second, SecurityError)
        self.assertEqual(len(self.recorder.calls), 1)
        self.assertEqual(self.total(host), 99 * U)

    def test_control_payments_within_the_budget_all_run(self):
        host, result = self.run_payments([_pay(60), _pay(30), _pay(10)])
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(self.recorder.calls), 3)
        self.assertEqual(self.total(host), 100 * U)

    def test_cents_are_exact(self):
        host, result = self.run_payments([_pay(33.33), _pay(33.33), _pay(33.34)])
        self.assertEqual(result.status, "completed")
        self.assertEqual(self.total(host), 100 * U)

    def test_a_call_refused_before_launch_gives_the_money_back(self):
        # The refusal must come AFTER the reservation, or this proves nothing: a bad argument (a wrong
        # vendor) is now refused by the early check before any money is reserved, so the total is 0
        # whether or not the give-back works. Here invoke refuses (as a launch-capability or permit
        # check inside it would) after the reservation, and the tool never starts.
        host = self.host([_pay(50)])
        reserve = mock.patch.object(self.store, "reserve_spend", wraps=self.store.reserve_spend)
        release = mock.patch.object(self.store, "release_spend", wraps=self.store.release_spend)
        refuse = mock.patch.object(host.tools, "invoke", side_effect=SecurityError("launch refused"))
        with reserve as reserved, release as released, refuse:
            with self.assertRaisesRegex(SecurityError, "launch refused"):
                host.run(self.envelope(host))
        self.assertEqual(reserved.call_count, 1, "the call must be charged before the refusal")
        self.assertEqual(released.call_count, 1, "the refused call must be given back")
        self.assertEqual(self.recorder.calls, [])
        self.assertEqual(self.total(host), 0)

    def test_a_bad_argument_is_refused_before_any_money_is_reserved(self):
        # The early argument check (before the approval gate) refuses a wrong vendor first, so the
        # budget is never touched.
        with mock.patch.object(self.store, "reserve_spend", wraps=self.store.reserve_spend) as reserved:
            host, outcome = self.run_payments([_pay(50, vendor="evil")])
        self.assertIsInstance(outcome, SecurityError)
        self.assertIn("vendor", str(outcome))
        self.assertEqual(reserved.call_count, 0)
        self.assertEqual(self.recorder.calls, [])
        self.assertEqual(self.total(host), 0)

    def test_a_tool_that_started_and_failed_stays_counted(self):
        # Owner decision 3: the host cannot prove the vendor did not charge, so it counts.
        failing = _Recorder(fail=True)
        host, result = self.run_payments([_pay(50)], failing)
        self.assertEqual(len(failing.calls), 1)
        self.assertEqual(self.total(host), 50 * U)
        self.assertIn("tool.failed", self.events(result))

    def test_unusable_amounts_and_currencies_are_refused_before_anything_runs(self):
        for payment in (_pay(True), _pay("99"), _pay(1.005), {"amount": 5, "vendor": "acme"}, _pay(5, currency="EUR")):
            with self.subTest(payment=payment):
                recorder = _Recorder()
                host, outcome = self.run_payments([payment], recorder)
                self.assertIsInstance(outcome, SecurityError)
                self.assertEqual(recorder.calls, [])
                self.assertEqual(self.total(host), 0)

    def test_a_refusal_settles_a_side_effecting_ledger_row_back_to_prepared(self):
        host = self.host([])
        settled = []
        with mock.patch.object(self.store, "reserve_spend", return_value=False), \
                mock.patch.object(self.store, "settle_effect", side_effect=lambda *args: settled.append(args)):
            state = AgentState("task-1", "go")
            decision = ProviderDecision("tool", PAY, _pay(10))
            with self.assertRaisesRegex(SecurityError, "spend budget exceeded"):
                host._reserve_spend(host.policy, self.envelope(host).permit, state, decision, None, "effect-1")
        self.assertEqual(settled, [("effect-1", "prepared", None, "spend budget refused the call; nothing ran")])

    def test_a_migrated_task_is_refused_for_a_budgeted_tool(self):
        from portmark.host import _MIGRATION_TASK_NAMESPACE

        host = self.host([])
        state = AgentState(_MIGRATION_TASK_NAMESPACE + "abc", "go")
        decision = ProviderDecision("tool", PAY, _pay(10))
        with self.assertRaisesRegex(SecurityError, "migrated task"):
            host._reserve_spend(host.policy, self.envelope(host).permit, state, decision, None, None)
        self.assertEqual(self.total(host), 0)

    def test_a_reload_in_flight_cannot_remove_the_budget(self):
        from portmark.host import _ReloadedPolicy

        with_budget = policy_from_dict(_policy(), HOST)
        without = policy_from_dict(_policy(None), HOST)
        self.assertIs(_ReloadedPolicy(with_budget, without).spend_budgets, with_budget.spend_budgets)
        # A reload that only tightens applies the fresh budget at once.
        tighter = policy_from_dict(_policy({**SPEND, "limits": {"USD": 50}}), HOST)
        self.assertEqual(_ReloadedPolicy(with_budget, tighter).spend_budgets.limits, {"USD": 50 * U})

    def test_a_reload_in_flight_cannot_loosen_the_budget_in_any_way(self):
        # Codex review: a NON-empty fresh block can loosen too. Each of these keeps the previous budget.
        from portmark.host import _ReloadedPolicy

        previous = policy_from_dict(_policy(), HOST)
        other_tool = {"other.tool": {"impact": "medium", "constraints": {"max_amount": 5}}}
        looser = {
            "drops the tool": {**SPEND, "tools": {"other.tool": {"amount": "amount", "currency": "currency"}}},
            "changes the period": {**SPEND, "period": "month"},
            "raises the limit": {**SPEND, "limits": {"USD": 1000}},
            "drops the currency": {**SPEND, "limits": {"EUR": 100}},
            "remaps the amount argument": {**SPEND, "tools": {PAY: {"amount": "total", "currency": "currency"}}},
        }
        for label, spend in looser.items():
            with self.subTest(label):
                fresh_value = _policy(spend)
                fresh_value["tools"].update(other_tool)
                fresh = policy_from_dict(fresh_value, HOST)
                self.assertIs(_ReloadedPolicy(previous, fresh).spend_budgets, previous.spend_budgets)

    def test_a_scale_change_does_not_reinterpret_stored_totals(self):
        # Totals are stored in a fixed unit, so 50 USD is the same number at any policy scale.
        self.assertEqual(to_minor_units(50, 0), to_minor_units(50, 2))
        self.assertEqual(to_minor_units(50, 0), 50 * U)

    def test_calibration_the_split_test_bites_when_the_gate_is_off(self):
        # Neutralize the gate (always "reserved"): the split payment must then run twice. If this ever
        # passes with one call, the split test above is not exercising the budget.
        with mock.patch.object(self.store, "reserve_spend", return_value=True):
            self.run_payments([_pay(99), _pay(99)])
        self.assertEqual(len(self.recorder.calls), 2)


# --- amount-based approval: a call over a set amount needs a signed approval ------------------------

GATED = {**SPEND, "approval_above": {"USD": 50}}


class _PayOnce(ModelProvider):
    """Proposes one payment until the tool has run, then completes (so a resumed run re-proposes it)."""

    def __init__(self, payment: dict) -> None:
        self.payment = payment

    def decide(self, view, tools, grants=()):
        if PAY not in view.tool_results:
            return ProviderDecision("tool", PAY, self.payment)
        return ProviderDecision("complete", content="done")


class AmountApprovalParsingTests(unittest.TestCase):
    def test_a_threshold_parses_to_storage_units(self):
        self.assertEqual(parse_spend_budgets(GATED).approval_above, {"USD": 50 * U})
        self.assertEqual(parse_spend_budgets(SPEND).approval_above, {})

    def test_bad_thresholds_are_refused(self):
        for bad in ({"EUR": 50}, {"USD": True}, {"USD": -1}, {"USD": 50.001}, [50], {}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_spend_budgets({**SPEND, "approval_above": bad})


class HostAmountApprovalTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.policy_path = Path(self._dir.name) / "policy.json"
        self.authority = ApprovalAuthority.generate()
        self.write_policy(GATED)
        self.store = SQLiteRuntimeStore(Path(self._dir.name) / "store.sqlite3")
        self.recorder = _Recorder()

    def write_policy(self, spend: dict, impact: str = "medium") -> None:
        value = _policy(spend)
        value["tools"][PAY]["impact"] = impact
        value["approval_authorities"] = [
            {"key_id": self.authority.key_id, "approver": self.authority.approver, "public_key_b64": self.authority.public_key_b64()}
        ]
        self.policy_path.write_text(json.dumps(value), encoding="utf-8")

    def start(self, payment: dict):
        """(host, envelope, outcome) for one payment; outcome is the RunResult or the SecurityError."""
        tools = ToolRegistry()
        tools.register(PAY, self.recorder)
        with portmark_env():
            host = make_host(
                host_id=HOST, signer=host_signer(), policy_path=str(self.policy_path),
                store=self.store, tools=tools, providers={"p": _PayOnce(payment)},
            )
        envelope = HostSpendBudgetTests.envelope(host)
        try:
            return host, envelope, host.run(envelope)
        except SecurityError as error:
            return host, envelope, error

    def resume_with_approval(self, host, envelope, first, approved_arguments: dict):
        token = self.authority.issue(
            PAY, envelope.permit.subject, envelope.permit.audience, envelope.state.task_id, envelope.permit.nonce,
            approved_arguments, host.policy.policy_hash, trusted_now() + 60,
            checkpoint_generation=first.checkpoint["checkpoint_generation"],
        )
        envelope.state.memory["approvals"] = {PAY: asdict(token)}
        host.signer.seal(envelope)
        return host.run(envelope)

    def total(self, host) -> int:
        return self.store.spend_total(host.signer.issuer, "USD", period_key(trusted_now(), "day"))

    def test_a_payment_at_the_threshold_runs_without_approval(self):
        host, _, result = self.start(_pay(50))
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(self.recorder.calls), 1)
        self.assertEqual(self.total(host), 50 * U)

    def test_a_payment_over_the_threshold_waits_for_approval_and_nothing_runs(self):
        host, _, result = self.start(_pay(50.01))
        self.assertEqual(result.status, "awaiting_input")
        self.assertIs(result.result["approval_required"], True)
        self.assertEqual(result.result["approval_reason"], "amount")
        self.assertEqual(self.recorder.calls, [])
        self.assertEqual(self.total(host), 0)

    def test_a_signed_approval_lets_the_large_payment_run_and_it_is_charged(self):
        host, envelope, first = self.start(_pay(60))
        self.assertEqual(first.status, "awaiting_input")
        second = self.resume_with_approval(host, envelope, first, _pay(60))
        self.assertEqual(second.status, "completed")
        self.assertEqual(self.recorder.calls, [_pay(60)])
        self.assertEqual(self.total(host), 60 * U)

    def test_an_approval_for_a_smaller_amount_cannot_pay_a_larger_one(self):
        host, envelope, first = self.start(_pay(90))
        second = self.resume_with_approval(host, envelope, first, _pay(60))
        self.assertNotEqual(second.status, "completed")
        self.assertEqual(self.recorder.calls, [])
        self.assertEqual(self.total(host), 0)

    def test_an_unusable_amount_is_refused_before_anything_runs(self):
        for amount in ("60", True, 60.001):
            with self.subTest(amount=amount):
                _, _, outcome = self.start(_pay(amount))
                self.assertIsInstance(outcome, SecurityError)
        self.assertEqual(self.recorder.calls, [])

    def test_without_a_threshold_a_large_payment_needs_no_approval(self):
        # Control: the medium-impact tool needs no approval by itself, so the rule above is what gates it.
        self.write_policy(SPEND)
        _, _, result = self.start(_pay(60))
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(self.recorder.calls), 1)

    def test_a_reload_in_flight_cannot_drop_or_raise_a_threshold(self):
        from portmark.host import _ReloadedPolicy

        previous = policy_from_dict(_policy(GATED), HOST)
        for label, spend in {"drops it": SPEND, "raises it": {**SPEND, "approval_above": {"USD": 80}}}.items():
            with self.subTest(label):
                fresh = policy_from_dict(_policy(spend), HOST)
                self.assertIs(_ReloadedPolicy(previous, fresh).spend_budgets, previous.spend_budgets)
        lower = policy_from_dict(_policy({**SPEND, "approval_above": {"USD": 20}}), HOST)
        self.assertEqual(_ReloadedPolicy(previous, lower).spend_budgets.approval_above, {"USD": 20 * U})

    def test_a_call_outside_its_constraints_is_refused_before_anyone_is_asked_to_approve(self):
        # The argument check used to run only at launch, after the approval gate: a human was asked to
        # approve a call that could never run. It now runs before the gate too, for both approval rules.
        bad_calls = {"extra field": {**_pay(60), "note": "part 1"}, "wrong vendor": _pay(60, vendor="mallory")}
        for rule, (spend, impact) in {"amount rule": (GATED, "medium"), "impact rule": (SPEND, "external-payment")}.items():
            self.write_policy(spend, impact)
            for label, call in bad_calls.items():
                with self.subTest(rule=rule, call=label):
                    _, _, outcome = self.start(call)
                    self.assertIsInstance(outcome, SecurityError)
        self.assertEqual(self.recorder.calls, [])

    def test_a_valid_call_still_waits_for_approval_under_the_impact_rule(self):
        self.write_policy(SPEND, "external-payment")
        _, _, result = self.start(_pay(20))
        self.assertEqual(result.status, "awaiting_input")
        self.assertNotIn("approval_reason", result.result)

    def test_calibration_the_early_check_test_bites_when_the_early_check_is_off(self):
        # Neutralize only the early check: the bad call must then reach the approval gate and wait. If it is
        # still refused, the test above is passing on some other check, not the early one.
        with mock.patch("portmark.host.check_constraints"):
            _, _, result = self.start({**_pay(60), "note": "part 1"})
        self.assertEqual(result.status, "awaiting_input")

    def test_calibration_the_over_threshold_test_bites_when_the_rule_is_off(self):
        # Neutralize the rule: the 60 USD payment must then run with no approval. If it still waits, the
        # over-threshold tests above are not exercising the amount rule.
        with mock.patch("portmark.host.needs_amount_approval", return_value=False):
            _, _, result = self.start(_pay(60))
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(self.recorder.calls), 1)


if __name__ == "__main__":
    unittest.main()

"""A policy tool with no `impact` no longer runs silently as `low`.

`policy_from_dict` used to read `config.get("impact", "low")`, so a payment tool whose policy entry
forgot `impact` ran with no approval, and nothing said so. Now:

* 3A: the policy records which tools had no explicit impact. The production profile refuses such a
  policy (at boot and on every reload); development logs one warning per distinct policy file content.
* 3B: a side-effecting tool with no explicit impact is treated as `high`, so it needs approval even in
  development.
"""

from __future__ import annotations

import json
import secrets
import tempfile
import unittest
from pathlib import Path

from portmark._clock import trusted_now
from portmark.factory import make_host
from portmark.models import AgentEnvelope, AgentManifest, AgentState, Permit, ProviderDecision, ResourceBudget, ToolGrant
from portmark.policy import policy_from_dict
from portmark.providers import ModelProvider
from portmark.tools import IsolationMechanism, IsolationProfile, ToolRegistry, _has_tree_termination_primitive
from test_audit_floor import HOST, host_signer
from test_boundary_production_profile import PUBLIC, create_app, portmark_env

SEARCH = {"constraints": {"max_limit": 5, "arguments": {"query": {"type": "string"}}}, "output_projection": ["title"]}
WRITE = {"constraints": {"arguments": {"amount": {"type": "number"}}}, "output_projection": ["echo"]}


def _policy(tools: dict, version: str = "t1") -> dict:
    return {"version": version, "budget": {"max_steps": 6, "max_tool_calls": 3, "max_output_bytes": 65536}, "tools": tools}


def _with_impact(entry: dict, impact: str | None) -> dict:
    return {**entry, "impact": impact} if impact is not None else dict(entry)


class _CallsOnce(ModelProvider):
    """Calls `tool` once with `arguments`, then completes."""

    def __init__(self, tool: str, arguments: dict) -> None:
        self.tool, self.arguments = tool, arguments

    def decide(self, view, tools, grants=()):
        if not view.tool_results.get(self.tool):
            return ProviderDecision("tool", self.tool, self.arguments)
        return ProviderDecision("complete", content="done")


def _envelope(host, tool: str, constraints: dict, projection: tuple[str, ...]) -> AgentEnvelope:
    manifest = AgentManifest("agent:demo", "1.0.0", "p", (tool,))
    permit = Permit(
        host.signer.issuer, "agent:demo", host.host_id, trusted_now() + 600, secrets.token_hex(16),
        (ToolGrant(tool, constraints, projection),), ResourceBudget(6, 3, 32768),
    )
    return host.signer.seal(AgentEnvelope(manifest, permit, AgentState(secrets.token_hex(8), "go")))


def _events(result) -> list[str]:
    return [record["event"] for record in result.audit]


class PolicyRecordsImplicitImpactTests(unittest.TestCase):
    def test_a_tool_without_impact_is_recorded(self):
        policy = policy_from_dict(_policy({"catalog.search": SEARCH, "a.b": _with_impact(SEARCH, "low")}), HOST)
        self.assertEqual(policy.implicit_impacts, ("catalog.search",))

    def test_explicit_impacts_record_nothing(self):
        policy = policy_from_dict(_policy({"catalog.search": _with_impact(SEARCH, "low")}), HOST)
        self.assertEqual(policy.implicit_impacts, ())


class _PolicyFile(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.policy_path = Path(self._dir.name) / "policy.json"

    def write(self, impact: str | None, version: str = "t1") -> None:
        self.policy_path.write_text(json.dumps(_policy({"catalog.search": _with_impact(SEARCH, impact)}, version)), encoding="utf-8")

    def host(self, production: bool, reload_policy: bool = False, providers=None):
        with portmark_env():
            return make_host(
                host_id=HOST, signer=host_signer(), policy_path=str(self.policy_path),
                production=production, reload_policy=reload_policy, providers=providers,
            )


class ProductionRefusesImplicitImpactTests(_PolicyFile):
    def test_production_refuses_a_policy_tool_without_impact(self):
        self.write(None)
        with self.assertRaisesRegex(ValueError, "catalog.search.*no explicit impact"):
            self.host(production=True)

    def test_control_production_starts_with_an_explicit_impact(self):
        self.write("low")
        self.assertEqual(self.host(production=True).policy.implicit_impacts, ())

    def test_the_production_asgi_app_refuses_it_too(self):
        # The real production entry point, not only make_host(production=True).
        self.write(None)
        with portmark_env(**PUBLIC, PORTMARK_POLICY_PATH=str(self.policy_path)):
            with self.assertRaisesRegex(ValueError, "catalog.search.*no explicit impact"):
                create_app()
        # Control: the same production app builds once the impact is explicit.
        self.write("low")
        with portmark_env(**PUBLIC, PORTMARK_POLICY_PATH=str(self.policy_path)):
            app = create_app()
            self.assertTrue(callable(app))
            # Readiness re-reads the policy file: an edit that drops the impact is not "ready".
            self.write(None, version="t2")
            with self.assertRaisesRegex(ValueError, "catalog.search.*no explicit impact"):
                app.a2a_router.readiness_check()

    def test_a_production_reload_that_drops_impact_refuses_the_next_admission(self):
        self.write("low")
        provider = _CallsOnce("catalog.search", {"query": "x", "limit": 1})
        host = self.host(production=True, reload_policy=True, providers={"p": provider})
        self.write(None, version="t2")  # an operator edit removes the impact while the host runs
        with self.assertRaisesRegex(ValueError, "no explicit impact"):
            host.run(_envelope(host, "catalog.search", SEARCH["constraints"], ("title",)))

    def test_a_production_reload_that_drops_impact_mid_run_fails_the_run_closed(self):
        self.write("low")
        test = self

        class EditsPolicyThenCalls(_CallsOnce):
            def decide(self, view, tools, grants=()):
                if view.step == 0:
                    test.write(None, version="t2")  # the edit lands while the provider is answering
                return super().decide(view, tools, grants)

        host = self.host(
            production=True, reload_policy=True,
            providers={"p": EditsPolicyThenCalls("catalog.search", {"query": "x", "limit": 1})},
        )
        envelope = _envelope(host, "catalog.search", SEARCH["constraints"], ("title",))
        # The host's failure boundary closes the task durably as failed, then re-raises (PM-004).
        with self.assertRaisesRegex(ValueError, "no explicit impact"):
            host.run(envelope)
        checkpoint = host.store.load_checkpoint(envelope.state.task_id)
        self.assertEqual(checkpoint["status"], "failed")
        self.assertEqual(checkpoint["tool_calls"], 0)  # the tool never ran on a silent "low"


class DevelopmentWarnsTests(_PolicyFile):
    def test_development_starts_and_warns_once_per_policy_content(self):
        self.write(None)
        with self.assertLogs("portmark", level="WARNING") as logs:
            host = self.host(production=False, reload_policy=True)
            for _ in range(3):  # a reloading host calls the loader twice per step
                host._active_policy()
        warnings = [line for line in logs.output if "no explicit impact" in line]
        self.assertEqual(len(warnings), 1, logs.output)
        self.assertIn("catalog.search", warnings[0])


@unittest.skipUnless(_has_tree_termination_primitive(), "side-effecting tools need a process-tree hard-kill primitive")
class SideEffectingDefaultTests(unittest.TestCase):
    """3B: development, a side-effecting tool, no impact -> approval is required anyway."""

    def run_write(self, impact: str | None):
        registry = ToolRegistry(isolation_profile=IsolationProfile(mechanism=IsolationMechanism.EXTERNAL_CONTAINER, acknowledged_by="test-suite"))
        registry.register_isolated(
            "ledger.write", "isolated_tool_fixtures:echo", side_effecting=True,
            reconcile="isolated_tool_fixtures:reconcile_charge",
        )
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "policy.json"
            path.write_text(json.dumps(_policy({"ledger.write": _with_impact(WRITE, impact)})), encoding="utf-8")
            with portmark_env():
                host = make_host(
                    host_id=HOST, signer=host_signer(), policy_path=str(path), tools=registry,
                    providers={"p": _CallsOnce("ledger.write", {"amount": 5})},
                )
            return host.run(_envelope(host, "ledger.write", WRITE["constraints"], ("echo",)))

    def test_a_side_effecting_tool_without_impact_needs_approval(self):
        result = self.run_write(None)
        self.assertIn("approval.requested", _events(result))
        self.assertEqual(result.result["impact"], "high")
        self.assertNotIn("tool.executed", _events(result))

    def test_control_explicit_low_is_the_operators_choice_and_needs_none(self):
        result = self.run_write("low")
        self.assertNotIn("approval.requested", _events(result))

    def test_the_pre_launch_cancel_recheck_uses_the_same_decision(self):
        # test_runtime's test_cancel_after_consume_is_caught_before_tool_launch, with the payment tool
        # side-effecting and given NO impact. The gate asks for approval (3B); the pre-launch cancel
        # re-check must agree, or an approved, cancelled task would launch its effect.
        from dataclasses import asdict

        from authority_fixtures import ApprovalAuthority
        from portmark.security import HostPolicy
        from portmark.storage import InMemoryRuntimeStore
        from test_runtime import PaymentProvider, RuntimeTests

        class CancelBetween(InMemoryRuntimeStore):
            hide_next_read = False

            def transaction(self):
                txn = super().transaction()
                txn.is_task_cancelled = lambda task_id: False  # cancel not yet committed at gate time
                return txn

            def is_task_cancelled(self, task_id):
                # Batch 2's post-decision re-read comes first; the cancel commits just after it.
                if self.hide_next_read:
                    self.hide_next_read = False
                    return False
                return super().is_task_cancelled(task_id)

        registry = ToolRegistry(isolation_profile=IsolationProfile(mechanism=IsolationMechanism.EXTERNAL_CONTAINER, acknowledged_by="test-suite"))
        registry.register_isolated(
            "payments.reserve", "isolated_tool_fixtures:echo", side_effecting=True,
            reconcile="isolated_tool_fixtures:reconcile_charge",
        )
        store = CancelBetween()
        authority = ApprovalAuthority.generate()
        with portmark_env():
            host = make_host(store=store, tools=registry, attestation_policy=None, allow_ephemeral_signing_key=True)
        host.policy = HostPolicy(
            "host:local-demo",
            (ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}, ("reserved",)),),
            ResourceBudget(), "policy-v1", "policy-hash", {"payments.reserve": "low"}, (authority.trusted_approver(),),
            implicit_impacts=("payments.reserve",),
        )
        host.providers["payer"] = PaymentProvider()
        helpers = RuntimeTests()
        envelope, first = helpers._suspend_payment_envelope(host, "cancel between")
        self.assertEqual(first.status, "awaiting_input")  # the gate: side-effecting, no impact -> approval
        token = helpers._mint_payment_approval(authority, envelope, first.checkpoint["checkpoint_generation"])
        envelope.state.memory["approvals"] = {"payments.reserve": asdict(token)}
        host.signer.seal(envelope)
        store.cancel_task(envelope.state.task_id)  # committed; the pre-launch read will observe it
        store.hide_next_read = True
        result = host.run(envelope)
        self.assertFalse(store.hide_next_read)  # the post-decision re-read ran (and missed the cancel)
        self.assertEqual(result.status, "failed")
        denials = [record for record in result.audit if record["event"] == "approval.denied"]
        self.assertEqual([denial["details"]["reason"] for denial in denials], ["cancelled"])
        self.assertNotIn("tool.executed", _events(result))


if __name__ == "__main__":
    unittest.main()

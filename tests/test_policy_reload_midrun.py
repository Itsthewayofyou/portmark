"""U1: with reload_policy on, a policy that narrows while a run is in flight must narrow that run.

The provider below runs a hook inside decide() -- the window a slow remote provider leaves open -- that
swaps what the policy loader returns, then proposes a catalog.search. Each test compares against the
same flow with no swap, where the search legitimately runs. The oracle for "did the tool run" is a spy
on the tool registry itself, not the audit log the host writes about itself; the outcome is the stored
checkpoint, since a refused step closes the task as failed and then re-raises to the caller.
"""
import unittest
from unittest.mock import patch

from portmark.factory import make_demo_envelope, make_host
from portmark.models import ProviderDecision, ResourceBudget, ToolGrant
from portmark.providers import ModelProvider
from portmark.security import HostPolicy, MigrationPolicy, SecurityError

RESERVE = ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"})


def _search(max_limit):
    return ToolGrant("catalog.search", {"max_limit": max_limit, "arguments": {"query": {"type": "string"}}}, ("id", "title"))


def _policy(version, grants, search_impact="low", migrate_to=()):
    return HostPolicy(
        "host:local-demo", grants, ResourceBudget(max_steps=10, max_tool_calls=5, max_output_bytes=65_536),
        version, f"hash-{version}", {"catalog.search": search_impact, "payments.reserve": "external-payment"},
        migration=MigrationPolicy(allowed=bool(migrate_to), destinations=tuple(migrate_to)),
    )


class SearchAfterHook(ModelProvider):
    def __init__(self, hook, limit):
        self.hook = hook
        self.limit = limit

    def decide(self, view, available_tools, grants=()):
        if view.tool_results.get("catalog.search"):
            return ProviderDecision("complete", content={"done": True})
        self.hook()
        return ProviderDecision("tool", "catalog.search", {"query": "widgets", "limit": self.limit})


class MigrateAfterHook(ModelProvider):
    def __init__(self, hook):
        self.hook = hook

    def decide(self, view, available_tools, grants=()):
        self.hook()
        return ProviderDecision("migrate", destination="host:peer")


class TwoSearches(ModelProvider):
    """Searches, then (after `hook`) records what it can see of the first result and searches again."""

    def __init__(self, hook):
        self.hook = hook
        self.decisions = 0
        self.seen = None

    def decide(self, view, available_tools, grants=()):
        self.decisions += 1
        if self.decisions == 1:
            return ProviderDecision("tool", "catalog.search", {"query": "widgets", "limit": 1})
        if self.decisions == 2:
            self.seen = view.tool_results.get("catalog.search")
            return ProviderDecision("tool", "catalog.search", {"query": "gadgets", "limit": 1})
        return ProviderDecision("complete", content={"done": True})


class PolicyReloadMidRunTests(unittest.TestCase):
    def _run(self, swap_to=None, admitted=None, limit=2, reload_policy=True, migrate=False):
        """Returns (RunResult or the raised error, stored checkpoint status, tools actually launched)."""
        current = [admitted or _policy("v1", (_search(5), RESERVE))]
        host = make_host(attestation_policy=None, allow_ephemeral_signing_key=True)
        # make_host takes a policy file; drive the reload seam directly so the test controls timing.
        host._policy_loader = lambda: current[0]() if callable(current[0]) else current[0]
        host._reload_policy = reload_policy

        def hook():
            if swap_to is not None:
                current[0] = swap_to

        host.providers["reloader"] = MigrateAfterHook(hook) if migrate else SearchAfterHook(hook, limit)
        envelope = make_demo_envelope(host, "search", "reloader")
        if migrate:
            object.__setattr__(envelope.permit, "delegation_allowed", True)
            host.signer.seal(envelope)
        launched = []
        invoke = host.tools.invoke

        def recording_invoke(permit, name, *args, **kwargs):
            output = invoke(permit, name, *args, **kwargs)  # a refusal inside the registry raises here
            launched.append(name)
            return output

        with patch.object(host.tools, "invoke", recording_invoke):
            try:
                outcome = host.run(envelope)
            except (SecurityError, ValueError) as error:
                outcome = error
        return outcome, host.store.load_checkpoint(envelope.state.task_id)["status"], launched

    @staticmethod
    def _events(result, name):
        return [event["details"] for event in result.audit if event["event"] == name]

    def test_control_without_a_policy_change_runs_the_tool(self):
        result, status, launched = self._run(swap_to=_policy("v1", (_search(5), RESERVE)))
        self.assertEqual((status, launched), ("completed", ["catalog.search"]))
        self.assertEqual(self._events(result, "policy.reloaded"), [])

    def test_tool_removed_by_a_mid_run_reload_is_refused(self):
        error, status, launched = self._run(swap_to=_policy("v2", (RESERVE,)))
        self.assertIsInstance(error, SecurityError)
        self.assertEqual((status, launched), ("failed", []))

    def test_constraint_tightened_by_a_mid_run_reload_is_enforced(self):
        error, status, launched = self._run(swap_to=_policy("v2", (_search(1), RESERVE)), limit=2)
        self.assertIsInstance(error, SecurityError)
        self.assertEqual((status, launched), ("failed", []))

    def test_a_mid_run_reload_never_widens_the_run(self):
        # Admitted under max_limit 1; the reload raises it to 5. The run keeps the tighter bound.
        error, status, launched = self._run(
            admitted=_policy("v1", (_search(1), RESERVE)), swap_to=_policy("v2", (_search(5), RESERVE)), limit=2
        )
        self.assertIsInstance(error, SecurityError)
        self.assertEqual((status, launched), ("failed", []))

    def test_approval_required_by_a_mid_run_reload_gates_the_call(self):
        result, status, launched = self._run(swap_to=_policy("v2", (_search(5), RESERVE), search_impact="external-payment"))
        self.assertEqual((status, launched), ("awaiting_input", []))
        self.assertEqual(result.result["policy_hash"], "hash-v2")
        self.assertEqual(self._events(result, "policy.reloaded"), [{"policy_version": "v2", "policy_hash": "hash-v2"}])

    def test_approval_dropped_by_a_mid_run_reload_still_gates_the_call(self):
        result, status, launched = self._run(
            admitted=_policy("v1", (_search(5), RESERVE), search_impact="external-payment"),
            swap_to=_policy("v2", (_search(5), RESERVE)),
        )
        self.assertEqual((status, launched), ("awaiting_input", []))

    def test_migration_closed_by_a_mid_run_reload_is_refused(self):
        error, status, _ = self._run(
            admitted=_policy("v1", (_search(5), RESERVE), migrate_to=("host:peer",)),
            swap_to=_policy("v2", (_search(5), RESERVE)), migrate=True,
        )
        self.assertRegex(str(error), "host policy does not allow migration")
        self.assertEqual(status, "failed")

    def test_migration_opened_by_a_mid_run_reload_stays_closed(self):
        error, status, _ = self._run(swap_to=_policy("v2", (_search(5), RESERVE), migrate_to=("host:peer",)), migrate=True)
        self.assertRegex(str(error), "host policy does not allow migration")
        self.assertEqual(status, "failed")

    def test_a_loader_that_fails_mid_run_ends_the_task_as_failed(self):
        def broken():
            raise ValueError("policy file is unreadable")

        error, status, launched = self._run(swap_to=broken)
        self.assertIsInstance(error, ValueError)
        self.assertEqual((status, launched), ("failed", []))

    def _two_searches(self, after_first_tool):
        """Swap the policy right after the first tool runs, so it lands BEFORE the second view is built."""
        current = [_policy("v1", (_search(5), RESERVE))]
        host = make_host(attestation_policy=None, allow_ephemeral_signing_key=True)
        host._policy_loader = lambda: current[0]
        host._reload_policy = True
        provider = TwoSearches(lambda: None)
        host.providers["reloader"] = provider
        envelope = make_demo_envelope(host, "search", "reloader")
        launched = []
        invoke = host.tools.invoke

        def recording_invoke(permit, name, *args, **kwargs):
            output = invoke(permit, name, *args, **kwargs)
            launched.append(name)
            if len(launched) == 1 and after_first_tool is not None:
                current[0] = after_first_tool
            return output

        with patch.object(host.tools, "invoke", recording_invoke):
            try:
                host.run(envelope)
            except SecurityError:
                pass
        return provider, host.store.load_checkpoint(envelope.state.task_id)["status"], launched

    def test_projection_narrowed_by_a_reload_applies_before_the_provider_sees_the_view(self):
        control, _, _ = self._two_searches(None)
        self.assertIn("title", control.seen[0])
        id_only = ToolGrant("catalog.search", {"max_limit": 5, "arguments": {"query": {"type": "string"}}}, ("id",))
        provider, _, _ = self._two_searches(_policy("v2", (id_only, RESERVE)))
        self.assertNotIn("title", provider.seen[0])
        self.assertIn("id", provider.seen[0])

    def test_step_budget_shrunk_below_the_current_step_stops_the_next_action(self):
        _, status, launched = self._two_searches(None)
        self.assertEqual((status, launched), ("completed", ["catalog.search", "catalog.search"]))
        one_step = HostPolicy(
            "host:local-demo", (_search(5), RESERVE), ResourceBudget(max_steps=1, max_tool_calls=5, max_output_bytes=65_536),
            "v2", "hash-v2", {"catalog.search": "low", "payments.reserve": "external-payment"},
        )
        _, status, launched = self._two_searches(one_step)
        self.assertEqual((status, launched), ("failed", ["catalog.search"]))

    def test_reload_off_is_unchanged(self):
        result, status, launched = self._run(swap_to=_policy("v2", (RESERVE,)), reload_policy=False)
        self.assertEqual((status, launched), ("completed", ["catalog.search"]))
        self.assertEqual(self._events(result, "policy.reloaded"), [])


if __name__ == "__main__":
    unittest.main()

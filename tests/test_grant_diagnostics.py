"""Issue #16: a refused tool must say WHICH stage refused it.

`effective_permit` folds three grant sets together and reports only the absence.
Every misconfiguration therefore produced the same sentence, and it pointed at
the envelope — frequently the one place that was correct. These tests pin each
of the four causes to a distinguishable message.

They assert on substrings that carry the cause, not on whole sentences, so
rewording stays cheap while a message that stops naming its stage goes red.
"""

from __future__ import annotations

import time
import unittest

from portmark.models import AgentManifest, Permit, ResourceBudget, ToolGrant
from portmark.security import HostPolicy

AUDIENCE = "host-1"
BUDGET = ResourceBudget(max_steps=5, max_tool_calls=5, max_output_bytes=65_536)


def manifest(*tools: str) -> AgentManifest:
    return AgentManifest(agent_id="agent-1", version="1", provider="deterministic", requested_tools=tools)


def permit(*grants: ToolGrant) -> Permit:
    return Permit(
        issuer="issuer-1",
        subject="agent-1",
        audience=AUDIENCE,
        expires_at=int(time.time()) + 600,
        nonce="n1",
        grants=grants,
        budget=BUDGET,
    )


def policy(*grants: ToolGrant, version: str = "test-policy-v3") -> HostPolicy:
    return HostPolicy(audience=AUDIENCE, grants=grants, budget=BUDGET, policy_version=version)


class ExplainMissingGrantTest(unittest.TestCase):
    def test_manifest_did_not_request_the_tool(self) -> None:
        message = policy(ToolGrant("t.call")).explain_missing_grant(
            manifest("other.tool"), permit(ToolGrant("t.call")), "t.call"
        )
        self.assertIn("manifest does not request it", message)
        self.assertIn("other.tool", message, "the message should show what WAS requested")

    def test_permit_omits_the_tool(self) -> None:
        message = policy(ToolGrant("t.call")).explain_missing_grant(
            manifest("t.call"), permit(ToolGrant("other.tool")), "t.call"
        )
        self.assertIn("absent", message)
        self.assertIn("permit", message)

    def test_host_policy_omits_the_tool(self) -> None:
        message = policy(ToolGrant("other.tool")).explain_missing_grant(
            manifest("t.call"), permit(ToolGrant("t.call")), "t.call"
        )
        self.assertIn("test-policy-v3", message, "the message should name the policy version")
        self.assertIn("ceiling", message, "the message should explain why a permit cannot fix this")

    def test_constraints_could_not_be_combined(self) -> None:
        """The cause that #15 used to produce, and the one nobody could diagnose."""
        message = policy(ToolGrant("t.call", {"arguments": {"a": {"const": "x"}}})).explain_missing_grant(
            manifest("t.call"),
            permit(ToolGrant("t.call", {"arguments": {"a": {"const": "y"}}})),
            "t.call",
        )
        self.assertIn("could not be combined", message)
        self.assertIn("arguments.a.const", message, "the message should name the key that failed")
        self.assertIn("one place", message, "the message should say what to do about it")

    def test_the_four_causes_are_distinguishable(self) -> None:
        """Control: the whole point is that these do not read alike."""
        messages = {
            policy(ToolGrant("t.call")).explain_missing_grant(manifest(), permit(ToolGrant("t.call")), "t.call"),
            policy(ToolGrant("t.call")).explain_missing_grant(manifest("t.call"), permit(), "t.call"),
            policy().explain_missing_grant(manifest("t.call"), permit(ToolGrant("t.call")), "t.call"),
            policy(ToolGrant("t.call", {"arguments": {"a": {"const": "x"}}})).explain_missing_grant(
                manifest("t.call"), permit(ToolGrant("t.call", {"arguments": {"a": {"const": "y"}}})), "t.call"
            ),
        }
        self.assertEqual(len(messages), 4, "two causes produce the same message")


class HostReportsTheCauseTest(unittest.TestCase):
    """The diagnostic has to reach the error a user actually sees."""

    def test_host_error_names_the_stage(self) -> None:
        from portmark.host import AgentHost

        self.assertIn(
            "explain_missing_grant",
            AgentHost._apply_decision.__code__.co_names + tuple(AgentHost._apply_decision.__code__.co_consts or ()),
            msg="AgentHost no longer calls the diagnostic; the message regressed to the generic one",
        )


if __name__ == "__main__":
    unittest.main()

"""Issue #18: make_host accepts in-process providers.

Before this, the only way to drive an agent with a local model was to run a
separate HTTP service translating Portmark's provider protocol and point
--provider-endpoint at it. That adapter is a good seam and remains the
recommended shape, but it should be a choice, not the only path.
"""

from __future__ import annotations

import unittest

from portmark.factory import make_host
from portmark.models import ProviderDecision
from portmark.providers import DeterministicProvider, ModelProvider


class StubProvider(ModelProvider):
    def decide(self, state, available_tools, grants=()):
        return ProviderDecision(kind="complete", content={"stub": True})


class MakeHostProvidersTest(unittest.TestCase):
    def test_provider_can_be_passed_in_process(self) -> None:
        host = make_host(providers={"local": StubProvider()})
        self.assertIsInstance(host.providers["local"], StubProvider)

    def test_defaults_survive(self) -> None:
        """Merge over the defaults, not replace them.

        Replacing would silently remove `deterministic` and break every envelope
        naming it. This is where make_host's `providers` differs from `tools`.
        """
        host = make_host(providers={"local": StubProvider()})
        self.assertIsInstance(host.providers["deterministic"], DeterministicProvider)

    def test_a_default_can_still_be_shadowed(self) -> None:
        host = make_host(providers={"deterministic": StubProvider()})
        self.assertIsInstance(host.providers["deterministic"], StubProvider)

    def test_omitting_providers_changes_nothing(self) -> None:
        self.assertIsInstance(make_host().providers["deterministic"], DeterministicProvider)


if __name__ == "__main__":
    unittest.main()

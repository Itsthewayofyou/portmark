"""Explicit resource caps must be refused where they cannot be enforced.

TOOLS.md promises that applying the caps is fail-closed: a requested cap that cannot be put in force
is refused, never silently skipped. On Windows there is no POSIX `setrlimit`, so the worker skips the
caps and returns no refusal, and the Job Object gets no memory ceiling. A registry built with
`resource_limits={...}` then enforced nothing.

`ToolRegistry` now refuses at construction when an operator passes explicit `resource_limits` on a
platform without `setrlimit`. `disable_resource_limits=True` is the explicit opt-out. The default caps
(no `resource_limits`, or `{}`) are not an explicit request and do not refuse.

The Windows branch is simulated by setting the runner's `_resource` sentinel to None -- the same
sentinel the worker checks -- so this runs on Linux too.
"""

from __future__ import annotations

import time
import unittest
from unittest import mock

from portmark import tool_subprocess_runner
from portmark.models import Permit, ToolGrant
from portmark.tools import ToolExecutionError, ToolRegistry


def _no_setrlimit():
    return mock.patch.object(tool_subprocess_runner, "_resource", None)


def _permit(name: str) -> Permit:
    return Permit(
        issuer="issuer",
        subject="agent",
        audience="host",
        expires_at=int(time.time()) + 60,
        nonce="nonce-windows-caps",
        grants=(ToolGrant(name),),
    )


class ExplicitCapsRefusedWithoutSetrlimitTest(unittest.TestCase):
    def test_explicit_resource_limits_refused_without_setrlimit(self):
        with _no_setrlimit():
            with self.assertRaisesRegex(RuntimeError, "address_space"):
                ToolRegistry(resource_limits={"address_space": 256 * 1024 * 1024})

    def test_every_operator_key_is_refused_without_setrlimit(self):
        with _no_setrlimit():
            for key in ("address_space", "file_size", "open_files", "processes"):
                with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, key):
                    ToolRegistry(resource_limits={key: 4096})

    def test_disable_resource_limits_is_the_opt_out(self):
        with _no_setrlimit():
            registry = ToolRegistry(disable_resource_limits=True)
        self.assertEqual(registry.resource_limits, {})

    def test_default_caps_do_not_refuse_without_setrlimit(self):
        # Control: no explicit request, so a default Windows registry still builds.
        with _no_setrlimit():
            ToolRegistry()
            ToolRegistry(resource_limits={})

    def test_falsey_dict_subclass_is_still_an_explicit_request(self):
        class FalseyDict(dict):
            def __bool__(self):
                return False

        with _no_setrlimit():
            with self.assertRaisesRegex(RuntimeError, "address_space"):
                ToolRegistry(resource_limits=FalseyDict(address_space=256 * 1024 * 1024))

    def test_caps_set_after_construction_are_refused_at_launch(self):
        # resource_limits is a public attribute, so the construction check alone can be bypassed.
        registry = ToolRegistry()
        registry.register_isolated("iso.echo", "isolated_tool_fixtures:echo")
        registry.resource_limits = {"address_space": 256 * 1024 * 1024}
        with _no_setrlimit():
            with self.assertRaisesRegex(ToolExecutionError, "cannot be enforced"):
                registry.invoke(_permit("iso.echo"), "iso.echo", {})

    def test_explicit_resource_limits_still_accepted_with_setrlimit(self):
        # Control: on a POSIX platform the caps apply, so the request is accepted as before.
        if tool_subprocess_runner._resource is None:
            self.skipTest("POSIX setrlimit is not available on this platform")
        registry = ToolRegistry(resource_limits={"address_space": 256 * 1024 * 1024})
        self.assertEqual(registry.resource_limits["address_space"], 256 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()

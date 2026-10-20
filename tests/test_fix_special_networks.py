"""The public-address check refuses every special-purpose network, not only the ones Python calls private.

`_address_is_disallowed` used `is_private`/`is_loopback`/`is_link_local`/`is_multicast`/`is_reserved`/
`is_unspecified`. Python marks the shared address space `100.64.0.0/10` (carrier-grade NAT; Tailscale
and many cloud-internal endpoints live there) as none of those, so a provider endpoint or MCP host that
resolved to `100.100.100.200` passed as "public". Now an address must also be globally reachable
(`is_global`), and special blocks are refused by name: `192.88.99.0/24`, `fec0::/10`, the forms that
embed an IPv4 address (6to4 `2002::/16`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`), the documentation
ranges and SRv6 SIDs. They are named because Python's own tables for them differ by patch release: on an
older 3.11 (the Windows CI runner), `2002:7f00:1::1` -- 6to4 for 127.0.0.1 -- was "global" and accepted.
"""

from __future__ import annotations

import unittest

from portmark.providers import _address_is_disallowed, _classify_address, resolve_public_address
from portmark.security import SecurityError


def disallowed(ip: str) -> bool:
    return _address_is_disallowed(_classify_address(ip))


class SpecialNetworkTests(unittest.TestCase):
    def test_shared_address_space_is_refused(self):
        for ip in ("100.64.0.1", "100.100.100.200", "100.127.255.254"):
            with self.subTest(ip=ip):
                self.assertTrue(disallowed(ip))

    def test_named_special_networks_are_refused(self):
        for ip in ("192.88.99.1", "fec0::1"):
            with self.subTest(ip=ip):
                self.assertTrue(disallowed(ip))

    def test_ipv6_that_embeds_an_ipv4_address_is_refused_on_every_python(self):
        # 6to4 / NAT64 of 127.0.0.1, 10.0.0.1, 169.254.169.254, and of the public 8.8.8.8: refused outright,
        # by name, so the answer does not depend on the running Python's patch-level address tables.
        for ip in ("2002:7f00:1::1", "2002:a00:1::1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe",
                   "2002:808:808::1", "64:ff9b::808:808", "64:ff9b:1::1"):
            with self.subTest(ip=ip):
                self.assertTrue(disallowed(ip))

    def test_documentation_and_srv6_ranges_are_refused(self):
        for ip in ("2001:db8::1", "3fff::1", "5f00::1"):
            with self.subTest(ip=ip):
                self.assertTrue(disallowed(ip))

    def test_the_named_blocks_decide_without_pythons_tables(self):
        # Simulate an older Python whose tables call these addresses global and not private/reserved: the
        # named list alone must still refuse them. (This is how the Windows 3.11 runner behaved.)
        from unittest import mock
        import ipaddress as ipa
        with mock.patch.object(ipa.IPv6Address, "is_global", new_callable=mock.PropertyMock, return_value=True), \
                mock.patch.object(ipa.IPv6Address, "is_private", new_callable=mock.PropertyMock, return_value=False), \
                mock.patch.object(ipa.IPv6Address, "is_reserved", new_callable=mock.PropertyMock, return_value=False):
            for ip in ("2002:7f00:1::1", "64:ff9b::7f00:1", "64:ff9b:1::1", "fec0::1", "2001:db8::1"):
                with self.subTest(ip=ip):
                    self.assertTrue(disallowed(ip))
            self.assertFalse(disallowed("2606:4700:4700::1111"))  # control: an ordinary global address passes

    def test_resolve_public_address_refuses_shared_address_space(self):
        with self.assertRaisesRegex(SecurityError, "non-public"):
            resolve_public_address("100.100.100.200", 443)

    def test_control_public_addresses_still_pass(self):
        for ip in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
            with self.subTest(ip=ip):
                self.assertFalse(disallowed(ip))
        self.assertEqual(resolve_public_address("8.8.8.8", 443), "8.8.8.8")

    def test_control_already_refused_networks_stay_refused(self):
        # The literals are addresses the check must REFUSE, not a bind; bandit B104 flags "0.0.0.0" regardless.
        for ip in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "0.0.0.0", "224.0.0.1"):  # nosec B104
            with self.subTest(ip=ip):
                self.assertTrue(disallowed(ip))


if __name__ == "__main__":
    unittest.main()

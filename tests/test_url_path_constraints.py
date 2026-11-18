"""S3: URL port, path and query constraints (allowed_ports, path_prefixes, allowed_query_keys).

Hand-derived cases, not generated from the implementation. Each refusal names the attack it stops.
The no-widening property for these keys is covered by test_constraint_intersection's generator.
"""

from __future__ import annotations

import unittest

from portmark.models import ToolGrant
from portmark.security import SecurityError, check_constraints, intersect_grants

TOOL = "http.fetch"


def grant(spec: dict) -> dict:
    return {"arguments": {"url": spec}}


def accepts(spec: dict, url: str) -> bool:
    try:
        check_constraints(grant(spec), {"url": url})
    except SecurityError:
        return False
    return True


def merged_spec(left: dict, right: dict) -> dict | None:
    result = intersect_grants((ToolGrant(TOOL, grant(left)),), (ToolGrant(TOOL, grant(right)),))
    return result[0].constraints["arguments"]["url"] if result else None


def kept(left: dict, right: dict) -> dict:
    merged = merged_spec(left, right)
    if merged is None:
        raise AssertionError("the merge dropped a grant it should keep")
    return merged


class AllowedPortsTest(unittest.TestCase):
    def test_default_port_counts_as_that_port(self):
        self.assertTrue(accepts({"allowed_ports": [443]}, "https://api.example.com/x"))
        self.assertTrue(accepts({"allowed_ports": [80]}, "http://api.example.com/x"))

    def test_explicit_port_must_be_listed(self):
        self.assertTrue(accepts({"allowed_ports": [8443]}, "https://api.example.com:8443/x"))
        self.assertFalse(accepts({"allowed_ports": [443]}, "https://api.example.com:8443/x"))

    def test_unknown_scheme_without_port_is_refused(self):
        # No default port to compare against: refuse rather than guess.
        self.assertFalse(accepts({"allowed_ports": [21]}, "ftp://files.example.com/x"))

    def test_invalid_port_is_refused(self):
        self.assertFalse(accepts({"allowed_ports": [443]}, "https://api.example.com:99999/x"))

    def test_bad_constraint_is_refused(self):
        for bad in ([], ["443"], [True], [0], [70000], 443):
            with self.subTest(bad=bad):
                self.assertFalse(accepts({"allowed_ports": bad}, "https://api.example.com/x"))

    def test_merge_is_intersection(self):
        self.assertEqual(kept({"allowed_ports": [443, 8443]}, {"allowed_ports": [443]})["allowed_ports"], [443])
        self.assertIsNone(merged_spec({"allowed_ports": [8443]}, {"allowed_ports": [443]}))


class PathPrefixesTest(unittest.TestCase):
    def test_segment_bounded_prefix(self):
        spec = {"path_prefixes": ["/v1"]}
        self.assertTrue(accepts(spec, "https://api.example.com/v1"))
        self.assertTrue(accepts(spec, "https://api.example.com/v1/items"))
        self.assertFalse(accepts(spec, "https://api.example.com/v10"))  # sibling, not child
        self.assertFalse(accepts(spec, "https://api.example.com/admin"))

    def test_trailing_slash_on_prefix_means_the_same_prefix(self):
        spec = {"path_prefixes": ["/v1/"]}
        self.assertTrue(accepts(spec, "https://api.example.com/v1/items"))
        self.assertFalse(accepts(spec, "https://api.example.com/v10"))

    def test_root_prefix_admits_every_path(self):
        self.assertTrue(accepts({"path_prefixes": ["/"]}, "https://api.example.com/anything/at/all"))
        self.assertTrue(accepts({"path_prefixes": ["/"]}, "https://api.example.com"))

    def test_empty_path_is_root(self):
        self.assertFalse(accepts({"path_prefixes": ["/v1"]}, "https://api.example.com"))

    def test_traversal_and_ambiguous_paths_are_refused(self):
        spec = {"path_prefixes": ["/v1"]}
        for url in (
            "https://api.example.com/v1/../admin",   # dot-segment escape
            "https://api.example.com/v1/./x",        # dot segment
            "https://api.example.com/v1/%2e%2e/admin",  # encoded dot-segment
            "https://api.example.com/v1%2F..%2Fadmin",  # encoded slash
            "https://api.example.com/v1%5C..%5Cadmin",  # encoded backslash
            "https://api.example.com/v1\\..\\admin",  # raw backslash
            "https://api.example.com/v1//x",         # empty segment
            "https://api.example.com/v1#frag",       # fragment
        ):
            with self.subTest(url=url):
                self.assertFalse(accepts(spec, url))

    def test_bad_constraint_is_refused(self):
        for bad in ([], ["v1"], [""], [1], "/v1", ["/v1/../x"]):
            with self.subTest(bad=bad):
                self.assertFalse(accepts({"path_prefixes": bad}, "https://api.example.com/v1"))

    def test_merge_keeps_the_narrower_prefix(self):
        self.assertEqual(kept({"path_prefixes": ["/v1"]}, {"path_prefixes": ["/v1/items"]})["path_prefixes"], ["/v1/items"])
        self.assertEqual(kept({"path_prefixes": ["/v1/items"]}, {"path_prefixes": ["/"]})["path_prefixes"], ["/v1/items"])

    def test_merge_of_siblings_drops_the_grant(self):
        self.assertIsNone(merged_spec({"path_prefixes": ["/v1"]}, {"path_prefixes": ["/v10"]}))

    def test_merged_prefix_never_admits_what_either_side_refuses(self):
        left, right = {"path_prefixes": ["/v1", "/v2/public"]}, {"path_prefixes": ["/v2", "/v3"]}
        merged = kept(left, right)
        for path in ("/v1", "/v2", "/v2/public", "/v2/public/a", "/v2/private", "/v3", "/v10"):
            url = "https://api.example.com" + path
            with self.subTest(path=path):
                if accepts(merged, url):
                    self.assertTrue(accepts(left, url) and accepts(right, url))


class AllowedQueryKeysTest(unittest.TestCase):
    def test_only_listed_keys(self):
        spec = {"allowed_query_keys": ["q", "page"]}
        self.assertTrue(accepts(spec, "https://api.example.com/s?q=red&page=2"))
        self.assertTrue(accepts(spec, "https://api.example.com/s"))
        self.assertFalse(accepts(spec, "https://api.example.com/s?q=red&token=x"))

    def test_duplicate_key_is_refused(self):
        # Two parsers may pick different copies (parameter pollution).
        self.assertFalse(accepts({"allowed_query_keys": ["q"]}, "https://api.example.com/s?q=a&q=b"))

    def test_key_without_value_is_still_a_key(self):
        self.assertFalse(accepts({"allowed_query_keys": ["q"]}, "https://api.example.com/s?debug"))

    def test_encoded_key_is_compared_decoded(self):
        self.assertFalse(accepts({"allowed_query_keys": ["q"]}, "https://api.example.com/s?%74oken=x"))

    def test_merge_is_intersection(self):
        self.assertEqual(
            kept({"allowed_query_keys": ["q", "page"]}, {"allowed_query_keys": ["q"]})["allowed_query_keys"], ["q"]
        )


class ExistingUrlBehaviourTest(unittest.TestCase):
    def test_host_only_constraints_are_unchanged(self):
        # No new key present: fragments and odd paths behave exactly as before S3.
        self.assertTrue(accepts({"allowed_hosts": ["api.example.com"]}, "https://api.example.com/a/../b#x"))


if __name__ == "__main__":
    unittest.main()

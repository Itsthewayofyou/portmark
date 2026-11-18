"""S4: nested output projection with JSON Pointer paths (RFC 6901).

An entry starting with "/" is a path; any other entry is a top-level key exactly as before, so every
existing policy keeps its meaning (a key named "a.b" is still the top-level key "a.b"). Lists are
mapped at every level, the same rule the top level already used.
"""

from __future__ import annotations

import unittest

from portmark.models import AgentState, ToolGrant
from portmark.projection import project_tool_output, provider_view
from portmark.security import intersect_grants, normalize_output_projection

TOOL = "crm.lookup"


def project(content, *entries):
    return project_tool_output(content, tuple(entries))


class NestedPathTest(unittest.TestCase):
    def test_nested_path_keeps_only_that_leaf(self):
        content = {"user": {"name": "a", "ssn": "x"}, "top": 1}
        self.assertEqual(project(content, "/user/name"), {"user": {"name": "a"}})

    def test_lists_are_mapped_at_every_level(self):
        content = {"items": [{"id": 1, "hidden": 2}, {"id": 3}, "not-a-dict"]}
        self.assertEqual(project(content, "/items/id"), {"items": [{"id": 1}, {"id": 3}]})

    def test_top_level_list_still_maps(self):
        self.assertEqual(project([{"id": 1, "s": 2}], "/id"), [{"id": 1}])

    def test_path_through_a_scalar_shares_nothing_there(self):
        self.assertEqual(project({"user": "bob"}, "/user/name"), {})

    def test_missing_leaf_keeps_an_empty_parent(self):
        self.assertEqual(project({"user": {"ssn": "x"}}, "/user/name"), {"user": {}})

    def test_plain_key_keeps_the_whole_subtree(self):
        content = {"user": {"name": "a", "ssn": "x"}}
        self.assertEqual(project(content, "user"), content)

    def test_plain_key_and_one_segment_path_are_the_same(self):
        content = {"user": {"name": "a"}, "other": 1}
        self.assertEqual(project(content, "/user"), project(content, "user"))

    def test_shallower_entry_wins_when_both_are_listed(self):
        content = {"user": {"name": "a", "ssn": "x"}}
        self.assertEqual(project(content, "/user/name", "user"), content)

    def test_dotted_plain_key_is_still_a_literal_top_level_key(self):
        content = {"a.b": 1, "a": {"b": 2}}
        self.assertEqual(project(content, "a.b"), {"a.b": 1})

    def test_pointer_escapes(self):
        content = {"a/b": 1, "a~b": 2, "a": {"b": 3}}
        self.assertEqual(project(content, "/a~1b"), {"a/b": 1})
        self.assertEqual(project(content, "/a~0b"), {"a~b": 2})

    def test_star_still_shares_everything(self):
        content = {"user": {"ssn": "x"}}
        self.assertEqual(project(content, "*"), content)


class PathValidationTest(unittest.TestCase):
    def test_malformed_pointers_are_refused(self):
        for bad in ("/", "/a//b", "/a/", "/a~2", "/a~"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                normalize_output_projection([bad], "test")

    def test_valid_entries_are_accepted(self):
        self.assertEqual(normalize_output_projection(["user", "/user/name", "/a~1b"], "test"), ("user", "/user/name", "/a~1b"))


class PathIntersectionTest(unittest.TestCase):
    def merged(self, left, right):
        result = intersect_grants((ToolGrant(TOOL, {}, left),), (ToolGrant(TOOL, {}, right),))
        self.assertTrue(result)
        projection = result[0].output_projection
        if projection is None:
            raise AssertionError("merge returned no projection")
        return projection

    def test_deeper_path_survives_under_a_plain_key(self):
        self.assertEqual(self.merged(("user",), ("/user/name",)), ("/user/name",))
        self.assertEqual(self.merged(("/user/name",), ("user",)), ("/user/name",))

    def test_sibling_paths_share_nothing(self):
        self.assertEqual(self.merged(("/user/name",), ("/user/ssn",)), ())

    def test_same_field_in_both_forms_survives(self):
        self.assertEqual(len(self.merged(("/user",), ("user",))), 1)

    def test_none_and_star_are_unchanged(self):
        self.assertEqual(self.merged(None, ("/user/name",)), ("/user/name",))
        self.assertEqual(self.merged(("*",), ("/user/name",)), ("/user/name",))
        self.assertEqual(self.merged((), ("/user/name",)), ())

    def test_merged_projection_never_shares_more_than_either_side(self):
        content = {"user": {"name": "a", "ssn": "x", "address": {"city": "c", "street": "s"}}, "id": 7}
        sides = [("user",), ("/user/name",), ("/user/address",), ("/user/address/city",), ("id",), ("/id", "/user/ssn")]
        for left in sides:
            for right in sides:
                merged = self.merged(left, right)
                with self.subTest(left=left, right=right):
                    shared = project_tool_output(content, merged)
                    self.assertTrue(_within(shared, project_tool_output(content, left)))
                    self.assertTrue(_within(shared, project_tool_output(content, right)))


def _within(small, big) -> bool:
    """Every leaf in `small` is also in `big` at the same place."""
    if isinstance(small, dict):
        return isinstance(big, dict) and all(key in big and _within(value, big[key]) for key, value in small.items())
    return small == big


class ProviderViewTest(unittest.TestCase):
    def test_provider_never_sees_the_nested_secret(self):
        state = AgentState(task_id="t", goal="g")
        state.memory["tool_results"] = {TOOL: {"user": {"name": "a", "ssn": "x"}}}
        view = provider_view(state, (ToolGrant(TOOL, {}, ("/user/name",)),))
        self.assertEqual(view.tool_results[TOOL], {"user": {"name": "a"}})


if __name__ == "__main__":
    unittest.main()

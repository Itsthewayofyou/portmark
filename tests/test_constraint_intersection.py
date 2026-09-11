"""Property tests for permit/policy constraint intersection.

Five distinct jobs, and they are not interchangeable:

1. ``NoWideningPropertyTest`` — the safety property. A merged constraint set must
   never accept an argument dict that either input would have rejected. This is
   green against today's conservative implementation (dropping every grant it
   cannot merge never widens anything) and must STAY green after the merge
   learns to narrow nested argument schemas.

2. ``GeneratorDiscriminationTest`` — proof that (1) can fail. The same generator
   is run against a deliberately naive union merge, the obvious implementation
   someone would reach for, and must FIND a violation. A property test that
   cannot fail proves nothing; this is its control.

3. ``NarrowingCompletenessTest`` — the #15 regression. A permit that narrows a
   nested argument schema below the host policy must keep the grant. Red before
   the fix, green after.

4. ``DormantConstraintTest`` — hand-written cases the generator cannot reliably
   reach. ``required`` and ``additional_arguments`` are inert without an
   ``arguments`` schema, so a merge can activate one side's dormant key. These
   pin both directions of that.

5. ``OutputProjectionTest`` — the same subset discipline for the data-sharing
   half of a grant, which merges alongside the constraints.

The generator drives everything through ``check_constraints``. A constraint dict
only means something via the checker, so comparing schemas structurally would be
testing the wrong artifact.
"""

from __future__ import annotations

import random
import unittest
from typing import Any

from portmark.models import ToolGrant
from portmark.security import SecurityError, check_constraints, intersect_grants

TOOL = "probe.tool"
SEED = 20260901
ITERATIONS = 3000
CANDIDATES_PER_PAIR = 12

ARGUMENT_NAMES = ("a", "b", "c")

VALUE_POOL: tuple[Any, ...] = (
    1,
    5,
    10,
    "x",
    "xyz",
    "abc",
    "https://api.example.com/v1",
    "https://other.example.com/v1",
    "http://evil.test/path",
    True,
    None,
)


def accepts(constraints: dict[str, Any], arguments: dict[str, Any]) -> bool:
    """Does this constraint set admit these arguments?"""
    try:
        check_constraints(constraints, arguments)
    except SecurityError:
        return False
    return True


def merge_real(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any] | None:
    """Merge via the shipping code path, returning None when the grant is dropped."""
    merged = intersect_grants((ToolGrant(TOOL, left),), (ToolGrant(TOOL, right),))
    if not merged:
        return None
    return merged[0].constraints


def merge_naive_union(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any] | None:
    """The obvious wrong implementation, used only as a control.

    Recurses per key and narrows each one sensibly, which looks correct and is
    not: unioning the ``arguments`` key set widens the set of argument NAMES a
    strict side would have accepted, because ``additional_arguments: False``
    turns that key set into a whitelist.
    """
    result: dict[str, Any] = {}
    for key in left.keys() | right.keys():
        if key not in left:
            result[key] = right[key]
        elif key not in right:
            result[key] = left[key]
        elif left[key] == right[key]:
            result[key] = left[key]
        elif isinstance(left[key], dict) and isinstance(right[key], dict):
            nested = merge_naive_union(left[key], right[key])
            if nested is None:
                return None
            result[key] = nested
        elif key in {"maximum", "max_length"} or key.startswith("max_"):
            result[key] = min(left[key], right[key])
        elif key in {"minimum", "min_length"}:
            result[key] = max(left[key], right[key])
        elif key == "additional_arguments":
            result[key] = left[key] and right[key]
        elif isinstance(left[key], list) and isinstance(right[key], list):
            shared = [item for item in left[key] if item in right[key]]
            if not shared:
                return None
            result[key] = shared
        else:
            return None
    return result


def random_argument_spec(rng: random.Random) -> dict[str, Any]:
    """One per-argument spec drawn from the vocabulary check_constraints enforces.

    Kept deliberately sparse. Piling several keys onto one argument produces
    specs nothing can satisfy, and a generator whose constraint sets reject every
    candidate never reaches the region where widening is observable.
    """
    generators: list[tuple[str, Any]] = [
        ("type", lambda: rng.choice([["string"], ["integer"], ["number"], ["string", "integer"], "string", "integer"])),
        ("const", lambda: rng.choice(["x", "xyz", 5])),
        ("enum", lambda: rng.sample(["x", "xyz", "abc", 1, 5, 10], rng.randint(1, 3))),
        ("minimum", lambda: rng.choice([0, 1, 5])),
        ("maximum", lambda: rng.choice([5, 10, 100])),
        ("min_length", lambda: rng.choice([0, 1, 3])),
        ("max_length", lambda: rng.choice([1, 3, 8])),
        ("pattern", lambda: rng.choice(["[a-z]+", "x.*", "abc"])),
        ("required", lambda: True),
        ("scheme", lambda: rng.choice(["https", "http"])),
        ("allowed_schemes", lambda: rng.sample(["https", "http", "ftp"], rng.randint(1, 2))),
        ("allowed_hosts", lambda: rng.sample(["api.example.com", "other.example.com", "evil.test"], rng.randint(1, 2))),
        ("allowed_domains", lambda: rng.sample(["example.com", "evil.test"], rng.randint(1, 2))),
    ]
    rng.shuffle(generators)
    spec: dict[str, Any] = {}
    for key, generate in generators[: rng.randint(0, 2)]:
        spec[key] = generate()
    return spec


def random_constraints(rng: random.Random) -> dict[str, Any]:
    """One full constraint set, covering nested schemas and the legacy flat keys."""
    constraints: dict[str, Any] = {}
    if rng.random() < 0.85:
        names = rng.sample(ARGUMENT_NAMES, rng.randint(1, len(ARGUMENT_NAMES)))
        constraints["arguments"] = {name: random_argument_spec(rng) for name in names}
    # `required` and `additional_arguments` are emitted INDEPENDENTLY of
    # `arguments` on purpose. `required` is still inert without a schema, so a
    # generator that only ever emits it alongside `arguments` could never produce
    # the merge case that activates the other side's dormant `required`. (Since
    # finding #4, `additional_arguments: False` is live without a schema; emitting
    # it independently now also exercises that path.) Keep them independent.
    if rng.random() < 0.4:
        constraints["additional_arguments"] = rng.choice([True, False])
    if rng.random() < 0.3:
        constraints["required"] = rng.sample(ARGUMENT_NAMES, rng.randint(1, 2))
    if rng.random() < 0.25:
        constraints[f"max_{rng.choice(ARGUMENT_NAMES)}"] = rng.choice([5, 10])
    if rng.random() < 0.25:
        constraints[f"allowed_{rng.choice(ARGUMENT_NAMES)}"] = rng.sample(["x", "xyz", 1, 5], rng.randint(1, 3))
    if rng.random() < 0.15:
        constraints[rng.choice(ARGUMENT_NAMES)] = rng.choice(["x", 5])
    return constraints


def random_arguments(rng: random.Random) -> dict[str, Any]:
    arguments: dict[str, Any] = {}
    for name in ARGUMENT_NAMES:
        if rng.random() < 0.6:
            arguments[name] = rng.choice(VALUE_POOL)
    return arguments


def candidate_arguments(rng: random.Random, left: dict[str, Any], right: dict[str, Any]) -> list[dict[str, Any]]:
    """Argument dicts worth trying against this specific pair of constraint sets.

    A witness to widening must be accepted by one side and refused by the other,
    so purely random values are wasteful: almost all of them are refused by both
    and carry no information. These candidates are seeded from the values the two
    sides actually name, which puts the search on the boundary rather than far
    outside it.
    """
    interesting: dict[str, list[Any]] = {name: list(VALUE_POOL) for name in ARGUMENT_NAMES}
    for side in (left, right):
        for name, spec in (side.get("arguments") or {}).items():
            if not isinstance(spec, dict):
                continue
            if "const" in spec:
                interesting.setdefault(name, []).append(spec["const"])
            if isinstance(spec.get("enum"), list):
                interesting.setdefault(name, []).extend(spec["enum"])
        for key, value in side.items():
            if key.startswith("allowed_") and isinstance(value, list):
                interesting.setdefault(key[8:], []).extend(value)
            elif key.startswith("max_") and isinstance(value, (int, float)):
                interesting.setdefault(key[4:], []).append(value)

    candidates: list[dict[str, Any]] = []
    for _ in range(CANDIDATES_PER_PAIR):
        arguments: dict[str, Any] = {}
        for name in ARGUMENT_NAMES:
            if rng.random() < 0.65:
                arguments[name] = rng.choice(interesting.get(name) or list(VALUE_POOL))
        candidates.append(arguments)
    return candidates


def find_widening(merge, iterations: int = ITERATIONS, seed: int = SEED) -> tuple | None:
    """Search for a case where the merged constraints accept what an input rejects.

    Returns the offending (left, right, arguments, merged) tuple, or None.
    """
    # nosec B311 - generating test inputs, not key material. A seeded PRNG is the
    # point here: a failing case has to be reproducible from the seed alone.
    rng = random.Random(seed)  # nosec B311
    for _ in range(iterations):
        left = random_constraints(rng)
        right = random_constraints(rng)
        try:
            merged = merge(left, right)
        except SecurityError:
            continue
        if merged is None:
            continue
        for arguments in candidate_arguments(rng, left, right):
            try:
                if not accepts(merged, arguments):
                    continue
                if accepts(left, arguments) and accepts(right, arguments):
                    continue
            except SecurityError:
                continue
            return left, right, arguments, merged
    return None


class NoWideningPropertyTest(unittest.TestCase):
    """The safety property: merging never creates authority."""

    def test_merged_constraints_never_accept_what_an_input_rejects(self) -> None:
        violation = find_widening(merge_real)
        self.assertIsNone(
            violation,
            msg=f"constraint intersection widened authority: {violation}",
        )

    def test_strict_side_argument_whitelist_is_not_widened(self) -> None:
        """Hand-derived authority case, written from the spec, not generated.

        The left side is strict and knows only 'a'. The right side also describes
        'b'. Unioning the argument maps would let 'b' through, which the left
        side refuses. The merge must either drop the grant or exclude 'b'.
        """
        left = {"arguments": {"a": {"type": "string"}}, "additional_arguments": False}
        right = {"arguments": {"a": {"type": "string"}, "b": {"type": "string"}}}
        arguments = {"a": "x", "b": "y"}

        self.assertFalse(accepts(left, arguments), "fixture is wrong: left should reject 'b'")
        self.assertTrue(accepts(right, arguments), "fixture is wrong: right should accept 'b'")

        merged = merge_real(left, right)
        if merged is not None:
            self.assertFalse(
                accepts(merged, arguments),
                msg=f"merged constraints admit an argument the strict side rejects: {merged}",
            )


class DormantConstraintTest(unittest.TestCase):
    """`required` is inert without an `arguments` schema; a merge can activate it.

    check_constraints only consults `required` inside `if schema is not None`, so a
    merge that brings a schema in from one side can ACTIVATE the other side's
    dormant `required`. Activating is narrowing and therefore safe; the direction
    that would not be safe is a merge that loses enforcement one side had. These pin
    both directions, because the generator cannot reliably reach them.
    (`additional_arguments: False` is live without a schema since finding #4 — its
    test below pins that, plus the merge-preservation property.)
    """

    def require_merged(self, merged: dict[str, Any] | None) -> dict[str, Any]:
        """Fail the test if the grant was dropped, and narrow the type for callers."""
        if merged is None:
            self.fail("grant was dropped instead of merged")
        return merged

    def test_a_schema_from_one_side_may_activate_the_others_required(self) -> None:
        left = {"arguments": {"a": {}}}
        right = {"required": ["a"]}
        merged = self.require_merged(merge_real(left, right))
        self.assertFalse(accepts(merged, {}), "required should now be enforced")
        self.assertTrue(accepts(left, {}), "fixture: left had no required")
        self.assertTrue(accepts(right, {}), "fixture: right's required was dormant")

    def test_enforcement_is_never_lost_when_the_schema_is_emptied(self) -> None:
        """Filtering by permitted names can empty the schema. `required` must not go inert."""
        left = {"arguments": {"a": {}}, "required": ["a"], "additional_arguments": False}
        right = {"arguments": {"b": {}}, "additional_arguments": False}
        merged = merge_real(left, right)
        if merged is not None:
            for arguments in ({}, {"a": 1}, {"b": 1}, {"a": 1, "b": 1}):
                if accepts(merged, arguments):
                    self.assertTrue(accepts(left, arguments), f"left rejects {arguments}")
                    self.assertTrue(accepts(right, arguments), f"right rejects {arguments}")

    def test_required_naming_an_excluded_argument_drops_the_grant(self) -> None:
        left = {"arguments": {"a": {}}, "required": ["a"], "additional_arguments": False}
        right = {"arguments": {"b": {}}, "required": ["b"], "additional_arguments": False}
        self.assertIsNone(
            merge_real(left, right),
            msg="each side requires an argument the other refuses; the set is unsatisfiable",
        )

    def test_additional_arguments_false_is_live_without_a_schema(self) -> None:
        # Finding #4 fix: `additional_arguments: False` now bounds admitted fields
        # even with no `arguments` schema. This test previously asserted the
        # opposite (that left's flag was dormant); it now pins the live behavior
        # and the property that a merge must not LOSE the stricter side's rejection.
        left = {"additional_arguments": False}
        # `right` must OPT IN to extra fields explicitly now: a bare `arguments`
        # schema is deny-by-default, so without the flag it would reject `z` too
        # and the merge below would no longer be testing "keeps the stricter side".
        right = {"arguments": {"b": {}}, "additional_arguments": True}
        merged = self.require_merged(merge_real(left, right))
        self.assertFalse(accepts(left, {"z": 1}), "left's flag is live: an unknown field is rejected")
        self.assertTrue(accepts(left, {}), "left still admits the empty argument set")
        self.assertTrue(accepts(right, {"z": 1}), "fixture: right opts into extra fields")
        self.assertFalse(accepts(merged, {"z": 1}), "merge keeps the stricter side's rejection")


class OutputProjectionTest(unittest.TestCase):
    """The same subset discipline, for the other half of a grant.

    `_projection_intersection` was not changed by this work, but it merges
    alongside the constraints and answers a data-sharing question rather than an
    acceptance one: which tool output fields reach the provider. The property is
    the same shape — a field the merged grant shares must be shared by both
    inputs — and `None` means "unrestricted", which is the part worth pinning.
    """

    def merged_projection(self, left, right):
        grants = intersect_grants(
            (ToolGrant(TOOL, {}, left),),
            (ToolGrant(TOOL, {}, right),),
        )
        self.assertTrue(grants, "grant should survive; only projections differ")
        return grants[0].output_projection

    def shared(self, projection, field: str) -> bool:
        if projection is None or "*" in projection:
            return True
        return field in projection

    def test_merged_projection_shares_only_what_both_share(self) -> None:
        cases = [
            (None, ("a",)),
            (("*",), ("a",)),
            (("a", "b"), ("b", "c")),
            ((), ("a",)),
            (("a",), ()),
            (None, None),
            (("*",), ("*",)),
        ]
        for left, right in cases:
            merged = self.merged_projection(left, right)
            for field in ("a", "b", "c", "secret"):
                if self.shared(merged, field):
                    self.assertTrue(self.shared(left, field), f"{left} does not share {field!r}")
                    self.assertTrue(self.shared(right, field), f"{right} does not share {field!r}")

    def test_empty_projection_stays_empty(self) -> None:
        """Sharing nothing is the strictest setting and must win."""
        self.assertEqual(self.merged_projection((), ("a", "b")), ())


class GeneratorDiscriminationTest(unittest.TestCase):
    """Control: prove the property test above is capable of failing."""

    def test_naive_union_merge_is_caught(self) -> None:
        violation = find_widening(merge_naive_union)
        self.assertIsNotNone(
            violation,
            msg="the generator found no widening in a deliberately naive union merge, "
            "so NoWideningPropertyTest is decorative and proves nothing",
        )

    def test_naive_union_widens_the_hand_derived_case(self) -> None:
        left = {"arguments": {"a": {"type": "string"}}, "additional_arguments": False}
        right = {"arguments": {"a": {"type": "string"}, "b": {"type": "string"}}}
        arguments = {"a": "x", "b": "y"}
        merged = merge_naive_union(left, right)
        self.assertIsNotNone(merged)
        self.assertTrue(
            accepts(merged, arguments),
            msg="the naive control no longer widens, so it cannot serve as a control",
        )


class NarrowingCompletenessTest(unittest.TestCase):
    """Issue #15: a permit that narrows a nested argument schema keeps the grant."""

    def assert_kept(self, envelope: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
        merged = merge_real(envelope, policy)
        if merged is None:
            self.fail("grant was dropped instead of narrowed")
        return merged

    def test_narrower_numeric_bounds_are_kept(self) -> None:
        policy = {"arguments": {"latitude": {"minimum": 30.0, "maximum": 30.6}}}
        envelope = {"arguments": {"latitude": {"minimum": 30.1, "maximum": 30.5}}}
        merged = self.assert_kept(envelope, policy)
        self.assertEqual(merged["arguments"]["latitude"], {"minimum": 30.1, "maximum": 30.5})

    def test_narrower_enum_is_kept_as_the_intersection(self) -> None:
        policy = {"arguments": {"station": {"enum": ["austin", "london", "tokyo"]}}}
        envelope = {"arguments": {"station": {"enum": ["austin", "london"]}}}
        merged = self.assert_kept(envelope, policy)
        self.assertEqual(sorted(merged["arguments"]["station"]["enum"]), ["austin", "london"])

    def test_disjoint_enum_drops_the_grant(self) -> None:
        policy = {"arguments": {"station": {"enum": ["tokyo"]}}}
        envelope = {"arguments": {"station": {"enum": ["austin"]}}}
        self.assertIsNone(merge_real(envelope, policy))

    def test_narrower_string_length_is_kept(self) -> None:
        policy = {"arguments": {"query": {"min_length": 1, "max_length": 100}}}
        envelope = {"arguments": {"query": {"min_length": 3, "max_length": 20}}}
        merged = self.assert_kept(envelope, policy)
        self.assertEqual(merged["arguments"]["query"], {"min_length": 3, "max_length": 20})

    def test_extra_argument_constraint_is_kept_when_both_sides_are_open(self) -> None:
        # Both sides must declare themselves open now: deny-by-default would
        # otherwise bound each to {a} and drop b from the merged whitelist.
        policy = {"arguments": {"a": {"type": "string"}}, "additional_arguments": True}
        envelope = {"arguments": {"a": {"type": "string"}, "b": {"maximum": 5}}, "additional_arguments": True}
        merged = self.assert_kept(envelope, policy)
        self.assertIn("b", merged["arguments"])

    def test_url_host_narrowing_is_kept(self) -> None:
        policy = {"arguments": {"url": {"allowed_hosts": ["api.example.com", "other.example.com"]}}}
        envelope = {"arguments": {"url": {"allowed_hosts": ["api.example.com"]}}}
        merged = self.assert_kept(envelope, policy)
        self.assertEqual(merged["arguments"]["url"]["allowed_hosts"], ["api.example.com"])

    def test_unknown_spec_key_drops_the_grant(self) -> None:
        """Fail closed: an unrecognised key might mean 'relax', so refuse to merge."""
        policy = {"arguments": {"a": {"type": "string"}}}
        envelope = {"arguments": {"a": {"type": "string", "someFutureKey": 1}}}
        self.assertIsNone(merge_real(envelope, policy))

    def test_identical_constraints_still_merge(self) -> None:
        """Regression guard: the case that already worked must keep working."""
        shared = {"arguments": {"a": {"type": "string", "max_length": 4}}}
        merged = self.assert_kept(dict(shared), dict(shared))
        self.assertEqual(merged, shared)


class AdditionalArgumentsEmissionTest(unittest.TestCase):
    """Pin the merge's `additional_arguments` emission guard: the merged grant
    carries the flag only when it overrides the merged constraints' own default,
    and either way the effective acceptance is correct."""

    def test_both_open_result_declares_names_stays_open(self):
        # Both sides opt in; the merged result declares `a`, so its default would
        # be deny -- the merge must emit `true` to keep it open.
        merged = merge_real(
            {"additional_arguments": True},
            {"additional_arguments": True, "arguments": {"a": {}}},
        )
        self.assertIsNotNone(merged)
        self.assertTrue(accepts(merged, {"z": 1}), "both sides opted in; extras still admitted")

    def test_one_bounded_side_denies_extras_with_no_emitted_flag(self):
        # Left bounds `amount` (declares policy); right is open but declares
        # nothing. Merged flag is False and the result still carries `max_amount`,
        # so the guard emits no flag and check_constraints denies via the default.
        merged = merge_real({"max_amount": 5}, {"additional_arguments": True})
        self.assertIsNotNone(merged)
        self.assertNotIn("additional_arguments", merged)
        self.assertFalse(accepts(merged, {"amount": 1, "z": 2}), "the bounded side's whitelist survives")
        self.assertTrue(accepts(merged, {"amount": 1}), "the declared argument is still accepted")


class ManifestNameFilterTest(unittest.TestCase):
    """The manifest is a pure name filter (`allow`), never a source of argument policy.

    `effective_permit` used to fold the manifest in as bare `ToolGrant(name)` grants
    with empty constraints. An empty grant reads as an argument passthrough, so the
    manifest's role ("this tool may exist") was carried by the same shape that means
    "any argument is allowed". Passing the manifest as `intersect_grants(..., allow=)`
    keeps the two apart: `allow` decides membership only, and the argument policy comes
    entirely from the permit and host grants.
    """

    def test_allow_filters_membership_only(self):
        left = (ToolGrant(TOOL, {"max_amount": 5}),)
        right = (ToolGrant(TOOL, {"max_amount": 5}),)
        # In the allow-set: kept. Absent, or the set names a different tool: dropped.
        self.assertEqual(len(intersect_grants(left, right, allow=frozenset({TOOL}))), 1)
        self.assertEqual(intersect_grants(left, right, allow=frozenset()), ())
        self.assertEqual(intersect_grants(left, right, allow=frozenset({"other.tool"})), ())

    def test_allow_never_alters_constraints(self):
        # The surviving grant's constraints are identical with and without the filter:
        # the manifest name adds a name to the whitelist, never an argument permission.
        constraints = {"arguments": {"amount": {"type": "number"}}}
        left = (ToolGrant(TOOL, constraints),)
        right = (ToolGrant(TOOL, constraints),)
        with_allow = intersect_grants(left, right, allow=frozenset({TOOL}))
        without_allow = intersect_grants(left, right)
        self.assertEqual(with_allow[0].constraints, without_allow[0].constraints)

    def test_a_name_in_allow_cannot_widen_arguments(self):
        # A tool bounded to `amount` by both grants stays bounded once its name passes
        # the allow filter: an undeclared field is still rejected (deny-by-default).
        # The manifest naming the tool does not re-open its argument set.
        constraints = {"arguments": {"amount": {"type": "number"}}}
        merged = intersect_grants(
            (ToolGrant(TOOL, constraints),),
            (ToolGrant(TOOL, constraints),),
            allow=frozenset({TOOL}),
        )
        self.assertEqual(len(merged), 1)
        self.assertTrue(accepts(merged[0].constraints, {"amount": 5}))
        self.assertFalse(accepts(merged[0].constraints, {"amount": 5, "recipient": "x"}))


if __name__ == "__main__":
    unittest.main()

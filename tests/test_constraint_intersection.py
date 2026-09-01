"""Property tests for permit/policy constraint intersection.

Three distinct jobs, and they are not interchangeable:

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
        if rng.random() < 0.5:
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
        policy = {"arguments": {"a": {"type": "string"}}}
        envelope = {"arguments": {"a": {"type": "string"}, "b": {"maximum": 5}}}
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


if __name__ == "__main__":
    unittest.main()

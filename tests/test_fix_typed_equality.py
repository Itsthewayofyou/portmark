"""Constraint values compare as JSON values: a boolean never equals a number.

Python says `True == 1` and `1 in [True]`, so `allowed_*`, flat exact-match keys, `const`, and `enum`
accepted `true` where a policy allowed `1` (and the reverse). The permit x policy merge used the same
equality, so merging `[1]` with `[True]` kept a value the policy never allowed. Both the check and the
merge now use one JSON equality: booleans equal only booleans, strings only strings, containers compare
element by element, and numbers compare by value (`1` equals `1.0`, as JSON Schema `enum`/`const` do).
"""

from __future__ import annotations

import unittest

from portmark.security import SecurityError, _constraint_intersection, _narrow_argument_spec, check_constraints


class TypedEqualityCheckTests(unittest.TestCase):
    def refused(self, constraints, arguments):
        with self.assertRaises(SecurityError):
            check_constraints(constraints, arguments)

    def test_allowed_list_refuses_a_boolean_for_a_number(self):
        self.refused({"allowed_amount": [1]}, {"amount": True})  # deep-dive A7

    def test_allowed_list_refuses_a_number_for_a_boolean(self):
        self.refused({"allowed_mode": [True]}, {"mode": 1})

    def test_flat_exact_match_refuses_a_boolean_for_a_number(self):
        self.refused({"region": 0}, {"region": False})

    def test_const_refuses_a_boolean_for_a_number(self):
        self.refused({"arguments": {"n": {"const": 1}}}, {"n": True})

    def test_const_compares_nested_values_by_type(self):
        self.refused({"arguments": {"n": {"const": [1, {"a": 0}]}}}, {"n": [True, {"a": False}]})

    def test_enum_refuses_a_boolean_for_a_number(self):
        self.refused({"arguments": {"n": {"enum": [0, 1]}}}, {"n": False})

    def test_control_matching_values_still_pass(self):
        check_constraints({"allowed_amount": [1, 2]}, {"amount": 2})
        check_constraints({"allowed_mode": [True]}, {"mode": True})
        check_constraints({"region": "us"}, {"region": "us"})
        check_constraints({"arguments": {"n": {"const": [1, {"a": False}]}}}, {"n": [1, {"a": False}]})
        check_constraints({"arguments": {"n": {"enum": [None, "x"]}}}, {"n": None})

    def test_control_integer_and_float_of_equal_value_match(self):
        # JSON has one number type; JSON Schema enum/const treat 1 and 1.0 as equal.
        check_constraints({"allowed_amount": [1]}, {"amount": 1.0})
        check_constraints({"arguments": {"n": {"enum": [2.0]}}}, {"n": 2})


class TypedEqualityMergeTests(unittest.TestCase):
    def test_allowed_intersection_of_number_and_boolean_is_empty(self):
        merged, failing = _constraint_intersection({"allowed_amount": [1]}, {"allowed_amount": [True]})
        self.assertIsNone(merged)  # nothing is allowed by both: drop the grant, never keep `1`
        self.assertEqual(failing, "allowed_amount")

    def test_flat_keys_of_number_and_boolean_do_not_merge(self):
        merged, failing = _constraint_intersection({"region": 0}, {"region": False})
        self.assertIsNone(merged)
        self.assertEqual(failing, "region")

    def test_enum_intersection_of_number_and_boolean_is_empty(self):
        merged, failing = _narrow_argument_spec({"enum": [1]}, {"enum": [True]})
        self.assertIsNone(merged)
        self.assertEqual(failing, "enum")

    def test_const_of_number_and_boolean_is_not_identical(self):
        merged, failing = _narrow_argument_spec({"const": 1}, {"const": True})
        self.assertIsNone(merged)
        self.assertEqual(failing, "const")

    def test_control_shared_values_survive_the_merge(self):
        merged, failing = _constraint_intersection({"allowed_amount": [1, 2, True]}, {"allowed_amount": [2, True]})
        self.assertIsNone(failing)
        self.assertEqual(merged["allowed_amount"], [2, True])


if __name__ == "__main__":
    unittest.main()

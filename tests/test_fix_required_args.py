"""A grant's `required` list is enforced whether or not the grant also has an `arguments` schema.

`check_constraints` checked `required` names only inside `if schema is not None`, so a flat grant
(`{"required": ["recipient"], "max_amount": 10}`) accepted a call with no `recipient` at all. The
missing argument then fell to the tool's own default. Now the presence check runs first, for every
grant shape, and the merged (permit x policy) grant keeps it.
"""

from __future__ import annotations

import unittest

from portmark.security import SecurityError, _constraint_intersection, check_constraints


class RequiredArgumentsTests(unittest.TestCase):
    def test_flat_grant_refuses_a_missing_required_argument(self):
        with self.assertRaisesRegex(SecurityError, "'recipient' is required"):
            check_constraints({"required": ["recipient"]}, {})

    def test_flat_grant_with_other_limits_refuses_a_missing_required_argument(self):
        # deep-dive A3: {"required": ["account_id"], "max_amount": 10} used to accept {"amount": 5}
        with self.assertRaisesRegex(SecurityError, "'account_id' is required"):
            check_constraints({"required": ["account_id"], "max_amount": 10}, {"amount": 5})

    def test_control_flat_grant_accepts_the_required_argument(self):
        check_constraints({"required": ["account_id"], "max_amount": 10}, {"amount": 5, "account_id": "a1"})

    def test_control_schema_grant_still_refuses_a_missing_required_argument(self):
        with self.assertRaisesRegex(SecurityError, "'recipient' is required"):
            check_constraints({"required": ["recipient"], "arguments": {"recipient": {"type": "string"}}}, {})

    def test_merged_grant_keeps_a_flat_required_argument(self):
        # A flat permit grant intersected with a schema-less policy grant: the result must still demand it.
        merged, failing = _constraint_intersection(
            {"required": ["account_id"], "max_amount": 10}, {"required": ["account_id"], "max_amount": 5}
        )
        self.assertIsNone(failing)
        self.assertNotIn("arguments", merged)  # still a flat grant, the shape that skipped the check
        with self.assertRaisesRegex(SecurityError, "'account_id' is required"):
            check_constraints(merged, {"amount": 5})


if __name__ == "__main__":
    unittest.main()

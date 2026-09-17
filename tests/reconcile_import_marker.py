"""Section 7 PR 2b round 3 regression fixture (the auditor's exact reproduction).

This module writes a MARKER FILE at IMPORT time -- i.e. its top-level code runs a side effect the
moment anything imports it. It is registered as a reconcile target in
test_registration_does_not_import_the_reconcile_module to prove that register_isolated does NOT import
the reconcile module (which would execute this untrusted top-level code before any ledger/permit/claim).
The marker path comes from an env var so the test can point it at a temp file; if the var is unset the
import is inert.
"""

import os

_marker_path = os.environ.get("RECONCILE_IMPORT_MARKER")
if _marker_path:
    # Import-time side effect: this is exactly what must NOT happen during registration.
    with open(_marker_path, "w", encoding="utf-8") as _handle:
        _handle.write("the reconcile module was imported")


def reconcile(arguments, effect_id=None):
    # A well-formed reconcile target (never actually called by the regression test).
    return {"landed": False}

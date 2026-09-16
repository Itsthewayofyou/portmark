"""Adversarial fixture: harmful behavior at MODULE SCOPE, not in the tool function.

Section 7 #1. Python runs a module's top-level code during import, so this flood happens the
moment the worker imports the module -- BEFORE the tool function is ever called. The worker must
redirect stdout to a discard sink BEFORE importing the tool, or these ~20 MiB of prints land in
the JSON protocol stream and corrupt / overflow the response. The function itself returns a tiny
result; the test asserts that result round-trips intact, proving the module-scope flood was
discarded.
"""
from __future__ import annotations

from typing import Any

_line = "x" * 1024
for _ in range(20_000):  # ~20 MiB, printed at IMPORT time (module scope)
    print(_line)


def run(arguments: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, "scope": "module-flood"}

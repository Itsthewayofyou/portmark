"""Adversarial fixture: a filesystem write at MODULE SCOPE, not in the tool function.

Section 7 #1. The write happens during import, before the tool function runs, and the path/size
come from the worker's environment (a module body takes no tool arguments) -- passed via the
``env=`` allowlist. Because the resource caps are now applied BEFORE the tool is imported, a
small RLIMIT_FSIZE refuses this module-scope write (OSError/EFBIG), which the worker reports as
a controlled ``tool import raised OSError`` -- not a crashed, response-less worker, and not a
write that already succeeded before any cap applied. The test asserts that controlled failure;
calibration (caps applied AFTER import, the old order) lets the write through instead.
"""
from __future__ import annotations

import os
from typing import Any

_path = os.environ.get("PORTMARK_TEST_MODULE_WRITE_PATH")
if _path:
    with open(_path, "wb") as _handle:  # at IMPORT time (module scope)
        _handle.write(b"x" * int(os.environ.get("PORTMARK_TEST_MODULE_WRITE_SIZE", "0")))


def run(arguments: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, "scope": "module-write"}

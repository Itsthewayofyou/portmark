"""Isolated tool worker (EV-002).

Runs exactly one host-registered tool in a fresh Python process so the host can
hard-kill it at a deadline -- something the in-process thread path in
``tools.py`` cannot do. The protocol is JSON in, JSON out, one document each way:

    request  (stdin) : {"target": "module:function", "arguments": {...},
                        "max_output_bytes": N}
    response (stdout): {"ok": true, "result": <json>}
                       {"ok": false, "error": "<reason>"}

The tool's own ``print`` output is redirected away from fd 1 so it cannot forge
or corrupt the response. The parent still reads stdout bounded and re-checks the
size, because a hostile tool can write to fd 1 directly, past this redirect.
"""
from __future__ import annotations

import importlib
import io
import json
import sys
from contextlib import redirect_stdout
from typing import Any


def main() -> None:
    raw = sys.stdin.read()
    try:
        request = json.loads(raw)
        target = request["target"]
        arguments = request["arguments"]
        max_output_bytes = int(request["max_output_bytes"])
    except (ValueError, KeyError, TypeError):
        _respond_error("invalid request")
        return
    if not isinstance(target, str) or not isinstance(arguments, dict) or max_output_bytes < 1:
        _respond_error("invalid request")
        return

    module_name, separator, object_path = target.partition(":")
    if not separator or not module_name or not object_path:
        _respond_error("target must use module:function syntax")
        return
    try:
        loaded: Any = importlib.import_module(module_name)
        for part in object_path.split("."):
            if not part:
                raise AttributeError
            loaded = getattr(loaded, part)
    except (ImportError, AttributeError):
        _respond_error("could not import tool target")
        return
    if not callable(loaded):
        _respond_error("tool target is not callable")
        return

    # The tool must never write to the response stream. Redirect its stdout to a
    # discarded buffer; only this module writes the protocol JSON to fd 1.
    try:
        with redirect_stdout(io.StringIO()):
            result = loaded(arguments)
    except BaseException as error:  # noqa: BLE001 - any tool failure fails closed
        _respond_error(f"tool raised {type(error).__name__}")
        return

    try:
        from .security import canonical_json

        encoded_size = len(canonical_json(result))
    except (TypeError, ValueError):
        _respond_error("tool output is not JSON serializable")
        return
    if encoded_size > max_output_bytes:
        _respond_error("tool output exceeds output budget")
        return
    _respond_ok(result)


def _respond_ok(result: Any) -> None:
    try:
        payload = json.dumps({"ok": True, "result": result})
    except (TypeError, ValueError):
        _respond_error("tool output is not JSON serializable")
        return
    sys.stdout.write(payload)
    sys.stdout.flush()


def _respond_error(message: str) -> None:
    sys.stdout.write(json.dumps({"ok": False, "error": message}))
    sys.stdout.flush()


if __name__ == "__main__":
    main()

"""Isolated tool worker (EV-002 / Section 7).

Runs exactly one host-registered tool in a fresh Python process so the host can enforce a
hard wall-clock deadline and apply defense-in-depth kernel resource caps -- something the
in-process thread path in ``tools.py`` cannot do. The protocol is JSON in, JSON out:

    request  (stdin) : {"target": "module:function", "arguments": {...},
                        "max_output_bytes": N, "rlimits": {...}}
    response (stdout): {"ok": true, "result": <json>}
                       {"ok": false, "error": "<reason>"}

This worker is a RESOURCE-BOUNDED, HARD-DEADLINE worker -- it is NOT a hostile-code sandbox.
It runs as the same OS user, in the host's working directory, with normal filesystem and
network access; a hostile tool can still read host-accessible files and open sockets.
Containing a hostile tool is the DEPLOYMENT's job (container / PID namespace + cgroup /
separate uid / network policy). See THREAT_MODEL.md.

The tool's own ``print`` output is redirected to a discarding sink so it cannot forge or
corrupt the response and cannot exhaust memory via an unbounded buffer. The parent still reads
stdout bounded and re-checks the size, because a hostile tool can write to fd 1 directly.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from contextlib import redirect_stdout
from typing import Any

try:  # POSIX only; absent on Windows (which uses a Job Object with hard limits instead)
    import resource as _resource
except ImportError:  # pragma: no cover - platform dependent
    _resource = None  # type: ignore[assignment]


def _apply_resource_limits(limits: Any) -> None:
    """Defense-in-depth kernel resource caps for the tool (finding S7-#6).

    Applied here, in the fresh single-threaded worker, right before the tool runs -- NOT via
    the parent's ``preexec_fn`` (unsafe in the parent's threaded drain path) and NOT before the
    runner's own imports (a low RLIMIT_AS would kill the interpreter mid-import). These are
    defense in depth, not a boundary: they are POSIX-only, not equivalent across platforms, and
    do not constrain network access. Best-effort -- a limit the platform rejects is skipped, the
    tool still runs under the remaining caps and the host's wall-clock deadline.
    """
    if _resource is None or not isinstance(limits, dict):
        return
    by_name = {
        "address_space": getattr(_resource, "RLIMIT_AS", None),
        "cpu_seconds": getattr(_resource, "RLIMIT_CPU", None),
        "processes": getattr(_resource, "RLIMIT_NPROC", None),
        "file_size": getattr(_resource, "RLIMIT_FSIZE", None),
        "open_files": getattr(_resource, "RLIMIT_NOFILE", None),
    }
    for key, rlimit in by_name.items():
        value = limits.get(key)
        if rlimit is None or not isinstance(value, int) or isinstance(value, bool) or value < 0:
            continue
        try:
            _soft, hard = _resource.getrlimit(rlimit)
            # Never raise the ceiling: clamp to the existing hard limit, and lower it too so a
            # forked child cannot restore a higher soft limit.
            new = value if hard == _resource.RLIM_INFINITY else min(value, hard)
            _resource.setrlimit(rlimit, (new, new))
        except (ValueError, OSError):  # pragma: no cover - platform/limit dependent
            continue


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

    # Defense-in-depth kernel caps, applied after the runner's own imports and the tool import
    # (so neither is constrained by RLIMIT_AS) but before the tool executes.
    _apply_resource_limits(request.get("rlimits"))

    # The tool must never write to the response stream. Redirect Python-level stdout to a
    # DISCARDING sink (os.devnull), not an in-memory buffer: a hostile tool that prints
    # without bound would otherwise grow an io.StringIO until it exhausts worker memory
    # (finding S7-#6). This sink is not a containment boundary -- a tool can still write to
    # fd 1 directly, past this redirect; the PARENT reads stdout bounded and re-checks the
    # size, which is what actually caps fd-1 abuse. Only this module writes protocol JSON to fd 1.
    try:
        with open(os.devnull, "w", encoding="utf-8") as sink, redirect_stdout(sink):
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

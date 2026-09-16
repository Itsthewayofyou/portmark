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

The tool is UNTRUSTED code, and Python runs a module's top-level statements during import --
so the tool's module scope, not just its function, is attacker-controlled (finding S7-#1).
The caps are therefore applied, and stdout is redirected to a discarding sink, BEFORE the tool
module is imported: a hostile module body then runs already capped and cannot forge or corrupt
the response stream. The parent still reads stdout bounded and re-checks the size, because a
hostile tool can write to fd 1 directly, past the Python-level redirect.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from contextlib import redirect_stdout
from typing import Any

# Trusted bootstrap import, hoisted to module scope on purpose: everything the runner itself
# needs must be imported BEFORE the resource caps are applied in main(), so a low RLIMIT_AS can
# never fire mid-bootstrap. Only the untrusted tool module is imported after the caps.
from .security import canonical_json

try:  # POSIX only. On Windows the host contains the worker with a kill-on-close Job Object
    # (whole-tree termination) -- NOT kernel resource limits; the caps below are POSIX-only.
    import resource as _resource
except ImportError:  # pragma: no cover - platform dependent
    _resource = None  # type: ignore[assignment]


_RLIMIT_BY_NAME = {
    "address_space": getattr(_resource, "RLIMIT_AS", None) if _resource else None,
    "cpu_seconds": getattr(_resource, "RLIMIT_CPU", None) if _resource else None,
    "processes": getattr(_resource, "RLIMIT_NPROC", None) if _resource else None,
    "file_size": getattr(_resource, "RLIMIT_FSIZE", None) if _resource else None,
    "open_files": getattr(_resource, "RLIMIT_NOFILE", None) if _resource else None,
}


def _apply_resource_limits(limits: Any) -> list[str]:
    """Defense-in-depth kernel resource caps for the tool (findings S7-#6 / fail-open).

    Applied here, in the fresh single-threaded worker, AFTER the runner's own trusted imports
    (so a low RLIMIT_AS cannot kill the interpreter mid-bootstrap) but BEFORE the untrusted tool
    module is imported (finding S7-#1) -- so the tool's module-scope code, not just its function,
    runs under the caps. NOT applied via the parent's ``preexec_fn`` (unsafe in the parent's
    threaded drain path). Because the caps now also bound the tool's *import*, RLIMIT_AS (virtual
    address space) and RLIMIT_CPU cover module import too -- a heavy tool module may need
    ``address_space`` raised.

    FAIL-CLOSED and OBSERVABLE: returns the names of the requested limits that could NOT be put in
    force -- an unrecognised key, an unsupported/absent constant on this platform, a bad value, or a
    ``setrlimit`` that raised. The caller REFUSES to run the tool when this list is non-empty, so a
    tool never runs believing it is capped when a requested cap silently did not apply. A limit the
    request does not mention is simply not requested; only keys present in ``limits`` are checked.
    This fail-closed rule is POSIX-scoped: on Windows ``_resource`` is absent and the Job Object is
    the containment mechanism, so requested rlimits do not apply there and this returns ``[]``
    (their POSIX-only nature is a documented platform limitation, not a silent fail-open).
    """
    if not limits:
        return []
    if _resource is None:
        # No POSIX setrlimit on this platform (Windows): these caps are not the containment
        # mechanism here -- the kill-on-close Job Object is -- so their absence is a documented
        # platform limitation, NOT the fail-open this guards against. Do not refuse the tool.
        return []
    if not isinstance(limits, dict):
        return ["<malformed rlimits>"]
    unapplied: list[str] = []
    for key, value in limits.items():
        rlimit = _RLIMIT_BY_NAME.get(key)
        if rlimit is None or not isinstance(value, int) or isinstance(value, bool) or value < 0:
            unapplied.append(key)
            continue
        try:
            _soft, hard = _resource.getrlimit(rlimit)
            # Never raise the ceiling: clamp to the existing hard limit, and lower it too so a
            # forked child cannot restore a higher soft limit.
            new = value if hard == _resource.RLIM_INFINITY else min(value, hard)
            _resource.setrlimit(rlimit, (new, new))
        except (ValueError, OSError):  # a requested cap could not be applied -> fail closed above
            unapplied.append(key)
    return sorted(unapplied)


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

    # Open the discard sink FIRST, while still trusted (finding S7-#1): a low RLIMIT_NOFILE
    # could otherwise make this open() fail after the caps apply and take out the only
    # protocol-safe stdout path. Keep a handle to the real stdout for the reply -- under the
    # redirect, sys.stdout is the sink, so the reply must be written here, never inside it.
    try:
        sink = open(os.devnull, "w", encoding="utf-8")
    except OSError:
        _respond_error("worker could not open output sink")
        return
    real_stdout = sys.stdout

    try:
        # Caps THEN untrusted import, both after the trusted bootstrap above. FAIL CLOSED: if any
        # requested cap could not be put in force, do NOT run the tool believing it is capped when
        # it is not -- report which caps failed (observable), never silently run under weaker caps.
        unapplied = _apply_resource_limits(request.get("rlimits"))
        if unapplied:
            ok, value = False, "worker could not apply resource limits: " + ", ".join(unapplied)
        else:
            ok, value = _import_and_run(module_name, object_path, arguments, sink)
    finally:
        sink.close()

    if not ok:
        _respond_error(value, stream=real_stdout)
        return
    try:
        encoded_size = len(canonical_json(value))
    except (TypeError, ValueError):
        _respond_error("tool output is not JSON serializable", stream=real_stdout)
        return
    if encoded_size > max_output_bytes:
        _respond_error("tool output exceeds output budget", stream=real_stdout)
        return
    _respond_ok(value, stream=real_stdout)


def _import_and_run(
    module_name: str, object_path: str, arguments: dict[str, Any], sink: Any
) -> tuple[bool, Any]:
    """Import the untrusted tool and run it, with Python stdout redirected to a discard sink.

    Returns ``(True, result)`` or ``(False, error_message)``. It NEVER writes the protocol reply
    itself: under ``redirect_stdout`` that would land in the sink, not the parent's pipe, so the
    caller reports every outcome on the real stdout. Both the import and the call are wrapped in
    ``except BaseException`` and fail CLOSED with a controlled reason (the EV-010 non-terminal
    crash class): now that the caps bound the import, module-scope code can raise anything -- an
    FSIZE/AS cap firing, a hostile ``sys.exit()`` at import, a recursion bomb -- and none of that
    may escape as a dead worker with no response.
    """
    with redirect_stdout(sink):
        try:
            loaded: Any = importlib.import_module(module_name)
            for part in object_path.split("."):
                if not part:
                    raise AttributeError
                loaded = getattr(loaded, part)
        except (ImportError, AttributeError):
            return False, "could not import tool target"
        except BaseException as error:  # noqa: BLE001 - module-scope code failed; fail closed
            return False, f"tool import raised {type(error).__name__}"
        if not callable(loaded):
            return False, "tool target is not callable"
        try:
            return True, loaded(arguments)
        except BaseException as error:  # noqa: BLE001 - any tool failure fails closed
            return False, f"tool raised {type(error).__name__}"


def _respond_ok(result: Any, stream: Any = None) -> None:
    out = sys.stdout if stream is None else stream
    try:
        payload = json.dumps({"ok": True, "result": result})
    except (TypeError, ValueError):
        _respond_error("tool output is not JSON serializable", stream=out)
        return
    out.write(payload)
    out.flush()


def _respond_error(message: str, stream: Any = None) -> None:
    out = sys.stdout if stream is None else stream
    out.write(json.dumps({"ok": False, "error": message}))
    out.flush()


if __name__ == "__main__":
    main()

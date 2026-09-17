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
import inspect
import json
import os
import signal
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


def _harden_inherited_root_fd() -> None:
    # Section 7 PR 3: the runtime passes the safe-path root descriptor via pass_fds, which clears
    # close-on-exec so this worker inherits it. Re-set close-on-exec at once so that ANY process the
    # tool spawns does NOT inherit filesystem authority -- even if the tool never calls
    # SafeRoot.from_runtime(). from_runtime() still works: it uses the descriptor as a dir_fd
    # (inheritability is irrelevant there) and then re-opens its own close-on-exec copy.
    # The env-var name is safe_paths.ROOT_FD_ENV, inlined to keep the worker bootstrap import-light.
    raw_fd = os.environ.get("PORTMARK_ROOT_FD")
    if not raw_fd:
        return
    try:
        os.set_inheritable(int(raw_fd), False)
    except (ValueError, OSError):
        pass


def main() -> None:
    _harden_inherited_root_fd()
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
    effect_id = request.get("effect_id")  # Section 7 PR 2: optional idempotency key for side-effecting tools
    if effect_id is not None and not isinstance(effect_id, str):
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
            ok, value = _import_and_run(module_name, object_path, arguments, sink, effect_id)
    finally:
        sink.close()

    # Decide the reply, then send it through ONE path (_finish) so the process-group sweep runs on
    # EVERY post-tool outcome -- success, tool error, non-serializable output, over-budget, and the
    # fail-closed rlimit refusal. A tool whose module scope spawned a background child and then blew
    # up leaks today; the sweep must cover it too. (The pre-tool early returns above cannot have
    # spawned anything, so they neither reach here nor need the sweep.)
    if not ok:
        _finish(_respond_error, value, real_stdout)
        return
    try:
        encoded_size = len(canonical_json(value))
    except (TypeError, ValueError):
        _finish(_respond_error, "tool output is not JSON serializable", real_stdout)
        return
    if encoded_size > max_output_bytes:
        _finish(_respond_error, "tool output exceeds output budget", real_stdout)
        return
    _finish(_respond_ok, value, real_stdout)


def _finish(responder: Any, payload: Any, stream: Any) -> None:
    """Send the reply, guarantee it is flushed to the pipe, then sweep the worker's process group.

    The flush is redundant with the responder's own flush BUT deliberate: the sweep is an
    unrecoverable SIGKILL, and flushed pipe bytes survive the sender's death while an unflushed
    buffer does not -- so pay the extra flush before the sweep can never truncate the reply.
    """
    responder(payload, stream=stream)
    try:
        stream.flush()
    except (OSError, ValueError):  # pragma: no cover - stream already closed
        pass
    _sweep_own_process_group()


def _sweep_own_process_group() -> None:
    """POSIX: SIGKILL the worker's own process group before it exits, to sweep any background child
    the tool left in the group (the normal-exit leak: finding S7-#1's descendant-escape class).

    The worker is its own session leader (the parent launches it with ``start_new_session``), so its
    process group holds only its own descendants; signalling group 0 (the caller's group) reaps them.
    This kills the worker too, so a SUCCESSFUL isolated tool exits by SIGKILL BY DESIGN -- the host
    reads the JSON response from the pipe (already flushed above), never the worker's exit status.
    Three residual limits, all documented: a child that moved to its OWN process group -- via
    ``setsid()``/``start_new_session()`` (new session) OR ``setpgid()``/``setpgrp()`` (new group in
    the same session) -- is no longer in the worker's group and escapes this sweep; a worker that dies
    before reaching here cannot run it; and this sweep is only EFFECTIVE because the parent launches
    the worker with ``start_new_session`` (so the worker leads its own group) -- a launch path that
    omits that gets no sweep (the guard below makes that safe, not merely inert). On Windows there is
    no ``killpg`` and the kill-on-close Job Object already contains the tree, so this is a no-op.

    CRITICAL safety guard: only sweep when this worker is its OWN process-group leader (pgid == pid),
    which it is when the parent launched it with ``start_new_session`` (the real path) -- then group 0
    holds only its descendants. If it is NOT the leader (the worker was run directly inside another
    process's group, as a test harness or an unusual caller might), ``killpg(0)`` would signal THAT
    foreign group. Never do that; skip the sweep instead. This makes the sweep safe regardless of how
    the worker was started.
    """
    if not hasattr(os, "killpg") or not hasattr(os, "getpgrp"):
        return
    try:
        if os.getpgrp() != os.getpid():
            return
    except OSError:  # pragma: no cover - platform dependent
        return
    try:
        os.killpg(0, signal.SIGKILL)
    except OSError:  # pragma: no cover - group already gone
        pass


def _accepts_effect_id(fn: Any) -> bool:
    """Whether `fn` can be called as fn(arguments, effect_id) -- i.e. it takes a second positional
    parameter or accepts *args. Used to check the side-effecting-tool contract BEFORE the call, so a
    tool that does not accept the effect_id fails with a controlled reply and is NEVER called twice
    (a second call would double a real side effect)."""
    try:
        signature = inspect.signature(fn)
    except (TypeError, ValueError):  # pragma: no cover - C builtins etc.
        return False
    positional = 0
    for parameter in signature.parameters.values():
        if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD):
            positional += 1
        elif parameter.kind == parameter.VAR_POSITIONAL:
            return True
    return positional >= 2


def _import_and_run(
    module_name: str, object_path: str, arguments: dict[str, Any], sink: Any, effect_id: str | None = None
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
        if effect_id is not None and not _accepts_effect_id(loaded):
            # Contract violation for a side-effecting tool: fail closed with a controlled reply,
            # never call it (a call without the key, or a double call, could mis-apply the effect).
            return False, "tool does not accept effect_id"
        try:
            result = loaded(arguments, effect_id) if effect_id is not None else loaded(arguments)
            return True, result
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

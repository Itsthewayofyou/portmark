from __future__ import annotations

import json
import os
import queue
import signal
import subprocess  # nosec B404
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import _windows_job
from .models import Permit
from .security import SecurityError, canonical_json, check_constraints


Tool = Callable[[dict[str, Any]], Any]

# Extra bytes the parent will read past the tool's output budget before it
# declares an overflow: the response is `{"ok": true, "result": <output>}`, so
# the JSON envelope adds a little over the raw output. Kept small on purpose --
# it bounds host memory against a tool that writes to fd 1 directly.
_RESPONSE_ENVELOPE_SLACK = 65_536

# Section 7 #6: defense-in-depth kernel resource caps handed to each isolated worker, which
# applies them (POSIX only) right before running the tool. Generous defaults that do not break
# ordinary tools but cap runaway memory / fork bombs / disk / fd exhaustion. `cpu_seconds` is
# filled per invocation from the tool's wall-clock deadline. NOT a containment boundary (they
# are POSIX-only and do not constrain the network); real containment is the deployment substrate.
_DEFAULT_TOOL_RLIMITS: dict[str, int] = {
    "address_space": 1024 * 1024 * 1024,  # 1 GiB virtual memory (RLIMIT_AS)
    "file_size": 64 * 1024 * 1024,          # 64 MiB largest file a tool may write (RLIMIT_FSIZE)
    "open_files": 512,                      # RLIMIT_NOFILE
    # NOT defaulted: "processes" (RLIMIT_NPROC) is PER-UID -- it counts every process the OS user
    # already runs, so a fixed cap fails fork() with EAGAIN on a busy shared host and breaks
    # legitimate tools. An operator running tools under a DEDICATED low-privilege uid can set it
    # via ToolRegistry(resource_limits={..., "processes": N}); "cpu_seconds" is filled per call.
}

# Section 7 #3: resource-limit keys an OPERATOR may set on ToolRegistry. "cpu_seconds" is
# deliberately NOT here -- it is derived per invocation from each tool's own wall-clock timeout
# (a kernel backstop for the deadline), so letting an operator pin it could make it fire BEFORE
# the host's own deadline. The worker still accepts cpu_seconds in the request; the host fills it.
_OPERATOR_RESOURCE_LIMIT_KEYS = frozenset({"address_space", "processes", "file_size", "open_files"})


def _merged_resource_limits(overrides: dict[str, int] | None) -> dict[str, int]:
    """Validate operator resource-limit overrides and MERGE them over the defaults (finding #3).

    Fails startup (ValueError) on an unknown key -- catching a typo like ``adress_space`` that
    would otherwise silently disable the cap the operator meant to set -- or a value that is not a
    positive integer. Merge, not replace: supplying one key keeps the other default caps, so
    ``resource_limits={"file_size": N}`` does not silently drop the memory / fd caps. To turn OFF
    all caps, pass ``disable_resource_limits=True`` -- an explicit switch, not an easily-mistyped
    empty dict.
    """
    merged = dict(_DEFAULT_TOOL_RLIMITS)
    if overrides is None:
        return merged
    if not isinstance(overrides, dict):
        raise ValueError("resource_limits must be a dict of {name: positive int}")
    for key, value in overrides.items():
        if key not in _OPERATOR_RESOURCE_LIMIT_KEYS:
            allowed = ", ".join(sorted(_OPERATOR_RESOURCE_LIMIT_KEYS))
            raise ValueError(
                f"unknown resource_limits key {key!r}; allowed: {allowed} "
                "(cpu_seconds is derived from each tool's timeout and cannot be set here)"
            )
        # Order matters: bool is a subclass of int, so reject it FIRST -- otherwise True would
        # sail through as 1. Do not reorder these three checks (same discipline as a fail-closed gate).
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"resource_limits[{key!r}] must be a positive integer, got {value!r}")
        merged[key] = value
    return merged


# Environment names the isolated worker is allowed to inherit. This is a
# default-deny allowlist, not parent-minus-a-blocklist: a secret the host holds in its own
# environment (API keys, tokens, DB URLs) is NOT inherited as a child environment variable
# unless the operator names it explicitly via `env=`. Section 7 #3: "not inherited as a child
# env var" is NOT "inaccessible" -- because the worker runs under the SAME OS uid, a hostile
# tool can still read the parent's /proc/<pid>/environ and any credential file on the shared
# filesystem. Preventing that requires OS-level isolation (a separate uid, restricted /proc,
# filesystem namespaces) supplied by the deployment, not this allowlist.
# PYTHONPATH is required for the worker to import portmark and the tool module at all.
_INHERITED_ENV_KEYS = ("PYTHONPATH", "PATH", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT")

# Finding #5: the thread-timeout path cannot cancel a tool, so a timed-out tool leaks a
# running daemon thread. Cap how many thread-path executions may be in flight at once so
# leaked threads cannot accumulate without bound; beyond the cap a tool invocation fails
# closed. Long or side-effecting tools belong on the isolated (hard-killable) path.
DEFAULT_MAX_INFLIGHT_THREADED_TOOLS = 64

# POSIX process-group termination primitive: the worker is its own session leader
# (start_new_session) and the platform can signal the whole group (os.killpg). This is
# COOPERATIVE, not containment: a descendant that calls setsid()/start_new_session moves to
# its own group and escapes the signal. A background child left in the group after a NORMAL exit
# is swept at the source (the worker SIGKILLs its own group before exiting -- see
# tool_subprocess_runner._sweep_own_process_group); the residual escapees are a setsid() child and
# a worker that dies before its sweep.
# The contract (THREAT_MODEL): the isolated executor is a resource-bounded, hard-deadline
# worker, NOT a hostile-code sandbox -- containing a hostile tool is the deployment's job
# (container / PID namespace + cgroup / separate uid). Windows' Job Object (below) is
# materially stronger: it terminates the whole tree as one unit with no breakaway.
_CAN_KILL_PROCESS_GROUP = hasattr(os, "killpg") and hasattr(os, "getpgid")


class ToolExecutionError(SecurityError):
    pass


class ToolKilledError(ToolExecutionError):
    """An isolated tool was terminated at its deadline.

    Distinct from a clean ToolExecutionError because the host cannot know whether a side
    effect already landed before the termination. On Windows the Job Object reaps the whole
    tree; on POSIX the group signal is COOPERATIVE (a setsid() descendant can escape and keep
    running), so it does not even guarantee every *new* effect is stopped, let alone roll back
    one already in flight. The host audits this as a killed-at-deadline event with effect status
    unknown; the real guarantee against a hostile side-effecting tool is the deployment's
    isolation profile plus the tool's own idempotency/reconciliation, not this termination.
    """


@dataclass(frozen=True)
class _IsolatedSpec:
    target: str
    env: dict[str, str] = field(default_factory=dict)
    # Section 7 PR 2: a module:function the host runs (isolated, with the effect_id) to determine
    # whether a side-effecting tool's external effect actually landed, for the reconcile pass.
    reconcile: str | None = None


class ToolRegistry:
    def __init__(
        self,
        default_timeout: float = 5.0,
        max_output_bytes: int = 65_536,
        max_inflight_threaded: int = DEFAULT_MAX_INFLIGHT_THREADED_TOOLS,
        resource_limits: dict[str, int] | None = None,
        disable_resource_limits: bool = False,
    ) -> None:
        self._tools: dict[str, Tool] = {}
        self._isolated: dict[str, _IsolatedSpec] = {}
        self._timeouts: dict[str, float] = {}
        self._max_output: dict[str, int] = {}
        self._side_effecting: set[str] = set()
        # Section 7 PR 2 (round 2): the registry's only view of the durable effect ledger. AgentHost
        # binds this to a predicate that answers "did the host record this effect_id and mark it
        # `started`?" (bind_effect_ledger). invoke() then runs a side-effecting tool ONLY for such an
        # id -- a fabricated string names no started row and is refused AT THE GATE. Left None the
        # gate fails closed: an unbound registry cannot verify the ledger, so it refuses every
        # side-effecting call rather than trusting the caller.
        self._effect_started: Callable[[str], bool] | None = None
        self.default_timeout = default_timeout
        self.max_output_bytes = max_output_bytes
        # Section 7 #6/#3: defense-in-depth resource caps applied inside each isolated worker.
        # None uses the generous defaults; resource_limits={...} validates its keys/values and
        # MERGES over the defaults (an unknown key or non-positive value fails startup, not
        # silently). disable_resource_limits=True turns the exhaustion caps off -- an explicit
        # switch, never an overloaded {}; the CPU-time deadline backstop still applies per call.
        if disable_resource_limits:
            if resource_limits:
                raise ValueError("pass either resource_limits or disable_resource_limits=True, not both")
            self.resource_limits: dict[str, int] = {}
        else:
            self.resource_limits = _merged_resource_limits(resource_limits)
        # Finding #5: the thread-timeout path cannot cancel a tool once it starts, so a
        # tool that exceeds its deadline leaves its daemon thread running. This bounded
        # semaphore caps how many such executions can be in flight at once. A slot is held
        # for the whole lifetime of the worker thread -- including a leaked, timed-out one
        # (it is released in the worker's `finally`, when the thread actually finishes),
        # so leaked threads cannot grow without bound: once the cap is reached a new
        # invocation fails closed instead of spawning another leak.
        self._inflight_threaded = threading.BoundedSemaphore(max_inflight_threaded)

    def register(self, name: str, tool: Tool, timeout: float | None = None, side_effecting: bool = False) -> None:
        self._tools[name] = tool
        self._isolated.pop(name, None)
        if timeout is not None:
            self._timeouts[name] = timeout
        if side_effecting:
            self._side_effecting.add(name)

    def register_isolated(
        self,
        name: str,
        target: str,
        *,
        timeout: float | None = None,
        max_output_bytes: int | None = None,
        side_effecting: bool = False,
        env: dict[str, str] | None = None,
        reconcile: str | None = None,
    ) -> None:
        """Register a tool that runs in a separate, deadline-terminated subprocess (EV-002).

        `target` is a `module:function` import path resolved inside the worker,
        not a callable, because a closure cannot be shipped to a fresh process.
        `env` names extra environment variables to pass through; by default the
        worker sees only a minimal allowlist and none of the host's secrets.
        Only an isolated tool may be `side_effecting`: the thread path cannot
        cancel a running tool, so it still refuses side-effecting tools.

        NOTE: this subprocess is a resource-bounded, hard-deadline worker, NOT a
        hostile-code sandbox. At the deadline the host terminates the worker's
        process tree -- genuinely on Windows (a kill-on-close Job Object, no
        breakaway), but only COOPERATIVELY on POSIX (a setsid()/start_new_session
        descendant escapes the group signal). Containing a hostile tool is the
        deployment's job (see THREAT_MODEL.md); this flag only requires that SOME
        tree-termination primitive exists on the platform.
        """
        module_name, separator, object_path = target.partition(":")
        if not separator or not module_name or not object_path:
            raise ValueError("register_isolated target must use module:function syntax")
        if reconcile is not None:
            r_module, r_sep, r_object = reconcile.partition(":")
            if not r_sep or not r_module or not r_object:
                raise ValueError("register_isolated reconcile must use module:function syntax")
        if side_effecting and not _has_tree_termination_primitive():
            # Fail closed at startup, not at the first payment: on a platform with no
            # tree-kill primitive the host cannot guarantee the tool and its descendants
            # stop at the deadline, so it must not promise to run a side-effecting one.
            raise SecurityError(
                f"tool {name!r} is side-effecting but this platform cannot hard-kill a worker's "
                "process tree, so the host cannot guarantee it stops at its deadline; refusing "
                "to register it. Non-side-effecting isolated tools are allowed."
            )
        self._isolated[name] = _IsolatedSpec(target=target, env=dict(env or {}), reconcile=reconcile)
        self._tools.pop(name, None)
        if timeout is not None:
            self._timeouts[name] = timeout
        if max_output_bytes is not None:
            self._max_output[name] = max_output_bytes
        if side_effecting:
            self._side_effecting.add(name)

    def bind_effect_ledger(self, effect_started: Callable[[str], bool]) -> None:
        """Bind this registry's side-effecting gate to the host's durable effect ledger (Section 7
        PR 2, round 2). `effect_started(effect_id)` returns True only for an effect the host has
        recorded and marked `started`. AgentHost calls this at construction; invoke() then admits a
        side-effecting tool ONLY for such an id, so a caller-fabricated string (or a bare call that
        skips the ledger) is refused at the gate rather than trusted. One registry serves one host's
        ledger; a re-bind points the gate at the most recently bound host's store."""
        self._effect_started = effect_started

    def is_side_effecting(self, name: str) -> bool:
        """Whether the tool is registered side-effecting (the host wraps it in the effect ledger)."""
        return name in self._side_effecting

    def is_isolated(self, name: str) -> bool:
        """Whether the tool runs in an isolated worker (the only path that can carry an effect_id)."""
        return name in self._isolated

    def has_reconcile(self, name: str) -> bool:
        """Whether an isolated tool has a reconcile function registered (Section 7 PR 2)."""
        spec = self._isolated.get(name)
        return spec is not None and spec.reconcile is not None

    def reconcile(self, name: str, arguments: dict[str, Any], effect_id: str) -> Any:
        """Run a tool's registered reconcile function (isolated, with the effect_id) to determine
        whether its external effect landed. Host-invoked during the reconcile pass -- NOT an
        agent-facing tool call, so it does not go through the permit/constraint check. Returns the
        reconcile function's result (by contract, a dict like {"landed": bool, "result"?: ...})."""
        spec = self._isolated.get(name)
        if spec is None or spec.reconcile is None:
            raise ToolExecutionError(f"tool {name!r} has no reconcile function registered")
        reconcile_spec = _IsolatedSpec(target=spec.reconcile, env=dict(spec.env))
        timeout = self._timeouts.get(name, self.default_timeout)
        cap = self._max_output.get(name, self.max_output_bytes)
        return self._invoke_isolated(reconcile_spec, arguments, timeout, cap, effect_id=effect_id)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(set(self._tools) | set(self._isolated)))

    def invoke(self, permit: Permit, name: str, arguments: dict[str, Any], max_output_bytes: int | None = None, effect_id: str | None = None) -> Any:
        grant = next((grant for grant in permit.grants if grant.name == name), None)
        if grant is None:
            # Only the effective permit is visible here, so this cannot say which
            # stage dropped the tool. AgentHost checks first and reports the
            # cause; see HostPolicy.explain_missing_grant.
            raise SecurityError(
                f"tool {name!r} is not in the effective permit. It was removed by the manifest, "
                "the permit or the host policy; run it through AgentHost, or call "
                "HostPolicy.explain_missing_grant, to find out which."
            )
        is_isolated = name in self._isolated
        if not is_isolated and name not in self._tools:
            raise SecurityError(f"tool {name!r} is not installed")
        check_constraints(grant.constraints, arguments)
        timeout = self._timeouts.get(name, self.default_timeout)
        cap = max_output_bytes if max_output_bytes is not None else self._max_output.get(name, self.max_output_bytes)

        if name in self._side_effecting:
            # Fail closed at the invoke boundary. A side-effecting tool runs ONLY for an effect the
            # host recorded and marked `started` in the durable ledger. The gate CHECKS that fact via
            # an injected predicate (bind_effect_ledger) -- it never trusts the caller to have done the
            # recording. This closes the round-1 hole where any non-None effect_id string satisfied the
            # gate: a fabricated id names no started row and is refused here; no id, or an unbound
            # registry, also fails closed. The registry still holds no store, so this proves the effect
            # is host-recorded, not (by itself) that the whole ledger lifecycle ran -- but a bare public
            # string can no longer authorize a side-effecting call.
            if effect_id is None:
                raise ToolExecutionError(
                    f"tool {name!r} is side-effecting and must run through the effect ledger via AgentHost "
                    "(which supplies its effect_id); it cannot be invoked directly without one."
                )
            if self._effect_started is None:
                raise ToolExecutionError(
                    f"tool {name!r} is side-effecting but this ToolRegistry is not bound to an effect "
                    "ledger; construct it via AgentHost (which calls bind_effect_ledger) so invoke can "
                    "verify the host recorded the effect."
                )
            if not self._effect_started(effect_id):
                raise SecurityError(
                    f"effect_id {effect_id!r} does not name a started effect in the ledger; a "
                    "side-effecting tool runs only for an effect the host has recorded and marked "
                    "started -- a fabricated id cannot authorize one."
                )

        if is_isolated:
            return self._invoke_isolated(self._isolated[name], arguments, timeout, cap, effect_id=effect_id)

        if name in self._side_effecting:
            # Finding #3 / EV-002: the thread + queue-timeout path below cannot
            # cancel a tool once it has started. If the deadline fires, the host
            # raises ToolExecutionError and records failure, but the daemon thread
            # keeps running and its side effect (a payment, a booking) can still
            # land -- the audit record and the outside world then disagree. A tool
            # the operator marks side-effecting must not run on this path; it must
            # be registered with register_isolated, which runs it in a process the
            # host can hard-kill. Until then, fail closed.
            raise ToolExecutionError(
                f"tool {name!r} is marked side-effecting and cannot run on the thread-timeout "
                "path, which cannot cancel a tool once started; register it with "
                "register_isolated so the host can hard-kill it."
            )
        return self._invoke_threaded(self._tools[name], arguments, timeout, cap)

    def _invoke_threaded(self, tool: Tool, arguments: dict[str, Any], timeout: float, cap: int) -> Any:
        # Finding #5: acquire an in-flight slot BEFORE spawning. A leaked (timed-out)
        # thread keeps its slot until it actually finishes (released in run_tool's
        # finally), so if leaked threads fill the cap a new invocation fails closed here
        # instead of adding another unbounded leak.
        if not self._inflight_threaded.acquire(blocking=False):
            raise ToolExecutionError(
                "too many in-flight thread-path tool executions; a prior tool likely "
                "exceeded its deadline and is still running. Register long or "
                "side-effecting tools with register_isolated so the host can hard-kill them."
            )
        result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

        def run_tool() -> None:
            try:
                result_queue.put((True, tool(arguments)))
            except Exception as error:  # noqa: BLE001 - reported as a failed tool
                result_queue.put((False, error))
            finally:
                self._inflight_threaded.release()

        thread = threading.Thread(target=run_tool, daemon=True)
        try:
            thread.start()
        except RuntimeError:
            # The OS refused a new thread; release the slot we reserved and fail closed.
            self._inflight_threaded.release()
            raise ToolExecutionError("could not start a worker thread for the tool")
        try:
            succeeded, value = result_queue.get(timeout=timeout)
        except queue.Empty as error:
            raise ToolExecutionError("tool execution exceeded its deadline") from error
        if not succeeded:
            raise ToolExecutionError("tool execution failed") from value
        return self._checked_output(value, cap)

    def _invoke_isolated(
        self, spec: _IsolatedSpec, arguments: dict[str, Any], timeout: float, cap: int, effect_id: str | None = None
    ) -> Any:
        # Section 7 #6: hand the worker its resource caps. cpu_seconds is a kernel backstop for the
        # wall-clock deadline (a CPU-bound tool that ignores the clock still dies), set a little
        # above the timeout so it never fires before the host's own deadline does.
        rlimits = dict(self.resource_limits)
        if "cpu_seconds" not in rlimits:
            rlimits["cpu_seconds"] = int(timeout) + 2
        payload: dict[str, Any] = {
            "target": spec.target, "arguments": arguments, "max_output_bytes": cap, "rlimits": rlimits
        }
        # Section 7 PR 2: side-effecting tools (and their reconcile fns) receive a host-derived
        # idempotency key OUTSIDE `arguments` -- the deny-by-default argument-name whitelist in
        # check_constraints would reject an injected key. The worker passes it as tool(arguments, effect_id).
        if effect_id is not None:
            payload["effect_id"] = effect_id
        request = json.dumps(payload
        ).encode("utf-8")
        try:
            tree = _launch_process_tree(
                [sys.executable, "-m", "portmark.tool_subprocess_runner"],
                self._child_env(spec.env),
            )
        except OSError as error:
            raise ToolExecutionError("could not start isolated tool worker") from error

        hard_cap = cap + _RESPONSE_ENVELOPE_SLACK
        buffer = bytearray()
        overflow = threading.Event()

        def drain() -> None:
            stream = tree.stdout
            if stream is None:
                return
            try:
                while True:
                    chunk = stream.read(65_536)
                    if not chunk:
                        break
                    buffer.extend(chunk)
                    if len(buffer) > hard_cap:
                        overflow.set()
                        tree.terminate_tree()
                        break
            except (OSError, ValueError):
                pass

        reader = threading.Thread(target=drain, daemon=True)
        try:
            if tree.stdin is not None:
                try:
                    tree.stdin.write(request)
                    tree.stdin.close()
                except (BrokenPipeError, OSError):
                    pass
            reader.start()
            timed_out = False
            kill_confirmed = True
            try:
                tree.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                # Confirm the whole tree actually exited: the kill may fail to issue
                # (terminate_tree raises OSError -- a Win32 BOOL returned false) or the
                # process may outlive the kill (the second wait times out). In either
                # case do NOT claim a clean kill; fail closed below.
                try:
                    tree.terminate_tree()
                    tree.wait(timeout=2.0)
                except (subprocess.TimeoutExpired, OSError):
                    kill_confirmed = False
            reader.join(timeout=2.0)
        finally:
            # Best-effort cleanup: the outcome above is already decided, so a failure
            # here (a Win32 return, a close error) must not mask it. On Windows close()
            # also closes the job handle, a KILL_ON_JOB_CLOSE fallback.
            try:
                tree.terminate_tree()
            except OSError:
                pass
            try:
                tree.close()
            except OSError:
                pass

        if timed_out and not kill_confirmed:
            # The deadline fired but the process tree could not be confirmed dead. Do
            # not report a clean kill -- that would overstate containment.
            raise ToolExecutionError("isolated tool process tree could not be confirmed terminated")
        if timed_out:
            raise ToolKilledError("isolated tool exceeded its deadline and was killed")
        if overflow.is_set():
            raise ToolExecutionError("tool output exceeds output budget")

        # PR 1b verification: before accepting ANY reply (success or tool error), confirm the worker
        # actually ran its process-group self-sweep -- i.e. it exited by SIGKILL on a self-sweep
        # backend. If it exited any other way the sweep did not run and descendant containment is
        # unconfirmed; fail closed, reporting the containment breach in preference to any tool error.
        # This is the normal-exit analogue of the timeout "could not be confirmed terminated" branch.
        if not _self_sweep_confirmed(tree):
            raise ToolExecutionError(
                f"isolated worker did not self-terminate its process group (exit {tree.returncode}); "
                "descendant-containment sweep unconfirmed"
            )

        try:
            response = json.loads(bytes(buffer).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as error:
            raise ToolExecutionError("isolated tool produced invalid output") from error
        if not isinstance(response, dict) or "ok" not in response:
            raise ToolExecutionError("isolated tool produced invalid output")
        if not response["ok"]:
            raise ToolExecutionError(f"isolated tool failed: {response.get('error', 'unknown')}")
        return self._checked_output(response.get("result"), cap)

    def _checked_output(self, result: Any, cap: int) -> Any:
        try:
            encoded_size = len(canonical_json(result))
        except (TypeError, ValueError) as error:
            raise ToolExecutionError("tool output is not JSON serializable") from error
        if encoded_size > cap:
            raise ToolExecutionError("tool output exceeds output budget")
        return result

    def _child_env(self, extra: dict[str, str]) -> dict[str, str]:
        env = {key: os.environ[key] for key in _INHERITED_ENV_KEYS if key in os.environ}
        env.update(extra)
        return env


def _has_tree_termination_primitive() -> bool:
    # Whether this platform has ANY primitive to terminate a worker's descendants at the
    # deadline -- Windows a Job Object (genuine, whole-tree, no breakaway), POSIX os.killpg on
    # the worker's session group (COOPERATIVE: a setsid() descendant escapes). Enforcement reads
    # this to refuse side-effecting isolated tools only where NO primitive exists at all. It does
    # NOT assert containment of a hostile tool -- on POSIX the primitive is best-effort, and the
    # real safety for side-effecting tools (idempotency + reconciliation, and an acknowledged
    # isolation profile) is enforced separately. Named for what it checks, not an over-claim.
    return _CAN_KILL_PROCESS_GROUP or _windows_job.available()


def _terminate_posix_process_group(process: subprocess.Popen[bytes]) -> None:
    """Best-effort sweep of the worker and descendants via its process group (COOPERATIVE).

    The worker is its own session leader (start_new_session), so signalling its process group
    reaches grandchildren it left in that group. This is NOT containment: a descendant that
    calls setsid()/start_new_session moves to its own group and survives. Real containment of a
    hostile tool is the deployment substrate's job (container / PID namespace + cgroup). This runs
    on the TIMEOUT path, where the worker is still alive: killpg then reaches the whole group. The
    NORMAL-exit background-child leak is closed at the source -- the worker SIGKILLs its own process
    group before it exits (see tool_subprocess_runner._sweep_own_process_group) -- so the
    already-exited early return below is now correct, not a leak.
    """
    if process.poll() is not None:
        # Already exited: signalling a reaped pid could hit an unrelated reused pid, so do not.
        # This no longer leaks a background child -- on a NORMAL exit the worker already swept its
        # own group before dying; the residuals (a setsid() escapee, a worker that died before its
        # sweep) are documented best-effort limits, not fixed here by signalling a reaped pid.
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except (ProcessLookupError, OSError):
            pass


def _self_sweep_confirmed(tree: _ProcessTree) -> bool:
    """Whether the worker's PR-1b self-sweep is confirmed for a reply we are about to accept.

    A self-sweep backend (POSIX) SIGKILLs its own process group before exiting, so a worker that
    produced a reply MUST have exited by SIGKILL. Any other exit -- a clean ``0`` (the sweep did not
    run), a crash by another signal, or ``None`` (never reaped) -- means the descendant-containment
    sweep is unconfirmed and the host must not silently accept the reply. Keep the explicit
    ``== -SIGKILL`` equality: do NOT "simplify" it to a truthy check, which would read a clean ``0``
    as confirmed. Non-self-sweep backends (Windows Job Object, unmanaged) are never gated here.
    """
    if not tree.expects_self_sweep:
        return True
    return tree.returncode == -signal.SIGKILL


class _ProcessTree:
    """A launched isolated-tool worker with a deadline-termination contract.

    `terminate_tree()` attempts to stop the worker and its descendants at the deadline;
    `terminates_whole_tree` states whether this backend GUARANTEES that against a hostile
    tool. Windows' Job Object does (True). The POSIX process-group backend does NOT (False,
    cooperative): a setsid() descendant escapes. The isolated executor talks to this interface
    instead of scattering platform branches through `_invoke_isolated`.
    """

    terminates_whole_tree: bool = False

    # Whether this backend's worker SIGKILLs its OWN process group before a normal exit (PR 1b):
    # True on POSIX. When True, a worker that produced a reply MUST have exited by SIGKILL, and the
    # host verifies that before accepting the reply (see _self_sweep_confirmed). False backends
    # (Windows Job Object, unmanaged) neither self-sweep nor get verified.
    expects_self_sweep: bool = False

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process
        self._closed = False

    @property
    def returncode(self) -> int | None:
        return self._process.returncode

    @property
    def stdin(self) -> Any:
        return self._process.stdin

    @property
    def stdout(self) -> Any:
        return self._process.stdout

    def poll(self) -> int | None:
        return self._process.poll()

    def wait(self, timeout: float) -> int:
        return self._process.wait(timeout=timeout)

    def terminate_tree(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def close(self) -> None:
        # Release the worker fully and idempotently: kill it if still alive, reap it
        # (collect exit status -- an un-waited Popen warns "subprocess ... is still
        # running" and leaves a zombie), then close both pipes. On the normal path the
        # root has already exited so the kill is skipped; the executor's finally has
        # already issued the tree-kill (on Windows the CI-proven TerminateJobObject),
        # so the kill here is the launch-failure / standalone-close safety net, not a
        # replacement for it.
        if self._closed:
            return
        self._closed = True
        process = self._process
        if process.poll() is None:
            try:
                self.terminate_tree()
            except OSError:
                pass
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


class _PosixProcessTree(_ProcessTree):
    # COOPERATIVE, not containment: killpg sweeps the worker's process group, but a setsid()
    # descendant escapes. False by design -- POSIX does not guarantee whole-tree termination against
    # a hostile tool (that is the deployment substrate's job). The normal-exit background-child leak
    # is closed at the source (the worker sweeps its own group before exiting). The termination
    # PRIMITIVE still exists, which is what gates whether a side-effecting isolated tool may be
    # registered (see _has_tree_termination_primitive).
    terminates_whole_tree = False
    # The POSIX worker SIGKILLs its own process group before a normal exit (PR 1b), so a reply from
    # it MUST come with a SIGKILL exit -- the host verifies this before accepting the reply.
    expects_self_sweep = True

    def terminate_tree(self) -> None:
        _terminate_posix_process_group(self._process)


class _UnmanagedProcessTree(_ProcessTree):
    # A platform with no tree-termination primitive at all: kills only the root process, so
    # descendants may outlive it -- which is why side-effecting isolated tools are refused here.
    terminates_whole_tree = False

    def terminate_tree(self) -> None:
        if self._process.poll() is not None:
            return
        try:
            self._process.kill()
        except (ProcessLookupError, OSError):
            pass


class _WindowsJobProcessTree(_ProcessTree):
    # A worker created SUSPENDED, assigned to a kill-on-close Job Object before it can
    # spawn anything (race-free), then resumed. TerminateJobObject reaps the worker and
    # every descendant as one unit; closing the last job handle is a kill-on-close
    # safety net if terminate_tree was never called. This IS whole-tree containment: no
    # breakaway, assigned before the worker can spawn -- materially stronger than POSIX killpg.
    terminates_whole_tree = True

    def __init__(self, process: subprocess.Popen[bytes], job_handle: int) -> None:
        super().__init__(process)
        self._job = job_handle
        self._job_closed = False

    def terminate_tree(self) -> None:
        _windows_job.terminate_job(self._job)

    def close(self) -> None:
        super().close()
        if not self._job_closed:
            self._job_closed = True
            _windows_job.close_handle(self._job)


def _launch_windows_job_tree(argv: list[str], common: dict[str, Any]) -> _ProcessTree:
    job = _windows_job.create_kill_on_close_job()
    try:
        process = subprocess.Popen(  # nosec B603
            argv,
            creationflags=_windows_job.CREATE_SUSPENDED | _windows_job.CREATE_NO_WINDOW,
            **common,
        )
    except OSError:
        _close_job_quietly(job)
        raise
    try:
        # Assign while suspended: the worker cannot have spawned a child yet, so nothing
        # can escape the job. Then resume. Any failure fails closed -- kill the
        # suspended worker and the job; NEVER fall back to an unmanaged process.
        _windows_job.assign_process(job, int(process._handle))
        if _windows_job.resume_process_main_thread(process.pid) < 1:
            raise OSError("could not resume the suspended isolated-tool worker")
    except OSError:
        # Reap the suspended worker and the job before re-raising the real failure.
        # Cleanup is best-effort so a secondary Win32 error cannot mask the primary one;
        # the job's KILL_ON_JOB_CLOSE also reaps the worker as it closes.
        try:
            process.kill()
        except OSError:
            pass
        try:
            _windows_job.terminate_job(job)
        except OSError:
            pass
        _close_job_quietly(job)
        # Reap the suspended worker and close its pipes so a failed launch leaks
        # neither a Popen nor open handles. Best-effort: a secondary error here
        # (a broken pipe on a worker that never ran) must not mask the primary
        # launch failure being re-raised.
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        raise
    return _WindowsJobProcessTree(process, job)


def _close_job_quietly(job_handle: int) -> None:
    try:
        _windows_job.close_handle(job_handle)
    except OSError:
        pass


def _launch_process_tree(argv: list[str], env: dict[str, str]) -> _ProcessTree:
    common: dict[str, Any] = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "env": env,
        # Section 7: explicit, though Python defaults close_fds=True. Only the protocol pipes
        # (stdin/stdout) and discarded stderr reach the worker; no other host descriptor leaks in.
        "close_fds": True,
    }
    if _CAN_KILL_PROCESS_GROUP:
        process = subprocess.Popen(argv, start_new_session=True, **common)  # nosec B603
        return _PosixProcessTree(process)
    if _windows_job.available():
        return _launch_windows_job_tree(argv, common)
    process = subprocess.Popen(argv, **common)  # nosec B603
    return _UnmanagedProcessTree(process)


def demo_registry() -> ToolRegistry:
    registry = ToolRegistry()

    def search(arguments: dict[str, Any]) -> list[dict[str, Any]]:
        limit = int(arguments["limit"])
        query = str(arguments["query"])
        return [
            {"id": f"item-{i + 1}", "title": f"Result {i + 1} for {query}", "score": round(1 - i * 0.1, 2)}
            for i in range(limit)
        ]

    def reserve(arguments: dict[str, Any]) -> dict[str, Any]:
        return {"reserved": True, "amount": arguments["amount"], "currency": arguments["currency"]}

    registry.register("catalog.search", search)
    registry.register("payments.reserve", reserve)
    return registry

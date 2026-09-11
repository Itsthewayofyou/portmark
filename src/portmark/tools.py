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

# Environment names the isolated worker is allowed to inherit. This is a
# default-deny allowlist, not parent-minus-a-blocklist: a secret the host holds
# in its own environment (API keys, tokens, DB URLs) never reaches an untrusted
# tool unless the operator names it explicitly via `env=`. PYTHONPATH is required
# for the worker to import portmark and the tool module at all.
_INHERITED_ENV_KEYS = ("PYTHONPATH", "PATH", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT")

# Finding #5: the thread-timeout path cannot cancel a tool, so a timed-out tool leaks a
# running daemon thread. Cap how many thread-path executions may be in flight at once so
# leaked threads cannot accumulate without bound; beyond the cap a tool invocation fails
# closed. Long or side-effecting tools belong on the isolated (hard-killable) path.
DEFAULT_MAX_INFLIGHT_THREADED_TOOLS = 64

# The isolated executor's hard-kill guarantee rests on two things being true
# together: the worker became its own session leader (start_new_session) and the
# platform can signal a whole process group (os.killpg). On Windows both are
# absent -- start_new_session is silently ignored and killpg does not exist -- so
# a kill reaches only the worker, not a grandchild it spawned. We refuse to
# *claim* the guarantee where we cannot keep it: this positive capability, tested
# once here, gates both the side-effecting refusal and the kill itself.
_CAN_KILL_PROCESS_GROUP = hasattr(os, "killpg") and hasattr(os, "getpgid")


class ToolExecutionError(SecurityError):
    pass


class ToolKilledError(ToolExecutionError):
    """An isolated tool was hard-killed at its deadline.

    Distinct from a clean ToolExecutionError because the host cannot know whether
    a side effect already landed before the kill: killing the process group stops
    any *new* effect but does not roll back one already in flight. The host audits
    this as a killed-at-deadline event with effect status unknown.
    """


@dataclass(frozen=True)
class _IsolatedSpec:
    target: str
    env: dict[str, str] = field(default_factory=dict)


class ToolRegistry:
    def __init__(
        self,
        default_timeout: float = 5.0,
        max_output_bytes: int = 65_536,
        max_inflight_threaded: int = DEFAULT_MAX_INFLIGHT_THREADED_TOOLS,
    ) -> None:
        self._tools: dict[str, Tool] = {}
        self._isolated: dict[str, _IsolatedSpec] = {}
        self._timeouts: dict[str, float] = {}
        self._max_output: dict[str, int] = {}
        self._side_effecting: set[str] = set()
        self.default_timeout = default_timeout
        self.max_output_bytes = max_output_bytes
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
    ) -> None:
        """Register a tool that runs in a hard-killable subprocess (EV-002).

        `target` is a `module:function` import path resolved inside the worker,
        not a callable, because a closure cannot be shipped to a fresh process.
        `env` names extra environment variables to pass through; by default the
        worker sees only a minimal allowlist and none of the host's secrets.
        Only an isolated tool may be `side_effecting`: the thread path cannot
        cancel a running tool, so it still refuses side-effecting tools.
        """
        module_name, separator, object_path = target.partition(":")
        if not separator or not module_name or not object_path:
            raise ValueError("register_isolated target must use module:function syntax")
        if side_effecting and not _can_hard_kill_process_tree():
            # Fail closed at startup, not at the first payment: on a platform with no
            # tree-kill primitive the host cannot guarantee the tool and its descendants
            # stop at the deadline, so it must not promise to run a side-effecting one.
            raise SecurityError(
                f"tool {name!r} is side-effecting but this platform cannot hard-kill a worker's "
                "process tree, so the host cannot guarantee it stops at its deadline; refusing "
                "to register it. Non-side-effecting isolated tools are allowed."
            )
        self._isolated[name] = _IsolatedSpec(target=target, env=dict(env or {}))
        self._tools.pop(name, None)
        if timeout is not None:
            self._timeouts[name] = timeout
        if max_output_bytes is not None:
            self._max_output[name] = max_output_bytes
        if side_effecting:
            self._side_effecting.add(name)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(set(self._tools) | set(self._isolated)))

    def invoke(self, permit: Permit, name: str, arguments: dict[str, Any], max_output_bytes: int | None = None) -> Any:
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

        if is_isolated:
            return self._invoke_isolated(self._isolated[name], arguments, timeout, cap)

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

    def _invoke_isolated(self, spec: _IsolatedSpec, arguments: dict[str, Any], timeout: float, cap: int) -> Any:
        request = json.dumps(
            {"target": spec.target, "arguments": arguments, "max_output_bytes": cap}
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


def _can_hard_kill_process_tree() -> bool:
    # Whether this platform can kill a worker AND every descendant as one unit.
    # POSIX: a new session (start_new_session) + os.killpg. Windows: a Job Object with
    # KILL_ON_JOB_CLOSE (_WindowsJobProcessTree). Enforcement reads this, not a
    # scattered platform check; a side-effecting isolated tool is refused only where
    # neither primitive exists.
    return _CAN_KILL_PROCESS_GROUP or _windows_job.available()


def _terminate_posix_process_group(process: subprocess.Popen[bytes]) -> None:
    """Hard-kill the worker and every descendant via its process group.

    The worker is its own session leader (start_new_session), so killing its
    process group reaches grandchildren it spawned. Without this, a tool that
    forks a helper would leave that helper running past the deadline -- and "the
    host can hard-kill it", the whole premise of EV-002, would be false.
    """
    if process.poll() is not None:
        # Already exited; signalling a reaped pid could hit an unrelated reused pid.
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except (ProcessLookupError, OSError):
            pass


class _ProcessTree:
    """A launched isolated-tool worker with a tree-kill contract.

    `terminate_tree()` stops the worker AND every descendant it spawned;
    `kills_tree` states whether this implementation can actually guarantee that.
    The isolated executor talks to this interface instead of scattering platform
    branches through `_invoke_isolated`, so a Windows Job Object implementation
    (`_WindowsJobProcessTree`) can be dropped in without touching the executor.
    """

    kills_tree: bool = False

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process

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
        if self._process.stdout is not None:
            self._process.stdout.close()


class _PosixProcessTree(_ProcessTree):
    kills_tree = True

    def terminate_tree(self) -> None:
        _terminate_posix_process_group(self._process)


class _UnmanagedProcessTree(_ProcessTree):
    # A platform with no tree-kill primitive: kills only the root process, so
    # descendants may outlive it -- which is exactly why `kills_tree` is False and
    # side-effecting isolated tools are refused here. Windows uses this until the Job
    # Object executor lands.
    kills_tree = False

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
    # safety net if terminate_tree was never called.
    kills_tree = True

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

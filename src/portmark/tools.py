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
    def __init__(self, default_timeout: float = 5.0, max_output_bytes: int = 65_536) -> None:
        self._tools: dict[str, Tool] = {}
        self._isolated: dict[str, _IsolatedSpec] = {}
        self._timeouts: dict[str, float] = {}
        self._max_output: dict[str, int] = {}
        self._side_effecting: set[str] = set()
        self.default_timeout = default_timeout
        self.max_output_bytes = max_output_bytes

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
        if side_effecting and not _CAN_KILL_PROCESS_GROUP:
            # Fail closed at startup, not at the first payment: on a platform
            # without process groups the host cannot guarantee the tool stops at
            # its deadline, so it must not promise to run a side-effecting one.
            raise SecurityError(
                f"tool {name!r} is side-effecting but this platform cannot hard-kill a worker's "
                "process group (no os.killpg), so the host cannot guarantee it stops at its "
                "deadline; refusing to register it. Non-side-effecting isolated tools are allowed."
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
        result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

        def run_tool() -> None:
            try:
                result_queue.put((True, tool(arguments)))
            except Exception as error:  # noqa: BLE001 - reported as a failed tool
                result_queue.put((False, error))

        thread = threading.Thread(target=run_tool, daemon=True)
        thread.start()
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
            process = subprocess.Popen(  # nosec B603
                [sys.executable, "-m", "portmark.tool_subprocess_runner"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self._child_env(spec.env),
                start_new_session=True,
            )
        except OSError as error:
            raise ToolExecutionError("could not start isolated tool worker") from error

        hard_cap = cap + _RESPONSE_ENVELOPE_SLACK
        buffer = bytearray()
        overflow = threading.Event()

        def drain() -> None:
            stream = process.stdout
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
                        _terminate_process_group(process)
                        break
            except (OSError, ValueError):
                pass

        reader = threading.Thread(target=drain, daemon=True)
        try:
            if process.stdin is not None:
                try:
                    process.stdin.write(request)
                    process.stdin.close()
                except (BrokenPipeError, OSError):
                    pass
            reader.start()
            timed_out = False
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_process_group(process)
                try:
                    process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    pass
            reader.join(timeout=2.0)
        finally:
            _terminate_process_group(process)
            if process.stdout is not None:
                process.stdout.close()

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


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Hard-kill the worker and any descendants.

    The worker is its own session leader (start_new_session), so killing its
    process group reaches grandchildren it spawned. Without this, a tool that
    forks a helper would leave that helper running past the deadline -- and "the
    host can hard-kill it", the whole premise of EV-002, would be false.
    """
    if process.poll() is not None:
        # Already exited; nothing to kill, and signalling a reaped pid could hit
        # an unrelated process that reused it.
        return
    try:
        if _CAN_KILL_PROCESS_GROUP:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        else:  # pragma: no cover - Windows fallback, CI is Linux
            process.kill()
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except (ProcessLookupError, OSError):
            pass


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

from __future__ import annotations

import json
import os
import queue
import secrets
import signal
import subprocess  # nosec B404
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from . import _windows_job
from .models import Permit
from .security import SecurityError, canonical_json, check_constraints


Tool = Callable[[dict[str, Any]], Any]


@dataclass(frozen=True)
class EffectLedgerAuthority:
    """Private handle returned by ToolRegistry.attach_effect_ledger and held only by AgentHost. It is
    the ONLY way to reach the two effect-ledger operations that must not be public:
      * `arm` mints a one-use launch capability for a `started` effect (`disarm` drops an unconsumed
        one), so knowledge of a deterministic effect_id is not launch authority; and
      * `run_reconcile` executes a side-effecting tool's reconcile target, but only for an effect the
        host has already CLAIMED under an owned lease (Section 7 PR 2b round 2) -- there is no public
        registry method that runs a reconcile target with caller-chosen inputs.
    Bundling these here (instead of public registry methods) is what stops any caller with a registry
    reference from minting a launch or triggering a reconcile-target execution."""
    arm: Callable[[str, str, dict[str, Any]], str]
    disarm: Callable[[str | None], None]
    run_reconcile: Callable[[str, str, dict[str, Any], str], Any]


class IsolationMechanism(Enum):
    """HOW a deployment contains a side-effecting worker's escaped descendants (Section 7 PR 2b).

    The runtime CANNOT contain a hostile tool on its own -- on POSIX the deadline sweep is a
    cooperative process-group signal that a setsid() descendant escapes; a genuine payment or
    booking that already fired cannot be rolled back. Containment is the deployment's job. This
    enum names the mechanism the operator asserts is in place, and the registration gate cross-checks
    it against the platform (an over-claim for a platform that lacks the primitive is refused).
    """

    # The operator runs workers inside a container / VM / seccomp jail / dedicated sandbox that
    # confines any escaped descendant. This is the operator's own affirmation about the deployment,
    # not something the runtime can verify -- valid on ANY platform because it does not rely on a
    # runtime primitive.
    EXTERNAL_CONTAINER = "external_container"
    # The operator relies on the platform's own kill-on-close job for the worker tree. Genuine only
    # where such a primitive exists with NO breakaway -- the Windows Job Object. On POSIX there is no
    # equivalent (only the cooperative process-group signal above), so this mechanism is refused there.
    OS_JOB_OBJECT = "os_job_object"


@dataclass(frozen=True)
class IsolationProfile:
    """An operator's EXPLICIT, non-defaultable acknowledgement of how side-effecting worker processes
    are contained in this deployment (Section 7 PR 2b). Passed once to ToolRegistry(isolation_profile=...)
    -- containment is a property of the shared worker-spawn environment, identical for every isolated
    tool, so it is declared once, not per tool.

    Mirrors the a2a `allow_anonymous=True` idiom: there is NO default that satisfies the registration
    gate; the operator must construct this object with a real mechanism and name who acknowledged it.
    `acknowledged_by` is recorded in the audit trail so an incident responder can see what containment
    was claimed when an effect went `unknown`. This object records a CLAIM; it does not and cannot
    verify that the container is actually in place.
    """

    mechanism: IsolationMechanism
    acknowledged_by: str

    def __post_init__(self) -> None:
        if not isinstance(self.mechanism, IsolationMechanism):
            raise ValueError(
                "IsolationProfile.mechanism must be an IsolationMechanism, not "
                f"{type(self.mechanism).__name__}"
            )
        if not isinstance(self.acknowledged_by, str) or not self.acknowledged_by.strip():
            raise ValueError(
                "IsolationProfile.acknowledged_by must name the operator/team acknowledging the "
                "deployment's containment (a non-empty string); it is recorded in the audit trail."
            )

    def audit_summary(self) -> dict[str, str]:
        """The claim, as recorded on an effect-unknown audit event (Section 7 PR 2b)."""
        return {"mechanism": self.mechanism.value, "acknowledged_by": self.acknowledged_by}


def _profile_contains_on_this_platform(profile: IsolationProfile) -> bool:
    """Whether the operator's declared containment mechanism genuinely contains a worker's escaped
    descendants ON THIS PLATFORM (Section 7 PR 2b, coupled-teeth variant). external_container is the
    operator's own affirmation and is valid anywhere; os_job_object is genuine ONLY where the Windows
    kill-on-close Job Object exists, so on POSIX (cooperative process-group signal only) it is refused
    -- there the operator MUST affirm external containment. Named for what it checks; it proves the
    mechanism is APPROPRIATE for the platform, never that the container is actually running."""
    if profile.mechanism is IsolationMechanism.EXTERNAL_CONTAINER:
        return True
    if profile.mechanism is IsolationMechanism.OS_JOB_OBJECT:
        return _windows_job.available()
    return False


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
        isolation_profile: IsolationProfile | None = None,
    ) -> None:
        # Section 7 PR 2b: the operator's containment acknowledgement for side-effecting tools.
        # None means "not acknowledged" -- registering a side-effecting isolated tool then fails
        # closed. Containment is one shared property of the worker-spawn environment, so it lives
        # on the registry, not per tool (a per-tool profile could make inconsistent claims about
        # one shared fact).
        if isolation_profile is not None and not isinstance(isolation_profile, IsolationProfile):
            raise ValueError("isolation_profile must be an IsolationProfile or None")
        self._isolation_profile = isolation_profile
        self._tools: dict[str, Tool] = {}
        self._isolated: dict[str, _IsolatedSpec] = {}
        self._timeouts: dict[str, float] = {}
        self._max_output: dict[str, int] = {}
        self._side_effecting: set[str] = set()
        # Section 7 PR 2 (round 3, remediation): launching a side-effecting tool requires a one-use,
        # in-memory LAUNCH CAPABILITY that AgentHost arms right before the call and invoke() consumes
        # atomically. Knowledge of a (deterministic, non-secret) effect_id is NOT launch authority.
        #   * ARMING IS NOT A PUBLIC METHOD. attach_effect_ledger() returns a private armer handle (arm /
        #     disarm closures) that only AgentHost holds -- so no caller with a registry reference can
        #     mint a capability, and none can mint a SECOND one for a started effect (round-3-r1 hole:
        #     public arm_effect_launch let a caller mint N capabilities for one started row). Arming
        #     validates against the read-only ledger row (a fabricated effect_id cannot be armed) and
        #     refuses a second outstanding capability for the same effect.
        #   * `_armed` maps a random capability -> (effect_id, tool, canonical_args). invoke() pops it on
        #     an exact (tool, args) match: one-use, non-transferable, non-replayable. After a crash it is
        #     empty, so a durable `started` row alone authorizes nothing.
        # This removes the PUBLIC-API bypass; it is not protection against arbitrary in-process code
        # mutating these private attributes -- that is the deployment sandbox's job per the Section 7
        # contract, and the docs say so rather than overclaiming.
        self._ledger_attached = False
        self._armed: dict[str, tuple[str, str, str]] = {}
        self._arm_lock = threading.Lock()
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
        if side_effecting:
            # Section 7 PR 2b: refuse a side-effecting tool on the thread path AT REGISTRATION, not
            # (as before) only at the first invoke. The thread + queue-timeout path cannot cancel a
            # tool once started, and this path never arms an effect-ledger launch capability -- so a
            # side-effecting tool must use register_isolated (which enforces reconcile + IsolationProfile
            # and runs in a process the host can hard-kill). Registration here let a name into
            # _side_effecting with no reconcile and no profile: the 2b gate bypassed. Fail closed.
            raise SecurityError(
                f"tool {name!r} is side-effecting but register() runs it on the thread-timeout path, "
                "which cannot cancel a running tool and cannot carry an effect ledger; register it with "
                "register_isolated(side_effecting=True, reconcile=..., ...) and an acknowledged "
                "IsolationProfile instead."
            )
        self._tools[name] = tool
        self._isolated.pop(name, None)
        if timeout is not None:
            self._timeouts[name] = timeout
        # A plain (non-side-effecting) register REPLACES any prior registration of this name, so it
        # must also clear a stale side-effecting membership (e.g. re-registering an isolated
        # side-effecting name as a plain thread tool). Fail closed on the invariant, not just add.
        self._side_effecting.discard(name)

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
            if reconcile == target:
                # PR 2b round 2: the reconcile target must be a DISTINCT function from the tool. A
                # reconcile is observational -- it CHECKS whether the effect landed; it must never BE
                # the effect. Registering the effectful tool as its own reconcile target is the exact
                # exploit the auditor ran (a reconcile execution then fires the charge). The runtime
                # cannot verify a reconcile target is genuinely read-only, so it enforces the one thing
                # it can (distinctness) and documents the read-only requirement as an operator contract.
                raise SecurityError(
                    f"reconcile target for {name!r} must be a DISTINCT function from the tool target "
                    f"{target!r}; a reconcile must observe whether the effect landed, never re-run it. "
                    "The runtime cannot verify read-only-ness; keeping them distinct is the contract."
                )
        if side_effecting:
            # Section 7 PR 2b: the MANDATORY side-effecting startup gate. Validate the full contract
            # BEFORE mutating any state, so a refused registration leaves the registry untouched
            # (no half-registered name in _isolated with a stripped _side_effecting membership).
            if not _has_tree_termination_primitive():
                # Fail closed at startup, not at the first payment: on a platform with no
                # tree-kill primitive the host cannot guarantee the tool and its descendants
                # stop at the deadline, so it must not promise to run a side-effecting one.
                raise SecurityError(
                    f"tool {name!r} is side-effecting but this platform cannot hard-kill a worker's "
                    "process tree, so the host cannot guarantee it stops at its deadline; refusing "
                    "to register it. Non-side-effecting isolated tools are allowed."
                )
            if reconcile is None:
                # reconcile is now MANDATORY for a side-effecting tool (optional in 2a): 2a's whole
                # failure -> unknown -> reconcile machinery is dead unless every side-effecting tool
                # declares a reconcile target. Fail closed at startup, not when an effect first hangs.
                raise SecurityError(
                    f"tool {name!r} is side-effecting but has no reconcile target; pass "
                    "reconcile=<module:function> so an effect that fails to a known-unknown state can "
                    "be resolved. (Section 7 PR 2b -- reconcile is mandatory for side-effecting tools.)"
                )
            self._assert_isolation_profile(name)
            # PR 2b round 2: preflight the reconcile target in a worker (import + callable + signature)
            # so a broken reconcile is caught HERE, not when a real effect first becomes `unknown`.
            self._preflight_reconcile_target(name, reconcile, env or {})
        self._isolated[name] = _IsolatedSpec(target=target, env=dict(env or {}), reconcile=reconcile)
        self._tools.pop(name, None)
        if timeout is not None:
            self._timeouts[name] = timeout
        if max_output_bytes is not None:
            self._max_output[name] = max_output_bytes
        # Reconcile membership on EVERY registration, both branches: only adding on True let a
        # re-registration strip reconcile (register_isolated(name, side_effecting=False)) while the
        # name stayed in _side_effecting -- gate passed once, invariant then violated (Section 7 PR 2b).
        if side_effecting:
            self._side_effecting.add(name)
        else:
            self._side_effecting.discard(name)

    def attach_effect_ledger(self, effect_ledger_row: Callable[[str], dict[str, Any] | None]) -> EffectLedgerAuthority:
        """Attach the host's read-only durable-ledger view ONCE and RETURN a private authority handle
        (Section 7 PR 2, round 3 remediation; reconcile authority added in PR 2b round 2). AgentHost
        calls this at construction and keeps the handle; it is the ONLY way to mint a launch capability
        OR execute a reconcile target. Neither is a public registry method -- otherwise any caller
        holding the registry could mint capabilities (including several for one `started` effect) or run
        a reconcile TARGET with caller-chosen (tool, arguments, effect_id), which the auditor showed
        executes an effectful target with no ledger row, no claim, and no launch gate. Set-once: a second
        attach raises, so the validators cannot be swapped for permissive ones. The row lookup and the
        closures are captured here, not stored as reassignable attributes."""
        if self._ledger_attached:
            raise RuntimeError("effect ledger already attached; it is set once and cannot be re-attached")
        self._ledger_attached = True

        def arm(effect_id: str, tool: str, arguments: dict[str, Any]) -> str:
            # Validate against the durable ledger: a fabricated or drifted effect_id has no matching
            # `started` row and cannot be armed. Then refuse a SECOND outstanding capability for the same
            # effect, so even the holder of the armer cannot mint two launches for one started row. The
            # host disarms in a `finally`, so a launch that never consumes frees the slot (no poisoning).
            row = effect_ledger_row(effect_id)
            canonical_args = canonical_json(arguments).decode("utf-8")
            if row is None or row["state"] != "started" or row["tool"] != tool or row["arguments_json"] != canonical_args:
                raise SecurityError(
                    f"cannot arm a launch for effect {effect_id!r}: no `started` ledger row matches this "
                    "(tool, arguments). Knowledge of an effect_id is not launch authority."
                )
            with self._arm_lock:
                if any(existing[0] == effect_id for existing in self._armed.values()):
                    raise SecurityError(
                        f"a launch capability is already outstanding for effect {effect_id!r}; one "
                        "started effect authorizes at most one launch."
                    )
                capability = secrets.token_urlsafe(32)
                self._armed[capability] = (effect_id, tool, canonical_args)
            return capability

        def disarm(capability: str | None) -> None:
            if capability is None:
                return
            with self._arm_lock:
                self._armed.pop(capability, None)

        def run_reconcile(effect_id: str, tool: str, arguments: dict[str, Any], claim_id: str) -> Any:
            # Execute a side-effecting tool's reconcile target -- ONLY for an effect the host has already
            # CLAIMED under its owned lease. Validate against the durable ledger row before running:
            #   * a row exists and is in `reconciling` (the state claim_effect_for_reconcile creates);
            #   * its reconcile_claim_id equals THIS claim_id -- the host's unguessable token_urlsafe(24),
            #     minted only after claim_effect_for_reconcile atomically proved live-lease ownership; and
            #   * the recorded tool and canonical arguments match what the host passed (the STORED args,
            #     not caller-chosen), so a run cannot be retargeted to a different call's inputs.
            # Liveness note: the runner binds to the claim_id, NOT a re-read lease. The lease was proven
            # live atomically by claim_effect_for_reconcile; the registry has no handle on the store's
            # time base (Postgres uses DB time, embedded stores an injected clock), so re-checking expiry
            # here could not be done consistently. The claim_id carries the weight -- it is unguessable
            # and unique per claim, so a stale/foreign holder cannot match a live row. This is why the
            # reconcile authority lives here (private, host-only) and not as a public registry method:
            # that method (removed in PR 2b round 2) ran the target with no row, no claim, no gate.
            row = effect_ledger_row(effect_id)
            canonical_args = canonical_json(arguments).decode("utf-8")
            if (
                row is None
                or row["state"] != "reconciling"
                or row.get("reconcile_claim_id") != claim_id
                or row["tool"] != tool
                or row["arguments_json"] != canonical_args
            ):
                raise SecurityError(
                    f"cannot run a reconcile for effect {effect_id!r}: it must be a `reconciling` row "
                    "owned by this claim whose recorded tool and arguments match. A reconcile target is "
                    "run only through the host's claimed-lease path, never directly via the registry."
                )
            return self._run_reconcile_target(tool, arguments, effect_id)

        return EffectLedgerAuthority(arm=arm, disarm=disarm, run_reconcile=run_reconcile)

    def is_side_effecting(self, name: str) -> bool:
        """Whether the tool is registered side-effecting (the host wraps it in the effect ledger)."""
        return name in self._side_effecting

    @property
    def isolation_profile(self) -> IsolationProfile | None:
        """The operator's containment acknowledgement for side-effecting tools, or None if none was
        given (Section 7 PR 2b). Read-only; set once at construction. AgentHost reads it to record
        the claimed containment on an effect-unknown audit event."""
        return self._isolation_profile

    def _assert_isolation_profile(self, name: str) -> None:
        """Fail closed unless the deployment's IsolationProfile is acknowledged AND its mechanism is
        appropriate for this platform (Section 7 PR 2b). Name-agnostic to the tool's reconcile state,
        so it is reusable before the tool's spec is stored. Proves the containment is CLAIMED and
        platform-appropriate; it cannot prove the container is actually running (only the operator can)."""
        profile = self._isolation_profile
        if profile is None:
            raise SecurityError(
                f"tool {name!r} is side-effecting but no IsolationProfile was acknowledged; the runtime "
                "cannot contain a hostile tool by itself, so the operator must pass "
                "ToolRegistry(isolation_profile=IsolationProfile(...)) to affirm how workers are contained."
            )
        if not _profile_contains_on_this_platform(profile):
            raise SecurityError(
                f"tool {name!r} is side-effecting but the acknowledged IsolationProfile mechanism "
                f"{profile.mechanism.value!r} does not contain workers on this platform; on POSIX the "
                "deadline sweep is only cooperative, so external containment must be affirmed "
                "(IsolationMechanism.EXTERNAL_CONTAINER)."
            )

    def _assert_side_effecting_contract(self, name: str) -> None:
        """Fail closed unless the mandatory side-effecting contract holds for `name` (Section 7 PR 2b):
        a reconcile target is declared AND the IsolationProfile is acknowledged + platform-appropriate.
        Enforced at BOTH registration (startup) and the launch boundary in invoke() -- a startup-only
        check over a mutable set is advisory, not a gate (security.md: compute the enforcement AT the
        gate). Reads stored state, so it runs only after the tool's spec exists (i.e. at invoke time)."""
        if not self.has_reconcile(name):
            raise SecurityError(
                f"tool {name!r} is side-effecting but has no reconcile target; a side-effecting tool "
                "must declare reconcile=<module:function> so an effect that fails to a known-unknown "
                "state can be resolved instead of silently retried or dropped."
            )
        self._assert_isolation_profile(name)

    def is_isolated(self, name: str) -> bool:
        """Whether the tool runs in an isolated worker (the only path that can carry an effect_id)."""
        return name in self._isolated

    def has_reconcile(self, name: str) -> bool:
        """Whether an isolated tool has a reconcile function registered (Section 7 PR 2)."""
        spec = self._isolated.get(name)
        return spec is not None and spec.reconcile is not None

    def _preflight_reconcile_target(self, name: str, reconcile_target: str, env: dict[str, str]) -> None:
        """Spawn a worker to verify a side-effecting tool's reconcile target is importable, callable and
        accepts (arguments, effect_id) -- WITHOUT running it -- at registration (Section 7 PR 2b round 2).
        Registration otherwise validated only module:function SYNTAX, so a nonexistent module, missing
        function, non-callable object or wrong signature was discovered only when a real effect became
        `unknown` and the reconcile then failed, stranding it. Fail closed. The two failure classes are
        DISTINGUISHED in the message: a worker that could not START (a sandbox blocking subprocess spawn)
        is not a bad target -- but the tool itself could not run there either, so registration is still
        refused. This proves the target is DECLARED, importable and shaped correctly; it cannot prove the
        reconcile is semantically correct or read-only (only a deployment test against the real system can)."""
        spec = _IsolatedSpec(target=reconcile_target, env=dict(env))
        try:
            self._invoke_isolated(spec, {}, self.default_timeout, 4096, preflight=True)
        except ToolKilledError as error:
            raise SecurityError(
                f"reconcile preflight for tool {name!r} (target {reconcile_target!r}) did not complete "
                "within the deadline; refusing to register."
            ) from error
        except ToolExecutionError as error:
            # Carries the worker's own reason, which distinguishes a broken TARGET ("reconcile target
            # could not be imported / is not callable / does not accept (arguments, effect_id)") from a
            # preflight worker that COULD NOT START ("could not start isolated tool worker").
            raise SecurityError(
                f"reconcile target {reconcile_target!r} for tool {name!r} failed preflight: {error}. A "
                "side-effecting tool's reconcile target must be importable, callable, and accept "
                "(arguments, effect_id); refusing to register."
            ) from error

    def _run_reconcile_target(self, name: str, arguments: dict[str, Any], effect_id: str) -> Any:
        """Run a tool's registered reconcile function (isolated, with the effect_id) to determine whether
        its external effect landed. PRIVATE (PR 2b round 2): reachable ONLY through the run_reconcile
        closure of the EffectLedgerAuthority, which the host holds and calls only for an effect it has
        already claimed under an owned lease -- there is no public method that runs a reconcile target,
        because one (the old `reconcile()`) let any registry holder execute an effectful target with a
        fabricated effect_id, no ledger row, and no launch gate. NOT an agent-facing tool call, so it
        does not go through the permit/constraint check. Returns the reconcile function's result (by
        contract, a dict like {"landed": bool, "result"?: ...})."""
        spec = self._isolated.get(name)
        if spec is None or spec.reconcile is None:
            raise ToolExecutionError(f"tool {name!r} has no reconcile function registered")
        reconcile_spec = _IsolatedSpec(target=spec.reconcile, env=dict(spec.env))
        timeout = self._timeouts.get(name, self.default_timeout)
        cap = self._max_output.get(name, self.max_output_bytes)
        return self._invoke_isolated(reconcile_spec, arguments, timeout, cap, effect_id=effect_id)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(set(self._tools) | set(self._isolated)))

    def invoke(self, permit: Permit, name: str, arguments: dict[str, Any], max_output_bytes: int | None = None, launch_capability: str | None = None) -> Any:
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

        effect_id: str | None = None
        if name in self._side_effecting:
            # Section 7 PR 2b: RE-ASSERT the side-effecting contract at the launch boundary, not only
            # at registration. A startup-only gate over the mutable _side_effecting set is advisory,
            # not a gate (security.md: compute the enforcement AT the gate) -- so if any path ever left
            # a name side-effecting without a reconcile target or a platform-valid IsolationProfile,
            # the effect fails closed HERE, at the moment of launch, before any external effect fires.
            self._assert_side_effecting_contract(name)
            # Fail closed at the invoke boundary. Launching a side-effecting tool requires a one-use
            # LAUNCH CAPABILITY the host armed (arm_effect_launch) right before this call and bound to
            # THIS (effect_id, tool, canonical arguments). Knowledge of the (deterministic, non-secret)
            # effect_id is NOT launch authority -- so a fabricated id, a capability reused after its one
            # launch, one armed for a different tool, or one armed with different arguments all fail
            # here. The capability is consumed ONLY on an exact match, so a mismatch never burns a valid
            # one. This is the authority the round-2 "is it started?" predicate failed to be.
            if launch_capability is None:
                raise ToolExecutionError(
                    f"tool {name!r} is side-effecting and must run through the effect ledger via AgentHost "
                    "(which arms a one-use launch capability); it cannot be invoked directly without one."
                )
            with self._arm_lock:
                armed = self._armed.get(launch_capability)
                canonical_args = canonical_json(arguments).decode("utf-8")
                if armed is None or armed[1] != name or armed[2] != canonical_args:
                    raise SecurityError(
                        f"launch capability does not authorize this call to {name!r}; a fabricated, "
                        "already-consumed, cross-tool, or argument-mismatched capability cannot launch a "
                        "side-effecting tool. Knowledge of an effect_id is not launch authority."
                    )
                effect_id = armed[0]
                del self._armed[launch_capability]  # one-use: consume on the exact match

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
        self, spec: _IsolatedSpec, arguments: dict[str, Any], timeout: float, cap: int, effect_id: str | None = None,
        preflight: bool = False,
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
        # Section 7 PR 2b round 2: preflight mode imports + type-checks the target WITHOUT running it,
        # so register_isolated can catch a broken reconcile target at startup, not at first `unknown`.
        if preflight:
            payload["preflight"] = True
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

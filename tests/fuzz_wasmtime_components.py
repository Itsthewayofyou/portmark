"""Malformed-component fuzz campaign for the native Wasmtime provider (Section 9 follow-up).

Two arms, both deterministic (seeded) so any finding reproduces from (seed, case index):

* IN-PROCESS arm -- volume. A child process runs every case through
  ``wasmtime_component_runner._execute`` (the exact code the worker runs, under the same hardened
  engine config and store limits, and the same OS memory cap where one is enforceable). It proves
  that malformed input only ever produces a CONTROLLED error -- one of the exception types the
  worker turns into a clean rejection -- and never kills the process. If the child dies (a native
  crash: SIGSEGV, abort, ...), the parent records the exact case and resumes after it.

* END-TO-END arm -- containment. A sample of cases goes through ``NativeWasmtimeComponentProvider``
  and the real worker subprocess. It proves the provider contract: only ``RuntimeError`` or a
  valid decision, inside the deadline, no traceback or native panic text, no crash signal, and no
  worker left running.

A mutated component that still RUNS is not a finding by itself (a flipped byte inside a data
string is still valid Wasm; which code runs is pinned by the signed digest, not by this fuzzer).
It must still yield an outcome the host decoder accepts or rejects cleanly.

Coverage is reported, not assumed: every case is bucketed by the stage where it stopped, and the
run fails if too few cases get past the header -- a corpus that all dies at byte 0 proves nothing.

Usage: python tests/fuzz_wasmtime_components.py [--inproc-cases N] [--e2e-cases N] [--seed S]
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import random
import signal
import subprocess  # nosec B404 - fixed argv only: this interpreter + this script, no shell
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

DEFAULT_SEED = 20260918
MIB = 1024 * 1024
CAPSULE_PATH = ROOT / "capsules" / "research-agent.component.wasm.b64"
# In-process arm: lower fuel than production (1e9) so a looping mutant costs milliseconds; fuel
# exhaustion is itself a controlled trap, so this changes speed, not the property under test.
INPROC_FUEL = 10_000_000
INPROC_CASE_SLOW_SECONDS = 5.0
E2E_DEADLINE_MARGIN_SECONDS = 1.5
COUNT_LIMITS = {"instances": 8, "memories": 2, "tables": 4, "table_elements": 10_000}
# A crash signal from the worker is a finding. SIGKILL is our own deadline/overflow kill.
_OWN_KILL = -getattr(signal, "SIGKILL", 9)
_UNCONTROLLED_MARKERS = ("Traceback (most recent call last)", "panicked at", "RUST_BACKTRACE")


# --------------------------------------------------------------------------- corpus

_STRUCTURED_SEEDS_WAT = {
    # Imports a host function it does not re-export: must fail to LINK against the empty Linker.
    "importing": '(component (import "host" (func $h)) (core module $m) (core instance (instantiate $m)))',
    # Re-exports an imported function as `resume` (the shape of the existing import test).
    # Wasmtime refuses this already at parse time.
    "reexported-import": """(component
      (import "host-resume" (func $r (param "context-json" string) (param "checkpoint-json" string)
        (result string)))
      (export "resume" (func $r)))""",
    # Three memories: over the store's memory-count limit.
    "many-memories": "(component (core module $m (memory 1)) (core instance (instantiate $m))"
                     " (core instance (instantiate $m)) (core instance (instantiate $m)))",
    # `resume` with the wrong signature: calling it with two strings is a type error.
    "wrong-resume-signature": """(component
      (core module $m (func (export "f")))
      (core instance $i (instantiate $m))
      (func $r (canon lift (core func $i "f")))
      (export "resume" (func $r)))""",
    # Start function that never ends: fuel exhaustion.
    "infinite-start": "(component (core module $m (func $s (loop $l (br $l))) (start $s))"
                      " (core instance (instantiate $m)))",
    # Start function that traps.
    "trapping-start": "(component (core module $m (func $s unreachable) (start $s))"
                      " (core instance (instantiate $m)))",
    # Minimum memory far above the per-memory limit.
    "huge-memory": "(component (core module $m (memory 60000)) (core instance (instantiate $m)))",
    # Table far above the table-element limit.
    "huge-table": "(component (core module $m (table 200000 funcref)) (core instance (instantiate $m)))",
    # A core module where a component is expected.
    "core-module": "(module (func (export \"resume\") (result i32) i32.const 0))",
    # Valid component with no `resume` export.
    "no-resume": "(component (core module $m) (core instance (instantiate $m)))",
}


def build_seeds() -> list[tuple[str, bytes]]:
    """The fuzz seeds: the real capsule, a variant returning non-JSON, and the structured seeds."""
    from wasmtime import wat2wasm

    capsule = base64.b64decode(CAPSULE_PATH.read_bytes().strip(), validate=True)
    seeds = [("capsule", capsule)]
    capsule_wat = (ROOT / "capsules" / "research-agent.component.wat").read_text(encoding="utf-8")
    # Same capsule, but its tool-request data segment is not JSON: the outcome decoder must refuse
    # it cleanly. Length is preserved so the resume() pointer arithmetic stays valid.
    marker = '{\\"outcome\\":\\"tool\\"'
    if marker in capsule_wat:
        seeds.append(("capsule-non-json", bytes(wat2wasm(capsule_wat.replace(marker, "X" * len(marker), 1)))))
    for name, wat in _STRUCTURED_SEEDS_WAT.items():
        seeds.append((name, bytes(wat2wasm(wat))))
    return seeds


HEADER_BYTES = 8
# Share of mutations allowed to touch the 8-byte header. The binary-component check refuses a bad
# header before any parser runs, so header damage is cheap to test but proves little; most cases
# keep the header intact so they reach the parser, validator, limits, linker, and guest code.
HEADER_TOUCH_RATE = 0.1


def _mutate(rng: random.Random, data: bytes, other: bytes) -> tuple[str, bytes]:
    buf = bytearray(data)
    if not buf:
        return "empty", b""
    kind = rng.randrange(10)
    # First byte a mutation may touch: past the header, except for a small share of cases.
    low = 0 if (rng.random() < HEADER_TOUCH_RATE or len(buf) <= HEADER_BYTES) else HEADER_BYTES
    other_low = HEADER_BYTES if len(other) > HEADER_BYTES else 0

    def pos(extra: int = 0) -> int:
        return rng.randrange(low, len(buf) + extra)

    if kind == 0:  # flip 1-8 bits
        for _ in range(rng.randint(1, 8)):
            buf[pos()] ^= 1 << rng.randrange(8)
        return "bitflip", bytes(buf)
    if kind == 1:  # boundary byte values
        for _ in range(rng.randint(1, 4)):
            buf[pos()] = rng.choice((0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF))
        return "boundary-byte", bytes(buf)
    if kind == 2:  # truncate
        return "truncate", bytes(buf[: pos()])
    if kind == 3:  # insert random bytes
        at = pos(1)
        return "insert", bytes(buf[:at] + bytes(rng.randrange(256) for _ in range(rng.randint(1, 16))) + buf[at:])
    if kind == 4:  # delete a range
        at = pos()
        return "delete", bytes(buf[:at] + buf[at + rng.randint(1, 16):])
    if kind == 5:  # duplicate a range in place
        at = pos()
        chunk = buf[at: at + rng.randint(1, 32)]
        return "duplicate", bytes(buf[:at] + chunk + buf[at:])
    if kind == 6:  # LEB128 length bomb: a maximal varint where a length/count is likely
        at = pos()
        return "leb-bomb", bytes(buf[:at] + b"\xff\xff\xff\xff\x0f" + buf[at + 1:])
    if kind == 7:  # splice: prefix of this seed + a body suffix of another
        return "splice", bytes(buf[: pos()] + other[rng.randrange(other_low, len(other)):])
    if kind == 8:  # swap two ranges (within the body unless the header is in play)
        if len(buf) - low > 1:
            a, b = sorted(rng.sample(range(low, len(buf) + 1), 2))
            return "swap", bytes(buf[:low] + buf[a:b] + buf[low:a] + buf[b:])
        return "swap", bytes(buf)
    # explicit header damage
    buf[rng.randrange(min(HEADER_BYTES, len(buf)))] ^= 0xFF
    return "header", bytes(buf)


def generate_case(seeds: list[tuple[str, bytes]], seed: int, index: int) -> tuple[str, bytes]:
    """Case `index` is a pure function of (seed, index): any finding reproduces exactly."""
    # Deterministic fuzz corpus generation; not security randomness.
    rng = random.Random(f"{seed}:{index}")  # nosec B311
    if index < len(seeds):  # the seeds themselves come first, unmutated
        name, data = seeds[index]
        return f"seed:{name}", data
    name, data = seeds[rng.randrange(len(seeds))]
    _other_name, other = seeds[rng.randrange(len(seeds))]
    label, mutated = _mutate(rng, data, other)
    for _ in range(rng.choice((0, 0, 1, 2))):  # sometimes stack mutations
        extra, mutated = _mutate(rng, mutated, other)
        label = f"{label}+{extra}"
    return f"{name}/{label}", mutated


# --------------------------------------------------------------------------- stage buckets

# Ordered SPECIFIC -> GENERAL, matched against the FULL error text (Wasmtime puts the real reason on
# its "Caused by:" lines, not the first line). The generic decode rule comes last.
_STAGE_RULES = (
    ("header", ("not a binary component model artifact", "magic header", "unknown binary version",
                "expected a version", "bad magic")),
    ("limits", ("resource limit exceeded", "minimum size", "exceeds table limits", "exceeds memory limits",
                "memory count too high", "table count too high", "instance count too high")),
    ("link", ("not found in the linker", "unknown import", "implementation is missing")),
    ("run", ("all fuel consumed", "wasm trap", "wasm backtrace", "error while executing",
             "beyond end of memory", "realloc return")),
    ("export", ("does not export resume",)),
    ("deadline", ("execution deadline", "capacity exhausted")),
    ("call", ("wrong number of parameters", "expected a", "type mismatch")),
    ("outcome", ("outcome", "json object", "unsupported shape", "unsafe json", "jsondecodeerror")),
    ("decode", ("failed to parse", "unexpected end", "invalid leb", "malformed", "section size mismatch",
                "unknown section", "too large", "out of bounds", "invalid", "utf-8", "utf8", "unsupported")),
)


def stage_of(error_type: str, message: str) -> str:
    if error_type == "JSONDecodeError":
        return "outcome"
    if error_type == "TypeError":
        return "call"
    text = message.lower()
    for stage, needles in _STAGE_RULES:
        if any(needle in text for needle in needles):
            return stage
    return f"other:{error_type}"


# --------------------------------------------------------------------------- in-process arm

def _inproc_worker(seed: int, start: int, stop: int, abort_at: int | None) -> None:
    """Child process: run cases [start, stop) through _execute, one JSON line per case."""
    from portmark.providers import _worker_memory_cap_enforceable
    from portmark.tool_subprocess_runner import _apply_resource_limits
    from portmark.wasmtime_component_runner import _controlled_errors, _execute

    seeds = build_seeds()
    controlled = _controlled_errors()
    if sys.platform != "win32" and _worker_memory_cap_enforceable():
        if _apply_resource_limits({"address_space": 512 * MIB}):
            raise SystemExit("could not apply the worker memory cap in the fuzz child")
    for index in range(start, stop):
        if abort_at is not None and index == abort_at:  # calibration hook: simulate a native crash
            os.abort()
        label, component = generate_case(seeds, seed, index)
        started = time.monotonic()
        record: dict[str, Any] = {"i": index, "label": label}
        try:
            _execute(component, "{}", "{}", max_fuel=INPROC_FUEL, max_memory_bytes=64 * MIB,
                     count_limits=dict(COUNT_LIMITS))
            record.update(outcome="ok", stage="ran")
        except controlled as error:
            first_line = (str(error).strip().splitlines() or [""])[0]
            record.update(outcome="controlled", type=type(error).__name__,
                          stage=stage_of(type(error).__name__, str(error)), msg=first_line[:160])
        except BaseException as error:  # noqa: BLE001 -- the point is to catch the UNcontrolled ones
            record.update(outcome="uncontrolled", type=type(error).__name__, stage="uncontrolled",
                          msg=str(error)[:160])
        record["seconds"] = round(time.monotonic() - started, 4)
        print(json.dumps(record), flush=True)


def run_inproc_arm(cases: int, seed: int = DEFAULT_SEED, abort_at: int | None = None,
                   max_restarts: int = 25) -> dict[str, Any]:
    """Run `cases` cases in child process(es). A child death is recorded and the run resumes."""
    records: list[dict[str, Any]] = []
    findings: list[str] = []
    next_index, restarts = 0, 0
    while next_index < cases:
        argv = [sys.executable, str(Path(__file__).resolve()), "--inproc-worker",
                "--seed", str(seed), "--start", str(next_index), "--stop", str(cases)]
        if abort_at is not None:
            argv += ["--abort-at", str(abort_at)]
        child = subprocess.run(  # nosec B603 - fixed argv: this interpreter + this script
            argv, capture_output=True, text=True, timeout=max(120, cases), check=False,
        )
        seen = [json.loads(line) for line in child.stdout.splitlines() if line.startswith("{")]
        records.extend(seen)
        next_index = (seen[-1]["i"] + 1) if seen else next_index
        if child.returncode != 0 and next_index < cases:
            findings.append(
                f"in-process child died at case {next_index} (seed {seed}) with returncode "
                f"{child.returncode}: {(child.stderr.strip().splitlines() or [''])[-1][:160]}"
            )
            next_index += 1  # skip the crasher and resume
            restarts += 1
            if restarts > max_restarts:
                findings.append(f"in-process arm stopped after {max_restarts} child deaths")
                break
        elif child.returncode != 0:
            findings.append(f"in-process child exited {child.returncode} after the last case")
    for record in records:
        findings.extend(check_inproc_record(record))
    return {"records": records, "findings": findings}


def check_inproc_record(record: dict[str, Any]) -> list[str]:
    """The in-process oracle for one case. Returns findings (empty list = the case is fine)."""
    where = f"case {record.get('i')} [{record.get('label')}]"
    if record.get("outcome") == "uncontrolled":
        return [f"{where}: UNCONTROLLED {record.get('type')}: {record.get('msg')}"]
    if record.get("outcome") not in {"ok", "controlled"}:
        return [f"{where}: unknown outcome {record.get('outcome')!r}"]
    if float(record.get("seconds", 0)) > INPROC_CASE_SLOW_SECONDS:
        return [f"{where}: took {record['seconds']} s in-process (compile blow-up?)"]
    return []


# --------------------------------------------------------------------------- end-to-end arm

def _provider_for(component: bytes, timeout: float):
    from portmark.providers import NativeWasmtimeComponentProvider, _worker_memory_cap_enforceable

    uncapped = not _worker_memory_cap_enforceable()  # macOS: blocked by default; opt out to fuzz
    return NativeWasmtimeComponentProvider(component, timeout=timeout, allow_uncapped_worker=uncapped)


def check_e2e_result(label: str, elapsed: float, timeout: float, error: BaseException | None,
                     decision: Any, run: dict[str, Any] | None,
                     available_tools: tuple[str, ...] = ("catalog.search",)) -> list[str]:
    """The end-to-end oracle for one case. Returns findings (empty list = the case is fine)."""
    findings = []
    if elapsed > timeout + E2E_DEADLINE_MARGIN_SECONDS:
        findings.append(f"{label}: took {elapsed:.2f} s, deadline {timeout} s")
    if error is not None:
        if not isinstance(error, RuntimeError):
            findings.append(f"{label}: provider leaked {type(error).__name__}: {str(error)[:160]}")
        text = str(error)
        for marker in _UNCONTROLLED_MARKERS:
            if marker in text:
                findings.append(f"{label}: uncontrolled failure text ({marker!r}) reached the host")
    elif decision is None or (decision.kind == "tool" and decision.tool not in available_tools):
        findings.append(f"{label}: provider returned an invalid decision {decision!r}")
    if run is not None:
        returncode = run.get("returncode")
        if isinstance(returncode, int) and returncode < 0 and returncode != _OWN_KILL:
            findings.append(f"{label}: worker died from signal {-returncode}")
        if returncode == _OWN_KILL and not (run.get("timed_out") or run.get("overflowed")):
            findings.append(f"{label}: worker SIGKILLed without a deadline/overflow reason")
        if error is not None and not run.get("overflowed") and run.get("stdout"):
            findings.append(f"{label}: a failed decision still wrote stdout")
    return findings


def _leftover_children() -> list[int]:
    """PIDs of our own child processes still alive (Linux /proc). Empty elsewhere."""
    if not sys.platform.startswith("linux"):
        return []
    me, alive = os.getpid(), []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                with open(f"/proc/{entry}/stat", encoding="utf-8") as stat:
                    fields = stat.read().rsplit(")", 1)[1].split()
                if int(fields[1]) == me and fields[0] != "Z":
                    alive.append(int(entry))
            except (OSError, IndexError, ValueError):
                continue
    return alive


def run_e2e_arm(cases: int, seed: int = DEFAULT_SEED, timeout: float = 2.0) -> dict[str, Any]:
    """Run a sample of the corpus (all seeds first, then spread mutants) through the provider."""
    from unittest.mock import patch

    import portmark.providers as providers_module
    from portmark.models import AgentState
    from portmark.projection import provider_view

    seeds = build_seeds()
    view = provider_view(AgentState("fuzz", "fuzz"))
    real_run_bounded = providers_module._run_bounded
    findings: list[str] = []
    unclassified: list[str] = []
    stages: Counter[str] = Counter()
    stride = 7  # spread the mutant sample across the corpus
    indices = list(range(min(cases, len(seeds))))
    indices += [len(seeds) + stride * n for n in range(max(0, cases - len(indices)))]
    for index in indices:
        label, component = generate_case(seeds, seed, index)
        label = f"e2e case {index} [{label}]"
        runs: list[dict[str, Any]] = []

        def spy(*args, **kwargs):
            returncode, stdout, stderr, timed_out, overflowed = real_run_bounded(*args, **kwargs)
            runs.append({"returncode": returncode, "stdout": stdout, "timed_out": timed_out,
                         "overflowed": overflowed})
            return returncode, stdout, stderr, timed_out, overflowed

        error, decision = None, None
        started = time.monotonic()
        try:
            with patch.object(providers_module, "_run_bounded", side_effect=spy):
                decision = _provider_for(component, timeout).decide(view, ("catalog.search",))
            stages["decision"] += 1
        except BaseException as caught:  # noqa: BLE001 -- the oracle classifies every exception
            error = caught
            stage = stage_of(type(caught).__name__, str(caught))
            stages[stage] += 1
            if stage.startswith("other"):
                unclassified.append(f"{label}: {str(caught)[:200]}")
        findings.extend(check_e2e_result(label, time.monotonic() - started, timeout, error, decision,
                                         runs[0] if runs else None))
    leftovers = _leftover_children()
    if leftovers:
        findings.append(f"worker processes still running after the e2e arm: {leftovers}")
    return {"cases": len(indices), "stages": stages, "findings": findings, "unclassified": unclassified}


# --------------------------------------------------------------------------- campaign

def coverage_findings(records: list[dict[str, Any]], min_past_header: float = 0.6) -> list[str]:
    """Fail a corpus that proves little: too few cases past the header, or a stage never reached."""
    if not records:
        return ["coverage: no in-process cases ran"]
    stages = Counter(record.get("stage") for record in records)
    findings = []
    past_header = 1 - stages.get("header", 0) / len(records)
    if past_header < min_past_header:
        findings.append(f"coverage: only {past_header:.0%} of cases got past the header")
    for required in ("ran", "decode", "limits", "link", "run"):
        if stages.get(required, 0) == 0:
            findings.append(f"coverage: no case reached stage {required!r}")
    return findings


def run_campaign(inproc_cases: int, e2e_cases: int, seed: int = DEFAULT_SEED) -> list[str]:
    started = time.monotonic()
    inproc = run_inproc_arm(inproc_cases, seed)
    records = inproc["records"]
    findings = inproc["findings"] + coverage_findings(records)
    e2e = run_e2e_arm(e2e_cases, seed) if e2e_cases else {"cases": 0, "stages": Counter(), "findings": []}
    findings += e2e["findings"]

    stages = Counter(record.get("stage") for record in records)
    distinct = len({record.get("msg") for record in records if record.get("outcome") == "controlled"})
    print(f"[fuzz] seed={seed} platform={sys.platform} in-process cases={len(records)} "
          f"({time.monotonic() - started:.1f}s total)")
    print("[fuzz] in-process stages: " + ", ".join(f"{k}={v}" for k, v in stages.most_common()))
    print(f"[fuzz] distinct controlled error messages: {distinct}")
    print(f"[fuzz] end-to-end cases={e2e['cases']} stages: "
          + ", ".join(f"{k}={v}" for k, v in e2e["stages"].most_common()))
    other = [f"in-process case {r['i']} [{r['label']}]: {r.get('msg')}" for r in records
             if str(r.get("stage", "")).startswith("other")] + e2e.get("unclassified", [])
    for line in other[:10]:
        print(f"[fuzz] unclassified (not a finding; bucketing gap): {line}")
    print(f"[fuzz] findings: {len(findings)}")
    for finding in findings:
        print(f"  FINDING {finding}")
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--inproc-cases", type=int, default=1500)
    parser.add_argument("--e2e-cases", type=int, default=30)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--inproc-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--start", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--stop", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--abort-at", type=int, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inproc_worker:
        _inproc_worker(args.seed, args.start, args.stop, args.abort_at)
        return
    if run_campaign(args.inproc_cases, args.e2e_cases, args.seed):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

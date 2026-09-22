"""EV-013: the remote witness conformance kit (`portmark witness conformance`).

It checks that a deployed witness enforces the chain rules, not only that it answers. It drives a
dedicated conformance host id through a fixed script -- advance, confirm, retry, a restored host, a lost
commit, a clone's discarded receipt, a split or older task head, an older registry, an unenrolled key --
and then reads the state back with a fresh nonce. Every answer must be signed by the PINNED witness key
and bound to its request (the client refuses anything else).

A witness that agrees to everything fails the refusal cases. A witness that answers old state fails the
read-back. A witness that cannot discard a lost commit fails `lost-commit-discarded`, and one that is
not idempotent fails `identical-retry`.

The host id must start with `conformance:`. The kit advances that host's chain, so it must never run
against a real host's id: that host's next save would be refused as forked. It works from whatever state
the witness already holds for the id, with fresh task ids, so it can run again and again.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .remote_witness import (
    FORKED,
    REGISTRY_ROLLED_BACK,
    ROLLED_BACK,
    UNAUTHENTICATED,
    Answer,
    Transport,
    WitnessClient,
    WitnessUnavailable,
)

CONFORMANCE_PREFIX = "conformance:"
ACCEPT = "accept"


@dataclass(frozen=True)
class WitnessCase:
    name: str
    expect: str  # ACCEPT, or the refusal code the witness must answer
    outcome: str  # "accepted", "refused:<code>", or "unavailable"
    passed: bool
    detail: str


@dataclass(frozen=True)
class WitnessConformanceReport:
    host_id: str
    cases: tuple[WitnessCase, ...]

    @property
    def passed(self) -> bool:
        return bool(self.cases) and all(case.passed for case in self.cases)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "pass" if self.passed else "fail",
            "host_id": self.host_id,
            "cases": [
                {"name": case.name, "expect": case.expect, "outcome": case.outcome, "passed": case.passed, "detail": case.detail}
                for case in self.cases
            ],
        }


def _head(sequence: int, head_hash: str) -> dict[str, Any]:
    return {"sequence": sequence, "head_hash": head_hash}


class _Script:
    def __init__(self) -> None:
        self.cases: list[WitnessCase] = []
        self.stopped = False

    def expect(self, name: str, expect: str, call: Any, check: Any = None) -> Answer | None:
        """Run one case. `check(answer)` returns a problem string, or None if the answer is right."""
        if self.stopped:
            self.cases.append(WitnessCase(name, expect, "skipped", False, "an earlier case failed, so the chain is not where this case needs it"))
            return None
        try:
            answer = call()
        except WitnessUnavailable as error:
            self.cases.append(WitnessCase(name, expect, "unavailable", False, str(error)))
            self.stopped = True
            return None
        outcome = "accepted" if answer.kind != "refusal" else f"refused:{answer.code}"
        if expect == ACCEPT:
            problem = None if answer.kind != "refusal" else f"the witness refused: {answer.body.get('message')}"
        else:
            problem = None if answer.code == expect else f"expected a {expect!r} refusal"
        if problem is None and check is not None:
            problem = check(answer)
        self.cases.append(WitnessCase(name, expect, outcome, problem is None, problem or "ok"))
        if problem is not None and expect == ACCEPT:
            self.stopped = True  # the chain did not move as the next cases need
        return answer if problem is None else None


def _equal(label: str, actual: Any, expected: Any) -> str | None:
    return None if actual == expected else f"{label} is {actual!r}, expected {expected!r}"


def run_witness_conformance(
    transport: Transport, witness_public_key: bytes, host_id: str, host_key: Ed25519PrivateKey,
) -> WitnessConformanceReport:
    if not host_id.startswith(CONFORMANCE_PREFIX) or len(host_id) == len(CONFORMANCE_PREFIX):
        raise ValueError(f"the conformance host id must start with {CONFORMANCE_PREFIX!r} (it must never be a real host's id)")
    client = WitnessClient(transport, witness_public_key, host_id, host_key)
    script = _Script()
    run = secrets.token_hex(6)
    task, other_task = f"kit-{run}-a", f"kit-{run}-b"

    start = script.expect("state-read", ACCEPT, lambda: client.state(host_id))
    if start is None:
        return WitnessConformanceReport(host_id, tuple(script.cases))
    state = start.body
    base = state["pending"] or state["confirmed"]
    base_prev = None if base is None else base["receipt_hash"]
    base_seq = 0 if base is None else base["host_seq"]
    registry_version = (state["registry"] or {"version": 0})["version"] + 2
    registry = {"version": registry_version, "digest": f"kit-{run}"}
    floor = state["time_floor"] + 100

    first = script.expect(
        "first-advance", ACCEPT,
        lambda: client.advance(host_id, base_seq + 1, base_prev, {task: _head(1, "h1")}, registry, floor),
        lambda answer: _equal("confirmed", answer.body["confirmed"], state["pending"]),
    )
    first_hash = first.receipt_hash if first is not None else None
    second = script.expect(
        "second-advance-confirms-first", ACCEPT,
        lambda: client.advance(host_id, base_seq + 2, first_hash, {task: _head(2, "h2")}, registry, floor - 50),
        lambda answer: _equal("confirmed", answer.body["confirmed"], {"host_seq": base_seq + 1, "receipt_hash": first_hash}),
    )
    second_hash = second.receipt_hash if second is not None else None
    script.expect(
        "identical-retry", ACCEPT,
        lambda: client.advance(host_id, base_seq + 2, first_hash, {task: _head(2, "h2")}, registry, floor - 50),
        lambda answer: _equal("the retried receipt", answer.receipt_hash, second_hash),
    )
    script.expect(
        "restored-host-refused", ROLLED_BACK,
        lambda: client.advance(host_id, base_seq + 1, base_prev, {other_task: _head(1, "o1")}, registry, floor),
    )
    third = script.expect(
        "lost-commit-discarded", ACCEPT,
        lambda: client.advance(host_id, base_seq + 2, first_hash, {task: _head(2, "h2-retry")}, registry, floor - 80),
        lambda answer: _equal("discarded", answer.body["discarded"], second_hash),
    )
    third_hash = third.receipt_hash if third is not None else None
    script.expect(
        "discarded-receipt-refused", FORKED,
        lambda: client.advance(host_id, base_seq + 3, second_hash, {}, registry, floor),
    )
    script.expect(
        "task-head-split-refused", FORKED,
        lambda: client.advance(host_id, base_seq + 3, third_hash, {task: _head(2, "h2-other")}, registry, floor),
    )
    script.expect(
        "task-head-rollback-refused", ROLLED_BACK,
        lambda: client.advance(host_id, base_seq + 3, third_hash, {task: _head(1, "h1")}, registry, floor),
    )
    script.expect(
        "registry-rollback-refused", REGISTRY_ROLLED_BACK,
        lambda: client.advance(host_id, base_seq + 3, third_hash, {}, {"version": registry_version - 1, "digest": f"kit-{run}"}, floor),
    )
    stranger = WitnessClient(transport, witness_public_key, host_id, Ed25519PrivateKey.generate())
    script.expect(
        "unenrolled-key-refused", UNAUTHENTICATED,
        lambda: stranger.advance(host_id, base_seq + 3, third_hash, {task: _head(3, "h3")}, registry, floor),
    )
    fourth = script.expect(
        "fourth-advance-confirms-the-retry", ACCEPT,
        lambda: client.advance(host_id, base_seq + 3, third_hash, {task: _head(3, "h3")}, registry, floor - 90),
        lambda answer: _equal("confirmed", answer.body["confirmed"], {"host_seq": base_seq + 2, "receipt_hash": third_hash}),
    )
    fourth_hash = fourth.receipt_hash if fourth is not None else None

    def read_back(answer: Answer) -> str | None:
        body = answer.body
        expected = {
            "confirmed": {"host_seq": base_seq + 2, "receipt_hash": third_hash},
            "pending": {"host_seq": base_seq + 3, "receipt_hash": fourth_hash},
            "task": {"task_id": task, "confirmed": _head(2, "h2-retry"), "pending": _head(3, "h3")},
            "registry": registry,
            "time_floor": floor,
        }
        for label, value in expected.items():
            problem = _equal(label, body.get(label), value)
            if problem is not None:
                return problem
        return None

    script.expect("state-reflects-the-chain", ACCEPT, lambda: client.state(host_id, task), read_back)
    return WitnessConformanceReport(host_id, tuple(script.cases))

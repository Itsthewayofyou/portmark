"""Conformance kit for a deployment-supplied external attestation verifier (EV-004, TM-007).

Portmark checks the CLAIMED evidence fields itself (subject, audience, validity window, measurement,
nonce) before it calls the external verifier. Those checks are only as good as the verifier's proof
that the platform quote binds the same values: a verifier that parses the quote but never compares it
with the claims turns every Portmark check into a check of attacker-chosen text.

So the kit does not go through `AttestationPolicy.verify` -- those checks would refuse each bad case
before the verifier runs, and a rubber-stamp verifier would pass. It drives the verifier command
directly, through the same shell-free `ExternalAttestationVerifier` adapter the runtime uses.

The operator supplies one real, known-good verifier request (a fresh quote captured on the target
platform, never sent to the verifier before). Each negative case changes ONE dimension of it: the
claims and the request agree with each other (so Portmark's own checks would pass), but the quote
was issued for the original values. Only the verifier can refuse these.

The order defeats verifiers that remember a quote. One lie goes first, while the quote is new, so a
verifier that trusts the fields it first sees with a quote accepts it and fails. The base comes next
(expect accept), then the other negative cases, then the base again, so a verifier that refuses any
quote it has seen before fails too. A correct verifier answers from the request alone.
The kit cannot cover the evidence `signature`: the adapter never sends it to the verifier.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable

from .models import AttestationEvidence
from .security import ExternalAttestationVerifierProtocol, SecurityError

# A value no real host, relying party, measurement or nonce uses. Concrete on purpose: "*" is a
# legal audience wildcard, so mutating the audience to it would flag a correct verifier.
_OTHER = "portmark-conformance:other"
_GARBAGE = "portmark-conformance-not-a-quote"
_STRING_FIELDS = ("verifier", "subject", "audience", "measurement", "nonce", "quote", "signature_key_id", "signature")


def _other(*current: Any) -> str:
    """A concrete value that differs from every current one, so a case can never be a no-op."""
    candidate = _OTHER
    while candidate in current:
        candidate += "-x"
    return candidate


@dataclass(frozen=True)
class ConformanceCase:
    name: str
    expect: str  # "accept" or "reject"
    outcome: str  # "accepted" or "rejected"
    detail: str

    @property
    def passed(self) -> bool:
        return (self.expect == "accept") == (self.outcome == "accepted")


@dataclass(frozen=True)
class ConformanceReport:
    cases: tuple[ConformanceCase, ...]

    @property
    def passed(self) -> bool:
        return all(case.passed for case in self.cases)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "pass" if self.passed else "fail",
            "cases": [
                {"name": case.name, "expect": case.expect, "outcome": case.outcome, "passed": case.passed, "detail": case.detail}
                for case in self.cases
            ],
        }


def load_base_request(value: Any) -> dict[str, Any]:
    """Validate the operator's known-good request. Raise ValueError when it cannot be a clean base.

    Every negative case changes one dimension of this base. If the base is already inconsistent (its
    claims disagree with its own request), a case can be refused for the wrong reason and pass.
    """
    if not isinstance(value, dict):
        raise ValueError("the evidence file must hold a JSON object in the verifier request shape")
    unknown = set(value) - {"evidence", "expected_subject", "relying_party", "expected_nonce", "now"}
    if unknown:
        raise ValueError(f"the evidence file has unknown request keys: {sorted(unknown)}")
    raw = value.get("evidence")
    if not isinstance(raw, dict):
        raise ValueError("the evidence file must carry an 'evidence' object")
    try:
        evidence = AttestationEvidence(**raw)
    except TypeError as error:
        raise ValueError(f"the evidence object has an invalid shape: {error}") from error
    for name in _STRING_FIELDS:
        if not isinstance(getattr(evidence, name), str):
            raise ValueError(f"evidence.{name} must be a string")
    for name in ("issued_at", "expires_at"):
        field_value = getattr(evidence, name)
        if isinstance(field_value, bool) or not isinstance(field_value, int):
            raise ValueError(f"evidence.{name} must be an integer (epoch seconds)")
    if not isinstance(evidence.claims, dict):
        raise ValueError("evidence.claims must be an object")
    subject, relying_party = value.get("expected_subject"), value.get("relying_party")
    nonce, now = value.get("expected_nonce"), value.get("now")
    if not isinstance(subject, str) or not subject or not isinstance(relying_party, str) or not relying_party:
        raise ValueError("expected_subject and relying_party must be non-empty strings")
    if nonce is not None and not isinstance(nonce, str):
        raise ValueError("expected_nonce must be a string or null")
    if isinstance(now, bool) or not isinstance(now, int):
        raise ValueError("now must be an integer (epoch seconds)")
    if len(evidence.quote) < 2:
        # A real quote is far longer; two characters is the least that truncation can shorten.
        raise ValueError("the evidence must carry a platform quote")
    if evidence.subject != subject:
        raise ValueError("the base evidence subject must equal expected_subject")
    if evidence.audience not in {relying_party, "*"}:
        raise ValueError("the base evidence audience must equal relying_party (or '*')")
    if not evidence.issued_at <= now < evidence.expires_at:
        raise ValueError("now must fall inside the base evidence validity window")
    if (nonce or "") != evidence.nonce:
        raise ValueError("the base evidence nonce must equal expected_nonce")
    return {"evidence": evidence, "expected_subject": subject, "relying_party": relying_party, "expected_nonce": nonce, "now": now}


def _wrong_subject(request: dict[str, Any]) -> None:
    value = _other(request["evidence"]["subject"])
    request["evidence"]["subject"] = value
    request["expected_subject"] = value


def _wrong_audience(request: dict[str, Any]) -> None:
    value = _other(request["evidence"]["audience"], request["relying_party"])
    request["evidence"]["audience"] = value
    request["relying_party"] = value


def _wrong_measurement(request: dict[str, Any]) -> None:
    request["evidence"]["measurement"] = _other(request["evidence"]["measurement"])


def _wrong_nonce(request: dict[str, Any]) -> None:
    value = _other(request["evidence"]["nonce"])
    request["evidence"]["nonce"] = value
    request["expected_nonce"] = value


def _stale(request: dict[str, Any]) -> None:
    # Replay the quote after its window has closed, with the claimed window moved to cover the new
    # time. Portmark checks only the claimed window, so the verifier must bind it to the quote.
    evidence = request["evidence"]
    shift = (evidence["expires_at"] - evidence["issued_at"]) + 86_400
    evidence["issued_at"] += shift
    evidence["expires_at"] += shift
    request["now"] += shift


def _corrupt_quote(request: dict[str, Any]) -> None:
    quote = request["evidence"]["quote"]
    middle = len(quote) // 2
    request["evidence"]["quote"] = quote[:middle] + ("B" if quote[middle] == "A" else "A") + quote[middle + 1:]


def _truncated_quote(request: dict[str, Any]) -> None:
    quote = request["evidence"]["quote"]
    request["evidence"]["quote"] = quote[: len(quote) // 2]


def _garbage_quote(request: dict[str, Any]) -> None:
    request["evidence"]["quote"] = _GARBAGE if request["evidence"]["quote"] != _GARBAGE else _GARBAGE + "-x"


# The negative case sent first, before the verifier has seen the base quote (see run_conformance).
LEADING_CASE = "wrong-subject-first"

# Every negative case, in report order. Each changes one dimension of the known-good base.
NEGATIVE_CASES: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
    ("wrong-subject", _wrong_subject),
    ("wrong-audience", _wrong_audience),
    ("wrong-measurement", _wrong_measurement),
    ("wrong-nonce", _wrong_nonce),
    ("stale", _stale),
    ("malformed-quote-corrupted", _corrupt_quote),
    ("malformed-quote-truncated", _truncated_quote),
    ("malformed-quote-garbage", _garbage_quote),
)


def _run_case(verifier: ExternalAttestationVerifierProtocol, name: str, expect: str, request: dict[str, Any]) -> ConformanceCase:
    try:
        verifier.verify(
            AttestationEvidence(**request["evidence"]),
            request["expected_subject"],
            request["relying_party"],
            request["expected_nonce"],
            request["now"],
        )
    except SecurityError as error:
        return ConformanceCase(name, expect, "rejected", str(error))
    return ConformanceCase(name, expect, "accepted", "")


def _mutated(plain: dict[str, Any], name: str, mutate: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    request = copy.deepcopy(plain)
    mutate(request)
    if request == plain:
        # A case that changes nothing sends the known-good request and "fails" a correct verifier.
        raise RuntimeError(f"conformance case {name} does not change the base request")
    return request


def run_conformance(verifier: ExternalAttestationVerifierProtocol, base: dict[str, Any]) -> ConformanceReport:
    """Send the known-good base and every negative case to `verifier`; report accept or reject per case.

    `base` is the result of `load_base_request`. The verifier contract has no reason channel, so the
    kit asserts accept or reject only.
    """
    plain = dict(base, evidence=base["evidence"].unsigned_dict())
    cases = []
    # A LIE comes first, while the base quote is still new to the verifier. A verifier that trusts the
    # fields it first sees with a quote (a first-use association cache) and then refuses any other
    # fields would otherwise learn the truth from `valid` and refuse every later lie without comparing
    # a field with the quote. Sent first, the lie is what it learns, so it accepts it and fails here.
    # A correct verifier answers from the request alone, so the order does not change its answers.
    for name, mutate in ((LEADING_CASE, _wrong_subject), *NEGATIVE_CASES):
        if name == LEADING_CASE:
            cases.append(_run_case(verifier, name, "reject", _mutated(plain, name, mutate)))
            cases.append(_run_case(verifier, "valid", "accept", copy.deepcopy(plain)))
        else:
            cases.append(_run_case(verifier, name, "reject", _mutated(plain, name, mutate)))
    # Every negative case reuses the base quote. A verifier that refuses a quote it has seen before
    # (a replay cache) refuses them all as replays, whatever they claim, and would pass while it
    # compares no field. So the base must be accepted again at the end: the same request must get the
    # same answer. Replay protection is Portmark's job (permit and challenge nonces), not the verifier's.
    cases.append(_run_case(verifier, "valid-repeat", "accept", copy.deepcopy(plain)))
    return ConformanceReport(tuple(cases))

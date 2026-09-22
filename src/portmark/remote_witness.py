"""EV-013: the remote witness protocol -- signed requests and answers, the per-host chain rules, and a client.

Why a chain. The local audit floor (witness.py) catches a restored DATABASE, because the floor file
outside it remembers more. It cannot catch a restore of the database AND the floor together, or two
clones of the pair: each copy is internally consistent. A remote witness on another machine keeps, per
host, a hash chain of every advance the host made. Each advance names the receipt of the one before it
(`prev`), so a restored host names an OLD receipt and is refused (`rolled-back`), and two clones that
share a receipt are told apart at the latest on the second one's next commit (`forked`).

Pending, then confirmed. The host asks the witness to advance BEFORE its database commit (as the local
floor does). The witness keeps that newest advance as PENDING. The host's next request either confirms it
(`prev` = the pending receipt: the commit happened) or discards it (`prev` = the confirmed receipt before
it: the commit did not happen, for example a timeout rolled the save back). So a lost answer never wedges a
task. The cost, documented: a restore to exactly the last confirmed state loses at most ONE unconfirmed
commit without detection.

Trust roots outside the host. The witness signs every answer with its OWN Ed25519 key, which the host
pins. The host signs every request with a key the witness has enrolled. A rebaseline (the remote side of
`floor-reset`) needs an OPERATOR key the host does not hold, so a compromised host cannot erase its history.

Not closed by this protocol (documented in DEPLOYMENT.md): a compromised host can still send valid
advances (the witness orders history, it does not judge it); the witness is a dependency of every write;
the reference server is append-only at the application level, not WORM storage.

Every signature is Ed25519 over a domain-separated canonical JSON body:
    request:  b"portmark.witness.request.v1\\n" + canonical_json(body)
    answer:   b"portmark.witness.answer.v1\\n"  + canonical_json(body)
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import secrets
import socket
import ssl
import stat
import threading
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .json_guard import StrictJSONError, strict_json_loads
from .security import _b64url_decode, _b64url_encode, canonical_json
from .witness import FORKED, ROLLED_BACK, FloorError

REQUEST_DOMAIN = b"portmark.witness.request.v1\n"
ANSWER_DOMAIN = b"portmark.witness.answer.v1\n"

ADVANCE_FORMAT = "portmark.witness.advance.v1"
STATE_FORMAT = "portmark.witness.state-request.v1"
REBASELINE_FORMAT = "portmark.witness.rebaseline.v1"
ANSWER_FORMAT = "portmark.witness.answer.v1"

ADVANCE_PATH = "/v1/advance"
STATE_PATH = "/v1/state"
REBASELINE_PATH = "/v1/rebaseline"

MAX_REQUEST_BYTES = 1024 * 1024
MAX_HEADS = 10_000
MAX_ID_LENGTH = 512
DEFAULT_TIMEOUT_SECONDS = 2.0
# At most this many witness calls in flight per transport. A slot is freed only when its worker thread
# really exits: a worker blocked where no socket exists yet (a stalled DNS lookup) cannot be aborted,
# so without the cap every timed-out save would leave one more thread behind.
MAX_OUTSTANDING_CALLS = 4

# Refusal codes (the witness answers these, signed). ROLLED_BACK and FORKED are the audit-floor codes.
SEQUENCE_MISMATCH = "sequence-mismatch"
REGISTRY_ROLLED_BACK = "registry-rolled-back"
REGISTRY_FORKED = "registry-forked"
REGISTRY_MISSING = "registry-missing"
STALE_REBASELINE = "stale-rebaseline"
UNAUTHENTICATED = "unauthenticated"
WRONG_WITNESS = "wrong-witness"
MALFORMED = "malformed"
RATE_LIMITED = "rate-limited"
TOO_LARGE = "too-large"
NOT_FOUND = "not-found"

WITNESS_UNAVAILABLE = "witness-unavailable"


class WitnessProtocolError(ValueError):
    """A request the witness refuses before the chain rules run. `code` is one of the refusal codes."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class WitnessUnavailable(FloorError):
    """The witness did not give a usable answer: no connection, a timeout, a bad or unsigned answer, or
    an answer that does not match the request. The caller fails closed (EV-013 owner decision F1)."""

    def __init__(self, message: str) -> None:
        super().__init__(WITNESS_UNAVAILABLE, message)


# -- keys ------------------------------------------------------------------------------------------------

def public_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def key_id_for(public_key: bytes) -> str:
    """A stable name for an Ed25519 public key: `ed25519:` + the first 32 hex digits of its SHA-256."""
    return "ed25519:" + hashlib.sha256(public_key).hexdigest()[:32]


def decode_public_key(value: str) -> bytes:
    try:
        raw = _b64url_decode(value)
    except ValueError as error:
        raise ValueError(f"not a base64url Ed25519 public key: {error}") from error
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 raw bytes")
    Ed25519PublicKey.from_public_bytes(raw)
    return raw


def load_private_key_file(path: str) -> Ed25519PrivateKey:
    """A 32-byte Ed25519 private key, base64url, in a file only its owner can read (chmod 600)."""
    try:
        mode = os.stat(path).st_mode
        if os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError(f"key file {path} must not be readable by group or others (chmod 600)")
        with open(path, encoding="utf-8") as handle:
            text = handle.read().strip()
    except OSError as error:
        raise ValueError(f"key file {path} cannot be read: {error}") from error
    try:
        raw = _b64url_decode(text)
    except ValueError as error:
        raise ValueError(f"key file {path} is not base64url: {error}") from error
    if len(raw) != 32:
        raise ValueError(f"key file {path} must hold a 32-byte Ed25519 private key")
    return Ed25519PrivateKey.from_private_bytes(raw)


def generate_key_file(path: str) -> bytes:
    """Write a new Ed25519 private key (mode 600, never overwrites) and return its public key."""
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat

    private_key = Ed25519PrivateKey.generate()
    raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(_b64url_encode(raw) + "\n")
    return public_key_bytes(private_key)


# -- signing ---------------------------------------------------------------------------------------------

def digest(body: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(body)).hexdigest()


def sign_request(private_key: Ed25519PrivateKey, signer: str, body: dict[str, Any]) -> dict[str, Any]:
    return {"body": body, "signer": signer, "signature": _b64url_encode(private_key.sign(REQUEST_DOMAIN + canonical_json(body)))}


def open_request(raw: bytes, public_key_for: Callable[[str, str], bytes | None]) -> tuple[str, dict[str, Any]]:
    """Parse and authenticate a request envelope. `public_key_for(format, signer)` names the enrolled key
    for that signer in the role the format needs, or None. Returns (signer, body)."""
    try:
        envelope = strict_json_loads(raw, max_bytes=MAX_REQUEST_BYTES)
    except (StrictJSONError, ValueError, UnicodeDecodeError) as error:
        raise WitnessProtocolError(MALFORMED, f"the request is not valid JSON: {error}") from error
    if not isinstance(envelope, dict) or set(envelope) != {"body", "signer", "signature"}:
        raise WitnessProtocolError(MALFORMED, "the request envelope has an unexpected shape")
    body, signer, signature = envelope["body"], envelope["signer"], envelope["signature"]
    if not isinstance(body, dict) or not _is_id(signer) or not isinstance(signature, str):
        raise WitnessProtocolError(MALFORMED, "the request envelope has an unexpected shape")
    public_key = public_key_for(str(body.get("format")), signer)
    if public_key is None:
        raise WitnessProtocolError(UNAUTHENTICATED, f"{signer!r} is not enrolled for this request")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(_b64url_decode(signature), REQUEST_DOMAIN + canonical_json(body))
    except (InvalidSignature, ValueError) as error:
        raise WitnessProtocolError(UNAUTHENTICATED, "the request signature does not verify") from error
    return signer, body


def sign_answer(private_key: Ed25519PrivateKey, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "format": ANSWER_FORMAT,
        "body": body,
        "key_id": key_id_for(public_key_bytes(private_key)),
        "signature": _b64url_encode(private_key.sign(ANSWER_DOMAIN + canonical_json(body))),
    }


def open_answer(document: Any, witness_public_key: bytes) -> dict[str, Any]:
    """Verify a witness answer against the PINNED witness key. Raises WitnessUnavailable."""
    if not isinstance(document, dict) or set(document) != {"format", "body", "key_id", "signature"}:
        raise WitnessUnavailable("the witness answer has an unexpected shape")
    if document["format"] != ANSWER_FORMAT or not isinstance(document["body"], dict) or not isinstance(document["signature"], str):
        raise WitnessUnavailable("the witness answer has an unexpected shape")
    if document["key_id"] != key_id_for(witness_public_key):
        raise WitnessUnavailable("the witness answer is signed by a key other than the pinned witness key")
    try:
        Ed25519PublicKey.from_public_bytes(witness_public_key).verify(
            _b64url_decode(document["signature"]), ANSWER_DOMAIN + canonical_json(document["body"])
        )
    except (InvalidSignature, ValueError) as error:
        raise WitnessUnavailable("the witness answer signature does not verify") from error
    return document["body"]


# -- request bodies --------------------------------------------------------------------------------------

def _is_id(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_ID_LENGTH


def _is_int(value: Any, minimum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _check_heads(heads: Any) -> None:
    if not isinstance(heads, dict) or len(heads) > MAX_HEADS:
        raise WitnessProtocolError(MALFORMED, f"heads must be an object of at most {MAX_HEADS} tasks")
    for task_id, head in heads.items():
        if (
            not _is_id(task_id) or not isinstance(head, dict) or set(head) != {"sequence", "head_hash"}
            or not _is_int(head["sequence"], 1) or not _is_id(head["head_hash"])
        ):
            raise WitnessProtocolError(MALFORMED, f"head for task {task_id!r} is malformed")


def _check_registry(registry: Any) -> None:
    if registry is not None and (
        not isinstance(registry, dict) or set(registry) != {"version", "digest"}
        or not _is_int(registry["version"], 1) or not isinstance(registry["digest"], str)
    ):
        raise WitnessProtocolError(MALFORMED, "registry must be null or {version, digest}")


_BODY_FIELDS = {
    ADVANCE_FORMAT: {"format", "witness_key_id", "host_id", "host_seq", "prev", "heads", "registry", "time_floor"},
    STATE_FORMAT: {"format", "witness_key_id", "host_id", "nonce", "task_id"},
    REBASELINE_FORMAT: {"format", "witness_key_id", "host_id", "expected_last", "nonce", "reason", "heads", "registry", "time_floor"},
}


def check_body(body: dict[str, Any], witness_key_id: str) -> None:
    """Validate a request body's exact shape and that it is addressed to THIS witness."""
    fields = _BODY_FIELDS.get(body.get("format"))  # type: ignore[arg-type]
    if fields is None or set(body) != fields:
        raise WitnessProtocolError(MALFORMED, "unknown request format or unexpected fields")
    if body["witness_key_id"] != witness_key_id:
        raise WitnessProtocolError(WRONG_WITNESS, "the request is addressed to another witness")
    if not _is_id(body["host_id"]):
        raise WitnessProtocolError(MALFORMED, "host_id is malformed")
    if body["format"] == ADVANCE_FORMAT:
        if not _is_int(body["host_seq"], 1) or not (body["prev"] is None or _is_hash(body["prev"])):
            raise WitnessProtocolError(MALFORMED, "host_seq or prev is malformed")
        _check_heads(body["heads"])
        _check_registry(body["registry"])
        if not _is_int(body["time_floor"], 0):
            raise WitnessProtocolError(MALFORMED, "time_floor is malformed")
    elif body["format"] == STATE_FORMAT:
        if not (isinstance(body["nonce"], str) and 16 <= len(body["nonce"]) <= 128):
            raise WitnessProtocolError(MALFORMED, "nonce must be 16 to 128 characters")
        if body["task_id"] is not None and not _is_id(body["task_id"]):
            raise WitnessProtocolError(MALFORMED, "task_id is malformed")
    else:
        if not (body["expected_last"] is None or _is_hash(body["expected_last"])):
            raise WitnessProtocolError(MALFORMED, "expected_last is malformed")
        if not (isinstance(body["nonce"], str) and 16 <= len(body["nonce"]) <= 128):
            raise WitnessProtocolError(MALFORMED, "nonce must be 16 to 128 characters")
        if not isinstance(body["reason"], str) or not body["reason"].strip() or len(body["reason"]) > 2000:
            raise WitnessProtocolError(MALFORMED, "a rebaseline needs a reason")
        _check_heads(body["heads"])
        _check_registry(body["registry"])
        if not _is_int(body["time_floor"], 0):
            raise WitnessProtocolError(MALFORMED, "time_floor is malformed")


# -- the chain rules (pure) ------------------------------------------------------------------------------

@dataclass(frozen=True)
class Pending:
    host_seq: int
    receipt_hash: str
    request_sha256: str
    heads: dict[str, dict[str, Any]]
    registry: dict[str, Any] | None
    time_floor: int
    answer: dict[str, Any]  # the signed receipt, returned again for an identical retry


@dataclass(frozen=True)
class HostState:
    """What the witness remembers for one host. `confirmed_*` is the newest advance the host has built
    on; `pending` is the newest advance, not yet built on. Task heads are kept apart (per task)."""

    host_id: str
    epoch: int = 1
    confirmed_seq: int = 0
    confirmed_hash: str | None = None
    pending: Pending | None = None
    registry: dict[str, Any] | None = None
    time_floor: int = 0

    @property
    def last_hash(self) -> str | None:
        return self.pending.receipt_hash if self.pending is not None else self.confirmed_hash

    @property
    def last_seq(self) -> int:
        return self.pending.host_seq if self.pending is not None else self.confirmed_seq


@dataclass(frozen=True)
class KnownEntry:
    """A receipt this witness issued to the host: its sequence, epoch, and whether it was discarded."""

    host_seq: int
    epoch: int
    discarded: bool


@dataclass(frozen=True)
class Decision:
    outcome: str  # "accept", "replay", or "refuse"
    code: str | None = None
    message: str = ""
    confirm: Pending | None = None
    discard: Pending | None = None


def _higher_registry(first: dict[str, Any] | None, second: dict[str, Any] | None) -> dict[str, Any] | None:
    if first is None:
        return second
    if second is None:
        return first
    return second if second["version"] > first["version"] else first


def _classify_prev(state: HostState, prev: str | None, known: Callable[[str], KnownEntry | None]) -> Decision:
    if prev is None:
        return Decision("refuse", ROLLED_BACK, "the host names no earlier receipt, but this witness holds a chain for it: "
                        "the host database is OLDER than the witness (restored)")
    entry = known(prev)
    if entry is None:
        return Decision("refuse", FORKED, "the host builds on a receipt this witness never issued to it (forked)")
    if entry.discarded:
        return Decision("refuse", FORKED, "the host builds on an advance that was discarded because another copy of the "
                        "host advanced first: two copies of this host are running (forked or cloned)")
    return Decision("refuse", ROLLED_BACK, f"the host builds on receipt {entry.host_seq} (epoch {entry.epoch}), OLDER than "
                    f"the witnessed receipt {state.confirmed_seq} (epoch {state.epoch}): the host was restored or cloned")


def decide_advance(
    state: HostState,
    body: dict[str, Any],
    request_sha256: str,
    task_head: Callable[[str], tuple[int, str] | None],
    known: Callable[[str], KnownEntry | None],
) -> Decision:
    """The chain rules for one advance. `task_head(task_id)` is the CONFIRMED (sequence, head_hash);
    `known(receipt_hash)` looks up a receipt this witness issued to THIS host."""
    pending = state.pending
    if pending is not None and request_sha256 == pending.request_sha256:
        return Decision("replay")  # the same request again (a lost answer): the same receipt
    prev = body["prev"]
    confirm = discard = None
    if pending is not None and prev == pending.receipt_hash:
        confirm, base_seq = pending, pending.host_seq
    elif prev == state.confirmed_hash:
        discard, base_seq = pending, state.confirmed_seq
    else:
        return _classify_prev(state, prev, known)
    if body["host_seq"] != base_seq + 1:
        return Decision("refuse", SEQUENCE_MISMATCH, f"host_seq must be {base_seq + 1} after that receipt, not {body['host_seq']}")
    for task_id, head in body["heads"].items():
        if confirm is not None and task_id in confirm.heads:
            witnessed = (confirm.heads[task_id]["sequence"], confirm.heads[task_id]["head_hash"])
        else:
            witnessed = task_head(task_id)
        if witnessed is None:
            continue
        if head["sequence"] < witnessed[0]:
            return Decision("refuse", ROLLED_BACK, f"task {task_id!r}: sequence {head['sequence']} is OLDER than the witnessed {witnessed[0]}")
        if head["sequence"] == witnessed[0] and head["head_hash"] != witnessed[1]:
            return Decision("refuse", FORKED, f"task {task_id!r}: a different head for the witnessed sequence {witnessed[0]}")
    registry = _higher_registry(state.registry, confirm.registry if confirm is not None else None)
    if registry is not None:
        offered = body["registry"]
        if offered is None:
            return Decision("refuse", REGISTRY_MISSING, "the witness records a trust registry, but the host sent none")
        if offered["version"] < registry["version"]:
            return Decision("refuse", REGISTRY_ROLLED_BACK, "the trust registry is OLDER than the witnessed version")
        if offered["version"] == registry["version"] and offered["digest"] != registry["digest"]:
            return Decision("refuse", REGISTRY_FORKED, "the trust registry has the witnessed version but different content")
    return Decision("accept", confirm=confirm, discard=discard)


def receipt_body(state: HostState, body: dict[str, Any], request_sha256: str, decision: Decision, witness_key_id: str, at: int) -> dict[str, Any]:
    return {
        "kind": "receipt",
        "host_id": state.host_id,
        "epoch": state.epoch,
        "host_seq": body["host_seq"],
        "prev": body["prev"],
        "request_sha256": request_sha256,
        "witness_key_id": witness_key_id,
        "accepted_at": at,
        "confirmed": None if decision.confirm is None else {"host_seq": decision.confirm.host_seq, "receipt_hash": decision.confirm.receipt_hash},
        "discarded": None if decision.discard is None else decision.discard.receipt_hash,
    }


def apply_advance(state: HostState, body: dict[str, Any], request_sha256: str, decision: Decision, answer: dict[str, Any]) -> HostState:
    """The state after an accepted advance. The caller also writes `decision.confirm.heads` as confirmed."""
    confirm = decision.confirm
    if confirm is not None:
        state = replace(
            state,
            confirmed_seq=confirm.host_seq,
            confirmed_hash=confirm.receipt_hash,
            registry=_higher_registry(state.registry, confirm.registry),
            time_floor=max(state.time_floor, confirm.time_floor),
        )
    pending = Pending(
        host_seq=body["host_seq"],
        receipt_hash=digest(answer["body"]),
        request_sha256=request_sha256,
        heads=body["heads"],
        registry=body["registry"],
        time_floor=body["time_floor"],
        answer=answer,
    )
    return replace(state, pending=pending)


def decide_rebaseline(state: HostState, body: dict[str, Any]) -> Decision:
    if body["expected_last"] != state.last_hash:
        return Decision("refuse", STALE_REBASELINE, "the rebaseline names a last receipt that is not the witness's newest one")
    return Decision("accept", discard=state.pending)


def rebaseline_body(state: HostState, body: dict[str, Any], request_sha256: str, operator: str, witness_key_id: str, at: int) -> dict[str, Any]:
    return {
        "kind": "rebaseline",
        "host_id": state.host_id,
        "epoch": state.epoch + 1,
        "host_seq": state.last_seq + 1,
        "prev": state.last_hash,
        "request_sha256": request_sha256,
        "witness_key_id": witness_key_id,
        "accepted_at": at,
        "operator": operator,
        "reason": body["reason"],
    }


def apply_rebaseline(state: HostState, body: dict[str, Any], answer: dict[str, Any]) -> HostState:
    """A new epoch built on the host's CURRENT database: its heads replace the witnessed ones, and the
    time floor and registry are set (they may go down: this is operator recovery)."""
    return HostState(
        host_id=state.host_id,
        epoch=answer["body"]["epoch"],
        confirmed_seq=answer["body"]["host_seq"],
        confirmed_hash=digest(answer["body"]),
        pending=None,
        registry=body["registry"],
        time_floor=body["time_floor"],
    )


def state_body(
    state: HostState, request: dict[str, Any], request_sha256: str, task: tuple[int, str] | None, witness_key_id: str, at: int
) -> dict[str, Any]:
    task_id = request["task_id"]
    task_view = None
    if task_id is not None:
        pending_head = None if state.pending is None else state.pending.heads.get(task_id)
        task_view = {
            "task_id": task_id,
            "confirmed": None if task is None else {"sequence": task[0], "head_hash": task[1]},
            "pending": pending_head,
        }
    return {
        "kind": "state",
        "host_id": state.host_id,
        "nonce": request["nonce"],
        "request_sha256": request_sha256,
        "witness_key_id": witness_key_id,
        "at": at,
        "epoch": state.epoch,
        "confirmed": None if state.confirmed_hash is None else {"host_seq": state.confirmed_seq, "receipt_hash": state.confirmed_hash},
        "pending": None if state.pending is None else {"host_seq": state.pending.host_seq, "receipt_hash": state.pending.receipt_hash},
        "registry": state.registry,
        "time_floor": state.time_floor,
        "task": task_view,
    }


def refusal_body(code: str, message: str, request_sha256: str | None, host_id: str | None, witness_key_id: str, at: int) -> dict[str, Any]:
    return {
        "kind": "refusal",
        "code": code,
        "message": message,
        "request_sha256": request_sha256,
        "host_id": host_id,
        "witness_key_id": witness_key_id,
        "at": at,
    }


# -- the client ------------------------------------------------------------------------------------------

Transport = Callable[[str, bytes], tuple[int, bytes]]


def is_loopback_host(host: str) -> bool:
    """localhost, or a loopback IP address (the witness bind rule and the client URL rule share it)."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def http_transport(base_url: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> Transport:
    """POST to the witness. https, or plain http only to a loopback address (the answers are signed,
    but the request names tasks, so it should not cross a network in the clear)."""
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.query or parsed.fragment:
        raise ValueError("the witness URL must be https://host[:port][/prefix]")
    if parsed.scheme == "http" and not is_loopback_host(parsed.hostname):
        raise ValueError("the witness URL must use https (plain http only to a loopback address)")
    if not timeout > 0:
        raise ValueError("the witness timeout must be positive")
    https = parsed.scheme == "https"
    base_path = parsed.path.rstrip("/")
    slots = threading.BoundedSemaphore(MAX_OUTSTANDING_CALLS)
    host, port = parsed.hostname, parsed.port

    def send(path: str, payload: bytes) -> tuple[int, bytes]:
        """`timeout` is ONE absolute deadline for the whole call -- connect, TLS, headers, and body. A
        socket timeout alone bounds each read, so a witness sending a small chunk just under it would
        hold the caller (in PR 2: the host's database write transaction) forever. The exchange runs in
        a worker thread; at the deadline the caller gets WitnessUnavailable and the socket is shut down,
        which ends the worker's blocked read. A worker blocked BEFORE a socket exists (a stalled DNS
        lookup) cannot be ended that way; it keeps its slot until it exits, and once every slot is held
        a new call fails at once without starting a thread."""
        if not slots.acquire(blocking=False):
            raise WitnessUnavailable(
                f"{MAX_OUTSTANDING_CALLS} earlier calls to the witness at {base_url} are still stuck (for example in a DNS "
                "lookup); not starting another"
            )
        result: dict[str, Any] = {}
        try:
            if https:
                connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                    host, port, timeout=timeout, context=ssl.create_default_context()
                )
            else:
                connection = http.client.HTTPConnection(host, port, timeout=timeout)
        except BaseException:
            slots.release()  # no worker was started, so none will release the slot
            raise

        def exchange() -> None:
            try:
                connection.request("POST", base_path + path, body=payload, headers={"Content-Type": "application/json"})
                response = connection.getresponse()
                # Any status is read the same way: a refusal is a signed answer with a 4xx status.
                result["answer"] = (response.status, response.read(MAX_REQUEST_BYTES + 1))
            except Exception as error:  # every failure here means "no usable answer"
                result["error"] = error
            finally:
                slots.release()

        worker = threading.Thread(target=exchange, name="portmark-witness-call", daemon=True)
        try:
            worker.start()
        except BaseException:
            slots.release()  # the worker never ran, so it cannot release its slot
            raise
        worker.join(timeout)
        if worker.is_alive():
            _abort(connection)
            raise WitnessUnavailable(f"the witness at {base_url} did not answer within {timeout}s")
        connection.close()
        if "error" in result:
            raise WitnessUnavailable(f"the witness at {base_url} did not answer: {result['error']}") from result["error"]
        return result["answer"]

    return send


def _abort(connection: http.client.HTTPConnection) -> None:
    sock = connection.sock
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # already closed: nothing left to unblock
    connection.close()


@dataclass(frozen=True)
class Answer:
    status: int
    body: dict[str, Any]
    request_sha256: str
    document: dict[str, Any] = field(repr=False)

    @property
    def kind(self) -> str:
        return str(self.body.get("kind"))

    @property
    def code(self) -> str | None:
        return self.body.get("code") if self.kind == "refusal" else None

    @property
    def receipt_hash(self) -> str:
        return digest(self.body)


class WitnessClient:
    """Signs requests, sends them, and accepts only answers signed by the PINNED witness key that are
    bound to the request just sent. Anything else raises WitnessUnavailable (fail closed)."""

    def __init__(self, transport: Transport, witness_public_key: bytes, signer: str, private_key: Ed25519PrivateKey) -> None:
        self._transport = transport
        self.witness_public_key = witness_public_key
        self.witness_key_id = key_id_for(witness_public_key)
        self.signer = signer
        self._private_key = private_key

    def advance(
        self, host_id: str, host_seq: int, prev: str | None, heads: dict[str, dict[str, Any]],
        registry: dict[str, Any] | None = None, time_floor: int = 0,
    ) -> Answer:
        return self.send(ADVANCE_PATH, {
            "format": ADVANCE_FORMAT, "witness_key_id": self.witness_key_id, "host_id": host_id, "host_seq": host_seq,
            "prev": prev, "heads": heads, "registry": registry, "time_floor": time_floor,
        })

    def state(self, host_id: str, task_id: str | None = None) -> Answer:
        return self.send(STATE_PATH, {
            "format": STATE_FORMAT, "witness_key_id": self.witness_key_id, "host_id": host_id,
            "nonce": secrets.token_hex(16), "task_id": task_id,
        })

    def rebaseline(
        self, host_id: str, expected_last: str | None, reason: str, heads: dict[str, dict[str, Any]],
        registry: dict[str, Any] | None, time_floor: int,
    ) -> Answer:
        return self.send(REBASELINE_PATH, {
            "format": REBASELINE_FORMAT, "witness_key_id": self.witness_key_id, "host_id": host_id,
            "expected_last": expected_last, "nonce": secrets.token_hex(16), "reason": reason, "heads": heads,
            "registry": registry, "time_floor": time_floor,
        })

    def send(self, path: str, body: dict[str, Any]) -> Answer:
        return self.send_envelope(path, sign_request(self._private_key, self.signer, body))

    def send_envelope(self, path: str, envelope: dict[str, Any]) -> Answer:
        body = envelope["body"]
        request_sha256 = digest(body)
        payload = canonical_json(envelope)
        if len(payload) > MAX_REQUEST_BYTES:
            # Measured on the exact bytes about to be sent. The witness would refuse them (`too-large`);
            # refusing here says why, without a network call, and never as "unavailable".
            raise FloorError(TOO_LARGE, f"the witness request is {len(payload)} bytes; a request is at most {MAX_REQUEST_BYTES} bytes")
        status, raw = self._transport(path, payload)
        if len(raw) > MAX_REQUEST_BYTES:
            raise WitnessUnavailable("the witness answer is too large")
        try:
            document = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise WitnessUnavailable(f"the witness answer is not JSON (HTTP {status})") from error
        answer = open_answer(document, self.witness_public_key)
        # Bound to THIS request: a replayed or substituted answer (even a validly signed one) is refused.
        if answer.get("request_sha256") != request_sha256 or answer.get("witness_key_id") != self.witness_key_id:
            raise WitnessUnavailable("the witness answer is not bound to this request")
        kind = answer.get("kind")
        if kind == "refusal":
            if status == 200:
                raise WitnessUnavailable("the witness answered a refusal with HTTP 200")
        elif status != 200:
            raise WitnessUnavailable(f"the witness answered HTTP {status} without a refusal")
        elif answer.get("host_id") != body["host_id"]:
            raise WitnessUnavailable("the witness answer is for another host")
        elif body["format"] == STATE_FORMAT and (kind != "state" or answer.get("nonce") != body["nonce"]):
            raise WitnessUnavailable("the witness state answer does not echo this request's nonce")
        elif body["format"] == ADVANCE_FORMAT and (kind != "receipt" or answer.get("host_seq") != body["host_seq"] or answer.get("prev") != body["prev"]):
            raise WitnessUnavailable("the witness receipt does not match the advance")
        elif body["format"] == REBASELINE_FORMAT and kind != "rebaseline":
            raise WitnessUnavailable("the witness answered a rebaseline with something else")
        return Answer(status, answer, request_sha256, document)

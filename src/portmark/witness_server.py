"""EV-013: the reference remote witness server (`portmark witness serve`).

It runs on a machine OUTSIDE the host's failure domain (another machine, another backup set) and keeps,
per enrolled host, the chain of advances defined in remote_witness.py.

Storage. One SQLite file. `witness_log` is the record: every advance, discard, and rebaseline, with the
signed request and the signed answer, append-only (triggers refuse UPDATE and DELETE). `witness_hosts` and
`witness_task_heads` are an index derived from the log; `fold_log` rebuilds them from the log alone.
Append-only here is an application rule, not WORM storage: for WORM, put the file (or its backups) on
object-lock storage.

Authentication. Every endpoint except GET /healthz needs an Ed25519-signed request from an enrolled key:
  - POST /v1/advance     the host itself (signer == host_id);
  - POST /v1/state       the host itself, or an enrolled auditor;
  - POST /v1/rebaseline  an enrolled OPERATOR (a key the host does not hold).
Every answer, a refusal too, is signed with the witness's own key and bound to the request's digest.
There is no bearer token: the per-request signatures authenticate more than a shared token would.

Bind. Loopback by default. A non-loopback bind needs --public-mode behind-tls-proxy: the explicit
acknowledgement that a reverse proxy terminates TLS in front of this listener (the requests name tasks).
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import stat
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .json_guard import StrictJSONError, strict_json_loads
from .remote_witness import (
    ADVANCE_FORMAT,
    ADVANCE_PATH,
    MALFORMED,
    MAX_REQUEST_BYTES,
    NOT_FOUND,
    RATE_LIMITED,
    REBASELINE_FORMAT,
    REBASELINE_PATH,
    STATE_FORMAT,
    STATE_PATH,
    TOO_LARGE,
    UNAUTHENTICATED,
    WRONG_WITNESS,
    Decision,
    HostState,
    KnownEntry,
    Pending,
    WitnessProtocolError,
    apply_advance,
    apply_rebaseline,
    check_body,
    decide_advance,
    decide_rebaseline,
    decode_public_key,
    digest,
    is_loopback_host,
    key_id_for,
    open_request,
    public_key_bytes,
    rebaseline_body,
    receipt_body,
    refusal_body,
    sign_answer,
    state_body,
)
from .security import canonical_json

ENROLMENT_FORMAT = "portmark.witness.enrolment.v1"
PUBLIC_MODE_ACK = "behind-tls-proxy"
DEFAULT_PORT = 8787
SCHEMA_VERSION = 1
BODY_READ_TIMEOUT_SECONDS = 10.0

# Rate limits (token buckets): before authentication for everyone together, after it per signer.
GLOBAL_RATE_PER_SECOND = 500.0
GLOBAL_BURST = 1000.0
SIGNER_RATE_PER_SECOND = 100.0
SIGNER_BURST = 200.0

_PATH_FORMATS = {ADVANCE_PATH: ADVANCE_FORMAT, STATE_PATH: STATE_FORMAT, REBASELINE_PATH: REBASELINE_FORMAT}
_STATUS = {MALFORMED: 400, UNAUTHENTICATED: 401, NOT_FOUND: 404, TOO_LARGE: 413, RATE_LIMITED: 429, WRONG_WITNESS: 400}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS witness_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('advance', 'discard', 'rebaseline')),
    epoch INTEGER NOT NULL,
    host_seq INTEGER NOT NULL,
    receipt_hash TEXT NOT NULL,
    request_json TEXT NOT NULL,
    answer_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS witness_log_receipt ON witness_log (host_id, receipt_hash);
CREATE TRIGGER IF NOT EXISTS witness_log_no_update BEFORE UPDATE ON witness_log
BEGIN SELECT RAISE(ABORT, 'witness_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS witness_log_no_delete BEFORE DELETE ON witness_log
BEGIN SELECT RAISE(ABORT, 'witness_log is append-only'); END;
CREATE TABLE IF NOT EXISTS witness_hosts (
    host_id TEXT PRIMARY KEY,
    state_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS witness_task_heads (
    host_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    head_hash TEXT NOT NULL,
    PRIMARY KEY (host_id, task_id)
);
"""


# -- enrolment -------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Enrolment:
    """Who may talk to this witness. Each id appears in exactly one role."""

    hosts: dict[str, bytes]
    operators: dict[str, bytes]
    auditors: dict[str, bytes]

    @classmethod
    def from_path(cls, path: str) -> "Enrolment":
        try:
            with open(path, "rb") as handle:
                document = strict_json_loads(handle.read(), max_bytes=MAX_REQUEST_BYTES)
        except (OSError, StrictJSONError, ValueError) as error:
            raise ValueError(f"witness enrolment {path} cannot be read: {error}") from error
        if not isinstance(document, dict) or document.get("format") != ENROLMENT_FORMAT:
            raise ValueError(f"witness enrolment {path} must have \"format\": \"{ENROLMENT_FORMAT}\"")
        if not set(document) <= {"format", "hosts", "operators", "auditors"}:
            raise ValueError(f"witness enrolment {path} has unknown fields")
        groups: dict[str, dict[str, bytes]] = {}
        seen: set[str] = set()
        for role in ("hosts", "operators", "auditors"):
            entries = document.get(role, {})
            if not isinstance(entries, dict):
                raise ValueError(f"witness enrolment {role} must be an object")
            keys: dict[str, bytes] = {}
            for name, entry in entries.items():
                if not isinstance(name, str) or not name or len(name) > 512:
                    raise ValueError(f"witness enrolment {role} has a malformed id")
                if name in seen:
                    raise ValueError(f"witness enrolment id {name!r} appears in more than one role")
                if not isinstance(entry, dict) or set(entry) != {"public_key_b64"}:
                    raise ValueError(f"witness enrolment {role}[{name!r}] must be {{\"public_key_b64\": ...}}")
                keys[name] = decode_public_key(entry["public_key_b64"])
                seen.add(name)
            groups[role] = keys
        return cls(groups["hosts"], groups["operators"], groups["auditors"])

    def public_key_for(self, request_format: str, signer: str) -> bytes | None:
        if request_format == ADVANCE_FORMAT:
            return self.hosts.get(signer)
        if request_format == STATE_FORMAT:
            return self.hosts.get(signer) or self.auditors.get(signer)
        if request_format == REBASELINE_FORMAT:
            return self.operators.get(signer)
        return None


# -- the log ---------------------------------------------------------------------------------------------

def _state_to_json(state: HostState) -> str:
    return canonical_json(asdict(state)).decode("utf-8")


def _state_from_json(text: str) -> HostState:
    raw = json.loads(text)
    pending = raw.pop("pending")
    return HostState(**raw, pending=None if pending is None else Pending(**pending))


class WitnessLog:
    """The witness's SQLite file: the append-only log plus the index derived from it."""

    def __init__(self, path: str) -> None:
        self.path = path
        existed = os.path.exists(path)
        if existed and os.name == "posix" and os.stat(path).st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError(f"witness database {path} must not be accessible by group or others (chmod 600)")
        if not existed:
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        self._connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=10)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.executescript(_SCHEMA)
        version = self._connection.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            self._connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        elif version != SCHEMA_VERSION:
            raise ValueError(f"witness database {path} has schema version {version}; this server reads {SCHEMA_VERSION}")

    def close(self) -> None:
        self._connection.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        self._connection.execute("COMMIT")

    def host_state(self, host_id: str) -> HostState:
        row = self._connection.execute("SELECT state_json FROM witness_hosts WHERE host_id = ?", (host_id,)).fetchone()
        return HostState(host_id) if row is None else _state_from_json(row[0])

    def save_state(self, state: HostState) -> None:
        self._connection.execute(
            "INSERT INTO witness_hosts (host_id, state_json) VALUES (?, ?) "
            "ON CONFLICT (host_id) DO UPDATE SET state_json = excluded.state_json",
            (state.host_id, _state_to_json(state)),
        )

    def task_head(self, host_id: str, task_id: str) -> tuple[int, str] | None:
        row = self._connection.execute(
            "SELECT sequence, head_hash FROM witness_task_heads WHERE host_id = ? AND task_id = ?", (host_id, task_id)
        ).fetchone()
        return None if row is None else (row[0], row[1])

    def task_heads(self, host_id: str) -> dict[str, dict[str, Any]]:
        rows = self._connection.execute("SELECT task_id, sequence, head_hash FROM witness_task_heads WHERE host_id = ?", (host_id,))
        return {task_id: {"sequence": sequence, "head_hash": head_hash} for task_id, sequence, head_hash in rows}

    def confirm_heads(self, host_id: str, heads: dict[str, dict[str, Any]]) -> None:
        for task_id, head in heads.items():
            self._connection.execute(
                "INSERT INTO witness_task_heads (host_id, task_id, sequence, head_hash) VALUES (?, ?, ?, ?) "
                "ON CONFLICT (host_id, task_id) DO UPDATE SET sequence = excluded.sequence, head_hash = excluded.head_hash",
                (host_id, task_id, head["sequence"], head["head_hash"]),
            )

    def replace_heads(self, host_id: str, heads: dict[str, dict[str, Any]]) -> None:
        self._connection.execute("DELETE FROM witness_task_heads WHERE host_id = ?", (host_id,))
        self.confirm_heads(host_id, heads)

    def known(self, host_id: str, receipt_hash: str) -> KnownEntry | None:
        rows = self._connection.execute(
            "SELECT kind, epoch, host_seq FROM witness_log WHERE host_id = ? AND receipt_hash = ?", (host_id, receipt_hash)
        ).fetchall()
        issued = [row for row in rows if row[0] in ("advance", "rebaseline")]
        if not issued:
            return None
        return KnownEntry(host_seq=issued[0][2], epoch=issued[0][1], discarded=any(row[0] == "discard" for row in rows))

    def append(self, host_id: str, kind: str, epoch: int, host_seq: int, receipt_hash: str, request_json: str, answer_json: str, at: int) -> None:
        self._connection.execute(
            "INSERT INTO witness_log (host_id, kind, epoch, host_seq, receipt_hash, request_json, answer_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (host_id, kind, epoch, host_seq, receipt_hash, request_json, answer_json, at),
        )

    def log_rows(self, host_id: str) -> list[tuple[str, str, str]]:
        return self._connection.execute(
            "SELECT kind, request_json, answer_json FROM witness_log WHERE host_id = ? ORDER BY id", (host_id,)
        ).fetchall()


def fold_log(log: WitnessLog, host_id: str) -> tuple[HostState, dict[str, dict[str, Any]]]:
    """Rebuild one host's state and confirmed task heads from the append-only log alone, with the same
    chain rules the server applies. The derived tables must equal this (a test checks it)."""
    state = HostState(host_id)
    heads: dict[str, dict[str, Any]] = {}
    for kind, request_json, answer_json in log.log_rows(host_id):
        if kind == "discard":
            continue
        body = json.loads(request_json)["body"]
        answer = json.loads(answer_json)
        if kind == "advance":
            pending = state.pending
            confirm = pending if pending is not None and body["prev"] == pending.receipt_hash else None
            if confirm is not None:
                heads.update(confirm.heads)
            decision = Decision("accept", confirm=confirm, discard=None if confirm is not None else pending)
            state = apply_advance(state, body, digest(body), decision, answer)
        else:
            heads = dict(body["heads"])
            state = apply_rebaseline(state, body, answer)
    return state, heads


# -- the service -----------------------------------------------------------------------------------------

class _TokenBucket:
    def __init__(self, rate: float, burst: float, clock: Callable[[], float]) -> None:
        self.rate, self.burst, self._clock = rate, burst, clock
        self._tokens: dict[str, tuple[float, float]] = {}

    def take(self, key: str) -> bool:
        now = self._clock()
        tokens, last = self._tokens.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if tokens < 1.0:
            self._tokens[key] = (tokens, now)
            return False
        self._tokens[key] = (tokens - 1.0, now)
        return True


def _body_digest(raw: bytes) -> tuple[str | None, str | None]:
    """The request digest and host id, if the body parses, so even a refusal is bound to the request."""
    try:
        envelope = strict_json_loads(raw, max_bytes=MAX_REQUEST_BYTES)
    except (StrictJSONError, ValueError, UnicodeDecodeError):
        return None, None
    body = envelope.get("body") if isinstance(envelope, dict) else None
    if not isinstance(body, dict):
        return None, None
    try:
        host_id = body.get("host_id")
        return digest(body), host_id if isinstance(host_id, str) else None
    except (TypeError, ValueError):
        return None, None


class WitnessService:
    """Bytes in, (HTTP status, signed answer) out. One request at a time per process (a lock), and
    SQLite BEGIN IMMEDIATE across processes."""

    def __init__(
        self, log: WitnessLog, private_key: Ed25519PrivateKey, enrolment: Enrolment,
        clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.log = log
        self._private_key = private_key
        self.public_key = public_key_bytes(private_key)
        self.key_id = key_id_for(self.public_key)
        self.enrolment = enrolment
        self._clock = clock
        self._lock = threading.Lock()
        self._global = _TokenBucket(GLOBAL_RATE_PER_SECOND, GLOBAL_BURST, monotonic)
        self._per_signer = _TokenBucket(SIGNER_RATE_PER_SECOND, SIGNER_BURST, monotonic)

    def refusal(self, code: str, message: str, request_sha256: str | None = None, host_id: str | None = None) -> tuple[int, dict[str, Any]]:
        body = refusal_body(code, message, request_sha256, host_id, self.key_id, int(self._clock()))
        return _STATUS.get(code, 409), sign_answer(self._private_key, body)

    def handle(self, path: str, raw: bytes) -> tuple[int, dict[str, Any]]:
        request_sha256, host_id = _body_digest(raw)
        with self._lock:
            try:
                expected = _PATH_FORMATS.get(path)
                if expected is None:
                    raise WitnessProtocolError(NOT_FOUND, f"no such endpoint {path}")
                if not self._global.take("*"):
                    raise WitnessProtocolError(RATE_LIMITED, "the witness is busy")
                signer, body = open_request(raw, self.enrolment.public_key_for)
                if body.get("format") != expected:
                    raise WitnessProtocolError(MALFORMED, f"{path} takes {expected} requests")
                check_body(body, self.key_id)
                self._authorize(signer, body)
                if not self._per_signer.take(signer):
                    raise WitnessProtocolError(RATE_LIMITED, f"too many requests from {signer!r}")
                with self.log.transaction():
                    return self._dispatch(signer, body, raw.decode("utf-8"))
            except WitnessProtocolError as error:
                return self.refusal(error.code, str(error), request_sha256, host_id)

    def _authorize(self, signer: str, body: dict[str, Any]) -> None:
        host_id = body["host_id"]
        if body["format"] == ADVANCE_FORMAT and signer != host_id:
            raise WitnessProtocolError(UNAUTHENTICATED, "a host may advance only its own chain")
        if body["format"] == STATE_FORMAT and signer != host_id and signer not in self.enrolment.auditors:
            raise WitnessProtocolError(UNAUTHENTICATED, "a host may read only its own state")
        if host_id not in self.enrolment.hosts:
            raise WitnessProtocolError(UNAUTHENTICATED, f"host {host_id!r} is not enrolled")

    def _dispatch(self, signer: str, body: dict[str, Any], request_json: str) -> tuple[int, dict[str, Any]]:
        host_id = body["host_id"]
        at = int(self._clock())
        request_sha256 = digest(body)
        state = self.log.host_state(host_id)
        if body["format"] == STATE_FORMAT:
            task = self.log.task_head(host_id, body["task_id"]) if body["task_id"] is not None else None
            return 200, sign_answer(self._private_key, state_body(state, body, request_sha256, task, self.key_id, at))
        if body["format"] == ADVANCE_FORMAT:
            decision = decide_advance(
                state, body, request_sha256,
                lambda task_id: self.log.task_head(host_id, task_id),
                lambda receipt_hash: self.log.known(host_id, receipt_hash),
            )
            if decision.outcome == "replay" and state.pending is not None:
                return 200, state.pending.answer
            if decision.outcome != "accept":
                return self.refusal(str(decision.code), decision.message, request_sha256, host_id)
            answer = sign_answer(self._private_key, receipt_body(state, body, request_sha256, decision, self.key_id, at))
            new_state = apply_advance(state, body, request_sha256, decision, answer)
            if decision.confirm is not None:
                self.log.confirm_heads(host_id, decision.confirm.heads)
            if decision.discard is not None:
                self.log.append(host_id, "discard", state.epoch, decision.discard.host_seq, decision.discard.receipt_hash, "{}", "{}", at)
            self.log.append(host_id, "advance", state.epoch, body["host_seq"], digest(answer["body"]), request_json,
                            canonical_json(answer).decode("utf-8"), at)
            self.log.save_state(new_state)
            return 200, answer
        decision = decide_rebaseline(state, body)
        if decision.outcome != "accept":
            return self.refusal(str(decision.code), decision.message, request_sha256, host_id)
        answer = sign_answer(self._private_key, rebaseline_body(state, body, request_sha256, signer, self.key_id, at))
        new_state = apply_rebaseline(state, body, answer)
        if decision.discard is not None:
            self.log.append(host_id, "discard", state.epoch, decision.discard.host_seq, decision.discard.receipt_hash, "{}", "{}", at)
        self.log.replace_heads(host_id, body["heads"])
        self.log.append(host_id, "rebaseline", new_state.epoch, new_state.confirmed_seq, str(new_state.confirmed_hash), request_json,
                        canonical_json(answer).decode("utf-8"), at)
        self.log.save_state(new_state)
        return 200, answer


# -- ASGI ------------------------------------------------------------------------------------------------

def make_witness_app(service: WitnessService) -> Callable[..., Any]:
    async def respond(send: Callable[..., Any], status: int, payload: bytes, content_type: bytes = b"application/json") -> None:
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", content_type), (b"cache-control", b"no-store"), (b"content-length", str(len(payload)).encode()),
        ]})
        await send({"type": "http.response.body", "body": payload})

    async def app(scope: dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        if scope["method"] == "GET" and scope["path"] == "/healthz":
            await respond(send, 200, b"ok\n", b"text/plain")
            return
        if scope["method"] != "POST" or scope["path"] not in _PATH_FORMATS:
            status, document = service.refusal(NOT_FOUND, f"no such endpoint {scope['method']} {scope['path']}")
            await respond(send, status, canonical_json(document))
            return
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > MAX_REQUEST_BYTES):
            status, document = service.refusal(TOO_LARGE, f"a request is at most {MAX_REQUEST_BYTES} bytes")
            await respond(send, status, canonical_json(document))
            return
        chunks: list[bytes] = []
        size = 0
        more = True
        try:
            while more:
                message = await asyncio.wait_for(receive(), BODY_READ_TIMEOUT_SECONDS)
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                size += len(chunk)
                if size > MAX_REQUEST_BYTES:
                    status, document = service.refusal(TOO_LARGE, f"a request is at most {MAX_REQUEST_BYTES} bytes")
                    await respond(send, status, canonical_json(document))
                    return
                chunks.append(chunk)
                more = message.get("more_body", False)
        except asyncio.TimeoutError:
            status, document = service.refusal(MALFORMED, "the request body was not received in time")
            await respond(send, status, canonical_json(document))
            return
        status, document = await asyncio.to_thread(service.handle, scope["path"], b"".join(chunks))
        await respond(send, status, canonical_json(document))

    return app


def bind_problems(bind: str, public_mode: str | None) -> list[str]:
    if is_loopback_host(bind):
        return []
    if (public_mode or "").strip() != PUBLIC_MODE_ACK:
        return [f"a non-loopback bind needs --public-mode {PUBLIC_MODE_ACK}: acknowledge that a reverse proxy terminates TLS "
                "in front of this listener"]
    return []


def serve_witness(database: str, key_file: str, enrolment_path: str, bind: str, port: int, public_mode: str | None) -> None:
    """Run the reference witness under uvicorn (one process; the lock plus BEGIN IMMEDIATE keep it safe)."""
    import uvicorn

    from .remote_witness import load_private_key_file

    problems = bind_problems(bind, public_mode)
    if problems:
        raise ValueError("; ".join(problems))
    # The key and enrolment first: a bad one must not leave a new, empty witness database behind.
    private_key = load_private_key_file(key_file)
    enrolment = Enrolment.from_path(enrolment_path)
    service = WitnessService(WitnessLog(database), private_key, enrolment)
    config = uvicorn.Config(
        make_witness_app(service), host=bind, port=port, proxy_headers=False, server_header=False, lifespan="on", log_level="info",
    )
    uvicorn.Server(config).run()

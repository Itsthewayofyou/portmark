"""Section 10 PR B: the monotonic-witness contract and the local audit floor.

The problem (audit Section 10 findings #1 and #4). A signed audit head lives in the same database
as the events it signs, so restoring an older, internally consistent database (or an older trust
registry that predates a revocation) verifies as current: nothing outside the database remembers
that something newer existed.

The contract (`MonotonicWitness`). A witness remembers, OUTSIDE the runtime database, the highest
audit head it has seen per task and the trust-registry version/digest in use. Its semantics do not
depend on where it stores that:

- `check_head` (compare-before-use): the local chain must be at least the witnessed sequence AND
  still contain the witnessed head at that position. Behind -> `rolled-back`; different content at
  the witnessed position -> `forked`. A local chain AHEAD of the witness was never witnessed (for
  example written before the floor existed); it is adopted only after its whole chain verifies.
- `advance_head` (BEFORE the database commit, as the last step of the save transaction, so no commit
  is acknowledged that the witness has not recorded): monotonic, never lowers. Advancing to the SAME
  sequence with a DIFFERENT head is a fork and is refused. If the commit then fails, the witness is
  AHEAD of the database; that is indistinguishable from a rollback, so it is refused, never lowered.
- `check_registry` / `advance_registry`: the registry version never goes down, and one version
  never has two digests.

The local floor (`LocalFloorWitness`) is ONE implementation: a single signed JSON record per host,
on a path outside the runtime database. A remote transparency service can later replace or
supplement it (check both) without changing audit-head semantics.

WHAT THE LOCAL FLOOR GUARANTEES, exactly: it detects rollback or divergence of the database or trust
registry RELATIVE TO THE SURVIVING AUTHORITATIVE FLOOR FILE. It does NOT detect:
  1. whole-machine rollback that restores both the database and the floor;
  2. copying the database and the floor together (or running clones with independent floor copies);
  3. forks across separate hosts;
  4. heads signed by a compromised host;
  5. backdated signing before compromise.
A database rolled back to before the floor was initialized, combined with deleting the floor,
looks like a first run (the "initialized" marker lives in that database).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, Protocol

from ._durable_file import atomic_write_bytes, sidecar_lock
from .security import AUDIT_FLOOR_TYPE, SecurityError, canonical_json

logger = logging.getLogger(__name__)

# Section 12 #6: version 2 adds `time_floor` (the durable time floor, mirrored here so it survives a
# rollback of the database it also lives in). A version-1 file is still read (its time floor is 0)
# and is rewritten as version 2 on the next write.
FLOOR_FORMAT_VERSION = 2
_READABLE_FORMAT_VERSIONS = (1, 2)

# Head comparison outcomes (also the `floor_status` values verify-audit reports).
ANCHORED = "anchored"
NOT_ANCHORED = "not-anchored"
ROLLED_BACK = "rolled-back"
FORKED = "forked"


class FloorError(SecurityError):
    """A fail-closed audit-floor refusal. `code` is machine-readable (floor_status)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class MonotonicWitness(Protocol):
    def check_head(self, task_id: str, local_head: tuple[str, int] | None, event_hash_at: Callable[[int], str | None]) -> None:
        """Raise FloorError(rolled-back|forked) if the local chain is behind or diverged."""
        ...

    def advance_head(self, task_id: str, sequence: int, head_hash: str) -> None:
        """Record a head BEFORE its database commit (inside the save transaction). Monotonic; a
        same-sequence different head raises FloorError(forked)."""
        ...

    def check_registry(self, version: int | None, digest: str | None) -> None:
        ...

    def advance_registry(self, version: int | None, digest: str | None) -> None:
        ...

    # Section 12 #6: a witness may also remember the durable time floor outside the database.
    def witnessed_time_floor(self) -> int:
        ...

    def advance_time_floor(self, floor_at: int) -> None:
        """Monotonic: a lower value is ignored."""
        ...


def compare_head(witnessed: tuple[str, int] | None, local_head: tuple[str, int] | None, event_hash_at: Callable[[int], str | None]) -> str:
    """Pure comparison shared by every witness: ANCHORED, NOT_ANCHORED, ROLLED_BACK, or FORKED.

    `witnessed` / `local_head` are (head_hash, sequence) where sequence is the NEXT expected index
    (== number of events). The head hash of a chain with N events is the hash of event N-1.
    """
    if witnessed is None:
        return NOT_ANCHORED
    witnessed_hash, witnessed_sequence = witnessed
    if local_head is None or local_head[1] < witnessed_sequence:
        return ROLLED_BACK
    if event_hash_at(witnessed_sequence - 1) != witnessed_hash:
        return FORKED
    return ANCHORED


def check_registry_against(floor_registry: dict[str, Any] | None, version: int | None, digest: str | None) -> str | None:
    """Return a refusal code, or None if the registry is not older than / divergent from the floor."""
    if floor_registry is None:
        return None
    if version is None:
        return "registry-missing"
    if version < floor_registry["version"]:
        return "registry-rolled-back"
    if version == floor_registry["version"] and digest != floor_registry["digest"]:
        return "registry-forked"
    return None


@contextmanager
def _reader_lock(path: str) -> Iterator[None]:
    # Readers take the writers' lock when they can (see LocalFloorWitness.load). An auditor reading
    # a floor on read-only storage cannot create the lock file; then it reads unlocked -- nothing
    # there can write concurrently -- instead of misreporting the floor as corrupt.
    try:
        lock = sidecar_lock(path)
        lock.__enter__()
    except OSError:
        yield
        return
    try:
        yield
    finally:
        lock.__exit__(None, None, None)


def _file_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class LocalFloorWitness:
    """The local audit floor: one signed record per host, outside the runtime database.

    File: {"format": "portmark.audit-floor.v1", "body": {...}, "signature_key_id": ..., "signature": ...}
    body: {format_version, host_id, epoch, registry: null | {version, digest}, time_floor (v2),
           tasks: {task_id: {sequence, head_hash}}, resets: [...]}
    `resets` is append-only and holds two entry shapes: an audit-floor reset
    {at, reason, prior_epoch, prior_floor_sha256} and (Section 12) a time-floor reset
    {at, reason, kind: "time-floor", prior_time_floor, new_time_floor}. A reader must check `kind`.

    Every read verifies the signature (the host's audit key, `audit` purpose, issuer == host_id);
    every write is lock -> read -> verify -> merge -> sign -> temp -> fsync -> replace -> dir fsync.
    `signer` may be None for a read-only verifier (verify-audit).
    """

    def __init__(self, path: str | os.PathLike[str], host_id: str, signer: Any | None, verifier: Any) -> None:
        self.path = str(path)
        self.host_id = host_id
        self._signer = signer
        self._verifier = verifier

    @classmethod
    def for_verification(cls, path: str | os.PathLike[str], verifier: Any) -> "LocalFloorWitness | None":
        """A read-only handle for an offline verifier that does not know the host id: the id is
        taken from the file and then BOUND by the signature check (the key's issuer must equal
        it). None if the file does not exist."""
        try:
            with _reader_lock(str(path)):
                with open(path, "rb") as handle:
                    data = handle.read()
            document = json.loads(data)
            host_id = document["body"]["host_id"]
        except FileNotFoundError:
            return None
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise FloorError("floor-corrupt", "audit floor is unreadable or malformed") from error
        if not isinstance(host_id, str) or not host_id:
            raise FloorError("floor-corrupt", "audit floor host_id is malformed")
        return cls(path, host_id, None, verifier)

    # -- reading ---------------------------------------------------------------------------
    def read_raw(self) -> bytes | None:
        try:
            with open(self.path, "rb") as handle:
                return handle.read()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise FloorError("floor-corrupt", f"audit floor {self.path} is unreadable: {error}") from error

    def load(self) -> dict[str, Any] | None:
        """The verified floor body, or None if the file does not exist.

        Reads take the same cross-process lock as writes: on Windows a file that another handle
        holds open cannot be replaced, so an unlocked reader could make a concurrent writer's
        `os.replace` fail. (The lock is not re-entrant: code already holding it uses _load_locked.)
        """
        with _reader_lock(self.path):
            return self._load_locked()

    def _load_locked(self) -> dict[str, Any] | None:
        raw = self.read_raw()
        return None if raw is None else self._verified_body(raw)

    def _verified_body(self, raw: bytes) -> dict[str, Any]:
        try:
            document = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise FloorError("floor-corrupt", "audit floor is not valid JSON") from error
        if not isinstance(document, dict) or set(document) != {"format", "body", "signature_key_id", "signature"}:
            raise FloorError("floor-corrupt", "audit floor document has an unexpected shape")
        if document["format"] != AUDIT_FLOOR_TYPE:
            raise FloorError("floor-corrupt", "audit floor has an unknown format")
        body = document["body"]
        _validate_body(body)
        if body["host_id"] != self.host_id:
            raise FloorError("floor-corrupt", f"audit floor belongs to host {body['host_id']!r}, not {self.host_id!r}")
        key_id, signature = document["signature_key_id"], document["signature"]
        if not isinstance(key_id, str) or not isinstance(signature, str):
            raise FloorError("floor-corrupt", "audit floor signature is malformed")
        try:
            self._verifier.verify_audit_floor(key_id, body, signature)
        except SecurityError as error:
            raise FloorError("floor-corrupt", f"audit floor signature check failed: {error}") from error
        # Upgrade only AFTER the signature check: the signature covers the body exactly as stored.
        return _upgraded(body)

    # -- writing ---------------------------------------------------------------------------
    def _write(self, body: dict[str, Any]) -> None:
        if self._signer is None:
            raise FloorError("floor-write-failed", "this audit floor handle is read-only")
        _validate_body(body)
        document = {
            "format": AUDIT_FLOOR_TYPE,
            "body": body,
            "signature_key_id": self._signer.key_id,
            "signature": self._signer.sign_audit_floor(body),
        }
        atomic_write_bytes(self.path, canonical_json(document), prefix=".audit-floor-", mode=0o600)

    def create(
        self, epoch: int, registry: dict[str, Any] | None, tasks: dict[str, dict[str, Any]], resets: list[dict[str, Any]],
        time_floor: int = 0,
    ) -> None:
        with sidecar_lock(self.path):
            self._write({
                "format_version": FLOOR_FORMAT_VERSION,
                "host_id": self.host_id,
                "epoch": epoch,
                "registry": registry,
                "tasks": tasks,
                "resets": resets,
                "time_floor": time_floor,
            })

    def _update(self, mutate: Callable[[dict[str, Any]], bool]) -> None:
        # read -> verify -> merge -> write under the cross-process lock, so two processes advancing
        # different tasks never lose each other's entry and the floor never lowers.
        with sidecar_lock(self.path):
            body = self._load_locked()
            if body is None:
                raise FloorError("floor-missing", f"audit floor {self.path} disappeared; refusing to rebuild it")
            if mutate(body):
                self._write(body)

    # -- the MonotonicWitness contract -------------------------------------------------------
    def witnessed_head(self, task_id: str) -> tuple[str, int] | None:
        body = self.load()
        if body is None:
            raise FloorError("floor-missing", f"audit floor {self.path} is missing")
        entry = body["tasks"].get(task_id)
        return None if entry is None else (entry["head_hash"], entry["sequence"])

    def check_head(self, task_id: str, local_head: tuple[str, int] | None, event_hash_at: Callable[[int], str | None]) -> None:
        outcome = compare_head(self.witnessed_head(task_id), local_head, event_hash_at)
        if outcome == ROLLED_BACK:
            raise FloorError(ROLLED_BACK, f"task {task_id!r}: the database is OLDER than the audit floor (rolled back)")
        if outcome == FORKED:
            raise FloorError(FORKED, f"task {task_id!r}: the database diverges from the audit floor (forked)")

    def advance_head(self, task_id: str, sequence: int, head_hash: str) -> None:
        self.advance_heads({task_id: (head_hash, sequence)})

    def advance_heads(self, heads: dict[str, tuple[str, int]]) -> None:
        def mutate(body: dict[str, Any]) -> bool:
            changed = False
            for task_id, (head_hash, sequence) in heads.items():
                current = body["tasks"].get(task_id)
                if current is not None and sequence == current["sequence"] and head_hash != current["head_hash"]:
                    raise FloorError(FORKED, f"task {task_id!r}: a different head for an already-witnessed sequence (forked)")
                if current is None or sequence > current["sequence"]:
                    body["tasks"][task_id] = {"sequence": sequence, "head_hash": head_hash}
                    changed = True
            return changed

        self._update(mutate)

    def check_registry(self, version: int | None, digest: str | None) -> None:
        body = self.load()
        if body is None:
            raise FloorError("floor-missing", f"audit floor {self.path} is missing")
        code = check_registry_against(body["registry"], version, digest)
        if code is not None:
            raise FloorError(code, _REGISTRY_MESSAGES[code])

    def advance_registry(self, version: int | None, digest: str | None) -> None:
        if version is None:
            return

        def mutate(body: dict[str, Any]) -> bool:
            current = body["registry"]
            if current is not None and version == current["version"] and digest != current["digest"]:
                # The contract, enforced by the mutator itself (auditor round 2, Low): one registry
                # version never gets a second digest -- same shape as a same-sequence head fork.
                raise FloorError("registry-forked", _REGISTRY_MESSAGES["registry-forked"])
            if current is None or version > current["version"]:
                body["registry"] = {"version": version, "digest": digest}
                return True
            return False

        self._update(mutate)

    # -- Section 12 #6: the mirrored durable time floor ---------------------------------------------
    def witnessed_time_floor(self) -> int:
        body = self.load()
        return 0 if body is None else int(body["time_floor"])

    def advance_time_floor(self, floor_at: int) -> None:
        """Raise the mirrored floor to `floor_at`; never lowers it (a lower value is ignored)."""

        def mutate(body: dict[str, Any]) -> bool:
            if floor_at > body["time_floor"]:
                body["time_floor"] = int(floor_at)
                return True
            return False

        self._update(mutate)

    def reset_time_floor(self, floor_at: int, reason: str, at: int) -> int:
        """Operator recovery ONLY (`portmark time-floor reset`): set the mirrored floor, which may lower
        it, and record the reset in `resets`. Returns the previous value."""
        if not reason.strip():
            raise FloorError("reset-refused", "a time-floor reset requires a non-empty reason")
        prior: dict[str, int] = {}

        def mutate(body: dict[str, Any]) -> bool:
            prior["value"] = body["time_floor"]
            body["time_floor"] = int(floor_at)
            body["resets"].append({"at": at, "reason": reason, "kind": "time-floor", "prior_time_floor": prior["value"], "new_time_floor": int(floor_at)})
            return True

        self._update(mutate)
        return prior["value"]


_REGISTRY_MESSAGES = {
    "registry-missing": "the audit floor records a trust registry, but none is configured",
    "registry-rolled-back": "the trust registry is OLDER than the version recorded in the audit floor (rolled back)",
    "registry-forked": "the trust registry has the floor's version but different content (same version, two registries)",
}


def _validate_body(body: Any) -> None:
    def bad(detail: str) -> FloorError:
        return FloorError("floor-corrupt", f"audit floor body is malformed: {detail}")

    def is_int(value: Any, minimum: int) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value >= minimum

    base_fields = {"format_version", "host_id", "epoch", "registry", "tasks", "resets"}
    if not isinstance(body, dict) or "format_version" not in body:
        raise bad("unexpected fields")
    if body["format_version"] not in _READABLE_FORMAT_VERSIONS or isinstance(body["format_version"], bool):
        raise bad(f"unsupported format_version {body['format_version']!r}")
    expected = base_fields if body["format_version"] == 1 else base_fields | {"time_floor"}
    if set(body) != expected:
        raise bad("unexpected fields")
    if body["format_version"] >= 2 and not is_int(body["time_floor"], 0):
        raise bad("time_floor")
    if not isinstance(body["host_id"], str) or not body["host_id"]:
        raise bad("host_id")
    if not is_int(body["epoch"], 1):
        raise bad("epoch")
    registry = body["registry"]
    if registry is not None and (
        not isinstance(registry, dict) or set(registry) != {"version", "digest"} or not is_int(registry["version"], 1) or not isinstance(registry["digest"], str)
    ):
        raise bad("registry")
    tasks = body["tasks"]
    if not isinstance(tasks, dict):
        raise bad("tasks")
    for task_id, entry in tasks.items():
        if (
            not isinstance(entry, dict)
            or set(entry) != {"sequence", "head_hash"}
            or not is_int(entry["sequence"], 1)
            or not isinstance(entry["head_hash"], str)
            or not entry["head_hash"]
        ):
            raise bad(f"task {task_id!r}")
    if not isinstance(body["resets"], list):
        raise bad("resets")



def _upgraded(body: dict[str, Any]) -> dict[str, Any]:
    """A validated body in the CURRENT format: a version-1 body gets time_floor 0 (no floor recorded yet).
    The file on disk is rewritten as version 2 only by the next signed write."""
    if body["format_version"] == 1:
        body = {**body, "format_version": FLOOR_FORMAT_VERSION, "time_floor": 0}
    return body


# -- host boot, verification, and operator reset -----------------------------------------------

def open_audit_floor(witness: LocalFloorWitness, store: Any, registry_version: int | None, registry_digest: str | None) -> None:
    """Boot-time compare-before-use for this host. Raises FloorError on any refusal.

    Marker (in the DB) x floor file (outside it):
      none    + none          -> first run: create (marker pending -> floor -> marker active)
      pending + none          -> crash before the floor write: finish creating it
      pending + floor(epoch)  -> crash before activation: activate if the epochs match, else refuse
      active  + none          -> REFUSE floor-missing (never rebuilt automatically)
      none    + floor         -> REFUSE db-older-than-floor (DB from before the floor existed)
      active(e1) + floor(e2)  -> REFUSE epoch-mismatch (DB or floor from another reset epoch)
    Then: registry check + advance, and every witnessed task is compared with the database;
    heads this host signed that the floor has not seen are adopted ONLY if their chain verifies strictly;
    any that does not FAILS startup (FloorError unverified-head).
    """
    host_id = witness.host_id
    marker = store.audit_floor_marker(host_id)
    body = witness.load()
    if body is None:
        if marker is not None and not marker[1]:
            raise FloorError("floor-missing", f"audit floor {witness.path} is missing but this database recorded it (epoch {marker[0]}); "
                             "refusing to rebuild it. If the loss is understood, run `portmark floor-reset`.")
        epoch = marker[0] if marker is not None else 1
        store.set_audit_floor_marker(host_id, epoch, True)
        registry = None if registry_version is None else {"version": registry_version, "digest": registry_digest}
        witness.create(epoch, registry, {}, [])
        store.set_audit_floor_marker(host_id, epoch, False)
        body = witness.load()
    elif marker is None:
        raise FloorError("db-older-than-floor", "an audit floor exists but this database has no record of it: the database is "
                         "older than the floor (restored from before the floor was created)")
    elif marker[0] != body["epoch"]:
        raise FloorError("epoch-mismatch", f"audit floor epoch {body['epoch']} does not match this database's epoch {marker[0]} "
                         "(database or floor restored from another reset epoch, or an interrupted floor-reset)")
    elif marker[1]:
        store.set_audit_floor_marker(host_id, marker[0], False)
    assert body is not None  # nosec B101 -- narrowing only; every branch above set or raised
    code = check_registry_against(body["registry"], registry_version, registry_digest)
    if code is not None:
        raise FloorError(code, _REGISTRY_MESSAGES[code])
    witness.advance_registry(registry_version, registry_digest)
    # Compare EVERY witnessed task with the database (a rolled-back DB may have lost a task entirely).
    for task_id, entry in body["tasks"].items():
        outcome = compare_head((entry["head_hash"], entry["sequence"]), store.audit_head(task_id), lambda index, t=task_id: store.audit_event_hash(t, index))
        if outcome in (ROLLED_BACK, FORKED):
            raise FloorError(outcome, f"task {task_id!r}: the database is {'OLDER than' if outcome == ROLLED_BACK else 'diverged from'} the audit floor")
    # Adopt this host's heads that are new to (or ahead of) the floor: tasks written before the floor
    # existed, or a floor restored from an older copy. Each candidate is untrusted: it is adopted only
    # if its WHOLE chain verifies STRICTLY (no legacy-anchor override: complete pre-Section-10 anchors
    # are accepted only by an explicit `floor-reset --allow-legacy-anchor`) and the head is unchanged
    # right before the write. ANY failing candidate FAILS STARTUP (auditor round 3): logging and
    # continuing let a later save of that task write its invalid head into the floor.
    # debt: O(tasks) scan + a verify and a floor write per adopted task at boot; upgrade to a
    # sharded/append-only floor when a host carries enough tasks that boot becomes slow.
    rejected: list[str] = []
    adopt: dict[str, tuple[str, int]] = {}
    for task_id, head_hash, sequence in store.audit_heads_for_host(host_id):
        witnessed = body["tasks"].get(task_id)
        if witnessed is not None and sequence <= witnessed["sequence"]:
            continue
        verdict = store.verify_audit_chain_status(task_id, allow_legacy_anchor=False)
        if not verdict.valid:
            rejected.append(f"{task_id}: chain does not verify ({verdict.status}: {verdict.reason})")
        elif store.audit_head(task_id) != (head_hash, sequence):
            rejected.append(f"{task_id}: head changed while it was being verified")
        else:
            adopt[task_id] = (head_hash, sequence)
    if rejected:
        raise FloorError(
            "unverified-head",
            "refusing to start: these heads are not in the audit floor and cannot be verified, so they will "
            "not be witnessed: " + "; ".join(rejected) + ". Investigate the database; `portmark floor-reset` "
            "(with --allow-legacy-anchor only for complete pre-Section-10 migration anchors) re-verifies and "
            "rebaselines once it is sound.",
        )
    if adopt:
        witness.advance_heads(adopt)


def reset_audit_floor(
    witness: LocalFloorWitness,
    store: Any,
    reason: str,
    registry_version: int | None,
    registry_digest: str | None,
    allow_legacy_anchor: bool = False,
    clock: Callable[[], int] = lambda: int(time.time()),
) -> int:
    """Operator recovery: accept the CURRENT database as truth and start a new floor epoch.

    Every chain this host signed must verify first (a reset never launders a tampered chain).
    Records {at, reason, prior_epoch, prior_floor_sha256} in `resets`. Returns the new epoch.
    """
    if not reason.strip():
        raise FloorError("reset-refused", "floor-reset requires a non-empty --reason")
    host_id = witness.host_id
    heads = store.audit_heads_for_host(host_id)
    failures = []
    for task_id, _, _ in heads:
        result = store.verify_audit_chain_status(task_id, allow_legacy_anchor=allow_legacy_anchor)
        if not result.valid:
            failures.append(f"{task_id}: {result.status} ({result.reason})")
    if failures:
        raise FloorError("reset-refused", "refusing to reset the audit floor over chains that do not verify: " + "; ".join(failures))
    with _reader_lock(witness.path):
        raw = witness.read_raw()
    prior_epoch = 0
    prior_resets: list[dict[str, Any]] = []
    prior_time_floor = 0
    if raw is not None:
        try:
            prior = witness._verified_body(raw)
            prior_epoch, prior_resets = prior["epoch"], list(prior["resets"])
            # Section 12 #6: an audit-floor reset re-baselines HEADS, not time. The time floor carries
            # over; only `portmark time-floor reset` may lower it.
            prior_time_floor = prior["time_floor"]
        except FloorError:
            pass  # a corrupt floor is exactly what a reset replaces; its hash is still recorded
    marker = store.audit_floor_marker(host_id)
    epoch = max(prior_epoch, marker[0] if marker is not None else 0) + 1
    store.set_audit_floor_marker(host_id, epoch, True)
    resets = prior_resets + [{
        "at": clock(),
        "reason": reason,
        "prior_epoch": prior_epoch,
        "prior_floor_sha256": None if raw is None else _file_sha256(raw),
    }]
    registry = None if registry_version is None else {"version": registry_version, "digest": registry_digest}
    witness.create(
        epoch, registry, {task_id: {"sequence": sequence, "head_hash": head_hash} for task_id, head_hash, sequence in heads}, resets,
        time_floor=max(prior_time_floor, store.time_floor() if hasattr(store, "time_floor") else 0),
    )
    store.set_audit_floor_marker(host_id, epoch, False)
    return epoch


def apply_floor(
    result: Any,
    witness: LocalFloorWitness | None,
    store: Any,
    task_id: str,
    registry_version: int | None,
    registry_digest: str | None,
) -> Any:
    """Fold the floor verdict into an AuditVerificationResult (verify-audit).

    Rolled-back / forked / missing / corrupt / registry older -> `invalid` (exit 1), overriding any
    weaker verdict. A task the floor never witnessed -> `unverifiable` (exit 2). No floor configured
    -> `floor_status: no-floor`, status unchanged.
    """
    if witness is None:
        return replace(result, floor_status="no-floor")

    def refuse(code: str, reason: str) -> Any:
        prior = result.reason if result.status == "invalid" else reason
        return replace(result, status="invalid", reason=prior, floor_status=code)

    try:
        body = witness.load()
    except FloorError as error:
        return refuse(error.code, str(error))
    marker = store.audit_floor_marker(witness.host_id)
    if body is None:
        if marker is not None:
            return refuse("floor-missing", "the audit floor is missing but this database recorded it")
        return replace(result, status="invalid" if result.status == "invalid" else "unverifiable",
                       floor_status="floor-not-initialized", reason=result.reason if result.status == "invalid" else "no audit floor exists at the given path")
    if marker is None:
        return refuse("db-older-than-floor", "the database has no record of the audit floor (older than the floor)")
    if marker[0] != body["epoch"]:
        return refuse("epoch-mismatch", f"audit floor epoch {body['epoch']} does not match the database's epoch {marker[0]}")
    code = check_registry_against(body["registry"], registry_version, registry_digest)
    if code is not None:
        return refuse(code, _REGISTRY_MESSAGES[code])
    entry = body["tasks"].get(task_id)
    witnessed = None if entry is None else (entry["head_hash"], entry["sequence"])
    outcome = compare_head(witnessed, store.audit_head(task_id), lambda index: store.audit_event_hash(task_id, index))
    if outcome == ROLLED_BACK:
        return refuse(ROLLED_BACK, "the database is OLDER than the audit floor for this task (rolled back)")
    if outcome == FORKED:
        return refuse(FORKED, "the database diverges from the audit floor for this task (forked)")
    if outcome == NOT_ANCHORED:
        if result.status == "invalid":
            return replace(result, floor_status=NOT_ANCHORED)
        return replace(result, status="unverifiable", floor_status=NOT_ANCHORED,
                       reason="the audit floor has never witnessed this task; rollback cannot be ruled out")
    return replace(result, floor_status=ANCHORED)


def floor_path_inside(floor_path: str, directory: str) -> bool:
    floor = Path(floor_path).resolve()
    root = Path(directory).resolve()
    return floor == root or root in floor.parents

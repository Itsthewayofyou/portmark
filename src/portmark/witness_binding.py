"""EV-013 part 2: the host's side of the remote witness.

Every save (`AgentHost._persist`, the only code that appends audit events) advances the remote chain
INSIDE its database transaction: the advance names the receipt the database committed last (`prev`),
and the new receipt is stored in the same transaction as the save. So the database always names the
receipt of its own last commit, and a restored database names an OLD one, which the witness refuses.
A refusal or an unreachable witness raises FloorError and rolls the save back (owner decision F1).

At start, the database's last receipt is compared with the witness's state, O(1) (`classify_boot`):

  witness state             DB: none                     DB = confirmed / = pending   DB: another receipt
  empty                     first run: ok                -                            witness-behind
  confirmed only            rolled-back                  ok                           seq lower: rolled-back;
                                                                                      higher: witness-behind;
                                                                                      same: forked
  (confirmed) + pending     ok only if nothing is        ok (a lost commit, or a      lower than confirmed:
                            confirmed yet, else          committed one not yet        rolled-back; higher than
                            rolled-back                  confirmed)                   pending: witness-behind;
                                                                                      else forked

`witness-behind` means the WITNESS has less than this database (a wiped or restored witness, or the wrong
one): it is never adopted silently; an operator rebaseline (`floor-reset --operator-key-file`) fixes it.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any

from .remote_witness import DEFAULT_TIMEOUT_SECONDS, Answer, WitnessClient, decode_public_key, http_transport, load_private_key_file
from .security import canonical_json
from .witness import FORKED, ROLLED_BACK, FloorError

REMOTE_WITNESS_URL_ENV = "PORTMARK_REMOTE_WITNESS_URL"
REMOTE_WITNESS_PUBLIC_KEY_ENV = "PORTMARK_REMOTE_WITNESS_PUBLIC_KEY"
REMOTE_WITNESS_KEY_FILE_ENV = "PORTMARK_REMOTE_WITNESS_KEY_FILE"
REMOTE_WITNESS_TIMEOUT_ENV = "PORTMARK_REMOTE_WITNESS_TIMEOUT"
REMOTE_WITNESS_SIGNER_ENV = "PORTMARK_REMOTE_WITNESS_SIGNER"

WITNESS_BEHIND = "witness-behind"
ANCHORED = "anchored"
NO_REMOTE = "no-remote"


def classify_boot(database: tuple[int, str] | None, state: Mapping[str, Any]) -> tuple[str, str] | None:
    """The boot verdict for (the database's last receipt, the witness state): None, or (code, message)."""
    confirmed, pending = state["confirmed"], state["pending"]
    if confirmed is None and pending is None:
        if database is None:
            return None
        return WITNESS_BEHIND, ("this database holds a remote-witness receipt, but the witness has no chain for this host: "
                                "the witness was wiped or restored, or it is the wrong witness")
    if database is None:
        if confirmed is None:
            return None  # only a first advance whose commit never happened; the next save discards it
        return ROLLED_BACK, ("the witness holds a chain for this host, but this database has no receipt: the database is "
                             "OLDER than the witness (restored from before the remote witness was used)")
    seq, receipt_hash = database
    if (confirmed is not None and receipt_hash == confirmed["receipt_hash"]) or (pending is not None and receipt_hash == pending["receipt_hash"]):
        return None
    newest = pending if pending is not None else confirmed
    if confirmed is not None and seq < confirmed["host_seq"]:
        return ROLLED_BACK, (f"this database's last witness receipt ({seq}) is OLDER than the witness's ({confirmed['host_seq']}): "
                             "the database was restored, or it is a stale copy of this host")
    if seq > newest["host_seq"]:
        return WITNESS_BEHIND, (f"this database's last witness receipt ({seq}) is NEWER than the witness's ({newest['host_seq']}): "
                                "the witness was restored, or it is the wrong witness")
    return FORKED, (f"this database's last witness receipt ({seq}) is not the witness's receipt at that position: another "
                    "copy of this host advanced the chain (a clone or a fork)")


def _refusal(answer: Answer, doing: str) -> FloorError:
    return FloorError(str(answer.code), f"the remote witness refused {doing} ({answer.code}): {answer.body.get('message')}")


class HostWitness:
    """One host's binding to its remote witness. `registry()` names the trust registry in use
    ({version, digest}, or None), sent with every advance so the witness refuses an older registry."""

    def __init__(self, client: WitnessClient, host_id: str, registry: Callable[[], dict[str, Any] | None] = lambda: None) -> None:
        self.client = client
        self.host_id = host_id
        self._registry = registry

    def state(self) -> dict[str, Any]:
        answer = self.client.state(self.host_id)
        if answer.kind == "refusal":
            raise _refusal(answer, "a state read")
        return answer.body

    def check_boot(self, store: Any) -> dict[str, Any]:
        """Compare the database's last receipt with the witness. Raises FloorError; returns the state."""
        state = self.state()
        verdict = classify_boot(store.witness_receipt(self.host_id), state)
        if verdict is not None:
            raise FloorError(*verdict)
        return state

    def status(self, store: Any) -> str:
        """verify-audit's remote_status: `anchored`, or the refusal / unavailability code."""
        try:
            self.check_boot(store)
        except FloorError as error:
            return error.code
        return ANCHORED

    def advance(self, transaction: Any, heads: dict[str, dict[str, Any]], time_floor: int) -> None:
        """INSIDE the save transaction, before its commit: advance the chain from the receipt this database
        committed last, and store the new receipt in the same transaction. Raises FloorError."""
        # debt: the call runs while the store's write lock is held, so one host commits at most ~1/RTT saves
        # per second (DEFAULT_TIMEOUT_SECONDS bounds a stuck call); upgrade to batched advances when witness
        # p99 latency x the commit rate approaches 1 (see DEPLOYMENT.md "Remote Witness").
        prev = transaction.witness_receipt(self.host_id)
        seq, prev_hash = (0, None) if prev is None else prev
        answer = self.client.advance(self.host_id, seq + 1, prev_hash, heads, self._registry(), time_floor)
        if answer.kind == "refusal":
            raise _refusal(answer, "the save")
        transaction.store_witness_receipt(
            self.host_id, int(answer.body["host_seq"]), answer.receipt_hash, canonical_json(answer.document).decode("utf-8")
        )

    def rebaseline(
        self, operator: WitnessClient, store: Any, heads: dict[str, dict[str, Any]], reason: str,
        registry: dict[str, Any] | None, time_floor: int,
    ) -> int:
        """Operator recovery: start a new witness epoch from this database's CURRENT heads, and record the
        rebaseline receipt as the database's last receipt. Returns the new epoch."""
        state = self.state()
        newest = state["pending"] or state["confirmed"]
        answer = operator.rebaseline(self.host_id, None if newest is None else newest["receipt_hash"], reason, heads, registry, time_floor)
        if answer.kind == "refusal":
            raise _refusal(answer, "the rebaseline")
        store.set_witness_receipt(self.host_id, int(answer.body["host_seq"]), answer.receipt_hash, canonical_json(answer.document).decode("utf-8"))
        return int(answer.body["epoch"])


def client_from_environment(
    signer: str, key_file: str | None = None, environ: Mapping[str, str] | None = None,
) -> WitnessClient | None:
    """A client for the configured witness, or None if PORTMARK_REMOTE_WITNESS_URL is unset. A partial
    configuration is a ValueError (never a silent "no witness")."""
    env = os.environ if environ is None else environ
    url = (env.get(REMOTE_WITNESS_URL_ENV) or "").strip()
    public_key = (env.get(REMOTE_WITNESS_PUBLIC_KEY_ENV) or "").strip()
    key_path = key_file or (env.get(REMOTE_WITNESS_KEY_FILE_ENV) or "").strip()
    if not url:
        if public_key or key_path:
            raise ValueError(f"{REMOTE_WITNESS_PUBLIC_KEY_ENV} / {REMOTE_WITNESS_KEY_FILE_ENV} are set but {REMOTE_WITNESS_URL_ENV} is not")
        return None
    missing = [name for name, value in ((REMOTE_WITNESS_PUBLIC_KEY_ENV, public_key), (REMOTE_WITNESS_KEY_FILE_ENV, key_path)) if not value]
    if missing:
        raise ValueError(f"{REMOTE_WITNESS_URL_ENV} needs " + " and ".join(missing))
    raw_timeout = (env.get(REMOTE_WITNESS_TIMEOUT_ENV) or "").strip()
    try:
        timeout = float(raw_timeout) if raw_timeout else DEFAULT_TIMEOUT_SECONDS
    except ValueError as error:
        raise ValueError(f"{REMOTE_WITNESS_TIMEOUT_ENV} must be a number of seconds") from error
    if not 0 < timeout <= 30:
        raise ValueError(f"{REMOTE_WITNESS_TIMEOUT_ENV} must be more than 0 and at most 30 seconds")
    return WitnessClient(http_transport(url, timeout), decode_public_key(public_key), signer, load_private_key_file(key_path))


def host_witness_from_environment(
    host_id: str, registry: Callable[[], dict[str, Any] | None] = lambda: None, environ: Mapping[str, str] | None = None,
) -> HostWitness | None:
    client = client_from_environment(host_id, environ=environ)
    return None if client is None else HostWitness(client, host_id, registry)


def registry_identity(trust_source: Any) -> Callable[[], dict[str, Any] | None]:
    """The trust registry to name in each advance: {version, digest} of a VERSIONED registry, else None.
    Read on every call, so a reloaded registry is what the witness sees."""
    def current() -> dict[str, Any] | None:
        if trust_source is None or int(getattr(trust_source, "version", 0) or 0) < 1:
            return None
        return {"version": int(trust_source.version), "digest": str(trust_source.digest)}

    return current

"""EV-013 PR 1, phase 1: the witness seam.

The save path talks to a `MonotonicWitness`; boot, operator recovery, and offline verification talk to
the floor FILE through `LocalFloorStore`. These tests pin both contracts on the local floor, so a remote
witness (and the local + remote pair) in PR 2 is held to the same shape and the same failure rule.
"""

import tempfile
import typing
import unittest
from pathlib import Path

from test_audit_floor import HOST as DEPLOYED_HOST, Deployment, resume, start_task

from portmark.maintenance import reset_time_floor
from portmark.security import EnvelopeSigner
from portmark.witness import (
    ANCHORED,
    FloorError,
    LocalFloorStore,
    LocalFloorWitness,
    MonotonicWitness,
    apply_floor,
    open_audit_floor,
    reset_audit_floor,
)

HOST = "host:seam"


def _members(protocol):
    # Python 3.12+ stores the member names on the protocol; 3.11 computes them.
    names = getattr(protocol, "__protocol_attrs__", None)
    return frozenset(names if names is not None else typing._get_protocol_attrs(protocol))  # type: ignore[attr-defined]


class _Only:
    """A real witness seen through ONE protocol: any other attribute is an AttributeError. A caller
    that reaches past the seam (for example to a private method) fails here."""

    def __init__(self, target, protocol):
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_allowed", _members(protocol))

    def __getattr__(self, name):
        if name not in self._allowed:
            raise AttributeError(f"{name!r} is outside the witness seam")
        return getattr(self._target, name)


class _HalfWitness:
    """Has every MonotonicWitness method except witnessed_head."""

    host_id = HOST

    def check_head(self, task_id, local_head, event_hash_at): ...
    def advance_head(self, task_id, sequence, head_hash): ...
    def check_registry(self, version, digest): ...
    def advance_registry(self, version, digest): ...
    def witnessed_time_floor(self): return 0
    def advance_time_floor(self, floor_at): ...


class WitnessSeamTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.path = Path(self._dir.name) / "audit-floor.json"
        self.signer = EnvelopeSigner.from_private_key_bytes("seam-key", HOST, bytes(range(32)))
        self.witness = LocalFloorWitness(self.path, HOST, self.signer, self.signer)

    def tearDown(self):
        self._dir.cleanup()

    def test_the_local_floor_satisfies_both_contracts(self):
        self.assertIsInstance(self.witness, MonotonicWitness)
        self.assertIsInstance(self.witness, LocalFloorStore)

    def test_the_contract_check_is_not_vacuous(self):
        self.assertNotIsInstance(_HalfWitness(), MonotonicWitness)
        self.assertNotIsInstance(_HalfWitness(), LocalFloorStore)

    def test_unavailable_raises_and_only_never_witnessed_returns_none(self):
        # No floor file: the witness cannot answer, so it raises (never "nothing witnessed").
        with self.assertRaises(FloorError) as caught:
            self.witness.witnessed_head("t1")
        self.assertEqual(caught.exception.code, "floor-missing")
        self.witness.create(1, None, {"t1": {"sequence": 2, "head_hash": "h2"}}, [])
        self.assertEqual(self.witness.witnessed_head("t1"), ("h2", 2))
        self.assertIsNone(self.witness.witnessed_head("never"))
        # A corrupt floor also raises, for a witnessed and a never-witnessed task alike.
        self.path.write_bytes(self.path.read_bytes().replace(b'"h2"', b'"hX"'))
        for task_id in ("t1", "never"):
            with self.assertRaises(FloorError) as caught:
                self.witness.witnessed_head(task_id)
            self.assertEqual(caught.exception.code, "floor-corrupt")

    def test_verified_body_is_public_and_checks_the_signature(self):
        self.witness.create(1, None, {}, [])
        raw = self.witness.read_raw()
        if raw is None:
            self.fail("the floor was just created")
        self.assertEqual(self.witness.verified_body(raw)["host_id"], HOST)
        with self.assertRaises(FloorError) as caught:
            self.witness.verified_body(raw.replace(b'"epoch":1', b'"epoch":2'))
        self.assertEqual(caught.exception.code, "floor-corrupt")


class CallersUseOnlyTheSeamTests(unittest.TestCase):
    """Every caller runs against a proxy that exposes only its protocol, so PR 2 can hand it a remote
    witness (or the local + remote pair) without a caller reaching into the local floor."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.d = Deployment(self._dir.name)

    def tearDown(self):
        self._dir.cleanup()

    def test_the_save_path_uses_only_monotonic_witness(self):
        host = self.d.host()
        host.audit_floor = _Only(host.audit_floor, MonotonicWitness)
        envelope, first = start_task(host)
        self.assertEqual(resume(host, envelope).status, "awaiting_input")
        self.assertEqual(host.audit_floor.witnessed_head(first.task_id), host.store.audit_head(first.task_id))

    def test_boot_reset_verify_and_time_floor_reset_use_only_local_floor_store(self):
        # Written with no floor, so the first boot with one must ADOPT its head (advance_heads).
        task_id = start_task(self.d.host(floor=False))[1].task_id
        store = self.d.store()
        floor = LocalFloorWitness(self.d.floor_path, DEPLOYED_HOST, self.d.signer, self.d.signer)
        store.set_audit_head_verifier(self.d.signer)
        seam = _Only(floor, LocalFloorStore)
        open_audit_floor(seam, store, None, None)
        self.assertEqual(floor.witnessed_head(task_id), store.audit_head(task_id))
        verdict = apply_floor(store.verify_audit_chain_status(task_id), seam, store, task_id, None, None)
        self.assertEqual(verdict.floor_status, ANCHORED)
        self.assertEqual(reset_audit_floor(seam, store, "seam test", None, None), 2)
        outcome = reset_time_floor(store, seam, 1_000, "seam test", 2_000)
        self.assertEqual(outcome["new"], 1_000)
        self.assertEqual(floor.witnessed_time_floor(), 1_000)


if __name__ == "__main__":
    unittest.main()

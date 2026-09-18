"""Section 10 PR B: the monotonic-witness contract and the local audit floor.

Part 1 (this commit's mechanism): the signed floor record, head/registry comparison, monotonic
advance, cross-process merging, the boot state machine, and the operator reset. Host wiring and
end-to-end attack scenarios live in the integration section below.
"""

import base64
import dataclasses
import json
import os
import subprocess  # nosec B404 -- runs this test's own interpreter on a fixed inline script
import sys
import tempfile
import unittest
from pathlib import Path

from portmark.factory import make_demo_envelope, make_host
from portmark.security import EnvelopeSigner, SecurityError, TrustRegistry, TrustedIdentity, _parse_trust_registry
from portmark.storage import SQLITE_SCHEMA_VERSION, InMemoryRuntimeStore, SQLiteRuntimeStore
from portmark.witness import (
    ANCHORED,
    FORKED,
    NOT_ANCHORED,
    ROLLED_BACK,
    FloorError,
    LocalFloorWitness,
    compare_head,
    open_audit_floor,
    reset_audit_floor,
)

HOST = "host:floor"
# Fixed key bytes so a child process can rebuild the same signer (cross-process merge test).
HOST_KEY = bytes(range(32))


def host_signer(key_bytes=HOST_KEY, key_id="floor-key", issuer=HOST):
    return EnvelopeSigner.from_private_key_bytes(key_id, issuer, key_bytes)


def identity_of(signer, **changes):
    identity = TrustedIdentity(signer.key_id, signer.issuer, signer.public_key_bytes(), ("*",))
    return dataclasses.replace(identity, **changes) if changes else identity


class AuditFloorMechanismTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)
        self.floor_path = self.root / "floor" / "audit-floor.json"
        self.floor_path.parent.mkdir()
        self.signer = host_signer()

    def tearDown(self):
        self._dir.cleanup()

    def witness(self, signer=None, verifier=None, host_id=HOST):
        signer = self.signer if signer is None else signer
        return LocalFloorWitness(self.floor_path, host_id, signer, verifier if verifier is not None else signer)

    def fresh(self, tasks=None, registry=None):
        witness = self.witness()
        witness.create(1, registry, tasks or {}, [])
        return witness

    # -- the signed record --------------------------------------------------------------------
    def test_floor_round_trips_and_every_read_verifies_the_signature(self):
        witness = self.fresh({"t1": {"sequence": 3, "head_hash": "h3"}}, {"version": 2, "digest": "d"})
        body = witness.load()
        self.assertEqual(body["tasks"], {"t1": {"sequence": 3, "head_hash": "h3"}})
        self.assertEqual((body["host_id"], body["epoch"], body["format_version"]), (HOST, 1, 1))
        self.assertEqual(witness.witnessed_head("t1"), ("h3", 3))
        self.assertIsNone(witness.witnessed_head("t2"))

    def test_corrupted_floor_is_refused_not_trusted(self):
        original = None

        def rewrite(mutate):
            document = json.loads(original)
            mutate(document)
            self.floor_path.write_bytes(json.dumps(document).encode())

        self.fresh({"t1": {"sequence": 5, "head_hash": "h5"}})
        original = self.floor_path.read_bytes()
        cases = {
            "lowered sequence (the rollback-enabling edit)": lambda d: d["body"]["tasks"]["t1"].__setitem__("sequence", 1),
            "other host": lambda d: d["body"].__setitem__("host_id", "host:other"),
            "unknown format_version": lambda d: d["body"].__setitem__("format_version", 2),
            "extra body field": lambda d: d["body"].__setitem__("note", "x"),
            "extra document field": lambda d: d.__setitem__("note", "x"),
            "bool sequence": lambda d: d["body"]["tasks"]["t1"].__setitem__("sequence", True),
            "bad signature": lambda d: d.__setitem__("signature", "A" * 86),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                rewrite(mutate)
                with self.assertRaises(FloorError) as raised:
                    self.witness().load()
                self.assertEqual(raised.exception.code, "floor-corrupt")
        for label, data in {"truncated": original[: len(original) // 2], "bit flip": original.replace(b"h5", b"h6"), "not json": b"\xff\x00"}.items():
            with self.subTest(label):
                self.floor_path.write_bytes(data)
                with self.assertRaises(FloorError) as raised:
                    self.witness().load()
                self.assertEqual(raised.exception.code, "floor-corrupt")

    def test_floor_signed_by_another_or_revoked_key_is_refused(self):
        self.fresh()
        stranger = host_signer(bytes(range(1, 33)), key_id="stranger-key")
        # A trusted key of ANOTHER host cannot vouch for this host's floor.
        other_host = host_signer(bytes(range(2, 34)), key_id="other-host-key", issuer="host:other")
        registry = TrustRegistry((identity_of(self.signer), identity_of(other_host)))
        with self.assertRaises(FloorError):
            self.witness(verifier=stranger).load()  # stranger's registry does not trust our key
        self.witness(verifier=registry).load()  # control: our own key verifies
        revoked = TrustRegistry((identity_of(self.signer, revoked=True),))
        with self.assertRaisesRegex(FloorError, "revoked"):
            self.witness(verifier=revoked).load()
        audit_less = TrustRegistry((identity_of(self.signer, usages=("envelope",)),))
        with self.assertRaisesRegex(FloorError, "audit"):
            self.witness(verifier=audit_less).load()
        with self.assertRaises(SecurityError):
            other_host.sign_audit_floor({"host_id": HOST})  # a host cannot sign another host's floor

    # -- the contract ---------------------------------------------------------------------------
    def test_compare_head_outcomes(self):
        events = {0: "e0", 1: "e1", 2: "e2", 3: "e3"}
        at = events.get
        self.assertEqual(compare_head(None, ("e3", 4), at), NOT_ANCHORED)
        self.assertEqual(compare_head(("e2", 3), ("e2", 3), at), ANCHORED)
        self.assertEqual(compare_head(("e2", 3), ("e3", 4), at), ANCHORED)  # DB ahead = benign lag
        self.assertEqual(compare_head(("e3", 4), ("e2", 3), at), ROLLED_BACK)
        self.assertEqual(compare_head(("e3", 4), None, at), ROLLED_BACK)  # task gone entirely
        self.assertEqual(compare_head(("zz", 3), ("e3", 4), at), FORKED)

    def test_advance_is_monotonic_and_refuses_a_second_head_for_one_sequence(self):
        witness = self.fresh()
        witness.advance_head("t1", 3, "h3")
        witness.advance_head("t1", 2, "h2")  # older: ignored, never lowers
        self.assertEqual(witness.witnessed_head("t1"), ("h3", 3))
        witness.advance_head("t1", 3, "h3")  # idempotent
        with self.assertRaises(FloorError) as raised:
            witness.advance_head("t1", 3, "other")
        self.assertEqual(raised.exception.code, FORKED)
        witness.advance_head("t1", 5, "h5")
        self.assertEqual(witness.witnessed_head("t1"), ("h5", 5))
        with self.assertRaises(FloorError) as raised:
            witness.check_head("t1", ("h4", 4), lambda index: "h4")
        self.assertEqual(raised.exception.code, ROLLED_BACK)

    def test_a_missing_floor_is_never_rebuilt_by_an_advance(self):
        witness = self.fresh()
        self.floor_path.unlink()
        with self.assertRaises(FloorError) as raised:
            witness.advance_head("t1", 1, "h1")
        self.assertEqual(raised.exception.code, "floor-missing")
        self.assertFalse(self.floor_path.exists())

    def test_registry_floor_refuses_older_forked_or_missing_registry(self):
        witness = self.fresh(registry={"version": 3, "digest": "d3"})
        witness.check_registry(3, "d3")
        witness.check_registry(4, "d4")  # newer is fine
        for (version, digest), code in {(2, "d2"): "registry-rolled-back", (3, "other"): "registry-forked", (None, None): "registry-missing"}.items():
            with self.subTest(version=version, digest=digest):
                with self.assertRaises(FloorError) as raised:
                    witness.check_registry(version, digest)
                self.assertEqual(raised.exception.code, code)
        witness.advance_registry(4, "d4")
        witness.advance_registry(2, "d2")  # never lowers
        self.assertEqual(witness.load()["registry"], {"version": 4, "digest": "d4"})

    def test_concurrent_processes_merge_under_the_lock_and_never_lose_an_advance(self):
        self.fresh()
        script = (
            "import sys; sys.path.insert(0, sys.argv[1])\n"
            "from portmark.security import EnvelopeSigner\n"
            "from portmark.witness import LocalFloorWitness\n"
            "signer = EnvelopeSigner.from_private_key_bytes('floor-key', 'host:floor', bytes(range(32)))\n"
            "witness = LocalFloorWitness(sys.argv[2], 'host:floor', signer, signer)\n"
            "for seq in range(1, 26):\n"
            "    witness.advance_head(sys.argv[3], seq, f'{sys.argv[3]}-{seq}')\n"
        )
        src = str(Path(__file__).resolve().parents[1] / "src")
        workers = [
            subprocess.Popen([sys.executable, "-c", script, src, str(self.floor_path), f"task-{n}"])  # nosec B603
            for n in range(4)
        ]
        for worker in workers:
            self.assertEqual(worker.wait(timeout=120), 0)
        tasks = self.witness().load()["tasks"]
        self.assertEqual(tasks, {f"task-{n}": {"sequence": 25, "head_hash": f"task-{n}-25"} for n in range(4)})

    # -- registry version ---------------------------------------------------------------------------
    def test_registry_version_is_strict(self):
        self.assertEqual(_parse_trust_registry({"identities": []}).version, 0)
        self.assertEqual(_parse_trust_registry({"identities": [], "version": 7}).version, 7)
        for bad in (0, -1, True, "3", 1.5, None):
            with self.subTest(version=bad):
                with self.assertRaises(ValueError):
                    _parse_trust_registry({"identities": [], "version": bad})


class AuditFloorBootAndResetTests(unittest.TestCase):
    """The boot state machine (marker in the DB x floor file outside it) and operator reset."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)
        self.store = SQLiteRuntimeStore(self.root / "db" / "runtime.sqlite")
        self.floor_path = self.root / "floor" / "audit-floor.json"
        self.floor_path.parent.mkdir()
        self.signer = host_signer()

    def tearDown(self):
        self._dir.cleanup()

    def witness(self):
        return LocalFloorWitness(self.floor_path, HOST, self.signer, self.signer)

    def run_task(self, goal="floor task"):
        host = make_host(host_id=HOST, signer=self.signer, store=self.store, allow_ephemeral_signing_key=True)
        return host.run(make_demo_envelope(host, goal)).task_id

    def test_schema_has_the_marker_table(self):
        with self.store._connection() as connection:
            self.assertEqual(int(connection.execute("PRAGMA user_version").fetchone()[0]), SQLITE_SCHEMA_VERSION)
            self.assertEqual(SQLITE_SCHEMA_VERSION, 12)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_floor_markers)").fetchall()}
        self.assertEqual(columns, {"host_id", "epoch", "pending", "updated_at"})

    def test_first_boot_creates_and_adopts_existing_heads(self):
        task_id = self.run_task()
        open_audit_floor(self.witness(), self.store, 1, "d1")
        body = self.witness().load()
        self.assertEqual(body["epoch"], 1)
        self.assertEqual(body["registry"], {"version": 1, "digest": "d1"})
        head_hash, sequence = self.store.audit_head(task_id)
        self.assertEqual(body["tasks"][task_id], {"sequence": sequence, "head_hash": head_hash})
        self.assertEqual(self.store.audit_floor_marker(HOST), (1, False))

    def test_boot_state_machine(self):
        open_audit_floor(self.witness(), self.store, None, None)
        # active marker + missing floor -> refuse, never rebuild
        saved = self.floor_path.read_bytes()
        self.floor_path.unlink()
        with self.assertRaises(FloorError) as raised:
            open_audit_floor(self.witness(), self.store, None, None)
        self.assertEqual(raised.exception.code, "floor-missing")
        self.assertFalse(self.floor_path.exists())
        self.floor_path.write_bytes(saved)
        # floor present + DB with no marker -> the DB predates the floor
        other_store = SQLiteRuntimeStore(self.root / "db2" / "runtime.sqlite")
        with self.assertRaises(FloorError) as raised:
            open_audit_floor(self.witness(), other_store, None, None)
        self.assertEqual(raised.exception.code, "db-older-than-floor")
        # epoch mismatch
        self.store.set_audit_floor_marker(HOST, 2, False)
        with self.assertRaises(FloorError) as raised:
            open_audit_floor(self.witness(), self.store, None, None)
        self.assertEqual(raised.exception.code, "epoch-mismatch")
        # pending marker + floor of the same epoch (crash before activation) -> activated
        self.store.set_audit_floor_marker(HOST, 1, True)
        open_audit_floor(self.witness(), self.store, None, None)
        self.assertEqual(self.store.audit_floor_marker(HOST), (1, False))
        # pending marker + no floor (crash before the floor write) -> finish creating it
        self.floor_path.unlink()
        self.store.set_audit_floor_marker(HOST, 1, True)
        open_audit_floor(self.witness(), self.store, None, None)
        self.assertTrue(self.floor_path.exists())
        self.assertEqual(self.store.audit_floor_marker(HOST), (1, False))

    def test_boot_refuses_a_rolled_back_or_forked_database(self):
        task_id = self.run_task()
        open_audit_floor(self.witness(), self.store, None, None)
        head_hash, sequence = self.store.audit_head(task_id)
        # Floor claims a LATER head than the DB has -> rolled back.
        self.witness().advance_head(task_id, sequence + 2, "future-head")
        with self.assertRaises(FloorError) as raised:
            open_audit_floor(self.witness(), self.store, None, None)
        self.assertEqual(raised.exception.code, ROLLED_BACK)

    def test_boot_refuses_a_forked_database(self):
        task_id = self.run_task()
        open_audit_floor(self.witness(), self.store, None, None)
        _, sequence = self.store.audit_head(task_id)
        witness = self.witness()
        body = witness.load()
        body["tasks"][task_id]["head_hash"] = "not-the-db-head"
        witness.create(body["epoch"], body["registry"], body["tasks"], body["resets"])
        with self.assertRaises(FloorError) as raised:
            open_audit_floor(self.witness(), self.store, None, None)
        self.assertEqual(raised.exception.code, FORKED)

    def test_reset_accepts_the_current_database_with_a_new_epoch_and_a_record(self):
        task_id = self.run_task()
        open_audit_floor(self.witness(), self.store, None, None)
        prior = self.floor_path.read_bytes()
        self.floor_path.unlink()
        with self.assertRaises(FloorError):
            open_audit_floor(self.witness(), self.store, None, None)
        with self.assertRaises(FloorError):
            reset_audit_floor(self.witness(), self.store, "  ", None, None)
        epoch = reset_audit_floor(self.witness(), self.store, "floor volume lost in incident 42", None, None, clock=lambda: 1_700_000_000)
        self.assertEqual(epoch, 2)
        body = self.witness().load()
        self.assertEqual(body["epoch"], 2)
        self.assertEqual(body["resets"], [{"at": 1_700_000_000, "reason": "floor volume lost in incident 42", "prior_epoch": 0, "prior_floor_sha256": None}])
        self.assertIn(task_id, body["tasks"])
        open_audit_floor(self.witness(), self.store, None, None)  # boots again
        # A second reset records the prior floor's hash and epoch.
        reset_audit_floor(self.witness(), self.store, "rotate", None, None)
        body = self.witness().load()
        self.assertEqual(body["epoch"], 3)
        self.assertEqual(body["resets"][-1]["prior_epoch"], 2)
        self.assertIsNotNone(body["resets"][-1]["prior_floor_sha256"])
        del prior

    def test_reset_refuses_to_launder_a_tampered_chain(self):
        task_id = self.run_task()
        self.store.set_audit_head_verifier(self.signer)
        with sqlite3_connection(self.store.path) as connection:
            connection.execute("UPDATE audit_heads SET head_hash = 'tampered' WHERE task_id = ?", (task_id,))
        with self.assertRaises(FloorError) as raised:
            reset_audit_floor(self.witness(), self.store, "try to launder", None, None)
        self.assertEqual(raised.exception.code, "reset-refused")
        self.assertIn(task_id, str(raised.exception))
        self.assertFalse(self.floor_path.exists())

    def test_in_memory_store_implements_the_floor_reads(self):
        store = InMemoryRuntimeStore()
        host = make_host(host_id=HOST, signer=self.signer, store=store)
        task_id = host.run(make_demo_envelope(host, "memory floor")).task_id
        head_hash, sequence = store.audit_head(task_id)
        self.assertEqual(store.audit_heads_for_host(HOST), [(task_id, head_hash, sequence)])
        self.assertEqual(store.audit_event_hash(task_id, sequence - 1), head_hash)
        self.assertIsNone(store.audit_event_hash(task_id, sequence))
        store.set_audit_floor_marker(HOST, 4, True)
        self.assertEqual(store.audit_floor_marker(HOST), (4, True))


class sqlite3_connection:
    def __init__(self, path):
        import sqlite3

        self._connection = sqlite3.connect(path)

    def __enter__(self):
        return self._connection

    def __exit__(self, *exc):
        self._connection.commit()
        self._connection.close()


if __name__ == "__main__":
    unittest.main()

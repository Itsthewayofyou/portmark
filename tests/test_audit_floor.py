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
        with self.assertRaises(FloorError) as raised:
            witness.advance_registry(4, "another-digest")  # one version, two digests
        self.assertEqual(raised.exception.code, "registry-forked")
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


# ==================================================================================================
# Integration: the floor wired into make_host / _persist / verify-audit / floor-reset, attacked
# end to end. Every scenario uses a REAL host, a REAL SQLite database, and a REAL floor file.
# ==================================================================================================

from contextlib import redirect_stderr, redirect_stdout  # noqa: E402
import io  # noqa: E402
import shutil  # noqa: E402
import sqlite3  # noqa: E402
import threading  # noqa: E402
from unittest.mock import patch  # noqa: E402

from portmark.cli import main as cli_main  # noqa: E402
from portmark.models import ProviderDecision  # noqa: E402
from portmark.providers import ModelProvider  # noqa: E402
from portmark.witness import apply_floor  # noqa: E402


class SuspendProvider(ModelProvider):
    """Suspends on every decision, so the same task can be resumed and its chain advanced. The
    `tag` lands in the audited request, so two hosts with different tags write DIFFERENT events."""

    def __init__(self, tag="original"):
        self.tag = tag

    def decide(self, state, available_tools, grants=()):
        return ProviderDecision("await_input", content={"need": "more", "tag": self.tag})


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class Deployment:
    """One host's on-disk layout: store dir, a SEPARATE floor dir, and a trust registry."""

    def __init__(self, root):
        self.root = Path(root)
        self.store_path = self.root / "db" / "runtime.sqlite"
        self.floor_path = self.root / "floor" / "audit-floor.json"
        self.registry_path = self.root / "trust" / "trust.json"
        for directory in (self.store_path.parent, self.floor_path.parent, self.registry_path.parent):
            directory.mkdir(parents=True, exist_ok=True)
        self.signer = host_signer()
        self.write_registry(1)

    def write_registry(self, version, extra=(), host_revoked=False, drop_version=False):
        identities = [{
            "key_id": self.signer.key_id, "issuer": HOST, "public_key_b64": b64(self.signer.public_key_bytes()),
            "allowed_audiences": ["*"], "revoked": host_revoked,
        }, *extra]
        document = {"identities": identities} if drop_version else {"version": version, "identities": identities}
        self.registry_path.write_text(json.dumps(document), encoding="utf-8")

    def store(self):
        return SQLiteRuntimeStore(self.store_path)

    def host(self, floor=True, tag="original", **kwargs):
        return make_host(
            host_id=HOST, signer=self.signer, store=self.store(), providers={"suspender": SuspendProvider(tag)},
            audit_floor_path=str(self.floor_path) if floor else None, **kwargs,
        )

    def env(self):
        return {
            "PORTMARK_ED25519_PRIVATE_KEY_B64": b64(HOST_KEY),
            "PORTMARK_SIGNING_KEY_ID": self.signer.key_id,
            "PORTMARK_SIGNING_ISSUER": HOST,
        }

    def registry_host(self):
        # A host whose signer is bound to the on-disk, versioned trust registry (registry floor active).
        with patch.dict(os.environ, self.env()):
            return make_host(
                host_id=HOST, store=self.store(), trust_registry_path=str(self.registry_path),
                providers={"suspender": SuspendProvider()}, audit_floor_path=str(self.floor_path),
            )

    def snapshot(self, name):
        target = self.root / f"{name}.sqlite"
        source = sqlite3.connect(self.store_path)
        destination = sqlite3.connect(target)
        try:
            source.backup(destination)
        finally:
            source.close()
            destination.close()
        return target

    def restore(self, snapshot):
        for suffix in ("", "-wal", "-shm"):
            Path(str(self.store_path) + suffix).unlink(missing_ok=True)
        shutil.copyfile(snapshot, self.store_path)

    def verify_cli(self, task_id, floor=True):
        argv = ["portmark", "--host-id", HOST, "--store-path", str(self.store_path), "--trust-registry-path", str(self.registry_path)]
        if floor:
            argv += ["--audit-floor-path", str(self.floor_path)]
        argv += ["verify-audit", "--task-id", task_id]
        stdout = io.StringIO()
        code = 0
        with patch.object(sys, "argv", argv), redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            try:
                cli_main()
            except SystemExit as exit_:
                code = exit_.code
        return code, json.loads(stdout.getvalue())


def start_task(host, goal="floor"):
    envelope = make_demo_envelope(host, goal, "suspender")
    host.signer.seal(envelope)
    result = host.run(envelope)
    assert result.status == "awaiting_input", result.status  # nosec B101 -- test fixture precondition
    return envelope, result


def resume(host, envelope):
    host.signer.seal(envelope)
    return host.run(envelope)


class AuditFloorAttackTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.d = Deployment(self._dir.name)

    def tearDown(self):
        self._dir.cleanup()

    def assertBootRefused(self, code, make=None):
        with self.assertRaises(ValueError) as raised:
            (make or self.d.host)()
        self.assertIn(f"({code})", str(raised.exception))
        return raised.exception

    # -- High #1: the auditor's reproduction ------------------------------------------------------
    def test_restored_older_snapshot_is_refused_at_boot_and_by_verify_audit(self):
        host = self.d.host()
        envelope, first = start_task(host)
        task_id = first.task_id
        snapshot = self.d.snapshot("sequence-1")
        resume(host, envelope)  # the chain advances; the floor advances after the commit
        self.assertEqual(self.d.verify_cli(task_id), (0, self.d.verify_cli(task_id)[1]))
        self.assertEqual(self.d.verify_cli(task_id)[1]["floor_status"], "anchored")

        self.d.restore(snapshot)
        # Without the floor the restored copy still verifies: exactly the finding (documents the limit).
        code, report = self.d.verify_cli(task_id, floor=False)
        self.assertEqual((code, report["status"], report["floor_status"]), (0, "valid", "no-floor"))
        # With the surviving floor: refused at boot and by verify-audit.
        self.assertBootRefused("rolled-back")
        code, report = self.d.verify_cli(task_id)
        self.assertEqual((code, report["status"], report["floor_status"]), (1, "invalid", "rolled-back"))

    def test_a_host_already_running_refuses_to_write_over_a_rolled_back_database(self):
        host = self.d.host()
        envelope, first = start_task(host)
        older_envelope = copy_envelope(envelope, first)  # matches the snapshot's checkpoint generation
        snapshot = self.d.snapshot("before")
        resume(host, envelope)
        head_before = self.d.store().audit_head(first.task_id)
        self.d.restore(snapshot)
        restored_head = self.d.store().audit_head(first.task_id)
        # The replayed older envelope passes the checkpoint compare-and-swap against the RESTORED
        # database, so only the floor's compare-before-use (inside the transaction) can stop it.
        with self.assertRaisesRegex(SecurityError, "rolled back"):
            resume(host, older_envelope)
        self.assertEqual(self.d.store().audit_head(first.task_id), restored_head)  # nothing committed
        self.assertNotEqual(head_before, restored_head)

    # -- Medium #4: trust-registry rollback -------------------------------------------------------
    def test_restoring_an_older_registry_that_still_trusts_a_revoked_key_is_refused(self):
        peer = host_signer(bytes(range(3, 35)), key_id="peer-key", issuer="host:peer")
        peer_entry = {"key_id": peer.key_id, "issuer": "host:peer", "public_key_b64": b64(peer.public_key_bytes()), "allowed_audiences": ["*"]}
        self.d.write_registry(1, extra=[peer_entry])
        old_registry = self.d.registry_path.read_bytes()
        self.d.write_registry(2, extra=[{**peer_entry, "revoked": True}])  # the revocation
        host = self.d.registry_host()
        start_task(host)
        self.assertEqual(LocalFloorWitness(self.d.floor_path, HOST, self.d.signer, self.d.signer).load()["registry"]["version"], 2)

        self.d.registry_path.write_bytes(old_registry)  # restore the pre-revocation registry
        self.assertBootRefused("registry-rolled-back", self.d.registry_host)
        code, report = self.d.verify_cli(start_task_id(self.d))
        self.assertEqual((code, report["floor_status"]), (1, "registry-rolled-back"))

        self.d.write_registry(2, extra=[peer_entry])  # same version, different content
        self.assertBootRefused("registry-forked", self.d.registry_host)
        self.d.write_registry(3, extra=[{**peer_entry, "revoked": True}])  # a NEWER registry is fine
        self.d.registry_host()

    def test_an_unversioned_registry_cannot_be_used_with_a_floor(self):
        self.d.write_registry(0, drop_version=True)
        with self.assertRaisesRegex(ValueError, "VERSIONED trust registry"):
            self.d.registry_host()

    # -- cloned databases, relative to the surviving authoritative floor ------------------------
    def test_a_cloned_database_that_fell_behind_the_floor_is_refused(self):
        host = self.d.host()
        envelope, first = start_task(host)
        clone = self.d.snapshot("clone")
        resume(host, envelope)  # the original moves on; the floor follows it
        self.d.restore(clone)  # run the stale clone against the authoritative floor
        self.assertBootRefused("rolled-back")

    def test_a_clone_that_diverged_on_an_independent_floor_copy_is_refused_as_forked(self):
        host = self.d.host()
        envelope, first = start_task(host)
        clone_db = self.d.snapshot("clone")
        floor_copy = self.d.root / "floor-copy.json"
        shutil.copyfile(self.d.floor_path, floor_copy)
        resume(host, envelope)  # original: event N = X, authoritative floor records X

        # The clone runs on its OWN floor copy (a documented non-detection while separate) ...
        authoritative = self.d.floor_path.read_bytes()
        self.d.restore(clone_db)
        shutil.copyfile(floor_copy, self.d.floor_path)
        clone_host = self.d.host(tag="clone")  # a different decision -> different event content
        clone_envelope = copy_envelope(envelope, first)
        resume(clone_host, clone_envelope)  # clone: event N = Y
        # ... but paired again with the SURVIVING authoritative floor, the divergence is detected.
        self.d.floor_path.write_bytes(authoritative)
        self.assertBootRefused("forked")
        code, report = self.d.verify_cli(first.task_id)
        self.assertEqual((code, report["floor_status"]), (1, "forked"))

    # -- concurrent writers --------------------------------------------------------------------
    def test_concurrent_writers_share_one_floor_without_losing_an_advance(self):
        hosts = [self.d.host() for _ in range(3)]
        task_ids, errors = [], []

        def worker(host):
            try:
                for n in range(4):
                    envelope, first = start_task(host, f"concurrent {n}")
                    resume(host, envelope)
                    task_ids.append(first.task_id)
            except Exception as error:  # noqa: BLE001 -- surfaced below
                errors.append(error)

        threads = [threading.Thread(target=worker, args=(host,)) for host in hosts]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)
        self.assertEqual(errors, [])
        body = LocalFloorWitness(self.d.floor_path, HOST, self.d.signer, self.d.signer).load()
        store = self.d.store()
        for task_id in task_ids:
            head_hash, sequence = store.audit_head(task_id)
            self.assertEqual(body["tasks"][task_id], {"sequence": sequence, "head_hash": head_hash})
        self.assertEqual(len(task_ids), 12)

    # -- crashes around the floor advance --------------------------------------------------------
    def test_commit_failure_after_the_floor_advanced_leaves_the_floor_ahead_and_refused(self):
        # Auditor round 2 (High): the floor now advances BEFORE the commit. If the commit then fails,
        # the floor is ahead of the database -- indistinguishable from "committed, then rolled back"
        # -- so it is refused until an operator resets it, never lowered automatically.
        from portmark.storage import _SQLiteTransaction

        host = self.d.host()
        envelope, first = start_task(host)
        head_before = self.d.store().audit_head(first.task_id)
        original_exit = _SQLiteTransaction.__exit__

        def commit_fails(transaction, exc_type, exc, tb):
            if exc_type is None:
                original_exit(transaction, RuntimeError, RuntimeError("simulated"), None)  # roll back
                raise sqlite3.OperationalError("disk I/O error during commit")
            return original_exit(transaction, exc_type, exc, tb)

        with patch.object(_SQLiteTransaction, "__exit__", commit_fails):
            with self.assertLogs("portmark.host", "CRITICAL") as logs:
                with self.assertRaises(sqlite3.OperationalError):
                    resume(host, envelope)
        self.assertIn("floor is ahead of the database", "".join(logs.output))
        self.assertEqual(self.d.store().audit_head(first.task_id), head_before)  # nothing committed
        witnessed = LocalFloorWitness(self.d.floor_path, HOST, self.d.signer, self.d.signer).witnessed_head(first.task_id)
        self.assertGreater(witnessed[1], head_before[1])  # ...but the floor recorded it
        self.assertBootRefused("rolled-back")
        code, report = self.d.verify_cli(first.task_id)
        self.assertEqual((code, report["floor_status"]), (1, "rolled-back"))
        # Recovery is the explicit operator reset, which accepts the database as it is.
        store = self.d.store()
        store.set_audit_head_verifier(self.d.signer)
        reset_audit_floor(LocalFloorWitness(self.d.floor_path, HOST, self.d.signer, self.d.signer), store, "commit failed after floor write", None, None)
        self.d.host()
        self.assertEqual(self.d.verify_cli(first.task_id)[1]["floor_status"], "anchored")

    def test_the_committed_update_can_no_longer_be_rolled_back_undetected(self):
        # Auditor round 2 reproduction: N -> commit N+1 -> (crash) -> restore N used to boot as
        # anchored. The floor now records N+1 before the commit, so the restored N is refused.
        from portmark.storage import _SQLiteTransaction

        host = self.d.host()
        envelope, first = start_task(host)
        state_n = self.d.snapshot("state-n")
        original_exit = _SQLiteTransaction.__exit__
        crashed = {"once": False}

        def crash_right_after_commit(transaction, exc_type, exc, tb):
            result = original_exit(transaction, exc_type, exc, tb)
            if exc_type is None and not crashed["once"]:
                crashed["once"] = True
                raise KeyboardInterrupt("process died right after the database commit")
            return result

        with patch.object(_SQLiteTransaction, "__exit__", crash_right_after_commit):
            with self.assertRaises(KeyboardInterrupt):
                resume(host, envelope)  # N+1 is committed; nothing after the commit ran
        self.assertGreater(self.d.store().audit_head(first.task_id)[1], sqlite_head(state_n, first.task_id)[1])
        self.d.restore(state_n)  # restore N
        self.assertBootRefused("rolled-back")  # the floor already recorded N+1 before the commit

    def test_a_floor_write_failure_commits_nothing(self):
        host = self.d.host()
        envelope, first = start_task(host)
        head_before = self.d.store().audit_head(first.task_id)
        floor_before = self.d.floor_path.read_bytes()
        with patch.object(LocalFloorWitness, "advance_heads", side_effect=OSError("read-only volume")):
            with self.assertRaises(OSError):
                resume(host, envelope)
        self.assertEqual(self.d.store().audit_head(first.task_id), head_before)  # the transaction rolled back
        self.assertEqual(self.d.floor_path.read_bytes(), floor_before)
        resume(host, envelope)  # writable again: works, and stays anchored
        self.assertEqual(self.d.verify_cli(first.task_id)[1]["floor_status"], "anchored")

    def test_a_floor_behind_the_database_is_adopted_only_after_the_chain_verifies(self):
        host = self.d.host()
        envelope, first = start_task(host)
        floor_before = self.d.floor_path.read_bytes()
        resume(host, envelope)
        self.d.floor_path.write_bytes(floor_before)  # the floor lost its latest write (older copy put back)
        self.d.host()  # restart: the head is ahead, its chain verifies -> adopted
        witnessed = LocalFloorWitness(self.d.floor_path, HOST, self.d.signer, self.d.signer).witnessed_head(first.task_id)
        self.assertEqual(witnessed, self.d.store().audit_head(first.task_id))

    def test_boot_never_adopts_a_forged_head_into_the_floor(self):
        # Auditor round 2 (Medium) reproduction: a stored head raised to a higher sequence with an
        # arbitrary hash used to be adopted into the signed floor at restart.
        host = self.d.host()
        _, first = start_task(host)
        witnessed_before = LocalFloorWitness(self.d.floor_path, HOST, self.d.signer, self.d.signer).witnessed_head(first.task_id)
        with sqlite3_connection(self.d.store_path) as connection:
            connection.execute("UPDATE audit_heads SET head_hash = 'evil-head', sequence = sequence + 1 WHERE task_id = ?", (first.task_id,))
        with self.assertLogs("portmark.witness", "ERROR") as logs:
            self.d.host()
        self.assertIn(f"NOT adopting task {first.task_id}", "".join(logs.output))
        witnessed = LocalFloorWitness(self.d.floor_path, HOST, self.d.signer, self.d.signer).witnessed_head(first.task_id)
        self.assertEqual(witnessed, witnessed_before)  # the floor is not contaminated
        code, report = self.d.verify_cli(first.task_id)
        self.assertEqual((code, report["status"]), (1, "invalid"))

    def test_boot_does_not_adopt_a_head_that_changes_during_verification(self):
        no_floor = make_host(host_id=HOST, signer=self.d.signer, store=self.d.store(), providers={"suspender": SuspendProvider()})
        _, first = start_task(no_floor)  # written before any floor existed: an adoption candidate
        original = SQLiteRuntimeStore.verify_audit_chain_status

        def verify_then_move_head(store, task_id, allow_legacy_anchor=False):
            verdict = original(store, task_id, allow_legacy_anchor=allow_legacy_anchor)
            with sqlite3_connection(store.path) as connection:
                connection.execute("UPDATE audit_heads SET sequence = sequence + 1 WHERE task_id = ?", (task_id,))
            return verdict

        with patch.object(SQLiteRuntimeStore, "verify_audit_chain_status", verify_then_move_head):
            with self.assertLogs("portmark.witness", "ERROR") as logs:
                self.d.host()
        self.assertIn("head changed while it was being verified", "".join(logs.output))
        self.assertIsNone(LocalFloorWitness(self.d.floor_path, HOST, self.d.signer, self.d.signer).witnessed_head(first.task_id))

    def test_a_database_with_a_floor_cannot_be_started_without_it(self):
        self.d.host()
        with self.assertRaisesRegex(ValueError, "has an audit floor"):
            self.d.host(floor=False)

    def test_the_cli_passes_the_floor_path_to_the_host(self):
        # config -> merged_with_args -> make_host(audit_floor_path=...): a CLI-started host must not
        # silently run floorless.
        argv = ["portmark", "--host-id", HOST, "--store-path", str(self.d.store_path), "--trust-registry-path", str(self.d.registry_path),
                "--audit-floor-path", str(self.d.floor_path), "demo", "cli floor"]
        stdout = io.StringIO()
        with patch.dict(os.environ, self.d.env()), patch.object(sys, "argv", argv), redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            cli_main()
        task_id = json.loads(stdout.getvalue())["task_id"]
        body = LocalFloorWitness(self.d.floor_path, HOST, self.d.signer, self.d.signer).load()
        self.assertIsNotNone(body, "the CLI-started host ran without its audit floor")
        self.assertEqual(body["registry"]["version"], 1)
        head_hash, sequence = self.d.store().audit_head(task_id)
        self.assertEqual(body["tasks"][task_id], {"sequence": sequence, "head_hash": head_hash})
        stdout = io.StringIO()
        with patch.dict(os.environ, {**self.d.env(), "PORTMARK_AUDIT_FLOOR_PATH": str(self.d.floor_path)}), \
                patch.object(sys, "argv", argv[:7] + ["demo", "env floor"]), redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            cli_main()
        env_task = json.loads(stdout.getvalue())["task_id"]
        self.assertIn(env_task, LocalFloorWitness(self.d.floor_path, HOST, self.d.signer, self.d.signer).load()["tasks"])

    def test_crash_after_the_floor_advance_needs_no_recovery(self):
        host = self.d.host()
        envelope, first = start_task(host)
        resume(host, envelope)
        self.d.host()  # restart: boot compares every witnessed task and accepts
        self.assertEqual(self.d.verify_cli(first.task_id)[1]["floor_status"], "anchored")

    def test_a_rolled_back_persist_leaves_the_floor_untouched(self):
        host = self.d.host()
        envelope, first = start_task(host)
        stale = copy_envelope(envelope, first)
        resume(host, envelope)
        floor_before = self.d.floor_path.read_bytes()
        with self.assertRaisesRegex(SecurityError, "stale checkpoint generation"):
            resume(host, stale)  # save_checkpoint's CAS refuses -> the transaction rolls back
        self.assertEqual(self.d.floor_path.read_bytes(), floor_before)

    # -- corrupted / deleted floors -------------------------------------------------------------
    def test_corrupted_floor_refuses_boot_and_verification(self):
        host = self.d.host()
        _, first = start_task(host)
        data = bytearray(self.d.floor_path.read_bytes())
        index = data.index(b'"sequence":') + len(b'"sequence":')
        data[index] = ord("9") if data[index] != ord("9") else ord("8")
        self.d.floor_path.write_bytes(bytes(data))
        self.assertBootRefused("floor-corrupt")
        code, report = self.d.verify_cli(first.task_id)
        self.assertEqual((code, report["floor_status"]), (1, "floor-corrupt"))

    def test_deleted_floor_is_refused_never_rebuilt(self):
        host = self.d.host()
        _, first = start_task(host)
        self.d.floor_path.unlink()
        self.assertBootRefused("floor-missing")
        self.assertFalse(self.d.floor_path.exists())
        code, report = self.d.verify_cli(first.task_id)
        self.assertEqual((code, report["floor_status"]), (1, "floor-missing"))

    # -- backup restoration + the operator recovery procedure --------------------------------------
    def test_backup_restore_is_refused_until_an_explicit_operator_reset(self):
        host = self.d.host()
        _, kept = start_task(host, "in the backup")
        backup = self.d.snapshot("nightly")
        epoch_one_floor = self.d.floor_path.read_bytes()
        _, lost = start_task(host, "after the backup")
        self.d.restore(backup)
        self.assertBootRefused("rolled-back")

        base = ["portmark", "--host-id", HOST, "--store-path", str(self.d.store_path), "--trust-registry-path", str(self.d.registry_path),
                "--audit-floor-path", str(self.d.floor_path), "floor-reset", "--reason", "restored nightly backup after disk loss"]
        with patch.dict(os.environ, self.d.env()), patch.object(sys, "argv", base), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                cli_main()  # no --confirm
        self.assertEqual(raised.exception.code, 2)
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, self.d.env()), patch.object(sys, "argv", base + ["--confirm"]), redirect_stdout(stdout), redirect_stderr(stderr):
            cli_main()
        self.assertEqual(json.loads(stdout.getvalue()), {"host_id": HOST, "status": "reset", "epoch": 2})
        self.assertIn("WARNING: audit floor for host:floor was reset to epoch 2", stderr.getvalue())

        self.d.registry_host()  # boots again on the new epoch (the reset recorded the registry)
        body = LocalFloorWitness(self.d.floor_path, HOST, self.d.signer, self.d.signer).load()
        self.assertEqual(body["resets"][0]["reason"], "restored nightly backup after disk loss")
        self.assertIsNotNone(body["resets"][0]["prior_floor_sha256"])
        self.assertIn(kept.task_id, body["tasks"])
        self.assertNotIn(lost.task_id, body["tasks"])
        self.assertEqual(self.d.verify_cli(kept.task_id)[1]["floor_status"], "anchored")
        # The OLD (epoch 1) floor put back after the reset is refused, not trusted.
        self.d.floor_path.write_bytes(epoch_one_floor)
        self.assertBootRefused("epoch-mismatch", self.d.registry_host)

    # -- configuration guards ---------------------------------------------------------------------
    def test_floor_configuration_guards(self):
        with self.assertRaisesRegex(ValueError, "OUTSIDE the store directory"):
            make_host(host_id=HOST, signer=self.d.signer, store=self.d.store(), audit_floor_path=str(self.d.store_path.parent / "floor.json"))
        with self.assertRaisesRegex(ValueError, "durable store"):
            make_host(host_id=HOST, signer=self.d.signer, store=InMemoryRuntimeStore(), audit_floor_path=str(self.d.floor_path))
        with self.assertLogs("portmark.factory", "WARNING") as logs:
            self.d.host(floor=False)
        self.assertIn("will NOT be detected", "".join(logs.output))

    def test_a_task_the_floor_never_witnessed_is_unverifiable(self):
        no_floor_host = self.d.host(floor=False)
        _, before = start_task(no_floor_host, "before the floor existed")
        # Created before the floor: boot adopts it (this host signed it), so it becomes anchored.
        self.d.host()
        self.assertEqual(self.d.verify_cli(before.task_id)[1]["floor_status"], "anchored")
        # A task in the database the floor has never seen (e.g. another host's) is not anchored.
        result = apply_floor(self.d.store().verify_audit_chain_status("ghost"), LocalFloorWitness(self.d.floor_path, HOST, None, self.d.signer),
                             self.d.store(), "ghost", None, None)
        self.assertEqual(result.status, "invalid")  # missing chain stays invalid
        other = self.d.store()
        with patch.object(other, "audit_head", return_value=("h", 1)):
            result = apply_floor(dataclasses.replace(before_result(self.d, before.task_id), status="valid"),
                                 LocalFloorWitness(self.d.floor_path, HOST, None, self.d.signer), other, "never-seen", None, None)
        self.assertEqual((result.status, result.floor_status), ("unverifiable", "not-anchored"))


def sqlite_head(path, task_id):
    connection = sqlite3.connect(path)
    try:
        return connection.execute("SELECT head_hash, sequence FROM audit_heads WHERE task_id = ?", (task_id,)).fetchone()
    finally:
        connection.close()


def before_result(deployment, task_id):
    store = deployment.store()
    store.set_audit_head_verifier(deployment.signer)
    return store.verify_audit_chain_status(task_id)


def start_task_id(deployment):
    store = deployment.store()
    return store.audit_heads_for_host(HOST)[0][0]


def copy_envelope(envelope, first):
    # The suspended envelope as it stood after the first run (for a stale-replay / clone resume).
    import copy

    clone = copy.deepcopy(envelope)
    clone.state.checkpoint_generation = first.checkpoint["checkpoint_generation"]
    return clone


@unittest.skipUnless(os.environ.get("PORTMARK_TEST_POSTGRES_DSN"), "needs a live Postgres (PORTMARK_TEST_POSTGRES_DSN)")
class AuditFloorPostgresTests(unittest.TestCase):
    """The same floor on the PostgreSQL store: marker table, transaction reads, rollback refusal."""

    def setUp(self):
        import secrets

        from portmark.storage import PostgresRuntimeStore

        self.dsn = os.environ["PORTMARK_TEST_POSTGRES_DSN"]
        self.schema = "portmark_floor_" + secrets.token_hex(6)
        self.make_store = lambda: PostgresRuntimeStore(self.dsn, schema=self.schema)
        self._dir = tempfile.TemporaryDirectory()
        self.floor_path = Path(self._dir.name) / "audit-floor.json"
        self.signer = host_signer()

    def tearDown(self):
        import psycopg
        from psycopg import sql

        with psycopg.connect(self.dsn, autocommit=True) as connection:
            connection.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(self.schema)))
        self._dir.cleanup()

    def host(self):
        return make_host(host_id=HOST, signer=self.signer, store=self.make_store(), providers={"suspender": SuspendProvider()},
                         audit_floor_path=str(self.floor_path))

    def test_postgres_store_anchors_and_refuses_a_rolled_back_chain(self):
        from portmark.storage import POSTGRES_SCHEMA_VERSION

        self.assertEqual(POSTGRES_SCHEMA_VERSION, 10)
        host = self.host()
        envelope, first = start_task(host)
        store = self.make_store()
        self.assertEqual(store.audit_floor_marker(HOST), (1, False))
        early_hash, early_sequence = store.audit_head(first.task_id)
        resume(host, envelope)
        head_hash, sequence = store.audit_head(first.task_id)
        self.assertEqual(store.audit_event_hash(first.task_id, sequence - 1), head_hash)
        self.assertIn((first.task_id, head_hash, sequence), store.audit_heads_for_host(HOST))
        witnessed = LocalFloorWitness(self.floor_path, HOST, self.signer, self.signer).witnessed_head(first.task_id)
        self.assertEqual(witnessed, (head_hash, sequence))
        # "Restore" the earlier state in place: drop the later events and put the old head back.
        import psycopg
        from psycopg import sql

        with psycopg.connect(self.dsn, autocommit=True) as connection:
            connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(self.schema)))
            connection.execute("DELETE FROM audit_events WHERE task_id = %s AND sequence >= %s", (first.task_id, early_sequence))
            connection.execute("UPDATE audit_heads SET head_hash = %s, sequence = %s WHERE task_id = %s", (early_hash, early_sequence, first.task_id))
        with self.assertRaises(ValueError) as raised:
            self.host()
        self.assertIn("(rolled-back)", str(raised.exception))


if __name__ == "__main__":
    unittest.main()

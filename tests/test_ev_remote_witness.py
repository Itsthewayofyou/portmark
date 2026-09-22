"""EV-013 part 2 acceptance: the host with a remote witness.

The local audit floor catches a restored DATABASE. It cannot catch a restore of the database AND the floor
together, or two clones of the pair (`test_the_local_floor_alone_accepts_a_whole_pair_restore` pins that
gap; it is the behaviour on main before this change). With the remote witness compared on every commit, a
whole-pair restore and a clone of the pair are both refused, the local floor stays as a second layer, and
an unreachable witness refuses the save without wedging the task (owner decision F1).
"""

import io
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from test_audit_floor import HOST, Deployment, SuspendProvider, copy_envelope, resume, start_task
from witness_fixtures import OPERATOR, Witness, asgi_transport

from portmark import factory
from portmark.cli import main as cli_main
from portmark.remote_witness import WitnessClient, WitnessUnavailable, http_transport, public_key_bytes
from portmark.storage import InMemoryRuntimeStore, SQLiteRuntimeStore
from portmark.witness import FORKED, ROLLED_BACK, FloorError
from portmark.witness_binding import WITNESS_BEHIND, HostWitness, classify_boot


class _Switch:
    """A transport that can be taken down, lose one answer, or be replaced, while the host keeps it."""

    def __init__(self, inner):
        self.inner = inner
        self.down = False
        self.lose_next_answer = False

    def __call__(self, path, payload):
        if self.down:
            raise WitnessUnavailable("the witness is down")
        answer = self.inner(path, payload)
        if self.lose_next_answer:
            self.lose_next_answer = False
            raise WitnessUnavailable("the answer was lost on the way back")
        return answer


class RemoteWitnessHostTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = self._dir.name
        self.d = Deployment(os.path.join(self.root, "host-a"))
        self.w = Witness(os.path.join(self.root, "witness"), extra_hosts=(HOST,))
        self.switch = _Switch(asgi_transport(self.w.app))
        self.registry = {"current": None}

    def tearDown(self):
        self.w.close()
        self._dir.cleanup()

    def binding(self, transport=None):
        client = WitnessClient(transport or self.switch, public_key_bytes(self.w.key), HOST, self.w.keys[HOST])
        return HostWitness(client, HOST, lambda: self.registry["current"])

    def host(self, deployment=None, **kwargs):
        return (deployment or self.d).host(remote_witness=self.binding(), **kwargs)

    def assertBootRefused(self, code, deployment=None):
        with self.assertRaises(ValueError) as raised:
            self.host(deployment)
        self.assertIn(f"({code})", str(raised.exception))
        return str(raised.exception)

    def restore_pair(self, snapshot, floor_bytes, deployment=None):
        deployment = deployment or self.d
        deployment.restore(snapshot)
        deployment.floor_path.write_bytes(floor_bytes)

    def clone_to(self, name):
        """A second copy of this host's database AND floor, in its own directories (same host key)."""
        other = Deployment(os.path.join(self.root, name))
        shutil.copyfile(self.d.snapshot(f"for-{name}"), other.store_path)
        os.chmod(other.store_path, 0o600)
        shutil.copyfile(self.d.floor_path, other.floor_path)
        return other

    def commit_once(self, deployment=None, task_id="one-commit-task", time_floor=0):
        """Exactly ONE witnessed commit, shaped like a real save (one task head, advanced through the same
        HostWitness.advance the save path calls). A task run makes several commits, so the tests that need
        the chain exactly one commit ahead use this; the chain rules (`prev`) do not depend on the head."""
        store = (deployment or self.d).store()
        self.one_commit_sequence = getattr(self, "one_commit_sequence", 0) + 1
        with store.transaction() as transaction:
            self.binding().advance(transaction, {task_id: {"sequence": self.one_commit_sequence, "head_hash": f"h{self.one_commit_sequence}"}}, time_floor)

    def registry_host(self):
        """A host bound to the on-disk trust registry (what `floor-reset` records), with the remote witness."""
        from portmark.security import TrustSource
        from portmark.witness_binding import registry_identity

        trust = TrustSource.from_path(str(self.d.registry_path))
        binding = HostWitness(self.binding().client, HOST, registry_identity(trust))
        with patch.dict(os.environ, self.d.env()):
            return factory.make_host(
                host_id=HOST, store=self.d.store(), trust_registry_path=str(self.d.registry_path),
                audit_floor_path=str(self.d.floor_path), remote_witness=binding, providers={"suspender": SuspendProvider()},
            )

    def remote_state(self):
        return self.binding(asgi_transport(self.w.app)).state()

    # -- every commit is witnessed -------------------------------------------------------------------
    def test_every_save_is_witnessed_in_the_same_commit(self):
        host = self.host()
        self.assertIn("portmark_remote_witness_active 1", host.metrics.prometheus_text())
        envelope, first = start_task(host)
        # A run commits several times (admission, then the suspension); every commit is one advance, and the
        # database always names the witness's newest (pending) receipt, the one before it confirmed.
        receipt = self.d.store().witness_receipt(HOST)
        self.assertEqual(self.remote_state()["pending"], {"host_seq": receipt[0], "receipt_hash": receipt[1]})
        self.assertEqual(len(self.w.log.log_rows(HOST)), receipt[0])
        resume(host, envelope)
        second = self.d.store().witness_receipt(HOST)
        state = self.remote_state()
        self.assertGreater(second[0], receipt[0])
        self.assertEqual(state["pending"], {"host_seq": second[0], "receipt_hash": second[1]})
        self.assertEqual(state["confirmed"]["host_seq"], second[0] - 1)
        # The witnessed head is the task's audit head.
        task = self.binding(asgi_transport(self.w.app)).client.state(HOST, first.task_id).body["task"]
        head_hash, sequence = self.d.store().audit_head(first.task_id)
        self.assertEqual(task["pending"], {"sequence": sequence, "head_hash": head_hash})
        other = Deployment(os.path.join(self.root, "no-remote"))
        self.assertIn("portmark_remote_witness_active 0", other.host().metrics.prometheus_text())

    # -- the gap, and its closure ---------------------------------------------------------------------
    def test_the_local_floor_alone_accepts_a_whole_pair_restore(self):
        # The behaviour on main (and without a remote witness): restoring the database AND the floor
        # together passes every local check. This is exactly what EV-013 reports.
        host = self.d.host()
        envelope, first = start_task(host)
        snapshot, floor_bytes = self.d.snapshot("pair"), self.d.floor_path.read_bytes()
        resume(host, envelope)
        resume(host, envelope)
        self.restore_pair(snapshot, floor_bytes)
        restored = self.d.host()  # boots
        self.assertEqual(resume(restored, copy_envelope(envelope, first)).status, "awaiting_input")  # and writes

    def test_a_whole_pair_restore_is_refused(self):
        host = self.host()
        envelope, first = start_task(host)
        snapshot, floor_bytes = self.d.snapshot("pair"), self.d.floor_path.read_bytes()
        resume(host, envelope)
        resume(host, envelope)
        self.restore_pair(snapshot, floor_bytes)
        self.assertBootRefused(ROLLED_BACK)
        # Even a host that was already running (and so skipped the boot check) cannot write over it.
        with self.assertRaises(FloorError) as caught:
            resume(host, copy_envelope(envelope, first))
        self.assertIn(caught.exception.code, (ROLLED_BACK, "rolled-back"))

    def test_a_restore_that_loses_only_the_newest_unconfirmed_commit_still_boots(self):
        # The documented limit: the newest advance is pending until the next one confirms it, so a restore
        # to exactly the last confirmed state loses that ONE commit without detection.
        start_task(self.host())
        snapshot, floor_bytes = self.d.snapshot("pair"), self.d.floor_path.read_bytes()
        self.commit_once()  # one more commit, then the restore loses it
        self.restore_pair(snapshot, floor_bytes)
        self.host()  # boots: the lost commit was never confirmed
        self.commit_once()
        self.commit_once()  # two commits past the snapshot: now a restore is caught
        self.restore_pair(snapshot, floor_bytes)
        self.assertBootRefused(ROLLED_BACK)

    def test_two_clones_of_the_pair_are_refused(self):
        original = self.host()
        envelope, first = start_task(original)
        clone_dir = self.clone_to("host-b")
        clone = self.host(clone_dir, tag="clone")  # boots: same last receipt, nothing tells them apart yet
        self.commit_once()  # the original commits once ...
        resume(clone, copy_envelope(envelope, first))  # ... the clone builds on the same receipt: discards it
        with self.assertRaises(FloorError) as caught:
            resume(original, envelope)  # the original's next commit is refused
        self.assertEqual(caught.exception.code, FORKED)
        self.assertBootRefused(FORKED)  # restarting it is refused too
        self.assertEqual(resume(clone, _reseal(clone_dir, envelope)).status, "awaiting_input")  # the clone goes on

    def test_a_running_clone_is_refused_at_its_next_save_after_the_other_copy_runs(self):
        # Real runs only (no synthetic commits): both copies are up; the original runs a task to its next
        # suspension (several commits), so the clone's next save builds on an OLD receipt.
        original = self.host()
        envelope, first = start_task(original)
        clone_dir = self.clone_to("host-b")
        clone = self.host(clone_dir, tag="clone")
        resume(original, envelope)
        with self.assertRaises(FloorError) as caught:
            resume(clone, copy_envelope(envelope, first))
        self.assertEqual(caught.exception.code, ROLLED_BACK)
        self.assertEqual(resume(original, envelope).status, "awaiting_input")  # the original goes on

    def test_a_stale_clone_is_refused_at_boot(self):
        original = self.host()
        envelope, _ = start_task(original)
        clone_dir = self.clone_to("host-b")
        resume(original, envelope)
        resume(original, envelope)
        self.assertBootRefused(ROLLED_BACK, clone_dir)

    def test_the_local_floor_still_catches_a_database_only_restore(self):
        host = self.host()
        envelope, _ = start_task(host)
        snapshot = self.d.snapshot("db-only")
        resume(host, envelope)
        resume(host, envelope)
        self.d.restore(snapshot)  # the floor file survives
        message = self.assertBootRefused(ROLLED_BACK)
        self.assertIn("audit floor", message)  # the second layer answered first

    # -- F1: an unavailable witness refuses the save, and never wedges it ------------------------------
    def test_an_unreachable_witness_refuses_the_save_and_commits_nothing(self):
        host = self.host()
        envelope, first = start_task(host)
        store = self.d.store()
        before = (store.audit_head(first.task_id), store.witness_receipt(HOST), store.load_checkpoint(first.task_id)["checkpoint_generation"])
        self.switch.down = True
        with self.assertRaises(FloorError) as caught:
            resume(host, envelope)
        self.assertEqual(caught.exception.code, "witness-unavailable")
        after = (store.audit_head(first.task_id), store.witness_receipt(HOST), store.load_checkpoint(first.task_id)["checkpoint_generation"])
        self.assertEqual(after, before)
        self.switch.down = False
        self.assertEqual(resume(host, envelope).status, "awaiting_input")  # the same save goes through

    def test_a_lost_answer_rolls_the_save_back_and_the_next_save_discards_it(self):
        host = self.host()
        envelope, _ = start_task(host)
        receipt = self.d.store().witness_receipt(HOST)
        self.switch.lose_next_answer = True  # the witness records the advance; the host never hears back
        with self.assertRaises(FloorError):
            resume(host, envelope)
        self.assertEqual(self.d.store().witness_receipt(HOST), receipt)  # rolled back
        self.assertEqual(resume(host, envelope).status, "awaiting_input")  # not wedged
        # The retry repeats the request (the witness answers the SAME receipt) or builds anew (the lost
        # advance is discarded); either way the database now names the witness's newest receipt.
        self.assertEqual(self.d.store().witness_receipt(HOST)[1], self.remote_state()["pending"]["receipt_hash"])

    def test_a_stalled_witness_call_is_refused_the_same_way_at_the_call_cap(self):
        from portmark import remote_witness

        host = self.host()
        envelope, first = start_task(host)
        head = self.d.store().audit_head(first.task_id)
        release = threading.Event()

        def stalled(*args, **kwargs):
            release.wait(30)
            raise OSError("DNS is down")

        self.switch.inner = http_transport("http://localhost:9", timeout=0.05)
        try:
            with patch("socket.getaddrinfo", stalled):
                messages = []
                for _ in range(remote_witness.MAX_OUTSTANDING_CALLS + 2):
                    with self.assertRaises(FloorError) as caught:
                        resume(host, envelope)
                    self.assertEqual(caught.exception.code, "witness-unavailable")
                    messages.append(str(caught.exception))
            self.assertTrue(any("still stuck" in message for message in messages))  # the cap path, refused alike
            self.assertEqual(self.d.store().audit_head(first.task_id), head)
        finally:
            release.set()
        self.assertIsNotNone(socket.getaddrinfo)

    # -- the witness's other rules reach the host ------------------------------------------------------
    def test_an_older_trust_registry_is_refused_by_the_witness(self):
        self.registry["current"] = {"version": 2, "digest": "d2"}
        host = self.host()
        envelope, _ = start_task(host)
        resume(host, envelope)  # confirms version 2
        self.registry["current"] = {"version": 1, "digest": "d1"}
        with self.assertRaises(FloorError) as caught:
            resume(host, envelope)
        self.assertEqual(caught.exception.code, "registry-rolled-back")

    # -- configuration --------------------------------------------------------------------------------
    def test_a_database_with_a_receipt_cannot_start_without_its_witness(self):
        start_task(self.host())
        with self.assertRaisesRegex(ValueError, "holds a remote-witness receipt"):
            self.d.host()

    def test_configuration_guards(self):
        with self.assertRaisesRegex(ValueError, "durable store"):
            factory.make_host(host_id=HOST, signer=self.d.signer, store=InMemoryRuntimeStore(), remote_witness=self.binding(),
                              allow_ephemeral_signing_key=True)
        default = HostWitness(self.binding().client, factory.HOST_ID)
        with self.assertRaisesRegex(ValueError, "unique host id"):
            factory._open_remote_witness(default, self.d.store(), factory.HOST_ID, production=True)
        with self.assertRaisesRegex(ValueError, "binding is for"):
            factory._open_remote_witness(self.binding(), self.d.store(), "host:other", production=False)
        self.switch.down = True
        with self.assertRaisesRegex(ValueError, r"\(witness-unavailable\)"):
            self.host()  # fail closed at boot too

    def test_the_witness_time_floor_feeds_the_boot_clock_check(self):
        host = self.host()
        envelope, _ = start_task(host)
        resume(host, envelope)
        floor = factory._HighestTimeFloor(None, 5_000)
        self.assertEqual(floor.witnessed_time_floor(), 5_000)

    # -- operator tools --------------------------------------------------------------------------------
    def clients(self, down=False):
        def make(signer, key_file=None, environ=None):
            transport = self.switch if not down else _Switch(asgi_transport(self.w.app))
            if down:
                transport.down = True
            return WitnessClient(transport, public_key_bytes(self.w.key), signer, self.w.keys[signer])

        return patch("portmark.witness_binding.client_from_environment", make)

    def test_verify_audit_reports_the_remote_status(self):
        host = self.host()
        envelope, first = start_task(host)
        snapshot, floor_bytes = self.d.snapshot("pair"), self.d.floor_path.read_bytes()
        resume(host, envelope)
        with self.clients():
            code, report = self.d.verify_cli(first.task_id)
        self.assertEqual((code, report["status"], report["remote_status"]), (0, "valid", "anchored"))
        with self.clients(down=True):
            code, report = self.d.verify_cli(first.task_id)
        self.assertEqual((code, report["status"], report["remote_status"]), (2, "unverifiable", "witness-unavailable"))
        resume(host, envelope)
        self.restore_pair(snapshot, floor_bytes)
        with self.clients():
            code, report = self.d.verify_cli(first.task_id)
        # The local floor was restored with the database, so it says anchored; the witness does not.
        self.assertEqual((code, report["status"], report["floor_status"], report["remote_status"]), (1, "invalid", "anchored", ROLLED_BACK))
        # The same restored pair with the witness settings LEFT OUT: the database holds a receipt, so remote
        # witnessing was on, and without the witness the rollback cannot be ruled out (the review's repro).
        code, report = self.d.verify_cli(first.task_id)
        self.assertEqual((code, report["status"], report["remote_status"]), (2, "unverifiable", "witness-unconfigured"))
        # A database that never had a witness is unchanged: no-remote, and the result stands.
        plain = Deployment(os.path.join(self.root, "never-witnessed"))
        _, plain_task = start_task(plain.host())
        code, report = plain.verify_cli(plain_task.task_id)
        self.assertEqual((code, report["status"], report["remote_status"]), (0, "valid", "no-remote"))

    def test_floor_reset_with_an_operator_key_rebaselines_the_witness(self):
        host = self.host()
        envelope, first = start_task(host)
        snapshot, floor_bytes = self.d.snapshot("pair"), self.d.floor_path.read_bytes()
        resume(host, envelope)
        resume(host, envelope)
        self.restore_pair(snapshot, floor_bytes)
        self.assertBootRefused(ROLLED_BACK)
        base = ["portmark", "--host-id", HOST, "--store-path", str(self.d.store_path), "--trust-registry-path", str(self.d.registry_path),
                "--audit-floor-path", str(self.d.floor_path), "floor-reset", "--reason", "restored the pair after disk loss", "--confirm"]
        # A local reset alone does not satisfy the witness.
        stdout = io.StringIO()
        with patch.dict(os.environ, self.d.env()), patch.object(sys, "argv", base), redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            cli_main()
        self.assertEqual(json.loads(stdout.getvalue())["remote_status"], "not-rebaselined")
        with self.assertRaisesRegex(ValueError, r"remote witness refused to start \(rolled-back\)"):
            self.registry_host()
        # With the operator key, the witness is rebaselined too.
        key_file = os.path.join(self.root, "operator.key")
        stdout, stderr = io.StringIO(), io.StringIO()
        with self.clients(), patch.dict(os.environ, self.d.env()), redirect_stdout(stdout), redirect_stderr(stderr), \
                patch.object(sys, "argv", base + ["--operator-id", OPERATOR, "--operator-key-file", key_file]):
            cli_main()
        result = json.loads(stdout.getvalue())
        self.assertEqual((result["remote_status"], result["remote_epoch"]), ("rebaselined", 2))
        self.assertIn("rebaselined to epoch 2", stderr.getvalue())
        restored = self.registry_host()
        self.assertEqual(resume(restored, copy_envelope(envelope, first)).status, "awaiting_input")
        # The host cannot rebaseline itself: without the operator key the witness refuses it.
        with patch("portmark.witness_binding.client_from_environment",
                   lambda signer, key_file=None, environ=None: WitnessClient(self.switch, public_key_bytes(self.w.key), signer, self.w.keys[HOST])), \
                patch.dict(os.environ, self.d.env()), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()), \
                patch.object(sys, "argv", base + ["--operator-id", OPERATOR, "--operator-key-file", key_file]):
            with self.assertRaises(SystemExit) as raised:
                cli_main()
        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(json.loads(out.getvalue())["remote_code"], "unauthenticated")

    # -- review round 1 on #111 ------------------------------------------------------------------------
    def cli(self, *argv, witness="up"):
        """Run `portmark` against this deployment. witness: "up", "down", or None (no witness settings)."""
        full = ["portmark", "--host-id", HOST, "--store-path", str(self.d.store_path), "--trust-registry-path", str(self.d.registry_path),
                "--audit-floor-path", str(self.d.floor_path), *argv]
        stdout, stderr, code = io.StringIO(), io.StringIO(), 0
        with patch.dict(os.environ, self.d.env()), patch.object(sys, "argv", full), redirect_stdout(stdout), redirect_stderr(stderr):
            context = self.clients(down=witness == "down") if witness is not None else patch.dict(os.environ, {})
            with context:
                try:
                    cli_main()
                except SystemExit as exit_:
                    code = exit_.code
        text = stdout.getvalue()
        return code, (json.loads(text) if text.strip() else None), stderr.getvalue()

    def local_floors(self):
        return self.d.store().time_floor(), self.d.floor_path.read_bytes()

    def test_time_floor_reset_lowers_the_witness_floor_and_the_host_starts_again(self):
        import time

        host = self.host()
        envelope, _ = start_task(host)
        now, ahead = int(time.time()), int(time.time()) + 100_000
        self.commit_once(time_floor=ahead)  # a wrong clock moved the witnessed floor far ahead ...
        self.commit_once(time_floor=ahead)  # ... (the witness takes a floor when the next advance confirms it)
        self.assertEqual(self.remote_state()["time_floor"], ahead)
        with self.assertRaisesRegex(ValueError, "time floor refused to start") as raised:
            self.host()
        self.assertIn("--operator-key-file", str(raised.exception))  # the boot message names the working command
        key_file = os.path.join(self.root, "operator.key")
        reset = ("time-floor", "reset", "--to", str(now), "--reason", "the clock jumped ahead", "--confirm")
        # Without the operator key: refused, and NOTHING changed (the local floors are not lowered alone).
        before = self.local_floors()
        code, _, err = self.cli(*reset)
        self.assertEqual(code, 2)
        self.assertIn(f"time floor of {ahead}", err)
        self.assertEqual(self.local_floors(), before)
        # With it: the local floors AND the witness's floor are lowered, and the host starts again.
        code, result, err = self.cli(*reset, "--operator-id", OPERATOR, "--operator-key-file", key_file)
        self.assertEqual((code, result["status"], result["remote_status"], result["remote_epoch"]), (0, "reset", "rebaselined", 2))
        self.assertEqual(self.remote_state()["time_floor"], now)
        code, shown, _ = self.cli("time-floor", "show")
        self.assertEqual((shown["database_floor"], shown["remote_floor"]), (now, now))
        restarted = self.registry_host()
        self.assertEqual(resume(restarted, envelope).status, "awaiting_input")
        # Once the witness floor is not above --to, the witness is left alone.
        code, result, _ = self.cli("time-floor", "reset", "--to", str(now + 5), "--reason", "again", "--confirm")
        self.assertEqual((code, result["remote_status"]), (0, "unchanged"))

    def test_time_floor_reset_refuses_before_any_change_when_the_witness_is_missing_or_disagrees(self):
        import time

        host = self.host()
        envelope, _ = start_task(host)
        snapshot, floor_bytes = self.d.snapshot("pair"), self.d.floor_path.read_bytes()
        resume(host, envelope)
        resume(host, envelope)
        key_file = os.path.join(self.root, "operator.key")
        reset = ("time-floor", "reset", "--to", str(int(time.time())), "--reason", "clock", "--confirm",
                 "--operator-id", OPERATOR, "--operator-key-file", key_file)
        before = self.local_floors()
        # A database with a receipt, but no witness settings: the witness's own floor would be left behind.
        code, _, err = self.cli(*reset[:7], witness=None)
        self.assertEqual(code, 2)
        self.assertIn("holds a remote-witness receipt", err)
        self.assertEqual(self.local_floors(), before)
        # The witness is down: refused before anything local changes.
        code, result, _ = self.cli(*reset, witness="down")
        self.assertEqual((code, result["remote_code"]), (1, "witness-unavailable"))
        self.assertEqual(self.local_floors(), before)
        # A restored pair: a time-floor rebaseline would take its heads as they are; floor-reset is the way.
        self.restore_pair(snapshot, floor_bytes)
        before = self.local_floors()
        code, result, _ = self.cli(*reset)
        self.assertEqual((code, result["remote_code"]), (1, ROLLED_BACK))
        self.assertIn("floor-reset", result["note"])
        self.assertEqual(self.local_floors(), before)

    def test_floor_reset_asks_the_witness_before_the_local_reset(self):
        host = self.host()
        envelope, _ = start_task(host)
        resume(host, envelope)
        key_file = os.path.join(self.root, "operator.key")
        before = self.d.floor_path.read_bytes()
        code, result, _ = self.cli("floor-reset", "--reason", "r", "--confirm", "--operator-id", OPERATOR, "--operator-key-file", key_file,
                                   witness="down")
        self.assertEqual((code, result["remote_code"]), (1, "witness-unavailable"))
        self.assertEqual(self.d.floor_path.read_bytes(), before)  # the local floor was not reset

    def test_a_rebaseline_larger_than_one_request_goes_in_pages(self):
        import hashlib

        from portmark.remote_witness import MAX_HEADS, MAX_REQUEST_BYTES
        from portmark.witness_server import fold_log

        operator = WitnessClient(self.switch, public_key_bytes(self.w.key), OPERATOR, self.w.keys[OPERATOR])
        store = self.d.store()
        short = {f"task-{index:05d}": {"sequence": index + 1, "head_hash": hashlib.sha256(str(index).encode()).hexdigest()}
                 for index in range(MAX_HEADS)}
        long = {("t" * 505) + f"{index:07d}": {"sequence": 1, "head_hash": "h" * 512} for index in range(1_200)}
        tiny = {f"{index:05d}": {"sequence": 1, "head_hash": "h"} for index in range(2 * MAX_HEADS)}  # > MAX_HEADS fit in the bytes
        for epoch, heads, one_request in ((2, short, "too-large"), (3, long, "too-large"), (4, tiny, "malformed")):
            # One request cannot carry these heads: too many bytes (the review measured 1,070,385 for the short
            # ones; refused before it is sent), or more than MAX_HEADS heads (the witness refuses it) ...
            try:
                answer = operator.rebaseline(HOST, None, "one request", heads, None, 0)  # the shape is judged first
                refused, message = (answer.body["code"], "") if answer.kind == "refusal" else (None, "")
            except FloorError as error:
                refused, message = error.code, str(error)
            self.assertEqual(refused, one_request)
            if one_request == "too-large":
                self.assertIn(str(MAX_REQUEST_BYTES), message)
            # ... the rebaseline sends them in pages, and the witness ends up holding every one.
            self.assertEqual(self.binding().rebaseline(operator, store, heads, "restore", None, 0), epoch)
            state, confirmed = fold_log(self.w.log, HOST)
            witnessed = {**confirmed, **(state.pending.heads if state.pending is not None else {})}
            self.assertEqual(witnessed, heads)
            self.assertEqual(store.witness_receipt(HOST)[1], state.last_hash)
            self.binding().check_boot(store)  # the database names the witness's newest receipt


def _reseal(deployment, envelope):
    """The clone's current envelope: the task's checkpoint generation as the clone's own database holds it."""
    import copy

    fresh = copy.deepcopy(envelope)
    fresh.state.checkpoint_generation = deployment.store().load_checkpoint(envelope.state.task_id)["checkpoint_generation"]
    return fresh


class BootTableTests(unittest.TestCase):
    """classify_boot, cell by cell (the table in witness_binding's docstring)."""

    C, P = {"host_seq": 4, "receipt_hash": "c"}, {"host_seq": 5, "receipt_hash": "p"}

    def verdict(self, database, confirmed, pending):
        result = classify_boot(database, {"confirmed": confirmed, "pending": pending})
        return None if result is None else result[0]

    def test_every_cell(self):
        C, P = self.C, self.P
        genesis_pending = {"host_seq": 1, "receipt_hash": "g"}
        cases = [
            # witness empty
            (None, None, None, None),
            ((3, "x"), None, None, WITNESS_BEHIND),
            # confirmed only
            (None, C, None, ROLLED_BACK),
            ((4, "c"), C, None, None),
            ((3, "x"), C, None, ROLLED_BACK),
            ((5, "x"), C, None, WITNESS_BEHIND),
            ((4, "x"), C, None, FORKED),
            # confirmed + pending
            (None, None, genesis_pending, None),  # a first advance that never committed
            ((1, "g"), None, genesis_pending, None),
            ((1, "x"), None, genesis_pending, FORKED),
            ((2, "x"), None, genesis_pending, WITNESS_BEHIND),
            (None, C, P, ROLLED_BACK),
            ((4, "c"), C, P, None),  # a lost commit: the next save discards the pending one
            ((5, "p"), C, P, None),  # committed, not confirmed yet
            ((3, "x"), C, P, ROLLED_BACK),
            ((4, "x"), C, P, FORKED),
            ((5, "x"), C, P, FORKED),  # a clone committed a different advance at that position
            ((6, "x"), C, P, WITNESS_BEHIND),
        ]
        for database, confirmed, pending, expected in cases:
            self.assertEqual(self.verdict(database, confirmed, pending), expected, (database, confirmed, pending))


class ReceiptStorageTests(unittest.TestCase):
    """The receipt row lives and dies with the save transaction, on every store."""

    def check(self, store):
        self.assertIsNone(store.witness_receipt(HOST))
        with store.transaction() as transaction:
            self.assertIsNone(transaction.witness_receipt(HOST))
            transaction.store_witness_receipt(HOST, 1, "a" * 64, "{}")
            self.assertEqual(transaction.witness_receipt(HOST), (1, "a" * 64))
        self.assertEqual(store.witness_receipt(HOST), (1, "a" * 64))
        with self.assertRaises(RuntimeError):
            with store.transaction() as transaction:
                transaction.store_witness_receipt(HOST, 2, "b" * 64, "{}")
                raise RuntimeError("the save failed")
        self.assertEqual(store.witness_receipt(HOST), (1, "a" * 64))  # rolled back with the save
        store.set_witness_receipt(HOST, 9, "c" * 64, "{}")
        self.assertEqual(store.witness_receipt(HOST), (9, "c" * 64))
        self.assertIsNone(store.witness_receipt("host:other"))

    def test_in_memory(self):
        self.check(InMemoryRuntimeStore())

    def test_sqlite(self):
        with tempfile.TemporaryDirectory() as root:
            self.check(SQLiteRuntimeStore(os.path.join(root, "s.sqlite")))

    @unittest.skipUnless(os.environ.get("PORTMARK_TEST_POSTGRES_DSN"), "needs PORTMARK_TEST_POSTGRES_DSN")
    def test_postgres(self):
        import uuid

        from portmark.storage import PostgresRuntimeStore

        schema = "ev013_" + uuid.uuid4().hex[:12]
        store = PostgresRuntimeStore(os.environ["PORTMARK_TEST_POSTGRES_DSN"], schema=schema)
        self.check(store)


if __name__ == "__main__":
    unittest.main()

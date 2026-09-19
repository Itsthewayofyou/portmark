"""Section 12 PR B: capacity and retention (#4, owner decision D2) and clock rollback (#6, D3).

D3 test matrix (the owner's list): restart, concurrent advancement, backward jump, forward jump (the
whole lockout-and-recovery chain), tolerance boundaries, old schemas, and rollback of an older database
snapshot. D2: dry run by default, explicit apply, counts plus oldest/newest, bounded batches, legacy rows
without an expiry refused, pending/dead migrations kept, no VACUUM, a maintenance record per prune.
"""

import contextlib
import io
import json
import logging
import os
import secrets
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from portmark import _clock, storage
from portmark._clock import ClockRollbackError, TimeFloorError, TrustedClock, check_time_floor
from portmark.factory import make_demo_envelope, make_host
from portmark.maintenance import parse_cutoff, prune_cutoffs, reset_time_floor, run_prune
from portmark.security import SecurityError, canonical_json
from portmark.storage import (
    MAX_ADMIN_PAGE_SIZE,
    MAX_CLAIM_LIMIT,
    MAX_PRUNE_BATCH,
    TIME_FLOOR_CADENCE_SECONDS,
    InMemoryRuntimeStore,
    PostgresRuntimeStore,
    SQLiteRuntimeStore,
)
from portmark.witness import AUDIT_FLOOR_TYPE, LocalFloorWitness
from test_audit_floor import HOST, Deployment, host_signer
from test_section11_migrations import build_at_version

TOLERANCE = 300
PG_DSN = os.environ.get("PORTMARK_TEST_POSTGRES_DSN")
try:
    import psycopg  # noqa: F401

    HAVE_PSYCOPG = True
except ImportError:
    HAVE_PSYCOPG = False


class FakeTime:
    """A wall clock that can jump and a monotonic clock that only moves forward."""

    def __init__(self, wall: float) -> None:
        self.wall = float(wall)
        self.mono = 1000.0

    def advance(self, seconds: float) -> None:  # real time passing: both move
        self.wall += seconds
        self.mono += seconds

    def jump(self, seconds: float) -> None:  # the wall clock is set; monotonic does not move
        self.wall += seconds

    def clock(self, tolerance: int = TOLERANCE) -> TrustedClock:
        return TrustedClock(tolerance, wall=lambda: self.wall, monotonic=lambda: self.mono)


def _envelope_at(host, fake: "FakeTime", provider: str = "suspender"):
    """A demo envelope whose permit is ISSUED at the fake wall time (issuance is agent-side and uses the
    plain wall clock; the host then judges its expiry with the trusted clock)."""
    with patch("portmark.factory.time") as factory_time:
        factory_time.time.return_value = fake.wall
        return make_demo_envelope(host, "research Telescript", provider)


def _sqlite_store(root: Path) -> SQLiteRuntimeStore:
    (root / "db").mkdir(parents=True, exist_ok=True)
    return SQLiteRuntimeStore(root / "db" / "runtime.sqlite")


def _advance(store, now: int):
    with store.transaction() as transaction:
        return transaction.advance_time_floor(now)


class TrustedClockTests(unittest.TestCase):
    """In-process detection (D3): a monotonic baseline catches wall-clock jumps."""

    def test_backward_jump_beyond_tolerance_fails_closed_and_stays_failed(self):
        fake = FakeTime(2_000_000_000)
        clock = fake.clock()
        self.assertEqual(clock.now(), 2_000_000_000)
        fake.jump(-(TOLERANCE + 1))
        with self.assertRaises(ClockRollbackError):
            clock.now()
        fake.jump(TOLERANCE + 1)  # the clock is put back: still refused until a restart re-judges it
        with self.assertRaises(ClockRollbackError):
            clock.now()

    def test_tolerance_boundaries(self):
        for drift, outcome in ((-TOLERANCE, "ok"), (-(TOLERANCE + 1), "rollback"), (TOLERANCE, "ok"), (TOLERANCE + 1, "forward")):
            with self.subTest(drift=drift):
                fake = FakeTime(2_000_000_000)
                clock = fake.clock()
                clock.now()
                fake.jump(drift)
                if outcome == "rollback":
                    with self.assertRaises(ClockRollbackError):
                        clock.now()
                    continue
                self.assertEqual(clock.now(), int(fake.wall))
                self.assertEqual(clock.forward_jumps, 1 if outcome == "forward" else 0)

    def test_forward_jump_is_surfaced_once_as_log_and_metric(self):
        fake = FakeTime(2_000_000_000)
        clock = fake.clock()
        host = make_host(None)
        clock.on_forward_jump(host.metrics.note_clock_forward_jump)
        fake.jump(10 * TOLERANCE)
        with self.assertLogs("portmark._clock", level="CRITICAL") as logs:
            clock.now()
        self.assertIn("jumped FORWARD", "\n".join(logs.output))
        clock.now()  # re-based: the same jump is not reported twice
        self.assertIn('name="clock.forward_jumps"} 1', host.metrics.prometheus_text())

    def test_security_decisions_use_the_trusted_clock(self):
        fake = FakeTime(time.time())
        clock = fake.clock()
        host = make_host(None)
        envelope = make_demo_envelope(host, "research Telescript")
        with patch.object(_clock, "_default_clock", clock):
            host.policy.effective_permit(envelope.manifest, envelope.permit)  # fine now
            fake.jump(-(TOLERANCE + 1))
            with self.assertRaises(ClockRollbackError):
                host.policy.effective_permit(envelope.manifest, envelope.permit)

    def test_tolerance_setting_is_bounded(self):
        for bad in ("0", "-5", "3601", "x"):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                _clock.clock_tolerance_from_environment({"PORTMARK_CLOCK_TOLERANCE_SECONDS": bad})
        self.assertEqual(_clock.clock_tolerance_from_environment({}), 300)
        self.assertEqual(_clock.clock_tolerance_from_environment({"PORTMARK_CLOCK_TOLERANCE_SECONDS": "60"}), 60)


class TimeFloorStoreTests(unittest.TestCase):
    """The durable floor in each embedded store: monotonic, cadence-bound, survives restart."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)

    def tearDown(self):
        self._dir.cleanup()

    def stores(self):
        return (("memory", InMemoryRuntimeStore()), ("sqlite", _sqlite_store(self.root)))

    def test_advance_is_monotonic_and_at_most_once_per_cadence(self):
        for name, store in self.stores():
            with self.subTest(store=name):
                base = store.time_floor() + 10_000
                self.assertEqual(_advance(store, base), base)
                self.assertIsNone(_advance(store, base + TIME_FLOOR_CADENCE_SECONDS - 1))  # within the cadence
                self.assertIsNone(_advance(store, base - 5_000))  # never lowered
                self.assertEqual(store.time_floor(), base)
                self.assertEqual(_advance(store, base + TIME_FLOOR_CADENCE_SECONDS), base + TIME_FLOOR_CADENCE_SECONDS)

    def test_a_rolled_back_transaction_does_not_keep_its_advance(self):
        for name, store in self.stores():
            with self.subTest(store=name):
                before = store.time_floor()
                with self.assertRaises(RuntimeError):
                    with store.transaction() as transaction:
                        transaction.advance_time_floor(before + 100_000)
                        raise RuntimeError("roll back")
                self.assertEqual(store.time_floor(), before)

    def test_restart_keeps_the_floor_and_start_up_refuses_a_clock_behind_it(self):
        store = _sqlite_store(self.root)
        _advance(store, 2_000_000_000)
        reopened = SQLiteRuntimeStore(self.root / "db" / "runtime.sqlite")  # a restart
        self.assertEqual(reopened.time_floor(), 2_000_000_000)
        with self.assertRaises(TimeFloorError) as raised:
            check_time_floor(reopened, None, FakeTime(2_000_000_000 - TOLERANCE - 1).clock())
        self.assertEqual(raised.exception.code, "clock-behind-floor")
        check_time_floor(reopened, None, FakeTime(2_000_000_000 - TOLERANCE).clock())  # the boundary itself is accepted

    def test_concurrent_advancement_never_lowers_the_floor(self):
        path = self.root / "db" / "runtime.sqlite"
        _sqlite_store(self.root)
        values = [2_000_000_000 + TIME_FLOOR_CADENCE_SECONDS * index for index in range(40)]
        order = list(values)
        secrets.SystemRandom().shuffle(order)
        errors = []

        def worker(value):
            try:
                _advance(SQLiteRuntimeStore(path), value)
            except Exception as error:  # noqa: BLE001 -- collected and asserted below
                errors.append(error)

        threads = [threading.Thread(target=worker, args=(value,)) for value in order]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(errors, [])
        # Whatever the interleaving, the floor is at least the largest value that ran last and never went down:
        # the final value is the maximum written, because every write only raises it.
        self.assertEqual(SQLiteRuntimeStore(path).time_floor(), max(values))


class ForwardJumpLockoutChainTests(unittest.TestCase):
    """The owner's forward-jump sequence, end to end: jump -> floor follows -> clock corrected -> start-up
    refused -> operator reset with a reason -> start-up works again."""

    def test_the_whole_chain_with_a_mirrored_floor(self):
        with tempfile.TemporaryDirectory() as tmp:
            deployment = Deployment(tmp)
            now = int(time.time()) + 1_000  # deliveries (real clock) are safely before the cutoff
            fake = FakeTime(now)
            clock = fake.clock()
            with patch.object(_clock, "_default_clock", clock):
                host = deployment.host()
                fake.jump(365 * 24 * 3600)  # the wall clock jumps a year ahead
                envelope = _envelope_at(host, fake)
                with self.assertLogs("portmark._clock", level="CRITICAL"):
                    host.run(envelope)
                jumped_floor = deployment.store().time_floor()
                self.assertGreaterEqual(jumped_floor, now + 365 * 24 * 3600 - TIME_FLOOR_CADENCE_SECONDS)
                self.assertEqual(host.audit_floor.witnessed_time_floor(), jumped_floor)  # mirrored outside the DB
            corrected = FakeTime(now).clock()  # the operator fixes the clock and restarts
            with patch.object(_clock, "_default_clock", corrected):
                with self.assertRaisesRegex(ValueError, "time floor refused to start \\(clock-behind-floor\\)"):
                    deployment.host()
                witness = LocalFloorWitness(deployment.floor_path, HOST, deployment.signer, deployment.signer)
                outcome = reset_time_floor(deployment.store(), witness, now, "clock jumped a year ahead on 2026-09-19", now)
                self.assertEqual(outcome["prior_database_floor"], jumped_floor)
                deployment.host()  # starts again
            log = deployment.store().maintenance_log()
            self.assertEqual(log[0]["action"], "time-floor-reset")
            self.assertEqual(log[0]["detail"]["reason"], "clock jumped a year ahead on 2026-09-19")
            resets = witness.load()["resets"]
            self.assertEqual(resets[-1]["kind"], "time-floor")

    def test_reset_requires_a_reason_and_never_happens_by_itself(self):
        store = InMemoryRuntimeStore()
        with self.assertRaises(ValueError):
            store.reset_time_floor(1, "   ")
        with self.assertRaises(ValueError):
            store.reset_time_floor(-1, "why")


class SnapshotRollbackTests(unittest.TestCase):
    """Restoring an older database snapshot with a clock set back to match it."""

    def test_the_mirrored_floor_detects_a_restored_older_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            deployment = Deployment(tmp)
            now = int(time.time()) + 1_000  # deliveries (real clock) are safely before the cutoff
            with patch.object(_clock, "_default_clock", FakeTime(now).clock()):
                host = deployment.host()
            snapshot = Path(tmp) / "snapshot.sqlite"
            snapshot.write_bytes(deployment.store_path.read_bytes())  # taken at `now`
            later = now + 30 * 24 * 3600
            later_time = FakeTime(later)
            with patch.object(_clock, "_default_clock", later_time.clock()):
                host = deployment.host()
                host.run(_envelope_at(host, later_time))
            self.assertGreaterEqual(host.audit_floor.witnessed_time_floor(), later - TIME_FLOOR_CADENCE_SECONDS)
            deployment.store_path.write_bytes(snapshot.read_bytes())  # restore the old database...
            witness = LocalFloorWitness(deployment.floor_path, HOST, None, deployment.signer)
            with self.assertRaises(TimeFloorError) as raised:  # ...with the clock set back to match it
                check_time_floor(deployment.store(), witness, FakeTime(now).clock())
            self.assertEqual(raised.exception.code, "clock-behind-floor")
            self.assertIn("audit-floor file", str(raised.exception))

    def test_without_a_mirrored_floor_a_restored_snapshot_is_not_detected(self):
        # The documented non-guarantee (DEPLOYMENT.md): the database floor rolls back with the database.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = _sqlite_store(root)
            path = root / "db" / "runtime.sqlite"
            _advance(store, 2_000_000_000)
            snapshot = path.read_bytes()
            _advance(store, 2_100_000_000)
            path.write_bytes(snapshot)
            check_time_floor(SQLiteRuntimeStore(path), None, FakeTime(2_000_000_000).clock())  # not refused


class OldSchemaTests(unittest.TestCase):
    def test_upgrading_a_v12_database_seeds_the_floor_from_the_newest_stored_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runtime.sqlite"
            build_at_version(str(path), 12)
            connection = sqlite3.connect(path)
            try:
                newest = max(
                    connection.execute(f"SELECT MAX({column}) FROM {table}").fetchone()[0] or 0  # nosec B608 -- constant identifiers
                    for table, column in storage._TIME_FLOOR_SEED_COLUMNS
                )
                connection.execute("INSERT INTO consumed_nonces (nonce, subject, audience, task_id, consumed_at) VALUES ('legacy', 's', 'a', 't', 1)")
                connection.commit()
            finally:
                connection.close()
            store = SQLiteRuntimeStore(path)  # upgrades to v13
            self.assertGreater(newest, 0)
            self.assertEqual(store.time_floor(), newest)
            report = store.prune(10**12, 10**12)  # every cutoff far in the future: still keeps legacy rows
            self.assertEqual(report["kept"]["nonces_without_expiry"], store.capacity_report()["rows"]["consumed_nonces"])
            self.assertEqual(report["expired_nonces"]["eligible"], 0)

    def test_a_version_1_audit_floor_file_is_read_and_rewritten_as_version_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit-floor.json"
            signer = host_signer()
            body = {"format_version": 1, "host_id": HOST, "epoch": 1, "registry": None, "tasks": {}, "resets": []}
            document = {"format": AUDIT_FLOOR_TYPE, "body": body, "signature_key_id": signer.key_id, "signature": signer.sign_audit_floor(body)}
            path.write_bytes(canonical_json(document))
            witness = LocalFloorWitness(path, HOST, signer, signer)
            self.assertEqual(witness.witnessed_time_floor(), 0)  # a genuine v1 file verifies and reads as floor 0
            witness.advance_time_floor(2_000_000_000)
            stored = json.loads(path.read_bytes())["body"]
            self.assertEqual((stored["format_version"], stored["time_floor"]), (2, 2_000_000_000))


class NonceExpiryTests(unittest.TestCase):
    def test_runs_store_the_permit_expiry_with_the_nonce(self):
        store = InMemoryRuntimeStore()
        host = make_host(None, store=store)
        envelope = make_demo_envelope(host, "research Telescript")
        host.run(envelope)
        rows = [row for row in store._nonces.values() if row["task_id"] == envelope.state.task_id]
        self.assertEqual([row["expires_at"] for row in rows], [envelope.permit.expires_at])

    def test_an_approval_keeps_its_expiry_and_advances_and_mirrors_the_floor(self):
        import test_runtime as rt
        from dataclasses import asdict

        with tempfile.TemporaryDirectory() as tmp:
            deployment = Deployment(tmp)
            fake = FakeTime(int(time.time()))
            with patch.object(_clock, "_default_clock", fake.clock()):
                authority = rt.ApprovalAuthority.generate()
                grant = rt.ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}, ("reserved",))
                policy = rt.HostPolicy(HOST, (grant,), rt.ResourceBudget(), "policy-v1", "policy-hash",
                                       {"payments.reserve": "external-payment"}, (authority.trusted_approver(),))
                host = deployment.host(attestation_policy=None)
                host.policy = policy
                host.providers["payer"] = rt.PaymentProvider()
                envelope = _envelope_at(host, fake, "payer")
                object.__setattr__(envelope.permit, "grants", (rt.ToolGrant("payments.reserve", {"max_amount": 100, "currency": "USD"}),))
                host.signer.seal(envelope)
                first = host.run(envelope)
                fake.advance(TIME_FLOOR_CADENCE_SECONDS + 1)  # the next security write may advance the floor again
                expiry = int(fake.wall) + 3600  # outlives the slow provider below
                token = authority.issue("payments.reserve", envelope.permit.subject, envelope.permit.audience, envelope.state.task_id,
                                        envelope.permit.nonce, {"amount": 50, "currency": "USD"}, "policy-hash", expiry,
                                        checkpoint_generation=first.checkpoint["checkpoint_generation"])
                envelope.state.memory["approvals"] = {"payments.reserve": asdict(token)}
                host.signer.seal(envelope)
                # The admission save of this run advances the floor first; the provider then takes longer than
                # the cadence, so the APPROVAL write is the one that advances (and mirrors) the floor next.
                real_decide = host.providers["payer"].decide
                slow = {"once": True}

                def slow_decide(*args, **kwargs):
                    if slow.pop("once", False):
                        fake.advance(TIME_FLOOR_CADENCE_SECONDS + 1)
                    return real_decide(*args, **kwargs)

                host.providers["payer"].decide = slow_decide
                self.assertEqual(host.run(envelope).status, "completed")
            store = deployment.store()
            # closing(): sqlite3's own `with` commits but never closes, and Windows cannot delete an open file.
            with contextlib.closing(sqlite3.connect(deployment.store_path)) as connection:
                stored = connection.execute(
                    "SELECT expires_at FROM consumed_nonces WHERE nonce = ?", (f"approval:{envelope.state.task_id}:{token.approval_id}",)
                ).fetchone()[0]
            self.assertEqual(stored, expiry)
            # The approval write advanced the floor to the approval time and mirrored it into the audit-floor
            # file (the checkpoint save that followed in the same second was inside the cadence).
            self.assertEqual(store.time_floor(), int(fake.wall))
            self.assertEqual(host.audit_floor.witnessed_time_floor(), int(fake.wall))

    def test_an_audit_floor_reset_never_lowers_the_time_floor(self):
        from portmark.witness import reset_audit_floor

        with tempfile.TemporaryDirectory() as tmp:
            deployment = Deployment(tmp)
            now = int(time.time())
            with patch.object(_clock, "_default_clock", FakeTime(now).clock()):
                host = deployment.host()
                host.run(_envelope_at(host, FakeTime(now)))
            witness = LocalFloorWitness(deployment.floor_path, HOST, deployment.signer, deployment.signer)
            witness.advance_time_floor(now + 5_000)  # the mirror is ahead of the database
            store = deployment.store()
            store.set_audit_head_verifier(deployment.signer)
            reset_audit_floor(witness, store, "rebaseline heads", None, None)
            self.assertEqual(witness.witnessed_time_floor(), now + 5_000)

def _seed(store, now: int):
    """Rows of every class, on the embedded store's own write paths."""
    with store.transaction() as transaction:
        for index in range(5):
            transaction.consume_nonce(f"old-{index}", "s", "a", f"t{index}", expires_at=now - 10_000 - index)
        transaction.consume_nonce("recent", "s", "a", "t9", expires_at=now - 60)  # expired, but within the tolerance
        transaction.consume_nonce("legacy", "s", "a", "t8")  # no expiry: never provably safe
        transaction.enqueue_migration("m-delivered", "host:b", "{}")
        transaction.enqueue_migration("m-no-receipt", "host:b", "{}")
        transaction.enqueue_migration("m-pending", "host:b", "{}")
        transaction.enqueue_migration("m-dead", "host:b", "{}")
    store.mark_migration_delivered("m-delivered", '{"verified": true}')
    store.claim_migrations("w", 60, 5)
    store.dead_letter_migration("m-dead", "w", "gave up")


class PruneTests(unittest.TestCase):
    """Owner decision D2, on every embedded store."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)

    def tearDown(self):
        self._dir.cleanup()

    def stores(self):
        return (("memory", InMemoryRuntimeStore()), ("sqlite", _sqlite_store(self.root)))

    def test_dry_run_by_default_reports_counts_and_ranges_and_deletes_nothing(self):
        now = int(time.time()) + 1_000  # deliveries (real clock) are safely before the cutoff
        for name, store in self.stores():
            with self.subTest(store=name):
                _seed(store, now)
                before = store.capacity_report()["rows"]
                report = run_prune(store, None, now, clock=FakeTime(now).clock())
                self.assertFalse(report["applied"])
                self.assertEqual(report["expired_nonces"]["eligible"], 5)
                self.assertEqual((report["expired_nonces"]["oldest"], report["expired_nonces"]["newest"]), (now - 10_004, now - 10_000))
                self.assertEqual(report["delivered_migrations"]["eligible"], 1)
                self.assertEqual(report["kept"]["nonces_without_expiry"], 1)
                self.assertEqual(report["kept"]["pending_migrations"], 2)  # m-pending and m-no-receipt
                self.assertEqual(report["kept"]["dead_migrations"], 1)
                self.assertEqual(store.capacity_report()["rows"], before)  # nothing deleted, nothing logged

    def test_apply_deletes_exactly_the_eligible_rows_in_bounded_batches_and_logs_each(self):
        now = int(time.time()) + 1_000  # deliveries (real clock) are safely before the cutoff
        for name, store in self.stores():
            with self.subTest(store=name):
                _seed(store, now)
                report = run_prune(store, None, now, apply=True, batch_size=2, clock=FakeTime(now).clock())
                self.assertEqual((report["expired_nonces"]["deleted"], report["delivered_migrations"]["deleted"]), (5, 1))
                self.assertEqual(report["batches"], 4)  # 2 + 2 + 1 nonces, 1 migration
                self.assertTrue(store.consumed_nonce_exists("recent"))  # inside the clock tolerance: kept
                self.assertTrue(store.consumed_nonce_exists("legacy"))  # no stored expiry: kept
                self.assertFalse(store.consumed_nonce_exists("old-0"))
                self.assertEqual({row["task_id"] for row in store.list_pending_migrations()}, {"m-no-receipt", "m-pending"})
                self.assertEqual([row["task_id"] for row in store.list_dead_migrations()], ["m-dead"])
                log = store.maintenance_log()
                self.assertEqual([entry["action"] for entry in log], ["prune"] + ["prune-batch"] * 4)
                self.assertEqual(log[0]["detail"]["deleted"], {"expired_nonces": 5, "delivered_migrations": 1})
                again = run_prune(store, None, now, apply=True, clock=FakeTime(now).clock())
                self.assertEqual(again["expired_nonces"]["deleted"] + again["delivered_migrations"]["deleted"], 0)
                self.assertEqual(store.capacity_report()["rows"]["maintenance_log"], len(store.maintenance_log()))  # never pruned

    def test_a_delivered_row_without_a_stored_receipt_is_kept(self):
        now = int(time.time()) + 1_000  # deliveries (real clock) are safely before the cutoff
        store = _sqlite_store(self.root)
        _seed(store, now)
        with contextlib.closing(sqlite3.connect(self.root / "db" / "runtime.sqlite")) as connection:
            connection.execute("UPDATE migration_outbox SET status = 'delivered', delivered_at = 1 WHERE task_id = 'm-no-receipt'")
            connection.commit()
        report = run_prune(store, None, now, apply=True, clock=FakeTime(now).clock())
        self.assertEqual(report["delivered_migrations"]["deleted"], 1)  # only m-delivered
        self.assertEqual(report["kept"]["delivered_without_receipt"], 1)

    def test_a_row_that_changes_between_select_and_delete_is_not_deleted(self):
        # The DELETE re-checks the predicate: a delivered row re-queued in between survives.
        now = int(time.time()) + 1_000  # deliveries (real clock) are safely before the cutoff
        store = _sqlite_store(self.root)
        _seed(store, now)
        real_connect = store._connect

        class Racing:
            def __init__(self, connection):
                self._connection = connection

            def execute(self, sql, params=()):
                cursor = self._connection.execute(sql, params)
                if sql.startswith("SELECT task_id AS k"):
                    self._connection.execute("UPDATE migration_outbox SET status = 'pending' WHERE task_id = 'm-delivered'")
                return cursor

            def __enter__(self):
                self._connection.__enter__()
                return self

            def __exit__(self, *exc):
                return self._connection.__exit__(*exc)

            def __getattr__(self, name):
                return getattr(self._connection, name)

        with patch.object(store, "_connect", lambda: Racing(real_connect())):
            report = store.prune(now - TOLERANCE, now + 1_000, apply=True)
        self.assertEqual(report["delivered_migrations"]["deleted"], 0)
        self.assertIn("m-delivered", {row["task_id"] for row in store.list_pending_migrations()})

    def test_cutoffs_and_refusals(self):
        self.assertEqual(prune_cutoffs(1_000_000, 2_000_000, TOLERANCE), (1_000_000, 1_000_000))
        self.assertEqual(prune_cutoffs(2_000_000, 2_000_000, TOLERANCE), (2_000_000 - TOLERANCE, 2_000_000))
        with self.assertRaises(ValueError):
            prune_cutoffs(2_000_001, 2_000_000, TOLERANCE)  # a future cutoff
        store = InMemoryRuntimeStore()
        for bad in ({"batch_size": 0}, {"batch_size": MAX_PRUNE_BATCH + 1}, {"nonce_cutoff": 0}, {"migration_cutoff": True}):
            arguments = {"nonce_cutoff": 10, "migration_cutoff": 10, "batch_size": 5, **bad}
            with self.subTest(**bad), self.assertRaises(ValueError):
                store.prune(**arguments)
        self.assertEqual(parse_cutoff("1700000000"), 1_700_000_000)
        self.assertEqual(parse_cutoff("2023-11-14T22:13:20Z"), 1_700_000_000)
        self.assertEqual(parse_cutoff("2023-11-14T22:13:20"), 1_700_000_000)  # no offset = UTC

    def test_a_prune_refuses_to_run_while_the_clock_is_behind_the_floor(self):
        store = _sqlite_store(self.root)
        _advance(store, 2_000_000_000)
        with self.assertRaises(TimeFloorError):
            run_prune(store, None, 1_000, apply=True, clock=FakeTime(2_000_000_000 - TOLERANCE - 1).clock())

    def test_prune_never_vacuums(self):
        store = _sqlite_store(self.root)
        statements = []
        real_connect = store._connect

        def tracing_connect():
            connection = real_connect()
            connection.set_trace_callback(statements.append)
            return connection

        with patch.object(store, "_connect", tracing_connect):
            store.prune(10**9, 10**9, apply=True)
        self.assertTrue(statements)
        self.assertFalse([sql for sql in statements if "VACUUM" in sql.upper()])


class PagingAndCapacityTests(unittest.TestCase):
    def test_listings_are_paged_with_a_stable_cursor_and_a_ceiling(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, store in (("memory", InMemoryRuntimeStore()), ("sqlite", _sqlite_store(Path(tmp)))):
                with self.subTest(store=name):
                    with store.transaction() as transaction:
                        for index in range(7):
                            transaction.enqueue_migration(f"task-{index}", "host:b", "{}")
                    first = store.list_pending_migrations(limit=3)
                    second = store.list_pending_migrations(limit=3, after=first[-1]["task_id"])
                    third = store.list_pending_migrations(limit=3, after=second[-1]["task_id"])
                    self.assertEqual([row["task_id"] for row in first + second + third], [f"task-{index}" for index in range(7)])
                    for bad in (0, MAX_ADMIN_PAGE_SIZE + 1, True):
                        with self.assertRaises(ValueError):
                            store.list_pending_migrations(limit=bad)
                    with self.assertRaises(SecurityError):
                        store.claim_migrations("w", 60, MAX_CLAIM_LIMIT + 1)
                    self.assertEqual(len(store.claim_migrations("w", 60, MAX_CLAIM_LIMIT)), 7)

    def test_capacity_report_and_cached_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _sqlite_store(Path(tmp))
            with store.transaction() as transaction:
                transaction.enqueue_migration("old", "host:b", "{}")
            report = store.capacity_report()
            self.assertEqual(report["rows"]["migration_outbox"], 1)
            self.assertGreater(report["database_bytes"], 0)
            self.assertGreater(report["free_bytes"], 0)
            host = make_host(None, store=InMemoryRuntimeStore())
            host.store = store
            calls = []
            real = store.capacity_report
            with patch.object(store, "capacity_report", side_effect=lambda: (calls.append(1), real())[1]):
                host.refresh_capacity_metrics()
                host.refresh_capacity_metrics()  # cached: a scrape storm is not a query storm
            self.assertEqual(len(calls), 1)
            text = host.metrics.prometheus_text()
            self.assertIn('portmark_store_rows{table="migration_outbox"} 1', text)
            self.assertIn("portmark_store_database_bytes", text)
            self.assertIn("portmark_store_oldest_pending_migration_age_seconds", text)


class CliAndEntrypointTests(unittest.TestCase):
    def _cli(self, *argv, env=None):
        from portmark import cli

        out, err = io.StringIO(), io.StringIO()
        code = 0
        with patch("sys.argv", ["portmark", *argv]), patch.dict(os.environ, env or {}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                cli.main()
            except SystemExit as exit_:
                code = exit_.code if isinstance(exit_.code, int) else 1
        return code, out.getvalue(), err.getvalue()

    def test_store_prune_is_a_dry_run_unless_applied(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _sqlite_store(Path(tmp))
            now = int(time.time()) + 1_000  # deliveries (real clock) are safely before the cutoff
            _seed(store, now)
            path = str(Path(tmp) / "db" / "runtime.sqlite")
            code, out, err = self._cli("--store-path", path, "store", "prune", "--before", str(now - 1_000))
            self.assertEqual(code, 0, err)
            self.assertIn("DRY RUN", err)
            self.assertEqual(json.loads(out)["expired_nonces"]["deleted"], 0)
            self.assertTrue(store.consumed_nonce_exists("old-0"))
            code, out, err = self._cli("--store-path", path, "store", "prune", "--before", str(now - 1_000), "--apply")
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(out)["expired_nonces"]["deleted"], 5)
            code, out, _ = self._cli("--store-path", path, "store", "stats")
            self.assertEqual(json.loads(out)["backend"], "sqlite")

    def test_time_floor_reset_needs_confirm_and_a_reason_and_is_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _sqlite_store(Path(tmp))
            _advance(store, 2_000_000_000)
            path = str(Path(tmp) / "db" / "runtime.sqlite")
            code, _, _ = self._cli("--store-path", path, "time-floor", "reset", "--to", "1", "--reason", "clock fixed")
            self.assertNotEqual(code, 0)
            self.assertEqual(store.time_floor(), 2_000_000_000)
            code, out, err = self._cli("--store-path", path, "time-floor", "reset", "--to", "1", "--reason", "clock fixed", "--confirm")
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(out)["prior_database_floor"], 2_000_000_000)
            self.assertEqual(store.time_floor(), 1)
            self.assertEqual(store.maintenance_log()[0]["detail"]["reason"], "clock fixed")

    def test_the_container_entrypoint_refuses_a_clock_behind_the_floor_with_exit_2(self):
        from portmark import serve_asgi

        with patch("portmark.serve_asgi.run_uvicorn", side_effect=ValueError("time floor refused to start (clock-behind-floor): x")):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(serve_asgi.main({}), serve_asgi.REFUSED_EXIT)
        self.assertIn("refusing to start: time floor refused", err.getvalue())


@unittest.skipUnless(PG_DSN and HAVE_PSYCOPG, "needs a live Postgres (PORTMARK_TEST_POSTGRES_DSN)")
class PostgresClockAndPruneTests(unittest.TestCase):
    def setUp(self):
        import psycopg

        self.psycopg = psycopg
        self.schema = "s12b_" + secrets.token_hex(6)
        self.store = PostgresRuntimeStore(PG_DSN, schema=self.schema)

    def tearDown(self):
        with self.psycopg.connect(PG_DSN, autocommit=True) as connection:
            connection.execute(f'DROP SCHEMA IF EXISTS "{self.schema}" CASCADE')

    def test_the_floor_uses_the_database_clock_and_ignores_the_host_value(self):
        database_now = self.store.database_now()
        self.store.reset_time_floor(1, "test baseline")
        advanced = _advance(self.store, 10**12)  # a wild host value is ignored
        self.assertIsNotNone(advanced)
        self.assertLessEqual(abs(advanced - database_now), 5)
        self.assertIsNone(_advance(self.store, 10**12))  # within the cadence

    def test_a_locked_floor_row_is_skipped_never_waited_for(self):
        self.store.reset_time_floor(1, "test baseline")
        blocker = self.psycopg.connect(PG_DSN)
        try:
            blocker.execute(f'SELECT floor_at FROM "{self.schema}".time_floor FOR UPDATE')  # nosec B608 -- this test's own schema name
            started = time.monotonic()
            self.assertIsNone(_advance(self.store, 0))  # skipped: the save it rides in is not blocked
            self.assertLess(time.monotonic() - started, 2.0)
        finally:
            blocker.rollback()
            blocker.close()

    def test_concurrent_advancement_on_postgres_never_fails_or_lowers(self):
        self.store.reset_time_floor(1, "test baseline")
        errors, results = [], []

        def worker():
            try:
                results.append(_advance(PostgresRuntimeStore(PG_DSN, schema=self.schema), 0))
            except Exception as error:  # noqa: BLE001 -- asserted below
                errors.append(error)

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(errors, [])
        self.assertEqual(len([value for value in results if value is not None]), 1)  # one advance per cadence
        self.assertGreater(self.store.time_floor(), 1)

    def test_host_and_database_clock_skew_is_refused(self):
        database_now = self.store.database_now()
        with self.assertRaises(TimeFloorError) as raised:
            check_time_floor(self.store, None, FakeTime(database_now + TOLERANCE + 60).clock())
        self.assertEqual(raised.exception.code, "host-database-clock-skew")

    def test_prune_on_postgres(self):
        now = self.store.database_now()
        with self.store.transaction() as transaction:
            transaction.consume_nonce("old", "s", "a", "t", expires_at=now - 10_000)
            transaction.consume_nonce("legacy", "s", "a", "t2")
            transaction.enqueue_migration("m-delivered", "host:b", "{}")
            transaction.enqueue_migration("m-pending", "host:b", "{}")
        self.store.mark_migration_delivered("m-delivered", '{"verified": true}')
        dry = self.store.prune(now - TOLERANCE, now + 10, apply=False)
        self.assertEqual((dry["expired_nonces"]["eligible"], dry["delivered_migrations"]["eligible"]), (1, 1))
        report = self.store.prune(now - TOLERANCE, now + 10, apply=True, batch_size=1)
        self.assertEqual((report["expired_nonces"]["deleted"], report["delivered_migrations"]["deleted"]), (1, 1))
        self.assertTrue(self.store.consumed_nonce_exists("legacy"))
        self.assertEqual([row["task_id"] for row in self.store.list_pending_migrations()], ["m-pending"])
        self.assertEqual(self.store.maintenance_log()[0]["action"], "prune")
        self.assertEqual(self.store.capacity_report()["backend"], "postgres")

    def test_upgrading_a_v10_schema_seeds_the_floor(self):
        with self.psycopg.connect(PG_DSN, autocommit=True) as connection:
            connection.execute(f'SET search_path TO "{self.schema}"')
            connection.execute("INSERT INTO task_cancellations (task_id, cancelled_at) VALUES ('seed', 1900000000)")
            connection.execute("DROP TABLE time_floor")
            connection.execute("DROP TABLE maintenance_log")
            connection.execute("ALTER TABLE consumed_nonces DROP COLUMN expires_at")
            connection.execute("ALTER TABLE migration_outbox DROP COLUMN delivered_at")
            connection.execute("UPDATE portmark_schema SET version = 10")
        upgraded = PostgresRuntimeStore(PG_DSN, schema=self.schema)
        self.assertGreaterEqual(upgraded.time_floor(), 1_900_000_000)


if __name__ == "__main__":
    logging.basicConfig()
    unittest.main()

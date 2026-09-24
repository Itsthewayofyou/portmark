"""MCP/SIEM plan PR 1: `portmark audit export` and `audit verify-export` (owner decision D3c).

The export is a projection of the authoritative audit: default-deny per event kind, HMAC-SHA-256 digests
under a dedicated keyring, at-least-once delivery behind a per-task cursor, and an integrity check before
anything is copied. verify-export Level 1 proves order and completeness against the signed heads; Level 2
proves the projected values against the store.
"""

import base64
import hashlib
import hmac
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from portmark.audit_export import (
    BUILTIN_POLICY_DIGEST,
    CONTROL_SCHEMA,
    REDACTED,
    ExportConfigError,
    ExportCursor,
    Keyring,
    ProjectionPolicy,
    Projector,
    VerifyReport,
    ocsf_encoder,
    read_export,
    run_export,
    verify_against_store,
    verify_records,
)
from portmark.cli import main as cli_main
from portmark.factory import make_demo_envelope, make_host
from portmark.ocsf import HEAD_SIGNATURE_VERIFIED, from_ocsf, to_ocsf
from portmark.security import EnvelopeSigner, TrustRegistry, TrustedIdentity, canonical_json
from portmark.storage import InMemoryRuntimeStore, PostgresRuntimeStore, SQLiteRuntimeStore

try:
    import psycopg  # noqa: F401

    HAVE_PSYCOPG = True
except ImportError:  # pragma: no cover - the postgres extra is optional
    HAVE_PSYCOPG = False

PG_DSN = os.environ.get("PORTMARK_TEST_POSTGRES_DSN")
HOST = "host:export"
KEY_A = bytes(range(32))
KEY_B = bytes(range(1, 33))
MARKER_GOAL = "MARKER-GOAL-7d1c"


def signer():
    return EnvelopeSigner.from_private_key_bytes("export-key", HOST, bytes(range(40, 72)))


def registry(host_signer):
    return TrustRegistry((TrustedIdentity(host_signer.key_id, host_signer.issuer, host_signer.public_key_bytes(), ("*",)),))


def registry_document(host_signer):
    return {"identities": [{
        "key_id": host_signer.key_id,
        "issuer": host_signer.issuer,
        "public_key_b64": base64.urlsafe_b64encode(host_signer.public_key_bytes()).decode("ascii").rstrip("="),
        "allowed_audiences": ["*"],
    }]}


def keyring_document(active="a", **keys):
    keys = keys or {"a": KEY_A}
    return {"active": active, "keys": {key_id: base64.b64encode(key).decode() for key_id, key in keys.items()}}


class MemoryOut(io.BytesIO):
    """An in-memory output: the durable path is exercised by the CLI tests with a real file."""

    def fileno(self):  # pragma: no cover - never called with durable=False
        raise OSError("no descriptor")


def lines_of(data: bytes):
    return [json.loads(line) for line in data.splitlines() if line.strip()]


class ExportCase(unittest.TestCase):
    """Shared scenario: a signed host writes audit chains to a store, and the export reads them."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)
        self.signer = signer()
        self.registry = registry(self.signer)
        self.keyring = Keyring("a", {"a": KEY_A})
        self.store = self.make_store()
        self.host = make_host(host_id=HOST, signer=self.signer, store=self.store, allow_ephemeral_signing_key=True)

    def tearDown(self):
        self._dir.cleanup()

    def make_store(self):
        return SQLiteRuntimeStore(str(self.root / "runtime.sqlite"))

    def run_task(self, goal=MARKER_GOAL):
        return self.host.run(make_demo_envelope(self.host, goal)).task_id

    def export(self, cursor=None, policy=None, keyring=None, **kwargs):
        out = MemoryOut()
        projector = Projector(policy or ProjectionPolicy.builtin(), keyring or self.keyring)
        report = run_export(self.store, cursor or ExportCursor(None), projector, out, verifier=self.registry, durable=False, **kwargs)
        return report, out.getvalue()

    def verify(self, data, level2=False, verifier="default", policy=None, keyring=None):
        report = VerifyReport()
        records = read_export(data.splitlines(keepends=True), report)
        verify_records(records, self.registry if verifier == "default" else verifier, report)
        if level2:
            verify_against_store(records, self.store, policy or ProjectionPolicy.builtin(), keyring or self.keyring, report)
        return report

    def sql(self, statement, parameters=()):
        with self.store._connection() as connection:
            connection.execute(statement, parameters)


class ExportRoundTripTests(ExportCase):
    def test_export_verifies_at_both_levels_and_carries_no_model_or_user_data(self):
        task_id = self.run_task()
        report, data = self.export()
        self.assertTrue(report.ok, report.integrity_failures)
        self.assertEqual((report.heads, report.tasks), (1, 1))
        self.assertNotIn(MARKER_GOAL.encode(), data)
        records = lines_of(data)
        kinds = [(record["kind"], record.get("event")) for record in records]
        self.assertEqual(kinds[-1], ("head", None))
        self.assertEqual(records[-1]["signature_status"], "valid")
        executed = next(record for record in records if record.get("event") == "tool.executed")
        # Default-deny: an unnamed tool is hash_only -- a count and a digest, never the values or the names.
        self.assertNotIn("arguments", executed["details"])
        self.assertNotIn("argument_keys", executed["details"])
        self.assertEqual(executed["details"]["argument_count"], 2)
        completed = next(record for record in records if record.get("event") == "agent.completed")
        self.assertEqual(completed["details"], {})
        self.assertIn("result", completed["omitted"])
        for record in records[:-1]:
            self.assertEqual((record["task_id"], record["hmac_key_id"], record["policy_digest"]), (task_id, "a", BUILTIN_POLICY_DIGEST))
            self.assertEqual(record["key"], f"{task_id}:{record['sequence']}:{record['hash']}")
        self.assertEqual(self.verify(data).status, "valid")
        level2 = self.verify(data, level2=True)
        self.assertEqual((level2.status, level2.level, level2.unanchored_events), ("valid", 2, 0), level2.reasons)

    def test_exported_hashes_are_the_authoritative_ones(self):
        task_id = self.run_task()
        _, data = self.export()
        head_hash, sequence = self.store.audit_head(task_id)
        events = [record for record in lines_of(data) if record["kind"] == "event"]
        self.assertEqual(len(events), sequence)
        self.assertEqual(events[-1]["hash"], head_hash)
        for record in events:
            self.assertEqual(self.store.audit_event_hash(task_id, record["sequence"]), record["hash"])

    def test_arguments_hmac_is_over_the_original_arguments_with_the_named_key(self):
        self.run_task()
        _, data = self.export()
        executed = next(record for record in lines_of(data) if record.get("event") == "tool.executed")
        original = {"query": MARKER_GOAL, "limit": 3}
        expected = "hmac-sha256:" + hmac.new(KEY_A, canonical_json(original), hashlib.sha256).hexdigest()
        self.assertEqual(executed["details"]["arguments_hmac"], expected)

    def test_policy_include_and_redact_copy_only_what_the_operator_named(self):
        self.run_task()
        policy = ProjectionPolicy.from_bytes(json.dumps({
            "schema": "portmark.siem.projection.v1",
            "tool_arguments": {"default": "hash_only", "tools": {"catalog.search": {"include": ["limit"], "redact": ["query"]}}},
        }).encode())
        _, data = self.export(policy=policy)
        self.assertNotIn(MARKER_GOAL.encode(), data)
        executed = next(record for record in lines_of(data) if record.get("event") == "tool.executed")
        self.assertEqual(executed["details"]["arguments"], {"limit": 3, "query": REDACTED})
        self.assertEqual(executed["details"]["argument_keys"], ["limit", "query"])
        self.assertTrue(executed["policy_digest"].startswith("sha256:"))
        self.assertEqual(self.verify(data, level2=True, policy=policy).status, "valid")


class CursorTests(ExportCase):
    def test_a_second_run_exports_nothing_and_a_new_task_exports_only_itself(self):
        first = self.run_task()
        cursor_path = str(self.root / "cursor.json")
        cursor = ExportCursor(cursor_path)
        _, data = self.export(cursor)
        self.assertTrue(data)
        if os.name == "posix":  # Windows has no POSIX mode bits
            self.assertEqual(os.stat(cursor_path).st_mode & 0o777, 0o600)
        _, again = self.export(ExportCursor.load(cursor_path))
        self.assertEqual(again, b"")
        second = self.run_task("another goal")
        _, more = self.export(ExportCursor.load(cursor_path))
        self.assertEqual({record["task_id"] for record in lines_of(more)}, {second})
        self.assertEqual(self.verify(data + more, level2=True).status, "valid")
        self.assertNotEqual(first, second)

    def test_a_crash_before_the_cursor_is_saved_repeats_records_and_never_loses_one(self):
        self.run_task()
        cursor_path = str(self.root / "cursor.json")

        def crash():
            raise RuntimeError("process died after the write, before the cursor save")

        with self.assertRaises(RuntimeError):
            self.export(ExportCursor(cursor_path), _after_write=crash)
        self.assertFalse(os.path.exists(cursor_path))
        _, first_try = self.export(ExportCursor(None))
        _, retry = self.export(ExportCursor.load(cursor_path))
        self.assertEqual(retry, first_try)
        # The SIEM received both copies: byte-identical duplicates are accepted.
        self.assertEqual(self.verify(first_try + retry).status, "valid")

    def test_small_pages_export_exactly_what_one_large_page_does(self):
        for goal in ("a", "b", "c"):
            self.run_task(goal)
        _, whole = self.export()
        _, paged = self.export(page_size=1, max_events=1)
        self.assertEqual(sorted(whole.splitlines()), sorted(paged.splitlines()))
        _, mid = self.export(page_size=2, max_events=4)
        self.assertEqual(sorted(whole.splitlines()), sorted(mid.splitlines()))

    def test_malformed_cursor_is_refused_not_reset(self):
        cursor_path = self.root / "cursor.json"
        for label, content in {
            "not json": b"{",
            "wrong schema": b'{"schema": "x", "tasks": {}}',
            "extra key": b'{"schema": "portmark.audit.export.cursor.v1", "tasks": {}, "x": 1}',
            "bool next": b'{"schema": "portmark.audit.export.cursor.v1", "tasks": {"t": {"next": true, "hash": "h"}}}',
            "zero next": b'{"schema": "portmark.audit.export.cursor.v1", "tasks": {"t": {"next": 0, "hash": "h"}}}',
        }.items():
            with self.subTest(label):
                cursor_path.write_bytes(content)
                with self.assertRaises(ExportConfigError):
                    ExportCursor.load(str(cursor_path))


class IntegrityTests(ExportCase):
    def test_a_tampered_stored_event_is_reported_not_copied(self):
        task_id = self.run_task()
        self.sql("UPDATE audit_events SET details_json = ? WHERE task_id = ? AND sequence = 2", ('{"tool":"forged"}', task_id))
        report, data = self.export()
        self.assertFalse(report.ok)
        self.assertIn("hash", report.integrity_failures[0]["reason"])
        records = lines_of(data)
        self.assertEqual([record["sequence"] for record in records if record.get("kind") == "event"], [0, 1])
        self.assertEqual(records[-1]["schema"], CONTROL_SCHEMA)
        self.assertEqual(self.verify(data).status, "invalid")

    def test_a_stored_head_that_moved_backwards_is_a_rollback(self):
        task_id = self.run_task()
        cursor = ExportCursor(None)
        self.export(cursor)
        head_hash, sequence = self.store.audit_head(task_id)
        previous = self.store.audit_event_hash(task_id, sequence - 2)
        self.sql("DELETE FROM audit_events WHERE task_id = ? AND sequence = ?", (task_id, sequence - 1))
        self.sql("UPDATE audit_heads SET sequence = ?, head_hash = ? WHERE task_id = ?", (sequence - 1, previous, task_id))
        report, _ = self.export(cursor)
        self.assertIn("behind", report.integrity_failures[0]["reason"])

    def test_a_rewritten_head_at_the_same_sequence_is_reported(self):
        task_id = self.run_task()
        cursor = ExportCursor(None)
        self.export(cursor)
        self.sql("UPDATE audit_heads SET head_hash = ? WHERE task_id = ?", ("0" * 64, task_id))
        report, _ = self.export(cursor)
        self.assertIn("rewritten", report.integrity_failures[0]["reason"])

    def test_an_event_that_does_not_link_to_the_last_exported_one_is_reported(self):
        # The stored event re-hashes correctly, but its `previous` is not the event the SIEM already has:
        # history before the cursor was replaced by a different chain.
        task_id = self.run_task()
        cursor = ExportCursor(None, {task_id: (3, "0" * 64)})
        report, data = self.export(cursor)
        self.assertIn("does not link", report.integrity_failures[0]["reason"])
        self.assertNotIn(b'"kind":"event"', data)

    def test_missing_tail_rows_do_not_match_the_head(self):
        task_id = self.run_task()
        _, sequence = self.store.audit_head(task_id)
        self.sql("DELETE FROM audit_events WHERE task_id = ? AND sequence = ?", (task_id, sequence - 1))
        report, data = self.export()
        self.assertIn("does not match", report.integrity_failures[0]["reason"])
        self.assertNotIn(b'"kind":"head"', data)

    def test_one_damaged_task_does_not_stop_the_others(self):
        damaged = self.run_task("one")
        healthy = self.run_task("two")
        self.sql("UPDATE audit_events SET hash = ? WHERE task_id = ? AND sequence = 0", ("f" * 64, damaged))
        report, data = self.export(page_size=1, max_events=1)
        self.assertEqual([failure["task_id"] for failure in report.integrity_failures], [damaged])
        heads = [record["task_id"] for record in lines_of(data) if record.get("kind") == "head"]
        self.assertEqual(heads, [healthy])


class VerifyExportTests(ExportCase):
    def setUp(self):
        super().setUp()
        self.task_id = self.run_task()
        _, self.data = self.export()
        self.lines = self.data.splitlines(keepends=True)

    def rewrite(self, index, mutate):
        record = json.loads(self.lines[index])
        mutate(record)
        lines = list(self.lines)
        lines[index] = canonical_json(record) + b"\n"
        return b"".join(lines)

    def test_level_one_detects_dropped_relinked_and_forged_head_records(self):
        cases = {
            "dropped event": b"".join(self.lines[:1] + self.lines[2:]),
            "broken link": self.rewrite(2, lambda r: r.__setitem__("previous", "0" * 64)),
            "forged head signature": self.rewrite(len(self.lines) - 1, lambda r: r.__setitem__("signature", "A" * 86)),
            "head hash moved": self.rewrite(len(self.lines) - 1, lambda r: r.__setitem__("head_hash", "0" * 64)),
            "conflicting duplicate": self.data + self.rewrite(1, lambda r: r["details"].__setitem__("kind", "x")).splitlines(keepends=True)[1],
            "not json": self.data + b"{\n",
        }
        for label, data in cases.items():
            with self.subTest(label):
                self.assertEqual(self.verify(data).status, "invalid")

    def test_events_without_a_signed_head_are_never_valid(self):
        headless = b"".join(line for line in self.lines if b'"kind":"head"' not in line)
        report = self.verify(headless)
        self.assertEqual((report.status, report.unanchored_events), ("unverifiable", len(self.lines) - 1))
        self.assertEqual(self.verify(b"").status, "unverifiable")
        # A forged task with no head, added beside a real one, cannot make the file valid.
        forged = self.rewrite(0, lambda r: (r.__setitem__("task_id", "forged"), r.__setitem__("key", "forged:0:x")))
        self.assertEqual(self.verify(self.data + forged.splitlines(keepends=True)[0]).status, "unverifiable")

    def test_order_in_the_file_does_not_matter(self):
        self.assertEqual(self.verify(b"".join(reversed(self.lines))).status, "valid")

    def test_a_changed_value_passes_level_one_and_fails_level_two(self):
        # The documented limit: the projection is not inside the signed hash.
        index = next(i for i, line in enumerate(self.lines) if b'"provider.proposed"' in line)
        changed = self.rewrite(index, lambda r: r["details"].__setitem__("tool", "payments.reserve"))
        self.assertEqual(self.verify(changed).status, "valid")
        level2 = self.verify(changed, level2=True)
        self.assertEqual(level2.status, "invalid")
        self.assertIn("projected values were changed", " ".join(level2.reasons))

    def test_level_two_reports_a_record_missing_from_the_store(self):
        self.sql("DELETE FROM audit_events WHERE task_id = ? AND sequence = 1", (self.task_id,))
        self.assertEqual(self.verify(self.data, level2=True).status, "invalid")

    def test_without_a_trust_registry_heads_are_unverifiable(self):
        self.assertEqual(self.verify(self.data, verifier=None).status, "unverifiable")

    def test_level_two_with_another_policy_or_a_missing_key_is_unverifiable(self):
        other = ProjectionPolicy.from_bytes(b'{"schema": "portmark.siem.projection.v1"}')
        self.assertEqual(self.verify(self.data, level2=True, policy=other).status, "unverifiable")
        self.assertEqual(self.verify(self.data, level2=True, keyring=Keyring("b", {"b": KEY_B})).status, "unverifiable")

    def test_a_rotated_key_keeps_old_records_verifiable(self):
        rotated = Keyring("b", {"a": KEY_A, "b": KEY_B})
        cursor = ExportCursor(None)
        self.export(cursor)
        self.run_task("after rotation")
        _, newer = self.export(cursor, keyring=rotated)
        self.assertEqual({record["hmac_key_id"] for record in lines_of(newer) if record["kind"] == "event"}, {"b"})
        self.assertEqual(self.verify(self.data + newer, level2=True, keyring=rotated).status, "valid")


class OcsfExportTests(ExportCase):
    """The OCSF shape (class 6003), and the fact that verification is untouched by it."""

    def ocsf_export(self, **kwargs):
        return self.export(encode=ocsf_encoder("9.9.9", 1_700_000_000), **kwargs)

    def test_an_ocsf_export_verifies_at_both_levels_exactly_as_a_native_one(self):
        # The point of the whole mapping: a SIEM-shaped file is still a Portmark export.
        self.run_task()
        report, data = self.ocsf_export()
        self.assertTrue(report.ok, report.integrity_failures)
        for record in lines_of(data):
            self.assertEqual(record["class_uid"], 6003)
        self.assertEqual(self.verify(data, level2=True).status, "valid")

    def test_the_round_trip_is_exact(self):
        # Level 2 compares the WHOLE record for equality, so anything lost or reshaped on the way through
        # reads as a record that was altered after export.
        self.run_task()
        _, native = self.export()
        _, shaped = self.ocsf_export()
        self.assertEqual([from_ocsf(record) for record in lines_of(shaped)], lines_of(native))

    def test_every_record_carries_what_the_class_requires(self):
        self.run_task()
        for record in lines_of(self.ocsf_export()[1]):
            with self.subTest(record["activity_name"]):
                for field_name in ("activity_id", "actor", "api", "category_uid", "class_uid",
                                   "metadata", "severity_id", "src_endpoint", "time", "type_uid"):
                    self.assertIn(field_name, record)
                self.assertEqual(record["type_uid"], record["class_uid"] * 100 + record["activity_id"])
                self.assertEqual(record["type_name"], f"{record['class_name']}: {record['activity_name']}")
                self.assertEqual(record["metadata"]["version"], "1.9.0")
                self.assertEqual(record["metadata"]["product"], {
                    "name": "Portmark", "vendor_name": "Portmark", "version": "9.9.9",
                })
                self.assertEqual(record["api"]["operation"], record["activity_name"])
                # `at_least_one` on an actor and on a network endpoint: both are satisfied without
                # inventing a network address for a local audit record.
                self.assertIn("application", record["actor"])
                self.assertTrue(record["src_endpoint"].get("name"))

    def test_the_timestamp_is_milliseconds_not_seconds(self):
        # Portmark stores epoch SECONDS; OCSF requires milliseconds. Getting this wrong puts every event
        # in 1970 and is invisible until a SIEM draws a timeline.
        self.run_task()
        for record in lines_of(self.ocsf_export()[1]):
            native = from_ocsf(record)
            stamp = native.get("created_at") or native.get("signed_at")
            if stamp is not None:
                with self.subTest(record["activity_name"]):
                    self.assertEqual(record["time"], stamp * 1000)

    def test_an_outcome_is_reported_as_success_or_failure_and_a_state_as_neither(self):
        cases = {
            "tool.executed": (1, "Success"),
            "tool.refused": (2, "Failure"),
            "tool.killed": (2, "Failure"),
            "agent.awaiting_input": (0, "Unknown"),  # a state, not a result
            "not.a.portmark.event": (0, "Unknown"),
        }
        for event, (status_id, status) in cases.items():
            with self.subTest(event):
                record = to_ocsf(
                    {"kind": "event", "event": event, "key": "k", "host_id": "h", "created_at": 1, "details": {}},
                    product_version="1", now_seconds=1,
                )
                self.assertEqual((record["status_id"], record["status"]), (status_id, status))

    def test_a_refusal_is_louder_than_a_success_and_a_failure_is_louder_still(self):
        def severity(event):
            return to_ocsf(
                {"kind": "event", "event": event, "key": "k", "host_id": "h", "created_at": 1, "details": {}},
                product_version="1", now_seconds=1,
            )["severity_id"]

        self.assertLess(severity("tool.executed"), severity("tool.refused"))
        self.assertLess(severity("tool.refused"), severity("tool.failed"))

    def test_the_chain_is_carried_whole_and_no_attestation_is_claimed(self):
        # The hash chain covers the ORIGINAL audit event, not this record, so `attestation_list` -- whose
        # fingerprint the specification defines as covering THIS record -- must stay absent.
        self.run_task()
        for record in lines_of(self.ocsf_export()[1]):
            self.assertNotIn("attestation_list", record)
            carried = record["unmapped"]["portmark"]
            self.assertEqual(carried["schema"], "portmark.audit.export.v1")
            self.assertIn("hash" if carried["kind"] == "event" else "head_hash", carried)

    def test_an_integrity_failure_is_exported_as_a_loud_failure_and_still_fails_verification(self):
        self.run_task()
        self.sql("UPDATE audit_events SET details_json = ? WHERE sequence = 1", ('{"tampered":true}',))
        report, data = self.ocsf_export()
        self.assertFalse(report.ok)
        control = [r for r in lines_of(data) if r["activity_name"] == "audit.export.integrity_failure"]
        self.assertEqual(len(control), 1)
        self.assertEqual((control[0]["status_id"], control[0]["severity_id"]), (2, 4))
        self.assertEqual(control[0]["time"], 1_700_000_000 * 1000)  # the exporter's own clock: it has no other
        self.assertEqual(self.verify(data).status, "invalid")

    def test_a_head_is_a_success_only_when_its_signature_verified(self):
        # An exported head carries the outcome of its own signature check. Reporting a head that FAILED that
        # check as a success hides the one alarm an export exists to raise; reporting an unchecked one as a
        # success claims Portmark vouched for a chain nobody looked at.
        cases = {
            "valid": (1, 1),
            "valid-key-revoked": (1, 1),
            "unchecked": (0, 1),
            "signature-invalid": (2, 4),
            "untrusted": (2, 4),
            "a-status-from-a-later-version": (2, 4),
        }
        for signature_status, (status_id, severity_id) in cases.items():
            with self.subTest(signature_status):
                record = to_ocsf(
                    {"kind": "head", "key": "k", "host_id": "h", "signed_at": 1,
                     "signature_status": signature_status},
                    product_version="1", now_seconds=1,
                )
                self.assertEqual((record["status_id"], record["severity_id"]), (status_id, severity_id))
        # And the accepted set is not stale: a real export of a genuinely signed head lands inside it.
        self.run_task()
        self.assertIn(lines_of(self.export()[1])[-1]["signature_status"], HEAD_SIGNATURE_VERIFIED)

    def test_rewriting_the_ocsf_fields_around_an_untouched_record_is_refused(self):
        # Verification reads the native record out of `unmapped`, so nothing else would ever look at the
        # fields a SIEM actually displays. A failure relabelled as a success must not verify.
        self.run_task()
        _, data = self.ocsf_export()
        records = lines_of(data)
        for field, value in (("status", "Failure"), ("status_id", 2), ("time", 0),
                             ("severity_id", 4), ("activity_name", "audit.head")):
            with self.subTest(field):
                edited = [dict(record) for record in records]
                # Edit a record the value actually differs on, or the "tampering" is a no-op and the
                # test passes without ever exercising the check.
                target = next((record for record in edited if record[field] != value), None)
                self.assertIsNotNone(target, field)
                target[field] = value
                report = VerifyReport()
                read_export([canonical_json(record) + b"\n" for record in edited], report)
                self.assertEqual(report.status, "invalid")
                self.assertIn("do not describe the record they carry", " ".join(report.reasons))

    def test_an_ocsf_record_from_elsewhere_is_refused_not_guessed_at(self):
        report = VerifyReport()
        foreign = canonical_json({"class_uid": 6003, "unmapped": {"other_vendor": {"x": 1}}}) + b"\n"
        read_export([foreign], report)
        self.assertEqual(report.status, "invalid")
        self.assertIn("did not come from Portmark", " ".join(report.reasons))


class ProjectionUnitTests(unittest.TestCase):
    def setUp(self):
        self.projector = Projector(ProjectionPolicy.builtin(), Keyring("a", {"a": KEY_A}))

    def digest(self, value):
        return "hmac-sha256:" + hmac.new(KEY_A, canonical_json(value), hashlib.sha256).hexdigest()

    def test_the_plain_approval_arguments_hash_is_never_copied(self):
        details = {"approval_required": True, "tool": "payments.reserve", "arguments_hash": "abc", "impact": "high"}
        projected, omitted = self.projector.project("approval.requested", details)
        self.assertNotIn("arguments_hash", projected)
        self.assertEqual(omitted["arguments_hash"], self.digest("abc"))

    def test_an_unknown_event_kind_exports_keys_and_digests_only(self):
        projected, omitted = self.projector.project("mcp.future", {"a": 1, "b": "x"})
        self.assertEqual((projected, sorted(omitted)), ({}, ["a", "b"]))

    def test_model_and_tool_text_is_never_copied_by_default(self):
        cases = {
            "agent.failed": {"result": {"error": "model text"}},
            "agent.awaiting_input": {"request": "model text"},
            "tool.failed": {"tool": "t", "arguments": {}, "error": "tool text", "cause_message": "tool text"},
        }
        for event, details in cases.items():
            with self.subTest(event):
                projected, _ = self.projector.project(event, details)
                self.assertNotIn("model text", json.dumps(projected))
                self.assertNotIn("tool text", json.dumps(projected))

    def test_hash_only_tool_and_non_object_arguments(self):
        policy = ProjectionPolicy.from_bytes(json.dumps({
            "schema": "portmark.siem.projection.v1",
            "tool_arguments": {"tools": {"secrets.get": {"mode": "hash_only"}}},
        }).encode())
        projector = Projector(policy, Keyring("a", {"a": KEY_A}))
        projected, _ = projector.project("tool.executed", {"tool": "secrets.get", "arguments": {"name": "db"}})
        self.assertEqual(projected, {"tool": "secrets.get", "argument_count": 1, "arguments_hmac": self.digest({"name": "db"})})
        # A model-chosen argument NAME is data too: an unnamed tool never exports it.
        projected, _ = projector.project("tool.executed", {"tool": "unnamed", "arguments": {"token-ABC123": True}})
        self.assertNotIn("token-ABC123", json.dumps(projected))
        projected, _ = projector.project("tool.executed", {"tool": "x", "arguments": "not an object"})
        self.assertEqual(projected, {"tool": "x", "arguments_hmac": self.digest("not an object")})

    def test_a_policy_entry_replaces_the_builtin_entry(self):
        policy = ProjectionPolicy.from_bytes(json.dumps({
            "schema": "portmark.siem.projection.v1", "events": {"provider.proposed": {"include": ["kind"]}},
        }).encode())
        projected, omitted = Projector(policy, Keyring("a", {"a": KEY_A})).project("provider.proposed", {"kind": "tool", "tool": "t"})
        self.assertEqual((projected, list(omitted)), ({"kind": "tool"}, ["tool"]))

    def test_digesting_without_a_keyring_is_refused(self):
        with self.assertRaises(ExportConfigError):
            Projector(ProjectionPolicy.builtin(), None).project("agent.completed", {"result": 1})


class ConfigLoaderTests(unittest.TestCase):
    def test_policy_loader_refuses_ambiguous_or_widening_rules(self):
        cases = {
            "unknown top key": {"schema": "portmark.siem.projection.v1", "extra": 1},
            "wrong schema": {"schema": "v0"},
            "raw default": {"schema": "portmark.siem.projection.v1", "tool_arguments": {"default": "include_all"}},
            "include and redact": {"schema": "portmark.siem.projection.v1", "events": {"x": {"include": ["a"], "redact": ["a"]}}},
            "mode on an event": {"schema": "portmark.siem.projection.v1", "events": {"x": {"mode": "hash_only"}}},
            "mode plus include": {"schema": "portmark.siem.projection.v1", "tool_arguments": {"tools": {"t": {"mode": "hash_only", "include": ["a"]}}}},
            "other mode": {"schema": "portmark.siem.projection.v1", "tool_arguments": {"tools": {"t": {"mode": "raw"}}}},
            "duplicate field": {"schema": "portmark.siem.projection.v1", "events": {"x": {"include": ["a", "a"]}}},
            "non-string field": {"schema": "portmark.siem.projection.v1", "events": {"x": {"include": [1]}}},
        }
        for label, document in cases.items():
            with self.subTest(label):
                with self.assertRaises(ExportConfigError):
                    ProjectionPolicy.from_bytes(json.dumps(document).encode())
        with self.assertRaises(ExportConfigError):
            ProjectionPolicy.from_bytes(b'{"schema": "portmark.siem.projection.v1", "schema": "x"}')

    def test_keyring_loader_refuses_weak_or_ambiguous_keys(self):
        cases = {
            "short key": keyring_document(a=b"x" * 31),
            "active not in keys": keyring_document("b"),
            "bad key id": {"active": "a b", "keys": {"a b": base64.b64encode(KEY_A).decode()}},
            "not base64": {"active": "a", "keys": {"a": "***"}},
            "extra key": {**keyring_document(), "note": "x"},
            "empty": {"active": "a", "keys": {}},
        }
        for label, document in cases.items():
            with self.subTest(label):
                with self.assertRaises(ExportConfigError) as raised:
                    Keyring.from_bytes(json.dumps(document).encode())
                self.assertNotIn(base64.b64encode(KEY_A).decode(), str(raised.exception))

    @unittest.skipUnless(os.name == "posix", "POSIX file modes")
    def test_keyring_file_must_be_private_and_regular(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keyring.json"
            path.write_text(json.dumps(keyring_document()))
            os.chmod(path, 0o640)
            with self.assertRaises(ExportConfigError):
                Keyring.load(str(path))
            os.chmod(path, 0o600)
            self.assertEqual(Keyring.load(str(path)).active, "a")
            link = Path(directory) / "link.json"
            link.symlink_to(path)
            with self.assertRaises(ExportConfigError):
                Keyring.load(str(link))


class CliTests(ExportCase):
    def setUp(self):
        super().setUp()
        self.task_id = self.run_task()
        self.registry_path = self.root / "trust.json"
        self.registry_path.write_text(json.dumps(registry_document(self.signer)))
        self.keyring_path = self.root / "keyring.json"
        self.keyring_path.write_text(json.dumps(keyring_document()))
        os.chmod(self.keyring_path, stat.S_IRUSR | stat.S_IWUSR)
        self.out = self.root / "audit.jsonl"
        self.cursor = self.root / "cursor.json"

    def cli(self, *arguments, registry=True):
        argv = ["portmark", "--store-path", str(self.root / "runtime.sqlite")]
        if registry:
            argv += ["--trust-registry-path", str(self.registry_path)]
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", argv + list(arguments)), redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                cli_main()
                code = 0
            except SystemExit as exit_:
                code = exit_.code
        return code, stdout.getvalue(), stderr.getvalue()

    def export_cli(self, *extra):
        return self.cli("audit", "export", "--out", str(self.out), "--cursor-file", str(self.cursor),
                        "--projection-keyring", str(self.keyring_path), *extra)

    def test_the_ocsf_format_flag_writes_ocsf_and_verify_export_still_reads_it(self):
        code, _, _ = self.export_cli("--format", "ocsf")
        self.assertEqual(code, 0)
        written = lines_of(self.out.read_bytes())
        self.assertTrue(written)
        for record in written:
            self.assertEqual(record["class_uid"], 6003)
        code, stdout, stderr = self.cli(
            "audit", "verify-export", "--in", str(self.out), "--against-store",
            "--projection-keyring", str(self.keyring_path),
        )
        self.assertEqual(code, 0, stderr)
        self.assertEqual(json.loads(stdout)["status"], "valid")
        self.assertEqual(json.loads(stdout)["level"], 2)

    def test_export_then_verify_at_both_levels(self):
        synced = []
        real_fsync = os.fsync

        def fsync(fd):
            # Only the OUTPUT file's fsyncs count (the cursor's atomic write fsyncs its own temp file too).
            if self.out.exists() and os.fstat(fd).st_ino == os.stat(self.out).st_ino:
                synced.append(self.cursor.exists())
            real_fsync(fd)

        with patch("portmark.audit_export.os.fsync", fsync):
            code, _, stderr = self.export_cli()
        self.assertEqual(code, 0, stderr)
        # The output is fsynced, and it is fsynced BEFORE the cursor file first exists.
        self.assertEqual(synced, [False])
        self.assertEqual(json.loads(stderr)["heads"], 1)
        if os.name == "posix":
            self.assertEqual(os.stat(self.out).st_mode & 0o777, 0o600)
        code, stdout, _ = self.cli("audit", "verify-export", "--in", str(self.out))
        self.assertEqual((code, json.loads(stdout)["status"]), (0, "valid"))
        code, stdout, _ = self.cli("audit", "verify-export", "--in", str(self.out), "--against-store",
                                   "--projection-keyring", str(self.keyring_path))
        self.assertEqual((code, json.loads(stdout)["level"]), (0, 2))
        code, _, stderr = self.export_cli()
        self.assertEqual((code, json.loads(stderr)["events"]), (0, 0))

    def test_exit_codes_for_invalid_and_unverifiable(self):
        self.export_cli()
        code, stdout, _ = self.cli("audit", "verify-export", "--in", str(self.out), registry=False)
        self.assertEqual((code, json.loads(stdout)["status"]), (2, "unverifiable"))
        lines = self.out.read_bytes().splitlines(keepends=True)
        self.out.write_bytes(b"".join(lines[:1] + lines[2:]))
        code, stdout, _ = self.cli("audit", "verify-export", "--in", str(self.out))
        self.assertEqual((code, json.loads(stdout)["status"]), (1, "invalid"))

    def test_integrity_failure_exits_one(self):
        self.sql("UPDATE audit_events SET details_json = '{}' WHERE task_id = ? AND sequence = 0", (self.task_id,))
        code, _, stderr = self.export_cli()
        self.assertEqual(code, 1)
        self.assertEqual(len(json.loads(stderr)["integrity_failures"]), 1)

    def test_the_cursor_needs_a_durable_output_file(self):
        base = ("audit", "export", "--projection-keyring", str(self.keyring_path))
        self.assertEqual(self.cli(*base, "--cursor-file", str(self.cursor))[0], 2)
        self.assertEqual(self.cli(*base, "--out", str(self.out))[0], 2)
        self.assertEqual(self.cli(*base, "--no-cursor", "--cursor-file", str(self.cursor))[0], 2)
        self.assertFalse(self.cursor.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX symlinks")
    def test_the_output_must_be_a_regular_file_and_not_a_link(self):
        target = self.root / "elsewhere.jsonl"
        target.write_bytes(b"")
        self.out.symlink_to(target)
        self.assertEqual(self.export_cli()[0], 2)
        self.assertEqual(target.read_bytes(), b"")
        self.assertFalse(self.cursor.exists())
        self.out.unlink()
        self.out.mkdir()
        self.assertEqual(self.export_cli()[0], 2)
        self.out.rmdir()
        # A FIFO: with no reader the open fails at once (no hang); with a reader it opens and is refused.
        os.mkfifo(self.out)
        self.assertEqual(self.export_cli()[0], 2)
        reader = os.open(self.out, os.O_RDONLY | os.O_NONBLOCK)
        try:
            self.assertEqual(self.export_cli()[0], 2)
            self.assertEqual(os.read(reader, 1), b"")
        finally:
            os.close(reader)
        self.assertFalse(self.cursor.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX file modes")
    def test_a_readable_keyring_is_refused_before_anything_is_written(self):
        os.chmod(self.keyring_path, 0o644)
        code, _, stderr = self.export_cli()
        self.assertEqual(code, 2)
        self.assertIn("chmod 600", stderr)
        self.assertFalse(self.out.exists())
        self.assertFalse(self.cursor.exists())


class StoreParityTests(unittest.TestCase):
    """Every store answers audit_export_page the same way (the paging rule is shared, the reads are not)."""

    def check(self, store):
        host_signer = signer()
        host = make_host(host_id=HOST, signer=host_signer, store=store, allow_ephemeral_signing_key=True)
        for goal in ("one", "two", "three"):
            host.run(make_demo_envelope(host, goal))
        projector = Projector(ProjectionPolicy.builtin(), Keyring("a", {"a": KEY_A}))
        outputs = []
        for page_size, max_events in ((500, 2000), (1, 1), (2, 3)):
            out = MemoryOut()
            report = run_export(store, ExportCursor(None), projector, out, verifier=registry(host_signer), durable=False,
                                page_size=page_size, max_events=max_events)
            self.assertTrue(report.ok, report.integrity_failures)
            self.assertEqual(report.heads, 3)
            outputs.append(sorted(out.getvalue().splitlines()))
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[0], outputs[2])
        verification = VerifyReport()
        records = read_export(outputs[0], verification)
        verify_records(records, registry(host_signer), verification)
        verify_against_store(records, store, ProjectionPolicy.builtin(), Keyring("a", {"a": KEY_A}), verification)
        self.assertEqual(verification.status, "valid", verification.reasons)
        with self.assertRaises(ValueError):
            store.audit_export_page(None, {}, 0)
        with self.assertRaises(ValueError):
            store.audit_export_page(None, {}, 1, 0)

    def test_in_memory_store(self):
        self.check(InMemoryRuntimeStore())

    def test_sqlite_store(self):
        with tempfile.TemporaryDirectory() as directory:
            self.check(SQLiteRuntimeStore(str(Path(directory) / "runtime.sqlite")))

    @unittest.skipUnless(PG_DSN and HAVE_PSYCOPG, "live PostgreSQL required")
    def test_postgres_store(self):
        self.check(PostgresRuntimeStore(PG_DSN, schema=f"export_{os.urandom(4).hex()}"))


if __name__ == "__main__":
    unittest.main()

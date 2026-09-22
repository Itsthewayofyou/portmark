"""EV-013 PR 1: the reference remote witness -- chain rules end to end, authentication, the append-only
log, and the client's fail-closed answer checks. All requests go through the real ASGI app in-process."""

import asyncio
import json
import os
import socket
import sqlite3
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_fixtures import AUDITOR, HOST, OPERATOR, OTHER_HOST, WitnessCase, asgi_transport, head, mode_of

from portmark.remote_witness import (
    FORKED,
    ROLLED_BACK,
    STATE_PATH,
    WitnessClient,
    WitnessUnavailable,
    digest,
    generate_key_file,
    http_transport,
    load_private_key_file,
    public_key_bytes,
    sign_answer,
    sign_request,
)
from portmark.security import canonical_json
from portmark.witness_server import Enrolment, WitnessLog, WitnessService, bind_problems, fold_log, make_witness_app


class ChainTests(WitnessCase, unittest.TestCase):
    def test_advance_is_pending_until_the_next_advance_confirms_it(self):
        client = self.w.client()
        first = client.advance(HOST, 1, None, {"t1": head(1, "h1")}, time_floor=500)
        self.assertEqual((first.status, first.kind, first.body["confirmed"]), (200, "receipt", None))
        state = client.state(HOST, "t1").body
        self.assertEqual(state["pending"], {"host_seq": 1, "receipt_hash": first.receipt_hash})
        self.assertIsNone(state["confirmed"])
        self.assertEqual(state["task"], {"task_id": "t1", "confirmed": None, "pending": head(1, "h1")})
        self.assertEqual(state["time_floor"], 0)  # only a CONFIRMED advance moves the floor
        second = client.advance(HOST, 2, first.receipt_hash, {"t1": head(2, "h2")})
        self.assertEqual(second.body["confirmed"], {"host_seq": 1, "receipt_hash": first.receipt_hash})
        state = client.state(HOST, "t1").body
        self.assertEqual(state["confirmed"], {"host_seq": 1, "receipt_hash": first.receipt_hash})
        self.assertEqual(state["task"]["confirmed"], head(1, "h1"))
        self.assertEqual(state["time_floor"], 500)

    def test_an_identical_retry_gets_the_same_receipt_and_writes_nothing(self):
        client = self.w.client()
        first = client.advance(HOST, 1, None, {"t1": head(1, "h1")})
        rows = len(self.w.log.log_rows(HOST))
        self.w.clock[0] += 60
        again = client.advance(HOST, 1, None, {"t1": head(1, "h1")})
        self.assertEqual(again.receipt_hash, first.receipt_hash)
        self.assertEqual(len(self.w.log.log_rows(HOST)), rows)

    def test_a_lost_commit_is_discarded_by_building_on_the_confirmed_receipt(self):
        client = self.w.client()
        first = client.advance(HOST, 1, None, {"t1": head(1, "h1")})
        lost = client.advance(HOST, 2, first.receipt_hash, {"t1": head(2, "h2-lost")})
        # The host's commit of `lost` failed; its next save builds on `first` again, same sequence.
        retry = client.advance(HOST, 2, first.receipt_hash, {"t1": head(2, "h2-other")})
        self.assertEqual(retry.body["discarded"], lost.receipt_hash)
        self.assertEqual(client.state(HOST).body["pending"]["receipt_hash"], retry.receipt_hash)
        kinds = [row[0] for row in self.w.log.log_rows(HOST)]
        self.assertEqual(kinds, ["advance", "advance", "discard", "advance"])

    def test_a_restored_host_is_refused_as_rolled_back(self):
        client = self.w.client()
        first = client.advance(HOST, 1, None, {"t1": head(1, "h1")})
        second = client.advance(HOST, 2, first.receipt_hash, {"t1": head(2, "h2")})
        client.advance(HOST, 3, second.receipt_hash, {"t1": head(3, "h3")})
        # A restored database knows only `first` (or nothing): a NEW task does not hide it.
        for prev, seq in ((first.receipt_hash, 2), (None, 1)):
            refused = client.advance(HOST, seq, prev, {"new-task": head(1, "n1")})
            self.assertEqual((refused.status, refused.code), (409, ROLLED_BACK), prev)

    def test_two_clones_are_told_apart_by_the_next_commit(self):
        # Clones A and B share every key and the same last receipt.
        clone_a, clone_b = self.w.client(), self.w.client()
        base = clone_a.advance(HOST, 1, None, {})
        confirmed = clone_a.advance(HOST, 2, base.receipt_hash, {})
        a_commit = clone_a.advance(HOST, 3, confirmed.receipt_hash, {"a-task": head(1, "a1")})
        b_commit = clone_b.advance(HOST, 3, confirmed.receipt_hash, {"b-task": head(1, "b1")})  # discards A's
        self.assertEqual(b_commit.body["discarded"], a_commit.receipt_hash)
        refused = clone_a.advance(HOST, 4, a_commit.receipt_hash, {"a-task": head(2, "a2")})
        self.assertEqual(refused.code, FORKED)
        # If A had gone on first instead, B (still on the old receipt) is behind: refused too.
        b_next = clone_b.advance(HOST, 4, b_commit.receipt_hash, {})
        refused = clone_a.advance(HOST, 3, confirmed.receipt_hash, {})
        self.assertEqual(refused.code, ROLLED_BACK)
        self.assertEqual(b_next.status, 200)

    def test_an_unknown_receipt_is_forked_and_a_wrong_sequence_is_refused(self):
        client = self.w.client()
        first = client.advance(HOST, 1, None, {})
        self.assertEqual(client.advance(HOST, 2, "f" * 64, {}).code, FORKED)
        self.assertEqual(client.advance(HOST, 5, first.receipt_hash, {}).code, "sequence-mismatch")
        # Another host's receipt is unknown to this host's chain.
        other = self.w.client(OTHER_HOST).advance(OTHER_HOST, 1, None, {})
        self.assertEqual(client.advance(HOST, 2, other.receipt_hash, {}).code, FORKED)

    def test_task_heads_never_go_back_or_split(self):
        client = self.w.client()
        first = client.advance(HOST, 1, None, {"t1": head(5, "h5")})
        second = client.advance(HOST, 2, first.receipt_hash, {"t1": head(6, "h6")})  # confirms t1 at 5
        self.assertEqual(client.advance(HOST, 3, second.receipt_hash, {"t1": head(4, "h4")}).code, ROLLED_BACK)
        self.assertEqual(client.advance(HOST, 3, second.receipt_hash, {"t1": head(6, "h6-other")}).code, FORKED)  # vs pending
        self.assertEqual(client.advance(HOST, 3, second.receipt_hash, {"t1": head(6, "h6")}).status, 200)  # same head: fine
        # A DISCARDED advance's head is not witnessed: the retry may write a different head at that sequence.
        base = self.w.client(OTHER_HOST)
        one = base.advance(OTHER_HOST, 1, None, {})
        base.advance(OTHER_HOST, 2, one.receipt_hash, {"t9": head(3, "lost")})
        self.assertEqual(base.advance(OTHER_HOST, 2, one.receipt_hash, {"t9": head(3, "kept")}).status, 200)

    def test_the_registry_never_goes_back_and_one_version_has_one_digest(self):
        client = self.w.client()
        first = client.advance(HOST, 1, None, {}, registry={"version": 3, "digest": "d3"})
        second = client.advance(HOST, 2, first.receipt_hash, {}, registry={"version": 3, "digest": "d3"})
        for registry, code in (({"version": 2, "digest": "d2"}, "registry-rolled-back"),
                               ({"version": 3, "digest": "other"}, "registry-forked"), (None, "registry-missing")):
            self.assertEqual(client.advance(HOST, 3, second.receipt_hash, {}, registry=registry).code, code)
        self.assertEqual(client.advance(HOST, 3, second.receipt_hash, {}, registry={"version": 4, "digest": "d4"}).status, 200)

    def test_the_time_floor_only_rises(self):
        client = self.w.client()
        a = client.advance(HOST, 1, None, {}, time_floor=900)
        b = client.advance(HOST, 2, a.receipt_hash, {}, time_floor=100)
        client.advance(HOST, 3, b.receipt_hash, {}, time_floor=950)
        self.assertEqual(client.state(HOST).body["time_floor"], 900)


class RebaselineTests(WitnessCase, unittest.TestCase):
    def test_an_operator_rebaseline_starts_a_new_epoch_from_the_hosts_database(self):
        host = self.w.client()
        first = host.advance(HOST, 1, None, {"t1": head(3, "h3")}, time_floor=900)
        second = host.advance(HOST, 2, first.receipt_hash, {"t1": head(4, "h4")}, time_floor=900)
        operator = self.w.client(OPERATOR)
        stale = operator.rebaseline(HOST, first.receipt_hash, "restored from backup", {"t1": head(3, "h3")}, None, 100)
        self.assertEqual(stale.code, "stale-rebaseline")
        # The host cannot rebaseline itself: its key signing under the operator's name is refused.
        forged = self.w.client(OPERATOR, key=self.w.keys[HOST]).rebaseline(HOST, second.receipt_hash, "x", {}, None, 0)
        self.assertEqual((forged.status, forged.code), (401, "unauthenticated"))
        done = operator.rebaseline(HOST, second.receipt_hash, "restored from backup", {"t1": head(3, "h3")}, None, 100)
        self.assertEqual((done.status, done.kind, done.body["epoch"], done.body["host_seq"]), (200, "rebaseline", 2, 3))
        state = host.state(HOST, "t1").body
        self.assertEqual((state["epoch"], state["time_floor"], state["pending"]), (2, 100, None))
        self.assertEqual(state["task"]["confirmed"], head(3, "h3"))
        # The old chain is refused (older epoch), and the host goes on from the rebaseline receipt.
        self.assertEqual(host.advance(HOST, 3, second.receipt_hash, {}).code, FORKED)  # discarded pending
        self.assertEqual(host.advance(HOST, 2, first.receipt_hash, {}).code, ROLLED_BACK)
        self.assertEqual(host.advance(HOST, 4, done.receipt_hash, {"t1": head(4, "h4b")}).status, 200)


class AuthenticationTests(WitnessCase, unittest.TestCase):
    def test_every_request_needs_an_enrolled_key_in_the_right_role(self):
        stranger = Ed25519PrivateKey.generate()
        cases = {
            "wrong key for the host": self.w.client(HOST, key=stranger).advance(HOST, 1, None, {}),
            "host advances another host": self.w.client(HOST).advance(OTHER_HOST, 1, None, {}),
            "auditor advances": self.w.client(AUDITOR).advance(HOST, 1, None, {}),
            "host reads another host": self.w.client(HOST).state(OTHER_HOST),
            "host rebaselines": self.w.client(HOST).rebaseline(HOST, None, "x", {}, None, 0),
            "unenrolled host": self.w.client("host:ghost", key=stranger).advance("host:ghost", 1, None, {}),
            "operator for an unenrolled host": self.w.client(OPERATOR).rebaseline("host:ghost", None, "x", {}, None, 0),
        }
        for label, answer in cases.items():
            self.assertEqual((answer.status, answer.code), (401, "unauthenticated"), label)
        self.assertEqual(self.w.log.log_rows(HOST), [])
        self.assertEqual(self.w.client(AUDITOR).state(HOST).status, 200)  # an auditor may read

    def test_a_request_for_another_witness_is_refused(self):
        other_witness = Ed25519PrivateKey.generate()
        client = WitnessClient(asgi_transport(self.w.app), public_key_bytes(other_witness), HOST, self.w.keys[HOST])
        # The refusal is signed by THIS witness, not the pinned one: the client cannot trust it either.
        with self.assertRaisesRegex(WitnessUnavailable, "other than the pinned"):
            client.advance(HOST, 1, None, {})
        body = {"format": "portmark.witness.advance.v1", "witness_key_id": "ed25519:" + "0" * 32, "host_id": HOST,
                "host_seq": 1, "prev": None, "heads": {}, "registry": None, "time_floor": 0}
        status, document = self.w.service.handle("/v1/advance", canonical_json(sign_request(self.w.keys[HOST], HOST, body)))
        self.assertEqual((status, document["body"]["code"]), (400, "wrong-witness"))

    def test_rate_limits_answer_a_signed_refusal(self):
        client = self.w.client()
        codes = [client.state(HOST).code for _ in range(205)]
        self.assertIn("rate-limited", codes)
        self.w.monotonic[0] += 10.0  # the bucket refills
        self.assertIsNone(client.state(HOST).code)


class LogTests(WitnessCase, unittest.TestCase):
    def test_the_log_is_append_only(self):
        self.w.client().advance(HOST, 1, None, {})
        connection = sqlite3.connect(self.w.log.path)
        try:
            for statement in ("UPDATE witness_log SET host_seq = 9", "DELETE FROM witness_log"):
                with self.assertRaisesRegex(sqlite3.DatabaseError, "append-only"):
                    connection.execute(statement)
        finally:
            connection.close()

    def test_the_derived_state_is_exactly_the_fold_of_the_log(self):
        host, operator = self.w.client(), self.w.client(OPERATOR)
        a = host.advance(HOST, 1, None, {"t1": head(1, "a")}, registry={"version": 1, "digest": "d"}, time_floor=10)
        b = host.advance(HOST, 2, a.receipt_hash, {"t1": head(2, "b"), "t2": head(1, "x")}, registry={"version": 1, "digest": "d"}, time_floor=20)
        host.advance(HOST, 3, b.receipt_hash, {"t1": head(3, "lost")}, registry={"version": 1, "digest": "d"})
        c = host.advance(HOST, 3, b.receipt_hash, {"t1": head(3, "c")}, registry={"version": 2, "digest": "e"}, time_floor=30)
        r = operator.rebaseline(HOST, c.receipt_hash, "drill", {"t1": head(2, "b")}, {"version": 2, "digest": "e"}, 5)
        registry = {"version": 2, "digest": "e"}
        d = host.advance(HOST, 5, r.receipt_hash, {"t3": head(1, "z")}, registry=registry)
        host.advance(HOST, 6, d.receipt_hash, {"t4": head(1, "lost")}, registry=registry)  # discarded next
        e = host.advance(HOST, 6, d.receipt_hash, {"t3": head(2, "zz")}, registry=registry)
        host.advance(HOST, 7, e.receipt_hash, {}, registry=registry)
        state, heads = fold_log(self.w.log, HOST)
        self.assertEqual(state, self.w.log.host_state(HOST))
        self.assertEqual(heads, self.w.log.task_heads(HOST))
        self.assertEqual(heads, {"t1": head(2, "b"), "t3": head(2, "zz")})

    def test_files_are_owner_only(self):
        self.assertEqual(mode_of(self.w.log.path), 0o600)
        loose = os.path.join(self._dir.name, "loose.sqlite")
        with open(loose, "w"):
            pass
        os.chmod(loose, 0o644)
        if os.name == "posix":
            with self.assertRaisesRegex(ValueError, "chmod 600"):
                WitnessLog(loose)
        key_path = os.path.join(self._dir.name, "witness.key")
        public = generate_key_file(key_path)
        self.assertEqual(mode_of(key_path), 0o600)
        self.assertEqual(public_key_bytes(load_private_key_file(key_path)), public)
        with self.assertRaises(FileExistsError):
            generate_key_file(key_path)
        if os.name == "posix":
            os.chmod(key_path, 0o640)
            with self.assertRaisesRegex(ValueError, "chmod 600"):
                load_private_key_file(key_path)


class EnrolmentAndBindTests(WitnessCase, unittest.TestCase):
    def write(self, document):
        path = os.path.join(self._dir.name, "e.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        return path

    def test_enrolment_is_strict(self):
        key = self.w.public(HOST)
        bad = {
            "no format": {"hosts": {}},
            "unknown field": {"format": "portmark.witness.enrolment.v1", "extra": 1},
            "one id in two roles": {"format": "portmark.witness.enrolment.v1", "hosts": {"x": {"public_key_b64": key}},
                                    "operators": {"x": {"public_key_b64": key}}},
            "bad key": {"format": "portmark.witness.enrolment.v1", "hosts": {"x": {"public_key_b64": "AAAA"}}},
        }
        for label, document in bad.items():
            with self.assertRaises(ValueError, msg=label):
                Enrolment.from_path(self.write(document))

    def test_a_public_bind_needs_the_tls_acknowledgement(self):
        self.assertEqual(bind_problems("127.0.0.1", None), [])
        self.assertEqual(bind_problems("::1", None), [])
        for bind in ("0.0.0.0", "10.0.0.5", "witness.example"):  # nosec B104 -- the refusal under test
            self.assertTrue(bind_problems(bind, None), bind)
            self.assertTrue(bind_problems(bind, "yes"), bind)
            self.assertEqual(bind_problems(bind, "behind-tls-proxy"), [], bind)

    def test_http_endpoints(self):
        def call(method, path, body=b""):
            messages = [{"type": "http.request", "body": body, "more_body": False}]
            out = {"body": b""}

            async def receive():
                return messages.pop(0) if messages else {"type": "http.disconnect"}

            async def send(message):
                if message["type"] == "http.response.start":
                    out["status"] = message["status"]
                else:
                    out["body"] += message.get("body", b"")

            asyncio.run(self.w.app({"type": "http", "method": method, "path": path,
                                    "headers": [(b"content-length", str(len(body)).encode())]}, receive, send))
            return out["status"], out["body"]

        self.assertEqual(call("GET", "/healthz"), (200, b"ok\n"))
        status, raw = call("GET", STATE_PATH)
        self.assertEqual((status, json.loads(raw)["body"]["code"]), (404, "not-found"))
        status, raw = call("POST", STATE_PATH, b"x" * (1024 * 1024 + 1))
        self.assertEqual((status, json.loads(raw)["body"]["code"]), (413, "too-large"))
        status, raw = call("POST", STATE_PATH, b"{not json")
        self.assertEqual((status, json.loads(raw)["body"]["code"]), (400, "malformed"))


class ClientTests(WitnessCase, unittest.TestCase):
    """The client accepts only answers signed by the pinned key AND bound to the request just sent."""

    def via(self, change):
        """A client whose transport passes each answer through change(status, document)."""
        inner = asgi_transport(self.w.app)

        def transport(path, payload):
            status, raw = inner(path, payload)
            status, document = change(status, json.loads(raw))
            return status, canonical_json(document)

        return self.w.client(transport=transport)

    def test_forged_replayed_or_mismatched_answers_are_refused(self):
        stranger = Ed25519PrivateKey.generate()
        old = self.w.client().state(HOST).document

        def resign(document, **changes):
            return sign_answer(self.w.key, {**document["body"], **changes})

        cases = {
            "signed by another key": lambda status, document: (status, sign_answer(stranger, document["body"])),
            "a replayed older answer": lambda status, document: (status, old),
            "the body edited after signing": lambda status, document: (status, {**document, "body": {**document["body"], "time_floor": 1}}),
            "a refusal sent as 200": lambda status, document: (200, resign(document, kind="refusal", code="x")),
            "an error status without a refusal": lambda status, document: (500, document),
            "another host": lambda status, document: (status, resign(document, host_id=OTHER_HOST)),
            "another nonce": lambda status, document: (status, resign(document, nonce="0" * 32)),
        }
        for label, change in cases.items():
            with self.assertRaises(WitnessUnavailable, msg=label):
                self.via(change).state(HOST)

    def test_a_receipt_for_another_advance_is_refused(self):
        client = self.w.client()
        first = client.advance(HOST, 1, None, {})

        def swap(status, document):
            return status, sign_answer(self.w.key, {**document["body"], "host_seq": 7})

        with self.assertRaisesRegex(WitnessUnavailable, "does not match"):
            self.via(swap).advance(HOST, 2, first.receipt_hash, {})

    def test_a_genuine_receipt_for_a_different_advance_is_refused(self):
        # Same host_seq and prev, validly signed by the pinned witness, but for OTHER heads: only the
        # request digest tells them apart.
        other = self.w.client().advance(HOST, 1, None, {"t1": head(1, "real")}).document
        with self.assertRaisesRegex(WitnessUnavailable, "not bound"):
            self.via(lambda status, document: (status, other)).advance(HOST, 1, None, {"t1": head(1, "forged")})

    def test_no_witness_is_unavailable_never_an_empty_answer(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        client = WitnessClient(http_transport(f"http://127.0.0.1:{port}", timeout=0.5), public_key_bytes(self.w.key), HOST, self.w.keys[HOST])
        with self.assertRaises(WitnessUnavailable) as caught:
            client.state(HOST)
        self.assertEqual(caught.exception.code, "witness-unavailable")
        not_json = WitnessClient(lambda path, payload: (200, b"<html>"), public_key_bytes(self.w.key), HOST, self.w.keys[HOST])
        with self.assertRaises(WitnessUnavailable):
            not_json.state(HOST)

    def test_the_url_must_be_https_except_on_loopback(self):
        http_transport("https://witness.example:8443/prefix")
        http_transport("http://127.0.0.1:8787")
        http_transport("http://localhost:8787")
        for url in ("http://witness.example", "ftp://witness.example", "https://", "https://w.example/?q=1"):
            with self.assertRaises(ValueError, msg=url):
                http_transport(url)

    def test_request_digests_are_what_the_answer_binds(self):
        answer = self.w.client().state(HOST)
        self.assertEqual(answer.body["request_sha256"], answer.request_sha256)
        self.assertEqual(answer.receipt_hash, digest(answer.body))


class ServerRestartTests(WitnessCase, unittest.TestCase):
    def test_a_restarted_server_reads_the_same_chain(self):
        receipt = self.w.client().advance(HOST, 1, None, {})
        self.w.log.close()
        self.w.log = WitnessLog(self.w.log.path)
        self.w.service = WitnessService(self.w.log, self.w.key, Enrolment.from_path(str(self.w.enrolment_path)))
        self.w.app = make_witness_app(self.w.service)
        self.assertEqual(self.w.client().state(HOST).body["pending"]["receipt_hash"], receipt.receipt_hash)


if __name__ == "__main__":
    unittest.main()

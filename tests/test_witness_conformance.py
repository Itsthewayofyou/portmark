"""EV-013 PR 1: the witness conformance kit. It must PASS the reference witness (again and again) and
FAIL each kind of broken witness on the case that shows the break -- including a witness that agrees
to everything and one that answers stale state. End to end: `portmark witness serve` + `portmark
witness conformance` over real HTTP."""

import io
import json
import os
import socket
import subprocess  # nosec B404 -- runs this interpreter on the fixed portmark CLI
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from witness_fixtures import CONFORMANCE_HOST, HOST, WitnessCase, asgi_transport

from portmark import witness_server
from portmark.cli import main as cli_main
from portmark.remote_witness import Decision, WitnessUnavailable, public_key_bytes, sign_answer, state_body
from portmark.security import _b64url_encode
from portmark.witness_conformance import run_witness_conformance

SRC = str(Path(__file__).resolve().parents[1] / "src")
REFUSAL_CASES = {"restored-host-refused", "discarded-receipt-refused", "task-head-split-refused",
                 "task-head-rollback-refused", "registry-rollback-refused"}


def failed(report):
    return {case.name for case in report.cases if not case.passed}


class ConformanceKitTests(WitnessCase, unittest.TestCase):
    def run_kit(self, pinned=None, host_id=CONFORMANCE_HOST):
        pinned = public_key_bytes(self.w.key) if pinned is None else pinned
        return run_witness_conformance(asgi_transport(self.w.app), pinned, host_id, self.w.keys.get(host_id) or Ed25519PrivateKey.generate())

    def test_the_reference_witness_passes_every_time(self):
        for attempt in range(3):  # later runs start from the pending advance the last run left
            report = self.run_kit()
            self.assertTrue(report.passed, (attempt, report.to_dict()))
        self.assertEqual(len(report.cases), 13)

    def test_it_refuses_to_touch_a_real_hosts_chain(self):
        for host_id in (HOST, "conformance:", "Conformance:x"):
            with self.assertRaisesRegex(ValueError, "conformance:"):
                self.run_kit(host_id=host_id)

    def test_a_witness_that_agrees_to_everything_fails(self):
        def agree(state, body, request_sha256, task_head, known):
            pending = state.pending
            if pending is not None and request_sha256 == pending.request_sha256:
                return Decision("replay")  # retries still work: only the refusals are missing
            if pending is not None and body["prev"] == pending.receipt_hash:
                return Decision("accept", confirm=pending)
            return Decision("accept", discard=pending)

        with patch.object(witness_server, "decide_advance", agree):
            report = self.run_kit()
        self.assertFalse(report.passed)
        # The FIRST refusal case really ran and saw an acceptance. That acceptance moved the chain, so the
        # kit stops the accept cases that need it; every later case fails as skipped (fail closed).
        first_failure = next(case for case in report.cases if not case.passed)
        self.assertEqual((first_failure.name, first_failure.outcome), ("restored-host-refused", "accepted"))
        self.assertLessEqual(REFUSAL_CASES, failed(report))

    def test_a_witness_that_goes_down_mid_run_fails_there_and_skips_the_rest(self):
        inner = asgi_transport(self.w.app)
        calls = []

        def flaky(path, payload):
            calls.append(path)
            if len(calls) > 3:
                raise WitnessUnavailable("connection refused")
            return inner(path, payload)

        report = run_witness_conformance(flaky, public_key_bytes(self.w.key), CONFORMANCE_HOST, self.w.keys[CONFORMANCE_HOST])
        outcomes = [case.outcome for case in report.cases]
        self.assertEqual(outcomes[:5], ["accepted", "accepted", "accepted", "unavailable", "skipped"])
        self.assertEqual(set(outcomes[4:]), {"skipped"})
        self.assertEqual(len(calls), 4)  # nothing more is sent once the witness is gone
        self.assertFalse(report.passed)

    def test_a_witness_that_answers_stale_state_fails_the_read_back(self):
        first_seen = {}
        real = witness_server.state_body

        def stale(state, request, request_sha256, task, key_id, at):
            # A fresh signature, nonce, and binding over OLD content: only the content is stale.
            first_seen.setdefault(state.host_id, (state, task))
            old_state, old_task = first_seen[state.host_id]
            return real(old_state, request, request_sha256, old_task, key_id, at)

        with patch.object(witness_server, "state_body", stale):
            report = self.run_kit()
        self.assertEqual(failed(report), {"state-reflects-the-chain"})

    def test_a_witness_that_cannot_discard_a_lost_commit_fails(self):
        real = witness_server.decide_advance

        def no_discard(state, body, request_sha256, task_head, known):
            decision = real(state, body, request_sha256, task_head, known)
            if decision.outcome == "accept" and decision.discard is not None and decision.confirm is None:
                return Decision("refuse", "forked", "no discards here")
            return decision

        with patch.object(witness_server, "decide_advance", no_discard):
            report = self.run_kit()
        self.assertIn("lost-commit-discarded", failed(report))
        self.assertNotIn("first-advance", failed(report))

    def test_a_witness_that_is_not_idempotent_fails(self):
        real = witness_server.decide_advance

        def no_replay(state, body, request_sha256, task_head, known):
            if state.pending is not None and request_sha256 == state.pending.request_sha256:
                state = type(state)(**{**state.__dict__, "pending": type(state.pending)(**{**state.pending.__dict__, "request_sha256": "x"})})
            return real(state, body, request_sha256, task_head, known)

        with patch.object(witness_server, "decide_advance", no_replay):
            self.w.clock[0] += 1  # a new receipt differs by its accepted_at
            report = self.run_kit()
        self.assertIn("identical-retry", failed(report))

    def test_a_witness_that_skips_authentication_fails(self):
        def blind(raw, public_key_for):
            envelope = json.loads(raw)  # parsed, never verified
            return envelope["signer"], envelope["body"]

        with patch.object(witness_server, "open_request", blind):
            report = self.run_kit()
        # The stranger's advance was accepted, so the chain also moved under the later cases.
        self.assertIn("unenrolled-key-refused", failed(report))
        self.assertLessEqual(failed(report), {"unenrolled-key-refused", "fourth-advance-confirms-the-retry", "state-reflects-the-chain"})

    def test_answers_from_another_key_fail_at_once(self):
        report = self.run_kit(pinned=public_key_bytes(Ed25519PrivateKey.generate()))
        self.assertFalse(report.passed)
        self.assertEqual(report.cases[0].outcome, "unavailable")
        self.assertEqual(len(report.cases), 1)

    def test_signed_answers_are_what_the_kit_checks(self):
        # Sanity: the patched helpers above are the ones the service really calls.
        self.assertIs(witness_server.state_body, state_body)
        self.assertIs(witness_server.sign_answer, sign_answer)


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def child_env():
    env = {key: value for key, value in os.environ.items() if not key.startswith("PORTMARK_")}
    env.update(PYTHONPATH=SRC, PYTHONDONTWRITEBYTECODE="1")
    return env


def run_cli(argv):
    stdout, stderr = io.StringIO(), io.StringIO()
    code = 0
    with patch.object(sys, "argv", ["portmark", *argv]), redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            cli_main()
        except SystemExit as exit_:
            code = exit_.code
    return code, stdout.getvalue(), stderr.getvalue()


class WitnessCliTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)

    def tearDown(self):
        self._dir.cleanup()

    def keygen(self, name):
        code, out, _ = run_cli(["witness", "keygen", "--out", str(self.root / name)])
        self.assertEqual(code, 0)
        return json.loads(out)

    def serve(self, *extra):
        return subprocess.Popen(  # nosec B603 -- this interpreter, the fixed portmark CLI
            [sys.executable, "-c", "from portmark.cli import main; main()", "witness", "serve",
             "--db", str(self.root / "witness.sqlite"), "--key-file", str(self.root / "witness.key"),
             "--enrolment", str(self.root / "enrolment.json"), *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=child_env(),
        )

    def test_keygen_never_overwrites(self):
        self.keygen("a.key")
        code, _, err = run_cli(["witness", "keygen", "--out", str(self.root / "a.key")])
        self.assertEqual(code, 2)
        self.assertIn("never overwritten", err)

    def test_serve_refuses_a_public_bind_without_the_tls_acknowledgement(self):
        self.keygen("witness.key")
        (self.root / "enrolment.json").write_text(json.dumps({"format": "portmark.witness.enrolment.v1"}), encoding="utf-8")
        server = self.serve("--bind", "0.0.0.0", "--port", str(free_port()))  # nosec B104 -- the refusal under test
        out, _ = server.communicate(timeout=120)
        self.assertEqual(server.returncode, 2)
        self.assertIn("behind-tls-proxy", json.loads(out)["reason"])

    def test_serve_and_conformance_end_to_end_over_http(self):
        witness = self.keygen("witness.key")
        host = self.keygen("conformance.key")
        (self.root / "enrolment.json").write_text(json.dumps({
            "format": "portmark.witness.enrolment.v1",
            "hosts": {"conformance:ci": {"public_key_b64": host["public_key_b64"]}},
        }), encoding="utf-8")
        port = free_port()
        server = self.serve("--port", str(port))
        try:
            base = f"http://127.0.0.1:{port}"
            deadline = time.monotonic() + 60
            while True:
                try:
                    with urllib.request.urlopen(f"{base}/healthz", timeout=2):  # nosec B310 -- a local test server
                        break
                except (urllib.error.URLError, ConnectionError):
                    self.assertIsNone(server.poll(), "the witness exited before serving")
                    self.assertLess(time.monotonic(), deadline, "the witness never became healthy")
                    time.sleep(0.1)
            argv = ["witness", "conformance", "--url", base, "--host-id", "conformance:ci",
                    "--host-key-file", str(self.root / "conformance.key"), "--witness-public-key", witness["public_key_b64"]]
            for _ in range(2):
                code, out, _ = run_cli(argv)
                self.assertEqual(code, 0, out)
                self.assertEqual(json.loads(out)["status"], "pass")
            # Pinned to the wrong key: every answer is refused, and the kit fails (exit 1).
            wrong = _b64url_encode(public_key_bytes(Ed25519PrivateKey.generate()))
            code, out, _ = run_cli(argv[:-1] + [wrong])
            self.assertEqual((code, json.loads(out)["status"]), (1, "fail"))
            # A real host's id is refused before anything is sent.
            code, _, err = run_cli(["witness", "conformance", "--url", base, "--host-id", "host:prod",
                                    "--host-key-file", str(self.root / "conformance.key"), "--witness-public-key", witness["public_key_b64"]])
            self.assertEqual(code, 2)
            self.assertIn("conformance:", err)
        finally:
            server.terminate()
            server.communicate(timeout=30)

    def test_the_key_file_holds_a_raw_ed25519_key(self):
        public = self.keygen("k.key")
        from portmark.remote_witness import load_private_key_file

        key = load_private_key_file(str(self.root / "k.key"))
        raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self.assertEqual(len(raw), 32)
        self.assertEqual(_b64url_encode(public_key_bytes(key)), public["public_key_b64"])


if __name__ == "__main__":
    unittest.main()

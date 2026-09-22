"""Shared EV-013 test fixtures: an in-process reference witness and an ASGI transport (no sockets)."""

import asyncio
import json
import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from portmark.remote_witness import WitnessClient, public_key_bytes
from portmark.security import _b64url_encode
from portmark.witness_server import ENROLMENT_FORMAT, Enrolment, WitnessLog, WitnessService, make_witness_app

HOST = "host:alpha"
OTHER_HOST = "host:beta"
CONFORMANCE_HOST = "conformance:kit"
OPERATOR = "operator:alice"
AUDITOR = "auditor:bob"


def asgi_transport(app, path_prefix=""):
    """POST through an ASGI app in this process, like http_transport does over the network."""

    def send(path, payload):
        messages = [{"type": "http.request", "body": payload, "more_body": False}]
        out = {"body": b""}

        async def receive():
            return messages.pop(0) if messages else {"type": "http.disconnect"}

        async def sender(message):
            if message["type"] == "http.response.start":
                out["status"] = message["status"]
            else:
                out["body"] += message.get("body", b"")

        scope = {"type": "http", "method": "POST", "path": path_prefix + path,
                 "headers": [(b"content-length", str(len(payload)).encode())]}
        asyncio.run(app(scope, receive, sender))
        return out["status"], out["body"]

    return send


class Witness:
    """A reference witness on a temporary SQLite file, with enrolled host, operator, and auditor keys."""

    def __init__(self, root, extra_hosts=()):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.key = Ed25519PrivateKey.generate()
        hosts = (HOST, OTHER_HOST, CONFORMANCE_HOST, *extra_hosts)
        self.keys = {name: Ed25519PrivateKey.generate() for name in (*hosts, OPERATOR, AUDITOR)}
        self.enrolment_path = self.root / "enrolment.json"
        self.enrolment_path.write_text(json.dumps({
            "format": ENROLMENT_FORMAT,
            "hosts": {name: {"public_key_b64": self.public(name)} for name in hosts},
            "operators": {OPERATOR: {"public_key_b64": self.public(OPERATOR)}},
            "auditors": {AUDITOR: {"public_key_b64": self.public(AUDITOR)}},
        }), encoding="utf-8")
        self.clock = [1_000_000]
        self.monotonic = [0.0]
        self.log = WitnessLog(str(self.root / "witness.sqlite"))
        self.service = WitnessService(
            self.log, self.key, Enrolment.from_path(str(self.enrolment_path)),
            clock=lambda: self.clock[0], monotonic=lambda: self.monotonic[0],
        )
        self.app = make_witness_app(self.service)

    def public(self, name):
        return _b64url_encode(public_key_bytes(self.keys[name]))

    def client(self, signer=HOST, key=None, transport=None):
        return WitnessClient(
            transport or asgi_transport(self.app), public_key_bytes(self.key), signer, key if key is not None else self.keys[signer],
        )

    def close(self):
        self.log.close()


class WitnessCase:
    """Mixin: self.w is a fresh Witness per test."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.w = Witness(self._dir.name)

    def tearDown(self):
        self.w.close()
        self._dir.cleanup()


def head(sequence, head_hash):
    return {"sequence": sequence, "head_hash": head_hash}


def mode_of(path):
    return os.stat(path).st_mode & 0o777

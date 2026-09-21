"""Section 11 PR C: the container entrypoint's public-mode gate (#1) and one proxy authority (#6).

#1: the image launched raw uvicorn on 0.0.0.0 with no bearer token, no TLS assertion, and uvicorn's
own proxy handling. `python -m portmark.serve_asgi` now owns the bind: loopback by default, and a
public bind needs the acknowledgement, a token, trusted-proxy CIDRs, and an https public URL, all
together (owner decision D1a: the acknowledgement alone never weakens anything).

#6: uvicorn's default proxy_headers=True rewrote the peer from X-Forwarded-For (for 127.0.0.1) before
Portmark's trusted-proxy policy ran. Both server paths now pass proxy_headers=False.
"""

import dataclasses
import os
import shutil
import socket
import subprocess  # nosec B404 -- runs this test's own interpreter on a fixed module / inline script
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from portmark import serve_asgi
from portmark.config import RuntimeConfig
from portmark.serve_asgi import PUBLIC_MODE_ACK, public_mode_problems

SRC = str(Path(__file__).resolve().parent.parent / "src")
TOKEN = "t0ken-for-tests-only"  # nosec B105 -- a fixture value, not a credential
COMPLETE = {
    "ack": PUBLIC_MODE_ACK,
    "a2a_token": TOKEN,
    "a2a_trusted_proxies": "10.0.0.0/8",
    "a2a_public_base_url": "https://agents.example.com",
}


def config_with(**fields):
    return dataclasses.replace(RuntimeConfig(), **fields)


def problems_for(bind, **overrides):
    values = {**COMPLETE, **overrides}
    ack = values.pop("ack")
    return public_mode_problems(bind, config_with(**values), ack)


def child_env(**extra):
    env = {key: value for key, value in os.environ.items() if not key.startswith("PORTMARK_")}
    env.update(PYTHONPATH=SRC, PYTHONDONTWRITEBYTECODE="1")
    env.update(extra)
    return env


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class PublicModeGateTests(unittest.TestCase):
    def test_loopback_binds_need_nothing(self):
        for bind in ("127.0.0.1", "::1", "localhost", "127.8.9.10"):
            with self.subTest(bind=bind):
                self.assertEqual(public_mode_problems(bind, RuntimeConfig(), None), [])

    def test_the_acknowledgement_on_a_loopback_bind_changes_nothing(self):
        self.assertEqual(public_mode_problems("127.0.0.1", RuntimeConfig(), PUBLIC_MODE_ACK), [])

    def test_a_complete_public_configuration_may_start(self):
        for bind in ("0.0.0.0", "::", "192.0.2.10", "portmark.internal"):  # nosec B104 -- the public binds under test
            with self.subTest(bind=bind):
                self.assertEqual(problems_for(bind), [])

    def test_a_bare_public_bind_reports_all_four_requirements_at_once(self):
        problems = public_mode_problems("0.0.0.0", RuntimeConfig(), None)  # nosec B104 -- the public bind under test
        self.assertEqual(len(problems), 4, problems)
        joined = "\n".join(problems)
        for name in ("PORTMARK_PUBLIC_MODE", "PORTMARK_A2A_TOKEN", "PORTMARK_A2A_TRUSTED_PROXIES", "PORTMARK_A2A_PUBLIC_BASE_URL"):
            self.assertIn(name, joined)

    def test_the_acknowledgement_alone_never_suffices(self):
        problems = problems_for("0.0.0.0", a2a_token=None, a2a_trusted_proxies=None, a2a_public_base_url=None)  # nosec B104
        self.assertEqual(len(problems), 3, problems)
        self.assertFalse(any("PORTMARK_PUBLIC_MODE" in problem for problem in problems))

    def test_each_requirement_is_enforced_on_its_own(self):
        # Exactly one requirement missing (unset AND empty-string forms); the other three present.
        cases = {
            "PORTMARK_PUBLIC_MODE": [{"ack": None}, {"ack": ""}, {"ack": "yes"}, {"ack": "1"}],
            "PORTMARK_A2A_TOKEN": [{"a2a_token": None}, {"a2a_token": ""}, {"a2a_token": "   "}, {"a2a_token": "has space"}],  # nosec B105 -- invalid-token fixtures
            "PORTMARK_A2A_TRUSTED_PROXIES": [
                {"a2a_trusted_proxies": None}, {"a2a_trusted_proxies": ""}, {"a2a_trusted_proxies": " , "},
                {"a2a_trusted_proxies": "not-a-cidr"},
            ],
            "PORTMARK_A2A_PUBLIC_BASE_URL": [
                {"a2a_public_base_url": None}, {"a2a_public_base_url": ""},
                {"a2a_public_base_url": "http://agents.example.com"},
                {"a2a_public_base_url": "https://user:pass@agents.example.com"},
            ],
        }
        for name, variants in cases.items():
            for override in variants:
                with self.subTest(requirement=name, override=override):
                    problems = problems_for("0.0.0.0", **override)  # nosec B104 -- the public bind under test
                    self.assertEqual(len(problems), 1, problems)
                    self.assertIn(name, problems[0])


class EntrypointTests(unittest.TestCase):
    def test_refused_public_bind_never_starts_uvicorn(self):
        environ = {"PORTMARK_BIND_HOST": "0.0.0.0", "PORTMARK_PUBLIC_MODE": PUBLIC_MODE_ACK}  # nosec B104
        with patch("portmark.serve_asgi.run_uvicorn") as run, patch("sys.stderr"):
            self.assertEqual(serve_asgi.main(environ), serve_asgi.REFUSED_EXIT)
        run.assert_not_called()

    def test_default_bind_is_loopback_with_portmark_as_the_only_proxy_authority(self):
        # Section 12 #1: the entrypoint runs uvicorn through run_uvicorn (uvicorn.run plus the drain hook).
        with patch("portmark.serve_asgi.run_uvicorn") as run:
            self.assertEqual(serve_asgi.main({}), 0)
        run.assert_called_once()
        app, options = run.call_args.args
        self.assertEqual(app, "portmark.asgi:app")
        self.assertEqual((options["host"], options["port"]), ("127.0.0.1", 8080))
        self.assertIs(options["proxy_headers"], False)
        self.assertIsNone(options["log_config"])

    def test_bad_port_is_refused(self):
        for port in ("http", "0", "70000"):
            with self.subTest(port=port), patch("portmark.serve_asgi.run_uvicorn") as run, patch("sys.stderr"):
                self.assertEqual(serve_asgi.main({"PORTMARK_BIND_PORT": port}), serve_asgi.REFUSED_EXIT)
                run.assert_not_called()

    def test_cli_serve_also_disables_uvicorn_proxy_headers(self):
        from portmark.a2a import serve
        from portmark.factory import make_host

        with patch("portmark.a2a.run_uvicorn") as run:
            serve(make_host(None), "127.0.0.1", 8080)
        self.assertIs(run.call_args.args[1]["proxy_headers"], False)

    def test_public_refusal_from_a_real_process_lists_every_requirement(self):
        result = subprocess.run(  # nosec B603 -- this interpreter, fixed module
            [sys.executable, "-m", "portmark.serve_asgi"], capture_output=True, text=True, timeout=120,
            env=child_env(PORTMARK_BIND_HOST="0.0.0.0"),  # nosec B104 -- the public bind under test
        )
        self.assertEqual(result.returncode, serve_asgi.REFUSED_EXIT, result.stderr)
        for name in ("PORTMARK_PUBLIC_MODE", "PORTMARK_A2A_TOKEN", "PORTMARK_A2A_TRUSTED_PROXIES", "PORTMARK_A2A_PUBLIC_BASE_URL"):
            self.assertIn(name, result.stderr)


ENTRYPOINT_LOG_SCRIPT = """
import logging, sys
import uvicorn.config
import uvicorn.server

SECRET = sys.argv[1]
real_load_app = uvicorn.config.Config.load_app

def observed_load_app(self):
    # Layer 1, observed directly, in the window where it is load-bearing: uvicorn's Config has applied
    # (or skipped) its log config, and uvicorn.run() is about to import the app -- whose own
    # configure_logging (layer 2) would take the loggers over again. Uvicorn's own startup messages,
    # such as "Error loading ASGI app", are written in this window.
    server_logger = logging.getLogger("uvicorn")
    print(f"UVICORN_HANDLERS_BEFORE_APP={len(server_logger.handlers)} PROPAGATE={server_logger.propagate}", flush=True)
    return real_load_app(self)

def fake_run(self, sockets=None):
    # uvicorn.run() has already imported the app (Config.load_app) before calling this.
    self.started = True
    try:
        raise RuntimeError(f"db down postgres://u:{SECRET}@db/x")
    except RuntimeError:
        logging.getLogger("uvicorn.error").exception("Exception in ASGI application Authorization: Bearer %s", SECRET)

uvicorn.config.Config.load_app = observed_load_app
uvicorn.server.Server.run = fake_run
from portmark.serve_asgi import main
sys.exit(main())
"""


class EntrypointLogRedactionTests(unittest.TestCase):
    def test_the_container_entrypoint_keeps_uvicorn_output_redacted(self):
        # The same real-startup-order check PR A added for `portmark serve`, for the new entrypoint:
        # serve_asgi -> configure_logging -> uvicorn.run(log_config=None) -> Config -> app import.
        secret = "entrypoint-secret-value"  # nosec B105 -- a synthetic marker, not a credential
        result = subprocess.run(  # nosec B603 -- this interpreter, fixed inline script
            [sys.executable, "-c", ENTRYPOINT_LOG_SCRIPT, secret], capture_output=True, text=True, timeout=120,
            # Development profile: a loopback run with no public controls (production needs them all).
            env=child_env(PORTMARK_PROFILE="development"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        # Layer 1 (uvicorn.run(log_config=None)): uvicorn installed no handler of its own. Two layers
        # each keep the output redacted, so the secret check below alone could not see this one go.
        markers = [line for line in result.stdout.splitlines() if line.startswith("UVICORN_HANDLERS_BEFORE_APP=")]
        self.assertEqual(markers, ["UVICORN_HANDLERS_BEFORE_APP=0 PROPAGATE=True"])
        # Both layers together: the real output carries no secret.
        output = result.stdout + result.stderr
        self.assertIn("Exception in ASGI application", output)
        self.assertIn("Traceback", output)
        self.assertNotIn(secret, output)


class SingleProxyAuthorityTests(unittest.TestCase):
    """End to end on the REAL entrypoint and uvicorn: with no trusted proxies configured, a client that
    sends X-Forwarded-For must still be identified (and rate-limited) by its own peer address."""

    def test_forwarded_for_from_an_untrusted_peer_does_not_change_client_identity(self):
        port = free_port()
        server = subprocess.Popen(  # nosec B603 -- this interpreter, fixed module
            [sys.executable, "-m", "portmark.serve_asgi"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
            # Development profile: this test needs NO trusted proxy, which production refuses.
            env=child_env(PORTMARK_BIND_PORT=str(port), PORTMARK_A2A_AGENT_CARD_RATE_LIMIT_PER_IP="1",
                          PORTMARK_PROFILE="development"),
        )
        try:
            base = f"http://127.0.0.1:{port}"
            deadline = time.monotonic() + 60
            while True:
                try:
                    with urllib.request.urlopen(f"{base}/healthz", timeout=2):  # nosec B310 -- a local test server
                        break
                except (urllib.error.URLError, ConnectionError):
                    self.assertIsNone(server.poll(), "the entrypoint exited before serving")
                    self.assertLess(time.monotonic(), deadline, "the entrypoint never became healthy")
                    time.sleep(0.1)
            statuses = []
            for spoofed in ("198.51.100.1", "198.51.100.2"):
                request = urllib.request.Request(f"{base}/.well-known/agent-card.json", headers={"X-Forwarded-For": spoofed})
                try:
                    with urllib.request.urlopen(request, timeout=5) as response:  # nosec B310 -- a local test server
                        statuses.append(response.status)
                except urllib.error.HTTPError as error:
                    statuses.append(error.code)
            # One client, one allowance: the second request is limited even though it claims to be a
            # different address. With uvicorn's proxy handling on, each spoofed address got its own.
            self.assertEqual(statuses, [200, 429])
        finally:
            server.terminate()
            server.communicate(timeout=30)


_IMAGE = os.environ.get("PORTMARK_TEST_IMAGE")
_DOCKER = shutil.which("docker")


@unittest.skipUnless(_IMAGE and _DOCKER, "needs docker + PORTMARK_TEST_IMAGE (built image tag)")
class DeploymentProfileTestsPublicMode(unittest.TestCase):
    """The shipped image itself (CI builds it and sets PORTMARK_TEST_IMAGE). The name contains
    DeploymentProfileTests so CI's `-k DeploymentProfileTests` image step runs it."""

    def docker(self, *args, check=True, timeout=120):
        result = subprocess.run([_DOCKER, *args], capture_output=True, text=True, timeout=timeout)  # nosec B603 -- docker, fixed args
        if check and result.returncode != 0:
            self.fail(f"docker {' '.join(args)} failed: {result.stderr}")
        return result

    def start(self, *env):
        name = f"portmark-s11c-{os.getpid()}-{time.monotonic_ns()}"
        options = []
        for pair in env:
            options += ["-e", pair]
        self.docker("run", "-d", "--name", name, "-p", "127.0.0.1::8080", *options, _IMAGE)
        self.addCleanup(self.docker, "rm", "-f", name, check=False)
        return name

    def published_port(self, name):
        mapping = self.docker("port", name, "8080/tcp").stdout.strip().splitlines()[0]
        return int(mapping.rsplit(":", 1)[1])

    def inside_health(self, name):
        probe = "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status)"
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            result = self.docker("exec", name, "python", "-c", probe, check=False)
            if result.returncode == 0:
                return int(result.stdout.strip())
            time.sleep(0.5)
        self.fail(f"container never became healthy: {self.docker('logs', name, check=False).stderr}")

    def outside_status(self, port):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=3) as response:  # nosec B310 -- local test
                return response.status
        except (urllib.error.URLError, ConnectionError, OSError):
            return None

    def test_a_bare_public_bind_in_the_image_is_refused_with_every_requirement(self):
        result = self.docker("run", "--rm", "-e", "PORTMARK_BIND_HOST=0.0.0.0", _IMAGE, check=False)  # nosec B104
        self.assertEqual(result.returncode, 2, result.stderr)
        for name in ("PORTMARK_PUBLIC_MODE", "PORTMARK_A2A_TOKEN", "PORTMARK_A2A_TRUSTED_PROXIES", "PORTMARK_A2A_PUBLIC_BASE_URL"):
            self.assertIn(name, result.stderr)

    def test_the_default_image_refuses_to_start_without_production_controls(self):
        # Boundary audit NET-02 (owner decision 1A): the image is production by default. With no
        # configuration it refuses to start and names every missing control, even on loopback.
        result = self.docker("run", "--rm", _IMAGE, check=False)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("production profile", result.stderr)
        for name in ("PORTMARK_PUBLIC_MODE", "PORTMARK_A2A_TOKEN", "PORTMARK_A2A_TRUSTED_PROXIES", "PORTMARK_A2A_PUBLIC_BASE_URL"):
            self.assertIn(name, result.stderr)

    def test_the_default_image_listens_on_loopback_only(self):
        # Development profile: this test is about the loopback bind, not the production controls.
        name = self.start("PORTMARK_PROFILE=development")
        self.assertEqual(self.inside_health(name), 200)  # the HEALTHCHECK path works
        self.assertIsNone(self.outside_status(self.published_port(name)))  # even when -p publishes the port

    def test_a_complete_public_configuration_is_reachable(self):
        name = self.start(
            "PORTMARK_BIND_HOST=0.0.0.0",  # nosec B104 -- the public bind under test
            f"PORTMARK_PUBLIC_MODE={PUBLIC_MODE_ACK}",
            f"PORTMARK_A2A_TOKEN={TOKEN}",
            "PORTMARK_A2A_TRUSTED_PROXIES=172.16.0.0/12",
            "PORTMARK_A2A_PUBLIC_BASE_URL=https://agents.example.com",
        )
        self.assertEqual(self.inside_health(name), 200)
        port = self.published_port(name)
        deadline = time.monotonic() + 30
        while self.outside_status(port) != 200:
            self.assertLess(time.monotonic(), deadline, "the public listener was not reachable")
            time.sleep(0.5)


if __name__ == "__main__":
    unittest.main()

"""Section 12 PR A: bounded shutdown (#1), request-body deadline (#2), PostgreSQL time bounds (#3),
and permits released when a worker thread cannot start (#5).

Owner decision D1 (bounded shutdown): stop admitting work at once, wait only the grace, report the
unfinished runs by identifiers only, reply lifespan.shutdown.failed, and let the process terminate --
an abandoned run launches no tool and writes no checkpoint after the deadline.
"""

import asyncio
import json
import logging
import math
import os
import secrets
import signal
import socket
import subprocess  # nosec B404 -- runs this interpreter on a fixed script
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest.mock import patch

from portmark import _run_progress
from portmark.a2a import (
    MAX_BODY_READ_TIMEOUT_SECONDS,
    MAX_SHUTDOWN_GRACE_SECONDS,
    BoundedReferenceHTTPServer,
    HttpResponse,
    make_asgi_app,
    make_handler,
    run_uvicorn,
    validate_timeout_seconds,
)
from portmark.factory import make_demo_envelope, make_host
from portmark.storage import (
    InMemoryRuntimeStore,
    PostgresRuntimeStore,
    PostgresTimeouts,
    _effective_connect_timeout,
)

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
SECRET_ARGUMENT = "SECRET-ARGUMENT-" + secrets.token_hex(4)  # nosec B105 -- synthetic, must never be logged

try:
    import psycopg  # noqa: F401

    HAVE_PSYCOPG = True
except ImportError:
    HAVE_PSYCOPG = False
PG_DSN = os.environ.get("PORTMARK_TEST_POSTGRES_DSN")


def _post_scope(body: bytes, client=("203.0.113.7", 4000)) -> dict:
    return {
        "type": "http",
        "method": "POST",
        "path": "/message:send",
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        "client": client,
    }


def _get_scope(path: str) -> dict:
    return {"type": "http", "method": "GET", "path": path, "headers": [], "client": ("203.0.113.7", 4000)}


async def _call(app, scope, receive) -> dict:
    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    start = next(message for message in sent if message["type"] == "http.response.start")
    body = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    return {"status": start["status"], "headers": dict(start["headers"]), "body": body}


def _whole_body(body: bytes):
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


def _app(**kwargs):
    kwargs.setdefault("allow_anonymous", True)
    return make_asgi_app(make_host(None), None, **kwargs)


def _blocking_dispatch(app, *, release: threading.Event, started: threading.Event, note: dict | None = None):
    def dispatch(body: bytes) -> HttpResponse:
        if note:
            _run_progress.note(**note)
        started.set()
        release.wait(30)
        _run_progress.ensure_live()  # what the host does before its next step
        return app.a2a_router.response(200, {"ok": True})

    app.a2a_router.dispatch_post = dispatch


class _Lifespan:
    """Drive the ASGI lifespan protocol from a test."""

    def __init__(self, app):
        self.app = app
        self.inbox: asyncio.Queue = asyncio.Queue()
        self.outbox: list[dict] = []
        self.task = None

    async def start(self):
        async def receive():
            return await self.inbox.get()

        async def send(message):
            self.outbox.append(message)

        self.task = asyncio.create_task(self.app({"type": "lifespan"}, receive, send))
        await self.inbox.put({"type": "lifespan.startup"})
        while not self.outbox:
            await asyncio.sleep(0.01)
        if self.outbox[-1]["type"] != "lifespan.startup.complete":
            raise AssertionError(f"lifespan startup failed: {self.outbox[-1]}")

    async def shutdown(self) -> dict:
        await self.inbox.put({"type": "lifespan.shutdown"})
        await self.task
        return self.outbox[-1]


def _free_permits(semaphore) -> int:
    taken = 0
    while semaphore.acquire(blocking=False):
        taken += 1
    for _ in range(taken):
        semaphore.release()
    return taken


class ThreadStartFailureReleasesPermitTests(unittest.TestCase):
    """Finding #5: a refused Thread.start() must return the permit it reserved."""

    def test_http_provider_releases_its_transaction_slot(self):
        from portmark import providers

        provider = providers.GenericHttpProvider("http://127.0.0.1:9/decide", allow_local_endpoint=True, timeout=5)
        before = _free_permits(providers._TRANSACTION_SLOTS)
        with patch.object(threading.Thread, "start", side_effect=RuntimeError("can't start new thread")):
            with self.assertRaisesRegex(providers.ProviderError, "could not start"):
                provider._post(b"{}")
        self.assertEqual(_free_permits(providers._TRANSACTION_SLOTS), before)

    def test_migration_attester_releases_its_slot(self):
        from portmark.security import SecurityError

        host = make_host(None)

        class _Attester:
            def attest(self, **_kwargs):
                raise AssertionError("never called: the thread did not start")

        host.migration_attester = _Attester()
        before = _free_permits(host._attester_slots)
        with patch.object(threading.Thread, "start", side_effect=RuntimeError("can't start new thread")):
            with self.assertRaisesRegex(SecurityError, "could not start"):
                host._attest_migration_challenge(subject="s", audience="a", challenge="c")
        self.assertEqual(_free_permits(host._attester_slots), before)

    def test_asgi_run_thread_start_failure_releases_admission(self):
        # Same class, new code: the ASGI run thread. A refused start answers 503 and frees the slot.
        app = _app(max_concurrent_requests=1)
        app.a2a_router.dispatch_post = lambda body: app.a2a_router.response(200, {"ok": True})

        async def scenario():
            with patch.object(threading.Thread, "start", side_effect=RuntimeError("can't start new thread")):
                refused = await _call(app, _post_scope(b"{}"), _whole_body(b"{}"))
            accepted = await _call(app, _post_scope(b"{}"), _whole_body(b"{}"))
            return refused, accepted

        refused, accepted = asyncio.run(scenario())
        self.assertEqual(refused["status"], 503)
        self.assertEqual(accepted["status"], 200)  # the only slot was released
        self.assertEqual(app.run_tracker.active_count(), 0)


class TimeoutValidationTests(unittest.TestCase):
    def test_bounds_that_would_disable_a_limit_are_refused(self):
        for bad in (0, -1, math.nan, math.inf, True, "5", None):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    validate_timeout_seconds("x", bad, 60)
        self.assertEqual(validate_timeout_seconds("x", 60, 60), 60.0)
        with self.assertRaises(ValueError):
            validate_timeout_seconds("x", 60.001, 60)
        for kwargs in ({"shutdown_grace_seconds": 0}, {"body_read_timeout_seconds": -1},
                       {"shutdown_grace_seconds": MAX_SHUTDOWN_GRACE_SECONDS + 1},
                       {"body_read_timeout_seconds": MAX_BODY_READ_TIMEOUT_SECONDS + 1}):
            with self.subTest(**kwargs), self.assertRaises(ValueError):
                _app(**kwargs)
        with self.assertRaises(ValueError):
            make_handler(make_host(None), None, allow_anonymous=True, body_read_timeout_seconds=0)


class AsgiBodyDeadlineTests(unittest.TestCase):
    """Finding #2: one absolute deadline for the whole body; the slot is released on expiry."""

    def test_a_stalled_body_gets_408_and_releases_admission(self):
        # The auditor's repro: two partial requests against a two-request limit starved a valid third.
        app = _app(max_concurrent_requests=2, body_read_timeout_seconds=0.3)
        app.a2a_router.dispatch_post = lambda body: app.a2a_router.response(200, {"ok": True})
        body = b'{"jsonrpc": "2.0"}'

        def stalled():
            state = {"sent": False}

            async def receive():
                if not state["sent"]:
                    state["sent"] = True
                    return {"type": "http.request", "body": body[:5], "more_body": True}
                await asyncio.Event().wait()  # the rest never arrives

            return receive

        async def scenario():
            started = time.monotonic()
            partial = await asyncio.gather(
                _call(app, _post_scope(body), stalled()), _call(app, _post_scope(body), stalled())
            )
            elapsed = time.monotonic() - started
            third = await _call(app, _post_scope(body), _whole_body(body))
            return partial, elapsed, third

        partial, elapsed, third = asyncio.run(scenario())
        self.assertEqual([response["status"] for response in partial], [408, 408])
        self.assertEqual(partial[0]["headers"].get(b"connection"), b"close")
        self.assertLess(elapsed, 3.0)
        self.assertEqual(third["status"], 200)  # both slots came back
        self.assertIn('reason="request_timeout"} 2', app.a2a_router.host.metrics.prometheus_text())

    def test_the_deadline_is_absolute_not_reset_by_each_chunk(self):
        # Each chunk arrives well inside the deadline, but the whole body never finishes in time.
        app = _app(body_read_timeout_seconds=0.4)
        app.a2a_router.dispatch_post = lambda body: app.a2a_router.response(200, {"ok": True})
        body = b"x" * 100

        async def drip():
            await asyncio.sleep(0.05)
            return {"type": "http.request", "body": b"x", "more_body": True}

        async def scenario():
            started = time.monotonic()
            response = await _call(app, _post_scope(body), drip)
            return response, time.monotonic() - started

        response, elapsed = asyncio.run(scenario())
        self.assertEqual(response["status"], 408)
        self.assertLess(elapsed, 2.0)


@unittest.skipIf(os.name == "nt", "the reference server test uses POSIX socket timing")
class ReferenceServerBodyDeadlineTests(unittest.TestCase):
    """Finding #2, the second transport: the loopback reference http.server."""

    def test_a_dripping_body_gets_408_within_one_absolute_deadline(self):
        handler = make_handler(make_host(None), None, allow_anonymous=True, max_concurrent_requests=1,
                               body_read_timeout_seconds=0.6)
        handler.a2a_router.dispatch_post = lambda body: handler.a2a_router.response(200, {"ok": True})
        server = BoundedReferenceHTTPServer(("127.0.0.1", 0), handler, max_connections=1)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=10) as client:
                client.sendall(
                    b"POST /message:send HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                    b"Content-Length: 100\r\n\r\n"
                )
                started = time.monotonic()
                reply = b""
                for _ in range(40):  # one byte every 0.1 s: each read is quick, the whole body is not
                    try:
                        client.sendall(b"x")
                    except OSError:
                        break
                    client.settimeout(0.1)
                    try:
                        chunk = client.recv(4096)
                        if chunk:
                            reply += chunk
                            break
                    except TimeoutError:
                        continue
                elapsed = time.monotonic() - started
            self.assertTrue(reply.startswith(b"HTTP/1.0 408") or reply.startswith(b"HTTP/1.1 408"), reply[:60])
            self.assertLess(elapsed, 3.0)
            # The single connection slot comes back once the handler thread ends (just after it wrote
            # the 408), and a normal request is then served.
            for _ in range(300):
                if _free_permits(server._connection_slots) == 1:
                    break
                time.sleep(0.01)
            self.assertEqual(_free_permits(server._connection_slots), 1)
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/message:send", data=b"{}", headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(request, timeout=10) as response:  # nosec B310 -- loopback test server
                self.assertEqual(response.status, 200)
        finally:
            server.shutdown()
            server.server_close()

    def test_a_read_that_stalls_near_the_deadline_waits_only_the_time_left(self):
        # Drip for most of the deadline, then stop sending. Each read may wait only for the time LEFT;
        # a per-read timeout of the full body timeout would answer about one timeout too late.
        handler = make_handler(make_host(None), None, allow_anonymous=True, body_read_timeout_seconds=2.0)
        server = BoundedReferenceHTTPServer(("127.0.0.1", 0), handler, max_connections=1)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=10) as client:
                client.sendall(
                    b"POST /message:send HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                    b"Content-Length: 100\r\n\r\n"
                )
                started = time.monotonic()
                while time.monotonic() - started < 1.8:
                    client.sendall(b"x")
                    time.sleep(0.1)
                client.settimeout(10)
                reply = client.recv(4096)  # now silent: the server must answer at its deadline
                elapsed = time.monotonic() - started
        finally:
            server.shutdown()
            server.server_close()
        self.assertTrue(reply.split(b" ", 2)[1:2] == [b"408"], reply[:60])
        self.assertGreater(elapsed, 1.7)
        self.assertLess(elapsed, 3.0)  # a full per-read timeout would answer at about 3.8 s


class BoundedShutdownTests(unittest.TestCase):
    """Finding #1, owner decision D1."""

    def test_shutdown_waits_for_a_run_that_finishes_inside_the_grace(self):
        app = _app(shutdown_grace_seconds=5)
        release, started = threading.Event(), threading.Event()
        _blocking_dispatch(app, release=release, started=started)

        async def scenario():
            lifespan = _Lifespan(app)
            await lifespan.start()
            request = asyncio.create_task(_call(app, _post_scope(b"{}"), _whole_body(b"{}")))
            await asyncio.get_running_loop().run_in_executor(None, started.wait, 10)
            shutdown = asyncio.create_task(lifespan.shutdown())
            await asyncio.sleep(0.3)
            self.assertFalse(shutdown.done(), "shutdown completed while accepted work was still running")
            release.set()
            return await shutdown, await request

        reply, response = asyncio.run(scenario())
        self.assertEqual(reply["type"], "lifespan.shutdown.complete")
        self.assertEqual(response["status"], 200)

    def test_grace_expiry_reports_identifiers_only_and_fails_the_shutdown(self):
        app = _app(shutdown_grace_seconds=0.3)
        release, started = threading.Event(), threading.Event()
        note = {"task_id": "task-s12-1", "checkpoint_generation": 4, "phase": "side_effecting_tool", "effect_id": "effect-s12-1"}
        _blocking_dispatch(app, release=release, started=started, note=note)
        body = json.dumps({"arguments": SECRET_ARGUMENT}).encode()

        async def scenario():
            lifespan = _Lifespan(app)
            await lifespan.start()
            request = asyncio.create_task(_call(app, _post_scope(body), _whole_body(body)))
            await asyncio.get_running_loop().run_in_executor(None, started.wait, 10)
            began = time.monotonic()
            reply = await lifespan.shutdown()
            elapsed = time.monotonic() - began
            request.cancel()
            return reply, elapsed

        with self.assertLogs("portmark.a2a", level="CRITICAL") as logs:
            reply, elapsed = asyncio.run(scenario())
        release.set()
        self.assertEqual(reply["type"], "lifespan.shutdown.failed")
        self.assertIn("1 run(s)", reply["message"])
        self.assertLess(elapsed, 3.0)
        joined = "\n".join(logs.output)
        for expected in ("task_id='task-s12-1'", "checkpoint_generation=4", "phase=side_effecting_tool", "effect-s12-1", "reconcile"):
            self.assertIn(expected, joined)
        self.assertNotIn(SECRET_ARGUMENT, joined + reply["message"])

    def test_admission_stops_the_moment_draining_begins(self):
        app = _app()
        app.a2a_router.dispatch_post = lambda body: app.a2a_router.response(200, {"ok": True})
        app.a2a_router.ready = lambda: True

        async def scenario():
            before = await _call(app, _get_scope("/readyz"), _whole_body(b""))
            app.begin_shutdown()
            post = await _call(app, _post_scope(b"{}"), _whole_body(b"{}"))
            ready = await _call(app, _get_scope("/readyz"), _whole_body(b""))
            health = await _call(app, _get_scope("/healthz"), _whole_body(b""))
            return before, post, ready, health

        before, post, ready, health = asyncio.run(scenario())
        self.assertEqual(before["status"], 200)
        self.assertEqual(post["status"], 503)
        self.assertIn(b"shutting down", post["body"])
        self.assertEqual(ready["status"], 503)
        self.assertEqual(health["status"], 200)  # still alive, just not accepting work

    def test_a_cancelled_request_keeps_its_slot_until_the_run_ends(self):
        app = _app(max_concurrent_requests=1)
        release, started = threading.Event(), threading.Event()
        _blocking_dispatch(app, release=release, started=started)

        async def scenario():
            first = asyncio.create_task(_call(app, _post_scope(b"{}"), _whole_body(b"{}")))
            await asyncio.get_running_loop().run_in_executor(None, started.wait, 10)
            first.cancel()
            await asyncio.gather(first, return_exceptions=True)
            while_running = await _call(app, _post_scope(b"{}"), _whole_body(b"{}"))
            release.set()
            for _ in range(200):
                if app.run_tracker.active_count() == 0:
                    break
                await asyncio.sleep(0.01)
            app.a2a_router.dispatch_post = lambda body: app.a2a_router.response(200, {"ok": True})
            after = await _call(app, _post_scope(b"{}"), _whole_body(b"{}"))
            return while_running, after

        while_running, after = asyncio.run(scenario())
        self.assertEqual(while_running["status"], 503)  # the run still holds the only slot
        self.assertEqual(after["status"], 200)

    def test_an_abandoned_run_writes_no_checkpoint_and_launches_no_tool(self):
        # The host fences: a real run under an abandoned progress record stops before any write.
        store = InMemoryRuntimeStore()
        host = make_host(None, store=store)
        envelope = make_demo_envelope(host, "research Telescript")
        progress = _run_progress.RunProgress()
        progress.abandon()
        with _run_progress.tracking(progress):
            with self.assertRaises(_run_progress.RunAbandoned):
                host.run(envelope)
        self.assertIsNone(store.load_checkpoint(envelope.state.task_id))

    def test_an_abandoned_run_makes_no_provider_call_after_the_deadline(self):
        # Abandoned right AFTER its admission checkpoint: the next step (a provider decision) must not run.
        host = make_host(None, store=InMemoryRuntimeStore())
        envelope = make_demo_envelope(host, "research Telescript")
        progress = _run_progress.RunProgress()
        real_persist = host._persist

        def persist_then_abandon(*args, **kwargs):
            result = real_persist(*args, **kwargs)
            progress.abandon()
            return result

        decide_calls = []
        for provider in host.providers.values():
            real_decide = provider.decide
            provider.decide = lambda *a, _real=real_decide, **k: (decide_calls.append(1), _real(*a, **k))[1]
        with patch.object(host, "_persist", side_effect=persist_then_abandon), _run_progress.tracking(progress):
            with self.assertRaises(_run_progress.RunAbandoned):
                host.run(envelope)
        self.assertEqual(decide_calls, [])

    def test_an_abandoned_run_launches_no_tool_after_the_deadline(self):
        # Abandoned while the provider decides: the tool it proposed must not be launched.
        host = make_host(None, store=InMemoryRuntimeStore())
        envelope = make_demo_envelope(host, "research Telescript")
        progress = _run_progress.RunProgress()
        for provider in host.providers.values():
            real_decide = provider.decide
            provider.decide = lambda *a, _real=real_decide, **k: (progress.abandon(), _real(*a, **k))[1]
        invoked = []
        real_invoke = host.tools.invoke
        with patch.object(host.tools, "invoke", side_effect=lambda *a, **k: (invoked.append(1), real_invoke(*a, **k))[1]):
            with _run_progress.tracking(progress), self.assertRaises(_run_progress.RunAbandoned):
                host.run(envelope)
        self.assertEqual(invoked, [])

    def test_draining_that_begins_during_the_body_read_still_refuses_the_run(self):
        app = _app()
        ran = []
        app.a2a_router.dispatch_post = lambda body: (ran.append(1), app.a2a_router.response(200, {"ok": True}))[1]

        async def receive():
            app.begin_shutdown()  # the shutdown signal lands while this body is arriving
            return {"type": "http.request", "body": b"{}", "more_body": False}

        response = asyncio.run(_call(app, _post_scope(b"{}"), receive))
        self.assertEqual(response["status"], 503)
        self.assertEqual(ran, [])
        self.assertEqual(app.run_tracker.active_count(), 0)

    def test_a_post_during_drain_is_refused_before_its_body_is_read(self):
        app = _app()
        app.begin_shutdown()

        async def receive():
            raise AssertionError("a draining server must not read the body")

        response = asyncio.run(_call(app, _post_scope(b"{}"), receive))
        self.assertEqual(response["status"], 503)

    def test_run_uvicorn_drains_on_the_signal_and_shares_one_grace(self):
        import uvicorn

        app = _app(shutdown_grace_seconds=7)
        seen = {}

        def fake_run(server, sockets=None):
            seen["grace"] = server.config.timeout_graceful_shutdown
            server.handle_exit(signal.SIGTERM, None)
            seen["draining"] = app.run_tracker.draining
            seen["should_exit"] = server.should_exit
            server.started = True

        with patch.object(uvicorn.Server, "run", fake_run):
            run_uvicorn(app, {"host": "127.0.0.1", "port": 0, "log_config": None})
        self.assertEqual(seen, {"grace": 7.0, "draining": True, "should_exit": True})

    def test_run_uvicorn_refuses_an_app_without_the_drain_hook(self):
        async def plain_app(scope, receive, send):  # pragma: no cover - never served
            return None

        with self.assertRaisesRegex(RuntimeError, "shutdown hook"):
            run_uvicorn(plain_app, {"host": "127.0.0.1", "port": 0, "log_config": None})


_SERVER_SCRIPT = r"""
import pathlib, sys, threading
sys.path.insert(0, sys.argv[3])
from portmark import _run_progress
from portmark.a2a import make_asgi_app, run_uvicorn
from portmark.factory import make_host

marker = pathlib.Path(sys.argv[2])
app = make_asgi_app(make_host(None), None, allow_anonymous=True, shutdown_grace_seconds=3.0)

def dispatch(body):
    _run_progress.note(task_id="task-sigterm-1", checkpoint_generation=2, phase="side_effecting_tool",
                       effect_id="effect-sigterm-1")
    marker.write_text("running")
    threading.Event().wait()  # never finishes

app.a2a_router.dispatch_post = dispatch
run_uvicorn(app, {"host": "127.0.0.1", "port": int(sys.argv[1]), "log_config": None, "log_level": "warning",
                  "proxy_headers": False, "access_log": False})
"""


_EMBEDDED_SCRIPT = r"""
import asyncio, sys, threading
sys.path.insert(0, sys.argv[1])
from portmark.a2a import make_asgi_app
from portmark.factory import make_host

app = make_asgi_app(make_host(None), None, allow_anonymous=True, shutdown_grace_seconds=0.5)
started = threading.Event()

def dispatch(body):
    started.set()
    threading.Event().wait()  # never finishes

app.a2a_router.dispatch_post = dispatch

async def main():
    inbox = asyncio.Queue()
    replies = []

    async def receive():
        return await inbox.get()

    async def send(message):
        replies.append(message)

    lifespan = asyncio.create_task(app({"type": "lifespan"}, receive, send))
    await inbox.put({"type": "lifespan.startup"})

    async def body():
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def ignore(message):
        pass

    scope = {"type": "http", "method": "POST", "path": "/message:send", "client": ("127.0.0.1", 1),
             "headers": [(b"content-type", b"application/json"), (b"content-length", b"2")]}
    request = asyncio.create_task(app(scope, body, ignore))
    await asyncio.get_running_loop().run_in_executor(None, started.wait, 10)
    await inbox.put({"type": "lifespan.shutdown"})
    await lifespan
    request.cancel()
    print(replies[-1]["type"], flush=True)

asyncio.run(main())
"""


class EmbeddedShutdownTests(unittest.TestCase):
    """The auditor's case: the ASGI app embedded without uvicorn's signal handling."""

    def test_a_stuck_run_does_not_hold_the_process_open_after_a_failed_shutdown(self):
        started = time.monotonic()
        result = subprocess.run(  # nosec B603 -- this interpreter, fixed script
            [sys.executable, "-c", _EMBEDDED_SCRIPT, str(SRC)], capture_output=True, text=True, timeout=60,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "lifespan.shutdown.failed")
        # The interpreter exits right after main() returns: the stuck run is on a daemon thread. A
        # pool thread (the old ThreadPoolExecutor) would be joined at exit and never return.
        self.assertLess(elapsed, 20.0)


@unittest.skipIf(os.name == "nt", "sends SIGTERM to a real uvicorn process")
class RealServerShutdownTests(unittest.TestCase):
    """The shipped path end to end: a real uvicorn process, a run that never finishes, and SIGTERM."""

    def test_sigterm_with_a_stuck_run_exits_after_one_grace_and_names_the_run(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "running"
            process = subprocess.Popen(  # nosec B603 -- this interpreter, fixed script
                [sys.executable, "-c", _SERVER_SCRIPT, str(port), str(marker), str(SRC)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            try:
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    try:
                        socket.create_connection(("127.0.0.1", port), timeout=1).close()
                        break
                    except OSError:
                        time.sleep(0.1)
                body = json.dumps({"arguments": SECRET_ARGUMENT}).encode()

                def post():
                    request = urllib.request.Request(
                        f"http://127.0.0.1:{port}/message:send", data=body, headers={"Content-Type": "application/json"}
                    )
                    try:
                        urllib.request.urlopen(request, timeout=30)  # nosec B310 -- loopback test server
                    except (urllib.error.URLError, OSError):
                        pass

                threading.Thread(target=post, daemon=True).start()
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(marker.exists(), "the run never started")
                signalled = time.monotonic()
                process.send_signal(signal.SIGTERM)
                _stdout, stderr = process.communicate(timeout=30)
                elapsed = time.monotonic() - signalled
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
        # ONE grace (3 s) plus a teardown margin -- not two graces (about 6 s: uvicorn's wait, then a second
        # full wait in the lifespan), and not "forever": the stuck run is on a daemon thread, so it does
        # not hold the interpreter open at exit.
        self.assertGreater(elapsed, 2.5, stderr)
        self.assertLess(elapsed, 5.0, stderr)
        for expected in ("task_id='task-sigterm-1'", "checkpoint_generation=2", "phase=side_effecting_tool", "effect-sigterm-1"):
            self.assertIn(expected, stderr)
        self.assertNotIn(SECRET_ARGUMENT, stderr)


class PostgresTimeoutConfigTests(unittest.TestCase):
    """Finding #3: the bounds themselves (no server needed)."""

    def test_zero_negative_and_oversized_bounds_are_refused(self):
        for field in ("connect_seconds", "statement_ms", "lock_ms", "idle_in_transaction_ms"):
            for bad in (0, -1, True, 1.5, 10**9):
                with self.subTest(field=field, value=bad), self.assertRaises(ValueError):
                    PostgresTimeouts(**{field: bad})

    def test_environment_overrides_and_rejects_garbage(self):
        timeouts = PostgresTimeouts.from_environment({
            "PORTMARK_POSTGRES_CONNECT_TIMEOUT_SECONDS": "3",
            "PORTMARK_POSTGRES_STATEMENT_TIMEOUT_MS": "1500",
            "PORTMARK_POSTGRES_LOCK_TIMEOUT_MS": " 700 ",
            "PORTMARK_POSTGRES_IDLE_IN_TRANSACTION_TIMEOUT_MS": "",
        })
        self.assertEqual(timeouts, PostgresTimeouts(connect_seconds=3, statement_ms=1500, lock_ms=700))
        for env in ("PORTMARK_POSTGRES_STATEMENT_TIMEOUT_MS", "PORTMARK_POSTGRES_LOCK_TIMEOUT_MS"):
            for bad in ("0", "abc", "-5"):
                with self.subTest(env=env, value=bad), self.assertRaises(ValueError):
                    PostgresTimeouts.from_environment({env: bad})

    def test_schema_migration_bounds_are_longer_but_finite(self):
        schema = PostgresTimeouts(statement_ms=1000, lock_ms=1000).for_schema_migration()
        self.assertEqual((schema.statement_ms, schema.lock_ms), (600_000, 300_000))
        self.assertEqual(PostgresTimeouts(statement_ms=900_000).for_schema_migration().statement_ms, 900_000)

    @unittest.skipUnless(HAVE_PSYCOPG, "needs psycopg (the postgres extra)")
    def test_a_dsn_cannot_disable_or_widen_the_connect_bound_but_may_tighten_it(self):
        timeouts = PostgresTimeouts(connect_seconds=5)
        for dsn, expected in (
            ("host=db dbname=app", 5),
            ("host=db dbname=app connect_timeout=0", 5),  # libpq's "wait forever"
            ("host=db dbname=app connect_timeout=-3", 5),
            ("host=db dbname=app connect_timeout=600", 5),
            ("host=db dbname=app connect_timeout=2", 2),
            ("postgresql://u@db/app?connect_timeout=1", 1),
        ):
            with self.subTest(dsn=dsn):
                self.assertEqual(_effective_connect_timeout(dsn, timeouts), expected)

    @unittest.skipUnless(HAVE_PSYCOPG, "needs psycopg (the postgres extra)")
    def test_a_blackholed_server_fails_the_connect_within_the_bound(self):
        # A listener that completes the TCP handshake (kernel backlog) but never speaks: the classic
        # blackhole. Without connect_timeout, libpq waits for the server's reply indefinitely.
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(8)
            port = listener.getsockname()[1]
            started = time.monotonic()
            with self.assertRaises(Exception):
                PostgresRuntimeStore(
                    f"host=127.0.0.1 port={port} dbname=portmark user=portmark connect_timeout=0",
                    timeouts=PostgresTimeouts(connect_seconds=2),
                )
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 8.0)


@unittest.skipUnless(PG_DSN and HAVE_PSYCOPG, "needs a live Postgres (PORTMARK_TEST_POSTGRES_DSN)")
class PostgresTimeoutEnforcementTests(unittest.TestCase):
    """Finding #3 against a live server: blocked locks and slow statements fail within the bounds."""

    def setUp(self):
        import psycopg

        self.psycopg = psycopg
        self.schema = "s12_" + secrets.token_hex(6)

    def tearDown(self):
        with self.psycopg.connect(PG_DSN, autocommit=True) as connection:
            connection.execute(f'DROP SCHEMA IF EXISTS "{self.schema}" CASCADE')

    def _store(self, **timeouts) -> PostgresRuntimeStore:
        return PostgresRuntimeStore(PG_DSN, schema=self.schema, timeouts=PostgresTimeouts(**timeouts))

    def test_every_connection_carries_the_bounds_even_if_the_dsn_disables_them(self):
        hostile = PG_DSN + ("&" if "?" in PG_DSN else "?") + "options=" + urllib.parse.quote(
            "-c statement_timeout=0 -c lock_timeout=0 -c idle_in_transaction_session_timeout=0"
        )
        store = PostgresRuntimeStore(hostile, schema=self.schema)
        connection = store._connect()
        try:
            values = connection.execute(
                "SELECT current_setting('statement_timeout') AS s, current_setting('lock_timeout') AS l, "
                "current_setting('idle_in_transaction_session_timeout') AS i"
            ).fetchone()
            self.assertEqual((values["s"], values["l"], values["i"]), ("30s", "10s", "1min"))
            connection.rollback()  # a rolled-back transaction must not undo the session bounds
            again = connection.execute("SELECT current_setting('lock_timeout') AS l").fetchone()
            self.assertEqual(again["l"], "10s")
        finally:
            connection.close()

    def test_a_blocked_table_lock_fails_the_operation_and_rolls_it_back(self):
        store = self._store(lock_ms=300)
        blocker = self.psycopg.connect(PG_DSN)
        try:
            blocker.execute(f'LOCK TABLE "{self.schema}".task_cancellations IN ACCESS EXCLUSIVE MODE')
            started = time.monotonic()
            with self.assertRaises(self.psycopg.errors.LockNotAvailable):
                store.cancel_task("t-lock")
            self.assertLess(time.monotonic() - started, 5.0)
        finally:
            blocker.rollback()
            blocker.close()
        self.assertFalse(store.is_task_cancelled("t-lock"))  # nothing was committed
        store.cancel_task("t-lock")  # and the store works once the lock is gone
        self.assertTrue(store.is_task_cancelled("t-lock"))

    def test_a_held_advisory_lock_fails_the_transaction_and_rolls_back_earlier_writes(self):
        store = self._store(lock_ms=300)
        blocker = self.psycopg.connect(PG_DSN)
        try:
            blocker.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", ("t-adv",))
            started = time.monotonic()
            with self.assertRaises(self.psycopg.errors.LockNotAvailable):
                with store.transaction() as transaction:
                    transaction.consume_nonce("nonce-adv", "subject", "audience", "t-adv")
                    transaction.is_task_cancelled("t-adv")  # takes the same advisory lock
            self.assertLess(time.monotonic() - started, 5.0)
        finally:
            blocker.rollback()
            blocker.close()
        with store.transaction() as transaction:  # the nonce consume above was rolled back
            transaction.consume_nonce("nonce-adv", "subject", "audience", "t-adv")

    def test_a_slow_statement_is_cancelled(self):
        store = self._store(statement_ms=200)
        connection = store._connect()
        try:
            started = time.monotonic()
            with self.assertRaises(self.psycopg.errors.QueryCanceled):
                connection.execute("SELECT pg_sleep(5)")
            self.assertLess(time.monotonic() - started, 3.0)
        finally:
            connection.close()

    def test_an_idle_open_transaction_is_ended_by_the_server(self):
        store = self._store(idle_in_transaction_ms=300)
        connection = store._connect()
        try:
            connection.execute("SELECT 1")  # opens a transaction
            time.sleep(1.5)
            with self.assertRaises(self.psycopg.errors.IdleInTransactionSessionTimeout):
                connection.execute("SELECT 1")
        finally:
            connection.close()

    def test_a_start_behind_another_schema_migration_waits_a_finite_time(self):
        from portmark import storage

        self._store()  # create the schema
        blocker = self.psycopg.connect(PG_DSN)
        try:
            blocker.execute("SELECT pg_advisory_lock(%s)", (storage._advisory_lock_key("portmark-schema:" + self.schema),))
            with patch.object(PostgresTimeouts, "for_schema_migration", lambda self: self):
                started = time.monotonic()
                with self.assertRaises(self.psycopg.errors.LockNotAvailable):
                    self._store(lock_ms=300)
                self.assertLess(time.monotonic() - started, 5.0)
        finally:
            blocker.close()


if __name__ == "__main__":
    logging.basicConfig()
    unittest.main()

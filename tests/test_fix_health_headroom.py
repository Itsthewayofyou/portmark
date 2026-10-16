"""Health probes keep a connection when every run slot is busy.

uvicorn's `limit_concurrency` counts every open connection, health probes included. It used to equal
the app's run cap, so a server with every run slot busy answered `/healthz` with uvicorn's own 503, and
an orchestrator could restart a healthy, merely busy, server. The uvicorn limit now sits above the run
cap by a fixed headroom. The app's own semaphore stays the run limit.
"""

from __future__ import annotations

import json
import os
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from asgi_test_server import serve_asgi
from portmark import a2a
from portmark import serve_asgi as serve_asgi_entry
from portmark.factory import make_host

RUN_CAP = 2


def _served_options(max_concurrent_requests: int):
    """The app and the uvicorn options `portmark serve` would run with."""
    with patch("portmark.a2a.run_uvicorn") as run:
        a2a.serve(make_host(), "127.0.0.1", 8080, max_concurrent_requests=max_concurrent_requests)
    app, options = run.call_args.args
    return app, options


def _get(port: int, path: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as response:  # nosec B310 -- loopback test server
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def _post(port: int) -> tuple[int, bytes]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/message:send", data=b"{}", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310 -- loopback test server
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


class UvicornLimitTests(unittest.TestCase):
    def test_options_put_the_connection_limit_above_the_run_cap(self):
        options = a2a.uvicorn_options("127.0.0.1", 8080, max_concurrent_requests=50)
        self.assertGreater(a2a.A2A_CONNECTION_HEADROOM, 0)
        self.assertEqual(options["limit_concurrency"], 50 + a2a.A2A_CONNECTION_HEADROOM)

    def test_default_options_use_the_default_run_cap(self):
        options = a2a.uvicorn_options("127.0.0.1", 8080)
        self.assertEqual(
            options["limit_concurrency"], a2a.DEFAULT_MAX_CONCURRENT_REQUESTS + a2a.A2A_CONNECTION_HEADROOM
        )

    def test_portmark_serve_passes_its_run_cap_plus_headroom(self):
        _, options = _served_options(7)
        self.assertEqual(options["limit_concurrency"], 7 + a2a.A2A_CONNECTION_HEADROOM)

    def test_container_entrypoint_reads_the_configured_run_cap(self):
        # serve_asgi used to ignore PORTMARK_A2A_MAX_CONCURRENT_REQUESTS and always pass 32.
        with patch.dict(os.environ, {"PORTMARK_A2A_MAX_CONCURRENT_REQUESTS": "50"}):
            with patch("portmark.serve_asgi.run_uvicorn") as run:
                self.assertEqual(serve_asgi_entry.main({}), 0)
        _, options = run.call_args.args
        self.assertEqual(options["limit_concurrency"], 50 + a2a.A2A_CONNECTION_HEADROOM)


@unittest.skipIf(os.name == "nt", "uses real loopback sockets")
class SaturatedServerTests(unittest.TestCase):
    """Real uvicorn, run with the exact options `portmark serve` builds, every run slot held busy."""

    def test_healthz_answers_while_every_run_slot_is_busy_and_the_run_cap_still_holds(self):
        app, options = _served_options(RUN_CAP)
        release = threading.Event()
        entered = threading.Semaphore(0)

        def blocked_dispatch(body: bytes):
            entered.release()
            release.wait(30)
            return app.a2a_router.response(200, {"ok": True})

        app.a2a_router.dispatch_post = blocked_dispatch
        config = {key: value for key, value in options.items() if key not in ("host", "port")}
        with serve_asgi(app, **config) as port:
            results: list[tuple[int, bytes]] = []
            runs = [threading.Thread(target=lambda: results.append(_post(port))) for _ in range(RUN_CAP)]
            try:
                # Fill the run slots one at a time. uvicorn counts the arriving connection itself, so a
                # connection limit equal to the run cap refuses the LAST run slot before the app sees it.
                for number, run in enumerate(runs, start=1):
                    run.start()
                    while not entered.acquire(timeout=0.05):
                        if not run.is_alive():
                            self.fail(f"run {number} of {RUN_CAP} was refused before the app: {results[-1]!r}")

                # Every run slot is busy. Health must still answer.
                status, _ = _get(port, "/healthz")
                self.assertEqual(status, 200)

                # Control: the run cap itself still holds, and it is the APP that refuses (JSON-RPC body),
                # not uvicorn's connection limit (plain-text "Service Unavailable").
                status, body = _post(port)
                self.assertEqual(status, 503)
                self.assertIn("server busy", json.loads(body)["error"]["message"])
            finally:
                release.set()
                for run in runs:
                    run.join(30)
            self.assertEqual([status for status, _ in results], [200] * RUN_CAP)


if __name__ == "__main__":
    unittest.main()

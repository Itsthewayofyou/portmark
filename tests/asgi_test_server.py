"""Serve an ASGI app on a real uvicorn server, on a free loopback port, for tests that need real sockets."""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from collections.abc import Iterator

import uvicorn


@contextlib.contextmanager
def serve_asgi(app) -> Iterator[int]:
    """Yield the port of a uvicorn server running `app`; stop the server on exit."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_config=None, log_level="warning"))
    # Off the main thread uvicorn installs no signal handlers, so the test process keeps its own.
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 30
        while not server.started:
            if not thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("the test uvicorn server did not start")
            time.sleep(0.01)
        yield sock.getsockname()[1]
    finally:
        server.should_exit = True
        thread.join(30)
        sock.close()

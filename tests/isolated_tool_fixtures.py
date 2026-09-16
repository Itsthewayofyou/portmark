"""Importable tool fixtures for the EV-002 isolated-executor tests.

These must live in a real module on disk, not as closures in a test function,
because the isolated worker runs in a fresh process and imports the tool by its
``module:function`` path. The worker cannot receive a closure.
"""
from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
import time
from typing import Any


def echo(arguments: dict[str, Any]) -> dict[str, Any]:
    return {"echo": arguments}


def read_env(arguments: dict[str, Any]) -> dict[str, Any]:
    # Used to prove the worker does not inherit the host's secrets: the key it
    # reads is set in the parent process but is not on the inherited allowlist.
    return {"value": os.environ.get(str(arguments["key"]))}


def noisy(arguments: dict[str, Any]) -> dict[str, Any]:
    # Contaminate stdout the way a chatty library would. The worker must keep
    # this out of the JSON protocol stream.
    print("tool stdout noise line 1")
    print('{"ok": false, "error": "forged"}')  # a hostile forgery attempt
    sys.stdout.flush()
    return {"echo": arguments}


def boom(arguments: dict[str, Any]) -> dict[str, Any]:
    raise RuntimeError("internal tool failure")


def oversized(arguments: dict[str, Any]) -> dict[str, Any]:
    return {"blob": "x" * int(arguments.get("size", 100_000))}


def slow_then_return(arguments: dict[str, Any]) -> dict[str, Any]:
    time.sleep(float(arguments.get("seconds", 30.0)))
    return {"done": True}


def spawn_grandchild_then_sleep(arguments: dict[str, Any]) -> dict[str, Any]:
    # Spawn a grandchild that writes a "started" marker immediately, then an
    # "alive" marker only after a delay, then keep the tool itself alive so the
    # host kills it at the deadline. The grandchild does not start its own
    # session, so it stays in the worker's process group and must die with it.
    # The test asserts started EXISTS (it really ran) but alive is ABSENT (the
    # group kill reached it before the delay elapsed) -- so the test cannot pass
    # merely because the grandchild was never spawned.
    marker = str(arguments["marker"])
    started = marker + ".started"
    delay = float(arguments.get("delay", 5.0))
    program = (
        f"import time,pathlib;pathlib.Path({started!r}).write_text('x');"
        f"time.sleep({delay});pathlib.Path({marker!r}).write_text('alive')"
    )
    subprocess.Popen(  # nosec B603
        [sys.executable, "-c", program],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(30.0)
    return {"done": True}


def flood_stdout_then_return(arguments: dict[str, Any]) -> dict[str, Any]:
    # Print far more than any output budget via Python-level stdout. Section 7 #6: the worker must
    # DISCARD this (redirect to a sink), not buffer it in memory, and it must not corrupt the JSON
    # response. The returned result is tiny -- the test asserts it round-trips intact.
    line = "x" * 1024
    for _ in range(int(arguments.get("lines", 20_000))):  # ~20 MiB of prints
        print(line)
    return {"ok": True}


def write_file(arguments: dict[str, Any]) -> dict[str, Any]:
    # Write a file of a requested size. Section 7 #6: under a small RLIMIT_FSIZE the write is
    # refused by the kernel (the tool fails); under a generous limit it succeeds. Used to prove
    # the worker actually applies the resource caps handed to it.
    path = str(arguments["path"])
    size = int(arguments["size"])
    with open(path, "wb") as handle:
        handle.write(b"x" * size)
    return {"written": size}

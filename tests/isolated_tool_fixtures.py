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


def spawn_bg_child_then_return_normally(arguments: dict[str, Any]) -> dict[str, Any]:
    # PR 1b: the tool spawns a background child and then RETURNS NORMALLY (it does not sleep like
    # spawn_grandchild_then_sleep, which tests the timeout path). The child writes a ".started"
    # marker at once, sleeps `delay`, then writes the "alive" marker. On a normal worker exit the
    # worker SIGKILLs its own process group, which must kill this child before its `alive` write.
    # The tool waits until ".started" exists before returning, so the test can assert the child
    # really ran (started present) yet was swept (alive absent) -- it cannot pass merely because the
    # child never spawned. With `escape`="setsid" (new session) or "setpgid" (new group in the same
    # session) the child moves to its OWN process group and ESCAPES the sweep (documented residuals),
    # so `alive` DOES appear. The group-change runs BEFORE the ".started" write, so that marker
    # proves the escape already happened -- the test's "alive present" is real evidence, not luck.
    marker = str(arguments["marker"])
    started = marker + ".started"
    delay = float(arguments.get("delay", 3.0))
    escape = arguments.get("escape")
    escape_call = {"setsid": "os.setsid();", "setpgid": "os.setpgid(0,0);"}.get(str(escape), "")
    # The child records into the "alive" marker whether it is its OWN process-group leader
    # (getpgrp()==getpid()) -- True exactly when it escaped the worker's group (setsid/setpgid made it
    # a new group leader). The test asserts that content, so "alive present" means "survived BECAUSE
    # it left the group," not merely "survived" (which timing or a failed setpgid could also produce).
    program = (
        f"import os,time,pathlib;{escape_call}"
        f"pathlib.Path({started!r}).write_text('x');"
        f"time.sleep({delay});pathlib.Path({marker!r}).write_text(str(os.getpgrp()==os.getpid()))"
    )
    subprocess.Popen(  # nosec B603
        [sys.executable, "-c", program],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 10.0
    while not os.path.exists(started) and time.time() < deadline:
        time.sleep(0.02)
    return {"spawned": True}


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

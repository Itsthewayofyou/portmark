from __future__ import annotations

import base64
import binascii
import io
import json
import sys
from contextlib import redirect_stdout
from typing import Any


def main() -> None:
    try:
        request = json.load(sys.stdin)
        component = base64.b64decode(_string(request, "component"), validate=True)
        context_json = _string(request, "context_json")
        checkpoint_json = _string(request, "checkpoint_json")
        max_output_bytes = int(request["max_output_bytes"])
        if max_output_bytes < 1:
            raise RuntimeError("max_output_bytes must be positive")
        max_fuel = int(request["max_fuel"])
        if max_fuel < 1:
            raise RuntimeError("max_fuel must be positive")
        max_memory_bytes = int(request["max_memory_bytes"])
        if max_memory_bytes < 1:
            raise RuntimeError("max_memory_bytes must be positive")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, binascii.Error) as error:
        _fail(error)
        raise SystemExit(1)

    try:
        from wasmtime import Config, Engine, Store
        try:
            from wasmtime import WasmtimeError
        except ImportError:
            WasmtimeError = RuntimeError
        from wasmtime.component import Component, Linker
    except ImportError as error:
        _fail(error)
        raise SystemExit(1)

    try:
        captured_stdout = _CappedTextIO(max_output_bytes)
        with redirect_stdout(captured_stdout):
            # Bound guest CPU with fuel (deterministic instruction budget) and guest
            # memory with a store limit, so a component cannot exhaust the worker via
            # a tight loop or aggressive memory.grow before the wall-clock fires. #6.
            config = Config()
            config.consume_fuel = True
            engine = Engine(config)
            store = Store(engine)
            store.set_fuel(max_fuel)
            store.set_limits(memory_size=max_memory_bytes)
            instance = Linker(engine).instantiate(store, Component(engine, component))
            resume = instance.get_func(store, "resume")
            if resume is None:
                raise RuntimeError("component does not export resume")
            result = resume(store, context_json, checkpoint_json)
            resume.post_return(store)
        outcome = json.dumps(_normalize_outcome(result))
        if len(outcome.encode()) > max_output_bytes:
            raise RuntimeError("component outcome exceeds output limit")
        print(outcome, end="")
    except (WasmtimeError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as error:
        _fail(error)
        raise SystemExit(1)


def _string(value: dict[str, Any], key: str) -> str:
    item = value[key]
    if not isinstance(item, str):
        raise RuntimeError(f"{key} must be a string")
    return item


def _fail(error: BaseException) -> None:
    print(f"native Wasmtime component failed: {type(error).__name__}: {error}", file=sys.stderr)


def _normalize_outcome(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        parsed = json.loads(value)
        if not isinstance(parsed, dict):
            raise RuntimeError("component outcome string must decode to a JSON object")
        return parsed
    tag = getattr(value, "tag", None) or getattr(value, "case", None)
    payload = getattr(value, "value", None)
    if isinstance(tag, str):
        return _outcome_from_tag(tag, payload)
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
        return _outcome_from_tag(value[0], value[1])
    raise RuntimeError("component outcome has an unsupported shape")


def _outcome_from_tag(tag: str, payload: Any) -> dict[str, Any]:
    normalized = tag.replace("_", "-")
    if normalized == "tool":
        if not isinstance(payload, dict):
            name = getattr(payload, "name", None)
            arguments_json = getattr(payload, "arguments_json", None) or getattr(payload, "arguments-json", None)
            payload = {"name": name, "arguments_json": arguments_json}
        return {"outcome": "tool", "request": payload}
    if normalized in {"completed", "suspended", "awaiting-input", "failed"}:
        return {"outcome": normalized, "content_json": payload}
    if normalized == "migrate":
        if isinstance(payload, tuple) and len(payload) == 2:
            destination, content_json = payload
        else:
            destination = getattr(payload, "destination", None)
            content_json = getattr(payload, "content_json", None) or getattr(payload, "content-json", None)
        return {"outcome": "migrate", "destination": destination, "content_json": content_json}
    raise RuntimeError("component outcome tag is not supported")


class _CappedTextIO(io.StringIO):
    def __init__(self, max_bytes: int):
        super().__init__()
        self._max_bytes = max_bytes
        self._bytes_written = 0

    def write(self, value: str) -> int:
        self._bytes_written += len(value.encode())
        if self._bytes_written > self._max_bytes:
            raise RuntimeError("component wrote too much stdout")
        return len(value)


if __name__ == "__main__":
    main()

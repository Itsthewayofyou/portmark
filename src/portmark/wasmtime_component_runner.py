from __future__ import annotations

import base64
import binascii
import io
import json
import sys

from .json_guard import strict_json_loads
from contextlib import redirect_stdout
from typing import Any

# Trusted import, before any cap is applied: the fail-closed rlimit helper shared with the
# isolated tool worker (returns the names of caps that could NOT be put in force).
from .tool_subprocess_runner import _apply_resource_limits

# Wasmtime store count limits, passed through verbatim from the provider (Section 9, #1).
_COUNT_LIMIT_KEYS = ("instances", "memories", "tables", "table_elements")
_MEMORY_GUARD_BYTES = 64 * 1024


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
        # Per LINEAR MEMORY, not an aggregate: Wasmtime applies memory_size to each memory
        # separately. The aggregate guest ceiling is max_memories x this value (Section 9, #1).
        max_memory_bytes = int(request["max_memory_bytes"])
        if max_memory_bytes < 1:
            raise RuntimeError("max_memory_bytes must be positive")
        count_limits = {key: int(request[key]) for key in _COUNT_LIMIT_KEYS}
        if any(value < 0 for value in count_limits.values()):
            raise RuntimeError("store count limits must not be negative")
        rlimits = request.get("rlimits") or {}
        if not isinstance(rlimits, dict):
            raise RuntimeError("rlimits must be an object")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, binascii.Error) as error:
        _fail(error)
        raise SystemExit(1)

    try:
        from wasmtime import Engine, Store
        try:
            from wasmtime import WasmtimeError
        except ImportError:
            WasmtimeError = RuntimeError
        from wasmtime.component import Component, Linker
    except ImportError as error:
        _fail(error)
        raise SystemExit(1)

    # ORDER IS LOAD-BEARING (Section 9, #1/#3): every trusted import above -- including the
    # native wasmtime wheel -- happens BEFORE the OS caps, so a low address-space cap cannot kill
    # the interpreter mid-bootstrap; the caps are in force BEFORE the Engine is built and the
    # component is compiled, so JIT compilation (which fuel does not meter) runs capped too.
    # Moving the caps below Engine()/Component() silently reopens the uncapped-compile gap.
    unapplied = _apply_resource_limits(rlimits)
    if unapplied:
        _fail(RuntimeError("worker resource limits could not be applied: " + ", ".join(unapplied)))
        raise SystemExit(1)

    try:
        captured_stdout = _CappedTextIO(max_output_bytes)
        with redirect_stdout(captured_stdout):
            # Bound guest CPU with fuel (deterministic instruction budget), each linear memory
            # with memory_size, and the NUMBER of instances/memories/tables/table elements, so
            # a component cannot multiply the per-memory ceiling by declaring many memories
            # (Section 9, #1). The worker process itself is capped by the OS (above).
            engine = Engine(_engine_config(max_memory_bytes))
            store = Store(engine)
            store.set_fuel(max_fuel)
            store.set_limits(memory_size=max_memory_bytes, **count_limits)
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


def _engine_config(max_memory_bytes: int) -> Any:
    """The one hardened Wasmtime ``Config`` for untrusted components (Section 9, #1/#3/#4).

    Every setting is explicit, so behaviour does not drift with Wasmtime's changing defaults.
    Imported lazily: the module must stay importable without the optional wasmtime extra.
    """
    from wasmtime import Config

    config = Config()
    config.consume_fuel = True
    # Compile on one thread: the default fans compilation out across all cores, and every
    # decision compiles afresh in its own worker, so concurrent requests multiplied it (#3).
    config.parallel_compilation = False
    # Reserve only what the guest may use. The default reservation (GiBs of virtual space per
    # memory) cannot fit under an OS address-space cap -- probed: ENOMEM under 1 GiB, SIGABRT
    # under 256 MiB -- while this fits two full memories under the 512 MiB worker cap. (The
    # "RLIMIT_AS is unusable" note on the Node provider is about V8, not this path.)
    config.memory_reservation = max_memory_bytes
    config.memory_guard_size = _MEMORY_GUARD_BYTES
    # debt: with no growth reservation, memory.grow past the initial size copies the memory;
    # ceiling = a guest that needs large dynamic growth; upgrade when a real capsule's grow
    # latency shows up in decision timing.
    config.memory_reservation_for_growth = 0
    # Deterministic results across x86-64 / AArch64 (#4): pin relaxed-SIMD lowering and
    # canonicalize NaN payloads, which a guest could otherwise observe and branch on.
    config.wasm_relaxed_simd = True
    config.wasm_relaxed_simd_deterministic = True
    config.cranelift_nan_canonicalization = True
    # Lock the proposal set. Off: host-dependent or unneeded surface. Each "off" below that
    # Wasmtime 48 enables by default is proven refused by a test (threads, memory64,
    # multi-memory, gc, exceptions); the rest are already off by default and pinned here.
    config.wasm_threads = False
    config.shared_memory = False
    config.wasm_memory64 = False
    config.wasm_multi_memory = False
    config.wasm_gc = False
    config.wasm_exceptions = False
    config.wasm_stack_switching = False
    config.wasm_wide_arithmetic = False
    config.wasm_custom_page_sizes = False
    # On: what the Component Model contract needs.
    config.wasm_component_model = True
    config.wasm_multi_value = True
    config.wasm_bulk_memory = True
    config.wasm_reference_types = True
    config.wasm_simd = True
    return config


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
        parsed = strict_json_loads(value)
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

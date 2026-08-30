from __future__ import annotations

import json
import hashlib
import base64
import os
import shutil
import subprocess  # nosec B404
import sys
import urllib.request
from urllib.parse import urlparse
from abc import ABC, abstractmethod
from typing import Any

from .component_bindings import component_checkpoint, component_context, decode_component_decision, encode_component_input
from .models import AgentState, ProviderDecision, ToolGrant
from .projection import provider_state
from .security import SecurityError

DEFAULT_MAX_WASM_COMPONENT_BYTES = 10_000_000


class ModelProvider(ABC):
    @abstractmethod
    def decide(self, state: AgentState, available_tools: tuple[str, ...], grants: tuple[ToolGrant, ...] = ()) -> ProviderDecision:
        """Return a proposal. The host remains responsible for authorization and execution."""


class DeterministicProvider(ModelProvider):
    """Offline provider used for tests and the demo."""

    def decide(self, state: AgentState, available_tools: tuple[str, ...], grants: tuple[ToolGrant, ...] = ()) -> ProviderDecision:
        if not state.memory.get("catalog") and "catalog.search" in available_tools:
            return ProviderDecision("tool", "catalog.search", {"query": state.goal, "limit": 3})
        return ProviderDecision(
            "complete",
            content={"summary": f"Completed: {state.goal}", "evidence": state.memory.get("catalog", [])},
        )


class GenericHttpProvider(ModelProvider):
    """Provider-neutral JSON adapter for a local or remote model gateway."""

    def __init__(self, endpoint: str, bearer_token: str | None = None, timeout: float = 30.0, max_response_bytes: int = 65_536) -> None:
        scheme = urlparse(endpoint).scheme
        if scheme not in {"http", "https"}:
            raise ValueError("provider endpoint must use http or https")
        self.endpoint = endpoint
        self.bearer_token = bearer_token
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes

    def decide(self, state: AgentState, available_tools: tuple[str, ...], grants: tuple[ToolGrant, ...] = ()) -> ProviderDecision:
        body = json.dumps({"state": provider_state(state, grants), "available_tools": available_tools}).encode()
        headers = {"Content-Type": "application/json"}
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        request = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
        # Endpoint scheme is validated at initialization.
        with urllib.request.urlopen(request, timeout=self.timeout) as response:  # nosec B310
            raw = response.read(self.max_response_bytes + 1)
        if len(raw) > self.max_response_bytes:
            raise SecurityError("provider response exceeds output limit")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise SecurityError("provider response is malformed JSON") from error
        return _provider_decision(value)


def _provider_decision(value: Any) -> ProviderDecision:
    if not isinstance(value, dict):
        raise SecurityError("provider response must be a JSON object")
    kind = value.get("kind")
    if kind == "tool":
        tool = value.get("tool")
        if not isinstance(tool, str) or not tool:
            raise SecurityError("provider tool decision has an invalid tool name")
        arguments = value.get("arguments", {})
        if not isinstance(arguments, dict):
            raise SecurityError("provider tool decision arguments must be a JSON object")
        return ProviderDecision("tool", tool=tool, arguments=arguments, content=value.get("content"), destination=value.get("destination"))
    if kind in {"complete", "await_input", "fail"}:
        return ProviderDecision(kind, content=value.get("content"))
    if kind == "migrate":
        destination = value.get("destination")
        if not isinstance(destination, str) or not destination:
            raise SecurityError("provider migration decision has an invalid destination")
        content = value.get("content")
        if content is not None and not isinstance(content, dict):
            raise SecurityError("provider migration decision content must be a JSON object")
        return ProviderDecision("migrate", content=content, destination=destination)
    raise SecurityError("provider response kind is not supported")


def _read_component_file(path: str, max_component_bytes: int) -> bytes:
    if max_component_bytes < 1:
        raise ValueError("max_component_bytes must be at least 1")
    read_limit = max_component_bytes + 1
    if path.endswith(".b64"):
        read_limit = max_component_bytes * 2 + 1
    with open(path, "rb") as file:
        component = file.read(read_limit)
    if len(component) >= read_limit:
        raise RuntimeError("Wasm component exceeds input limit")
    if path.endswith(".b64"):
        component = base64.b64decode(component.strip(), validate=True)
    if len(component) > max_component_bytes:
        raise RuntimeError("Wasm component exceeds input limit")
    return component


class WasmDecisionProvider(ModelProvider):
    """Runs WIT-shaped portable agent decision logic in Wasm with no ambient imports."""

    def __init__(
        self,
        component: bytes,
        timeout: float = 2.0,
        max_output_bytes: int = 65_536,
        max_component_bytes: int = DEFAULT_MAX_WASM_COMPONENT_BYTES,
    ) -> None:
        node = shutil.which("node")
        if not node:
            raise RuntimeError("Node.js is required to execute WebAssembly capsules")
        if len(component) > max_component_bytes:
            raise RuntimeError("Wasm component exceeds input limit")
        self._node = node
        self._component = component
        self._timeout = timeout
        self._max_output_bytes = max_output_bytes
        self._runner = os.path.join(os.path.dirname(__file__), "wasm_runner.mjs")
        self.component_digest = "sha256:" + hashlib.sha256(component).hexdigest()

    @classmethod
    def from_file(
        cls,
        path: str,
        timeout: float = 2.0,
        max_output_bytes: int = 65_536,
        max_component_bytes: int = DEFAULT_MAX_WASM_COMPONENT_BYTES,
    ) -> "WasmDecisionProvider":
        component = _read_component_file(path, max_component_bytes)
        return cls(component, timeout, max_output_bytes, max_component_bytes)

    def decide(self, state: AgentState, available_tools: tuple[str, ...], grants: tuple[ToolGrant, ...] = ()) -> ProviderDecision:
        encoded_component = base64.b64encode(self._component).decode("ascii")
        context_json = encode_component_input(component_context(state, available_tools, grants))
        checkpoint_json = encode_component_input(component_checkpoint(state, grants))
        try:
            # Shell is disabled and the executable/runner paths are host-controlled.
            process = subprocess.run(  # nosec B603
                [self._node, self._runner],
                input=json.dumps({"component": encoded_component, "context_json": context_json, "checkpoint_json": checkpoint_json}),
                capture_output=True, text=True, timeout=self._timeout, check=False,
                # Node needs the normal Windows process environment to initialize.
                # The Wasm guest cannot observe it because the module receives no imports.
                env=os.environ.copy(),
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("Wasm capsule exceeded its execution deadline") from error
        if process.returncode != 0:
            raise RuntimeError("Wasm capsule rejected: " + process.stderr.strip())
        if len(process.stdout.encode()) > self._max_output_bytes:
            raise RuntimeError("Wasm component decision exceeded output limit")
        return decode_component_decision(process.stdout, available_tools)


class NativeWasmtimeComponentProvider(ModelProvider):
    """Runs a Component Model provider through wasmtime-py."""

    def __init__(
        self,
        component: bytes,
        timeout: float = 2.0,
        max_output_bytes: int = 65_536,
        max_component_bytes: int = DEFAULT_MAX_WASM_COMPONENT_BYTES,
    ) -> None:
        if len(component) > max_component_bytes:
            raise RuntimeError("Wasm component exceeds input limit")
        self._component = component
        self._timeout = timeout
        self._max_output_bytes = max_output_bytes
        self.component_digest = "sha256:" + hashlib.sha256(component).hexdigest()

    @classmethod
    def from_file(
        cls,
        path: str,
        timeout: float = 2.0,
        max_output_bytes: int = 65_536,
        max_component_bytes: int = DEFAULT_MAX_WASM_COMPONENT_BYTES,
    ) -> "NativeWasmtimeComponentProvider":
        component = _read_component_file(path, max_component_bytes)
        return cls(component, timeout, max_output_bytes, max_component_bytes)

    def decide(
        self,
        state: AgentState,
        available_tools: tuple[str, ...],
        grants: tuple[ToolGrant, ...] = (),
    ) -> ProviderDecision:
        context_json = encode_component_input(component_context(state, available_tools, grants))
        checkpoint_json = encode_component_input(component_checkpoint(state, grants))
        environment = {}
        python_path = os.environ.get("PYTHONPATH")
        if python_path:
            environment["PYTHONPATH"] = python_path
        try:
            process = subprocess.run(  # nosec B603
                [sys.executable, "-m", "portmark.wasmtime_component_runner"],
                input=json.dumps({
                    "component": base64.b64encode(self._component).decode("ascii"),
                    "context_json": context_json,
                    "checkpoint_json": checkpoint_json,
                    "max_output_bytes": self._max_output_bytes,
                }),
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
                env=environment,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("native Wasmtime component exceeded its execution deadline") from error
        if process.returncode != 0:
            raise RuntimeError("native Wasmtime component rejected")
        if len(process.stdout.encode()) > self._max_output_bytes:
            raise RuntimeError("native Wasmtime component decision exceeded output limit")
        return decode_component_decision(process.stdout, available_tools)

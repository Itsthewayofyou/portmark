from __future__ import annotations

import json
import hashlib
import base64
import os
import shutil
import subprocess  # nosec B404
import urllib.request
from urllib.parse import urlparse
from abc import ABC, abstractmethod
from typing import Any

from .component_bindings import component_checkpoint, component_context, decode_component_decision, encode_component_input
from .models import AgentState, ProviderDecision


class ModelProvider(ABC):
    @abstractmethod
    def decide(self, state: AgentState, available_tools: tuple[str, ...]) -> ProviderDecision:
        """Return a proposal. The host remains responsible for authorization and execution."""


class DeterministicProvider(ModelProvider):
    """Offline provider used for tests and the demo."""

    def decide(self, state: AgentState, available_tools: tuple[str, ...]) -> ProviderDecision:
        if not state.memory.get("catalog") and "catalog.search" in available_tools:
            return ProviderDecision("tool", "catalog.search", {"query": state.goal, "limit": 3})
        return ProviderDecision(
            "complete",
            content={"summary": f"Completed: {state.goal}", "evidence": state.memory.get("catalog", [])},
        )


class GenericHttpProvider(ModelProvider):
    """Provider-neutral JSON adapter for a local or remote model gateway."""

    def __init__(self, endpoint: str, bearer_token: str | None = None, timeout: float = 30.0) -> None:
        scheme = urlparse(endpoint).scheme
        if scheme not in {"http", "https"}:
            raise ValueError("provider endpoint must use http or https")
        self.endpoint = endpoint
        self.bearer_token = bearer_token
        self.timeout = timeout

    def decide(self, state: AgentState, available_tools: tuple[str, ...]) -> ProviderDecision:
        body = json.dumps({"state": state.__dict__, "available_tools": available_tools}).encode()
        headers = {"Content-Type": "application/json"}
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        request = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
        # Endpoint scheme is validated at initialization.
        with urllib.request.urlopen(request, timeout=self.timeout) as response:  # nosec B310
            value: dict[str, Any] = json.load(response)
        return ProviderDecision(
            kind=value["kind"],
            tool=value.get("tool"),
            arguments=value.get("arguments", {}),
            content=value.get("content"),
            destination=value.get("destination"),
        )


class WasmDecisionProvider(ModelProvider):
    """Runs WIT-shaped portable agent decision logic in Wasm with no ambient imports."""

    def __init__(self, component: bytes, timeout: float = 2.0, max_output_bytes: int = 65_536) -> None:
        node = shutil.which("node")
        if not node:
            raise RuntimeError("Node.js is required to execute WebAssembly capsules")
        self._node = node
        self._component = component
        self._timeout = timeout
        self._max_output_bytes = max_output_bytes
        self._runner = os.path.join(os.path.dirname(__file__), "wasm_runner.mjs")
        self.component_digest = "sha256:" + hashlib.sha256(component).hexdigest()

    @classmethod
    def from_file(cls, path: str, timeout: float = 2.0, max_output_bytes: int = 65_536) -> "WasmDecisionProvider":
        with open(path, "rb") as file:
            component = file.read()
        if path.endswith(".b64"):
            component = base64.b64decode(component.strip(), validate=True)
        return cls(component, timeout, max_output_bytes)

    def decide(self, state: AgentState, available_tools: tuple[str, ...]) -> ProviderDecision:
        encoded_component = base64.b64encode(self._component).decode("ascii")
        context_json = encode_component_input(component_context(state, available_tools))
        checkpoint_json = encode_component_input(component_checkpoint(state))
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

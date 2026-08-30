from __future__ import annotations

import secrets
from dataclasses import asdict
from collections.abc import Callable
from typing import Any

from .metrics import RuntimeMetrics
from .models import AgentEnvelope, ApprovalToken, AttestationEvidence, ProviderDecision, RunResult
from .providers import ModelProvider
from .security import AttestationPolicy, AuditLog, EnvelopeSigningIdentity, HostPolicy, SecurityError, arguments_hash, audit_head_payload, canonical_json
from .storage import InMemoryRuntimeStore, RuntimeStore
from .tools import ToolExecutionError, ToolRegistry


class AgentHost:
    def __init__(
        self,
        host_id: str,
        signer: EnvelopeSigningIdentity,
        policy: HostPolicy,
        tools: ToolRegistry,
        providers: dict[str, ModelProvider],
        store: RuntimeStore | None = None,
        attestation_policy: AttestationPolicy | None = None,
        policy_loader: Callable[[], HostPolicy] | None = None,
        reload_policy: bool = False,
        metrics: RuntimeMetrics | None = None,
    ) -> None:
        if policy.audience != host_id:
            raise ValueError("policy audience must equal host id")
        self.host_id = host_id
        self.signer = signer
        self.policy = policy
        self.tools = tools
        self.providers = providers
        self.store = store or InMemoryRuntimeStore()
        if hasattr(self.store, "set_audit_head_verifier"):
            self.store.set_audit_head_verifier(self.signer)
        self.attestation_policy = attestation_policy or AttestationPolicy()
        self._policy_loader = policy_loader
        self._reload_policy = reload_policy
        self.metrics = metrics or RuntimeMetrics()

    def run(self, envelope: AgentEnvelope) -> RunResult:
        self.metrics.increment("runs.started")
        try:
            return self._run(envelope)
        except SecurityError:
            self.metrics.increment("runs.failed")
            self.metrics.increment("security.rejections")
            raise
        except Exception:
            self.metrics.increment("runs.failed")
            raise

    def _run(self, envelope: AgentEnvelope) -> RunResult:
        active_policy = self._active_policy()
        self.signer.verify(envelope)
        effective = active_policy.effective_permit(envelope.manifest, envelope.permit)
        self.attestation_policy.verify_execution(effective, self.host_id)
        provider = self.providers.get(envelope.manifest.provider)
        if provider is None:
            raise SecurityError(f"provider {envelope.manifest.provider!r} is not configured")
        provider_digest = getattr(provider, "component_digest", None)
        if provider_digest is not None and envelope.manifest.component_digest != provider_digest:
            raise SecurityError("Wasm component digest does not match the signed manifest")

        state = envelope.state
        consume_nonce = envelope.permit.nonce if state.status == "ready" else None
        state.status = "running"
        previous_hash, start_sequence = self._audit_start(envelope)
        audit = AuditLog(previous_hash, start_sequence)
        audit.append(
            "agent.accepted",
            {
                "agent": envelope.manifest.agent_id,
                "host": self.host_id,
                "policy_version": active_policy.policy_version,
                "policy_hash": active_policy.policy_hash,
            },
        )
        persisted_events = self._persist(envelope, state, audit, 0, consume_nonce=consume_nonce)
        tool_names = tuple(grant.name for grant in effective.grants)

        while state.step < effective.budget.max_steps:
            decision = provider.decide(state, tool_names, effective.grants)
            self.metrics.increment("provider.decisions")
            audit.append("provider.proposed", {"kind": decision.kind, "tool": decision.tool})
            finished, migration = self._apply_decision(decision, state, effective, audit, envelope, active_policy)
            state.step += 1
            persisted_events = self._persist(envelope, state, audit, persisted_events)
            if finished:
                result = self._result(envelope, audit, migration)
                self._record_run_status(result.status)
                return result

        state.status = "failed"
        state.result = {"error": "step budget exhausted"}
        audit.append("agent.failed", state.result)
        self._persist(envelope, state, audit, persisted_events)
        result = self._result(envelope, audit)
        self._record_run_status(result.status)
        return result

    def _apply_decision(self, decision, state, effective, audit, envelope, active_policy):
        if decision.kind == "tool":
            if state.tool_calls >= effective.budget.max_tool_calls:
                raise SecurityError("tool-call budget exhausted")
            if not decision.tool:
                raise SecurityError("provider proposed a tool action without a tool name")
            if not any(grant.name == decision.tool for grant in effective.grants):
                raise SecurityError(f"tool {decision.tool!r} was not granted")
            approval_result = self._approval_gate(active_policy, effective, state, decision, audit)
            if approval_result is not None:
                return approval_result
            try:
                result = self.tools.invoke(effective, decision.tool, decision.arguments, effective.budget.max_output_bytes)
            except ToolExecutionError as error:
                self.metrics.increment("tools.failed")
                state.status = "failed"
                state.result = {"error": "tool execution failed"}
                audit.append(
                    "tool.failed",
                    {
                        "tool": decision.tool,
                        "arguments": decision.arguments,
                        "error": str(error),
                        "cause": type(error.__cause__).__name__ if error.__cause__ is not None else None,
                        "cause_message": str(error.__cause__) if error.__cause__ is not None else "",
                    },
                )
                audit.append("agent.failed", state.result)
                return True, None
            state.tool_calls += 1
            self.metrics.increment("tools.executed")
            state.memory[decision.tool.removesuffix(".search").replace(".", "_")] = result
            if decision.tool == "catalog.search":
                state.memory["catalog"] = result
            state.messages.append({"role": "tool", "name": decision.tool, "content": result})
            audit.append("tool.executed", {"tool": decision.tool, "arguments": decision.arguments})
            return False, None
        if decision.kind == "complete":
            state.status = "completed"
            state.result = decision.content
            audit.append("agent.completed", {"result": decision.content})
            return True, None
        if decision.kind == "await_input":
            state.status = "awaiting_input"
            state.result = decision.content
            audit.append("agent.awaiting_input", {"request": decision.content})
            return True, None
        if decision.kind == "migrate":
            if not decision.destination:
                raise SecurityError("migration proposal lacks a destination")
            if not envelope.permit.delegation_allowed:
                raise SecurityError("permit does not allow migration delegation")
            destination_attestation = self._migration_attestation(decision)
            self.attestation_policy.verify_migration(destination_attestation, decision.destination, self.host_id)
            state.status = "ready"
            state.memory["migration"] = {"from": self.host_id, "to": decision.destination}
            if destination_attestation is not None:
                state.memory["migration"]["attested_measurement"] = destination_attestation.measurement
            state.result = {"destination": decision.destination}
            audit.append("agent.migrating", state.result)
            delegated = type(effective)(
                issuer=self.host_id,
                subject=effective.subject,
                audience=decision.destination,
                expires_at=effective.expires_at,
                nonce=secrets.token_hex(16),
                grants=effective.grants,
                budget=effective.budget,
                delegation_allowed=False,
                attestation=destination_attestation,
            )
            previous_sequence = audit.events[-1]["sequence"] + 1
            migrated = AgentEnvelope(
                envelope.manifest,
                delegated,
                state,
                previous_audit_hash=audit.head,
                previous_audit_sequence=previous_sequence,
                previous_audit_host_id=self.host_id,
                previous_audit_signature_key_id=self.signer.key_id,
                previous_audit_signature=self.signer.sign_audit_head(state.task_id, self.host_id, audit.head, previous_sequence),
            )
            self.signer.seal(migrated)
            return True, asdict(migrated)
        state.status = "failed"
        state.result = decision.content or {"error": "provider failed"}
        audit.append("agent.failed", {"result": state.result})
        return True, None

    def _active_policy(self) -> HostPolicy:
        if self._policy_loader is not None and self._reload_policy:
            loaded = self._policy_loader()
            if loaded.audience != self.host_id:
                raise ValueError("policy audience must equal host id")
            self.policy = loaded
        return self.policy

    def _approval_gate(self, policy: HostPolicy, permit, state, decision: ProviderDecision, audit: AuditLog) -> tuple[bool, None] | None:
        if decision.tool is None or not policy.requires_approval(decision.tool):
            return None
        token = self._approval_token(state, decision.tool)
        if token is None:
            state.status = "awaiting_input"
            state.result = {
                "approval_required": True,
                "tool": decision.tool,
                "impact": policy.impact_for_tool(decision.tool),
                "arguments_hash": arguments_hash(decision.arguments),
                "policy_version": policy.policy_version,
                "policy_hash": policy.policy_hash,
            }
            audit.append("approval.requested", state.result)
            return True, None
        used = set(state.memory.get("used_approval_ids", []))
        if token.approval_id in used:
            return self._approval_failure(state, audit, "approval.denied", "replayed")
        try:
            policy.verify_approval(token, permit, state.task_id, decision.tool, decision.arguments)
        except SecurityError as error:
            event = "approval.expired" if "expired" in str(error) else "approval.denied"
            return self._approval_failure(state, audit, event, "invalid")
        audit.append("approval.approved", {"approval_id": token.approval_id, "tool": decision.tool, "approved_by": token.approved_by})
        used_values = list(state.memory.get("used_approval_ids", []))
        used_values.append(token.approval_id)
        state.memory["used_approval_ids"] = used_values
        audit.append("approval.used", {"approval_id": token.approval_id, "tool": decision.tool})
        return None

    def _approval_failure(self, state, audit: AuditLog, event: str, reason: str) -> tuple[bool, None]:
        state.status = "failed"
        state.result = {"error": "approval rejected"}
        audit.append(event, {"reason": reason})
        audit.append("agent.failed", state.result)
        return True, None

    def _approval_token(self, state, tool: str) -> ApprovalToken | None:
        approvals = state.memory.get("approvals")
        value = None
        if isinstance(approvals, dict):
            value = approvals.get(tool)
        elif isinstance(approvals, list):
            value = next((item for item in approvals if isinstance(item, dict) and item.get("tool") == tool), None)
        if value is None:
            return None
        if isinstance(value, ApprovalToken):
            return value
        if not isinstance(value, dict):
            raise SecurityError("approval token has invalid shape")
        return ApprovalToken(**value)

    def _migration_attestation(self, decision: ProviderDecision) -> AttestationEvidence | None:
        if not isinstance(decision.content, dict):
            return None
        value = decision.content.get("attestation")
        if value is None:
            return None
        if isinstance(value, AttestationEvidence):
            return value
        if not isinstance(value, dict):
            raise SecurityError("migration attestation has invalid shape")
        return AttestationEvidence(**value)

    def _result(self, envelope, audit, migration=None):
        checkpoint = asdict(envelope.state)
        encoded_size = len(canonical_json(checkpoint))
        if encoded_size > envelope.permit.budget.max_output_bytes:
            raise SecurityError("checkpoint exceeds output budget")
        return RunResult(envelope.state.status, envelope.state.task_id, envelope.state.result, checkpoint, audit.events, migration)

    def _record_run_status(self, status: str) -> None:
        self.metrics.increment(f"runs.{status}")
        if status == "failed":
            self.metrics.increment("runs.failed")

    def _audit_start(self, envelope: AgentEnvelope) -> tuple[str, int]:
        stored = self.store.audit_head(envelope.state.task_id)
        if envelope.previous_audit_hash:
            if stored is not None and stored[0] != envelope.previous_audit_hash:
                raise SecurityError("envelope audit head does not match stored audit head")
            if stored is None:
                self._verify_previous_audit_head(envelope)
            return envelope.previous_audit_hash, stored[1] if stored is not None else 0
        if stored is not None:
            return stored
        return "", 0

    def _verify_previous_audit_head(self, envelope: AgentEnvelope) -> None:
        if (
            not envelope.previous_audit_host_id
            or not envelope.previous_audit_signature_key_id
            or not envelope.previous_audit_signature
            or envelope.previous_audit_sequence <= 0
        ):
            raise SecurityError("previous audit head signature is missing")
        self.signer.verify_audit_head(
            envelope.previous_audit_signature_key_id,
            audit_head_payload(
                envelope.state.task_id,
                envelope.previous_audit_host_id,
                envelope.previous_audit_hash,
                envelope.previous_audit_sequence,
            ),
            envelope.previous_audit_signature,
        )

    def _persist(
        self,
        envelope: AgentEnvelope,
        state,
        audit: AuditLog,
        persisted_events: int,
        consume_nonce: str | None = None,
    ) -> int:
        checkpoint = asdict(state)
        encoded_size = len(canonical_json(checkpoint))
        if encoded_size > envelope.permit.budget.max_output_bytes:
            raise SecurityError("checkpoint exceeds output budget")
        with self.store.transaction() as transaction:
            if consume_nonce is not None:
                transaction.consume_nonce(consume_nonce, envelope.permit.subject, envelope.permit.audience, state.task_id)
            transaction.append_audit_events(
                state.task_id,
                self.host_id,
                audit.events[persisted_events:],
                lambda head_hash, sequence: (self.signer.key_id, self.signer.sign_audit_head(state.task_id, self.host_id, head_hash, sequence)),
            )
            transaction.save_checkpoint(state.task_id, state)
        return len(audit.events)

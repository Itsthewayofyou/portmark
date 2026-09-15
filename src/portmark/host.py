from __future__ import annotations

import json
import secrets
import threading
import time
from dataclasses import asdict, replace
from collections.abc import Callable
from typing import Any

from .metrics import RuntimeMetrics
from .models import AgentEnvelope, ApprovalToken, AttestationEvidence, ProviderDecision, RunResult
from .projection import project_state_for_migration, project_state_for_provider
from .providers import ModelProvider
from .security import _MIGRATION_RECEIPT_FIELDS, _OPTIONAL_MIGRATION_RECEIPT_FIELDS, AttestationPolicy, AuditLog, EnvelopeSigningIdentity, HostPolicy, MigrationAttesterProtocol, SecurityError, arguments_hash, audit_head_payload, canonical_json, migration_envelope_digest, migration_receipt_payload
from .storage import InMemoryRuntimeStore, RuntimeStore
from .tools import ToolExecutionError, ToolKilledError, ToolRegistry

# Prefixes that mark a manifest's component_digest as a content-addressed pin of
# exact bytes, as opposed to the symbolic default (e.g. "python:reference-agent-v1").
_CONTENT_DIGEST_ALGOS = frozenset({"sha256", "sha384", "sha512", "blake3"})


def _is_content_digest(digest: str) -> bool:
    algo, _, rest = digest.partition(":")
    return bool(rest) and algo in _CONTENT_DIGEST_ALGOS


# Section 4 #7: task ids are caller-chosen and only unique within their originating host.
# A destination that admits migrations from several sources would otherwise key
# checkpoints/audit/receipts on a bare task id, so one source could squat another's id
# (observed: the second migration is rejected as a receipt collision, a denial of the
# peer's delivery). The destination namespaces a MIGRATED task's stored identity by the
# source host it has cryptographically authenticated at admission
# (previous_audit_host_id == permit.issuer == signing identity.issuer). The source is not
# yet trusted to name another source's space, so the namespace comes from the verified
# source, not the id the source chose.
_MIGRATION_TASK_NAMESPACE = "mig::"


def _namespaced_migration_task_id(source_host_id: str, task_id: str) -> str:
    # Injective by the embedded length: given the result, the source is exactly the
    # `len(source_host_id)` chars after the count, so two distinct (source, task_id) pairs
    # can never collide even if either contains "::". We never parse this back -- the
    # source settles delivery by the ORIGINAL task_id carried in the receipt payload, so a
    # constructor is all that is needed (a parser would be a second place to get it wrong).
    return f"{_MIGRATION_TASK_NAMESPACE}{len(source_host_id)}::{source_host_id}::{task_id}"


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
        migration_attester: MigrationAttesterProtocol | None = None,
        migration_attester_timeout: float | None = 5.0,
        migration_attester_max_inflight: int = 8,
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
            self.store.set_audit_head_verifier(self.signer)  # type: ignore[attr-defined]  # guarded by hasattr; not on the base RuntimeStore protocol
        self.attestation_policy = attestation_policy or AttestationPolicy()
        # Section 4 #5: destination-side challenge attester. When a migrated envelope demands a challenge,
        # the host uses this to attest to its own identity over the source's fresh challenge at admission.
        # None (default) => the host cannot satisfy a challenge-required migration and fails it closed.
        self.migration_attester = migration_attester
        # Section 4 #5 (finding 2): the attester runs inside the admission path, so the host bounds it
        # rather than trusting each implementation to self-bound. On timeout admission fails CLOSED
        # (nothing persisted); the worker thread is a daemon so a hung attester leaks a thread but can
        # never hold admission open. None disables the host bound (an explicit opt-out).
        self.migration_attester_timeout = migration_attester_timeout
        # Section 4 #5 (finding 2b): cap concurrent in-flight attester calls so a stream of deliveries
        # against a slow/hung attester cannot spawn an unbounded number of worker threads. A timed-out
        # call's worker holds its permit until it actually finishes (a truly-hung one holds it, so at
        # most this many hang before further calls are refused fail-closed); a call that returns -- even
        # after its timeout -- releases its permit, so transient slowness self-heals.
        self._attester_slots = threading.BoundedSemaphore(max(1, migration_attester_max_inflight))
        self._policy_loader = policy_loader
        self._reload_policy = reload_policy
        self.metrics = metrics or RuntimeMetrics()

    def run(self, envelope: AgentEnvelope) -> RunResult:
        started = time.monotonic()
        self.metrics.increment("runs.started")
        try:
            return self._run(envelope)
        except SecurityError:
            self.metrics.increment("runs.failed")
            self.metrics.increment("security.rejections")
            self.metrics.increment_refusal("security")
            raise
        except Exception:
            self.metrics.increment("runs.failed")
            raise
        finally:
            self.metrics.observe_duration("run_duration_seconds", time.monotonic() - started)

    def settle_migration(self, task_id: str, receipt: dict[str, Any]) -> None:
        """Source-side delivery settlement against a verified destination receipt (section 4 #2).

        A source marks a migration delivered ONLY on a receipt it has verified here: the receipt's
        signature against this source's trust (the destination's key must be trusted, with the
        `receipt` usage) AND every binding matching the outbox row (task id, this source, the row's
        destination, the delegated permit nonce, the sealed-envelope digest). A receipt that fails
        any check raises and the row stays pending -- an unverifiable receipt can never settle a
        migration. A source that does not trust the destination's key gets a clear
        "signing key is not trusted" error, which is the deployment prerequisite for settlement.
        """
        # Pending OR dead-lettered (section 4 #4): a verified receipt beats the dispatcher's local
        # give-up, so a late-but-valid receipt still settles a row the dispatcher dead-lettered --
        # this is what keeps #4 from regressing the section 4 #2 lost-ack fix. A row already
        # delivered returns None here (re-settlement is out of scope, Part 2b).
        row = self.store.find_migration_for_settlement(task_id)
        if row is None:
            raise SecurityError(f"no pending migration for task {task_id!r} to settle")
        self.signer.verify_migration_receipt(receipt)
        sealed = json.loads(row["sealed_envelope_json"])
        expected = {
            "task_id": task_id,
            "source_host_id": self.host_id,
            "destination_host_id": row["destination"],
            "permit_nonce": sealed["permit"]["nonce"],
            "envelope_digest": migration_envelope_digest(sealed),
        }
        mismatches = [field for field, value in expected.items() if receipt.get(field) != value]
        if mismatches:
            raise SecurityError(f"migration receipt does not match the outbox row: {', '.join(mismatches)}")
        # Section 4 #5 (challenge-passing protocol): when this migration was sealed as challenge-required,
        # the source demands the destination's fresh attestation over the challenge it minted (the sealed
        # permit nonce) and verifies it here against the source's trusted attestation authorities. Because
        # the source chose the challenge, pre-collected or stale destination evidence cannot satisfy it.
        # Runs after the receipt's own signature/shape check, so a present attestation is already
        # destination-signed. A challenge-required row whose receipt carries no attestation fails closed.
        sealed_memory = sealed.get("state", {}).get("memory", {})
        sealed_migration = sealed_memory.get("migration") if isinstance(sealed_memory, dict) else None
        if isinstance(sealed_migration, dict) and sealed_migration.get("challenge_required"):
            self.attestation_policy.verify_migration_challenge(
                receipt.get("destination_attestation"),
                challenge=sealed["permit"]["nonce"],
                destination=row["destination"],
                source_host_id=self.host_id,
            )
        # Persist the canonical body + signature envelope by CONSTRUCTION (not the caller's dict), so a
        # stored receipt only ever holds destination-signed fields even if the verify-side shape check is
        # ever weakened -- every persisted field is one the signature covered.
        canonical = {field: receipt[field] for field in _MIGRATION_RECEIPT_FIELDS}
        for field in _OPTIONAL_MIGRATION_RECEIPT_FIELDS:
            if field in receipt:
                canonical[field] = receipt[field]
        canonical["signature_key_id"] = receipt["signature_key_id"]
        canonical["signature"] = receipt["signature"]
        self.store.mark_migration_delivered(task_id, canonical_json(canonical).decode("utf-8"))

    def _run(self, envelope: AgentEnvelope) -> RunResult:
        active_policy = self._active_policy()
        self.signer.verify(envelope)
        # Section 4 #2: digest the sealed migration envelope NOW, while it is pristine -- admission
        # mutates envelope.state (status, counters), and the source's stored copy is pre-mutation,
        # so a later digest would not match. None for non-migration envelopes.
        incoming_migration_digest = migration_envelope_digest(asdict(envelope)) if envelope.previous_audit_hash else None
        # Section 4 #7: namespace a migrated task's stored identity by the authenticated
        # source. The digest above was taken on the pristine, source-sealed envelope (the
        # source's outbox row carries the ORIGINAL id), so it is computed BEFORE this
        # rewrite. previous_audit_host_id is only cryptographically verified later in
        # _audit_start; using it here is safe because nothing is PERSISTED under the
        # namespaced id until that verification has passed (a forged source aborts the run),
        # and the lookups below only READ -- a forged namespace finds nothing or a row whose
        # bindings will not match. The original id rides on in receipt_binding for the
        # source-facing receipt; every downstream store key uses the namespaced id.
        original_task_id = envelope.state.task_id
        if envelope.previous_audit_hash:
            envelope.state.task_id = _namespaced_migration_task_id(envelope.previous_audit_host_id, original_task_id)
        # A re-delivery of an already-admitted migration returns a receipt (no re-execution) instead of
        # a replay error, so a source whose acknowledgement was lost can still settle delivery. The
        # lookup happens before any nonce is touched. A stored receipt whose bindings differ means a
        # DIFFERENT envelope is squatting this task id -- reject it.
        if envelope.previous_audit_hash:
            existing_receipt = self.store.get_migration_receipt(envelope.state.task_id)
            if existing_receipt is not None:
                if (
                    existing_receipt.get("permit_nonce") != envelope.permit.nonce
                    or existing_receipt.get("envelope_digest") != incoming_migration_digest
                ):
                    raise SecurityError("a migration receipt already exists for this task under a different envelope")
                delivered_receipt = existing_receipt
                migration_memory = envelope.state.memory.get("migration") if isinstance(envelope.state.memory, dict) else None
                if isinstance(migration_memory, dict) and migration_memory.get("challenge_required"):
                    # Section 4 #5: REGENERATE the challenge attestation on redelivery, keeping the
                    # admission's checkpoint/audit bindings (task id, generation, audit head, accepted_at)
                    # unchanged. Keep-first storage would otherwise freeze the FIRST attester's evidence,
                    # so a first evidence the destination could not locally reject (e.g. signed by a key
                    # only the SOURCE knows it does not trust, or a source-only measurement policy) would
                    # be returned forever and the source could never settle -- an unrecoverable wedge. A
                    # corrected attester now supplies fresh evidence on the next delivery; if the attester
                    # is still bad this fails closed (nothing changes) and the row stays pending to retry.
                    delivered_receipt = self.signer.sign_migration_receipt(
                        migration_receipt_payload(
                            task_id=existing_receipt["task_id"],
                            source_host_id=existing_receipt["source_host_id"],
                            destination_host_id=self.host_id,
                            permit_nonce=existing_receipt["permit_nonce"],
                            envelope_digest=existing_receipt["envelope_digest"],
                            destination_checkpoint_generation=existing_receipt["destination_checkpoint_generation"],
                            destination_audit_head=existing_receipt["destination_audit_head"],
                            accepted_at=existing_receipt["accepted_at"],
                            destination_attestation=self._produce_challenge_evidence(envelope),
                        )
                    )
                stored_checkpoint = self.store.load_checkpoint(envelope.state.task_id)
                status = stored_checkpoint["status"] if stored_checkpoint else envelope.state.status
                result = stored_checkpoint.get("result") if stored_checkpoint else None
                return RunResult(status, envelope.state.task_id, result, stored_checkpoint or {}, (), migration_receipt=delivered_receipt)
        effective = active_policy.effective_permit(envelope.manifest, envelope.permit)
        self.attestation_policy.verify_execution(effective, self.host_id)
        provider = self.providers.get(envelope.manifest.provider)
        if provider is None:
            raise SecurityError(f"provider {envelope.manifest.provider!r} is not configured")
        provider_digest = getattr(provider, "component_digest", None)
        manifest_digest = envelope.manifest.component_digest
        if provider_digest is not None:
            if manifest_digest != provider_digest:
                raise SecurityError("Wasm component digest does not match the signed manifest")
        elif _is_content_digest(manifest_digest):
            # The signed manifest pins exact component bytes, but the selected
            # provider exposes no digest to verify against. Fail closed rather
            # than run an unverified component under a pinned manifest.
            raise SecurityError("signed manifest pins a component digest but the provider exposes none to verify")

        state = envelope.state
        # Finding EV-008: fresh-vs-resume and replay protection come from the durable
        # store's checkpoint generation, not from caller-supplied state.status. A task
        # with no stored checkpoint is a fresh run: it must carry generation 0 and it
        # consumes the permit nonce. A task with a stored checkpoint is a resume whose
        # admission is a compare-and-swap on that generation. This load only selects the
        # branch and whether to consume the nonce; the atomic CAS in the first _persist
        # is the actual authorization, so a stale or replayed resume is rejected there,
        # before any provider decision, tool call, approval, or migration.
        stored = self.store.load_checkpoint(state.task_id)
        if stored is None:
            if state.checkpoint_generation != 0:
                raise SecurityError("new task has invalid checkpoint generation")
            # Section 4 #7: the migration namespace is reserved. A fresh, NON-migration
            # admission (no previous_audit_hash) may not claim a reserved id -- otherwise a
            # local caller could pre-occupy a migrated task's key and deny a remote peer's
            # migration (the same squat, reached without any credential). A resume of a
            # resident migrated task takes the `else` branch (stored is not None), so this
            # never blocks a legitimate resume; a migration admission has previous_audit_hash
            # set and its id was namespaced above, so it is exempt here.
            if not envelope.previous_audit_hash and state.task_id.startswith(_MIGRATION_TASK_NAMESPACE):
                raise SecurityError("task id uses the reserved migration namespace")
            # Finding #3: budget accounting (max_steps / max_tool_calls) trusts the
            # step/tool_calls counters on the incoming state. A fresh admission with
            # caller-supplied NEGATIVE (or bool/float) counters -- e.g. tool_calls=-3
            # under a 1-call budget -- runs the tool several extra times before the
            # counter climbs to the limit. Reject non-nonnegative-int counters at the
            # door. Only their type/sign is constrained here, not their value: a fresh
            # admission legitimately carries POSITIVE counters and populated memory --
            # a suspended `awaiting_input` envelope resumes by presenting its own
            # signed wire state (its memory holds the injected approval), and a
            # migration arrives with the source run's counters. The exact values are
            # re-bound from the durable checkpoint on a local resume (below), which is
            # where a captured envelope could otherwise under-report consumed budget.
            self._require_nonnegative_counters(state)
            consume_nonce: str | None = envelope.permit.nonce
        else:
            # Local resume: the durable checkpoint is the sole authority on how much
            # budget has been spent. Rebind the counters from the store so a resume
            # envelope cannot under-report step/tool_calls to win extra budget.
            # memory/messages/result stay caller-visible on purpose -- an
            # awaiting_input resume injects approval input into state.memory before
            # re-running, and that wire state is already treated as untrusted
            # (approvals are consumed via a namespaced store nonce, not memory).
            state.step = int(stored["step"])
            state.tool_calls = int(stored["tool_calls"])
            consume_nonce = None
        state.status = "running"
        previous_hash, start_sequence, migration_anchor = self._audit_start(envelope, original_task_id)
        audit = AuditLog(previous_hash, start_sequence, self.host_id)
        accepted_details: dict[str, Any] = {
            "agent": envelope.manifest.agent_id,
            "host": self.host_id,
            "policy_version": active_policy.policy_version,
            "policy_hash": active_policy.policy_hash,
        }
        receipt_binding: dict[str, Any] | None = None
        if migration_anchor is not None:
            accepted_details["migration"] = migration_anchor
            # This is a migration admission: bind a destination receipt to the source
            # (previous_audit_host_id == permit.issuer, per finding #1), the delegated permit
            # nonce, and the exact sealed envelope, so the source can settle delivery.
            receipt_binding = {
                "source_host_id": envelope.previous_audit_host_id,
                "permit_nonce": envelope.permit.nonce,
                "envelope_digest": incoming_migration_digest,
                # Section 4 #7: the receipt is source-facing -- the source settles by the
                # ORIGINAL task id its outbox row is keyed on, so the receipt payload keeps
                # the original id even though the destination stores everything under the
                # source-namespaced id.
                "original_task_id": original_task_id,
            }
            # Section 4 #5 (challenge-passing protocol): if the source sealed a `challenge_required`
            # marker into this migration, the destination must attest to ITS OWN identity over the
            # source's fresh challenge (the delegated permit nonce) and return that evidence in the
            # receipt for the source to verify at settlement. This runs BEFORE the first _persist so a
            # missing or failing attester fails admission CLOSED with nothing stored -- a stored
            # evidence-less receipt would be handed back idempotently on every retry and strand the
            # outbox row forever, so fail-open here is unrecoverable, not merely degraded. A recovered
            # attester lets the source re-deliver the same envelope.
            migration_memory = envelope.state.memory.get("migration") if isinstance(envelope.state.memory, dict) else None
            if isinstance(migration_memory, dict) and migration_memory.get("challenge_required"):
                receipt_binding["destination_attestation"] = self._produce_challenge_evidence(envelope)
        audit.append("agent.accepted", accepted_details)
        persisted_events = self._persist(envelope, effective, state, audit, 0, consume_nonce=consume_nonce, receipt_binding=receipt_binding)
        tool_names = tuple(grant.name for grant in effective.grants)

        while state.step < effective.budget.max_steps:
            decision_started = time.monotonic()
            # Finding #4: hand the provider a host-projected copy of the state, so tool
            # outputs are reduced to each grant's output_projection before any provider
            # -- in-process or a remote adapter -- can read them. Projection is enforced
            # here, not trusted to the adapter. The provider only reads the state to
            # decide; the host mutates the real state via _apply_decision below.
            projected_state = project_state_for_provider(state, effective.grants)
            try:
                decision = provider.decide(projected_state, tool_names, effective.grants)
            finally:
                self.metrics.observe_duration("provider_decision_duration_seconds", time.monotonic() - decision_started)
            self.metrics.increment("provider.decisions")
            audit.append("provider.proposed", {"kind": decision.kind, "tool": decision.tool})
            tool_calls_before = state.tool_calls
            finished, migration = self._apply_decision(decision, state, effective, audit, envelope, active_policy)
            state.step += 1
            # Close the checkpoint's lineage at this host when the task terminates
            # (completed/failed) or migrates away, so it can never be resumed here
            # again (finding EV-008). An awaiting_input suspend stays open.
            closed = migration is not None or state.status in ("completed", "failed")
            # Terminalization guarantee (generalizes EV-010): an admitted task must
            # always reach a durable CLOSED checkpoint. A closed persist that would
            # exceed the output budget is collapsed to a bounded terminal tombstone
            # instead of raising out of run() and leaving the prior checkpoint
            # resumable. Covers a successful tool whose result overflowed AND a tool
            # exception, a hard kill, step-exhaustion, or an oversized completion whose
            # small terminal state tipped a near-ceiling checkpoint over. The killed
            # side-effecting-tool case is the dangerous one: a resumable pre-tool
            # checkpoint would let the provider re-propose the effect. await_input and
            # migrate are deliberately excluded -- an open or relocating checkpoint
            # cannot be shrunk without losing resume state, so those still raise (rare,
            # and neither carries a re-proposal risk here).
            tool_ran = state.tool_calls > tool_calls_before
            # Finding #1 (extended to migration): terminalize on any closed persist that
            # would overflow, not only tool-fail/kill/completion. A `migrate` closes the
            # source (status="ready", closed) because the working state has moved to the
            # migrated envelope -- already snapshotted in _apply_decision, so dropping
            # the source's now-redundant copy is correct. Without this an oversized
            # source-close raised out of run(), leaving the source checkpoint
            # status="running" and resumable WHILE a sealed migrated envelope existed:
            # the source could resume AND the destination run the same work (double
            # effect). await_input is still excluded (open, not closed).
            if not self._checkpoint_fits(effective, state) and (tool_ran or closed):
                persisted_events = self._terminalize_over_budget(
                    envelope, effective, state, audit, persisted_events, decision, tool_ran, migration
                )
                result = self._result(envelope, audit, migration)
                self._record_run_status(result.status)
                return result
            persisted_events = self._persist(envelope, effective, state, audit, persisted_events, closed=closed, migration=migration)
            if finished:
                result = self._result(envelope, audit, migration)
                self._record_run_status(result.status)
                return result

        state.status = "failed"
        state.result = {"error": "step budget exhausted"}
        audit.append("agent.failed", state.result)
        # Same terminalization guarantee as the loop: if the step-exhaustion tombstone
        # tips a near-ceiling checkpoint over the budget, bound it rather than raise.
        if self._checkpoint_fits(effective, state):
            self._persist(envelope, effective, state, audit, persisted_events, closed=True)
        else:
            self._terminalize_over_budget(envelope, effective, state, audit, persisted_events, None, False)
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
                raise SecurityError(
                    active_policy.explain_missing_grant(envelope.manifest, envelope.permit, decision.tool)
                )
            approval_result = self._approval_gate(active_policy, effective, state, decision, audit)
            if approval_result is not None:
                return approval_result
            try:
                tool_started = time.monotonic()
                try:
                    result = self.tools.invoke(effective, decision.tool, decision.arguments, effective.budget.max_output_bytes)
                finally:
                    self.metrics.observe_duration("tool_invocation_duration_seconds", time.monotonic() - tool_started)
            except ToolKilledError as error:
                # EV-002: the isolated tool was hard-killed at its deadline. The
                # kill stops any *new* side effect, but a call already in flight
                # (a payment POST mid-request) may have landed, so the audit
                # trail records the effect status as unknown rather than a clean
                # failure. This is a narrowed race, not an eliminated one.
                self.metrics.increment("tools.failed")
                state.status = "failed"
                state.result = {"error": "tool killed at deadline"}
                audit.append(
                    "tool.killed",
                    {
                        "tool": decision.tool,
                        "arguments": decision.arguments,
                        "error": str(error),
                        "effect_status": "unknown",
                    },
                )
                audit.append("agent.failed", state.result)
                return True, None
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
            if not self._is_encodable(result):
                # An in-process (thread-path) tool can return a live Python object --
                # a NaN, a reference cycle -- that no JSON transport would have caught.
                # Storing it would strand the run at the closing _persist; fail closed
                # here instead. Finding #7. (The side effect, if any, already happened;
                # the audit records the rejection.)
                self.metrics.increment("tools.failed")
                return self._fail_unserializable(state, audit, "tool", decision.tool)
            state.tool_calls += 1
            self.metrics.increment("tools.executed")
            # Record the raw tool result generically, keyed by the tool name, so a
            # provider can consult it on a later step. The enforcement core names
            # no specific tool -- the previous demo-shaped key derivation
            # (stripping ".search", and a hardcoded catalog.search branch) lived
            # here only to feed the bundled demo provider.
            state.memory.setdefault("tool_results", {})[decision.tool] = result
            state.messages.append({"role": "tool", "name": decision.tool, "content": result})
            audit.append("tool.executed", {"tool": decision.tool, "arguments": decision.arguments})
            return False, None
        if decision.kind == "complete":
            if not self._is_encodable(decision.content):
                return self._fail_unserializable(state, audit, "complete")
            state.status = "completed"
            state.result = decision.content
            audit.append("agent.completed", {"result": decision.content})
            return True, None
        if decision.kind == "await_input":
            if not self._is_encodable(decision.content):
                return self._fail_unserializable(state, audit, "await_input")
            state.status = "awaiting_input"
            state.result = decision.content
            audit.append("agent.awaiting_input", {"request": decision.content})
            return True, None
        if decision.kind == "migrate":
            if not decision.destination:
                raise SecurityError("migration proposal lacks a destination")
            # Finding EV-009: host policy is a ceiling over movement, not only tools.
            # The incoming permit's delegation_allowed alone is not enough; the host
            # must also allow migration and allowlist this destination.
            active_policy.authorize_migration(envelope.permit, decision.destination)
            destination_attestation = self._migration_attestation(decision)
            # Section 4 #5: bind the destination attestation to this migration's permit nonce (the same
            # nonce verify_execution binds to), so a valid attestation can't be replayed for another
            # migration. Enforcement is gated by attestation_policy.require_migration_nonce.
            self.attestation_policy.verify_migration(
                destination_attestation, decision.destination, self.host_id, expected_nonce=effective.nonce
            )
            state.status = "ready"
            state.memory["migration"] = {"from": self.host_id, "to": decision.destination}
            if destination_attestation is not None:
                state.memory["migration"]["attested_measurement"] = destination_attestation.measurement
            # Section 4 #5 (challenge-passing protocol): when the source requires a challenge, mint a
            # FRESH, source-chosen challenge and carry it as the delegated permit nonce (so it inherits
            # the sealed-envelope digest and the receipt permit_nonce binding for free). The destination
            # attests to itself over this challenge at admission and returns that evidence in the
            # receipt, which the source verifies at settlement -- pre-collected/stale evidence cannot
            # satisfy a challenge the source just minted. A `challenge_required` marker rides in the
            # sealed migration memory (set pre-seal, so it is digest-covered) so an honest destination
            # with no attester fails admission closed before persisting anything. This supersedes #64's
            # incoming-nonce reuse: in challenge mode the delegated permit carries NO source-provided
            # attestation, because that attestation (bound to the incoming nonce) would make the
            # destination's verify_execution raise against the fresh challenge nonce.
            if self.attestation_policy.require_migration_challenge:
                delegated_nonce = secrets.token_urlsafe(32)
                delegated_attestation = None
                state.memory["migration"]["challenge_required"] = True
            else:
                delegated_nonce = effective.nonce
                delegated_attestation = destination_attestation
            state.result = {"destination": decision.destination}
            audit.append("agent.migrating", state.result)
            delegated = type(effective)(
                issuer=self.host_id,
                subject=effective.subject,
                audience=decision.destination,
                expires_at=effective.expires_at,
                # Section 4 #5: the delegated permit nonce is either #64's reused incoming nonce (default)
                # or, in challenge mode, a fresh source-minted challenge (see above). Either way it is
                # unique per migration (so attestation replay across migrations is rejected) and unseen at
                # the destination, so first-admission is still nonce-guarded; the deliberate consequence is
                # that a task migrates to a given destination once (its nonce is consumed there).
                nonce=delegated_nonce,
                grants=effective.grants,
                budget=effective.budget,
                delegation_allowed=False,
                attestation=delegated_attestation,
            )
            previous_sequence = audit.events[-1]["sequence"] + 1
            # Finding EV-008: the destination host runs its own checkpoint lineage,
            # so the migrated envelope must start at generation 0 (a fresh task
            # there). Carrying the source generation would make the destination's
            # fresh-task admission reject it. Safe because the delegated permit's
            # nonce (this migration's incoming nonce, see above) has never been seen
            # at the destination, so the first admission there is nonce-guarded and
            # every later one is generation-guarded. The source task is closed by the
            # final _persist of this run (closed=True).
            # Section 4 #6 (payload confidentiality): reduce the migrated payload to the
            # destination's entitlement BEFORE sealing. `delegated.grants` == this
            # migration's grants, and the delegated permit's audience IS the destination,
            # so a tool's output_projection ceiling (already enforced on the provider
            # path) is applied here to what crosses the trust boundary -- otherwise the
            # source's full raw tool output would reach the destination host unprojected.
            # The source's OWN checkpoint keeps the full state; only this sealed copy is
            # projected. Order is project -> construct -> seal -> digest (the receipt
            # digest, section 4 #2, is taken on the sealed projected bytes at both ends).
            migrated_state = project_state_for_migration(replace(state, checkpoint_generation=0), delegated.grants)
            migrated = AgentEnvelope(
                envelope.manifest,
                delegated,
                migrated_state,
                previous_audit_hash=audit.head,
                previous_audit_sequence=previous_sequence,
                previous_audit_host_id=self.host_id,
                previous_audit_signature_key_id=self.signer.key_id,
                previous_audit_signature=self.signer.sign_audit_head(state.task_id, self.host_id, audit.head, previous_sequence),
            )
            self.signer.seal(migrated)
            return True, asdict(migrated)
        if not self._is_encodable(decision.content):
            return self._fail_unserializable(state, audit, "failed")
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
        # Durable, replay-proof one-time consumption of this approval. The
        # state.memory guard above lives in *wire* state, so a captured suspended
        # ("awaiting_input") envelope could replay the same approval to re-run a
        # side-effecting tool. Consume a namespaced token in the runtime store —
        # atomic on every backend and independent of the replayable wire state.
        try:
            with self.store.transaction() as approval_transaction:
                approval_transaction.consume_nonce(
                    f"approval:{state.task_id}:{token.approval_id}",
                    permit.subject,
                    permit.audience,
                    state.task_id,
                )
        except SecurityError:
            return self._approval_failure(state, audit, "approval.denied", "replayed")
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

    def _attest_migration_challenge(self, *, subject: str, audience: str, challenge: str) -> AttestationEvidence:
        # Section 4 #5 (finding 2): run the injected attester with a host-enforced timeout so a hung
        # attester cannot hold admission open. The worker is a daemon thread; on timeout admission fails
        # closed (nothing persisted) while the thread is abandoned (it cannot be force-killed, but it
        # never blocks admission and does not keep the process alive). `migration_attester_timeout=None`
        # is an explicit opt-out that calls the attester synchronously.
        attester = self.migration_attester
        if attester is None:  # guarded by the caller; re-checked so this helper is safe in isolation
            raise SecurityError("migration requires a challenge attestation but no attester is configured")
        timeout = self.migration_attester_timeout
        if timeout is None:
            return attester.attest(subject=subject, audience=audience, challenge=challenge)
        # Finding 2b: refuse (fail closed) rather than spawn a worker when the in-flight bound is
        # already saturated by earlier hung calls, so a flood of deliveries cannot grow threads without
        # limit. The permit is released by the worker itself (below), so a call that eventually returns
        # -- even past its timeout -- frees its slot; only truly-hung calls hold slots indefinitely.
        if not self._attester_slots.acquire(blocking=False):
            raise SecurityError("migration challenge attester capacity is exhausted")
        outcome: dict[str, Any] = {}

        def _invoke() -> None:
            try:
                outcome["value"] = attester.attest(subject=subject, audience=audience, challenge=challenge)
            except Exception as error:  # surfaced to the caller below (fail closed)
                outcome["error"] = error
            finally:
                self._attester_slots.release()

        worker = threading.Thread(target=_invoke, daemon=True)
        worker.start()
        worker.join(timeout)
        if worker.is_alive():
            raise SecurityError("migration challenge attestation timed out")
        if "error" in outcome:
            raise outcome["error"]
        return outcome["value"]

    def _produce_challenge_evidence(self, envelope: AgentEnvelope) -> dict[str, Any]:
        # Section 4 #5: obtain + locally validate the destination's challenge evidence, returning it as a
        # dict for the receipt. Shared by first admission and by redelivery regeneration so a corrected
        # attester recovers from a bad first evidence. Fails closed (nothing persisted) on a missing,
        # failing, or locally-detectably-invalid attester output.
        if self.migration_attester is None:
            raise SecurityError("migration requires a challenge attestation but no attester is configured")
        try:
            evidence = self._attest_migration_challenge(
                subject=self.host_id,
                audience=envelope.previous_audit_host_id,
                challenge=envelope.permit.nonce,
            )
        except SecurityError:
            raise
        except Exception as error:
            # A flaky/erroring attester fails admission CLOSED (nothing persisted) as a SecurityError,
            # not an uncaught error out of run() (the EV-010 defect class).
            raise SecurityError("migration challenge attestation failed") from error
        if not isinstance(evidence, AttestationEvidence):
            raise SecurityError("migration attester returned invalid evidence")
        # Validate the attester's OWN output before it can be persisted, so a defective attester's
        # evidence is never frozen into the keep-first receipt store (which the source would reject
        # forever). The source's verify_migration_challenge stays the trust authority at settlement.
        self.attestation_policy.check_local_migration_evidence(
            evidence,
            subject=self.host_id,
            audience=envelope.previous_audit_host_id,
            challenge=envelope.permit.nonce,
        )
        return asdict(evidence)

    def _result(self, envelope, audit, migration=None):
        # No size guard here: _result runs only right after a _persist that already
        # sized this exact state against the output budget, so a guard here could
        # never fire -- and if a future call path ever reached it, it would raise out
        # of run() (the very uncaught-raise EV-010 removed). Persist is the one place
        # the checkpoint ceiling is enforced.
        checkpoint = asdict(envelope.state)
        # Section 4 #2: surface the receipt this run issued as a migration destination (None for
        # ordinary runs and on the source side), read from the store so it reflects what committed.
        # `envelope.state.task_id` here is the storage key: source-namespaced for a migration
        # admission (rewritten above, section 4 #7), the unchanged original for a local run -- either
        # way it matches the key store_migration_receipt used, so this lookup is always consistent.
        receipt = self.store.get_migration_receipt(envelope.state.task_id)
        return RunResult(envelope.state.status, envelope.state.task_id, envelope.state.result, checkpoint, audit.events, migration, migration_receipt=receipt)

    def _checkpoint_fits(self, effective, state) -> bool:
        # Mirrors the ceiling _persist enforces (effective.budget = min(permit, host)),
        # so the loop can foresee a persist that would refuse the checkpoint and turn it
        # into an honest terminal event rather than an uncaught raise.
        return len(canonical_json(asdict(state))) <= effective.budget.max_output_bytes

    def _terminalize_over_budget(self, envelope, effective, state, audit, persisted_events, decision, tool_ran, migration=None):
        # Collapse an over-budget terminal state to a bounded closed tombstone that is
        # provably <= the admitted checkpoint, so the closed persist always lands. The
        # admitted checkpoint already held the goal plus this working state, so goal +
        # empty memory + empty messages + a null result cannot exceed it -- and the
        # audit chain, not the checkpoint, is the durable record of what happened.
        ceiling = effective.budget.max_output_bytes
        oversized = len(canonical_json(asdict(state)))
        state.memory = {}
        state.messages = []
        if tool_ran and state.status == "running":
            # A successful tool's result overflowed the checkpoint and no failure has
            # been recorded yet (EV-010). The tool ran, so the effect status is unknown,
            # exactly as for a hard kill: a resume must not re-propose it.
            state.status = "failed"
            state.result = {"error": "checkpoint exceeds output budget after tool execution"}
            audit.append(
                "output.refused",
                {
                    "tool": decision.tool if decision is not None else None,
                    "encoded_size": oversized,
                    "max_output_bytes": ceiling,
                    "effect_status": "unknown",
                },
            )
            audit.append("agent.failed", state.result)
        else:
            # The state is already terminal (a tool exception or hard kill, an oversized
            # completion, or step-exhaustion). Its cause -- including tool.killed with
            # effect_status "unknown" -- is already in the audit; keep the status and
            # the result when they fit, and record that the checkpoint was terminalized
            # under budget pressure with its working state dropped.
            audit.append(
                "checkpoint.terminalized",
                {
                    "status": state.status,
                    "encoded_size": oversized,
                    "max_output_bytes": ceiling,
                    "dropped": ["memory", "messages"],
                },
            )
        self.metrics.increment("checkpoints.terminalized")
        # Guarantee fit: with memory and messages emptied the checkpoint is the admitted
        # one minus its working state plus this result. If the result still tips it over
        # (a large kill reason or an oversized completion payload), drop it to null --
        # goal + empty memory + empty messages + null result is <= the admitted
        # checkpoint, which admitted under the ceiling with the goal already present.
        if len(canonical_json(asdict(state))) > ceiling:
            state.result = None
        # Pass `migration` through: an over-budget migration closes the source via
        # this branch (host.py comment above), so the outbox write must ride the same
        # close here too, or the exact data-loss hole reopens on the terminalize path.
        return self._persist(envelope, effective, state, audit, persisted_events, closed=True, migration=migration)

    def _record_run_status(self, status: str) -> None:
        self.metrics.increment(f"runs.{status}")
        if status == "failed":
            self.metrics.increment("runs.failed")

    @staticmethod
    def _is_encodable(value: Any) -> bool:
        # A value canonical_json cannot render -- a non-finite float (now that
        # allow_nan=False, finding #2), a reference cycle, or an unsupported type
        # (finding #7) -- must never be written into state: it would raise out of
        # _persist and leave the prior checkpoint status="running" and resumable,
        # exactly the failure class _terminalize_over_budget was built to eliminate.
        try:
            canonical_json(value)
        except (ValueError, TypeError, RecursionError):
            return False
        return True

    def _fail_unserializable(self, state, audit, source: str, tool: str | None = None) -> tuple[bool, None]:
        # Convert un-encodable provider/tool content into a clean, bounded terminal
        # failure at the boundary where it would enter state. state.result is a small
        # fixed dict that always encodes, so the closing _persist succeeds and the
        # task lands failed+closed instead of raising mid-run. Finding #7.
        self.metrics.increment("provider.rejected")
        state.status = "failed"
        state.result = {"error": "non-serializable content rejected", "source": source}
        details: dict[str, Any] = {"source": source, "reason": "content is not JSON-encodable"}
        if tool is not None:
            details["tool"] = tool
        audit.append("content.rejected", details)
        audit.append("agent.failed", state.result)
        return True, None

    @staticmethod
    def _require_nonnegative_counters(state) -> None:
        # A bool is an int subclass and a float slips past a bare `>= 0` while still
        # arithmetic-working through `+= 1`, so exclude both -- same root cause as the
        # numeric-limit fix (Finding #2), kept consistent here.
        for name in ("step", "tool_calls"):
            value = getattr(state, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise SecurityError(f"migrated state has invalid {name} counter")

    def _audit_start(self, envelope: AgentEnvelope, original_task_id: str) -> tuple[str, int, dict[str, Any] | None]:
        # `envelope.state.task_id` is the destination storage key (source-namespaced for a
        # migration, section 4 #7), so store lookups use it; `original_task_id` is the
        # source-signed id, used only to reconstruct the SOURCE's audit-head signature.
        stored = self.store.audit_head(envelope.state.task_id)
        if envelope.previous_audit_hash:
            if stored is not None and stored[0] != envelope.previous_audit_hash:
                raise SecurityError("envelope audit head does not match stored audit head")
            if stored is None:
                # A migration accepted onto a fresh local chain. The prior head is
                # signature-verified here but the local sequence restarts at 0, so
                # record the verified anchor (prior head hash + sequence + host) in
                # the first audit event. It lands inside the hashed event, making the
                # migration point durable and tamper-evident. Finding #3.
                self._verify_previous_audit_head(envelope, original_task_id)
                anchor = {
                    "previous_audit_hash": envelope.previous_audit_hash,
                    "previous_audit_sequence": envelope.previous_audit_sequence,
                    "previous_audit_host_id": envelope.previous_audit_host_id,
                }
                return envelope.previous_audit_hash, 0, anchor
            return envelope.previous_audit_hash, stored[1], None
        if stored is not None:
            return stored[0], stored[1], None
        return "", 0, None

    def _verify_previous_audit_head(self, envelope: AgentEnvelope, original_task_id: str) -> None:
        if (
            not envelope.previous_audit_host_id
            or not envelope.previous_audit_signature_key_id
            or not envelope.previous_audit_signature
            or envelope.previous_audit_sequence <= 0
        ):
            raise SecurityError("previous audit head signature is missing")
        # Finding S4-#1 (provenance splice): bind the anchor's host to the permit issuer.
        # verify_audit_head below already ties previous_audit_signature_key_id's identity.issuer
        # to previous_audit_host_id (via the payload host_id check on the Ed25519 path); without
        # this line an anchor validly signed by a DIFFERENT trusted, migration-capable host could
        # be spliced onto this permit and recorded as false lineage. Together this makes
        # previous_audit_host_id == permit.issuer == identity.issuer. NOTE: legacy
        # HmacEnvelopeSigner.verify_audit_head checks neither host_id nor usage, so on that
        # (demo/non-production) path this equality is the ONLY provenance binding.
        if envelope.previous_audit_host_id != envelope.permit.issuer:
            raise SecurityError("migration audit host does not match permit issuer")
        # A migration handoff is a distinct purpose from ordinary audit-head signing
        # (finding #5/#2): require the source key to carry the "migration" usage, so an
        # operator can scope a key to audit-only and it cannot mint migration handoffs.
        self.signer.verify_audit_head(
            envelope.previous_audit_signature_key_id,
            audit_head_payload(
                # The source signed its audit head over the ORIGINAL task id; the
                # destination reconstructs that exact payload here (section 4 #7).
                original_task_id,
                envelope.previous_audit_host_id,
                envelope.previous_audit_hash,
                envelope.previous_audit_sequence,
            ),
            envelope.previous_audit_signature,
            required_usage="migration",
        )

    def _persist(
        self,
        envelope: AgentEnvelope,
        effective,
        state,
        audit: AuditLog,
        persisted_events: int,
        consume_nonce: str | None = None,
        closed: bool = False,
        migration: dict[str, Any] | None = None,
        receipt_binding: dict[str, Any] | None = None,
    ) -> int:
        checkpoint = asdict(state)
        encoded_size = len(canonical_json(checkpoint))
        # The checkpoint is host-owned state, and a migration can transport it to a
        # peer host, so its size ceiling must be the host minimum (effective.budget =
        # min(permit, host)), not the visitor's permit alone -- otherwise a narrower
        # host output budget is silently widened to the permit's, against "budgets
        # take the minimum". The nonce below still binds to envelope.permit, the
        # incoming permit that minted it.
        if encoded_size > effective.budget.max_output_bytes:
            raise SecurityError("checkpoint exceeds output budget")
        # Finding EV-008: nonce consumption, audit append, and the checkpoint-generation
        # compare-and-swap all commit or roll back together. save_checkpoint raises on a
        # stale or closed generation, so a replayed resume is rejected here — before any
        # provider decision, tool call, approval, or migration — and the nonce it tried
        # to reuse and the audit it tried to append are rolled back with it. The store
        # owns the generation; state.checkpoint_generation is only the CAS assertion.
        with self.store.transaction() as transaction:
            if consume_nonce is not None:
                transaction.consume_nonce(consume_nonce, envelope.permit.subject, envelope.permit.audience, state.task_id)
            # Finding #3 (Option B): sign audit heads as v2 with an attested signed_at so
            # verification can be judged at signing time. One timestamp per persist; returned
            # alongside (key_id, signature) so the store persists it for later verification.
            head_signed_at = int(time.time())
            # Finding #2 (runtime enforcement): fail closed if the audit-signing key stopped
            # being usable while the process ran (e.g. it expired past its expires_at, which
            # no on-disk file change would catch). We are about to sign a new audit head; if
            # the key can no longer sign one we refuse rather than write evidence that is
            # invalid from birth. Raising inside the transaction rolls back the nonce, the
            # audit append, and the checkpoint together -- a closing _persist that trips this
            # leaves the task in its prior (resumable) state, to be completed after a restart
            # with a usable key. Legacy HMAC has no key lifecycle and exposes no registry.
            audit_trust = getattr(self.signer, "registry", None)
            if audit_trust is not None and hasattr(audit_trust, "audit_signing_reason"):
                signing_reason = audit_trust.audit_signing_reason(self.signer.key_id, now=head_signed_at)
                if signing_reason is not None:
                    raise SecurityError(
                        f"audit-signing key {self.signer.key_id!r} is no longer usable ({signing_reason}); "
                        "refusing to sign a new audit head"
                    )
            transaction.append_audit_events(
                state.task_id,
                self.host_id,
                audit.events[persisted_events:],
                lambda head_hash, sequence: (
                    self.signer.key_id,
                    self.signer.sign_audit_head(state.task_id, self.host_id, head_hash, sequence, signed_at=head_signed_at),
                    head_signed_at,
                ),
            )
            new_generation = transaction.save_checkpoint(state.task_id, state, state.checkpoint_generation, closed)
            # Section 4 #2: the destination issues a signed migration receipt in the SAME
            # transaction that commits the admission checkpoint, so a crash can never leave a
            # task admitted without a receipt to prove it. Bound to the just-committed
            # generation and audit head; keep-first, so a duplicate delivery returns this same
            # receipt instead of re-executing. accepted_at is destination-set (recorded, not gated).
            if receipt_binding is not None:
                receipt = self.signer.sign_migration_receipt(
                    migration_receipt_payload(
                        # Section 4 #7: the receipt payload carries the ORIGINAL task id (the
                        # source settles against its outbox row keyed on it); the receipt ROW
                        # below is stored under the source-namespaced state.task_id.
                        task_id=receipt_binding["original_task_id"],
                        source_host_id=receipt_binding["source_host_id"],
                        destination_host_id=self.host_id,
                        permit_nonce=receipt_binding["permit_nonce"],
                        envelope_digest=receipt_binding["envelope_digest"],
                        destination_checkpoint_generation=new_generation,
                        destination_audit_head=audit.head,
                        accepted_at=head_signed_at,
                        # Section 4 #5: present only for a challenge-required migration; part of the
                        # signed body, so the source can verify the destination's fresh evidence.
                        destination_attestation=receipt_binding.get("destination_attestation"),
                    )
                )
                transaction.store_migration_receipt(state.task_id, canonical_json(receipt).decode("utf-8"))
            # Section 1, finding #2: a migration's sealed destination envelope is
            # written to the outbox in the SAME transaction that closes the source
            # checkpoint. Either both commit or both roll back, so the source can
            # never be closed (un-resumable) while the migration is lost. The sealed
            # envelope was snapshotted in _apply_decision, so terminalizing the
            # source's own checkpoint here does not alter it. A dispatcher delivers it
            # later; duplicate delivery is safe (destination nonce/CAS reject replays).
            if migration is not None and closed:
                transaction.enqueue_migration(
                    state.task_id, migration["permit"]["audience"], canonical_json(migration).decode("utf-8")
                )
        state.checkpoint_generation = new_generation
        return len(audit.events)

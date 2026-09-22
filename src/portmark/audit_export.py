"""SIEM export of the audit chains (MCP/SIEM plan, PR 1; owner decision D3c).

The store keeps the full, authoritative audit record. The export is a PROJECTION of it: each event keeps
its authoritative `hash` and `previous`, but its `details` hold only the fields a projection policy
allows. Every other field becomes its name plus an HMAC-SHA-256 digest of the original value, under a
dedicated, rotatable keyring. The export only reads the store, needs no signing key, opens no network
connection, and trusts no clock. See OPERATIONS.md "Audit Export To A SIEM" and THREAT_MODEL.md TM-009.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import stat
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, BinaryIO

from ._durable_file import atomic_write_bytes
from .json_guard import StrictJSONError, strict_json_loads
from .security import canonical_json
from .storage import (
    DEFAULT_ADMIN_PAGE_SIZE,
    DEFAULT_EXPORT_EVENTS,
    AuditExportTask,
    AuditHeadVerifier,
    RuntimeStore,
    _audit_event_hash_matches,
    _verify_head_signature,
)

EXPORT_SCHEMA = "portmark.audit.export.v1"
CONTROL_SCHEMA = "portmark.audit.export.control.v1"
CURSOR_SCHEMA = "portmark.audit.export.cursor.v1"
POLICY_SCHEMA = "portmark.siem.projection.v1"
HMAC_PREFIX = "hmac-sha256:"
REDACTED = "[REDACTED]"
MIN_KEY_BYTES = 32
MAX_CONFIG_BYTES = 1 << 20
MAX_RECORD_BYTES = 16 << 20
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
# A watermark past any real chain: tells the store to return no events for a task that failed in this run.
_SKIP_TASK = 1 << 62

# Events whose details carry the tool's `arguments`; those follow the per-tool argument policy.
TOOL_EVENTS = frozenset({"tool.executed", "tool.failed", "tool.killed", "tool.refused", "tool.replayed"})

# The built-in projection: ONLY fields the host writes itself (tool names, host-written reasons and fixed
# error strings, effect status, policy identity, approval ids). Model output and user data -- the result of
# agent.completed, the request of agent.awaiting_input, agent.failed's `result`, a tool error's text, and
# the approval's PLAIN `arguments_hash` (guessable for small arguments) -- are never copied by default.
# An event kind not listed here exports keys and digests only.
BUILTIN_EVENT_FIELDS: dict[str, tuple[str, ...]] = {
    "agent.accepted": ("agent", "host", "policy_version", "policy_hash"),
    "agent.completed": (),
    "agent.awaiting_input": (),
    "agent.failed": ("error", "source"),
    "agent.migrating": ("destination",),
    "provider.proposed": ("kind", "tool"),
    "provider.failed": ("error",),
    "tool.executed": ("tool",),
    "tool.replayed": ("tool", "effect_id"),
    "tool.failed": ("tool", "effect_status", "isolation_profile"),
    "tool.killed": ("tool", "effect_status", "isolation_profile"),
    "tool.refused": ("tool", "reason"),
    "content.rejected": ("source", "reason", "tool", "effect_status", "isolation_profile"),
    "approval.requested": ("approval_required", "tool", "impact", "policy_version", "policy_hash"),
    "approval.approved": ("approval_id", "tool", "approved_by"),
    "approval.used": ("approval_id", "tool"),
    "approval.denied": ("reason",),
    "approval.expired": ("reason",),
}
BUILTIN_POLICY_DIGEST = "builtin:v1"


class ExportConfigError(ValueError):
    """A policy, keyring, cursor, or argument problem: nothing was exported (CLI exit 2)."""


def _reject_unknown(value: Mapping[str, Any], allowed: Iterable[str], label: str) -> None:
    unknown = set(value) - set(allowed)
    if unknown:
        raise ExportConfigError(f"{label} has unknown keys: {sorted(unknown)}")


def _string_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ExportConfigError(f"{label} must be a list of non-empty strings")
    if len(set(value)) != len(value):
        raise ExportConfigError(f"{label} lists a field twice")
    return tuple(value)


@dataclass(frozen=True)
class FieldRule:
    include: tuple[str, ...] = ()
    redact: tuple[str, ...] = ()
    hash_only: bool = False


def _field_rule(value: Any, label: str, allow_mode: bool) -> FieldRule:
    if not isinstance(value, dict):
        raise ExportConfigError(f"{label} must be an object")
    _reject_unknown(value, ("include", "redact", "mode") if allow_mode else ("include", "redact"), label)
    if "mode" in value:
        if value["mode"] != "hash_only":
            raise ExportConfigError(f"{label}.mode must be \"hash_only\"")
        if "include" in value or "redact" in value:
            raise ExportConfigError(f"{label}: mode hash_only cannot be combined with include or redact")
        return FieldRule(hash_only=True)
    include = _string_list(value.get("include", []), f"{label}.include")
    redact = _string_list(value.get("redact", []), f"{label}.redact")
    if set(include) & set(redact):
        raise ExportConfigError(f"{label}: a field cannot be both included and redacted")
    return FieldRule(include, redact)


@dataclass(frozen=True)
class ProjectionPolicy:
    """Which detail fields a SIEM record may copy. Default-deny for every event kind and every tool."""

    events: Mapping[str, FieldRule]
    tools: Mapping[str, FieldRule]
    digest: str

    @classmethod
    def builtin(cls) -> ProjectionPolicy:
        return cls({kind: FieldRule(fields) for kind, fields in BUILTIN_EVENT_FIELDS.items()}, {}, BUILTIN_POLICY_DIGEST)

    @classmethod
    def from_bytes(cls, raw: bytes) -> ProjectionPolicy:
        try:
            document = strict_json_loads(raw, max_bytes=MAX_CONFIG_BYTES)
        except StrictJSONError as error:
            raise ExportConfigError(f"projection policy is not valid JSON: {error}") from error
        if not isinstance(document, dict):
            raise ExportConfigError("projection policy must be a JSON object")
        _reject_unknown(document, ("schema", "events", "tool_arguments"), "projection policy")
        if document.get("schema") != POLICY_SCHEMA:
            raise ExportConfigError(f"projection policy schema must be {POLICY_SCHEMA!r}")
        events = {kind: FieldRule(fields) for kind, fields in BUILTIN_EVENT_FIELDS.items()}
        raw_events = document.get("events", {})
        if not isinstance(raw_events, dict):
            raise ExportConfigError("projection policy events must be an object")
        for kind, rule in raw_events.items():
            # A policy entry REPLACES the built-in entry for that event kind; it is not merged.
            events[kind] = _field_rule(rule, f"events[{kind!r}]", allow_mode=False)
        tools: dict[str, FieldRule] = {}
        arguments = document.get("tool_arguments", {})
        if not isinstance(arguments, dict):
            raise ExportConfigError("projection policy tool_arguments must be an object")
        _reject_unknown(arguments, ("default", "tools"), "tool_arguments")
        if arguments.get("default", "hash_only") != "hash_only":
            # Raw arguments are never the default: a tool the policy does not name exports a count + digest.
            raise ExportConfigError('tool_arguments.default must be "hash_only"')
        raw_tools = arguments.get("tools", {})
        if not isinstance(raw_tools, dict):
            raise ExportConfigError("tool_arguments.tools must be an object")
        for tool, rule in raw_tools.items():
            tools[tool] = _field_rule(rule, f"tool_arguments.tools[{tool!r}]", allow_mode=True)
        return cls(events, tools, "sha256:" + hashlib.sha256(raw).hexdigest())

    @classmethod
    def load(cls, path: str | None) -> ProjectionPolicy:
        if path is None:
            return cls.builtin()
        with open(path, "rb") as handle:
            return cls.from_bytes(handle.read(MAX_CONFIG_BYTES + 1))


@dataclass(frozen=True)
class Keyring:
    """The dedicated SIEM-export HMAC keys. Never an audit, envelope, or other runtime key."""

    active: str
    keys: Mapping[str, bytes] = field(repr=False)

    @classmethod
    def from_bytes(cls, raw: bytes) -> Keyring:
        try:
            document = strict_json_loads(raw, max_bytes=MAX_CONFIG_BYTES)
        except StrictJSONError as error:
            raise ExportConfigError("projection keyring is not valid JSON") from error
        if not isinstance(document, dict):
            raise ExportConfigError("projection keyring must be a JSON object")
        _reject_unknown(document, ("active", "keys"), "projection keyring")
        raw_keys = document.get("keys")
        if not isinstance(raw_keys, dict) or not raw_keys:
            raise ExportConfigError("projection keyring needs a non-empty keys object")
        keys: dict[str, bytes] = {}
        for key_id, encoded in raw_keys.items():
            if not _KEY_ID.match(key_id):
                raise ExportConfigError(f"keyring key id {key_id!r} must match {_KEY_ID.pattern}")
            try:
                key = base64.b64decode(encoded, validate=True) if isinstance(encoded, str) else b""
            except ValueError:
                key = b""
            if len(key) < MIN_KEY_BYTES:
                # Never echo key material in an error.
                raise ExportConfigError(f"keyring key {key_id!r} must be base64 of at least {MIN_KEY_BYTES} bytes")
            keys[key_id] = key
        active = document.get("active")
        if not isinstance(active, str) or active not in keys:
            raise ExportConfigError("keyring `active` must name one of its keys")
        return cls(active, keys)

    @classmethod
    def load(cls, path: str) -> Keyring:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as error:
            raise ExportConfigError(f"cannot open projection keyring {path!r}: {error.strerror}") from error
        try:
            status = os.fstat(fd)
            if not stat.S_ISREG(status.st_mode):
                raise ExportConfigError("projection keyring must be a regular file")
            if os.name == "posix" and status.st_mode & 0o077:
                raise ExportConfigError("projection keyring must not be readable by group or others (chmod 600)")
            with os.fdopen(os.dup(fd), "rb") as handle:
                raw = handle.read(MAX_CONFIG_BYTES + 1)
        finally:
            os.close(fd)
        return cls.from_bytes(raw)

    def digest(self, value: Any, key_id: str | None = None) -> str:
        key = self.keys[key_id or self.active]
        return HMAC_PREFIX + hmac.new(key, canonical_json(value), hashlib.sha256).hexdigest()


class Projector:
    """Turns one authoritative event's details into the SIEM-safe `details` and `omitted` maps."""

    def __init__(self, policy: ProjectionPolicy, keyring: Keyring | None) -> None:
        self.policy = policy
        self.keyring = keyring

    def _digest(self, value: Any, key_id: str | None) -> str:
        if self.keyring is None:
            raise ExportConfigError("a projection keyring is required: this record has fields that must be digested")
        return self.keyring.digest(value, key_id)

    def project(self, event: str, details: Any, key_id: str | None = None) -> tuple[dict[str, Any], dict[str, str]]:
        if not isinstance(details, dict):
            return {}, {"details": self._digest(details, key_id)}
        rule = self.policy.events.get(event, FieldRule())
        projected: dict[str, Any] = {}
        omitted: dict[str, str] = {}
        for name in sorted(details):
            value = details[name]
            if name == "arguments" and event in TOOL_EVENTS:
                projected.update(self._project_arguments(details.get("tool"), value, key_id))
            elif name in rule.include:
                projected[name] = value
            elif name in rule.redact:
                projected[name] = REDACTED
                omitted[name] = self._digest(value, key_id)
            else:
                omitted[name] = self._digest(value, key_id)
        return projected, omitted

    def _project_arguments(self, tool: Any, arguments: Any, key_id: str | None) -> dict[str, Any]:
        # arguments_hmac covers the COMPLETE, ORIGINAL arguments, never the projected copy.
        out: dict[str, Any] = {"arguments_hmac": self._digest(arguments, key_id)}
        if not isinstance(arguments, dict):
            return out
        rule = self.policy.tools.get(tool) if isinstance(tool, str) else None
        if rule is None or rule.hash_only:
            # Argument NAMES are chosen by the model as much as the values are, so a tool the policy does not
            # name (or names as hash_only) exports only how many there were (Codex review R1).
            out["argument_count"] = len(arguments)
            return out
        out["argument_keys"] = sorted(arguments)
        shown: dict[str, Any] = {}
        for name in sorted(arguments):
            if name in rule.include:
                shown[name] = arguments[name]
            elif name in rule.redact:
                shown[name] = REDACTED
        out["arguments"] = shown
        return out


def event_record(task_id: str, row: Mapping[str, Any], details: Any, projector: Projector, key_id: str | None = None) -> dict[str, Any]:
    projected, omitted = projector.project(row["event"], details, key_id)
    record: dict[str, Any] = {
        "schema": EXPORT_SCHEMA,
        "kind": "event",
        "key": f"{task_id}:{row['sequence']}:{row['hash']}",
        "task_id": task_id,
        "host_id": row["host_id"],
        "sequence": row["sequence"],
        "event": row["event"],
        "previous": row["previous"],
        "hash": row["hash"],
        "created_at": row["created_at"],
        "details": projected,
        "omitted": omitted,
        "policy_digest": projector.policy.digest,
    }
    if projector.keyring is not None:
        record["hmac_key_id"] = key_id or projector.keyring.active
    return record


def head_record(task_id: str, head: Mapping[str, Any], signature_status: str) -> dict[str, Any]:
    return {
        "schema": EXPORT_SCHEMA,
        "kind": "head",
        "key": f"{task_id}:head:{head['sequence']}:{head['head_hash']}",
        "task_id": task_id,
        "host_id": head["host_id"],
        "sequence": int(head["sequence"]),
        "head_hash": head["head_hash"],
        "signature_key_id": head["signature_key_id"],
        "signature": head["signature"],
        "signed_at": head["signed_at"],
        "signature_status": signature_status,
    }


def control_record(task_id: str, sequence: int, reason: str) -> dict[str, Any]:
    # An EXPORTER diagnostic, not a store event: it has no hash and claims no store provenance.
    return {"schema": CONTROL_SCHEMA, "kind": "integrity_failure", "task_id": task_id, "sequence": sequence, "reason": reason}


def encode_record(record: Mapping[str, Any]) -> bytes:
    return canonical_json(record) + b"\n"


class ExportCursor:
    """Per-task watermark: the next sequence to export and the hash of the last exported event.

    Keyed by task, never by time: a writer's clock or a late commit cannot make the export skip a row.
    debt: the whole map is rewritten on every save; ceiling about 1M tasks (tens of MB per save); upgrade
    to a store-side table when a store holds more than 100k tasks."""

    def __init__(self, path: str | None, tasks: dict[str, tuple[int, str]] | None = None) -> None:
        self.path = path
        self.tasks: dict[str, tuple[int, str]] = dict(tasks or {})

    @classmethod
    def load(cls, path: str) -> ExportCursor:
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except FileNotFoundError:
            return cls(path)
        try:
            document = strict_json_loads(raw)
        except StrictJSONError as error:
            raise ExportConfigError("export cursor is not valid JSON; refusing to guess where the export stopped") from error
        if not isinstance(document, dict) or document.get("schema") != CURSOR_SCHEMA or not isinstance(document.get("tasks"), dict):
            raise ExportConfigError(f"export cursor must be a {CURSOR_SCHEMA} object")
        _reject_unknown(document, ("schema", "tasks"), "export cursor")
        tasks: dict[str, tuple[int, str]] = {}
        for task_id, entry in document["tasks"].items():
            if (
                not isinstance(entry, dict)
                or set(entry) != {"next", "hash"}
                or isinstance(entry["next"], bool)
                or not isinstance(entry["next"], int)
                or entry["next"] < 1
                or not isinstance(entry["hash"], str)
            ):
                raise ExportConfigError(f"export cursor entry for {task_id!r} is malformed")
            tasks[task_id] = (entry["next"], entry["hash"])
        return cls(path, tasks)

    def save(self) -> None:
        if self.path is None:
            return
        document = {"schema": CURSOR_SCHEMA, "tasks": {task: {"next": n, "hash": h} for task, (n, h) in sorted(self.tasks.items())}}
        atomic_write_bytes(self.path, canonical_json(document) + b"\n", mode=0o600)


@dataclass
class ExportReport:
    events: int = 0
    heads: int = 0
    tasks: int = 0
    integrity_failures: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.integrity_failures


def _check_event(task_id: str, expected: int, previous: str | None, row: Mapping[str, Any]) -> tuple[Any, str | None]:
    """(parsed details, None) when the stored row is intact at this position, else (None, reason)."""
    if row["sequence"] != expected:
        return None, f"expected sequence {expected}, found {row['sequence']}"
    if previous is not None and row["previous"] != previous:
        return None, "previous hash does not link to the last exported event"
    try:
        details = strict_json_loads(row["details_json"])
    except (StrictJSONError, TypeError):
        return None, "stored details are not valid JSON"
    if not _audit_event_hash_matches(row["sequence"], row["event"], details, row["previous"], row["host_id"], row["hash"]):
        return None, "event hash does not match its stored content"
    return details, None


def run_export(
    store: RuntimeStore,
    cursor: ExportCursor,
    projector: Projector,
    out: BinaryIO,
    *,
    verifier: AuditHeadVerifier | None = None,
    durable: bool = True,
    page_size: int = DEFAULT_ADMIN_PAGE_SIZE,
    max_events: int = DEFAULT_EXPORT_EVENTS,
    _after_write: Callable[[], None] | None = None,
) -> ExportReport:
    """Export everything past the cursor. Per page: write the records, flush (+ fsync when `durable`), and
    only THEN save the cursor -- a crash between the two repeats records, it never loses one.

    debt: every run reads every task head (no clock is trusted, so there is no "changed since" filter);
    ceiling about 1M heads per run; upgrade to a store-side change sequence when one run takes longer than
    the export interval."""
    report = ExportReport()
    failed: set[str] = set()
    after: str | None = None
    while True:
        watermarks = {task: position for task, (position, _) in cursor.tasks.items()}
        watermarks.update({task: _SKIP_TASK for task in failed})
        page = store.audit_export_page(after, watermarks, page_size, max_events)
        lines: list[bytes] = []
        for task in page.tasks:
            if task.task_id in failed:
                continue
            reason = _export_task(task, cursor, projector, verifier, lines, report)
            if reason is not None:
                failed.add(task.task_id)
                failure = control_record(task.task_id, cursor.tasks.get(task.task_id, (0, ""))[0], reason)
                report.integrity_failures.append(failure)
                lines.append(encode_record(failure))
        if lines:
            out.write(b"".join(lines))
            out.flush()
            if durable:
                os.fsync(out.fileno())
        if _after_write is not None:
            _after_write()
        cursor.save()
        if page.done:
            return report
        after = page.next_after


def _export_task(
    task: AuditExportTask,
    cursor: ExportCursor,
    projector: Projector,
    verifier: AuditHeadVerifier | None,
    lines: list[bytes],
    report: ExportReport,
) -> str | None:
    task_id = task.task_id
    position, last_hash = cursor.tasks.get(task_id, (0, None))
    head_sequence = int(task.head["sequence"])
    if head_sequence < position:
        return f"stored head (sequence {head_sequence}) is behind events already exported (next {position}): rollback or rewrite"
    if head_sequence == position:
        if last_hash is not None and task.head["head_hash"] != last_hash:
            return "stored head hash differs from the last exported event: history was rewritten"
        return None
    previous = last_hash
    for row in task.events:
        details, reason = _check_event(task_id, position, previous, row)
        if reason is not None:
            return reason
        lines.append(encode_record(event_record(task_id, row, details, projector)))
        report.events += 1
        position, previous = position + 1, row["hash"]
        cursor.tasks[task_id] = (position, row["hash"])
    if task.truncated:
        return None
    if position != head_sequence or previous != task.head["head_hash"]:
        return "stored head does not match the stored events (missing or extra rows)"
    status = "unchecked" if verifier is None else _verify_head_signature(verifier, task_id, task.head).head_status or "invalid"
    lines.append(encode_record(head_record(task_id, task.head, status)))
    report.heads += 1
    report.tasks += 1
    return None


# -- verification of an exported file ---------------------------------------------------------------------


@dataclass
class VerifyReport:
    status: str = "valid"  # valid | invalid | unverifiable
    reasons: list[str] = field(default_factory=list)
    tasks: int = 0
    events: int = 0
    unanchored_events: int = 0
    level: int = 1

    def fail(self, reason: str) -> None:
        self.status = "invalid"
        self.reasons.append(reason)

    def unverifiable(self, reason: str) -> None:
        if self.status == "valid":
            self.status = "unverifiable"
        self.reasons.append(reason)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "level": self.level,
            "tasks": self.tasks,
            "events": self.events,
            "unanchored_events": self.unanchored_events,
            "reasons": self.reasons[:50],
        }


def read_export(lines: Iterable[bytes], report: VerifyReport) -> dict[str, dict[str, Any]]:
    """Parse an exported file into unique records by key. A repeated key must be byte-identical."""
    records: dict[str, dict[str, Any]] = {}
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = strict_json_loads(line, max_bytes=MAX_RECORD_BYTES)
        except StrictJSONError:
            report.fail(f"line {number} is not valid JSON")
            continue
        if not isinstance(record, dict):
            report.fail(f"line {number} is not a JSON object")
            continue
        if record.get("schema") == CONTROL_SCHEMA:
            report.fail(f"export-control record: task {record.get('task_id')!r}: {record.get('reason')}")
            continue
        key = record.get("key")
        if record.get("schema") != EXPORT_SCHEMA or record.get("kind") not in ("event", "head") or not isinstance(key, str):
            report.fail(f"line {number} is not a {EXPORT_SCHEMA} event or head record")
            continue
        if key in records:
            if records[key] != record:
                report.fail(f"record {key} appears twice with different content")
            continue
        records[key] = record
    return records


def verify_records(records: Mapping[str, dict[str, Any]], verifier: AuditHeadVerifier | None, report: VerifyReport) -> None:
    """Level 1: per task, links without a gap from sequence 0, and every head matches its event and is signed."""
    events: dict[str, dict[int, dict[str, Any]]] = {}
    heads: dict[str, list[dict[str, Any]]] = {}
    for record in records.values():
        task_id = record.get("task_id")
        sequence = record.get("sequence")
        if not isinstance(task_id, str) or isinstance(sequence, bool) or not isinstance(sequence, int):
            report.fail(f"record {record.get('key')} has no valid task_id or sequence")
            continue
        if record["kind"] == "event":
            if sequence in events.setdefault(task_id, {}):
                report.fail(f"task {task_id!r} has two different events at sequence {sequence}")
                continue
            events[task_id][sequence] = record
        else:
            heads.setdefault(task_id, []).append(record)
    for task_id in sorted(set(events) | set(heads)):
        report.tasks += 1
        chain = events.get(task_id, {})
        report.events += len(chain)
        count = len(chain)
        if sorted(chain) != list(range(count)):
            report.fail(f"task {task_id!r}: exported events are not contiguous from sequence 0")
            continue
        for sequence in range(1, count):
            if chain[sequence].get("previous") != chain[sequence - 1].get("hash"):
                report.fail(f"task {task_id!r}: event {sequence} does not link to event {sequence - 1}")
                break
        anchored = 0
        for head in heads.get(task_id, []):
            head_sequence = head["sequence"]
            if not 1 <= head_sequence <= count or chain[head_sequence - 1].get("hash") != head.get("head_hash"):
                report.fail(f"task {task_id!r}: head at sequence {head_sequence} does not match the exported events")
                continue
            anchored = max(anchored, head_sequence)
            if verifier is None:
                report.unverifiable("no trust registry: head signatures were not checked")
                continue
            result = _verify_head_signature(verifier, task_id, head)
            if not result.valid:
                report.fail(f"task {task_id!r}: head at sequence {head_sequence}: {result.reason}")
        unanchored = count - anchored
        report.unanchored_events += unanchored
        if unanchored:
            # Not proven: a run still in progress leaves these until its head record lands, but so does a file
            # whose head records were removed, or a forged task that never had one (Codex review R1).
            report.unverifiable(f"task {task_id!r}: {unanchored} exported events have no matching signed head")
    if report.tasks == 0:
        report.unverifiable("the file holds no audit records")


def verify_against_store(
    records: Mapping[str, dict[str, Any]],
    store: RuntimeStore,
    policy: ProjectionPolicy,
    keyring: Keyring,
    report: VerifyReport,
) -> None:
    """Level 2: recompute each exported event from the authoritative store and require an exact match.

    debt: reads every stored event of the exported tasks into memory; ceiling is the store's audit size in
    RAM; upgrade to a per-task streaming read when a verification run exceeds the host's memory budget."""
    report.level = 2
    projector = Projector(policy, keyring)
    wanted = {record["task_id"] for record in records.values() if record["kind"] == "event"}
    stored: dict[str, dict[str, Any]] = {}
    watermarks: dict[str, int] = {}
    after: str | None = None
    while True:
        # The store's own paging continues a task that one page's event budget cut short: the watermark
        # advances and `next_after` stays before that task, so no order between task ids is assumed here.
        page = store.audit_export_page(after, watermarks, DEFAULT_ADMIN_PAGE_SIZE, DEFAULT_EXPORT_EVENTS)
        for task in page.tasks:
            if task.task_id not in wanted:
                watermarks[task.task_id] = _SKIP_TASK
                continue
            for row in task.events:
                stored[f"{task.task_id}:{row['sequence']}:{row['hash']}"] = {"task_id": task.task_id, **row}
            if task.events:
                watermarks[task.task_id] = task.events[-1]["sequence"] + 1
        if page.done:
            break
        after = page.next_after
    for key, record in sorted(records.items()):
        if record["kind"] != "event":
            continue
        row = stored.get(key)
        if row is None:
            report.fail(f"record {key} is not in the store")
            continue
        details, reason = _check_event(record["task_id"], row["sequence"], None, row)
        if reason is not None:
            report.fail(f"record {key}: stored event is damaged: {reason}")
            continue
        if record.get("policy_digest") != policy.digest:
            report.unverifiable(f"record {key} was produced by a different projection policy ({record.get('policy_digest')})")
            continue
        key_id = record.get("hmac_key_id")
        if key_id not in keyring.keys:
            report.unverifiable(f"record {key} names key {key_id!r}, which is not in the keyring")
            continue
        if event_record(record["task_id"], row, details, projector, key_id) != record:
            report.fail(f"record {key} does not match the store: its projected values were changed")

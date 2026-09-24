"""The OCSF projection of an exported audit record (MCP/SIEM plan, deferred from PR 1).

An exported record is already a policy-controlled projection of the authoritative audit chain. This module
reshapes that record into the Open Cybersecurity Schema Framework so a SIEM can read it without a custom
parser, and reshapes it BACK so `verify-export` keeps working on the same file.

Read from the live schema on 2026-09-23: OCSF **1.9.0** (`https://schema.ocsf.io/api/version`), class
`api_activity`, `class_uid` 6003, `category_uid` 6 "Application Activity". Two facts here were checked at
the source rather than assumed, because both are easy to get plausibly wrong: `time` is a UTC epoch in
MILLISECONDS ("This must be a UTC epoch value in milliseconds"), while Portmark stores epoch SECONDS; and
`type_uid` is not a constant but "class_uid * 100 + activity_id".

**The round trip is exact.** Level-2 verification recomputes an event from the store and compares the WHOLE
record for equality, so `from_ocsf(to_ocsf(record)) == record` must hold for every record. Nothing is
summarised, rounded or re-ordered on the way through: the native record travels intact under `unmapped`, and
the projected details travel once, in `api.request.data`, where a SIEM expects a request payload.

**Why `attestation_list` is deliberately EMPTY.** OCSF's `record_integrity` profile looks like a home for
Portmark's hash chain, and its `chain_uid` / `prev_event` / `fingerprint` fields line up almost exactly. They
are not used, because OCSF defines that fingerprint as covering "this event's canonical serialization" -- the
OCSF record. Portmark's hash covers the ORIGINAL audit event, before projection. Putting one where the other
belongs would state something false, and a verifier following the specification would recompute, find a
mismatch, and read an honest export as tampered with. The chain therefore travels under `unmapped`, which is
what OCSF sanctions for a mapper's source-specific data.

**Why no `ai_operation` profile.** It is the schema's mechanism for an autonomous agent, and Portmark's events
are about one. But its `ai_agent` object wants an agent identity that is not on every record -- the projection
policy decides what survives, and most kinds carry no agent field. Emitting the profile with nothing in it, or
inventing an identity, would both be worse than leaving it out. See MCP-free docs: OPERATIONS.md.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

OCSF_VERSION = "1.9.0"
CLASS_UID = 6003
CLASS_NAME = "API Activity"
CATEGORY_UID = 6
CATEGORY_NAME = "Application Activity"
# A tool call is not one of the CRUD activities this class enumerates (1..4), so it is "Other". The schema
# is explicit about what that obliges: when `activity_id` is 99, `activity_name` must carry the
# source-specific label -- here, Portmark's own event kind.
ACTIVITY_OTHER = 99
TYPE_UID = CLASS_UID * 100 + ACTIVITY_OTHER
PRODUCT_NAME = "Portmark"
SERVICE_NAME = "portmark"
LOG_NAME = "portmark.audit"
# The single key under `unmapped` that carries the native record. One namespaced key, so nothing Portmark
# adds later can collide with another mapper's fields in the same file.
UNMAPPED_KEY = "portmark"
HEAD_ACTIVITY = "audit.head"
CONTROL_ACTIVITY = "audit.export.integrity_failure"

SEVERITY_INFORMATIONAL, SEVERITY_MEDIUM, SEVERITY_HIGH = 1, 3, 4
SEVERITY_NAMES = {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Fatal"}
STATUS_UNKNOWN, STATUS_SUCCESS, STATUS_FAILURE = 0, 1, 2
STATUS_NAMES = {0: "Unknown", 1: "Success", 2: "Failure"}

# The outcome of each audit event kind, stated once. An event kind that is neither an outcome nor a failure
# is `Unknown` rather than `Success`: `agent.awaiting_input` and `agent.migrating` report a state, not a
# result, and calling them successes would tell a SIEM something Portmark never claimed.
EVENT_STATUS: dict[str, int] = {
    "agent.accepted": STATUS_SUCCESS,
    "agent.completed": STATUS_SUCCESS,
    "agent.awaiting_input": STATUS_UNKNOWN,
    "agent.migrating": STATUS_UNKNOWN,
    "agent.failed": STATUS_FAILURE,
    "provider.proposed": STATUS_SUCCESS,
    "provider.failed": STATUS_FAILURE,
    "tool.executed": STATUS_SUCCESS,
    "tool.replayed": STATUS_SUCCESS,
    "tool.failed": STATUS_FAILURE,
    "tool.killed": STATUS_FAILURE,
    "tool.refused": STATUS_FAILURE,
    "content.rejected": STATUS_FAILURE,
    "approval.requested": STATUS_SUCCESS,
    "approval.approved": STATUS_SUCCESS,
    "approval.used": STATUS_SUCCESS,
    "approval.denied": STATUS_FAILURE,
    "approval.expired": STATUS_FAILURE,
}
# How loudly a SIEM should hear it. A refusal is the gate working as designed, so it is worth attention but
# is not an error; a failure, a kill or a rejected result means something went wrong, or an effect is unknown.
EVENT_SEVERITY: dict[str, int] = {
    "agent.failed": SEVERITY_HIGH,
    "provider.failed": SEVERITY_HIGH,
    "tool.failed": SEVERITY_HIGH,
    "tool.killed": SEVERITY_HIGH,
    "content.rejected": SEVERITY_HIGH,
    "tool.refused": SEVERITY_MEDIUM,
    "approval.denied": SEVERITY_MEDIUM,
    "approval.expired": SEVERITY_MEDIUM,
}

_NO_DETAILS = object()


def product_version() -> str:
    """Portmark's own version for `metadata.product.version`, or "" when it cannot be determined.

    Read from the installed distribution rather than written here, so it cannot drift from pyproject.toml.
    An empty answer is left out of the record entirely: `version` is only recommended, and an empty string
    would be a claim about the producer that is not true."""
    try:
        from importlib.metadata import version  # noqa: PLC0415 - only an OCSF export asks

        return version("portmark")
    except Exception:  # noqa: BLE001 - not installed as a distribution; the record simply omits the version
        return ""


def is_ocsf(record: Mapping[str, Any]) -> bool:
    """Whether this parsed line is an OCSF record at all. Read before trusting anything else in it."""
    return record.get("class_uid") == CLASS_UID


def to_ocsf(record: Mapping[str, Any], *, product_version: str, now_seconds: int) -> dict[str, Any]:
    """One exported record, reshaped for a SIEM. `now_seconds` times a record that carries no time of its own.

    Only an export-control record needs `now_seconds`: it is the EXPORTER's own diagnostic, so the moment it
    was noticed is the only honest time it has."""
    native = dict(record)
    details = native.pop("details", _NO_DETAILS)
    kind = native.get("kind")
    activity, seconds = _activity_and_time(native, kind, now_seconds)
    status_id = _status_of(kind, native.get("event"))
    severity_id = _severity_of(kind, native.get("event"))
    host_id = native.get("host_id") or ""
    key = native.get("key")

    api: dict[str, Any] = {"operation": activity, "service": {"name": SERVICE_NAME}}
    if isinstance(key, str):
        # `request.uid` is required inside an api request object, and the export key already IS a unique,
        # stable identifier for this record. A record without one carries no request at all.
        request: dict[str, Any] = {"uid": key}
        if details is not _NO_DETAILS:
            request["data"] = details
        api["request"] = request

    product: dict[str, Any] = {"name": PRODUCT_NAME, "vendor_name": PRODUCT_NAME}
    if product_version:
        product["version"] = product_version
    metadata: dict[str, Any] = {"version": OCSF_VERSION, "product": product, "log_name": LOG_NAME}
    if isinstance(key, str):
        metadata["uid"] = key

    return {
        "activity_id": ACTIVITY_OTHER,
        "activity_name": activity,
        "api": api,
        # `at_least_one` on an actor is satisfied by `application`; the application acting here is the
        # Portmark host itself, identified by the same host id the audit record carries.
        "actor": {"application": {"name": SERVICE_NAME, "uid": host_id}},
        "category_name": CATEGORY_NAME,
        "category_uid": CATEGORY_UID,
        "class_name": CLASS_NAME,
        "class_uid": CLASS_UID,
        "metadata": metadata,
        "severity": SEVERITY_NAMES[severity_id],
        "severity_id": severity_id,
        # Required, and an audit event has no network peer. `at_least_one` on a network endpoint accepts a
        # name and a uid, so it names the host that produced the record rather than inventing an address.
        "src_endpoint": {"name": SERVICE_NAME, "uid": host_id},
        "status": STATUS_NAMES[status_id],
        "status_id": status_id,
        "time": seconds * 1000,  # Portmark stores epoch SECONDS; OCSF requires milliseconds.
        "type_name": f"{CLASS_NAME}: {activity}",
        "type_uid": TYPE_UID,
        "unmapped": {UNMAPPED_KEY: native},
    }


def from_ocsf(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """The native export record this OCSF record was built from, or None if it did not come from Portmark.

    The inverse must be EXACT: level-2 verification recomputes a record from the store and compares the whole
    thing for equality, so anything lost here reads as a record that was altered after export."""
    unmapped = record.get("unmapped")
    if not isinstance(unmapped, Mapping):
        return None
    native = unmapped.get(UNMAPPED_KEY)
    if not isinstance(native, Mapping):
        return None
    rebuilt = dict(native)
    api = record.get("api")
    request = api.get("request") if isinstance(api, Mapping) else None
    if isinstance(request, Mapping) and "data" in request:
        rebuilt["details"] = request["data"]
    return rebuilt


def _activity_and_time(native: Mapping[str, Any], kind: Any, now_seconds: int) -> tuple[str, int]:
    if kind == "event":
        event = native.get("event")
        return (event if isinstance(event, str) else "audit.event"), _seconds(native.get("created_at"), now_seconds)
    if kind == "head":
        # A v1 head carries no signing time; the export run's own clock is then the only one there is.
        return HEAD_ACTIVITY, _seconds(native.get("signed_at"), now_seconds)
    return CONTROL_ACTIVITY, now_seconds


def _seconds(value: Any, fallback: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else fallback


def _status_of(kind: Any, event: Any) -> int:
    if kind == "head":
        return STATUS_SUCCESS
    if kind != "event":
        return STATUS_FAILURE  # an export-control record exists only to report an integrity failure
    return EVENT_STATUS.get(event, STATUS_UNKNOWN) if isinstance(event, str) else STATUS_UNKNOWN


def _severity_of(kind: Any, event: Any) -> int:
    if kind == "event" and isinstance(event, str):
        return EVENT_SEVERITY.get(event, SEVERITY_INFORMATIONAL)
    return SEVERITY_INFORMATIONAL if kind in ("event", "head") else SEVERITY_HIGH

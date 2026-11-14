"""Obligation ledger: typed records for what an analysis still owes evidence.

An analysis that names its limits (:mod:`codevanta.core.unknowns`) also owes a
decision about each limit: which authority may close it, at what confidence,
in which environment. The obligation ledger is the typed home for those debts.
One :class:`ObligationRecord` per obligation (``question``, plus the required
``authority`` / ``confidence`` / ``environment`` triple that may discharge it)
with recommended probes, evidence references, and an ``open`` ->
``discharged``/``waived`` lifecycle.

The payload is shaped like every other CODEVANTA payload --
``{"count": N, "items": [...]}`` of JSON-safe records -- so it can be dropped
into an evidence bundle as the ``obligations`` entry without any
bundle-format change. Ids are deterministic content digests
(:func:`obligation_id`): the same requirement stated twice yields the same
id, so restating an obligation is reported as a duplicate instead of silently
duplicating the debt.

Ledger discipline matches :mod:`codevanta.core.unknowns` v2: every mutation
(add/waive/discharge) appends an immutable revision, mutations accept
``expected_revision`` for compare-and-swap semantics
(:class:`~codevanta.core.unknowns.LedgerConflictError` on a stale
expectation), and every function validates its inputs and raises
:class:`~codevanta.core.report.AnalysisError` on malformed ledgers, unknown
enums, oversized text, duplicate ids and over-budget records. Only the
standard library is used.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from dataclasses import replace as _dataclass_replace
from datetime import datetime, timezone
from typing import Any, Literal

from codevanta.core.report import AnalysisError
from codevanta.core.unknowns import (
    MAX_REVISIONS_PER_RECORD as _MAX_REVISIONS_PER_RECORD,
)
from codevanta.core.unknowns import (
    MAX_SUMMARY_LENGTH,
    LedgerConflictError,
    RevisionRecord,
    _clean_text,
    ensure_expected_revision,
    record_revision,
)

__all__ = [
    "DEFAULT_OBLIGATION_AUTHORITY",
    "DEFAULT_OBLIGATION_CONFIDENCE",
    "DEFAULT_OBLIGATION_ENVIRONMENT",
    "MAX_OBLIGATION_EVIDENCE_REFS",
    "MAX_OBLIGATION_NOTE_LENGTH",
    "MAX_OBLIGATION_RECORDS",
    "MAX_PROBE_LENGTH",
    "MAX_QUESTION_LENGTH",
    "MAX_RECOMMENDED_PROBES",
    "OBLIGATION_ACTIONS",
    "OBLIGATION_AUTHORITIES",
    "OBLIGATION_CONFIDENCES",
    "OBLIGATION_ENVIRONMENTS",
    "OBLIGATION_STATUSES",
    "OBLIGATION_STATUS_DISCHARGED",
    "OBLIGATION_STATUS_OPEN",
    "OBLIGATION_STATUS_WAIVED",
    "OBLIGATIONS_ENTRY_NAME",
    "OBLIGATION_ACTION_ADD",
    "OBLIGATION_ACTION_DISCHARGE",
    "OBLIGATION_ACTION_WAIVE",
    "OBLIGATION_ID_DIGEST_CHARS",
    "OBLIGATION_ID_PREFIX",
    "LedgerConflictError",
    "ObligationRecord",
    "add_obligation",
    "discharge_obligation",
    "get_obligation",
    "list_obligations",
    "make_open_obligation",
    "obligation_id",
    "obligations_from_payload",
    "obligations_to_payload",
    "record_revision",
    "remove_obligation",
    "waive_obligation",
]

#: Lifecycle status: the obligation is still open.
OBLIGATION_STATUS_OPEN = "open"
#: Lifecycle status: the obligation was satisfied by evidence.
OBLIGATION_STATUS_DISCHARGED = "discharged"
#: Lifecycle status: the obligation was consciously given up (documented).
OBLIGATION_STATUS_WAIVED = "waived"

#: Every obligation status (frozen; the lifecycle is exactly this).
OBLIGATION_STATUSES: tuple[str, ...] = (
    OBLIGATION_STATUS_OPEN,
    OBLIGATION_STATUS_DISCHARGED,
    OBLIGATION_STATUS_WAIVED,
)

#: Authority kinds that may close an obligation: a parse from the file
#: format, a computation over it, or an explicit verification step.
OBLIGATION_AUTHORITIES: tuple[str, ...] = ("parsed", "computed", "verified")

#: Confidence grades an obligation demands of its discharging evidence
#: (free of the evidence ``Confidence`` scale on purpose: this grades the
#: *requirement*, not a finding).
OBLIGATION_CONFIDENCES: tuple[str, ...] = ("low", "medium", "high")

#: Environments in which the obligation may be discharged: static host-side
#: analysis, on-device execution, or a network-facing probe.
OBLIGATION_ENVIRONMENTS: tuple[str, ...] = ("host", "device", "network")

#: Defaults for records opened without explicit requirements.
DEFAULT_OBLIGATION_AUTHORITY: Literal["parsed", "computed", "verified"] = "parsed"
DEFAULT_OBLIGATION_CONFIDENCE: Literal["low", "medium", "high"] = "medium"
DEFAULT_OBLIGATION_ENVIRONMENT: Literal["host", "device", "network"] = "host"

#: Entry name under which a ledger is embedded in an evidence bundle.
OBLIGATIONS_ENTRY_NAME = "obligations"

#: Prefix of every deterministic id (``ob-<16 hex>``).
OBLIGATION_ID_PREFIX = "ob"
#: Hex characters kept from the content digest for the id.
OBLIGATION_ID_DIGEST_CHARS = 16

#: Longest accepted ``question`` text.
MAX_QUESTION_LENGTH = 500
#: Longest accepted resolution/waiver note.
MAX_OBLIGATION_NOTE_LENGTH = 500
#: Longest accepted recommended-probe description.
MAX_PROBE_LENGTH = 200
#: Most recommended probes a single record may carry.
MAX_RECOMMENDED_PROBES = 8
#: Most evidence references a single record may carry.
MAX_OBLIGATION_EVIDENCE_REFS = 16
#: Most records one obligations ledger may hold.
MAX_OBLIGATION_RECORDS = 256

#: Revision actions of the obligation lifecycle (add is the birth revision).
OBLIGATION_ACTION_ADD = "add"
OBLIGATION_ACTION_DISCHARGE = "discharge"
OBLIGATION_ACTION_WAIVE = "waive"
OBLIGATION_ACTIONS: tuple[str, ...] = (
    OBLIGATION_ACTION_ADD,
    OBLIGATION_ACTION_DISCHARGE,
    OBLIGATION_ACTION_WAIVE,
)

#: Separator for the canonical id input (unit-separator: cannot appear in
#: normal text fields, so the join is unambiguous).
_OBLIGATION_ID_FIELD_SEPARATOR = "\x1f"


# ---- end of constants; record type follows -----------------------------------


@dataclass(frozen=True)
class ObligationRecord:
    """One evidence obligation, frozen and JSON-safe.

    Attributes:
        id: Deterministic content id (``ob-<16 hex>``), see
            :func:`obligation_id`.
        question: Human-readable statement of what must be decided.
        required_authority: One of :data:`OBLIGATION_AUTHORITIES`.
        required_confidence: One of :data:`OBLIGATION_CONFIDENCES`.
        required_environment: One of :data:`OBLIGATION_ENVIRONMENTS`.
        recommended_probes: Bounded list of concrete probe suggestions.
        status: One of :data:`OBLIGATION_STATUSES`.
        evidence_refs: References to the evidence that frames or closed the
            obligation (bundle entry names, report sections, digests).
        resolution: Note recorded when the obligation was discharged or
            waived; ``None`` while it is open.
        revisions: Immutable revision trail (see
            :class:`~codevanta.core.unknowns.RevisionRecord`).
        revisions_truncated: Warning marker counting pruned oldest revisions.
    """

    id: str
    question: str
    required_authority: str
    required_confidence: str
    required_environment: str
    recommended_probes: tuple[str, ...] = ()
    status: str = OBLIGATION_STATUS_OPEN
    evidence_refs: tuple[str, ...] = ()
    resolution: str | None = None
    revisions: tuple[RevisionRecord, ...] = ()
    revisions_truncated: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-safe mapping stored in ledger payloads."""
        data: dict[str, Any] = {
            "id": self.id,
            "question": self.question,
            "required_authority": self.required_authority,
            "required_confidence": self.required_confidence,
            "required_environment": self.required_environment,
            "recommended_probes": list(self.recommended_probes),
            "status": self.status,
            "evidence_refs": list(self.evidence_refs),
        }
        if self.resolution is not None:
            data["resolution"] = self.resolution
        if self.revisions:
            data["revisions"] = [revision.to_dict() for revision in self.revisions]
        if self.revisions_truncated:
            data["revisions_truncated"] = self.revisions_truncated
        return data


def _obligation_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ---- end of record type; validators follow -----------------------------------


def _clean_probe(name: str, value: str, limit: int) -> str:
    """Validate one bounded free-text list item (probe description)."""
    if not isinstance(value, str):
        raise AnalysisError(f"{name} must be a string, got {type(value).__name__}")
    text = value.strip()
    if not text:
        raise AnalysisError(f"{name} must be a non-empty string")
    if len(text) > limit:
        raise AnalysisError(f"{name} is too long ({len(text)} > limit {limit})")
    return text


def _clean_probes(probes: Sequence[str]) -> tuple[str, ...]:
    """Validate and freeze the recommended-probe list of one record."""
    if len(probes) > MAX_RECOMMENDED_PROBES:
        raise AnalysisError(
            f"too many recommended probes ({len(probes)} > limit {MAX_RECOMMENDED_PROBES})"
        )
    cleaned = tuple(_clean_probe("recommended probe", probe, MAX_PROBE_LENGTH) for probe in probes)
    if len(set(cleaned)) != len(cleaned):
        raise AnalysisError("recommended probes must be unique within one record")
    return cleaned


def _clean_refs(evidence_refs: Sequence[str]) -> tuple[str, ...]:
    """Validate and freeze the evidence-reference list of one record."""
    if len(evidence_refs) > MAX_OBLIGATION_EVIDENCE_REFS:
        raise AnalysisError(
            f"too many evidence refs ({len(evidence_refs)} > limit "
            f"{MAX_OBLIGATION_EVIDENCE_REFS})"
        )
    cleaned = tuple(_clean_text("evidence ref", ref, MAX_SUMMARY_LENGTH) for ref in evidence_refs)
    if len(set(cleaned)) != len(cleaned):
        raise AnalysisError("evidence refs must be unique within one record")
    return cleaned


def _validate_authority(authority: str) -> str:
    """Return the authority token or raise for an unknown one."""
    if authority not in OBLIGATION_AUTHORITIES:
        supported = ", ".join(OBLIGATION_AUTHORITIES)
        raise AnalysisError(f"unknown authority {authority!r}; expected one of: {supported}")
    return authority


def _validate_confidence(confidence: str) -> str:
    """Return the confidence token or raise for an unknown one."""
    if confidence not in OBLIGATION_CONFIDENCES:
        supported = ", ".join(OBLIGATION_CONFIDENCES)
        raise AnalysisError(f"unknown confidence {confidence!r}; expected one of: {supported}")
    return confidence


def _validate_environment(environment: str) -> str:
    """Return the environment token or raise for an unknown one."""
    if environment not in OBLIGATION_ENVIRONMENTS:
        supported = ", ".join(OBLIGATION_ENVIRONMENTS)
        raise AnalysisError(f"unknown environment {environment!r}; expected one of: {supported}")
    return environment


def _validate_status(status: str) -> str:
    """Return the status token or raise for an unknown one."""
    if status not in OBLIGATION_STATUSES:
        supported = ", ".join(OBLIGATION_STATUSES)
        raise AnalysisError(f"unknown status {status!r}; expected one of: {supported}")
    return status


def obligation_id(
    question: str,
    required_authority: str = DEFAULT_OBLIGATION_AUTHORITY,
    required_confidence: str = DEFAULT_OBLIGATION_CONFIDENCE,
    required_environment: str = DEFAULT_OBLIGATION_ENVIRONMENT,
) -> str:
    """Return the deterministic id for the given requirement content.

    The id is ``ob-`` plus the first 16 hex characters of the SHA-256 digest
    over ``question`` and the required authority/confidence/environment
    triple, joined with a unit separator. The lifecycle fields (status,
    resolution, revisions) are deliberately *not* hashed: closing or waiving
    an obligation never changes its identity. Same requirement -> same id,
    on every machine.
    """
    canonical = _OBLIGATION_ID_FIELD_SEPARATOR.join(
        (question, required_authority, required_confidence, required_environment)
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"{OBLIGATION_ID_PREFIX}-{digest[:OBLIGATION_ID_DIGEST_CHARS]}"


# ---- end of ids; construction and revision trail follows ---------------------


def make_open_obligation(
    *,
    question: str,
    required_authority: str = DEFAULT_OBLIGATION_AUTHORITY,
    required_confidence: str = DEFAULT_OBLIGATION_CONFIDENCE,
    required_environment: str = DEFAULT_OBLIGATION_ENVIRONMENT,
    recommended_probes: Sequence[str] = (),
    evidence_refs: Sequence[str] = (),
) -> ObligationRecord:
    """Create one fresh ``open`` obligation; the id is derived from the content.

    The record is born at revision ``1`` (``action="add"``) whose ``state``
    snapshot pins the full open state, ready for later CAS mutations.
    """
    clean_question = _clean_text("question", question, MAX_QUESTION_LENGTH)
    authority = _validate_authority(required_authority)
    confidence = _validate_confidence(required_confidence)
    environment = _validate_environment(required_environment)
    clean_probes = _clean_probes(recommended_probes)
    clean_refs = _clean_refs(evidence_refs)
    record = ObligationRecord(
        id=obligation_id(clean_question, authority, confidence, environment),
        question=clean_question,
        required_authority=authority,
        required_confidence=confidence,
        required_environment=environment,
        recommended_probes=clean_probes,
        status=OBLIGATION_STATUS_OPEN,
        evidence_refs=clean_refs,
    )
    return _with_revision(record, action=OBLIGATION_ACTION_ADD)


def _base_state(record: ObligationRecord) -> dict[str, Any]:
    """Return the record's content state without the revision trail.

    This is what a revision's ``state`` snapshot pins and what
    :meth:`ObligationRecord.to_dict` extends with the revision fields.
    """
    data: dict[str, Any] = {
        "id": record.id,
        "question": record.question,
        "required_authority": record.required_authority,
        "required_confidence": record.required_confidence,
        "required_environment": record.required_environment,
        "recommended_probes": list(record.recommended_probes),
        "status": record.status,
        "evidence_refs": list(record.evidence_refs),
    }
    if record.resolution is not None:
        data["resolution"] = record.resolution
    return data


def _with_revision(
    record: ObligationRecord,
    *,
    action: str,
    note: str = "",
) -> ObligationRecord:
    """Return a copy of ``record`` with one more immutable revision.

    The new revision pins the record's *post-mutation* state. Pruning keeps
    at most :data:`~codevanta.core.unknowns.MAX_REVISIONS_PER_RECORD`
    revisions: the oldest are dropped and the ``revisions_truncated``
    warning marker counts every dropped revision, so 1-based numbering stays
    monotonic across prunes.
    """
    revision = RevisionRecord(
        revision=record_revision(record) + 1,
        at=_obligation_now_iso(),
        action=action,
        state=_base_state(record),
        note=note or None,
    )
    revisions = (*record.revisions, revision)
    truncated = record.revisions_truncated
    if len(revisions) > _MAX_REVISIONS_PER_RECORD:
        revisions = revisions[len(revisions) - _MAX_REVISIONS_PER_RECORD :]
        truncated += 1
    return _dataclass_replace(record, revisions=revisions, revisions_truncated=truncated)


# ---- end of construction; payload round trips follow -------------------------


def obligations_to_payload(records: Sequence[ObligationRecord]) -> dict[str, Any]:
    """Serialise records into the ledger/bundle payload shape.

    Records are sorted by id, so the payload is canonical regardless of the
    caller's order; duplicate ids (the same requirement stated twice) are
    refused.
    """
    if len(records) > MAX_OBLIGATION_RECORDS:
        raise AnalysisError(
            f"too many obligation records ({len(records)} > limit {MAX_OBLIGATION_RECORDS})"
        )
    ordered = sorted(records, key=lambda record: record.id)
    seen: set[str] = set()
    for record in ordered:
        if record.id in seen:
            raise AnalysisError(f"duplicate obligation id {record.id!r} in ledger")
        seen.add(record.id)
    return {
        "count": len(ordered),
        "items": [record.to_dict() for record in ordered],
    }


def _parse_revisions(raw: tuple[Any, ...], item_index: int) -> tuple[RevisionRecord, ...]:
    """Parse and validate one obligation record's stored revision trail."""
    if len(raw) > _MAX_REVISIONS_PER_RECORD:
        raise AnalysisError(
            f"obligations item {item_index}: too many revisions "
            f"({len(raw)} > limit {_MAX_REVISIONS_PER_RECORD})"
        )
    revisions: list[RevisionRecord] = []
    previous = 0
    for revision_index, revision_raw in enumerate(raw):
        where = f"obligations item {item_index} revision {revision_index}"
        if not isinstance(revision_raw, Mapping):
            raise AnalysisError(f"{where} is not an object")
        number_raw = revision_raw.get("revision")
        if isinstance(number_raw, bool) or not isinstance(number_raw, int) or number_raw < 1:
            raise AnalysisError(f"{where}: revision must be a positive integer")
        if number_raw <= previous:
            raise AnalysisError(f"{where}: revision numbers must strictly increase")
        previous = number_raw
        at = _clean_text(f"{where}: at", str(revision_raw.get("at", "")), MAX_SUMMARY_LENGTH)
        action = str(revision_raw.get("action", ""))
        if action not in OBLIGATION_ACTIONS:
            supported = ", ".join(OBLIGATION_ACTIONS)
            raise AnalysisError(f"{where}: unknown action {action!r}; expected one of: {supported}")
        state_raw = revision_raw.get("state")
        if not isinstance(state_raw, Mapping):
            raise AnalysisError(f"{where}: state must be an object")
        note_raw = revision_raw.get("note")
        note = None if note_raw is None else str(note_raw)
        if note is not None and len(note) > MAX_OBLIGATION_NOTE_LENGTH:
            raise AnalysisError(
                f"{where}: note is too long (> limit {MAX_OBLIGATION_NOTE_LENGTH})"
            )
        revisions.append(
            RevisionRecord(
                revision=number_raw,
                at=at,
                action=action,
                state=dict(state_raw),
                note=note,
            )
        )
    return tuple(revisions)


# ---- end of parsing; query and mutation API follows --------------------------


def obligations_from_payload(payload: Mapping[str, Any]) -> tuple[ObligationRecord, ...]:
    """Parse an obligations ledger/bundle payload back into frozen records.

    Every item is validated (ids present, enums known, text bounded, revision
    trail well-formed); the id is *recomputed from the content* and a stored
    id that disagrees with it is rejected, so a ledger can never drift away
    from the deterministic-id rule. Malformed input raises ``AnalysisError``
    naming the problem and the offending item index.
    """
    if not isinstance(payload, Mapping):
        raise AnalysisError(
            f"obligations payload must be an object, got {type(payload).__name__}"
        )
    items = payload.get("items")
    if not isinstance(items, list):
        raise AnalysisError("obligations payload is missing the 'items' list")
    if len(items) > MAX_OBLIGATION_RECORDS:
        raise AnalysisError(
            f"too many obligation records ({len(items)} > limit {MAX_OBLIGATION_RECORDS})"
        )
    records: list[ObligationRecord] = []
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            raise AnalysisError(f"obligations item {index} is not an object")
        question = _clean_text("question", str(item.get("question", "")), MAX_QUESTION_LENGTH)
        authority = _validate_authority(
            str(item.get("required_authority", DEFAULT_OBLIGATION_AUTHORITY))
        )
        confidence = _validate_confidence(
            str(item.get("required_confidence", DEFAULT_OBLIGATION_CONFIDENCE))
        )
        environment = _validate_environment(
            str(item.get("required_environment", DEFAULT_OBLIGATION_ENVIRONMENT))
        )
        probes_raw = item.get("recommended_probes", ())
        if not isinstance(probes_raw, (list, tuple)):
            raise AnalysisError(f"obligations item {index}: recommended_probes must be a list")
        probes = _clean_probes(tuple(str(probe) for probe in probes_raw))
        refs_raw = item.get("evidence_refs", ())
        if not isinstance(refs_raw, (list, tuple)):
            raise AnalysisError(f"obligations item {index}: evidence_refs must be a list")
        refs = _clean_refs(tuple(str(ref) for ref in refs_raw))
        expected_id = obligation_id(question, authority, confidence, environment)
        record_id = str(item.get("id", ""))
        if record_id and record_id != expected_id:
            raise AnalysisError(
                f"obligations item {index}: id {record_id!r} does not match content "
                f"(expected {expected_id!r})"
            )
        status = _validate_status(str(item.get("status", OBLIGATION_STATUS_OPEN)))
        resolution_raw = item.get("resolution")
        resolution = None if resolution_raw is None else str(resolution_raw)
        revisions_raw = item.get("revisions", ())
        if not isinstance(revisions_raw, (list, tuple)):
            raise AnalysisError(f"obligations item {index}: revisions must be a list")
        revisions = _parse_revisions(tuple(revisions_raw), index)
        truncated_raw = item.get("revisions_truncated", 0)
        if isinstance(truncated_raw, bool) or not isinstance(truncated_raw, int):
            raise AnalysisError(
                f"obligations item {index}: revisions_truncated must be an integer"
            )
        if truncated_raw < 0:
            raise AnalysisError(
                f"obligations item {index}: revisions_truncated must not be negative"
            )
        if revisions and revisions[0].revision != 1 and truncated_raw == 0:
            raise AnalysisError(
                f"obligations item {index}: revision trail must start at 1 "
                "(a later start requires a revisions_truncated marker)"
            )
        records.append(
            ObligationRecord(
                id=expected_id,
                question=question,
                required_authority=authority,
                required_confidence=confidence,
                required_environment=environment,
                recommended_probes=probes,
                status=status,
                evidence_refs=refs,
                resolution=resolution,
                revisions=revisions,
                revisions_truncated=truncated_raw,
            )
        )
    if len({record.id for record in records}) != len(records):
        raise AnalysisError("duplicate obligation ids in ledger")
    return tuple(records)


def list_obligations(
    payload: Mapping[str, Any],
    *,
    status: str | None = None,
) -> tuple[ObligationRecord, ...]:
    """Return a ledger's records sorted by id, optionally status-filtered.

    A ``status`` outside :data:`OBLIGATION_STATUSES` raises ``AnalysisError``
    (a typo must not silently look like an empty ledger).
    """
    if status is not None and status not in OBLIGATION_STATUSES:
        supported = ", ".join(OBLIGATION_STATUSES)
        raise AnalysisError(f"unknown status {status!r}; expected one of: {supported}")
    records = obligations_from_payload(payload)
    if status is not None:
        return tuple(record for record in records if record.status == status)
    return records


def get_obligation(payload: Mapping[str, Any], obligation_id: str) -> ObligationRecord:
    """Return the one obligation with ``obligation_id`` from a ledger payload.

    Raises ``AnalysisError`` when the id is not in the ledger. This is the
    read-back half of the ledger discipline: CAS expectations and history are
    always taken from a freshly parsed payload, never from caller memory.
    """
    for record in obligations_from_payload(payload):
        if record.id == obligation_id:
            return record
    raise AnalysisError(f"obligation id {obligation_id!r} is not in the ledger")


# ---- end of queries; mutations follow ----------------------------------------


def add_obligation(
    payload: Mapping[str, Any] | None,
    record: ObligationRecord,
) -> dict[str, Any]:
    """Return a payload with ``record`` appended (``None`` starts a ledger).

    The input mapping is never mutated; a duplicate id (the same requirement
    stated twice) raises ``AnalysisError``. ``record`` is normally built by
    :func:`make_open_obligation`, so it already carries revision 1.
    """
    existing = () if payload is None else obligations_from_payload(payload)
    return obligations_to_payload([*existing, record])


def _close_obligation(
    payload: Mapping[str, Any],
    obligation_id: str,
    *,
    action: str,
    status: str,
    note: str,
    expected_revision: int | None,
) -> dict[str, Any]:
    """Shared CAS close path for waive/discharge: guard, close, re-serialise.

    The guard runs before anything changes, so a stale
    ``expected_revision`` leaves the payload untouched and raises
    :class:`LedgerConflictError` naming the record's current revision.
    """
    records = list(obligations_from_payload(payload))
    index = next((i for i, record in enumerate(records) if record.id == obligation_id), None)
    if index is None:
        raise AnalysisError(f"obligation id {obligation_id!r} is not in the ledger")
    target = records[index]
    ensure_expected_revision("obligation", target.id, record_revision(target), expected_revision)
    if target.status != OBLIGATION_STATUS_OPEN:
        raise AnalysisError(
            f"obligation {target.id} is already {target.status}; "
            "only open obligations can be closed"
        )
    clean_note = note.strip() if note else ""
    if len(clean_note) > MAX_OBLIGATION_NOTE_LENGTH:
        raise AnalysisError(
            f"resolution note is too long ({len(clean_note)} > limit "
            f"{MAX_OBLIGATION_NOTE_LENGTH})"
        )
    closed = _with_revision(
        _dataclass_replace(target, status=status, resolution=clean_note or None),
        action=action,
        note=clean_note,
    )
    records[index] = closed
    return obligations_to_payload(records)


def discharge_obligation(
    payload: Mapping[str, Any],
    obligation_id: str,
    *,
    note: str = "",
    expected_revision: int | None = None,
) -> dict[str, Any]:
    """Mark the obligation ``discharged``: the evidence obligation was met.

    The mutation appends one immutable ``discharge`` revision. With
    ``expected_revision`` the mutation is compare-and-swap: a stale
    expectation raises :class:`LedgerConflictError` naming the current
    revision; ``None`` keeps the blind-write behaviour. The new revision
    number is ``record_revision`` of the returned record (re-read the
    payload with :func:`get_obligation` to obtain it).
    """
    return _close_obligation(
        payload,
        obligation_id,
        action=OBLIGATION_ACTION_DISCHARGE,
        status=OBLIGATION_STATUS_DISCHARGED,
        note=note,
        expected_revision=expected_revision,
    )


def waive_obligation(
    payload: Mapping[str, Any],
    obligation_id: str,
    *,
    note: str = "",
    expected_revision: int | None = None,
) -> dict[str, Any]:
    """Mark the obligation ``waived``: consciously given up, note documented.

    Same CAS and revision discipline as :func:`discharge_obligation`.
    """
    return _close_obligation(
        payload,
        obligation_id,
        action=OBLIGATION_ACTION_WAIVE,
        status=OBLIGATION_STATUS_WAIVED,
        note=note,
        expected_revision=expected_revision,
    )


def remove_obligation(
    payload: Mapping[str, Any],
    obligation_id: str,
    *,
    expected_revision: int | None = None,
) -> dict[str, Any]:
    """Remove the obligation from the ledger entirely.

    The removal honours the same CAS guard as the other mutations (checked
    before anything changes); the record's revision trail disappears with the
    record, which is why removal should be reserved for obligations that were
    stated by mistake.
    """
    records = list(obligations_from_payload(payload))
    target = next((record for record in records if record.id == obligation_id), None)
    if target is None:
        raise AnalysisError(f"obligation id {obligation_id!r} is not in the ledger")
    ensure_expected_revision("obligation", target.id, record_revision(target), expected_revision)
    remaining = [record for record in records if record.id != obligation_id]
    return obligations_to_payload(remaining)







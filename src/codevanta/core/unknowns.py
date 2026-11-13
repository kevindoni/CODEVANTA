"""Residual-unknown ledger: typed records for what an analysis could not decide.

An analysis is honest when it names its limits. The ledger is the typed home
for those limits: one :class:`UnknownRecord` per open question ("the entry point
may not be a function boundary", "the CFG could not be built for section X"),
with a *deterministic id* so the same question found twice yields the same id,
a *severity*, a *lifecycle status* (``open`` -> ``resolved``) and *evidence
references* into the surrounding evidence discipline.

The ledger payload is deliberately shaped like every other CODEVANTA payload --
``{"count": N, "items": [...]}`` of JSON-safe records -- so it can be dropped
into an evidence bundle as the ``unknowns`` entry (see
:data:`UNKNOWN_ENTRY_NAME`) without any bundle-format change. Ids are
content digests (:func:`unknown_id`), never counters, so regenerating a ledger
from the same findings is stable across runs and machines.

Bounds and failure modes follow the codebase conventions: every helper
validates its inputs and raises
:class:`~codevanta.core.report.AnalysisError` on malformed ledgers, bad
severities/statuses, oversized text, duplicate ids and over-budget records.
Only the standard library is used.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from codevanta.core.report import AnalysisError

if TYPE_CHECKING:  # pragma: no cover - import used only for type checking
    from codevanta.analysis.evidence_bundle import Bundle

#: Lifecycle status of a record: discovered, not yet explained.
UNKNOWN_STATUS_OPEN = "open"
#: Lifecycle status of a record: explained or accepted by an analyst.
UNKNOWN_STATUS_RESOLVED = "resolved"

#: Every status a record may carry (frozen; the lifecycle is exactly this).
UNKNOWN_STATUSES: tuple[str, ...] = (UNKNOWN_STATUS_OPEN, UNKNOWN_STATUS_RESOLVED)

#: How much the unresolved record matters. Free of the evidence ``Confidence``
#: scale on purpose: a confidence grades how well a finding is supported, a
#: severity grades how much it matters that the question is still open.
UNKNOWN_SEVERITIES: tuple[str, ...] = ("low", "medium", "high")
#: Default severity for records opened without an explicit one.
DEFAULT_UNKNOWN_SEVERITY: Literal["low", "medium", "high"] = "medium"

#: Entry name under which a ledger is embedded in an evidence bundle.
UNKNOWN_ENTRY_NAME = "unknowns"

#: Prefix of every deterministic id (``unk-<16 hex>``).
UNKNOWN_ID_PREFIX = "unk"
#: Hex characters kept from the content digest for the id.
UNKNOWN_ID_DIGEST_CHARS = 16

#: Longest accepted ``domain`` tag (e.g. ``"functions"``, ``"cfg"``).
MAX_DOMAIN_LENGTH = 64
#: Longest accepted ``summary`` text.
MAX_SUMMARY_LENGTH = 500
#: Longest accepted resolution note.
MAX_RESOLUTION_LENGTH = 500
#: Most evidence references a single record may carry.
MAX_EVIDENCE_REFS = 64
#: Most records one ledger (or bundle ``unknowns`` entry) may hold.
MAX_UNKNOWN_RECORDS = 4_096

#: Separator for the canonical id input (unit-separator: cannot appear in a
#: normal domain/summary, so the join is unambiguous).
_ID_FIELD_SEPARATOR = "\x1f"


@dataclass(frozen=True)
class UnknownRecord:
    """One residual unknown, frozen and JSON-safe.

    Attributes:
        id: Deterministic content id (``unk-<16 hex>``), see :func:`unknown_id`.
        domain: Short analysis tag the question belongs to, e.g. ``"cfg"``.
        severity: One of :data:`UNKNOWN_SEVERITIES`.
        status: One of :data:`UNKNOWN_STATUSES`.
        summary: Human-readable one-line description of the open question.
        evidence_refs: References to the evidence that frames the question
            (bundle entry names, report sections, sample paths).
        resolution: Note recorded when the record was resolved; ``None`` while
            the record is open.
    """

    id: str
    domain: str
    severity: str
    status: str
    summary: str
    evidence_refs: tuple[str, ...] = field(default=())
    resolution: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-safe mapping stored in ledgers and bundles."""
        data: dict[str, Any] = {
            "id": self.id,
            "domain": self.domain,
            "severity": self.severity,
            "status": self.status,
            "summary": self.summary,
            "evidence_refs": list(self.evidence_refs),
        }
        if self.resolution is not None:
            data["resolution"] = self.resolution
        return data


def _clean_text(name: str, value: str, limit: int) -> str:
    """Validate one free-text field: non-empty after strip, bounded length."""
    if not isinstance(value, str):
        raise AnalysisError(f"{name} must be a string, got {type(value).__name__}")
    text = value.strip()
    if not text:
        raise AnalysisError(f"{name} must be a non-empty string")
    if len(text) > limit:
        raise AnalysisError(f"{name} is too long ({len(text)} > limit {limit})")
    return text


def _clean_evidence_refs(evidence_refs: Sequence[str]) -> tuple[str, ...]:
    """Validate and freeze the evidence-reference list of one record."""
    if len(evidence_refs) > MAX_EVIDENCE_REFS:
        raise AnalysisError(
            f"too many evidence refs ({len(evidence_refs)} > limit {MAX_EVIDENCE_REFS})"
        )
    cleaned = tuple(
        _clean_text("evidence ref", ref, MAX_SUMMARY_LENGTH) for ref in evidence_refs
    )
    if len(set(cleaned)) != len(cleaned):
        raise AnalysisError("evidence refs must be unique within one record")
    return cleaned


def _validate_severity(severity: str) -> str:
    """Return the severity token or raise for an unknown one."""
    if severity not in UNKNOWN_SEVERITIES:
        supported = ", ".join(UNKNOWN_SEVERITIES)
        raise AnalysisError(f"unknown severity {severity!r}; expected one of: {supported}")
    return severity


def _validate_status(status: str) -> str:
    """Return the status token or raise for an unknown one."""
    if status not in UNKNOWN_STATUSES:
        supported = ", ".join(UNKNOWN_STATUSES)
        raise AnalysisError(f"unknown status {status!r}; expected one of: {supported}")
    return status


def unknown_id(
    domain: str,
    summary: str,
    evidence_refs: Sequence[str] = (),
) -> str:
    """Return the deterministic id for the given record content.

    The id is ``unk-`` plus the first 16 hex characters of the SHA-256 digest
    over ``domain``, ``summary`` and the sorted evidence refs, joined with a
    unit separator. Same findings -> same id, on every machine, twice.
    """
    canonical = _ID_FIELD_SEPARATOR.join((domain, summary, *sorted(evidence_refs)))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"{UNKNOWN_ID_PREFIX}-{digest[:UNKNOWN_ID_DIGEST_CHARS]}"


def make_open_unknown(
    *,
    domain: str,
    summary: str,
    severity: str = DEFAULT_UNKNOWN_SEVERITY,
    evidence_refs: Sequence[str] = (),
) -> UnknownRecord:
    """Create one fresh ``open`` record; the id is derived from the content."""
    clean_domain = _clean_text("domain", domain, MAX_DOMAIN_LENGTH)
    clean_summary = _clean_text("summary", summary, MAX_SUMMARY_LENGTH)
    clean_refs = _clean_evidence_refs(evidence_refs)
    return UnknownRecord(
        id=unknown_id(clean_domain, clean_summary, clean_refs),
        domain=clean_domain,
        severity=_validate_severity(severity),
        status=UNKNOWN_STATUS_OPEN,
        summary=clean_summary,
        evidence_refs=clean_refs,
    )


def resolve_record(record: UnknownRecord, note: str = "") -> UnknownRecord:
    """Return a resolved copy of ``record``; refuse an already-resolved one.

    The id, domain, severity, summary and evidence refs are kept verbatim so a
    resolved record still hashes to the id it was opened with.
    """
    if record.status == UNKNOWN_STATUS_RESOLVED:
        raise AnalysisError(f"unknown {record.id} is already resolved")
    clean_note = note.strip() if note else ""
    if len(clean_note) > MAX_RESOLUTION_LENGTH:
        raise AnalysisError(
            f"resolution note is too long ({len(clean_note)} > limit {MAX_RESOLUTION_LENGTH})"
        )
    return UnknownRecord(
        id=record.id,
        domain=record.domain,
        severity=record.severity,
        status=UNKNOWN_STATUS_RESOLVED,
        summary=record.summary,
        evidence_refs=record.evidence_refs,
        resolution=clean_note or None,
    )


def records_to_payload(records: Sequence[UnknownRecord]) -> dict[str, Any]:
    """Serialise records into the ledger/bundle payload shape.

    Records are sorted by id, so the payload is canonical regardless of the
    caller's order; duplicate ids (identical content opened twice) are refused.
    """
    if len(records) > MAX_UNKNOWN_RECORDS:
        raise AnalysisError(
            f"too many unknown records ({len(records)} > limit {MAX_UNKNOWN_RECORDS})"
        )
    ordered = sorted(records, key=lambda record: record.id)
    seen: set[str] = set()
    for record in ordered:
        if record.id in seen:
            raise AnalysisError(f"duplicate unknown id {record.id!r} in ledger")
        seen.add(record.id)
    return {
        "count": len(ordered),
        "items": [record.to_dict() for record in ordered],
    }


def records_from_payload(payload: Mapping[str, Any]) -> tuple[UnknownRecord, ...]:
    """Parse a ledger/bundle ``unknowns`` payload back into frozen records.

    Every item is validated (ids present, severity/status known, text
    bounded); the id is *recomputed from the content* and a stored id that
    disagrees with it is rejected, so a ledger can never drift away from the
    deterministic-id rule. Malformed input raises ``AnalysisError`` naming the
    problem and the offending item index.
    """
    if not isinstance(payload, Mapping):
        raise AnalysisError(f"unknowns payload must be an object, got {type(payload).__name__}")
    items = payload.get("items")
    if not isinstance(items, list):
        raise AnalysisError("unknowns payload is missing the 'items' list")
    if len(items) > MAX_UNKNOWN_RECORDS:
        raise AnalysisError(
            f"too many unknown records ({len(items)} > limit {MAX_UNKNOWN_RECORDS})"
        )
    records: list[UnknownRecord] = []
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            raise AnalysisError(f"unknowns item {index} is not an object")
        domain = _clean_text("domain", str(item.get("domain", "")), MAX_DOMAIN_LENGTH)
        summary = _clean_text("summary", str(item.get("summary", "")), MAX_SUMMARY_LENGTH)
        refs_raw = item.get("evidence_refs", ())
        if not isinstance(refs_raw, (list, tuple)):
            raise AnalysisError(f"unknowns item {index}: evidence_refs must be a list")
        refs = _clean_evidence_refs(tuple(str(ref) for ref in refs_raw))
        expected_id = unknown_id(domain, summary, refs)
        record_id = str(item.get("id", ""))
        if record_id and record_id != expected_id:
            raise AnalysisError(
                f"unknowns item {index}: id {record_id!r} does not match content "
                f"(expected {expected_id!r})"
            )
        severity = str(item.get("severity", DEFAULT_UNKNOWN_SEVERITY))
        status = str(item.get("status", UNKNOWN_STATUS_OPEN))
        resolution_raw = item.get("resolution")
        resolution = None if resolution_raw is None else str(resolution_raw)
        records.append(
            UnknownRecord(
                id=expected_id,
                domain=domain,
                severity=_validate_severity(severity),
                status=_validate_status(status),
                summary=summary,
                evidence_refs=refs,
                resolution=resolution,
            )
        )
    if len({record.id for record in records}) != len(records):
        raise AnalysisError("duplicate unknown ids in ledger")
    return tuple(records)


def open_unknowns(ledger: Mapping[str, Any]) -> tuple[UnknownRecord, ...]:
    """Return the still-``open`` records of a ledger payload, sorted by id."""
    return tuple(
        record
        for record in records_from_payload(ledger)
        if record.status == UNKNOWN_STATUS_OPEN
    )


def resolve_unknowns(
    ledger: Mapping[str, Any],
    unknown_ids: Sequence[str],
    *,
    note: str = "",
) -> dict[str, Any]:
    """Resolve ``unknown_ids`` in ``ledger`` and return the updated payload.

    The input mapping is never mutated. Naming an id that is not in the
    ledger, or one that is already resolved, raises ``AnalysisError``; the
    returned payload only changes for the ids asked for and preserves the
    ledger's record order.
    """
    records = list(records_from_payload(ledger))
    known = {record.id: record for record in records}
    for wanted_id in unknown_ids:
        if wanted_id not in known:
            raise AnalysisError(f"unknown id {wanted_id!r} is not in the ledger")
    for wanted_id in unknown_ids:
        known[wanted_id] = resolve_record(known[wanted_id], note)
    updated = [known[record.id] for record in records]
    return records_to_payload(updated)


def unknowns_from_bundle(bundle: Bundle) -> tuple[UnknownRecord, ...]:
    """Read the ``unknowns`` section of a bundle, if it carries one.

    A bundle without an ``unknowns`` entry simply has no unknowns; a malformed
    one raises ``AnalysisError`` like every other bundle reader here. Digests
    are *not* re-verified here -- that is
    :func:`codevanta.analysis.evidence_bundle.verify_bundle`'s job.
    """
    if UNKNOWN_ENTRY_NAME not in bundle.entries:
        return ()
    document = bundle.payload(UNKNOWN_ENTRY_NAME)
    if not isinstance(document, Mapping):
        raise AnalysisError(f"bundle entry {UNKNOWN_ENTRY_NAME!r} is not a JSON object")
    return records_from_payload(document)

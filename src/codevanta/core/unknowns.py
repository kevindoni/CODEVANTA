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

Ledger v2 adds revision discipline: every mutation (open/resolve) appends an
immutable :class:`RevisionRecord` carrying a 1-based revision number, a UTC
timestamp, the action, a full state snapshot and an optional note. Mutations
accept ``expected_revision`` for compare-and-swap semantics -- a stale
expectation raises :class:`LedgerConflictError` naming the current revision --
and at most :data:`MAX_REVISIONS_PER_RECORD` revisions are kept per record
(oldest pruned, counted in the ``revisions_truncated`` warning marker).

Bounds and failure modes follow the codebase conventions: every helper
validates its inputs and raises
:class:`~codevanta.core.report.AnalysisError` on malformed ledgers, bad
severities/statuses, oversized text, duplicate ids and over-budget records.
Only the standard library is used.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal, Protocol

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
#: Most records one ledger (or bundle ``unknowns`` entry) may hold. Ledger v2
#: tightens the budget to the same 256-record bound as the other ledgers.
MAX_UNKNOWN_RECORDS = 256

#: Most revisions one record keeps (ledger v2). When a mutation would exceed
#: the budget the *oldest* revisions are pruned and the number of pruned
#: revisions is recorded on the record as the ``revisions_truncated`` warning
#: marker, so the revision counter keeps climbing even after pruning.
MAX_REVISIONS_PER_RECORD = 64

#: Revision action: the record was opened (revision 1).
REVISION_ACTION_OPEN = "open"
#: Revision action: the record was resolved.
REVISION_ACTION_RESOLVE = "resolve"

#: Every mutation action a record's revision trail may name (frozen).
REVISION_ACTIONS: tuple[str, ...] = (REVISION_ACTION_OPEN, REVISION_ACTION_RESOLVE)

#: Separator for the canonical id input (unit-separator: cannot appear in a
#: normal domain/summary, so the join is unambiguous).
_ID_FIELD_SEPARATOR = "\x1f"


class _Revisioned(Protocol):
    """Duck type shared by every revision-tracked ledger record.

    Both the unknown ledger (this module) and the obligation ledger
    (:mod:`codevanta.core.obligations`) carry a ``revisions`` trail of the
    same shape, so the revision helpers work over either record type without
    a circular import.
    """

    @property
    def revisions(self) -> tuple[RevisionRecord, ...]:  # pragma: no cover - protocol
        ...


class LedgerConflictError(AnalysisError):
    """A compare-and-swap (CAS) ledger mutation lost the race.

    Raised when a mutation names an ``expected_revision`` that does not match
    the record's current revision: the ledger changed under the caller. The
    message always names the record's *current* revision so the caller can
    re-read the ledger and retry with a fresh expectation.
    """


@dataclass(frozen=True)
class RevisionRecord:
    """One immutable revision of a ledger record.

    Every mutation appends a new revision instead of editing history: a
    revision pins the 1-based ``revision`` number, an ISO-8601 ``at``
    timestamp, the mutating ``action`` and a *full state snapshot* of the
    record as it looked after the mutation. Existing revisions are never
    rewritten; only :data:`MAX_REVISIONS_PER_RECORD` are kept per record.

    Attributes:
        revision: 1-based sequence number, strictly increasing per record.
        at: UTC ISO-8601 timestamp of the mutation.
        action: One of :data:`REVISION_ACTIONS` for unknown records.
        state: JSON-safe full-state snapshot of the record at this revision.
        note: Optional note recorded with the mutation.
    """

    revision: int
    at: str
    action: str
    state: dict[str, Any]
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-safe mapping stored inside ledger payloads."""
        data: dict[str, Any] = {
            "revision": self.revision,
            "at": self.at,
            "action": self.action,
            "state": dict(self.state),
        }
        if self.note is not None:
            data["note"] = self.note
        return data


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
        revisions: Immutable revision trail; every mutation appends one
            :class:`RevisionRecord` (ledger v2).
        revisions_truncated: Warning marker: how many oldest revisions were
            pruned once the per-record budget
            (:data:`MAX_REVISIONS_PER_RECORD`) was exhausted. ``0`` while no
            revision has been dropped.
    """

    id: str
    domain: str
    severity: str
    status: str
    summary: str
    evidence_refs: tuple[str, ...] = field(default=())
    resolution: str | None = None
    revisions: tuple[RevisionRecord, ...] = ()
    revisions_truncated: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-safe mapping stored in ledgers and bundles."""
        data = _base_state(self)
        if self.revisions:
            data["revisions"] = [revision.to_dict() for revision in self.revisions]
        if self.revisions_truncated:
            data["revisions_truncated"] = self.revisions_truncated
        return data


def _base_state(record: UnknownRecord) -> dict[str, Any]:
    """Return the record's content state without the revision trail.

    This is the pre-ledger-v2 payload shape; it is what a revision's
    ``state`` snapshot pins and what :meth:`UnknownRecord.to_dict` extends
    with the revision fields.
    """
    data: dict[str, Any] = {
        "id": record.id,
        "domain": record.domain,
        "severity": record.severity,
        "status": record.status,
        "summary": record.summary,
        "evidence_refs": list(record.evidence_refs),
    }
    if record.resolution is not None:
        data["resolution"] = record.resolution
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


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def record_revision(record: _Revisioned) -> int:
    """Return the record's current revision.

    A record parsed from a pre-ledger-v2 payload (no revision trail) is at
    revision ``0``: its first mutation produces revision ``1``.
    """
    return record.revisions[-1].revision if record.revisions else 0


def ensure_expected_revision(
    kind: str,
    record_id: str,
    current: int,
    expected_revision: int | None,
) -> None:
    """CAS guard: raise :class:`LedgerConflictError` on a stale expectation.

    ``expected_revision=None`` is a blind write and never conflicts. A
    non-``None`` expectation that disagrees with ``current`` raises
    :class:`LedgerConflictError`, whose message names the current revision so
    the caller can re-read and retry.
    """
    if expected_revision is not None and expected_revision != current:
        raise LedgerConflictError(
            f"{kind} {record_id}: ledger conflict: current revision {current}, "
            f"expected {expected_revision}"
        )


def _with_appended_revision(
    record: UnknownRecord,
    *,
    action: str,
    note: str = "",
) -> UnknownRecord:
    """Return a copy of ``record`` with one more immutable revision.

    The new revision pins the record's *post-mutation* state as its full
    snapshot. Pruning keeps at most :data:`MAX_REVISIONS_PER_RECORD`
    revisions: the oldest are dropped and the ``revisions_truncated`` warning
    marker counts every dropped revision, so the 1-based numbering stays
    monotonic even across prunes.
    """
    revision = RevisionRecord(
        revision=record_revision(record) + 1,
        at=_utc_now_iso(),
        action=action,
        state=_base_state(record),
        note=note or None,
    )
    revisions = (*record.revisions, revision)
    truncated = record.revisions_truncated
    if len(revisions) > MAX_REVISIONS_PER_RECORD:
        revisions = revisions[len(revisions) - MAX_REVISIONS_PER_RECORD :]
        truncated += 1
    return replace(record, revisions=revisions, revisions_truncated=truncated)


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
    """Create one fresh ``open`` record; the id is derived from the content.

    Ledger v2: the record is born at revision ``1`` (``action="open"``) whose
    ``state`` snapshot pins the full open state, so the revision a caller saw
    at creation is stable input for later CAS mutations.
    """
    clean_domain = _clean_text("domain", domain, MAX_DOMAIN_LENGTH)
    clean_summary = _clean_text("summary", summary, MAX_SUMMARY_LENGTH)
    clean_refs = _clean_evidence_refs(evidence_refs)
    record = UnknownRecord(
        id=unknown_id(clean_domain, clean_summary, clean_refs),
        domain=clean_domain,
        severity=_validate_severity(severity),
        status=UNKNOWN_STATUS_OPEN,
        summary=clean_summary,
        evidence_refs=clean_refs,
    )
    return _with_appended_revision(record, action=REVISION_ACTION_OPEN)


def resolve_record(
    record: UnknownRecord,
    note: str = "",
    *,
    expected_revision: int | None = None,
) -> UnknownRecord:
    """Return a resolved copy of ``record``; refuse an already-resolved one.

    The id, domain, severity, summary and evidence refs are kept verbatim so a
    resolved record still hashes to the id it was opened with.

    Ledger v2: the mutation appends one immutable ``resolve`` revision. With
    ``expected_revision`` the mutation is compare-and-swap: a stale
    expectation raises :class:`LedgerConflictError` naming the current
    revision; ``None`` (the default, keeping the historical behaviour) is a
    blind write. The new revision number is ``record_revision`` of the
    returned record.
    """
    ensure_expected_revision("unknown", record.id, record_revision(record), expected_revision)
    if record.status == UNKNOWN_STATUS_RESOLVED:
        raise AnalysisError(f"unknown {record.id} is already resolved")
    clean_note = note.strip() if note else ""
    if len(clean_note) > MAX_RESOLUTION_LENGTH:
        raise AnalysisError(
            f"resolution note is too long ({len(clean_note)} > limit {MAX_RESOLUTION_LENGTH})"
        )
    resolved = UnknownRecord(
        id=record.id,
        domain=record.domain,
        severity=record.severity,
        status=UNKNOWN_STATUS_RESOLVED,
        summary=record.summary,
        evidence_refs=record.evidence_refs,
        resolution=clean_note or None,
        revisions=record.revisions,
        revisions_truncated=record.revisions_truncated,
    )
    return _with_appended_revision(resolved, action=REVISION_ACTION_RESOLVE, note=clean_note)


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


def _parse_revisions(
    raw: tuple[Any, ...],
    item_index: int,
) -> tuple[RevisionRecord, ...]:
    """Parse and validate one record's stored revision trail.

    Every revision must be an object with a 1-based ``revision`` number
    strictly increasing along the trail, a bounded ISO-8601 ``at`` timestamp,
    a known ``action``, a full ``state`` mapping snapshot and an optional
    ``note``. A trail carrying more than
    :data:`MAX_REVISIONS_PER_RECORD` revisions is rejected (the writer never
    produces one; oversized trails mean a tampered ledger).
    """
    if len(raw) > MAX_REVISIONS_PER_RECORD:
        raise AnalysisError(
            f"unknowns item {item_index}: too many revisions "
            f"({len(raw)} > limit {MAX_REVISIONS_PER_RECORD})"
        )
    revisions: list[RevisionRecord] = []
    previous = 0
    for revision_index, revision_raw in enumerate(raw):
        where = f"unknowns item {item_index} revision {revision_index}"
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
        if action not in REVISION_ACTIONS:
            supported = ", ".join(REVISION_ACTIONS)
            raise AnalysisError(f"{where}: unknown action {action!r}; expected one of: {supported}")
        state_raw = revision_raw.get("state")
        if not isinstance(state_raw, Mapping):
            raise AnalysisError(f"{where}: state must be an object")
        note_raw = revision_raw.get("note")
        note = None if note_raw is None else str(note_raw)
        if note is not None and len(note) > MAX_RESOLUTION_LENGTH:
            raise AnalysisError(f"{where}: note is too long (> limit {MAX_RESOLUTION_LENGTH})")
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
        revisions_raw = item.get("revisions", ())
        if not isinstance(revisions_raw, (list, tuple)):
            raise AnalysisError(f"unknowns item {index}: revisions must be a list")
        revisions = _parse_revisions(tuple(revisions_raw), index)
        truncated_raw = item.get("revisions_truncated", 0)
        if isinstance(truncated_raw, bool) or not isinstance(truncated_raw, int):
            raise AnalysisError(
                f"unknowns item {index}: revisions_truncated must be an integer"
            )
        if truncated_raw < 0:
            raise AnalysisError(
                f"unknowns item {index}: revisions_truncated must not be negative"
            )
        if revisions and revisions[0].revision != 1 and truncated_raw == 0:
            raise AnalysisError(
                f"unknowns item {index}: revision trail must start at 1 "
                "(a later start requires a revisions_truncated marker)"
            )
        records.append(
            UnknownRecord(
                id=expected_id,
                domain=domain,
                severity=_validate_severity(severity),
                status=_validate_status(status),
                summary=summary,
                evidence_refs=refs,
                resolution=resolution,
                revisions=revisions,
                revisions_truncated=truncated_raw,
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


def find_record(payload: Mapping[str, Any], unknown_id: str) -> UnknownRecord:
    """Return the one record with ``unknown_id`` from a ledger payload.

    Raises ``AnalysisError`` when the id is not in the ledger. This is the
    read-back half of the ledger discipline: history and CAS expectations are
    always taken from a freshly parsed payload, never from caller memory.
    """
    for record in records_from_payload(payload):
        if record.id == unknown_id:
            return record
    raise AnalysisError(f"unknown id {unknown_id!r} is not in the ledger")


def resolve_unknowns(
    ledger: Mapping[str, Any],
    unknown_ids: Sequence[str],
    *,
    note: str = "",
    expected_revision: int | None = None,
) -> dict[str, Any]:
    """Resolve ``unknown_ids`` in ``ledger`` and return the updated payload.

    The input mapping is never mutated. Naming an id that is not in the
    ledger, or one that is already resolved, raises ``AnalysisError``; the
    returned payload only changes for the ids asked for and preserves the
    ledger's record order.

    Ledger v2: every resolved record gains one immutable ``resolve`` revision.
    With ``expected_revision`` the mutation is compare-and-swap across *all*
    named ids: the guard runs before any record changes, so a stale
    expectation raises :class:`LedgerConflictError` (naming the offending
    record's current revision) and leaves the payload untouched. ``None``
    keeps the historical blind-write behaviour.
    """
    records = list(records_from_payload(ledger))
    known = {record.id: record for record in records}
    for wanted_id in unknown_ids:
        if wanted_id not in known:
            raise AnalysisError(f"unknown id {wanted_id!r} is not in the ledger")
    for wanted_id in unknown_ids:
        ensure_expected_revision(
            "unknown", wanted_id, record_revision(known[wanted_id]), expected_revision
        )
    for wanted_id in unknown_ids:
        known[wanted_id] = resolve_record(
            known[wanted_id], note, expected_revision=expected_revision
        )
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

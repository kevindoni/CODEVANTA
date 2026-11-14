"""Coverage evaluation: do the evidence bundles pay the obligations?

An obligation (:mod:`codevanta.core.obligations`) is a debt: a question that
must be closed by evidence of a required authority, confidence and
environment. Coverage is the deterministic, offline check of which debts the
surrounding evidence bundle actually pays: every obligation's
``evidence_refs`` are matched against the bundle's entry names (the record
kinds), entry digests and the record ids carried inside entry payloads, and
each obligation gets exactly one verdict:

* ``complete`` -- the obligation carries at least one evidence ref and *all*
  of them match the bundle;
* ``partial`` -- some but not all refs match;
* ``uncovered`` -- no ref matches (including obligations with no refs).

The evaluation never executes anything and never mutates the ledger: it reads
the bundle document from disk, matches, and reports
``{"obligations": [...], "total": N, "complete": n, "partial": p,
"uncovered": u}`` with obligations sorted by id and matched refs sorted, so
the same inputs always produce byte-identical output. Only the standard
library is used.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from codevanta.core.obligations import (
    MAX_OBLIGATION_RECORDS,
    obligations_from_payload,
)
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "COVERAGE_VERDICTS",
    "MAX_BUNDLE_INDEX_IDS",
    "VERDICT_COMPLETE",
    "VERDICT_PARTIAL",
    "VERDICT_UNCOVERED",
    "evaluate",
]

#: Verdict: every evidence ref of the obligation matched the bundle.
VERDICT_COMPLETE = "complete"
#: Verdict: some, but not all, evidence refs matched the bundle.
VERDICT_PARTIAL = "partial"
#: Verdict: no evidence ref matched (including obligations without refs).
VERDICT_UNCOVERED = "uncovered"

#: Every verdict coverage may report (frozen).
COVERAGE_VERDICTS: tuple[str, ...] = (
    VERDICT_COMPLETE,
    VERDICT_PARTIAL,
    VERDICT_UNCOVERED,
)

#: Cap on the number of distinct matchable ids collected from one bundle, so
#: even a hostile bundle keeps the index bounded.
MAX_BUNDLE_INDEX_IDS = 4_096


def _load_bundle_document(path: str | Path) -> dict[str, Any]:
    """Read and structurally validate an evidence-bundle document from disk."""
    bundle_path = Path(path).expanduser()
    try:
        text = bundle_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AnalysisError(f"cannot read bundle {bundle_path}: {exc}") from exc
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise AnalysisError(f"bundle {bundle_path} is not valid JSON: {exc}") from exc
    if not isinstance(document, Mapping):
        raise AnalysisError(f"bundle {bundle_path} is not a JSON object")
    entries = document.get("entries")
    if not isinstance(entries, Mapping):
        raise AnalysisError(f"bundle {bundle_path} is not an evidence bundle (no 'entries')")
    return dict(document)


def _collect_payload_ids(payload: Any, ids: set[str]) -> None:
    """Collect record ids from one entry payload into ``ids`` (bounded).

    Recognised shapes: a mapping with an ``id`` field (a single record), a
    mapping with an ``items`` list of records, and a bare list of records.
    Everything else contributes nothing.
    """
    if len(ids) >= MAX_BUNDLE_INDEX_IDS:
        return
    if isinstance(payload, Mapping):
        record_id = payload.get("id")
        if isinstance(record_id, str):
            ids.add(record_id)
        items = payload.get("items")
        if isinstance(items, list):
            for item in items:
                if len(ids) >= MAX_BUNDLE_INDEX_IDS:
                    return
                if isinstance(item, Mapping):
                    item_id = item.get("id")
                    if isinstance(item_id, str):
                        ids.add(item_id)
    elif isinstance(payload, list):
        for item in payload:
            if len(ids) >= MAX_BUNDLE_INDEX_IDS:
                return
            if isinstance(item, Mapping):
                item_id = item.get("id")
                if isinstance(item_id, str):
                    ids.add(item_id)


def _bundle_index(document: Mapping[str, Any]) -> frozenset[str]:
    """Collect every matchable token of a bundle document.

    The index holds entry names (the record *kinds*), entry digests (the
    recorded ``sha256`` values) and record ids found inside the entry
    payloads (top-level ``id`` fields and ``items``-list members), so an
    obligation's evidence ref can point at any of them. Collection stops at
    :data:`MAX_BUNDLE_INDEX_IDS` ids to stay bounded.
    """
    entries = document.get("entries")
    if not isinstance(entries, Mapping):
        return frozenset()
    tokens: set[str] = set()
    ids: set[str] = set()
    for name, record in entries.items():
        tokens.add(str(name))
        if isinstance(record, Mapping):
            digest = record.get("sha256")
            if isinstance(digest, str):
                tokens.add(digest)
            payload = record.get("payload")
            _collect_payload_ids(payload, ids)
    return frozenset(tokens | ids)


def evaluate(
    obligations_ledger: Mapping[str, Any],
    evidence_bundle_path: str | Path,
) -> dict[str, Any]:
    """Evaluate every obligation of ``obligations_ledger`` against one bundle.

    Args:
        obligations_ledger: An obligations ledger payload
            (``{"count": N, "items": [...]}``; malformed ledgers raise).
        evidence_bundle_path: Path to an evidence-bundle document (its
            ``entries`` table supplies names, digests and payloads).

    Returns:
        ``{"obligations": [...], "total": N, "complete": c, "partial": p,
        "uncovered": u, "evidence": {...}}`` where every obligation verdict
        is ``{"id", "verdict", "matched_evidence_ids"}``. Verdicts are sorted
        by obligation id and matched refs are sorted, so the output is
        deterministic and canonical.

    Raises:
        AnalysisError: When the ledger or the bundle is malformed or
            unreadable.
    """
    items = obligations_ledger.get("items", ())
    if isinstance(items, list) and len(items) > MAX_OBLIGATION_RECORDS:
        raise AnalysisError("obligations ledger exceeds the record budget")
    records = obligations_from_payload(obligations_ledger)
    document = _load_bundle_document(evidence_bundle_path)
    index = _bundle_index(document)
    verdicts: list[dict[str, Any]] = []
    for record in sorted(records, key=lambda item: item.id):
        refs = sorted(set(record.evidence_refs))
        matched = [ref for ref in refs if ref in index]
        if not refs or not matched:
            verdict = VERDICT_UNCOVERED
        elif len(matched) == len(refs):
            verdict = VERDICT_COMPLETE
        else:
            verdict = VERDICT_PARTIAL
        verdicts.append(
            {
                "id": record.id,
                "verdict": verdict,
                "matched_evidence_ids": matched,
            }
        )
    counts = {verdict: 0 for verdict in COVERAGE_VERDICTS}
    for item in verdicts:
        counts[item["verdict"]] += 1
    return {
        "obligations": verdicts,
        "total": len(verdicts),
        "complete": counts[VERDICT_COMPLETE],
        "partial": counts[VERDICT_PARTIAL],
        "uncovered": counts[VERDICT_UNCOVERED],
        "evidence": Evidence(
            source="ledger.coverage",
            method="deterministic_evidence_ref_match",
            confidence=Confidence.HIGH,
            detail=(
                "evidence_refs matched against bundle entry names, entry digests "
                "and payload record ids; verdict ordering is deterministic"
            ),
        ).to_dict(),
    }

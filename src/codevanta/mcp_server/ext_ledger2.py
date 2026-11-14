"""MCP tools for the ledger-v2 lane (no MCP imports).

Two tools: ``codevanta_obligations`` (the obligation ledger CRUD with CAS
mutations and read-back verification) and ``codevanta_coverage`` (per-
obligation verdicts against an evidence bundle). The registration import
lives in :mod:`codevanta.mcp_server.tools`; the MCP wrappers in
:mod:`codevanta.mcp_server.server` follow the existing tool-spec shape.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from codevanta.analysis.compare import is_bundle_document, load_document
from codevanta.core.coverage import evaluate as evaluate_coverage
from codevanta.core.obligations import (
    DEFAULT_OBLIGATION_AUTHORITY,
    DEFAULT_OBLIGATION_CONFIDENCE,
    DEFAULT_OBLIGATION_ENVIRONMENT,
    OBLIGATIONS_ENTRY_NAME,
    add_obligation,
    discharge_obligation,
    get_obligation,
    list_obligations,
    make_open_obligation,
    obligations_from_payload,
    obligations_to_payload,
    record_revision,
    remove_obligation,
    waive_obligation,
)
from codevanta.core.report import AnalysisError

__all__ = ["codevanta_coverage", "codevanta_obligations"]

#: Every action the obligations tool accepts.
_OBLIGATION_ACTIONS = ("list", "get", "add", "discharge", "waive", "remove")


def _load_obligations_payload(ledger_path: Path) -> dict[str, Any]:
    """Read an obligations ledger file, unwrapping a bundle's entry if present."""
    document = load_document(ledger_path)
    if is_bundle_document(document):
        entry = document["entries"].get(OBLIGATIONS_ENTRY_NAME)
        if not isinstance(entry, dict) or not isinstance(entry.get("payload"), dict):
            raise AnalysisError(
                f"{ledger_path} is a bundle without an '{OBLIGATIONS_ENTRY_NAME}' entry"
            )
        document = entry["payload"]
    return document


def _write_obligations_payload(ledger_path: Path, payload: dict[str, Any]) -> None:
    """Write a ledger payload as canonical JSON (sorted keys, trailing newline)."""
    try:
        ledger_path.write_text(
            json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except OSError as exc:
        raise AnalysisError(f"cannot write ledger {ledger_path}: {exc}") from exc


# ---- end of io helpers; the obligations tool follows -------------------------


def codevanta_obligations(
    action: str,
    ledger: str,
    obligation_id: str | None = None,
    question: str | None = None,
    required_authority: str = DEFAULT_OBLIGATION_AUTHORITY,
    required_confidence: str = DEFAULT_OBLIGATION_CONFIDENCE,
    required_environment: str = DEFAULT_OBLIGATION_ENVIRONMENT,
    recommended_probes: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    note: str | None = None,
    status: str | None = None,
    expected_revision: int | None = None,
) -> dict[str, Any]:
    """Manage the obligation ledger at ``ledger`` (a JSON file).

    ``action="list"`` returns the records (optionally filtered by ``status``);
    ``action="get"`` returns one record with its revision trail;
    ``action="add"`` appends one typed open record;
    ``action="discharge"`` / ``action="waive"`` close one id (CAS via
    ``expected_revision``); ``action="remove"`` deletes one id (same CAS
    guard). Ids are deterministic content digests, so restating a
    requirement is refused as a duplicate.
    """
    if action not in _OBLIGATION_ACTIONS:
        supported = ", ".join(_OBLIGATION_ACTIONS)
        raise AnalysisError(f"unknown action {action!r}; expected one of: {supported}")
    ledger_path = Path(ledger).expanduser()

    if action == "add":
        if not question:
            raise AnalysisError("adding an obligation requires question")
        existing: list[Any] = []
        base: dict[str, Any] | None = None
        if ledger_path.exists():
            base = _load_obligations_payload(ledger_path)
            existing = list(obligations_from_payload(base))
        record = make_open_obligation(
            question=question,
            required_authority=required_authority,
            required_confidence=required_confidence,
            required_environment=required_environment,
            recommended_probes=tuple(recommended_probes or ()),
            evidence_refs=tuple(evidence_refs or ()),
        )
        payload = add_obligation(base if existing else None, record)
        _write_obligations_payload(ledger_path, payload)
        return {
            "action": "add",
            "record": record.to_dict(),
            "count": int(payload["count"]),
        }

    if not ledger_path.exists():
        raise AnalysisError(f"ledger {ledger_path} does not exist")
    document = _load_obligations_payload(ledger_path)

    if action == "list":
        records = list_obligations(document, status=status)
        listing = obligations_to_payload(list(records))
        return {
            "action": "list",
            "count": int(listing["count"]),
            "items": listing["items"],
        }

    if action == "get":
        if not obligation_id:
            raise AnalysisError("getting an obligation requires obligation_id")
        record = get_obligation(document, obligation_id)
        return {
            "action": "get",
            "record": record.to_dict(),
            "revision": record_revision(record),
        }

    if not obligation_id:
        raise AnalysisError(f"{action} requires obligation_id")

    if action == "remove":
        payload = remove_obligation(document, obligation_id, expected_revision=expected_revision)
        _write_obligations_payload(ledger_path, payload)
        return {
            "action": "remove",
            "removed": obligation_id,
            "count": int(payload["count"]),
        }

    close = discharge_obligation if action == "discharge" else waive_obligation
    payload = close(
        document,
        obligation_id,
        note=note or "",
        expected_revision=expected_revision,
    )
    _write_obligations_payload(ledger_path, payload)
    return {
        "action": action,
        "obligation": obligation_id,
        "revision": record_revision(get_obligation(payload, obligation_id)),
        "count": int(payload["count"]),
    }


def codevanta_coverage(obligations_ledger: str, evidence_bundle: str) -> dict[str, Any]:
    """Evaluate obligation coverage against an evidence bundle.

    Deterministic and offline: each obligation's ``evidence_refs`` are
    matched against the bundle's entry names, entry digests and payload
    record ids, producing one ``complete``/``partial``/``uncovered`` verdict
    per obligation plus overall counts. Raises ``AnalysisError`` for
    unreadable or malformed inputs.
    """
    ledger_path = Path(obligations_ledger).expanduser()
    if not ledger_path.exists():
        raise AnalysisError(f"ledger {ledger_path} does not exist")
    payload = evaluate_coverage(_load_obligations_payload(ledger_path), evidence_bundle)
    return {"action": "coverage", **payload}


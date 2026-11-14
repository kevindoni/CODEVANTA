"""Tests for coverage evaluation (obligations vs evidence bundles).

Everything runs offline: bundles are built from in-memory payloads over a
committed sample binary, the CLI is driven through Typer's ``CliRunner`` and
the MCP surface through ``build_server().call_tool``. No gdb, no network.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from codevanta.analysis.evidence_bundle import build_bundle, write_bundle
from codevanta.cli.main import app
from codevanta.core.coverage import COVERAGE_VERDICTS, evaluate
from codevanta.core.obligations import (
    ObligationRecord,
    make_open_obligation,
    obligations_to_payload,
)
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools as mcp_tools
from codevanta.mcp_server.server import build_server

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "samples"
PE_SAMPLE = SAMPLES / "pe64_text.bin"

runner = CliRunner()


def _obligation(question: str, evidence_refs: tuple[str, ...]) -> ObligationRecord:
    return make_open_obligation(question=question, evidence_refs=evidence_refs)


def _write_bundle(tmp_path: Path, payloads: dict[str, Any]) -> Path:
    """Build a real evidence bundle (hashed like production) and write it."""
    subject = tmp_path / "sample.bin"
    subject.write_bytes(PE_SAMPLE.read_bytes())
    bundle = build_bundle(subject, payloads)
    return write_bundle(bundle, tmp_path / "bundle.json")


# ---- verdicts -----------------------------------------------------------------


def test_complete_partial_and_uncovered_verdicts(tmp_path: Path) -> None:
    bundle_path = _write_bundle(
        tmp_path,
        {
            "report": {"items": [{"id": "rec-1"}, {"id": "rec-2"}]},
            "cfg": {"blocks": 3},
        },
    )
    document = json.loads(bundle_path.read_text(encoding="utf-8"))
    report_digest = document["entries"]["report"]["sha256"]
    complete = _obligation("everything matches", ("report", "cfg", "rec-1", report_digest))
    partial = _obligation("some match", ("report", "nowhere"))
    uncovered = _obligation("nothing matches", ("strings",))
    no_refs = _obligation("no refs at all", ())
    payload = obligations_to_payload([complete, partial, uncovered, no_refs])

    result = evaluate(payload, bundle_path)
    verdicts = {item["id"]: item for item in result["obligations"]}
    assert verdicts[complete.id]["verdict"] == "complete"
    assert verdicts[complete.id]["matched_evidence_ids"] == sorted(
        ("report", "cfg", "rec-1", report_digest)
    )
    assert verdicts[partial.id]["verdict"] == "partial"
    assert verdicts[partial.id]["matched_evidence_ids"] == ["report"]
    assert verdicts[uncovered.id]["verdict"] == "uncovered"
    assert verdicts[uncovered.id]["matched_evidence_ids"] == []
    assert verdicts[no_refs.id]["verdict"] == "uncovered"
    assert (result["total"], result["complete"], result["partial"], result["uncovered"]) == (
        4,
        1,
        1,
        2,
    )
    assert result["evidence"]["source"] == "ledger.coverage"


def test_evaluation_is_deterministic(tmp_path: Path) -> None:
    bundle_path = _write_bundle(tmp_path, {"report": {}, "cfg": {}})
    first = _obligation("one", ("report",))
    second = _obligation("two", ("cfg",))
    payload = obligations_to_payload([first, second])
    a = evaluate(payload, bundle_path)
    b = evaluate(payload, bundle_path)
    assert a == b
    assert [item["id"] for item in a["obligations"]] == sorted((first.id, second.id))
    assert COVERAGE_VERDICTS == ("complete", "partial", "uncovered")


def test_unknowns_section_records_are_matchable(tmp_path: Path) -> None:
    """An obligation can cite an unknown record id inside the bundle."""
    unknown = make_open_obligation(question="is the entry point a function?")
    subject = tmp_path / "sample.bin"
    subject.write_bytes(PE_SAMPLE.read_bytes())
    bundle = build_bundle(subject, {"report": {}}, unknowns=[unknown])
    bundle_path = write_bundle(bundle, tmp_path / "with-unknowns.json")
    obligation = _obligation("explain the entry point", (unknown.id,))
    result = evaluate(obligations_to_payload([obligation]), bundle_path)
    assert result["obligations"][0]["verdict"] == "complete"


# ---- malformed inputs ----------------------------------------------------------


def test_malformed_ledger_and_bundle_raise(tmp_path: Path) -> None:
    bundle_path = _write_bundle(tmp_path, {"report": {}})
    obligation = _obligation("q", ("report",))
    with pytest.raises(AnalysisError):
        evaluate({"count": 0}, bundle_path)
    with pytest.raises(AnalysisError):
        evaluate(obligations_to_payload([obligation]), tmp_path / "missing.json")
    not_a_bundle = tmp_path / "not-a-bundle.json"
    not_a_bundle.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    with pytest.raises(AnalysisError):
        evaluate(obligations_to_payload([obligation]), not_a_bundle)
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(AnalysisError):
        evaluate(obligations_to_payload([obligation]), broken)


# ---- CLI: codevanta obligations verify -----------------------------------------


def test_cli_verify_reports_verdicts(tmp_path: Path) -> None:
    bundle_path = _write_bundle(tmp_path, {"report": {"items": [{"id": "rec-1"}]}})
    complete = _obligation("paid", ("report",))
    uncovered = _obligation("unpaid", ("strings",))
    ledger = tmp_path / "obligations.json"
    ledger.write_text(
        json.dumps(obligations_to_payload([complete, uncovered])), encoding="utf-8"
    )
    as_json = runner.invoke(
        app, ["obligations", "verify", str(ledger), str(bundle_path), "--format", "json"]
    )
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.output)
    assert payload["total"] == 2
    assert payload["complete"] == 1
    assert payload["uncovered"] == 1

    as_text = runner.invoke(app, ["obligations", "verify", str(ledger), str(bundle_path)])
    assert as_text.exit_code == 0
    assert "complete" in as_text.output
    assert "uncovered" in as_text.output

    bad = runner.invoke(app, ["obligations", "verify", str(ledger), str(tmp_path / "nope.json")])
    assert bad.exit_code == 2


# ---- MCP: codevanta_coverage ----------------------------------------------------


def test_mcp_coverage_tool(tmp_path: Path) -> None:
    bundle_path = _write_bundle(tmp_path, {"report": {}})
    obligation = _obligation("paid", ("report",))
    ledger = tmp_path / "obligations.json"
    ledger.write_text(json.dumps(obligations_to_payload([obligation])), encoding="utf-8")

    result = asyncio.run(
        build_server().call_tool(
            "codevanta_coverage",
            {"obligations_ledger": str(ledger), "evidence_bundle": str(bundle_path)},
        )
    )
    structured = getattr(result, "structuredContent", None) or json.loads(
        result.content[0].text
    )
    assert structured["action"] == "coverage"
    assert structured["complete"] == 1
    assert structured["total"] == 1

    direct = mcp_tools.codevanta_coverage(str(ledger), str(bundle_path))
    assert direct["obligations"][0]["verdict"] == "complete"

    with pytest.raises(AnalysisError):
        mcp_tools.codevanta_coverage(str(tmp_path / "nope.json"), str(bundle_path))


# ---- bundle-index shapes and bounds -------------------------------------------


def test_bundle_payload_shapes_are_indexed(tmp_path: Path) -> None:
    """Entry names, digests, single-record ids, items ids and list payloads."""
    document = {
        "manifest": {"tool_version": "t"},
        "entries": {
            "report": {
                "sha256": "a" * 64,
                "payload": {"id": "rec-solo", "k": 1},
            },
            "listy": {
                "sha256": "b" * 64,
                "payload": [{"id": "rec-a"}, {"id": "rec-b"}, "not-a-record"],
            },
            "plain": {
                "sha256": "c" * 64,
                "payload": {"items": "not-a-list", "n": 0},
            },
            "bare": "not-even-a-record",
        },
    }
    bundle_path = tmp_path / "handmade.json"
    bundle_path.write_text(json.dumps(document), encoding="utf-8")
    everything = _obligation(
        "all", ("report", "listy", "plain", "bare", "rec-solo", "rec-a", "rec-b", "a" * 64)
    )
    result = evaluate(obligations_to_payload([everything]), bundle_path)
    assert result["complete"] == 1
    assert result["obligations"][0]["matched_evidence_ids"] == sorted(
        ("report", "listy", "plain", "bare", "rec-solo", "rec-a", "rec-b", "a" * 64)
    )


def test_malformed_bundle_documents_raise(tmp_path: Path) -> None:
    no_entries = tmp_path / "no-entries.json"
    no_entries.write_text(json.dumps({"manifest": {}}), encoding="utf-8")
    with pytest.raises(AnalysisError):
        evaluate({"count": 0, "items": []}, no_entries)
    bad_entries = tmp_path / "bad-entries.json"
    bad_entries.write_text(json.dumps({"manifest": {}, "entries": 5}), encoding="utf-8")
    with pytest.raises(AnalysisError):
        evaluate({"count": 0, "items": []}, bad_entries)


def test_over_budget_ledger_is_rejected(tmp_path: Path) -> None:
    bundle_path = _write_bundle(tmp_path, {"report": {}})
    oversized = {"count": 257, "items": [1] * 257}
    with pytest.raises(AnalysisError):
        evaluate(oversized, bundle_path)


def test_bundle_id_index_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codevanta.core import coverage as coverage_module

    monkeypatch.setattr(coverage_module, "MAX_BUNDLE_INDEX_IDS", 2)
    bundle_path = _write_bundle(tmp_path, {"report": {"items": [{"id": f"r{i}"} for i in range(5)]}})
    paid = _obligation("cap holds", ("report",))
    result = evaluate(obligations_to_payload([paid]), bundle_path)
    assert result["complete"] == 1
    ids = coverage_module._bundle_index(
        {"entries": {"e": {"sha256": "d" * 64, "payload": {"items": [{"id": f"x{i}"} for i in range(6)]}}}}
    )
    assert len([token for token in ids if token.startswith("x")]) == 2
    assert coverage_module._bundle_index({"entries": "not-a-mapping"}) == frozenset()


def test_bundle_document_edge_shapes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codevanta.core import coverage as coverage_module

    not_an_object = tmp_path / "array.json"
    not_an_object.write_text(json.dumps([1, 2]), encoding="utf-8")
    with pytest.raises(AnalysisError):
        evaluate({"count": 0, "items": []}, not_an_object)

    # A mapping entry without a payload contributes its name/digest only.
    no_payload = tmp_path / "no-payload.json"
    no_payload.write_text(
        json.dumps(
            {
                "manifest": {},
                "entries": {"naked": {"sha256": "e" * 64}},
            }
        ),
        encoding="utf-8",
    )
    paid = _obligation("naked entry", ("naked", "e" * 64))
    result = evaluate(obligations_to_payload([paid]), no_payload)
    assert result["complete"] == 1

    # The id cap stops collection mid-list and between entries.
    monkeypatch.setattr(coverage_module, "MAX_BUNDLE_INDEX_IDS", 3)
    ids: set[str] = set()
    coverage_module._collect_payload_ids(
        [{"id": f"a{i}"} for i in range(6)], ids
    )
    assert len(ids) == 3
    full = {"r1", "r2", "r3"}
    coverage_module._collect_payload_ids({"id": "r0", "items": [{"id": "r9"}]}, full)
    assert full == {"r1", "r2", "r3"}
    coverage_module._collect_payload_ids("just-a-string", full)
    assert full == {"r1", "r2", "r3"}



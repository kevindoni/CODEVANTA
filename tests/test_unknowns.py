"""Tests for the residual-unknown ledger and its bundle/CLI/MCP surfaces.

Everything runs offline: ledgers are hand-made JSON payloads, bundles are
built from in-memory payloads over a committed sample binary, and the CLI is
driven through Typer's ``CliRunner``. No gdb, no network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from codevanta.analysis.evidence_bundle import (
    build_bundle,
    read_bundle,
    verify_bundle,
    write_bundle,
)
from codevanta.cli.main import app
from codevanta.core.report import AnalysisError
from codevanta.core.unknowns import (
    DEFAULT_UNKNOWN_SEVERITY,
    MAX_REVISIONS_PER_RECORD,
    UNKNOWN_ENTRY_NAME,
    UNKNOWN_SEVERITIES,
    UNKNOWN_STATUSES,
    LedgerConflictError,
    make_open_unknown,
    open_unknowns,
    records_from_payload,
    records_to_payload,
    resolve_record,
    resolve_unknowns,
    unknown_id,
    unknowns_from_bundle,
)
from codevanta.mcp_server import tools as mcp_tools

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "samples"
PE_SAMPLE = SAMPLES / "pe64_text.bin"

runner = CliRunner()


def _record(domain: str = "cfg", summary: str = "entry point is a guess"):
    return make_open_unknown(domain=domain, summary=summary)


def _ledger(*records: Any) -> dict[str, Any]:
    return records_to_payload(list(records))


# ---- deterministic ids -------------------------------------------------------


def test_id_is_deterministic_and_content_bound() -> None:
    first = unknown_id("cfg", "entry point is a guess")
    second = unknown_id("cfg", "entry point is a guess")
    assert first == second
    assert first.startswith("unk-")
    assert unknown_id("cfg", "a different question") != first
    assert unknown_id("strings", "entry point is a guess") != first
    # Evidence refs are order-insensitive (sorted before hashing).
    assert unknown_id("cfg", "s", ["b", "a"]) == unknown_id("cfg", "s", ["a", "b"])


def test_make_open_unknown_validates_input() -> None:
    assert _record().severity == DEFAULT_UNKNOWN_SEVERITY
    assert _record().status == "open"
    assert _record().resolution is None
    with pytest.raises(AnalysisError):
        make_open_unknown(domain="cfg", summary="   ")
    with pytest.raises(AnalysisError):
        make_open_unknown(domain="", summary="x")
    with pytest.raises(AnalysisError):
        make_open_unknown(domain="cfg", summary="x", severity="catastrophic")
    with pytest.raises(AnalysisError):
        make_open_unknown(domain="cfg", summary="x", evidence_refs=["a", "a"])
    long_domain = "d" * 65
    with pytest.raises(AnalysisError):
        make_open_unknown(domain=long_domain, summary="x")


def test_severity_and_status_tables_are_frozen() -> None:
    assert UNKNOWN_SEVERITIES == ("low", "medium", "high")
    assert UNKNOWN_STATUSES == ("open", "resolved")
    assert DEFAULT_UNKNOWN_SEVERITY in UNKNOWN_SEVERITIES


# ---- lifecycle: open -> resolved --------------------------------------------


def test_resolve_record_keeps_identity_and_records_note() -> None:
    record = make_open_unknown(
        domain="cfg", summary="loop not explored", evidence_refs=["report.cfg"]
    )
    resolved = resolve_record(record, note="looked at it, benign")
    assert resolved.id == record.id
    assert resolved.domain == record.domain
    assert resolved.summary == record.summary
    assert resolved.evidence_refs == record.evidence_refs
    assert resolved.status == "resolved"
    assert resolved.resolution == "looked at it, benign"
    with pytest.raises(AnalysisError):
        resolve_record(resolved)


def test_resolve_unknowns_updates_only_the_named_ids() -> None:
    one = _record("cfg", "first")
    two = _record("strings", "second")
    ledger = _ledger(one, two)
    updated = resolve_unknowns(ledger, [one.id], note="done")
    resolved_ids = {item["id"] for item in updated["items"] if item["status"] == "resolved"}
    assert resolved_ids == {one.id}
    assert two.id in {item["id"] for item in updated["items"]}
    # The input ledger is never mutated (records come back sorted by id).
    assert open_unknowns(ledger) == tuple(sorted((one, two), key=lambda record: record.id))
    with pytest.raises(AnalysisError):
        resolve_unknowns(ledger, ["unk-does-not-exist"])
    with pytest.raises(AnalysisError):
        resolve_unknowns(updated, [one.id])


def test_open_unknowns_filters_and_sorts() -> None:
    one = _record("cfg", "first")
    two = _record("strings", "second")
    ledger = resolve_unknowns(_ledger(one, two), [one.id])
    assert [record.id for record in open_unknowns(ledger)] == [two.id]
    resolved = records_from_payload(ledger)
    assert [record.id for record in resolved] == sorted(record.id for record in resolved)


# ---- payload round trips and validation -------------------------------------


def test_payload_round_trip_is_json_safe_and_canonical() -> None:
    record = make_open_unknown(
        domain="diff",
        summary="addresses moved",
        severity="low",
        evidence_refs=["report.functions", "bundle.report"],
    )
    payload = records_to_payload([record])
    assert payload["count"] == len(payload["items"])
    text = json.dumps(payload, allow_nan=False, sort_keys=True)
    assert json.loads(text) == payload
    parsed = records_from_payload(json.loads(text))
    assert parsed == (record,)


def test_payload_rejects_tampered_ids_and_duplicates() -> None:
    record = _record()
    payload = _ledger(record)
    tampered = json.loads(json.dumps(payload))
    tampered["items"][0]["id"] = "unk-0000000000000000"
    with pytest.raises(AnalysisError):
        records_from_payload(tampered)
    with pytest.raises(AnalysisError):
        records_to_payload([record, _record()])
    broken = {"items": [{"domain": "cfg", "summary": "x", "severity": "nope"}]}
    with pytest.raises(AnalysisError):
        records_from_payload(broken)
    with pytest.raises(AnalysisError):
        records_from_payload({"count": 1})
    with pytest.raises(AnalysisError):
        records_from_payload("not-a-mapping")


# ---- evidence bundle integration ---------------------------------------------


def test_bundle_carries_an_unknowns_section(tmp_path: Path) -> None:
    records = [
        make_open_unknown(
            domain="cfg",
            summary="entry-point CFG could not be built",
            severity="low",
            evidence_refs=["report.cfg"],
        ),
        make_open_unknown(domain="strings", summary="one non-UTF-8 run skipped"),
    ]
    subject = tmp_path / "sample.bin"
    subject.write_bytes(PE_SAMPLE.read_bytes())
    bundle = build_bundle(subject, {"report": {"functions": []}}, unknowns=records)
    assert UNKNOWN_ENTRY_NAME in bundle.entries
    assert verify_bundle(bundle).passed

    path = write_bundle(bundle, tmp_path / "bundle.json")
    reread = read_bundle(path)
    assert unknowns_from_bundle(reread) == tuple(sorted(records, key=lambda record: record.id))

    # The section hashes like any other entry: flipping one byte is detected.
    document = json.loads(path.read_text(encoding="utf-8"))
    document["entries"][UNKNOWN_ENTRY_NAME]["payload"]["items"][0]["summary"] = "tampered"
    damaged = tmp_path / "damaged.json"
    damaged.write_text(json.dumps(document), encoding="utf-8")
    assert verify_bundle(read_bundle(damaged)).passed is False


def test_bundle_without_unknowns_reads_empty(tmp_path: Path) -> None:
    subject = tmp_path / "sample.bin"
    subject.write_bytes(PE_SAMPLE.read_bytes())
    bundle = build_bundle(subject, {"report": {}})
    assert unknowns_from_bundle(bundle) == ()


def test_bundle_unknowns_conflict_is_rejected(tmp_path: Path) -> None:
    subject = tmp_path / "sample.bin"
    subject.write_bytes(PE_SAMPLE.read_bytes())
    with pytest.raises(AnalysisError):
        build_bundle(subject, {"unknowns": {"count": 0, "items": []}}, unknowns=[])


# ---- MCP tools.unknowns ------------------------------------------------------


def test_mcp_unknowns_lifecycle(tmp_path: Path) -> None:
    from codevanta.mcp_server import tools

    ledger = str(tmp_path / "ledger.json")
    opened = tools.unknowns(
        "open", ledger, domain="cfg", summary="entry CFG missing", severity="low"
    )
    record_id = opened["record"]["id"]
    assert opened["count"] == 1

    listed = tools.unknowns("list", ledger)
    assert listed["count"] == 1
    assert listed["items"][0]["status"] == "open"

    resolved = tools.unknowns("resolve", ledger, unknown_id=record_id, note="checked")
    assert resolved["resolved"] == record_id
    assert tools.unknowns("list", ledger, status="open")["count"] == 0
    assert tools.unknowns("list", ledger, status="resolved")["count"] == 1

    with pytest.raises(AnalysisError):
        tools.unknowns("frobnicate", ledger)
    with pytest.raises(AnalysisError):
        tools.unknowns("open", ledger, domain="cfg", summary=None)
    with pytest.raises(AnalysisError):
        tools.unknowns("open", ledger, domain="cfg", summary="entry CFG missing")
    with pytest.raises(AnalysisError):
        tools.unknowns("resolve", ledger, unknown_id="unk-ffffffffffffffff")
    with pytest.raises(AnalysisError):
        tools.unknowns("list", str(tmp_path / "absent.json"))


def test_mcp_unknowns_list_reads_bundle_section(tmp_path: Path) -> None:
    from codevanta.mcp_server import tools

    subject = tmp_path / "sample.bin"
    subject.write_bytes(PE_SAMPLE.read_bytes())
    record = make_open_unknown(domain="diff", summary="nothing matched")
    bundle_path = write_bundle(
        build_bundle(subject, {"report": {}}, unknowns=[record]),
        tmp_path / "bundle.json",
    )
    listed = tools.unknowns("list", str(bundle_path))
    assert listed["count"] == 1
    assert listed["items"][0]["id"] == record.id


# ---- CLI: codevanta unknowns -------------------------------------------------


def test_cli_unknowns_lifecycle(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.json"
    opened = runner.invoke(
        app,
        ["unknowns", "open", str(ledger), "--domain", "cfg", "--summary", "entry CFG missing"],
    )
    assert opened.exit_code == 0, opened.output
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    record_id = payload["items"][0]["id"]
    assert record_id.startswith("unk-")

    listed = runner.invoke(app, ["unknowns", "list", str(ledger), "--format", "json"])
    assert listed.exit_code == 0
    listed_payload = json.loads(listed.output)
    assert listed_payload["count"] == 1
    assert listed_payload["items"][0]["id"] == record_id
    # The text table names the status even when the Id column is clipped.
    text_listed = runner.invoke(app, ["unknowns", "list", str(ledger)])
    assert text_listed.exit_code == 0
    assert "open" in text_listed.output

    resolved = runner.invoke(
        app,
        ["unknowns", "resolve", str(ledger), "--id", record_id, "--note", "verified"],
    )
    assert resolved.exit_code == 0, resolved.output
    after = json.loads(ledger.read_text(encoding="utf-8"))
    assert after["items"][0]["status"] == "resolved"
    assert after["items"][0]["resolution"] == "verified"

    empty = runner.invoke(app, ["unknowns", "list", str(ledger), "--status", "open"])
    assert empty.exit_code == 0
    assert "0" in empty.output


def test_cli_unknowns_json_format_and_errors(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.json"
    opened = runner.invoke(
        app,
        [
            "unknowns",
            "open",
            str(ledger),
            "--domain",
            "diff",
            "--summary",
            "nothing matched",
            "--severity",
            "high",
            "--evidence",
            "report.functions",
            "--evidence",
            "bundle.report",
            "--format",
            "json",
        ],
    )
    assert opened.exit_code == 0, opened.output
    opened_payload = json.loads(opened.output)
    assert opened_payload["action"] == "open"
    assert opened_payload["record"]["severity"] == "high"
    assert opened_payload["record"]["evidence_refs"] == ["report.functions", "bundle.report"]

    listed = runner.invoke(app, ["unknowns", "list", str(ledger), "--format", "json"])
    assert listed.exit_code == 0
    assert json.loads(listed.output)["count"] == 1

    bad_status = runner.invoke(app, ["unknowns", "list", str(ledger), "--status", "archived"])
    assert bad_status.exit_code == 2
    no_id = runner.invoke(app, ["unknowns", "resolve", str(ledger)])
    assert no_id.exit_code == 2
    no_domain = runner.invoke(app, ["unknowns", "open", str(ledger), "--summary", "x"])
    assert no_domain.exit_code == 2
    dup = runner.invoke(
        app,
        [
            "unknowns",
            "open",
            str(ledger),
            "--domain",
            "diff",
            "--summary",
            "nothing matched",
            "--severity",
            "high",
            "--evidence",
            "report.functions",
            "--evidence",
            "bundle.report",
        ],
    )
    assert dup.exit_code == 2
    assert "duplicate" in dup.output


# ---- ledger v2: CLI history and CAS resolve -----------------------------------


def test_cli_history_prints_the_revision_trail(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.json"
    opened = runner.invoke(
        app,
        ["unknowns", "open", str(ledger), "--domain", "cfg", "--summary", "trail test"],
    )
    assert opened.exit_code == 0, opened.output
    record_id = json.loads(ledger.read_text(encoding="utf-8"))["items"][0]["id"]

    as_json = runner.invoke(
        app, ["unknowns", "history", str(ledger), "--id", record_id, "--format", "json"]
    )
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.output)
    assert payload["id"] == record_id
    assert payload["count"] == 1
    assert payload["revisions"][0]["action"] == "open"
    assert payload["revisions"][0]["revision"] == 1
    assert payload["evidence"]["source"] == "ledger.revision"

    as_text = runner.invoke(app, ["unknowns", "history", str(ledger), "--id", record_id])
    assert as_text.exit_code == 0
    assert "open" in as_text.output
    assert "revision" in as_text.output.lower()

    missing = runner.invoke(app, ["unknowns", "history", str(ledger)])
    assert missing.exit_code == 2
    unknown_id_arg = runner.invoke(app, ["unknowns", "history", str(ledger), "--id", "unk-nope"])
    assert unknown_id_arg.exit_code == 2


def test_cli_resolve_expected_revision_cas(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.json"
    opened = runner.invoke(
        app,
        ["unknowns", "open", str(ledger), "--domain", "cfg", "--summary", "cas test"],
    )
    assert opened.exit_code == 0, opened.output
    record_id = json.loads(ledger.read_text(encoding="utf-8"))["items"][0]["id"]

    # A stale expectation exits 2 and leaves the ledger untouched.
    before = ledger.read_text(encoding="utf-8")
    conflict = runner.invoke(
        app,
        [
            "unknowns",
            "resolve",
            str(ledger),
            "--id",
            record_id,
            "--expected-revision",
            "7",
        ],
    )
    assert conflict.exit_code == 2
    assert "current revision 1" in conflict.output
    assert ledger.read_text(encoding="utf-8") == before

    # The matching expectation resolves and the trail grows to two revisions.
    resolved = runner.invoke(
        app,
        [
            "unknowns",
            "resolve",
            str(ledger),
            "--id",
            record_id,
            "--note",
            "done",
            "--expected-revision",
            "1",
        ],
    )
    assert resolved.exit_code == 0, resolved.output
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    assert payload["items"][0]["status"] == "resolved"
    assert [rev["revision"] for rev in payload["items"][0]["revisions"]] == [1, 2]


def test_mcp_unknowns_history_and_cas(tmp_path: Path) -> None:
    ledger = str(tmp_path / "ledger.json")
    opened = mcp_tools.unknowns("open", ledger, domain="cfg", summary="mcp history")
    record_id = opened["record"]["id"]

    history = mcp_tools.unknowns("history", ledger, unknown_id=record_id)
    assert history["action"] == "history"
    assert history["count"] == 1
    assert history["revisions"][0]["action"] == "open"

    with pytest.raises(LedgerConflictError):
        mcp_tools.unknowns("resolve", ledger, unknown_id=record_id, expected_revision=3)
    resolved = mcp_tools.unknowns(
        "resolve", ledger, unknown_id=record_id, expected_revision=1, note="ok"
    )
    assert resolved["revision"] == 2
    with pytest.raises(AnalysisError):
        mcp_tools.unknowns("explode", ledger)


# ---- ledger v2: payload validation matrix -------------------------------------


def _bad_unknown(**mutation: Any) -> dict[str, Any]:
    """A one-record ledger with one field replaced by a malformed value."""
    record = make_open_unknown(domain="cfg", summary="malformed matrix")
    payload = json.loads(json.dumps(records_to_payload([record])))
    payload["items"][0].update(mutation)
    return payload


def test_parse_rejects_malformed_revision_trails() -> None:
    with pytest.raises(AnalysisError):
        records_from_payload(_bad_unknown(revisions="not-a-list"))
    with pytest.raises(AnalysisError):
        records_from_payload(_bad_unknown(revisions=["not-an-object"]))
    with pytest.raises(AnalysisError):
        records_from_payload(
            _bad_unknown(revisions=[{"revision": 0, "at": "t", "action": "open", "state": {}}])
        )
    with pytest.raises(AnalysisError):
        records_from_payload(
            _bad_unknown(
                revisions=[{"revision": True, "at": "t", "action": "open", "state": {}}]
            )
        )
    with pytest.raises(AnalysisError):
        records_from_payload(
            _bad_unknown(
                revisions=[
                    {"revision": 1, "at": "t", "action": "open", "state": {}},
                    {"revision": 1, "at": "t", "action": "resolve", "state": {}},
                ]
            )
        )
    with pytest.raises(AnalysisError):
        records_from_payload(
            _bad_unknown(revisions=[{"revision": 1, "at": "  ", "action": "open", "state": {}}])
        )
    with pytest.raises(AnalysisError):
        records_from_payload(
            _bad_unknown(revisions=[{"revision": 1, "at": "t", "action": "explode", "state": {}}])
        )
    with pytest.raises(AnalysisError):
        records_from_payload(
            _bad_unknown(revisions=[{"revision": 1, "at": "t", "action": "open"}])
        )
    with pytest.raises(AnalysisError):
        records_from_payload(
            _bad_unknown(
                revisions=[{"revision": 1, "at": "t", "action": "open", "state": {}, "note": "n" * 501}]
            )
        )
    with pytest.raises(AnalysisError):
        records_from_payload(_bad_unknown(revisions_truncated="many"))
    with pytest.raises(AnalysisError):
        records_from_payload(_bad_unknown(revisions_truncated=-1))
    with pytest.raises(AnalysisError):
        records_from_payload(
            _bad_unknown(revisions=[{"revision": 3, "at": "t", "action": "open", "state": {}}])
        )


def test_resolve_refuses_over_long_notes_and_over_sized_trails() -> None:
    record = make_open_unknown(domain="cfg", summary="bounds")
    ledger = records_to_payload([record])
    with pytest.raises(AnalysisError):
        resolve_unknowns(ledger, [record.id], note="n" * 501)
    too_many = [
        {"revision": i + 1, "at": "t", "action": "open", "state": {}}
        for i in range(MAX_REVISIONS_PER_RECORD + 1)
    ]
    with pytest.raises(AnalysisError):
        records_from_payload(_bad_unknown(revisions=too_many))


def test_parse_rejects_malformed_unknown_items() -> None:
    with pytest.raises(AnalysisError):
        records_from_payload({"count": 1, "items": [42]})
    with pytest.raises(AnalysisError):
        records_from_payload({"count": 257, "items": [1] * 257})
    assert records_from_payload({"count": 0, "items": []}) == ()


def test_unknown_ledger_over_budget_is_refused() -> None:
    records = [make_open_unknown(domain="cfg", summary=f"question {i}") for i in range(257)]
    with pytest.raises(AnalysisError):
        records_to_payload(records)


def test_find_record_and_truncated_marker_round_trip() -> None:
    from codevanta.core.unknowns import MAX_REVISIONS_PER_RECORD, find_record

    record = make_open_unknown(domain="cfg", summary="marker round trip")
    ledger = records_to_payload([record])
    payload = ledger
    for _ in range(MAX_REVISIONS_PER_RECORD + 1):
        record_id = record.id
        payload = resolve_unknowns(payload, [record_id])
        parsed = records_from_payload(payload)
        payload = records_to_payload(
            [
                item
                if item.id != record_id
                else type(item)(
                    id=item.id,
                    domain=item.domain,
                    severity=item.severity,
                    status="open",
                    summary=item.summary,
                    evidence_refs=item.evidence_refs,
                    resolution=None,
                    revisions=item.revisions,
                    revisions_truncated=item.revisions_truncated,
                )
                for item in parsed
            ]
        )
    final = find_record(payload, record.id)
    assert final.revisions_truncated >= 1
    assert len(final.revisions) == MAX_REVISIONS_PER_RECORD
    # The marker round-trips through JSON exactly.
    reread = records_from_payload(json.loads(json.dumps(payload)))
    assert reread == records_from_payload(payload)

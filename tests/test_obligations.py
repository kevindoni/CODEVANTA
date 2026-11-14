"""Tests for the obligation ledger and the ledger-v2 revision discipline.

Everything runs offline: ledgers are hand-made JSON payloads, bundles are
built from in-memory payloads over a committed sample binary, the CLI is
driven through Typer's ``CliRunner`` and the MCP surface through
``build_server().call_tool``. No gdb, no network.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from codevanta.cli.main import app
from codevanta.core.obligations import (
    OBLIGATION_ACTIONS,
    OBLIGATION_AUTHORITIES,
    OBLIGATION_CONFIDENCES,
    OBLIGATION_ENVIRONMENTS,
    OBLIGATION_STATUSES,
    ObligationRecord,
    discharge_obligation,
    get_obligation,
    list_obligations,
    make_open_obligation,
    obligation_id,
    obligations_from_payload,
    obligations_to_payload,
    record_revision,
    remove_obligation,
    waive_obligation,
)
from codevanta.core.report import AnalysisError
from codevanta.core.unknowns import (
    MAX_REVISIONS_PER_RECORD,
    LedgerConflictError,
    make_open_unknown,
    records_from_payload,
    resolve_record,
    resolve_unknowns,
    unknown_id,
)
from codevanta.mcp_server import tools as mcp_tools
from codevanta.mcp_server.server import build_server

runner = CliRunner()


def _obligation(question: str = "is the entry point a function?", **kwargs: Any) -> ObligationRecord:
    return make_open_obligation(question=question, **kwargs)


def _ledger(*records: ObligationRecord) -> dict[str, Any]:
    return obligations_to_payload(list(records))


# ---- deterministic ids and frozen tables -------------------------------------


def test_obligation_id_is_deterministic_and_content_bound() -> None:
    first = obligation_id("is the entry point a function?")
    assert first == obligation_id("is the entry point a function?")
    assert first.startswith("ob-")
    assert obligation_id("a different question") != first
    # The lifecycle is not hashed: closing an obligation keeps its identity.
    record = _obligation()
    closed = obligations_from_payload(
        discharge_obligation(_ledger(record), record.id, note="done")
    )[0]
    assert closed.id == record.id


def test_enum_tables_are_frozen() -> None:
    assert OBLIGATION_AUTHORITIES == ("parsed", "computed", "verified")
    assert OBLIGATION_CONFIDENCES == ("low", "medium", "high")
    assert OBLIGATION_ENVIRONMENTS == ("host", "device", "network")
    assert OBLIGATION_STATUSES == ("open", "discharged", "waived")
    assert OBLIGATION_ACTIONS == ("add", "discharge", "waive")


def test_make_open_obligation_validates_input() -> None:
    record = _obligation(
        required_authority="verified",
        required_confidence="high",
        required_environment="device",
        recommended_probes=["walk xrefs"],
        evidence_refs=["report.cfg"],
    )
    assert record.status == "open"
    assert record.resolution is None
    assert record.revisions_truncated == 0
    assert record_revision(record) == 1
    assert record.revisions[0].action == "add"
    assert record.revisions[0].state["status"] == "open"
    for kwargs in (
        {"question": "   "},
        {"question": "q", "required_authority": "guessed"},
        {"question": "q", "required_confidence": "absolute"},
        {"question": "q", "required_environment": "cluster"},
        {"question": "q", "recommended_probes": ["a", "a"]},
        {"question": "q", "recommended_probes": [f"p{i}" for i in range(9)]},
        {"question": "q", "evidence_refs": ["a", "a"]},
    ):
        with pytest.raises(AnalysisError):
            make_open_obligation(**kwargs)


# ---- CAS: expected_revision semantics ----------------------------------------


def test_cas_conflict_names_the_current_revision() -> None:
    record = _obligation()
    ledger = _ledger(record)
    with pytest.raises(LedgerConflictError) as excinfo:
        discharge_obligation(ledger, record.id, expected_revision=99)
    message = str(excinfo.value)
    assert "current revision 1" in message
    assert "expected 99" in message
    with pytest.raises(LedgerConflictError):
        waive_obligation(ledger, record.id, note="n", expected_revision=2)
    with pytest.raises(LedgerConflictError):
        remove_obligation(ledger, record.id, expected_revision=7)


def test_cas_match_and_blind_write_both_mutate() -> None:
    record = _obligation()
    ledger = _ledger(record)
    discharged = discharge_obligation(ledger, record.id, note="met", expected_revision=1)
    assert get_obligation(discharged, record.id).status == "discharged"
    # A blind write (expected_revision=None) mutates like the historical API.
    again = discharge_obligation(_ledger(record), record.id)
    assert get_obligation(again, record.id).status == "discharged"


def test_closed_obligations_cannot_be_closed_twice() -> None:
    record = _obligation()
    waived = waive_obligation(_ledger(record), record.id, note="given up")
    with pytest.raises(AnalysisError):
        discharge_obligation(waived, record.id)
    with pytest.raises(AnalysisError):
        waive_obligation(waived, record.id, note="again")


# ---- revision immutability ----------------------------------------------------


def test_revisions_preserve_old_snapshots() -> None:
    record = _obligation(evidence_refs=["report.cfg"])
    ledger = _ledger(record)
    discharged = discharge_obligation(ledger, record.id, note="matched report.cfg")
    history = get_obligation(discharged, record.id).revisions
    assert [revision.revision for revision in history] == [1, 2]
    assert [revision.action for revision in history] == ["add", "discharge"]
    # The old snapshot is untouched: revision 1 still says "open".
    assert history[0].state["status"] == "open"
    assert history[0].note is None
    assert history[1].state["status"] == "discharged"
    assert history[1].note == "matched report.cfg"
    # And the parsed payload round-trips the trail exactly.
    reread = obligations_from_payload(json.loads(json.dumps(discharged)))
    assert reread[0].revisions == history


def _readd_closed(payload: dict[str, Any], record_id: str) -> dict[str, Any]:
    """Re-open a closed obligation by rewriting its lifecycle fields.

    The ledger stores frozen records; this helper simulates an external
    "re-open" so the pruning test can drive many mutations in a row without
    growing the ledger. The id is content-derived from the requirement triple,
    which the re-open keeps, so the identity stays stable.
    """
    records = list(obligations_from_payload(payload))
    target = next(record for record in records if record.id == record_id)
    reopened = ObligationRecord(
        id=target.id,
        question=target.question,
        required_authority=target.required_authority,
        required_confidence=target.required_confidence,
        required_environment=target.required_environment,
        recommended_probes=target.recommended_probes,
        status="open",
        evidence_refs=target.evidence_refs,
        resolution=None,
        revisions=target.revisions,
        revisions_truncated=target.revisions_truncated,
    )
    replacement = [reopened if record.id == record_id else record for record in records]
    return obligations_to_payload(replacement)


def test_revision_pruning_keeps_the_budget_and_marks_truncation() -> None:
    record = _obligation()
    payload = _ledger(record)
    for _ in range(MAX_REVISIONS_PER_RECORD + 2):
        payload = waive_obligation(payload, record.id)
        payload = _readd_closed(payload, record.id)
    final = get_obligation(payload, record.id)
    assert len(final.revisions) == MAX_REVISIONS_PER_RECORD
    assert final.revisions[-1].revision == MAX_REVISIONS_PER_RECORD + 3
    assert final.revisions_truncated == 3
    assert final.revisions[0].revision == 4


# ---- payload round trips and validation --------------------------------------


def test_payload_round_trip_is_json_safe_and_canonical() -> None:
    record = _obligation(recommended_probes=["p1", "p2"], evidence_refs=["a", "b"])
    payload = obligations_to_payload([record])
    assert payload["count"] == len(payload["items"])
    text = json.dumps(payload, allow_nan=False, sort_keys=True)
    assert json.loads(text) == payload
    parsed = obligations_from_payload(json.loads(text))
    assert parsed == (record,)


def test_payload_rejects_tampered_ids_and_malformed_trails() -> None:
    record = _obligation()
    payload = _ledger(record)
    tampered = json.loads(json.dumps(payload))
    tampered["items"][0]["id"] = "ob-0000000000000000"
    with pytest.raises(AnalysisError):
        obligations_from_payload(tampered)
    with pytest.raises(AnalysisError):
        obligations_to_payload([record, _obligation()])
    with pytest.raises(AnalysisError):
        obligations_from_payload({"count": 1})
    with pytest.raises(AnalysisError):
        obligations_from_payload("not-a-mapping")
    bad_trail = json.loads(json.dumps(payload))
    bad_trail["items"][0]["revisions"] = [
        {"revision": 2, "at": "2024-01-01T00:00:00+00:00", "action": "add", "state": {}}
    ]
    with pytest.raises(AnalysisError):
        obligations_from_payload(bad_trail)
    bad_action = json.loads(json.dumps(payload))
    bad_action["items"][0]["revisions"] = [
        {"revision": 1, "at": "2024-01-01T00:00:00+00:00", "action": "explode", "state": {}}
    ]
    with pytest.raises(AnalysisError):
        obligations_from_payload(bad_action)
    too_many = json.loads(json.dumps(payload))
    too_many["items"][0]["revisions"] = [
        {"revision": i + 1, "at": "t", "action": "add", "state": {}}
        for i in range(MAX_REVISIONS_PER_RECORD + 1)
    ]
    with pytest.raises(AnalysisError):
        obligations_from_payload(too_many)


def test_list_and_get_read_back_from_the_payload() -> None:
    one = _obligation("first?")
    two = _obligation("second?")
    waived = waive_obligation(_ledger(one, two), one.id, note="skip")
    assert [record.id for record in list_obligations(waived)] == sorted((one.id, two.id))
    assert [record.id for record in list_obligations(waived, status="open")] == [two.id]
    with pytest.raises(AnalysisError):
        list_obligations(waived, status="archived")
    with pytest.raises(AnalysisError):
        get_obligation(waived, "ob-does-not-exist")


def test_remove_honours_cas_and_keeps_the_rest() -> None:
    one = _obligation("first?")
    two = _obligation("second?")
    ledger = _ledger(one, two)
    with pytest.raises(LedgerConflictError):
        remove_obligation(ledger, one.id, expected_revision=3)
    trimmed = remove_obligation(ledger, one.id, expected_revision=1)
    assert [record.id for record in list_obligations(trimmed)] == [two.id]
    with pytest.raises(AnalysisError):
        remove_obligation(trimmed, one.id)


# ---- CLI: codevanta obligations ----------------------------------------------


def _add_one(tmp_path: Path, question: str = "is the entry point a function?") -> str:
    ledger = tmp_path / "obligations.json"
    added = runner.invoke(
        app,
        [
            "obligations",
            "add",
            str(ledger),
            "--question",
            question,
            "--authority",
            "verified",
            "--evidence",
            "report.cfg",
        ],
    )
    assert added.exit_code == 0, added.output
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    return str(payload["items"][0]["id"])


def test_cli_obligations_lifecycle(tmp_path: Path) -> None:
    ledger = tmp_path / "obligations.json"
    record_id = _add_one(tmp_path)
    assert record_id.startswith("ob-")

    listed = runner.invoke(app, ["obligations", "list", str(ledger), "--format", "json"])
    assert listed.exit_code == 0
    listed_payload = json.loads(listed.output)
    assert listed_payload["count"] == 1
    assert listed_payload["items"][0]["id"] == record_id

    got = runner.invoke(app, ["obligations", "get", str(ledger), record_id, "--format", "json"])
    assert got.exit_code == 0
    got_payload = json.loads(got.output)
    assert got_payload["id"] == record_id
    assert got_payload["revisions"][0]["action"] == "add"

    # A stale CAS expectation exits 2 and does not touch the file.
    before = ledger.read_text(encoding="utf-8")
    conflict = runner.invoke(
        app,
        ["obligations", "discharge", str(ledger), record_id, "--expected-revision", "42"],
    )
    assert conflict.exit_code == 2
    assert "current revision 1" in conflict.output
    assert ledger.read_text(encoding="utf-8") == before

    discharged = runner.invoke(
        app,
        ["obligations", "discharge", str(ledger), record_id, "--note", "cfg verified"],
    )
    assert discharged.exit_code == 0, discharged.output
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    assert payload["items"][0]["status"] == "discharged"
    assert payload["items"][0]["resolution"] == "cfg verified"
    assert len(payload["items"][0]["revisions"]) == 2

    waived = runner.invoke(
        app,
        [
            "obligations",
            "waive",
            str(ledger),
            record_id,
            "--note",
            "not reachable",
            "--expected-revision",
            "2",
        ],
    )
    assert waived.exit_code == 2  # only open obligations can be closed

    removed = runner.invoke(app, ["obligations", "remove", str(ledger), record_id])
    assert removed.exit_code == 0, removed.output
    assert json.loads(ledger.read_text(encoding="utf-8"))["count"] == 0

    missing = runner.invoke(app, ["obligations", "get", str(ledger), record_id])
    assert missing.exit_code == 2


def test_cli_obligations_waive_requires_note_and_duplicate_add_fails(tmp_path: Path) -> None:
    ledger = tmp_path / "obligations.json"
    record_id = _add_one(tmp_path)
    no_note = runner.invoke(app, ["obligations", "waive", str(ledger), record_id])
    assert no_note.exit_code == 2
    dup = runner.invoke(
        app,
        [
            "obligations",
            "add",
            str(ledger),
            "--question",
            "is the entry point a function?",
            "--authority",
            "verified",
        ],
    )
    assert dup.exit_code == 2
    assert "duplicate" in dup.output
    bad_status = runner.invoke(
        app, ["obligations", "list", str(ledger), "--status", "archived"]
    )
    assert bad_status.exit_code == 2


# ---- MCP: codevanta_obligations ----------------------------------------------


def test_mcp_obligations_lifecycle(tmp_path: Path) -> None:
    ledger = str(tmp_path / "obligations.json")
    opened = mcp_tools.codevanta_obligations(
        "add", ledger, question="entry point CFG built?", required_authority="computed"
    )
    record_id = opened["record"]["id"]
    assert opened["count"] == 1
    assert opened["record"]["status"] == "open"

    listed = mcp_tools.codevanta_obligations("list", ledger)
    assert listed["count"] == 1

    got = mcp_tools.codevanta_obligations("get", ledger, obligation_id=record_id)
    assert got["revision"] == 1

    with pytest.raises(LedgerConflictError):
        mcp_tools.codevanta_obligations(
            "discharge", ledger, obligation_id=record_id, expected_revision=5
        )
    discharged = mcp_tools.codevanta_obligations(
        "discharge",
        ledger,
        obligation_id=record_id,
        note="built",
        expected_revision=1,
    )
    assert discharged["revision"] == 2

    removed = mcp_tools.codevanta_obligations("remove", ledger, obligation_id=record_id)
    assert removed["count"] == 0

    with pytest.raises(AnalysisError):
        mcp_tools.codevanta_obligations("explode", ledger)


def test_mcp_server_registers_and_calls_obligations(tmp_path: Path) -> None:
    ledger = str(tmp_path / "obligations.json")
    result = asyncio.run(
        build_server().call_tool(
            "codevanta_obligations",
            {"action": "add", "ledger": ledger, "question": "uart console identified?"},
        )
    )
    structured = getattr(result, "structuredContent", None) or json.loads(
        result.content[0].text
    )
    assert structured["action"] == "add"
    assert structured["record"]["id"].startswith("ob-")
    listed = asyncio.run(build_server().list_tools())
    assert {"codevanta_obligations", "codevanta_coverage"} <= {tool.name for tool in listed}


# ---- backward compatibility of the v1 unknowns API ---------------------------


def test_old_unknowns_api_is_unchanged() -> None:
    """A pre-ledger-v2 payload keeps working: no revisions, no CAS required."""
    legacy = {
        "count": 1,
        "items": [
            {
                "id": unknown_id("cfg", "entry point is a guess"),
                "domain": "cfg",
                "severity": "medium",
                "status": "open",
                "summary": "entry point is a guess",
                "evidence_refs": [],
            }
        ],
    }
    record = records_from_payload(legacy)[0]
    assert record.revisions == ()
    assert record.revisions_truncated == 0
    # Old-style resolve: no expected_revision, payload returned as before.
    updated = resolve_unknowns(legacy, [record.id], note="looked")
    assert updated["count"] == 1
    assert updated["items"][0]["status"] == "resolved"
    # The mutation stamped the first revision onto the revision-less legacy record.
    assert updated["items"][0]["revisions"][0]["revision"] == 1
    fresh = make_open_unknown(domain="cfg", summary="new question")
    assert record_revision(fresh) == 1
    assert resolve_record(record).status == "resolved"


def test_legacy_obligation_parses_without_a_trail() -> None:
    """An obligation parsed from a pre-revision payload sits at revision 0."""
    legacy = {
        "count": 1,
        "items": [
            {
                "id": obligation_id("legacy question?"),
                "question": "legacy question?",
                "required_authority": "parsed",
                "required_confidence": "medium",
                "required_environment": "host",
                "recommended_probes": [],
                "status": "open",
                "evidence_refs": [],
            }
        ],
    }
    record = obligations_from_payload(legacy)[0]
    assert record.revisions == ()
    assert record_revision(record) == 0
    # The first mutation stamps revision 1, matching the unknown-ledger rule.
    discharged = discharge_obligation(obligations_to_payload([record]), record.id)
    assert record_revision(obligations_from_payload(discharged)[0]) == 1


# ---- CLI text output, json formats and error branches -------------------------


def _bundle_wrapped_ledger(tmp_path: Path, payload: dict[str, Any]) -> Path:
    """Write a hand-made bundle document carrying an 'obligations' entry."""
    path = tmp_path / "bundle-with-obligations.json"
    path.write_text(
        json.dumps({"manifest": {"tool_version": "0.1.0"}, "entries": {"obligations": {"payload": payload}}}),
        encoding="utf-8",
    )
    return path


def test_cli_remove_and_write_error_branches(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    failed = runner.invoke(app, ["obligations", "remove", str(broken), "ob-nope"])
    assert failed.exit_code == 2
    not_a_bundle = tmp_path / "doc.json"
    not_a_bundle.write_text(json.dumps({"manifest": {}, "entries": {}}), encoding="utf-8")
    missing_entry = runner.invoke(app, ["obligations", "remove", str(not_a_bundle), "ob-nope"])
    assert missing_entry.exit_code == 2


def test_cli_text_output_paths(tmp_path: Path) -> None:
    ledger = tmp_path / "obligations.json"
    record_id = _add_one(tmp_path)
    listed = runner.invoke(app, ["obligations", "list", str(ledger)])
    assert listed.exit_code == 0
    assert "Obligations" in listed.output

    got = runner.invoke(app, ["obligations", "get", str(ledger), record_id])
    assert got.exit_code == 0
    assert "question:" in got.output
    assert "revisions:" in got.output

    added = runner.invoke(
        app,
        [
            "obligations",
            "add",
            str(ledger),
            "--question",
            "second one?",
            "--probe",
            "walk cfg",
            "--format",
            "json",
        ],
    )
    assert added.exit_code == 0, added.output
    assert json.loads(added.output)["action"] == "add"

    as_json = runner.invoke(app, ["obligations", "list", str(ledger), "--format", "json"])
    assert json.loads(as_json.output)["count"] == 2


def test_cli_waive_success_and_json_formats(tmp_path: Path) -> None:
    ledger = tmp_path / "obligations.json"
    record_id = _add_one(tmp_path)
    waived = runner.invoke(
        app,
        ["obligations", "waive", str(ledger), record_id, "--note", "skipped"],
    )
    assert waived.exit_code == 0, waived.output
    assert "waived" in waived.output

    second = runner.invoke(
        app,
        [
            "obligations",
            "add",
            str(ledger),
            "--question",
            "another?",
            "--environment",
            "device",
        ],
    )
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    second_id = next(item["id"] for item in payload["items"] if item["status"] == "open")
    assert second.exit_code == 0
    discharged = runner.invoke(
        app,
        [
            "obligations",
            "discharge",
            str(ledger),
            second_id,
            "--format",
            "json",
        ],
    )
    assert discharged.exit_code == 0, discharged.output
    discharged_payload = json.loads(discharged.output)
    assert discharged_payload["action"] == "discharged"
    assert discharged_payload["count"] == 2

    removed = runner.invoke(
        app, ["obligations", "remove", str(ledger), second_id, "--format", "json"]
    )
    assert removed.exit_code == 0, removed.output
    assert json.loads(removed.output)["action"] == "removed"


def test_cli_load_and_write_error_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    failed_load = runner.invoke(app, ["obligations", "list", str(broken)])
    assert failed_load.exit_code == 2
    failed_add = runner.invoke(
        app, ["obligations", "add", str(broken), "--question", "q"]
    )
    assert failed_add.exit_code == 2

    wrapped = _bundle_wrapped_ledger(tmp_path, obligations_to_payload([_obligation("wrapped?")]))
    listed = runner.invoke(app, ["obligations", "list", str(wrapped), "--format", "json"])
    assert listed.exit_code == 0
    assert json.loads(listed.output)["count"] == 1

    unwrapped = tmp_path / "not-a-bundle.json"
    unwrapped.write_text(json.dumps({"manifest": {}, "entries": {}}), encoding="utf-8")
    missing_entry = runner.invoke(app, ["obligations", "list", str(unwrapped)])
    assert missing_entry.exit_code == 2

    def _boom(*args: Any, **kwargs: Any) -> str:
        raise OSError("disk gone")

    monkeypatch.setattr(Path, "write_text", _boom)
    failed_write = runner.invoke(
        app, ["obligations", "add", str(tmp_path / "fresh.json"), "--question", "q"]
    )
    assert failed_write.exit_code == 2
    assert "disk gone" in " ".join(failed_write.output.split())


# ---- MCP error and unwrap branches --------------------------------------------


def test_mcp_obligations_error_branches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = str(tmp_path / "obligations.json")
    with pytest.raises(AnalysisError):
        mcp_tools.codevanta_obligations("add", ledger)
    with pytest.raises(AnalysisError):
        mcp_tools.codevanta_obligations("list", str(tmp_path / "missing.json"))
    with pytest.raises(AnalysisError):
        mcp_tools.codevanta_obligations("get", ledger)
    opened = mcp_tools.codevanta_obligations("add", ledger, question="one?")
    record_id = opened["record"]["id"]
    second = mcp_tools.codevanta_obligations("add", ledger, question="two?")
    assert second["count"] == 2
    with pytest.raises(AnalysisError):
        mcp_tools.codevanta_obligations("discharge", ledger)
    with pytest.raises(AnalysisError):
        mcp_tools.codevanta_obligations(
            "get", str(tmp_path / "missing.json"), obligation_id=record_id
        )

    wrapped = _bundle_wrapped_ledger(
        tmp_path, obligations_to_payload([_obligation("wrapped?")])
    )
    listed = mcp_tools.codevanta_obligations("list", str(wrapped))
    assert listed["count"] == 1

    def _boom(*args: Any, **kwargs: Any) -> str:
        raise OSError("disk gone")

    monkeypatch.setattr(Path, "write_text", _boom)
    with pytest.raises(AnalysisError):
        mcp_tools.codevanta_obligations("discharge", ledger, obligation_id=record_id)



def test_probe_and_ref_validation_matrix() -> None:
    long_probe = "p" * 201
    for kwargs in (
        {"question": "q", "recommended_probes": [123]},  # type: ignore[list-item]
        {"question": "q", "recommended_probes": ["   "]},
        {"question": "q", "recommended_probes": [long_probe]},
        {"question": "q", "evidence_refs": [f"r{i}" for i in range(17)]},
    ):
        with pytest.raises(AnalysisError):
            make_open_obligation(**kwargs)


def test_ledger_over_budget_is_refused() -> None:
    records = [make_open_obligation(question=f"question {i}?") for i in range(257)]
    with pytest.raises(AnalysisError):
        obligations_to_payload(records)


def _bad_payload(**mutation: Any) -> dict[str, Any]:
    """A one-record ledger with one field replaced by a malformed value."""
    record = make_open_obligation(question="malformed matrix?")
    payload = json.loads(json.dumps(obligations_to_payload([record])))
    payload["items"][0].update(mutation)
    return payload


def test_parse_rejects_malformed_obligation_payloads() -> None:
    with pytest.raises(AnalysisError):
        obligations_from_payload({"count": 1, "items": [1]})
    with pytest.raises(AnalysisError):
        obligations_from_payload(_bad_payload(recommended_probes="not-a-list"))
    with pytest.raises(AnalysisError):
        obligations_from_payload(_bad_payload(evidence_refs="not-a-list"))
    with pytest.raises(AnalysisError):
        obligations_from_payload(_bad_payload(revisions="not-a-list"))
    with pytest.raises(AnalysisError):
        obligations_from_payload(_bad_payload(revisions_truncated="many"))
    with pytest.raises(AnalysisError):
        obligations_from_payload(_bad_payload(revisions_truncated=-1))
    with pytest.raises(AnalysisError):
        obligations_from_payload(_bad_payload(revisions=[{"revision": 2, "at": "t", "action": "add", "state": {}}]))
    with pytest.raises(AnalysisError):
        obligations_from_payload(
            _bad_payload(
                revisions=[
                    {
                        "revision": 1,
                        "at": "t",
                        "action": "add",
                        "state": {},
                        "note": "n" * 501,
                    }
                ]
            )
        )
    # Sanity: an empty ledger parses fine.
    assert obligations_from_payload({"count": 0, "items": []}) == ()


def test_mutations_refuse_missing_ids() -> None:
    record = _obligation()
    ledger = _ledger(record)
    with pytest.raises(AnalysisError):
        discharge_obligation(ledger, "ob-nope")
    with pytest.raises(AnalysisError):
        waive_obligation(ledger, "ob-nope", note="n")
    with pytest.raises(AnalysisError):
        remove_obligation(ledger, "ob-nope")






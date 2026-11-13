"""Tests for ``codevanta.analysis.compare`` -- typed comparators over JSON.

The comparators are exercised the way they are meant to be used: fully
offline, against the committed report samples plus small hand-made payloads,
and through the real CLI surface (``codevanta compare``). No binary is
loaded, nothing is executed, no network is touched.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from codevanta.analysis.compare import (
    MAX_COMPARE_FUNCTIONS,
    compare_bundles,
    compare_inventories,
    compare_strings,
    load_report_payload,
)
from codevanta.cli.main import app
from codevanta.core.report import AnalysisError

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "samples"
REPORT_ELF64 = SAMPLES / "report_elf64.json"
REPORT_BUNDLE = SAMPLES / "report_bundle.json"
PE_SAMPLE = SAMPLES / "pe64_text.bin"

runner = CliRunner()


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _report_functions(path: Path) -> int:
    """Number of functions the sample report lists (derived, never hardcoded)."""
    document = _load(path)
    if "functions" in document:
        return len(document["functions"])
    return len(document["entries"]["report"]["payload"]["functions"])


def _report_string_texts(path: Path) -> set[str]:
    """Unique string texts of a sample report (derived from the file)."""
    document = _load(path)
    if "strings" in document:
        items = document["strings"]["items"]
    else:
        items = document["entries"]["report"]["payload"]["strings"]["items"]
    return {str(item["text"]) for item in items}


def _assert_json_safe(payload: dict[str, Any]) -> None:
    """The result must survive a strict JSON round trip (no NaN/Infinity)."""
    text = json.dumps(payload, allow_nan=False)
    assert json.loads(text) == payload


def _function(name: str | None, address: str, digest: str | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"address": address}
    if name is not None:
        entry["name"] = name
    if digest is not None:
        entry["fingerprint"] = digest
    return entry


def _digest(seed: str) -> str:
    """A well-formed 64-hex fingerprint for tests."""
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def test_sample_pair_reports_one_sided_functions() -> None:
    left = load_report_payload(REPORT_ELF64)
    right = load_report_payload(REPORT_BUNDLE)
    result = compare_inventories(left, right)
    right_total = _report_functions(REPORT_BUNDLE)
    left_total = _report_functions(REPORT_ELF64)
    assert result.left_functions == left_total
    assert result.right_functions == right_total
    matched = len(result.matched_by_name) + len(result.matched_by_fingerprint)
    assert len(result.added) == right_total - matched
    assert len(result.removed) == left_total - matched
    added_names = {entry.name for entry in result.added if entry.name is not None}
    assert "codevanta_sample_main" in added_names
    _assert_json_safe(result.to_dict())


def test_name_matching_reports_address_changes() -> None:
    left = {"functions": [_function("main", "0x1000"), _function("helper", "0x2000")]}
    right = {"functions": [_function("main", "0x9000"), _function("new_thing", "0x3000")]}
    result = compare_inventories(left, right)
    assert [match.name for match in result.matched_by_name] == ["main"]
    match = result.matched_by_name[0]
    assert match.address_changed is True
    assert match.left_address == "0x1000"
    assert match.right_address == "0x9000"
    assert [entry.name for entry in result.added] == ["new_thing"]
    assert [entry.name for entry in result.removed] == ["helper"]


def test_fingerprint_matching_pairs_renamed_functions() -> None:
    digest = _digest("same-shape")
    left = {"functions": [_function("old_name", "0x1000", digest)]}
    right = {"functions": [_function("renamed", "0x5000", digest)]}
    result = compare_inventories(left, right)
    assert result.matched_by_name == ()
    assert len(result.matched_by_fingerprint) == 1
    fp = result.matched_by_fingerprint[0]
    assert fp.digest == digest
    assert fp.left_name == "old_name"
    assert fp.right_name == "renamed"
    assert result.added == ()
    assert result.removed == ()


def test_duplicate_names_are_skipped_with_warning() -> None:
    left = {
        "functions": [
            _function("dup", "0x1"),
            _function("dup", "0x2"),
            _function("solo", "0x3"),
        ]
    }
    right = {"functions": [_function("dup", "0x4"), _function("dup", "0x5")]}
    result = compare_inventories(left, right)
    assert result.matched_by_name == ()
    assert any("ambiguous duplicated names" in warning for warning in result.warnings)


def test_malformed_fingerprint_is_ignored_with_warning() -> None:
    left = {"functions": [_function("old", "0x1", "not-a-digest")]}
    right = {"functions": [_function("new", "0x2", "not-a-digest")]}
    result = compare_inventories(left, right)
    assert result.matched_by_name == ()
    assert result.matched_by_fingerprint == ()
    assert len(result.added) == 1
    assert len(result.removed) == 1
    assert any("sha256 hex digest" in warning for warning in result.warnings)


def test_inventory_budget_truncates_with_warning() -> None:
    left = {"functions": [_function(f"f{i}", f"0x{i:x}") for i in range(6)]}
    right: dict[str, Any] = {"functions": []}
    result = compare_inventories(left, right, max_functions=4)
    assert result.left_functions == 4
    assert len(result.removed) == 4
    assert any("truncated" in warning for warning in result.warnings)


def test_invalid_budget_is_rejected() -> None:
    left: dict[str, Any] = {"functions": []}
    right: dict[str, Any] = {"functions": []}
    with pytest.raises(AnalysisError):
        compare_inventories(left, right, max_functions=0)
    with pytest.raises(AnalysisError):
        compare_inventories(left, right, max_functions=MAX_COMPARE_FUNCTIONS + 1)


def test_missing_functions_section_is_rejected() -> None:
    with pytest.raises(AnalysisError):
        compare_inventories({"strings": {}}, {"functions": []})


def test_result_is_deterministic() -> None:
    left = load_report_payload(REPORT_ELF64)
    right = load_report_payload(REPORT_BUNDLE)
    first = compare_inventories(left, right).to_dict()
    second = compare_inventories(left, right).to_dict()
    assert first == second


def test_strings_sample_pair_matches_derived_set_diff() -> None:
    left = load_report_payload(REPORT_ELF64)
    right = load_report_payload(REPORT_BUNDLE)
    result = compare_strings(left, right)
    left_texts = _report_string_texts(REPORT_ELF64)
    right_texts = _report_string_texts(REPORT_BUNDLE)
    assert result.shared_count == len(left_texts & right_texts)
    assert set(result.added) == right_texts - left_texts
    assert set(result.removed) == left_texts - right_texts
    assert result.added == tuple(sorted(result.added))
    assert result.removed == tuple(sorted(result.removed))
    assert result.evidence["confidence"] == "high"
    _assert_json_safe(result.to_dict())


def test_strings_budget_truncates_with_warning() -> None:
    left = {"strings": {"items": [{"text": f"s{i:02d}"} for i in range(5)]}}
    right: dict[str, Any] = {"strings": {"items": []}}
    result = compare_strings(left, right, max_strings=3)
    assert len(result.removed) == 3
    assert any("truncated" in warning for warning in result.warnings)


def test_strings_missing_section_is_rejected() -> None:
    with pytest.raises(AnalysisError):
        compare_strings({"functions": []}, {"strings": {"items": []}})
    with pytest.raises(AnalysisError):
        compare_strings({"strings": {}}, {"strings": {"items": []}})


def _write_bundle(path: Path, payloads: dict[str, Any]) -> Path:
    from codevanta.analysis.evidence_bundle import build_bundle, write_bundle

    write_bundle(build_bundle(PE_SAMPLE, payloads), path)
    return path


def test_bundles_self_compare_is_all_unchanged(tmp_path: Path) -> None:
    bundle = _write_bundle(
        tmp_path / "a.json",
        {"report": {"functions": []}, "metadata": {"notes": "x"}},
    )
    result = compare_bundles(_load(bundle), _load(bundle))
    assert result.left_entries == result.right_entries
    assert result.added_names == ()
    assert result.removed_names == ()
    assert result.changed == ()
    assert set(result.unchanged_names) == {"metadata", "report"}
    assert result.shared_digest_count >= 1
    _assert_json_safe(result.to_dict())


def test_bundles_diff_by_kind_and_digest_membership(tmp_path: Path) -> None:
    left = _write_bundle(
        tmp_path / "left.json",
        {"report": {"functions": []}, "metadata": {"notes": "x"}},
    )
    right = _write_bundle(
        tmp_path / "right.json",
        {
            "report": {"functions": ["changed"]},
            "metadata": {"notes": "x"},
            "trace": {"hits": []},
            # Same canonical payload as left's "report" entry, under a new name.
            "renamed": {"functions": []},
        },
    )
    from codevanta.analysis.evidence_bundle import read_bundle, verify_bundle

    assert verify_bundle(read_bundle(right)).passed

    result = compare_bundles(_load(left), _load(right))
    assert result.added_names == ("renamed", "trace")
    assert result.removed_names == ()
    assert [change.name for change in result.changed] == ["report"]
    assert result.changed[0].left_sha256 != result.changed[0].right_sha256
    assert result.changed[0].left_sha256 is not None
    assert result.unchanged_names == ("metadata",)
    # "renamed" carries left's report digest: membership across record kinds.
    assert result.shared_digest_count == 2


def test_bundles_missing_entries_object_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"manifest": {}}), encoding="utf-8")
    with pytest.raises(AnalysisError):
        compare_bundles(_load(bad), _load(bad))


def test_load_report_payload_unwraps_bundle(tmp_path: Path) -> None:
    direct = load_report_payload(REPORT_ELF64)
    assert "functions" in direct
    assert "manifest" not in direct
    unwrapped = load_report_payload(REPORT_BUNDLE)
    assert "functions" in unwrapped
    assert "manifest" not in unwrapped


def test_load_report_payload_rejects_bundle_without_report(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path / "only_trace.json", {"trace": {"hits": []}})
    with pytest.raises(AnalysisError):
        load_report_payload(bundle)


def test_load_document_rejects_broken_files(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(AnalysisError):
        load_report_payload(broken)
    with pytest.raises(AnalysisError):
        load_report_payload(tmp_path / "missing.json")


# ---- CLI: codevanta compare --------------------------------------------------


def test_cli_compare_functions_text() -> None:
    result = runner.invoke(
        app,
        ["compare", str(REPORT_ELF64), str(REPORT_BUNDLE), "--what", "functions"],
    )
    assert result.exit_code == 0, result.output
    assert "Added" in result.output
    assert "codevanta_sample_main" in result.output
    # The footer wraps on a narrow test console; check the parts, not the line.
    assert "name_and_fingerprint_matching" in result.output
    assert "confidence" in result.output and "medium" in result.output


def test_cli_compare_strings_json() -> None:
    result = runner.invoke(
        app,
        [
            "compare",
            str(REPORT_ELF64),
            str(REPORT_BUNDLE),
            "--what",
            "strings",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    left_texts = _report_string_texts(REPORT_ELF64)
    right_texts = _report_string_texts(REPORT_BUNDLE)
    assert set(payload["added"]) == right_texts - left_texts
    assert set(payload["removed"]) == left_texts - right_texts
    assert payload["evidence"]["method"] == "string_set_diff"


def test_cli_compare_bundles_json(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path / "one.json", {"report": {}, "metadata": {}})
    result = runner.invoke(
        app,
        ["compare", str(bundle), str(bundle), "--what", "bundles", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["changed"] == []
    assert set(payload["unchanged_names"]) == {"metadata", "report"}


def test_cli_compare_rejects_unknown_what() -> None:
    result = runner.invoke(
        app,
        ["compare", str(REPORT_ELF64), str(REPORT_BUNDLE), "--what", "entropy"],
    )
    # Typer rejects a value outside the Literal at parse time (exit 2); the
    # AnalysisError guard inside the command covers direct API misuse.
    assert result.exit_code == 2


def test_cli_compare_reports_missing_file_as_exit_two(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["compare", str(tmp_path / "missing.json"), str(REPORT_ELF64)],
    )
    assert result.exit_code == 2
    assert "error:" in result.output


# ---- MCP tools.compare -------------------------------------------------------


def test_mcp_compare_functions_on_samples() -> None:
    from codevanta.mcp_server import tools

    payload = tools.compare(str(REPORT_ELF64), str(REPORT_BUNDLE), what="functions")
    left_total = _report_functions(REPORT_ELF64)
    right_total = _report_functions(REPORT_BUNDLE)
    matched = payload["matched_by_name_count"] + payload["matched_by_fingerprint_count"]
    assert payload["added_count"] == right_total - matched
    assert payload["removed_count"] == left_total - matched


def test_mcp_compare_bundles_rejects_non_bundle(tmp_path: Path) -> None:
    from codevanta.mcp_server import tools

    plain = tmp_path / "plain.json"
    plain.write_text(json.dumps({"functions": []}), encoding="utf-8")
    with pytest.raises(AnalysisError):
        tools.compare(str(plain), str(plain), what="bundles")
    with pytest.raises(AnalysisError):
        tools.compare(str(REPORT_ELF64), str(REPORT_BUNDLE), what="nope")

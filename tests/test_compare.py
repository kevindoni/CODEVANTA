"""Tests for ``codevanta.analysis.compare`` -- typed comparators over JSON.

The comparators are exercised the way they are meant to be used: fully
offline, against the committed report samples plus small hand-made payloads,
and through the real CLI surface (``codevanta compare``). No binary is
loaded, nothing is executed, no network is touched.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import struct
import zlib
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from codevanta.analysis.compare import (
    COMPARE_WHATS,
    DEFAULT_MAX_CHANGED_SECTIONS,
    DEFAULT_MAX_DETAIL_KEYS,
    DEFAULT_MAX_HAR_PATHS,
    DEFAULT_MAX_ROWS,
    JSON_COMPARE_WHATS,
    MAX_COMPARE_FUNCTIONS,
    MAX_COMPARE_HAR_PATHS,
    MAX_COMPARE_REGISTERS,
    PATH_COMPARE_WHATS,
    compare_artifacts,
    compare_bundles,
    compare_crash,
    compare_firmware,
    compare_har,
    compare_inventories,
    compare_metadata,
    compare_nav,
    compare_reports,
    compare_screenshots,
    compare_sessions,
    compare_strings,
    compare_wasm,
    load_report_payload,
)
from codevanta.analysis.nav import NavStore
from codevanta.analysis.png_diff import MAX_PNG_PIXELS, decode_png, load_png
from codevanta.cli.main import app
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError
from codevanta.storage.session import SessionStore
from test_crash import (
    _CORE_NAME,
    FAULT_ADDR,
    RIP,
    RSP,
    TID,
    _note,
    _nt_file64,
    _prpsinfo64,
    _siginfo64,
    make_core64,
)

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


# ---- fixtures for the path/JSON comparators -----------------------------------


_WASM_HEADER = b"\x00asm\x01\x00\x00\x00"
_WASM_TYPES = b"\x01\x05\x01\x60\x00\x01\x7f"  # one () -> i32
_WASM_IMPORT_EF = b"\x02\x07\x01\x01\x65\x01\x66\x00\x00"  # e.f = func 0
_WASM_EXPORT_OK = b"\x07\x06\x01\x02\x6f\x6b\x00\x00"  # "ok" -> func 0
_WASM_CODE = b"\x0a\x04\x01\x02\x00\x0b"  # one empty body

_WASM_MODULE_A = (
    _WASM_HEADER + _WASM_TYPES + _WASM_IMPORT_EF + _WASM_EXPORT_OK + _WASM_CODE
)
# Module B keeps import e.f, adds import g.h and a memory section, and
# renames the export "ok" to "ok2".
_WASM_IMPORTS_BOTH = b"\x02\x0d\x02\x01\x65\x01\x66\x00\x00\x01\x67\x01\x68\x00\x00"
_WASM_MODULE_B = (
    _WASM_HEADER
    + _WASM_TYPES
    + _WASM_IMPORTS_BOTH  # imports: e.f and g.h
    + b"\x05\x03\x01\x00\x01"  # memory: 1 page
    + b"\x07\x07\x01\x03\x6f\x6b\x32\x00\x00"  # "ok2" -> func 0
    + _WASM_CODE
)


def _write_wasm(tmp_path: Path, name: str, blob: bytes) -> Path:
    target = tmp_path / name
    target.write_bytes(blob)
    return target


def _prstatus64_at(tid: int, signal: int, rip: int, rsp: int) -> bytes:
    """``NT_PRSTATUS`` descriptor with explicit rip/rsp (test-local builder)."""
    descriptor = bytearray(324)
    struct.pack_into("<II", descriptor, 0, signal, 1)
    struct.pack_into("<H", descriptor, 16, signal)
    struct.pack_into("<I", descriptor, 24, tid)
    struct.pack_into("<Q", descriptor, 104 + 16 * 8, rip)
    struct.pack_into("<Q", descriptor, 104 + 19 * 8, rsp)
    return bytes(descriptor)


def _core_notes(*, rip: int = RIP, rsp: int = RSP, signal: int = 11) -> list[bytes]:
    """The canonical four notes with parameterised rip/rsp/signal."""
    return [
        _note(_CORE_NAME, 1, _prstatus64_at(TID, signal, rip, rsp)),
        _note(_CORE_NAME, 3, _prpsinfo64(TID, b"crashtest\x00", b"crashtest --run\x00")),
        _note(_CORE_NAME, 0x53494749, _siginfo64(signal, 1, FAULT_ADDR)),
        _note(
            _CORE_NAME,
            0x46494C45,
            _nt_file64([(0x401000, 0x402000)], [b"/opt/crashtest"]),
        ),
    ]


def _make_info(path: Path) -> BinaryInfo:
    """Minimal metadata for one session row (mirrors test_nav.make_info)."""
    return BinaryInfo(
        path=path,
        format="ELF",
        architecture="x86_64",
        bitness=64,
        endianness="little",
        entry_point=0x401000,
        image_base=0x400000,
        sha256="a" * 64,
        file_size=4096,
    )


def _session_db(tmp_path: Path, name: str, session_id: str) -> Path:
    """A session database with one saved session (and no annotations yet)."""
    db_path = tmp_path / name
    store = SessionStore(db_path)
    try:
        store.save(_make_info(db_path.with_suffix(".bin")), 1, 1, session_id=session_id)
    finally:
        store.close()
    return db_path


# ---- registry sanity ----------------------------------------------------------


def test_registry_partitions_all_twelve_kinds() -> None:
    assert len(COMPARE_WHATS) == 12
    assert set(JSON_COMPARE_WHATS) | set(PATH_COMPARE_WHATS) == set(COMPARE_WHATS)
    assert not set(JSON_COMPARE_WHATS) & set(PATH_COMPARE_WHATS)
    assert "functions" in JSON_COMPARE_WHATS and "firmware" in PATH_COMPARE_WHATS
    assert {"screenshots", "har"} <= set(PATH_COMPARE_WHATS)


# ---- compare_reports ----------------------------------------------------------


def test_reports_identical_payload_is_identical() -> None:
    payload = json.loads(REPORT_ELF64.read_text(encoding="utf-8"))
    result = compare_reports(payload, payload)
    assert result.identical is True
    assert result.changed == ()
    assert result.added_sections == () and result.removed_sections == ()
    paths = {count.path for count in result.section_counts}
    assert {"functions", "strings", "binary.sections"} <= paths
    functions = next(c for c in result.section_counts if c.path == "functions")
    assert functions.left == functions.right and functions.to_dict()["delta"] == 0
    _assert_json_safe(result.to_dict())
    assert result.to_dict()["what"] == "reports"


def test_reports_sample_pair_reports_changes_and_counts() -> None:
    left = load_report_payload(REPORT_ELF64)
    right = load_report_payload(REPORT_BUNDLE)
    result = compare_reports(left, right)
    assert result.left_sections == len(left)
    assert result.right_sections == len(right)
    assert result.identical is False
    changed_names = {change.name for change in result.changed}
    assert "provenance" in changed_names  # created_at differs between builds
    for count in result.section_counts:
        if count.left is not None and count.right is not None:
            assert count.to_dict()["delta"] == count.right - count.left
    _assert_json_safe(result.to_dict())


def test_reports_added_removed_and_budget_bound() -> None:
    left: dict[str, Any] = {"functions": [{"address": "0x1000"}], "binary": {"sections": []}}
    right: dict[str, Any] = {
        "functions": [{"address": "0x2000"}],
        "binary": {"sections": []},
        "metadata": {"tool": "codevanta"},
    }
    result = compare_reports(left, right)
    assert result.added_sections == ("metadata",)
    assert result.removed_sections == ()
    assert [change.name for change in result.changed] == ["functions"]

    many_left = {f"section_{i:02d}": {"i": i} for i in range(20)}
    many_right = {f"section_{i:02d}": {"i": i + 1} for i in range(20)}
    bounded = compare_reports(many_left, many_right)  # budget defaults to 16
    assert len(bounded.changed) == DEFAULT_MAX_CHANGED_SECTIONS
    assert any("changed sections: kept 16 of 20" in warning for warning in bounded.warnings)
    with pytest.raises(AnalysisError):
        compare_reports(left, right, max_changed_sections=0)


def test_reports_rejects_non_object_payloads() -> None:
    with pytest.raises(AnalysisError, match="left"):
        compare_reports(["not", "an", "object"], {})
    with pytest.raises(AnalysisError, match="right"):
        compare_reports({}, "nope")


# ---- compare_metadata ---------------------------------------------------------


def _metadata_doc(kind: str, details: dict[str, Any]) -> dict[str, Any]:
    return {"path": "ignored", "kind": kind, "details": details, "evidence": []}


def test_metadata_kind_change_and_key_diff() -> None:
    left = _metadata_doc("elf", {"format": "ELF64", "entry": "0x401000", "stripped": True})
    right = _metadata_doc("pe", {"format": "PE32+", "entry": "0x401000", "compiler": "msvc"})
    result = compare_metadata(left, right)
    assert result.same_kind is False
    assert result.left_kind == "elf" and result.right_kind == "pe"
    assert result.added_keys == ("compiler",)
    assert result.removed_keys == ("stripped",)
    assert {change.key for change in result.changed} == {"format"}
    assert result.identical is False
    _assert_json_safe(result.to_dict())
    assert result.to_dict()["what"] == "metadata"


def test_metadata_identical_bounded_and_missing_kind() -> None:
    details = {f"key_{i:02d}": i for i in range(40)}
    result = compare_metadata(_metadata_doc("elf", details), _metadata_doc("elf", details))
    assert result.identical is True and result.same_kind is True

    changed_left = {f"key_{i:02d}": i for i in range(40)}
    changed_right = {f"key_{i:02d}": i + 1 for i in range(40)}
    bounded = compare_metadata(
        _metadata_doc("elf", changed_left), _metadata_doc("elf", changed_right)
    )
    assert len(bounded.changed) == DEFAULT_MAX_DETAIL_KEYS
    assert any(
        "changed detail keys: kept 32 of 40" in warning for warning in bounded.warnings
    )

    missing_kind = compare_metadata({"details": {"a": 1}}, {"details": {"a": 1}})
    assert missing_kind.same_kind is None and missing_kind.identical is True
    assert any("'kind'" in warning for warning in missing_kind.warnings)


def test_metadata_typed_errors() -> None:
    with pytest.raises(AnalysisError, match="left"):
        compare_metadata({"kind": "elf"}, _metadata_doc("elf", {}))
    with pytest.raises(AnalysisError, match="right"):
        compare_metadata(_metadata_doc("elf", {}), {"kind": "elf"})
    with pytest.raises(AnalysisError):
        compare_metadata(_metadata_doc("elf", {}), _metadata_doc("elf", {}), max_detail_keys=0)


# ---- compare_wasm -------------------------------------------------------------


def test_wasm_identical_modules(tmp_path: Path) -> None:
    left = _write_wasm(tmp_path, "a.wasm", _WASM_MODULE_A)
    right = _write_wasm(tmp_path, "b.wasm", _WASM_MODULE_A)
    result = compare_wasm(left, right)
    assert result.identical is True
    assert result.added_sections == () and result.removed_sections == ()
    assert result.section_deltas == ()
    assert result.size_delta == 0
    assert result.left_version == 1
    _assert_json_safe(result.to_dict())
    assert result.to_dict()["what"] == "wasm"


def test_wasm_diff_sections_names_and_sizes(tmp_path: Path) -> None:
    left = _write_wasm(tmp_path, "a.wasm", _WASM_MODULE_A)
    right = _write_wasm(tmp_path, "b.wasm", _WASM_MODULE_B)
    result = compare_wasm(left, right)
    assert result.added_sections == ("5:memory",)
    assert result.removed_sections == ()
    assert result.imports_added == ("g.h",)
    assert result.imports_removed == ()
    assert result.exports_added == ("ok2",)
    assert result.exports_removed == ("ok",)
    assert result.size_delta == len(_WASM_MODULE_B) - len(_WASM_MODULE_A)
    assert result.size_delta > 0
    assert result.identical is False
    _assert_json_safe(result.to_dict())


def test_wasm_typed_errors(tmp_path: Path) -> None:
    not_wasm = tmp_path / "elf.bin"
    not_wasm.write_bytes(b"\x7fELF" + bytes(32))
    with pytest.raises(AnalysisError, match="not a WebAssembly module"):
        compare_wasm(not_wasm, not_wasm)
    with pytest.raises(AnalysisError):
        compare_wasm(tmp_path / "missing.wasm", not_wasm)


# ---- compare_crash ------------------------------------------------------------


def test_crash_same_site_verdict_high(tmp_path: Path) -> None:
    left = make_core64(tmp_path / "left.core", _core_notes())
    right = make_core64(tmp_path / "right.core", _core_notes())
    result = compare_crash(left, right)
    assert result.same_crash_site is True
    assert result.verdict_confidence == "high"
    assert result.same_signal is True
    assert result.same_fault_module is True
    assert result.left_fault_module == "/opt/crashtest"
    assert result.rip_same is True and result.sp_same is True
    assert result.rip_delta == 0
    registers = {delta.register for delta in result.register_deltas}
    assert {"rip", "rsp", "rbp"} <= registers
    assert all(not delta.changed for delta in result.register_deltas)
    assert len(result.register_deltas) <= MAX_COMPARE_REGISTERS
    _assert_json_safe(result.to_dict())
    assert result.to_dict()["what"] == "crash"


def test_crash_rip_shift_is_a_different_site(tmp_path: Path) -> None:
    left = make_core64(tmp_path / "left.core", _core_notes())
    right = make_core64(tmp_path / "right.core", _core_notes(rip=RIP + 0x10))
    result = compare_crash(left, right)
    assert result.same_crash_site is False
    assert result.verdict_confidence == "high"
    assert result.rip_same is False
    assert result.rip_delta == 0x10
    changed = {delta.register for delta in result.register_deltas if delta.changed}
    assert changed == {"rip"}
    _assert_json_safe(result.to_dict())


def test_crash_signal_mismatch_and_unmapped_module(tmp_path: Path) -> None:
    left = make_core64(tmp_path / "left.core", _core_notes(signal=11))
    right = make_core64(tmp_path / "right.core", _core_notes(signal=10))
    result = compare_crash(left, right)
    assert result.same_signal is False
    assert result.same_crash_site is False

    unmapped_left = make_core64(tmp_path / "u1.core", _core_notes()[:3])
    unmapped_right = make_core64(tmp_path / "u2.core", _core_notes()[:3])
    partial = compare_crash(unmapped_left, unmapped_right)
    assert partial.same_fault_module is None
    assert partial.left_fault_module is None
    assert partial.same_crash_site is True
    # signal + rip still decide the verdict even with both modules unknown.
    assert partial.verdict_confidence == "high"


def test_crash_undecidable_is_medium_confidence(tmp_path: Path) -> None:
    # No NT_PRSTATUS and no NT_FILE: no signal, no ip, no module on either side.
    minimal = [
        _note(_CORE_NAME, 3, _prpsinfo64(TID, b"crashtest\x00", b"crashtest --run\x00")),
    ]
    left = make_core64(tmp_path / "l.core", minimal)
    right = make_core64(tmp_path / "r.core", minimal)
    result = compare_crash(left, right)
    assert result.same_signal is None
    assert result.rip_same is None
    assert result.same_fault_module is None
    assert result.verdict_confidence == "medium"


def test_crash_typed_errors(tmp_path: Path) -> None:
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not a core dump at all")
    with pytest.raises(AnalysisError):
        compare_crash(junk, junk)
    with pytest.raises(AnalysisError):
        compare_crash(tmp_path / "missing.core", junk)


# ---- compare_sessions ---------------------------------------------------------


def test_sessions_annotation_diff(tmp_path: Path) -> None:
    left_db = _session_db(tmp_path, "left.db", "samesid0001")
    right_db = _session_db(tmp_path, "right.db", "samesid0001")
    left_store = SessionStore(left_db)
    right_store = SessionStore(right_db)
    try:
        left_store.annotate("samesid0001", 0x1000, "left note")
        left_store.annotate("samesid0001", 0x2000, "shared note")
        right_store.annotate("samesid0001", 0x2000, "shared note")
        right_store.annotate("samesid0001", 0x3000, "right note")
    finally:
        left_store.close()
        right_store.close()
    result = compare_sessions(left_db, right_db)
    assert result.left_annotations == 2 and result.right_annotations == 2
    assert result.annotation_delta == 0
    assert result.addresses_only_left == ("0x1000",)
    assert result.addresses_only_right == ("0x3000",)
    assert result.left_sessions == 1 and result.right_sessions == 1
    assert result.identical is False
    _assert_json_safe(result.to_dict())
    assert result.to_dict()["what"] == "sessions"


def test_sessions_identical_empty_databases(tmp_path: Path) -> None:
    left_db = _session_db(tmp_path, "l.db", "sess00000001")
    right_db = _session_db(tmp_path, "r.db", "sess00000002")
    result = compare_sessions(left_db, right_db)
    assert result.left_annotations == 0 and result.right_annotations == 0
    assert result.identical is True
    assert result.addresses_only_left == () and result.addresses_only_right == ()


def test_sessions_bounded_addresses(tmp_path: Path) -> None:
    left_db = _session_db(tmp_path, "l.db", "sess00000001")
    right_db = _session_db(tmp_path, "r.db", "sess00000002")
    store = SessionStore(left_db)
    try:
        for index in range(DEFAULT_MAX_ROWS + 6):  # 70 > budget 64
            store.annotate("sess00000001", 0x1000 + index, f"note {index}")
    finally:
        store.close()
    result = compare_sessions(left_db, right_db)
    assert result.left_annotations == DEFAULT_MAX_ROWS + 6
    assert len(result.addresses_only_left) == DEFAULT_MAX_ROWS
    assert any("kept 64 of 70" in warning for warning in result.warnings)


def test_sessions_typed_errors(tmp_path: Path) -> None:
    plain_db = tmp_path / "plain.db"
    connection = sqlite3.connect(plain_db)
    try:
        connection.execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(AnalysisError, match="not a CODEVANTA session database"):
        compare_sessions(plain_db, plain_db)
    not_sqlite = tmp_path / "not.db"
    not_sqlite.write_bytes(b"garbage")
    with pytest.raises(AnalysisError):
        compare_sessions(not_sqlite, not_sqlite)
    good_db = _session_db(tmp_path, "good.db", "sess00000003")
    with pytest.raises(AnalysisError):
        compare_sessions(good_db, good_db, max_addresses=0)


# ---- compare_nav --------------------------------------------------------------


def _navmark(
    db_path: Path, sid: str, *, name_addr: int, comment_addr: int, cursor: int
) -> None:
    nav = NavStore(db_path)
    try:
        nav.bookmark(sid, name_addr, "entry")
        nav.comment(sid, comment_addr, "looks fine")
        nav.goto(sid, cursor)
    finally:
        nav.close()


def test_nav_bookmark_comment_cursor_diff(tmp_path: Path) -> None:
    left_db = _session_db(tmp_path, "left.db", "samesid0001")
    right_db = _session_db(tmp_path, "right.db", "samesid0001")
    _navmark(left_db, "samesid0001", name_addr=0x1000, comment_addr=0x2000, cursor=0x3000)
    _navmark(right_db, "samesid0001", name_addr=0x1500, comment_addr=0x2500, cursor=0x3500)
    nav_right = NavStore(right_db)
    try:
        nav_right.bookmark("samesid0001", 0x9000, "added")
        nav_right.comment("samesid0001", 0x2000, "rewritten")
    finally:
        nav_right.close()

    result = compare_nav(left_db, right_db, session_id="samesid0001")
    assert result.session_id == "samesid0001"
    assert result.left_bookmarks == 1 and result.right_bookmarks == 2
    assert result.bookmarks_added == ("added",)
    assert result.bookmarks_removed == ()
    moves = {
        (move.name, move.left_address, move.right_address)
        for move in result.bookmarks_moved
    }
    assert moves == {("entry", "0x1000", "0x1500")}
    assert result.comments_added == ("0x2500",)
    assert result.comments_removed == ()
    changed = {
        (change.address, change.left_text, change.right_text)
        for change in result.comments_changed
    }
    assert changed == {("0x2000", "looks fine", "rewritten")}
    assert result.cursor_left == "0x3000" and result.cursor_right == "0x3500"
    assert result.cursor_same is False
    assert result.identical is False
    _assert_json_safe(result.to_dict())
    assert result.to_dict()["what"] == "nav"


def test_nav_identical_and_auto_picked_session(tmp_path: Path) -> None:
    left_db = _session_db(tmp_path, "left.db", "autoses00001")
    right_db = _session_db(tmp_path, "right.db", "autoses00002")
    _navmark(left_db, "autoses00001", name_addr=0x1000, comment_addr=0x2000, cursor=0x3000)
    _navmark(right_db, "autoses00002", name_addr=0x1000, comment_addr=0x2000, cursor=0x3000)
    result = compare_nav(left_db, right_db)  # session_id=None picks newest per db
    assert result.session_id == "autoses00001"
    assert result.identical is True
    assert result.cursor_same is True
    assert result.bookmarks_moved == ()


def test_nav_typed_errors(tmp_path: Path) -> None:
    # A valid SQLite database whose sessions table exists but is empty.
    bare_db = tmp_path / "bare.db"
    connection = sqlite3.connect(bare_db)
    try:
        connection.execute("CREATE TABLE sessions (session_id TEXT, created_at TEXT)")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(AnalysisError, match="no saved sessions"):
        compare_nav(bare_db, bare_db)
    good_db = _session_db(tmp_path, "good.db", "sess00000002")
    with pytest.raises(AnalysisError):
        compare_nav(good_db, good_db, max_rows=0)


# ---- compare_firmware ---------------------------------------------------------


def test_firmware_hits_added_and_removed(tmp_path: Path) -> None:
    left = bytearray(2048)
    left[0:3] = b"\x1f\x8b\x08"  # gzip
    left[512:516] = b"hsqs"  # squashfs
    right = bytearray(2048)
    right[0:3] = b"\x1f\x8b\x08"  # gzip kept
    right[1024:1028] = b"\xd0\x0d\xfe\xed"  # DTB added
    left_path = tmp_path / "left.img"
    right_path = tmp_path / "right.img"
    left_path.write_bytes(bytes(left))
    right_path.write_bytes(bytes(right))
    result = compare_firmware(left_path, right_path)
    assert result.left_hits == 2 and result.right_hits == 2
    assert result.unchanged_hit_count == 1  # the gzip magic at offset 0
    added = {(hit["offset"], hit["kind"]) for hit in result.hits_added}
    removed = {(hit["offset"], hit["kind"]) for hit in result.hits_removed}
    assert added == {(1024, "dtb")}
    assert removed == {(512, "squashfs")}
    assert result.identical is False
    assert result.size_delta == 0
    payload = result.to_dict()
    assert payload["what"] == "firmware"
    assert payload["evidence"]["confidence"] == "medium"
    _assert_json_safe(payload)


def test_firmware_identical_and_no_hits(tmp_path: Path) -> None:
    blob = bytearray(2048)
    blob[0:3] = b"\x1f\x8b\x08"
    left = tmp_path / "same1.img"
    right = tmp_path / "same2.img"
    left.write_bytes(bytes(blob))
    right.write_bytes(bytes(blob))
    result = compare_firmware(left, right)
    assert result.identical is True and result.hits_added == ()

    bigger = tmp_path / "bigger.img"
    bigger.write_bytes(bytes(blob) + b"\x00" * 16)
    grown = compare_firmware(left, bigger)
    assert grown.identical is True and grown.size_delta == 16

    empty_left = tmp_path / "e1.img"
    empty_right = tmp_path / "e2.img"
    empty_left.write_bytes(b"\x00" * 512)
    empty_right.write_bytes(b"\x00" * 512)
    no_hits = compare_firmware(empty_left, empty_right)
    assert no_hits.left_hits == 0 and no_hits.identical is True


def test_firmware_typed_errors(tmp_path: Path) -> None:
    missing = tmp_path / "missing.img"
    with pytest.raises(AnalysisError):
        compare_firmware(missing, missing)


# ---- png_diff: fixture builder, decoder, pixel_diff ---------------------------


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    """One CRC-verified PNG chunk (test-local builder)."""
    return (
        struct.pack(">I", len(payload))
        + chunk_type
        + payload
        + struct.pack(">I", zlib.crc32(chunk_type + payload) & 0xFFFFFFFF)
    )


def _paeth(a: int, b: int, c: int) -> int:
    """Encoder-side Paeth predictor (must mirror the decoder's)."""
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def _make_png(
    width: int,
    height: int,
    pixels: list[list[tuple[int, ...]]],
    *,
    color_type: int = 2,
    filter_type: int = 0,
    bit_depth: int = 8,
    interlace: int = 0,
    compression: int = 0,
) -> bytes:
    """A minimal valid 8-bit PNG with the requested filter applied per row."""
    channels = {0: 1, 2: 3, 6: 4}[color_type]
    header = struct.pack(
        ">IIBBBBB", width, height, bit_depth, color_type, compression, 0, interlace
    )
    stream = bytearray()
    previous = [0] * (width * channels)
    for row in pixels:
        flat = [value for pixel in row for value in pixel]
        filtered = bytearray([filter_type])
        for x in range(len(flat)):
            left = flat[x - channels] if x >= channels else 0
            above = previous[x]
            upper_left = previous[x - channels] if x >= channels else 0
            if filter_type == 0:
                value = flat[x]
            elif filter_type == 1:
                value = (flat[x] - left) & 0xFF
            elif filter_type == 2:
                value = (flat[x] - above) & 0xFF
            elif filter_type == 3:
                value = (flat[x] - ((left + above) >> 1)) & 0xFF
            else:
                value = (flat[x] - _paeth(left, above, upper_left)) & 0xFF
            filtered.append(value)
        stream.extend(filtered)
        previous = flat
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", header)
        + _png_chunk(b"IDAT", zlib.compress(bytes(stream)))
        + _png_chunk(b"IEND", b"")
    )


def _gradient(width: int, height: int) -> list[list[tuple[int, int, int]]]:
    """Deterministic RGB image used as the baseline screenshot fixture."""
    return [
        [((column * 7) % 256, (row * 3) % 256, 128) for column in range(width)]
        for row in range(height)
    ]


def _write_png(path: Path, blob: bytes) -> Path:
    path.write_bytes(blob)
    return path


def test_png_decoder_roundtrips_all_five_filters() -> None:
    pixels = _gradient(16, 16)
    expected = tuple(tuple(row) for row in pixels)
    for filter_type in range(5):
        image = decode_png(_make_png(16, 16, pixels, filter_type=filter_type))
        assert image.width == 16 and image.height == 16
        assert image.color_type == 2 and image.channels == 3
        assert image.pixels == expected, f"filter {filter_type}"


def test_png_decoder_supports_grayscale_and_rgba() -> None:
    gray = decode_png(_make_png(2, 2, [[(10,), (20,)], [(30,), (40,)]], color_type=0))
    assert gray.channels == 1
    assert gray.pixels == (((10,), (20,)), ((30,), (40,)))
    rgba = decode_png(
        _make_png(1, 2, [[(1, 2, 3, 4)], [(5, 6, 7, 8)]], color_type=6)
    )
    assert rgba.channels == 4
    assert rgba.pixels == (((1, 2, 3, 4),), ((5, 6, 7, 8),))


@pytest.mark.parametrize(
    ("kwargs", "pixels", "message"),
    [
        ({"bit_depth": 16}, [[(1, 2, 3)]], "unsupported bit depth 16"),
        ({"filter_type": 5}, [[(1, 2, 3)]], "unsupported filter type 5"),
        ({"interlace": 1}, [[(1, 2, 3)]], "interlaced"),
        ({"compression": 1}, [[(1, 2, 3)]], "compression method"),
    ],
)
def test_png_header_and_filter_typed_errors(
    kwargs: dict[str, Any], pixels: list[list[tuple[int, ...]]], message: str
) -> None:
    blob = _make_png(1, 1, pixels, **kwargs)
    with pytest.raises(AnalysisError, match=message):
        decode_png(blob)


def test_png_typed_errors_structural(tmp_path: Path) -> None:
    signature = b"\x89PNG\r\n\x1a\n"
    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    body = _make_png(1, 1, [[(1, 2, 3)]])
    with pytest.raises(AnalysisError, match="bad signature"):
        decode_png(b"NOTPNG!" + body[8:])
    with pytest.raises(AnalysisError, match="missing IHDR"):
        decode_png(signature + _png_chunk(b"IEND", b""))
    with pytest.raises(AnalysisError, match="IDAT before IHDR"):
        decode_png(
            signature + _png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + _png_chunk(b"IEND", b"")
        )
    with pytest.raises(AnalysisError, match="duplicate IHDR"):
        decode_png(body[:-12] + _png_chunk(b"IHDR", header) + _png_chunk(b"IEND", b""))
    with pytest.raises(AnalysisError, match="fails its CRC"):
        broken = bytearray(body)
        broken[-1] ^= 0xFF  # corrupt IEND's stored CRC byte
        decode_png(bytes(broken))
    with pytest.raises(AnalysisError, match="missing IEND"):
        decode_png(body[:-12])
    with pytest.raises(AnalysisError, match="unsupported critical chunk"):
        decode_png(
            signature
            + _png_chunk(b"ABCD", b"x")
            + _png_chunk(b"IHDR", header)
            + _png_chunk(b"IEND", b"")
        )
    with pytest.raises(AnalysisError, match="invalid dimensions"):
        decode_png(
            signature
            + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 0, 4, 8, 2, 0, 0, 0))
            + _png_chunk(b"IEND", b"")
        )
    with pytest.raises(AnalysisError, match="pixel ceiling"):
        assert 5000 * 5000 > MAX_PNG_PIXELS
        decode_png(
            signature
            + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 5000, 5000, 8, 2, 0, 0, 0))
            + _png_chunk(b"IDAT", zlib.compress(b"\x00"))
            + _png_chunk(b"IEND", b"")
        )
    with pytest.raises(AnalysisError, match="missing IDAT"):
        decode_png(signature + _png_chunk(b"IHDR", header) + _png_chunk(b"IEND", b""))
    # A truncated decompressed scanline stream is a typed error, not a crash.
    with pytest.raises(AnalysisError, match="scanline data truncated"):
        decode_png(
            signature
            + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0))
            + _png_chunk(b"IDAT", zlib.compress(b"\x00\x01\x02\x03"))
            + _png_chunk(b"IEND", b"")
        )
    # An oversize decompressed stream (IDAT lies about its content) too.
    with pytest.raises(AnalysisError, match="exceeds the expected size"):
        decode_png(
            signature
            + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0))
            + _png_chunk(
                b"IDAT", zlib.compress(b"\x00" + b"\x01" * 12 + b"\x00" + b"\x02" * 12)
            )
            + _png_chunk(b"IEND", b"")
        )


def test_load_png_rejects_unreadable_file(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="cannot read"):
        load_png(tmp_path / "absent.png")


def test_pixel_diff_identical_pair_is_identical(tmp_path: Path) -> None:
    blob = _make_png(16, 16, _gradient(16, 16))
    left = _write_png(tmp_path / "a.png", blob)
    right = _write_png(tmp_path / "b.png", blob)
    result = compare_screenshots(left, right)
    diff = result.diff
    assert diff.verdict == "identical" and diff.identical is True
    assert diff.changed_pixels == 0 and diff.changed_ratio == 0.0
    assert all(delta.mean == 0.0 for delta in diff.channel_deltas)
    payload = result.to_dict()
    assert payload["what"] == "screenshots"
    assert payload["evidence"]["source"] == "compare.screenshots"
    assert payload["evidence"]["confidence"] == "high"
    text = json.dumps(payload, allow_nan=False)
    assert json.loads(text) == payload


def test_pixel_diff_one_pixel_change_is_minor(tmp_path: Path) -> None:
    pixels = _gradient(16, 16)
    changed = [list(row) for row in pixels]
    changed[3][5] = (0, 0, 200)
    left = _write_png(tmp_path / "a.png", _make_png(16, 16, pixels))
    right = _write_png(
        tmp_path / "b.png", _make_png(16, 16, [tuple(p) for p in changed])
    )
    result = compare_screenshots(left, right)
    diff = result.diff
    assert pixels[3][5] == (35, 9, 128)  # derived expectation, not hardcoded
    assert diff.changed_pixels == 1
    assert diff.changed_ratio == round(1 / (16 * 16), 6)
    assert diff.verdict == "minor" and diff.identical is False
    assert {delta.name: delta.mean for delta in diff.channel_deltas} == {
        "r": 35.0,
        "g": 9.0,
        "b": 72.0,
    }
    assert result.warnings == ()


def test_pixel_diff_ratio_at_threshold_is_major(tmp_path: Path) -> None:
    pixels = _gradient(10, 10)
    changed = [list(row) for row in pixels]
    changed[0][0] = (255, 0, 0)
    left = _write_png(tmp_path / "a.png", _make_png(10, 10, pixels))
    right = _write_png(
        tmp_path / "b.png", _make_png(10, 10, [tuple(p) for p in changed])
    )
    result = compare_screenshots(left, right)
    # 1 of 100 pixels is exactly 0.01 -- minor is strictly below the bound.
    assert result.diff.changed_ratio == 0.01
    assert result.diff.verdict == "major"


def test_pixel_diff_different_dimensions_is_major_with_note(tmp_path: Path) -> None:
    left = _write_png(tmp_path / "small.png", _make_png(2, 2, [[(1, 2, 3)] * 2] * 2))
    right = _write_png(
        tmp_path / "big.png",
        _make_png(4, 4, [[(0, 0, 0)] * 4 for _ in range(4)]),
    )
    result = compare_screenshots(left, right)
    diff = result.diff
    assert diff.verdict == "major" and diff.identical is False
    assert diff.changed_ratio == 1.0
    assert diff.changed_pixels == 0  # no aligned grid, so no pixel loop ran
    assert any("dimensions differ" in warning for warning in diff.warnings)
    assert result.warnings == diff.warnings


def test_pixel_diff_color_type_mismatch_compares_prefix(tmp_path: Path) -> None:
    left = _write_png(
        tmp_path / "rgb.png", _make_png(2, 1, [[(10, 20, 30), (1, 2, 3)]])
    )
    right = _write_png(
        tmp_path / "rgba.png",
        _make_png(2, 1, [[(10, 20, 30, 255), (1, 2, 3, 0)]], color_type=6),
    )
    result = compare_screenshots(left, right)
    assert result.diff.verdict == "identical"
    assert any("color types differ" in warning for warning in result.warnings)
    assert [delta.name for delta in result.diff.channel_deltas] == ["ch0", "ch1", "ch2"]


def test_compare_screenshots_rejects_broken_png(tmp_path: Path) -> None:
    junk = _write_png(tmp_path / "junk.png", b"definitely not a png")
    good = _write_png(tmp_path / "good.png", _make_png(1, 1, [[(0, 0, 0)]]))
    with pytest.raises(AnalysisError, match="not a PNG"):
        compare_screenshots(junk, good)
    with pytest.raises(AnalysisError, match="cannot read"):
        compare_screenshots(tmp_path / "missing.png", good)


# ---- compare_har: fixtures through the sibling har_capture parser -------------


def _har_entry(method: str, url: str, status: int, time_ms: float = 10.0) -> dict[str, Any]:
    """One minimal HAR log entry with a request/response pair."""
    return {
        "startedDateTime": "2026-01-01T00:00:00.000Z",
        "time": time_ms,
        "request": {"method": method, "url": url, "headers": []},
        "response": {
            "status": status,
            "headers": [],
            "content": {"size": 1, "mimeType": "application/json"},
        },
    }


def _write_har(path: Path, entries: list[dict[str, Any]]) -> Path:
    """Write a small HAR document; expectations derive from ``entries``."""
    path.write_text(
        json.dumps({"log": {"entries": entries}}, sort_keys=True), encoding="utf-8"
    )
    return path


def test_har_self_compare_is_identical(tmp_path: Path) -> None:
    entries = [
        _har_entry("GET", "https://app.test/api/a?token=x", 200),
        _har_entry("POST", "https://app.test/api/b", 201, time_ms=2.5),
    ]
    left = _write_har(tmp_path / "a.har", entries)
    right = _write_har(tmp_path / "b.har", entries)
    result = compare_har(left, right)
    assert result.identical is True and result.verdict == "identical"
    assert result.left_entries == result.right_entries == len(entries)
    assert result.paths_added == () and result.paths_removed == ()
    assert result.status_changes == () and result.method_deltas == ()
    payload = result.to_dict()
    assert payload["what"] == "har"
    assert payload["evidence"]["source"] == "compare.har"
    assert payload["evidence"]["confidence"] == "high"
    text = json.dumps(payload, allow_nan=False)
    assert json.loads(text) == payload


def test_har_path_status_and_method_diff(tmp_path: Path) -> None:
    left = _write_har(
        tmp_path / "a.har",
        [
            _har_entry("GET", "https://app.test/api/a?q=1", 200),
            _har_entry("POST", "https://app.test/api/b", 201),
            _har_entry("DELETE", "https://app.test/gone", 204),
        ],
    )
    right = _write_har(
        tmp_path / "b.har",
        [
            _har_entry("GET", "https://app.test/api/a?q=2", 200),
            _har_entry("POST", "https://app.test/api/b", 404),
            _har_entry("get", "https://other.test/new", 200),  # case + new host
        ],
    )
    result = compare_har(left, right)
    assert result.paths_added == ("/new",)
    assert result.paths_removed == ("/gone",)
    assert result.status_change_count == 1
    change = result.status_changes[0]
    assert (change.method, change.path) == ("POST", "/api/b")
    assert change.left_statuses == (201,) and change.right_statuses == (404,)
    methods = {delta.method: delta.to_dict() for delta in result.method_deltas}
    assert methods["GET"]["delta"] == 1
    assert methods["DELETE"]["delta"] == -1  # method normalised case-insensitively
    assert result.identical is False and result.verdict == "changed"
    payload = result.to_dict()
    assert payload["entry_delta"] == 0  # 3 vs 3 entries; drift shows in paths
    assert payload["left_listed"] == 3 and payload["right_listed"] == 3


def test_har_time_delta_never_breaks_identity(tmp_path: Path) -> None:
    entries_a = [_har_entry("GET", "https://app.test/x", 200, time_ms=10.0)]
    entries_b = [_har_entry("GET", "https://app.test/x", 200, time_ms=99.5)]
    left = _write_har(tmp_path / "a.har", entries_a)
    right = _write_har(tmp_path / "b.har", entries_b)
    result = compare_har(left, right)
    assert result.identical is True
    assert result.time_delta_ms == 89.5


def test_har_path_budget_bounds_and_warns(tmp_path: Path) -> None:
    left = _write_har(tmp_path / "a.har", [_har_entry("GET", "https://h.test/keep", 200)])
    right = _write_har(
        tmp_path / "b.har",
        [_har_entry("GET", f"https://h.test/new{i}", 200) for i in range(5)],
    )
    result = compare_har(left, right, max_paths=2)
    assert result.paths_added == ("/new0", "/new1")
    assert any("kept 2 of 5" in warning for warning in result.warnings)
    with pytest.raises(AnalysisError, match="max_paths must be between 1 and"):
        compare_har(left, right, max_paths=0)
    with pytest.raises(AnalysisError, match="max_paths must be between 1 and"):
        compare_har(left, right, max_paths=MAX_COMPARE_HAR_PATHS + 1)
    assert DEFAULT_MAX_HAR_PATHS == 64  # the documented bound


def test_har_typed_errors_pass_through(tmp_path: Path) -> None:
    entries = [_har_entry("GET", "https://h.test/x", 200)]
    left = _write_har(tmp_path / "a.har", entries)
    broken = tmp_path / "broken.har"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(AnalysisError):
        compare_har(left, broken)
    with pytest.raises(AnalysisError, match="cannot read|file not found"):
        compare_har(left, tmp_path / "absent.har")


# ---- CLI + dispatch + MCP for the two new kinds --------------------------------


def test_cli_compare_screenshots_text_and_json(tmp_path: Path) -> None:
    changed = [list(row) for row in _gradient(16, 16)]
    changed[0][0] = (1, 1, 1)
    left = _write_png(tmp_path / "a.png", _make_png(16, 16, _gradient(16, 16)))
    right = _write_png(
        tmp_path / "b.png", _make_png(16, 16, [tuple(p) for p in changed])
    )
    result = runner.invoke(app, ["compare", str(left), str(right), "--what", "screenshots"])
    assert result.exit_code == 0, result.output
    # 1 of 256 pixels = 0.003906 < 0.01 -> minor; the footer is the compare-level record.
    assert "verdict: minor" in result.output
    assert "screenshot_file_diff" in result.output

    as_json = runner.invoke(
        app,
        ["compare", str(left), str(right), "--what", "screenshots", "--format", "json"],
    )
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.output)
    assert payload["what"] == "screenshots"
    assert payload["changed_pixels"] == 1
    assert payload["verdict"] == "minor"


def test_cli_compare_har_text_and_json(tmp_path: Path) -> None:
    left = _write_har(tmp_path / "a.har", [_har_entry("GET", "https://h.test/x", 200)])
    right = _write_har(
        tmp_path / "b.har",
        [
            _har_entry("GET", "https://h.test/x", 200),
            _har_entry("POST", "https://h.test/y", 201),
        ],
    )
    result = runner.invoke(app, ["compare", str(left), str(right), "--what", "har"])
    assert result.exit_code == 0, result.output
    assert "entries: 1 vs 2" in result.output
    assert "har_summary_diff" in result.output
    as_json = runner.invoke(
        app, ["compare", str(left), str(right), "--what", "har", "--format", "json"]
    )
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.output)
    assert payload["what"] == "har"
    assert payload["paths_added"] == ["/y"]
    assert payload["verdict"] == "changed"


def test_cli_compare_screenshots_error_exits_two(tmp_path: Path) -> None:
    junk = _write_png(tmp_path / "junk.png", b"nope")
    result = runner.invoke(app, ["compare", str(junk), str(junk), "--what", "screenshots"])
    assert result.exit_code == 2
    assert "error:" in result.output


# --- dispatch registry additions appended below ---


def test_dispatch_rejects_unknown_what(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="unknown --what"):
        compare_artifacts("entropy", tmp_path, tmp_path)


def test_dispatch_runs_every_registered_kind(tmp_path: Path) -> None:
    assert isinstance(compare_artifacts("functions", REPORT_ELF64, REPORT_BUNDLE), object)
    assert isinstance(compare_artifacts("strings", REPORT_ELF64, REPORT_BUNDLE), object)
    assert isinstance(compare_artifacts("bundles", REPORT_BUNDLE, REPORT_BUNDLE), object)
    assert isinstance(compare_artifacts("reports", REPORT_ELF64, REPORT_BUNDLE), object)
    doc = tmp_path / "meta.json"
    doc.write_text(json.dumps({"kind": "elf", "details": {"fmt": "ELF64"}}), encoding="utf-8")
    assert isinstance(compare_artifacts("metadata", doc, doc), object)
    wasm_path = _write_wasm(tmp_path, "m.wasm", _WASM_MODULE_A)
    assert isinstance(compare_artifacts("wasm", wasm_path, wasm_path), object)
    core = make_core64(tmp_path / "c.core", _core_notes())
    assert isinstance(compare_artifacts("crash", core, core), object)
    left_db = _session_db(tmp_path, "l.db", "sess00000001")
    right_db = _session_db(tmp_path, "r.db", "sess00000002")
    assert isinstance(compare_artifacts("sessions", left_db, right_db), object)
    assert isinstance(compare_artifacts("nav", left_db, right_db), object)
    image = tmp_path / "fw.img"
    image.write_bytes(b"\x00" * 512)
    assert isinstance(compare_artifacts("firmware", image, image), object)
    shot = _write_png(tmp_path / "shot.png", _make_png(4, 4, _gradient(4, 4)))
    assert isinstance(compare_artifacts("screenshots", shot, shot), object)
    har_path = _write_har(tmp_path / "c.har", [_har_entry("GET", "https://h.test/x", 200)])
    assert isinstance(compare_artifacts("har", har_path, har_path), object)


def test_dispatch_bundles_rejects_non_bundle(tmp_path: Path) -> None:
    plain = tmp_path / "plain.json"
    plain.write_text(json.dumps({"functions": []}), encoding="utf-8")
    with pytest.raises(AnalysisError, match="not an evidence-bundle document"):
        compare_artifacts("bundles", plain, plain)


# ---- CLI: the new kinds through codevanta compare -----------------------------


def test_cli_compare_reports_text_and_json() -> None:
    result = runner.invoke(
        app,
        ["compare", str(REPORT_ELF64), str(REPORT_BUNDLE), "--what", "reports"],
    )
    assert result.exit_code == 0, result.output
    assert "Changed sections" in result.output
    assert "report_section_sha_diff" in result.output

    as_json = runner.invoke(
        app,
        [
            "compare",
            str(REPORT_ELF64),
            str(REPORT_ELF64),
            "--what",
            "reports",
            "--format",
            "json",
        ],
    )
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.output)
    assert payload["what"] == "reports" and payload["identical"] is True


def test_cli_compare_wasm_text(tmp_path: Path) -> None:
    left = _write_wasm(tmp_path, "a.wasm", _WASM_MODULE_A)
    right = _write_wasm(tmp_path, "b.wasm", _WASM_MODULE_B)
    result = runner.invoke(app, ["compare", str(left), str(right), "--what", "wasm"])
    assert result.exit_code == 0, result.output
    assert "5:memory" in result.output  # added section (title wraps on narrow consoles)
    assert "g.h" in result.output
    assert "wasm_summary_diff" in result.output


def test_cli_compare_crash_json(tmp_path: Path) -> None:
    core = make_core64(tmp_path / "c.core", _core_notes())
    result = runner.invoke(
        app,
        ["compare", str(core), str(core), "--what", "crash", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["what"] == "crash"
    assert payload["same_crash_site"] is True
    assert payload["verdict_confidence"] == "high"


def test_cli_compare_firmware_text(tmp_path: Path) -> None:
    image = tmp_path / "fw.img"
    image.write_bytes(b"\x1f\x8b\x08" + b"\x00" * 509)
    result = runner.invoke(app, ["compare", str(image), str(image), "--what", "firmware"])
    assert result.exit_code == 0, result.output
    assert "identical: True" in result.output
    assert "firmware_magic_diff" in result.output


def test_cli_compare_sessions_text_and_metadata_json(tmp_path: Path) -> None:
    left_db = _session_db(tmp_path, "l.db", "sess00000001")
    right_db = _session_db(tmp_path, "r.db", "sess00000002")
    result = runner.invoke(
        app, ["compare", str(left_db), str(right_db), "--what", "sessions"]
    )
    assert result.exit_code == 0, result.output
    assert "annotations: 0 vs 0" in result.output
    assert "session_annotation_diff" in result.output

    doc = tmp_path / "meta.json"
    doc.write_text(json.dumps({"kind": "elf", "details": {"fmt": "ELF64"}}), encoding="utf-8")
    as_json = runner.invoke(
        app,
        ["compare", str(doc), str(doc), "--what", "metadata", "--format", "json"],
    )
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.output)
    assert payload["what"] == "metadata" and payload["same_kind"] is True


def test_cli_compare_new_kind_error_exits_two(tmp_path: Path) -> None:
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"junk")
    result = runner.invoke(app, ["compare", str(junk), str(junk), "--what", "sessions"])
    assert result.exit_code == 2
    assert "error:" in result.output


# ---- MCP: the registry through tools.compare ----------------------------------


def test_mcp_compare_reports_and_wasm(tmp_path: Path) -> None:
    from codevanta.mcp_server import tools

    payload = tools.compare(str(REPORT_ELF64), str(REPORT_ELF64), what="reports")
    assert payload["what"] == "reports" and payload["identical"] is True
    wasm_path = _write_wasm(tmp_path, "m.wasm", _WASM_MODULE_A)
    wasm_payload = tools.compare(str(wasm_path), str(wasm_path), what="wasm")
    assert wasm_payload["what"] == "wasm" and wasm_payload["identical"] is True
    with pytest.raises(AnalysisError):
        tools.compare(str(wasm_path), str(wasm_path), what="sessions")
    shot = _write_png(tmp_path / "s.png", _make_png(4, 4, _gradient(4, 4)))
    shot_payload = tools.compare(str(shot), str(shot), what="screenshots")
    assert shot_payload["what"] == "screenshots"
    assert shot_payload["identical"] is True
    assert shot_payload["evidence"]["source"] == "compare.screenshots"
    har_path = _write_har(tmp_path / "m.har", [_har_entry("GET", "https://h.test/x", 200)])
    har_payload = tools.compare(str(har_path), str(har_path), what="har")
    assert har_payload["what"] == "har"
    assert har_payload["identical"] is True
    assert har_payload["evidence"]["source"] == "compare.har"


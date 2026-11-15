"""Tests for the file-scope capability-detection rule engine.

The feature-evaluation layer is exercised directly with synthetic
:class:`BinaryFeatureSet` values (building a real PE import table byte by
byte is impractical and would test LIEF, not the engine), while the public
entry points run end to end on the synthetic ELF64 fixtures from
``conftest.py`` and on the committed ``samples/pe64_text.bin``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codevanta.analysis.capabilities import (
    BUILTIN_RULES,
    MAX_TREE_DEPTH,
    BinaryFeatureSet,
    CapabilityReport,
    FeatureAnd,
    FeatureExport,
    FeatureImport,
    FeatureOr,
    FeatureSection,
    FeatureString,
    FiredFeature,
    ImportRef,
    Rule,
    StringRef,
    _leaf_kinds,
    detect_capabilities,
    evaluate_feature,
    load_rules,
)
from codevanta.core.report import AnalysisError
from conftest import make_elf64_with_text, make_minimal_elf64

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---- helpers ------------------------------------------------------------------


def _feature_set(
    imports: tuple[tuple[str | None, str], ...] = (),
    strings: tuple[tuple[str, int], ...] = (),
    exports: tuple[str, ...] = (),
    sections: tuple[str, ...] = (),
) -> BinaryFeatureSet:
    """Build a synthetic feature set from plain tuples."""
    return BinaryFeatureSet(
        imports=tuple(ImportRef(library, name) for library, name in imports),
        strings=tuple(StringRef(text, offset, "ascii") for text, offset in strings),
        exports=exports,
        sections=sections,
    )


def _rule_payload(**overrides: Any) -> dict[str, Any]:
    """One valid JSON rule dict, with optional field overrides."""
    payload: dict[str, Any] = {
        "id": "CV-TEST-RULE",
        "name": "Test rule",
        "namespace": "test/demo",
        "severity": "low",
        "attck": [],
        "description": "demo rule used by the tests",
        "features": {"kind": "string", "value": ".text"},
    }
    payload.update(overrides)
    return payload


def _write_rules(path: Path, *rules: dict[str, Any]) -> Path:
    """Write a JSON rules file with the given rule objects."""
    path.write_text(json.dumps({"rules": list(rules)}), encoding="utf-8")
    return path


def _builtin_rule(rule_id: str) -> Rule:
    """Fetch one built-in rule by id."""
    return next(rule for rule in BUILTIN_RULES if rule.id == rule_id)


def _elf_with_strings(tmp_path: Path, extra: bytes, name: str = "elf_strings.bin") -> Path:
    """ELF64 fixture plus extra NUL-separated payload bytes appended.

    The appended bytes sit past the section table, so the loader still sees
    the unchanged image while the string extractor (which scans raw file
    bytes) picks them up.
    """
    base = make_elf64_with_text(tmp_path / "base.bin")
    out = tmp_path / name
    out.write_bytes(base.read_bytes() + b"\x00" + extra + b"\x00")
    return out


# ---- built-in pack -------------------------------------------------------------


def test_builtin_pack_is_valid() -> None:
    ids = [rule.id for rule in BUILTIN_RULES]
    assert len(ids) == 14
    assert len(set(ids)) == len(ids), "rule ids must be unique"
    for rule in BUILTIN_RULES:
        assert rule.severity in ("critical", "high", "medium", "low")
        assert rule.description
        assert rule.features is not None
        for technique in rule.attck:
            assert technique.startswith("T")


def test_builtin_reverse_shell_requires_all_three_branches() -> None:
    rule = _builtin_rule("CV-REVERSE-SHELL")
    assert isinstance(rule.features, FeatureAnd)
    socketish, cmd, create_process = rule.features.children
    # Every branch individually can fire...
    partial = _feature_set(
        strings=(("socket", 0x10), ("cmd.exe", 0x20)),
        imports=(("KERNEL32.dll", "CreateProcessW"),),
    )
    assert evaluate_feature(socketish, partial) is not None
    assert evaluate_feature(cmd, partial) is not None
    assert evaluate_feature(create_process, partial) is not None
    # ...and together they satisfy the conjunction.
    fired = evaluate_feature(rule.features, partial)
    assert fired is not None
    # Drop any one branch and the whole rule must stop matching.
    for replacement in (
        _feature_set(strings=(("cmd.exe", 0x20),), imports=(("KERNEL32.dll", "CreateProcessW"),)),
        _feature_set(strings=(("socket", 0x10),), imports=(("KERNEL32.dll", "CreateProcessW"),)),
        _feature_set(strings=(("socket", 0x10), ("cmd.exe", 0x20))),
    ):
        assert evaluate_feature(rule.features, replacement) is None


def test_injection_rule_is_a_conjunction() -> None:
    rule = _builtin_rule("CV-INJECTION")
    assert isinstance(rule.features, FeatureAnd)
    triad = _feature_set(
        imports=(
            ("KERNEL32.dll", "VirtualAllocEx"),
            ("kernel32.dll", "WriteProcessMemory"),
            ("KERNEL32.DLL", "CreateRemoteThreadEx"),
        )
    )
    fired = evaluate_feature(rule.features, triad)
    assert fired is not None and len(fired) == 3
    missing_write = _feature_set(
        imports=(("KERNEL32.dll", "VirtualAllocEx"), ("KERNEL32.dll", "CreateRemoteThread"))
    )
    assert evaluate_feature(rule.features, missing_write) is None


# ---- feature evaluation truth table --------------------------------------------


def test_or_and_truth_table() -> None:
    empty = _feature_set()
    hit = FeatureString("cmd.exe")
    miss = FeatureString("absent")
    assert evaluate_feature(FeatureOr((miss, miss)), empty) is None
    assert evaluate_feature(FeatureOr((miss, hit)), empty) is None  # nothing to hit
    present = _feature_set(strings=(("cmd.exe /c del", 0x40),))
    assert evaluate_feature(FeatureOr((miss, hit)), present) is not None
    assert evaluate_feature(FeatureAnd((hit, miss)), present) is None
    both = FeatureAnd((hit, FeatureString("/c del")))
    fired = evaluate_feature(both, present)
    assert fired is not None and len(fired) == 2


def test_import_feature_variants() -> None:
    features = _feature_set(
        imports=(
            ("KERNEL32.dll", "CreateProcessW"),
            ("ws2_32.DLL", "socket"),
            (None, "socket"),  # ELF-style import without a library
        )
    )
    assert evaluate_feature(FeatureImport("kernel32", "CreateProcessW"), features)
    assert evaluate_feature(FeatureImport("KERNEL32.DLL", "createprocessw"), features)
    assert evaluate_feature(FeatureImport("ws2_32"), features)  # any import counts
    assert evaluate_feature(FeatureImport("ws2_32", "WSAStartup"), features) is None
    # A library-less import never satisfies a library-scoped feature.
    assert evaluate_feature(FeatureImport("libc", "socket"), features) is None


def test_string_feature_is_substring_with_locations() -> None:
    features = _feature_set(strings=(("HTTP://UPDATE.EXAMPLE", 0x2A4), ("other", 0x10)))
    fired = evaluate_feature(FeatureString("http"), features)
    assert isinstance(fired, tuple)
    assert fired[0].total == 1
    assert fired[0].locations == ("string@0x2a4/ascii",)


def test_export_and_section_features() -> None:
    features = _feature_set(exports=("codevanta_sample_main",), sections=(".text", "UPX0"))
    assert evaluate_feature(FeatureExport("CODEVANTA_SAMPLE_MAIN"), features)
    assert evaluate_feature(FeatureExport("missing"), features) is None
    assert evaluate_feature(FeatureSection("upx0"), features)
    assert evaluate_feature(FeatureSection("upx9"), features) is None


def test_location_rows_are_capped() -> None:
    features = _feature_set(strings=tuple((f"run{i:03d}", 0x10 * i) for i in range(10)))
    fired = evaluate_feature(FeatureString("run"), features)
    assert isinstance(fired, tuple)
    assert fired[0].total == 10
    assert len(fired[0].locations) == 4


# ---- JSON rule loader ----------------------------------------------------------


def test_load_rules_valid_file(tmp_path: Path) -> None:
    rules_file = _write_rules(
        tmp_path / "rules.json",
        _rule_payload(),
        _rule_payload(
            id="CV-TEST-NESTED",
            severity="critical",
            attck=["T1059.003"],
            features={
                "kind": "and",
                "children": [
                    {"kind": "import", "library": "kernel32", "name": "IsDebuggerPresent"},
                    {"kind": "or", "children": [{"kind": "string", "value": "vmware"}]},
                ],
            },
        ),
    )
    rules = load_rules(rules_file)
    assert len(rules) == 2
    nested = next(rule for rule in rules if rule.id == "CV-TEST-NESTED")
    assert nested.severity == "critical"
    assert nested.attck == ("T1059.003",)
    assert isinstance(nested.features, FeatureAnd)


def test_load_rules_accepts_top_level_list(tmp_path: Path) -> None:
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(json.dumps([_rule_payload()]), encoding="utf-8")
    assert [rule.id for rule in load_rules(rules_file)] == ["CV-TEST-RULE"]


def test_load_rules_malformed_json(tmp_path: Path) -> None:
    rules_file = tmp_path / "rules.json"
    rules_file.write_text("{not json", encoding="utf-8")
    with pytest.raises(AnalysisError, match="rules.json"):
        load_rules(rules_file)


def test_load_rules_missing_file(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="cannot read rules file"):
        load_rules(tmp_path / "absent.json")


def test_load_rules_unknown_feature_kind(tmp_path: Path) -> None:
    rules_file = _write_rules(
        tmp_path / "rules.json",
        _rule_payload(features={"kind": "regex", "value": "x"}),
    )
    with pytest.raises(AnalysisError, match="unknown feature kind"):
        load_rules(rules_file)


def test_load_rules_too_deep_tree(tmp_path: Path) -> None:
    node: dict[str, Any] = {"kind": "string", "value": "x"}
    for _ in range(MAX_TREE_DEPTH + 1):
        node = {"kind": "or", "children": [node]}
    rules_file = _write_rules(tmp_path / "rules.json", _rule_payload(features=node))
    with pytest.raises(AnalysisError, match="deeper than"):
        load_rules(rules_file)


def test_load_rules_too_wide_node(tmp_path: Path) -> None:
    node = {"kind": "or", "children": [{"kind": "string", "value": "x"}] * 17}
    rules_file = _write_rules(tmp_path / "rules.json", _rule_payload(features=node))
    with pytest.raises(AnalysisError, match="the cap is 16"):
        load_rules(rules_file)


def test_load_rules_missing_and_bad_fields(tmp_path: Path) -> None:
    bad_severity = _write_rules(
        tmp_path / "a.json", _rule_payload(severity="extreme")
    )
    with pytest.raises(AnalysisError, match="severity must be one of"):
        load_rules(bad_severity)
    bad_attck = _write_rules(
        tmp_path / "b.json", _rule_payload(attck=["not-a-technique"])
    )
    with pytest.raises(AnalysisError, match="attck"):
        load_rules(bad_attck)
    missing = _write_rules(tmp_path / "c.json", _rule_payload(description=None))
    with pytest.raises(AnalysisError, match="'description'"):
        load_rules(missing)
    no_features = tmp_path / "d.json"
    no_features.write_text(
        json.dumps({"rules": [{k: v for k, v in _rule_payload().items() if k != "features"}]}),
        encoding="utf-8",
    )
    with pytest.raises(AnalysisError, match="'features'"):
        load_rules(no_features)


def test_load_rules_duplicate_id_later_wins(tmp_path: Path) -> None:
    rules_file = _write_rules(
        tmp_path / "rules.json",
        _rule_payload(name="first"),
        _rule_payload(name="second", severity="critical"),
    )
    rules = load_rules(rules_file)
    assert len(rules) == 1
    assert rules[0].name == "second"
    assert rules[0].severity == "critical"


# ---- detect_capabilities: errors and bounds ------------------------------------


def test_detect_nonexistent_path(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="no such binary file"):
        detect_capabilities(tmp_path / "ghost.bin")


def test_detect_string_limit_bounds(tmp_path: Path) -> None:
    binary = make_minimal_elf64(tmp_path / "min.bin")
    with pytest.raises(AnalysisError, match="string_limit"):
        detect_capabilities(binary, string_limit=0)
    with pytest.raises(AnalysisError, match="string_limit"):
        detect_capabilities(binary, string_limit=50_001)


def test_detect_bad_extra_rules_file(tmp_path: Path) -> None:
    binary = make_minimal_elf64(tmp_path / "min.bin")
    broken = tmp_path / "broken.json"
    broken.write_text("[]]", encoding="utf-8")
    with pytest.raises(AnalysisError, match="broken.json"):
        detect_capabilities(binary, extra_rules=broken)


# ---- detect_capabilities: end to end -------------------------------------------


def test_detect_negative_header_only_elf(tmp_path: Path) -> None:
    binary = make_minimal_elf64(tmp_path / "min.bin")
    report = detect_capabilities(binary)
    assert report.matches == ()
    assert report.warnings == ()
    assert report.truncated is False
    assert report.rule_count == len(BUILTIN_RULES)
    # No imports/exports/sections/strings exist, so non-matching rules that
    # need them are attributed to unavailable data, not absent features.
    assert "imports_unavailable" in report.skipped_counts
    assert "strings_unavailable" in report.skipped_counts


def test_detect_known_rules_on_string_payload(tmp_path: Path) -> None:
    binary = _elf_with_strings(
        tmp_path,
        b"cmd.exe /c del payload\x00http://update.example\x00helper",
    )
    report = detect_capabilities(binary)
    rule_ids = {match.rule_id for match in report.matches}
    assert "CV-CREATE-PROCESS" in rule_ids  # "cmd.exe" string
    assert "CV-HTTP-COMM" in rule_ids  # "http" string
    assert "CV-SELF-DELETE" in rule_ids  # "cmd.exe /c del" string
    # File-scope evidence only: no import table, so nothing critical fires.
    assert all(match.severity != "critical" for match in report.matches)
    for match in report.matches:
        assert match.evidence.confidence.value == "medium"
        assert match.fired_features
        for fired in match.fired_features:
            assert isinstance(fired, FiredFeature)
            assert fired.locations


def test_detect_extra_rules_append_and_override(tmp_path: Path) -> None:
    binary = make_elf64_with_text(tmp_path / "text.bin")
    rules_file = _write_rules(
        tmp_path / "rules.json",
        # Override a built-in id: this binary has no UPX sections, so the
        # built-in CV-UPX cannot fire -- the override must replace it.
        _rule_payload(id="CV-UPX", severity="critical", namespace="test/override"),
        # Plus one genuinely new rule.
        _rule_payload(id="CV-DOTTEXT", name="dottext", severity="medium"),
    )
    report = detect_capabilities(binary, extra_rules=rules_file)
    assert report.rule_count == len(BUILTIN_RULES) + 1  # dedupe by id, later wins
    by_id = {match.rule_id: match for match in report.matches}
    assert "CV-UPX" in by_id and by_id["CV-UPX"].severity == "critical"
    assert "CV-DOTTEXT" in by_id
    # The bare fixture still matches nothing from the built-in pack.
    assert set(by_id) == {"CV-UPX", "CV-DOTTEXT"}


def test_detect_matches_sorted_by_severity_then_id(tmp_path: Path) -> None:
    binary = make_elf64_with_text(tmp_path / "text.bin")
    rules_file = _write_rules(
        tmp_path / "rules.json",
        *[
            _rule_payload(id=f"CV-SORT-{tag}", severity=severity, name=severity)
            for severity, tag in (("low", "A"), ("critical", "B"), ("medium", "C"), ("high", "D"))
        ],
    )
    report = detect_capabilities(binary, extra_rules=rules_file)
    custom = [m for m in report.matches if m.rule_id.startswith("CV-SORT-")]
    assert [m.severity for m in custom] == ["critical", "high", "medium", "low"]
    assert [m.rule_id for m in custom] == [
        "CV-SORT-B",
        "CV-SORT-D",
        "CV-SORT-C",
        "CV-SORT-A",
    ]


def test_detect_truncation_is_reported(tmp_path: Path) -> None:
    payload = b"\x00".join(f"str{i:03d}".encode() for i in range(8))
    binary = _elf_with_strings(tmp_path, payload, name="many.bin")
    report = detect_capabilities(binary, string_limit=3)
    assert report.truncated is True
    assert report.warnings and "truncated" in report.warnings[0]
    assert report.evidence.extra["strings_kept"] == 3
    assert report.evidence.extra["strings_total"] > 3


def test_report_shape_and_json_safety(tmp_path: Path) -> None:
    binary = _elf_with_strings(tmp_path, b"cmd.exe\x00http://x\x00")
    report = detect_capabilities(binary)
    assert isinstance(report, CapabilityReport)
    assert report.format == "ELF"
    assert len(report.sha256) == 64
    payload = report.to_dict()
    json.dumps(payload)  # must not raise
    assert payload["match_count"] == len(payload["matches"])
    assert payload["rule_count"] == len(BUILTIN_RULES)
    assert set(payload["skipped_counts"]) <= {
        "imports_unavailable",
        "strings_unavailable",
        "exports_unavailable",
        "sections_unavailable",
    }
    for match in payload["matches"]:
        assert match["evidence"]["confidence"] == "medium"
        assert match["attck"] == list(match["attck"])


def test_end_to_end_committed_pe_sample() -> None:
    sample = REPO_ROOT / "samples" / "pe64_text.bin"
    if not sample.exists():  # pragma: no cover - the sample is committed
        pytest.skip("samples/pe64_text.bin not present")
    report = detect_capabilities(sample)
    # The sample has no imports, no suspicious strings, no UPX sections and
    # exports only codevanta_sample_main: the pack must stay silent.
    assert report.matches == ()
    assert report.warnings == ()
    assert report.format == "PE"
    assert report.architecture == "x86_64"
    assert report.rule_count == len(BUILTIN_RULES)
    assert report.skipped_counts.get("imports_unavailable") == len(
        [rule for rule in BUILTIN_RULES if "import" in _leaf_kinds(rule.features)]
    )


def test_rule_and_feature_constructors_enforce_bounds() -> None:
    children = tuple(FeatureString(f"s{i}") for i in range(17))
    with pytest.raises(AnalysisError, match="the cap is 16"):
        FeatureOr(children)
    with pytest.raises(AnalysisError, match="severity"):
        Rule(
            id="CV-BAD",
            name="bad",
            namespace="x/y",
            severity="apocalyptic",
            attck=(),
            description="invalid severity",
            features=FeatureString("x"),
        )
    with pytest.raises(AnalysisError, match="ATT&CK"):
        Rule(
            id="CV-BAD2",
            name="bad",
            namespace="x/y",
            severity="low",
            attck=("T99",),
            description="invalid technique",
            features=FeatureString("x"),
        )
    with pytest.raises(AnalysisError, match="substring"):
        FeatureString("x", kind="regex")
    with pytest.raises(AnalysisError, match="exceeds the cap"):
        deep: Any = FeatureString("x")
        for _ in range(MAX_TREE_DEPTH):
            deep = FeatureOr((deep,))
        Rule(
            id="CV-DEEP",
            name="deep",
            namespace="x/y",
            severity="low",
            attck=(),
            description="too deep",
            features=deep,
        )


# ---- CLI ------------------------------------------------------------------------


def test_cli_capabilities_table_and_json(elf64_text_path: Path) -> None:
    """`codevanta capabilities` renders the table and --json round-trips."""
    import json as _json

    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    result = runner.invoke(cli, ["capabilities", str(elf64_text_path)])
    assert result.exit_code == 0, result.output
    assert "rules evaluated" in result.output

    result = runner.invoke(cli, ["capabilities", str(elf64_text_path), "--json"])
    assert result.exit_code == 0, result.output
    payload = _json.loads(result.output)
    assert payload["rule_count"] >= 14
    assert payload["matches"] == []


def test_cli_capabilities_error_exit(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    result = runner.invoke(cli, ["capabilities", str(tmp_path / "missing.bin")])
    assert result.exit_code == 2
    assert "no such binary file" in result.output

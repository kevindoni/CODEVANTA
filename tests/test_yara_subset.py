"""Tests for the YARA-subset rule matching engine.

The parser is exercised directly on rule text (AST shape and typed error
paths); the matcher runs end to end on synthetic byte files written to
``tmp_path`` and on the committed ``samples/pe64_text.bin``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from codevanta.analysis.yara_subset import (
    AllOf,
    And,
    AnyOf,
    FileSize,
    HexByte,
    HexJump,
    HexPattern,
    NOf,
    Not,
    Or,
    StrCount,
    StrTruthy,
    TextPattern,
    YaraMatchReport,
    load_rules_file,
    match_rules,
    parse_rules,
)
from codevanta.core.report import AnalysisError

REPO_ROOT = Path(__file__).resolve().parents[1]


def _write(tmp_path: Path, data: bytes, name: str = "target.bin") -> Path:
    """Write one synthetic target file."""
    target = tmp_path / name
    target.write_bytes(data)
    return target


FULL_RULES = """\
/* header comment */
rule full_shape
{
    meta:
        author = "cv"        // line comment
        score = 5
        stable = true
    strings:
        $a = "text"
        $b = "CaSe" nocase
        $c = "wide" wide
        $d = { AA BB ?? CC [4-8] }
    condition:
        $a and not $b and #c > 1 and filesize < 65536 and
        all of ($a*, $d*) and any of them and 2 of ($a, $b, $d)
}

rule second_rule
{
    condition:
        filesize >= 1
}
"""


# ---- parser: shapes ----------------------------------------------------------------


def test_parse_full_rule_shape_and_comments() -> None:
    rules = parse_rules(FULL_RULES)
    assert [rule.name for rule in rules] == ["full_shape", "second_rule"]
    rule = rules[0]
    assert rule.meta == {"author": "cv", "score": 5, "stable": True}
    assert set(rule.strings) == {"a", "b", "c", "d"}
    assert rule.strings["a"] == TextPattern(text="text")
    assert rule.strings["b"] == TextPattern(text="CaSe", nocase=True)
    assert rule.strings["c"] == TextPattern(text="wide", wide=True)
    assert rule.strings["d"] == HexPattern(
        tokens=(
            HexByte(0xAA, 0xFF),
            HexByte(0xBB, 0xFF),
            HexByte(0x00, 0x00),
            HexByte(0xCC, 0xFF),
            HexJump(4, 8),
        )
    )
    condition = rule.condition
    assert isinstance(condition, And)
    assert len(condition.children) == 7
    truthy, negated, count, filesize, all_of, any_of, n_of = condition.children
    assert truthy == StrTruthy(name="a")
    assert negated == Not(child=StrTruthy(name="b"))
    assert count == StrCount(name="c", op=">", value=1)
    assert filesize == FileSize(op="<", value=65536)
    assert all_of == AllOf(items=("a", "d"))
    assert any_of == AnyOf(items=("a", "b", "c", "d"))
    assert n_of == NOf(count=2, items=("a", "b", "d"))
    # Second rule: no strings section, hex-literal file size.
    assert rules[1].strings == {}
    assert rules[1].condition == FileSize(op=">=", value=1)
    json.dumps(rule.to_dict())  # JSON-safe


def test_parse_or_and_parentheses() -> None:
    rules = parse_rules(
        'rule orrule { strings: $a = "x" $b = "y" '
        "condition: $a or ($b and not $a) }"
    )
    condition = rules[0].condition
    assert isinstance(condition, Or)
    assert condition.children[0] == StrTruthy(name="a")
    assert isinstance(condition.children[1], And)
    assert isinstance(condition.children[1].children[1], Not)
    # Hex integer literals decode.
    rules2 = parse_rules("rule h { condition: filesize == 0x10 }")
    assert rules2[0].condition == FileSize(op="==", value=16)


def test_parse_string_escapes() -> None:
    rules = parse_rules(
        r'rule esc { strings: $a = "tab\tquote\"hex\x41" condition: $a }'
    )
    assert rules[0].strings["a"] == TextPattern(text='tab\tquote"hexA')
    with pytest.raises(AnalysisError, match="unsupported escape"):
        parse_rules(r'rule esc { strings: $a = "\q" condition: $a }')


# ---- parser: typed error paths -------------------------------------------------------


def test_error_unsupported_modifier() -> None:
    for modifier in ("ascii", "fullword"):
        text = f'rule modrule {{ strings: $a = "x" {modifier} condition: $a }}'
        with pytest.raises(AnalysisError, match=f"rule 'modrule'.*{modifier!r}"):
            parse_rules(text)


def test_error_regex_string() -> None:
    text = "rule rregex { strings: $a = /ab/ condition: $a }"
    with pytest.raises(AnalysisError, match="regex strings.*not supported"):
        parse_rules(text)


def test_error_unbounded_jump() -> None:
    for payload in ("AA [*] BB", "AA [2-] BB"):
        text = f"rule jump {{ strings: $h = {{ {payload} }} condition: $h }}"
        with pytest.raises(AnalysisError, match="unbounded jump"):
            parse_rules(text)


def test_error_jump_span_cap() -> None:
    for payload in ("AA [1-100] BB", "AA [70] BB"):
        text = f"rule jump {{ strings: $h = {{ {payload} }} condition: $h }}"
        with pytest.raises(AnalysisError, match="maximum jump span of 64"):
            parse_rules(text)


def test_error_uneven_hex_digits() -> None:
    text = "rule hexrule { strings: $h = { ABC } condition: $h }"
    with pytest.raises(AnalysisError, match="odd number of hex digits"):
        parse_rules(text)


def test_error_hex_alternation() -> None:
    text = "rule hexrule { strings: $h = { AA (BB | CC) DD } condition: $h }"
    with pytest.raises(AnalysisError, match="alternation"):
        parse_rules(text)


def test_error_unknown_condition_token() -> None:
    text = 'rule modrule { strings: $a = "x" condition: pe.machine == 14 }'
    with pytest.raises(AnalysisError, match="rule 'modrule'.*unexpected 'pe'"):
        parse_rules(text)
    text2 = "rule loop { strings: $a = \"x\" condition: for any of them : ( $a ) }"
    with pytest.raises(AnalysisError, match="rule 'loop'.*unexpected 'for'"):
        parse_rules(text2)


def test_error_import_statement() -> None:
    text = 'import "pe"\nrule r { condition: filesize > 0 }'
    with pytest.raises(AnalysisError, match="import statements are not supported"):
        parse_rules(text)


def test_error_duplicate_rule_names() -> None:
    text = 'rule dup { condition: filesize > 0 } rule dup { condition: filesize > 0 }'
    with pytest.raises(AnalysisError, match="duplicate rule name 'dup'"):
        parse_rules(text)


def test_error_empty_rules_input() -> None:
    with pytest.raises(AnalysisError, match="no rules found"):
        parse_rules("")
    with pytest.raises(AnalysisError, match="no rules found"):
        parse_rules("// nothing\n/* still nothing */")


def test_error_undefined_string_reference() -> None:
    text = 'rule ref { strings: $a = "x" condition: $z }'
    with pytest.raises(AnalysisError, match="rule 'ref'.*undefined string"):
        parse_rules(text)


def test_error_empty_wildcard_set() -> None:
    text = 'rule set { strings: $a = "x" condition: all of ($x*) }'
    with pytest.raises(AnalysisError, match="selects no strings"):
        parse_rules(text)


def test_error_other_unsupported_syntax() -> None:
    with pytest.raises(AnalysisError, match="boolean literal"):
        parse_rules("rule b { condition: true }")
    with pytest.raises(AnalysisError, match="'global' rules"):
        parse_rules("global rule g { condition: filesize > 0 }")
    with pytest.raises(AnalysisError, match=r"expected '\{'"):
        parse_rules("rule tagged : epic { condition: filesize > 0 }")
    with pytest.raises(AnalysisError, match="got 'at'"):
        parse_rules('rule at { strings: $a = "x" condition: $a at 0x100 }')


# ---- matcher: synthetic files --------------------------------------------------------


def test_match_text_string_exact_offsets(tmp_path: Path) -> None:
    target = _write(tmp_path, b"--PATTERN--PATTERN--")
    report = match_rules(
        target, rules_text='rule t { strings: $a = "PATTERN" condition: $a }'
    )
    assert isinstance(report, YaraMatchReport)
    assert report.rule_count == 1
    row = report.matches[0]
    assert row.rule_name == "t"
    assert row.condition_satisfied is True
    (string_row,) = row.string_matches
    assert string_row.string_id == "$a"
    assert string_row.offsets == (2, 11)
    assert string_row.total == 2
    assert string_row.truncated is False


def test_match_overlapping_occurrences(tmp_path: Path) -> None:
    target = _write(tmp_path, b"aaaa")
    report = match_rules(
        target,
        rules_text='rule o { strings: $a = "aa" condition: #a == 3 }',
    )
    (row,) = report.matches
    assert row.string_matches[0].offsets == (0, 1, 2)


def test_match_nocase(tmp_path: Path) -> None:
    target = _write(tmp_path, b"pAtTeRn tExT")
    hit = match_rules(
        target, rules_text='rule n { strings: $a = "pattern" nocase condition: $a }'
    )
    assert hit.matches[0].string_matches[0].offsets == (0,)
    miss = match_rules(
        target, rules_text='rule n { strings: $a = "pattern" condition: $a }'
    )
    assert miss.matches == ()
    assert miss.evaluations[0].condition_satisfied is False


def test_match_wide_utf16le(tmp_path: Path) -> None:
    target = _write(tmp_path, b"\xff" + "wide payload".encode("utf-16-le") + b"\xfe")
    hit = match_rules(
        target, rules_text='rule w { strings: $a = "wide payload" wide condition: $a }'
    )
    assert hit.matches[0].string_matches[0].offsets == (1,)
    miss = match_rules(
        target, rules_text='rule w { strings: $a = "wide payload" condition: $a }'
    )
    assert miss.evaluations[0].condition_satisfied is False
    mixed = _write(tmp_path, "MiXeD CaSe".encode("utf-16-le"), name="mixed.bin")
    combo = match_rules(
        mixed,
        rules_text='rule wc { strings: $a = "mixed case" wide nocase condition: $a }',
    )
    assert combo.matches[0].string_matches[0].offsets == (0,)


def test_match_hex_wildcard_and_jump(tmp_path: Path) -> None:
    data = bytes([0x00, 0xAA, 0xBB, 0x12, 0xCC, 0xDE, 0xAD, 0xDE, 0xAD, 0xC0, 0xDD, 0x00])
    target = _write(tmp_path, data)

    def scan(pattern: str) -> tuple[int, ...]:
        report = match_rules(
            target, rules_text=f"rule h {{ strings: $h = {{ {pattern} }} condition: $h }}"
        )
        if not report.matches:
            return ()
        return report.matches[0].string_matches[0].offsets

    assert scan("AA BB ?? CC [2-4] C0 DD") == (1,)
    assert scan("AA BB ?2 CC [2-4] C0 DD") == (1,)  # nibble wildcard ?2 matches 0x12
    assert scan("AA BB ?? CC [1-1] C0 DD") == ()  # jump of 1 lands on 0xAD, not 0xC0
    assert scan("DE AD") == (5, 7)  # the pattern occurs at both DE positions
    assert scan("?? ?? ??") == tuple(range(len(data) - 2))  # any three bytes


def test_match_count_comparisons(tmp_path: Path) -> None:
    target = _write(tmp_path, b"needle needle needle")

    def satisfies(condition: str) -> bool:
        report = match_rules(
            target,
            rules_text=f'rule c {{ strings: $a = "needle" condition: {condition} }}',
        )
        return bool(report.matches)

    assert satisfies("#a == 3")
    assert satisfies("#a >= 2")
    assert satisfies("#a > 2")
    assert not satisfies("#a > 3")
    assert not satisfies("#a < 3")
    assert not satisfies("#a != 3")


def test_match_filesize_condition(tmp_path: Path) -> None:
    target = _write(tmp_path, b"abcdefghijklmnopqrstuvwxyz")

    def satisfies(condition: str) -> bool:
        report = match_rules(target, rules_text=f"rule f {{ condition: {condition} }}")
        return bool(report.matches)

    assert satisfies("filesize == 26")
    assert satisfies("filesize == 0x1a")
    assert satisfies("filesize >= 1")
    assert not satisfies("filesize > 26")
    assert not satisfies("filesize < 26")


def test_match_all_of_any_of_wildcard_sets(tmp_path: Path) -> None:
    both = _write(tmp_path, b"alpha beta")
    one = _write(tmp_path, b"beta only", name="one.bin")

    all_both = match_rules(
        both,
        rules_text='rule s { strings: $x1 = "alpha" $x2 = "beta" '
        "condition: all of ($x*) }",
    )
    assert bool(all_both.matches)
    any_one = match_rules(
        one,
        rules_text='rule s { strings: $x1 = "alpha" $x2 = "beta" '
        "condition: any of ($x*) }",
    )
    assert bool(any_one.matches)
    all_one = match_rules(
        one,
        rules_text='rule s { strings: $x1 = "alpha" $x2 = "beta" '
        "condition: all of ($x*) }",
    )
    assert all_one.matches == ()
    assert all_one.evaluations[0].condition_satisfied is False


def test_match_n_of(tmp_path: Path) -> None:
    target = _write(tmp_path, b"alpha beta")
    rules = (
        'rule n { strings: $a = "alpha" $b = "beta" $c = "gamma" '
        "condition: 2 of ($a, $b, $c) }"
    )
    assert bool(match_rules(target, rules_text=rules).matches)
    rules_three = (
        'rule n3 { strings: $a = "alpha" $b = "beta" $c = "gamma" '
        "condition: 3 of them }"
    )
    report = match_rules(target, rules_text=rules_three)
    assert report.matches == ()
    assert report.evaluations[0].condition_satisfied is False


def test_negative_rule_not_satisfied(tmp_path: Path) -> None:
    target = _write(tmp_path, b"nothing to see here")
    report = match_rules(
        target, rules_text='rule miss { strings: $a = "absent" condition: $a }'
    )
    assert report.matches == ()
    (row,) = report.evaluations
    assert row.rule_name == "miss"
    assert row.condition_satisfied is False
    assert row.string_matches == ()
    assert row.evidence.confidence.value == "medium"
    assert report.truncated is False
    assert report.warnings == ()


def test_per_string_truncation_is_honest(tmp_path: Path) -> None:
    target = _write(tmp_path, b"ab" * 8)  # "ab" occurs 8 times (even offsets)
    report = match_rules(
        target,
        rules_text='rule cap { strings: $a = "ab" condition: #a == 8 }',
        max_matches_per_string=4,
    )
    assert report.truncated is True
    (string_row,) = report.evaluations[0].string_matches
    assert string_row.offsets == (0, 2, 4, 6)
    assert string_row.total == 8
    assert string_row.truncated is True
    assert any("kept 4 of 8" in warning for warning in report.warnings)
    # Counting continued, so the count condition still holds.
    assert report.evaluations[0].condition_satisfied is True
    assert bool(report.matches)


def test_global_match_budget(tmp_path: Path) -> None:
    target = _write(tmp_path, b"ab" * 8)
    report = match_rules(
        target,
        rules_text='rule budget { strings: $a = "abab" $b = "ab" '
        "condition: any of them }",
        max_strings=10,
    )
    rows = {row.string_id: row for row in report.evaluations[0].string_matches}
    assert rows["$a"].total == 7 and rows["$a"].truncated is False
    assert rows["$b"].total == 8
    assert len(rows["$b"].offsets) == 3  # 10 - 7 spent on $a
    assert rows["$b"].truncated is True
    assert report.truncated is True
    assert any("global match budget" in warning for warning in report.warnings)


def test_deterministic_order(tmp_path: Path) -> None:
    target = _write(tmp_path, b"alpha beta")
    report = match_rules(
        target,
        rules_text=(
            'rule zeta_rule { strings: $z = "alpha" condition: $z }\n'
            'rule alpha_rule { strings: $a = "beta" $b = "alpha" '
            "condition: all of them }"
        ),
    )
    assert [row.rule_name for row in report.evaluations] == ["alpha_rule", "zeta_rule"]
    assert [row.rule_name for row in report.matches] == ["alpha_rule", "zeta_rule"]
    assert [row.string_id for row in report.evaluations[0].string_matches] == [
        "$a",
        "$b",
    ]


def test_json_safety_and_evidence(tmp_path: Path) -> None:
    target = _write(tmp_path, b"--PATTERN--pattern--")
    report = match_rules(
        target,
        rules_text=(
            "rule j { meta: author = \"cv\" strings: $a = \"PATTERN\" nocase "
            "condition: $a }"
        ),
    )
    payload = report.to_dict()
    json.dumps(payload)  # must not raise
    (match_payload,) = payload["matches"]
    assert match_payload["meta"] == {"author": "cv"}
    assert match_payload["string_matches"][0]["offsets"] == ["0x2", "0xb"]
    assert payload["truncated"] is False
    assert payload["evidence"]["source"] == "yara.subset"
    assert payload["evidence"]["method"] == "byte_pattern_scan"
    assert match_payload["string_matches"][0]["evidence"]["confidence"] == "certain"
    assert match_payload["evidence"]["confidence"] == "medium"
    assert match_payload["evidence"]["extra"]["fired"] == {"$a": 2}


# ---- file loading and argument validation ---------------------------------------------


def test_load_rules_file_roundtrip(tmp_path: Path) -> None:
    rules_file = tmp_path / "rules.yar"
    rules_file.write_text(FULL_RULES, encoding="utf-8")
    rules = load_rules_file(rules_file)
    assert [rule.name for rule in rules] == ["full_shape", "second_rule"]
    with pytest.raises(AnalysisError, match="cannot read rules file"):
        load_rules_file(tmp_path / "absent.yar")


def test_match_rules_argument_validation(tmp_path: Path) -> None:
    target = _write(tmp_path, b"data")
    rules_file = tmp_path / "rules.yar"
    rules_file.write_text("rule r { condition: filesize > 0 }", encoding="utf-8")
    good = "rule r { condition: filesize > 0 }"
    with pytest.raises(AnalysisError, match="exactly one of rules_text or rules_path"):
        match_rules(target, rules_text=good, rules_path=rules_file)
    with pytest.raises(AnalysisError, match="exactly one of rules_text or rules_path"):
        match_rules(target)
    with pytest.raises(AnalysisError, match="max_strings"):
        match_rules(target, rules_text=good, max_strings=0)
    with pytest.raises(AnalysisError, match="max_matches_per_string"):
        match_rules(target, rules_text=good, max_matches_per_string=0)
    with pytest.raises(AnalysisError, match="no such file"):
        match_rules(tmp_path / "ghost.bin", rules_text=good)


# ---- end to end on the committed sample ------------------------------------------------


def test_end_to_end_committed_pe_sample() -> None:
    sample = REPO_ROOT / "samples" / "pe64_text.bin"
    if not sample.exists():  # pragma: no cover - the sample is committed
        pytest.skip("samples/pe64_text.bin not present")
    rules = """
rule cv_marker_absent
{
    strings:
        $absent = "definitely not in this file"
    condition:
        $absent
}

rule cv_sample_marker
{
    strings:
        $marker = "codevanta x64 sample"
    condition:
        #marker == 1 and filesize == 1024
}
"""
    report = match_rules(sample, rules_text=rules)
    assert report.rule_count == 2
    assert report.sha256 == hashlib.sha256(sample.read_bytes()).hexdigest()
    # Evaluations sorted by rule name; only the marker rule fires.
    assert [row.rule_name for row in report.evaluations] == [
        "cv_marker_absent",
        "cv_sample_marker",
    ]
    assert report.evaluations[0].condition_satisfied is False
    (match,) = report.matches
    assert match.rule_name == "cv_sample_marker"
    (string_row,) = match.string_matches
    assert string_row.string_id == "$marker"
    assert string_row.offsets == (0x225,)  # offset from the strings extractor
    payload = report.to_dict()
    json.dumps(payload)
    assert payload["match_count"] == 1


# ---- CLI ------------------------------------------------------------------------


def test_cli_yara_table_and_error(tmp_path: Path) -> None:
    """`codevanta yara --rules` renders matches; bad grammar exits 2."""
    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    target = tmp_path / "t.bin"
    target.write_bytes(b"hello codevanta world codevanta again")
    rules = tmp_path / "r.yar"
    rules.write_text(
        'rule twice { strings: $a = "codevanta" condition: #a > 1 }',
        encoding="utf-8",
    )
    result = runner.invoke(cli, ["yara", str(target), "--rules", str(rules)])
    assert result.exit_code == 0, result.output
    assert "twice" in result.output

    bad = tmp_path / "bad.yar"
    bad.write_text(
        'rule bad { strings: $a = "x" condition: pe.machine == 1 }',
        encoding="utf-8",
    )
    result = runner.invoke(cli, ["yara", str(target), "--rules", str(bad)])
    assert result.exit_code == 2

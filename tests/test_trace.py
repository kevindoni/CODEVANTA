"""Tests for trace parsing: gdb text output and Frida JSON-lines messages.

Both traces are hand-written here, in exactly the shape the generated scripts
produce (see ``tests/test_dynamic.py`` for the generator side), so these tests
never need gdb or Frida installed and never depend on a saved session. Function
attribution is exercised twice: through the real
:func:`codevanta.core.functions.discover_functions` over a tiny ELF fixture, and
through hand-built candidates that pin down the size/next-start boundary rules.
"""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from codevanta.analysis.trace import (
    MAX_BACKTRACE_FRAMES,
    MAX_TRACE_HITS,
    MAX_TRACE_LINES,
    MAX_WARNINGS,
    TraceHit,
    TraceReport,
    parse_frida_trace,
    parse_gdb_trace,
)
from codevanta.core.functions import FunctionCandidate, discover_functions
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

TEXT_VA = 0x401000

#: A gdb session as the generated script prints it: two hits with backtraces,
#: wrapped in the noise gdb adds on its own.
GDB_TRACE = """\
Breakpoint 1 at 0x401000
HIT 0x401000 pc=0x401000 sp=0x7ffffffde0 fp=0x7ffffffde0 ps=0x246 rip=0x401000 rax=0x1
BACKTRACE
#0  0x0000000000401000 in ?? ()
#1  0x0000000000401010 in ?? ()
HIT 0x401002 pc=0x401002 sp=0x7ffffffdd0 fp=0x7ffffffdd0 ps=0x202 rip=0x401002 rax=0x0
BACKTRACE
#0  0x0000000000401002 in main ()
[Inferior 1 (process 1234) exited normally]
DONE 2 hits
"""


def _frida_message(
    hit: int,
    address: str,
    *,
    tid: int = 4321,
    args: list[str] | None = None,
) -> str:
    """Return one JSON-lines message in the shape the Frida hook sends."""
    return json.dumps(
        {
            "hit": hit,
            "address": address,
            "tid": tid,
            "args": args if args is not None else ["0x1", "0x2", "0x3", "0x4"],
        }
    )


def _candidate(
    address: int, *, name: str | None = None, size: int | None = None
) -> FunctionCandidate:
    """Return a function candidate with the evidence the dataclass requires."""
    return FunctionCandidate(
        address=address,
        name=name,
        size=size,
        source="binary.entry_point",
        confidence=Confidence.MEDIUM,
        evidence=Evidence(
            source="binary.entry_point",
            method="entry_point",
            confidence=Confidence.MEDIUM,
            address=address,
        ),
    )


# --------------------------------------------------------------------------- #
# gdb traces
# --------------------------------------------------------------------------- #


def test_gdb_trace_parses_hits_registers_and_backtraces() -> None:
    report = parse_gdb_trace(GDB_TRACE)
    assert isinstance(report, TraceReport)
    assert report.provider == "gdb"
    assert report.total_hits == 2
    assert report.truncated is False
    assert report.warnings == ()
    first, second = report.hits
    assert isinstance(first, TraceHit)
    assert first.index == 1
    assert first.kind == "breakpoint"
    assert first.address == TEXT_VA
    assert first.registers["rip"] == 0x401000
    assert first.registers["ps"] == 0x246
    assert first.backtrace == (0x401000, 0x401010)
    assert second.index == 2
    assert second.address == TEXT_VA + 2
    assert second.backtrace == (0x401002,)
    assert report.unique_addresses == (TEXT_VA, TEXT_VA + 2)


def test_gdb_trace_ignores_gdb_noise() -> None:
    noise = "\n".join(
        [
            "Reading symbols from sample.bin...",
            "Breakpoint 1 at 0x401000",
            "Thread 1 \"sample\" hit Breakpoint 1",
            "[Inferior 1 (process 1234) exited with code 01]",
            "DONE 0 hits",
        ]
    )
    report = parse_gdb_trace(noise)
    assert report.hits == ()
    assert report.total_hits == 0
    assert report.warnings == ()
    assert report.truncated is False


def test_gdb_trace_warns_about_an_unparseable_hit_line() -> None:
    report = parse_gdb_trace("\n".join(["HIT not-an-address", "HIT 0x401000 pc=0x401000"]))
    assert report.total_hits == 1
    assert report.hits[0].address == TEXT_VA
    assert any("unparseable HIT line" in warning for warning in report.warnings)


def test_gdb_trace_marks_a_session_limit_as_truncation() -> None:
    report = parse_gdb_trace(
        "\n".join(
            [
                "HIT 0x401000 pc=0x401000",
                "LIMIT 64 hits reached",
                "DONE 64 hits",
            ]
        )
    )
    assert report.truncated is True
    assert report.total_hits == 1
    assert any("hit limit" in warning for warning in report.warnings)


def test_gdb_trace_respects_the_line_budget() -> None:
    report = parse_gdb_trace(GDB_TRACE, max_lines=3)
    assert report.truncated is True
    assert any("truncated to the first 3 line(s)" in warning for warning in report.warnings)
    assert report.evidence.extra["lines_scanned"] == 3
    assert report.evidence.extra["line_limit"] == 3


def test_gdb_trace_respects_the_hit_budget() -> None:
    trace = "\n".join(
        f"HIT 0x{0x401000 + offset:x} pc=0x{0x401000 + offset:x}"
        for offset in (0, 2, 4, 6)
    )
    report = parse_gdb_trace(trace, max_hits=2)
    assert len(report.hits) == 2
    assert report.total_hits == 4
    assert report.truncated is True
    assert report.evidence.extra["kept_hits"] == 2


def test_gdb_trace_bounds_the_backtrace_length() -> None:
    frames = "\n".join(
        f"#0  0x{0x401000 + index:x} in ??" for index in range(MAX_BACKTRACE_FRAMES + 10)
    )
    trace = "\n".join(["HIT 0x401000 pc=0x401000", "BACKTRACE", frames])
    report = parse_gdb_trace(trace)
    assert len(report.hits[0].backtrace) == MAX_BACKTRACE_FRAMES


def test_frames_before_a_backtrace_marker_are_not_collected() -> None:
    trace = "\n".join(["#0  0x0000000000401000 in ?? ()", "HIT 0x401000 pc=0x401000"])
    report = parse_gdb_trace(trace)
    assert report.hits[0].backtrace == ()


@pytest.mark.parametrize("max_lines", [0, -1, MAX_TRACE_LINES + 1, "10", 10.0, False])
def test_gdb_trace_rejects_an_out_of_range_line_budget(max_lines: object) -> None:
    with pytest.raises(AnalysisError) as excinfo:
        parse_gdb_trace(GDB_TRACE, max_lines=max_lines)  # type: ignore[arg-type]
    assert "max_lines" in str(excinfo.value)


@pytest.mark.parametrize("max_hits", [0, -1, MAX_TRACE_HITS + 1, "2", True])
def test_gdb_trace_rejects_an_out_of_range_hit_budget(max_hits: object) -> None:
    with pytest.raises(AnalysisError) as excinfo:
        parse_gdb_trace(GDB_TRACE, max_hits=max_hits)  # type: ignore[arg-type]
    assert "max_hits" in str(excinfo.value)


def test_an_empty_trace_is_an_empty_report() -> None:
    for parser in (parse_gdb_trace, parse_frida_trace):
        report = parser("")
        assert report.hits == ()
        assert report.total_hits == 0
        assert report.truncated is False
        assert report.warnings == ()
        assert report.unique_addresses == ()
        assert report.function_coverage == {}


# --------------------------------------------------------------------------- #
# frida traces
# --------------------------------------------------------------------------- #


def test_frida_trace_parses_json_messages() -> None:
    trace = "\n".join(
        [
            _frida_message(1, "0x401000"),
            _frida_message(2, "0x401004", tid=99, args=["0xa", "0xb"]),
        ]
    )
    report = parse_frida_trace(trace)
    assert report.provider == "frida"
    assert report.total_hits == 2
    assert report.truncated is False
    assert report.warnings == ()
    first, second = report.hits
    assert first.kind == "message"
    assert first.index == 1
    assert first.address == TEXT_VA
    assert first.registers == {"tid": 4321, "arg0": 1, "arg1": 2, "arg2": 3, "arg3": 4}
    assert first.backtrace == ()
    assert second.index == 2
    assert second.registers == {"tid": 99, "arg0": 0xA, "arg1": 0xB}


def test_frida_trace_skips_malformed_lines_with_warnings() -> None:
    trace = "\n".join(
        [
            _frida_message(1, "0x401000"),
            "definitely not json",
            "[1, 2, 3]",
            json.dumps({"unrelated": True}),
            json.dumps({"hit": 2}),
        ]
    )
    report = parse_frida_trace(trace)
    assert report.total_hits == 1
    assert len(report.hits) == 1
    messages = " ".join(report.warnings)
    assert "malformed JSON message" in messages
    assert "not a JSON object" in messages
    assert "known event" in messages
    assert "usable address" in messages


def test_frida_trace_treats_a_limit_event_as_truncation() -> None:
    trace = "\n".join(
        [
            _frida_message(1, "0x401000"),
            json.dumps({"event": "limit", "hits": 1}),
        ]
    )
    report = parse_frida_trace(trace)
    assert report.truncated is True
    assert report.total_hits == 1
    assert any("hit limit" in warning for warning in report.warnings)


def test_frida_trace_reports_provider_errors_as_warnings() -> None:
    trace = "\n".join(
        [
            json.dumps({"event": "error", "message": "module not found"}),
            _frida_message(1, "0x401000"),
        ]
    )
    report = parse_frida_trace(trace)
    assert report.total_hits == 1
    assert report.truncated is False
    assert any("provider error: module not found" in warning for warning in report.warnings)


def test_frida_trace_keeps_four_arguments_and_warns_about_non_numeric_ones() -> None:
    trace = _frida_message(
        1,
        "0x401000",
        args=["0x1", "not-a-number", "0x3", "0x4", "0x5", "0x6"],
    )
    report = parse_frida_trace(trace)
    registers = report.hits[0].registers
    assert "arg1" not in registers
    assert registers["arg3"] == 4
    assert "arg4" not in registers
    assert any("argument 1 is not a number" in warning for warning in report.warnings)


def test_frida_trace_ignores_a_non_list_args_field() -> None:
    trace = json.dumps({"hit": 1, "address": "0x401000", "tid": 7, "args": "nope"})
    report = parse_frida_trace(trace)
    assert report.hits[0].registers == {"tid": 7}
    assert any("'args' is not a list" in warning for warning in report.warnings)


def test_frida_trace_accepts_an_integer_address() -> None:
    trace = json.dumps({"hit": 1, "address": TEXT_VA})
    report = parse_frida_trace(trace)
    assert report.hits[0].address == TEXT_VA


def test_frida_trace_respects_the_hit_budget() -> None:
    trace = "\n".join(_frida_message(number, f"0x{0x401000 + number:x}") for number in (1, 2, 3))
    report = parse_frida_trace(trace, max_hits=1)
    assert len(report.hits) == 1
    assert report.total_hits == 3
    assert report.truncated is True


def test_frida_trace_respects_the_line_budget() -> None:
    trace = "\n".join(_frida_message(number, "0x401000") for number in (1, 2, 3))
    report = parse_frida_trace(trace, max_lines=2)
    assert report.truncated is True
    assert report.total_hits == 2
    assert report.evidence.extra["lines_scanned"] == 2


def test_blank_lines_are_skipped_without_warnings() -> None:
    gdb_report = parse_gdb_trace("\n\nHIT 0x401000 pc=0x401000\n\n")
    assert gdb_report.total_hits == 1
    assert gdb_report.warnings == ()
    frida_report = parse_frida_trace("\n" + _frida_message(1, "0x401000") + "\n\n")
    assert frida_report.total_hits == 1
    assert frida_report.warnings == ()


def test_function_index_ignores_a_zero_address_and_duplicates() -> None:
    candidates = [
        _candidate(0, name="bogus", size=None),
        _candidate(TEXT_VA, name="main", size=0x20),
        _candidate(TEXT_VA, name="main-again", size=0x20),
    ]
    report = parse_gdb_trace("HIT 0x401000 pc=0x401000", functions=candidates)
    assert report.hits[0].function == TEXT_VA
    assert report.hits[0].function_name == "main"


def test_frida_trace_skips_boolean_and_empty_arguments() -> None:
    trace = json.dumps(
        {"hit": 1, "address": "0x401000", "tid": 5, "args": [True, "", "0x7"]}
    )
    report = parse_frida_trace(trace)
    assert report.hits[0].registers == {"tid": 5, "arg2": 7}
    assert any("argument 0 is not a number" in warning for warning in report.warnings)
    assert any("argument 1 is not a number" in warning for warning in report.warnings)


def test_trace_warnings_are_capped() -> None:
    report = parse_gdb_trace("\n".join("HIT nope" for _ in range(MAX_WARNINGS + 10)))
    assert len(report.warnings) == MAX_WARNINGS + 1
    assert "further warnings suppressed" in report.warnings[-1]


# --------------------------------------------------------------------------- #
# Function attribution
# --------------------------------------------------------------------------- #


def test_hits_map_onto_functions_discovered_in_a_real_elf(elf64_text_path: Path) -> None:
    info: BinaryInfo = BinaryLoader().load(elf64_text_path)
    candidates = discover_functions(info)
    assert [candidate.address for candidate in candidates] == [TEXT_VA]

    trace = "\n".join(
        [
            "HIT 0x401000 pc=0x401000",
            "BACKTRACE",
            "#0  0x0000000000401000 in ?? ()",
            "HIT 0x401002 pc=0x401002",
        ]
    )
    report = parse_gdb_trace(trace, info=info, functions=candidates)
    assert [hit.function for hit in report.hits] == [TEXT_VA, TEXT_VA]
    assert report.function_coverage == {TEXT_VA: 2}
    assert report.evidence.extra["format"] == "ELF"
    assert report.evidence.extra["image_base"] == f"0x{info.image_base:x}"


def test_hits_are_attributed_through_a_known_size() -> None:
    candidates = [
        _candidate(TEXT_VA, name="main", size=0x20),
        _candidate(0x402000, name="helper", size=0x10),
    ]
    trace = "\n".join(
        [
            "HIT 0x401004 pc=0x401004",
            "HIT 0x401020 pc=0x401020",
            "HIT 0x402004 pc=0x402004",
        ]
    )
    report = parse_gdb_trace(trace, functions=candidates)
    by_address = {hit.address: hit for hit in report.hits}
    assert by_address[0x401004].function == TEXT_VA
    assert by_address[0x401004].function_name == "main"
    # 0x401020 is one byte past the end of main: unattributed, not guessed.
    assert by_address[0x401020].function is None
    assert by_address[0x401020].function_name is None
    assert by_address[0x402004].function_name == "helper"
    assert report.function_coverage == {TEXT_VA: 1, 0x402000: 1}


def test_a_size_less_candidate_stops_at_the_next_one() -> None:
    candidates = [
        _candidate(TEXT_VA, size=None),
        _candidate(TEXT_VA + 0x100, name="next", size=0x10),
    ]
    trace = "\n".join([f"HIT 0x{TEXT_VA + offset:x} pc=0x0" for offset in (0x50, 0x110)])
    report = parse_gdb_trace(trace, functions=candidates)
    assert report.hits[0].function == TEXT_VA
    assert report.hits[1].function is None


def test_a_hit_below_every_candidate_is_unattributed() -> None:
    report = parse_gdb_trace("HIT 0x1000 pc=0x1000", functions=[_candidate(TEXT_VA)])
    assert report.hits[0].function is None
    assert report.function_coverage == {}


def test_frida_hits_are_attributed_too() -> None:
    candidates = [_candidate(TEXT_VA, name="entry", size=0x40)]
    report = parse_frida_trace(_frida_message(1, "0x401010"), functions=candidates)
    assert report.hits[0].function == TEXT_VA
    assert report.hits[0].function_name == "entry"
    assert report.function_coverage == {TEXT_VA: 1}


# --------------------------------------------------------------------------- #
# Serialization
# --------------------------------------------------------------------------- #


def test_report_to_dict_is_json_safe() -> None:
    candidates = [_candidate(TEXT_VA, name="main", size=0x20)]
    gdb_report = parse_gdb_trace(GDB_TRACE, functions=candidates)
    frida_report = parse_frida_trace(_frida_message(1, "0x401000"), functions=candidates)
    for report in (gdb_report, frida_report):
        payload = json.loads(json.dumps(report.to_dict()))
        assert set(payload) == {
            "provider",
            "hits",
            "total_hits",
            "truncated",
            "unique_addresses",
            "function_coverage",
            "warnings",
            "evidence",
        }
        assert payload["hits"][0]["address"].startswith("0x")
        assert isinstance(payload["hits"][0]["registers"], dict)
        assert set(payload["function_coverage"]) == {"0x401000"}
        assert sum(payload["function_coverage"].values()) == report.total_hits
        assert payload["evidence"]["source"] == f"{report.provider}.trace"


def test_evidence_confidence_drops_when_the_parse_had_warnings() -> None:
    clean = parse_gdb_trace("HIT 0x401000 pc=0x401000")
    assert clean.evidence.confidence is Confidence.CERTAIN
    noisy = parse_gdb_trace("HIT nope")
    assert noisy.evidence.confidence is Confidence.HIGH
    assert noisy.evidence.extra["warning_count"] == 1


def test_hit_and_report_are_frozen() -> None:
    report = parse_gdb_trace("HIT 0x401000 pc=0x401000")
    with pytest.raises(FrozenInstanceError):
        report.total_hits = 5  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        report.hits[0].address = 0  # type: ignore[misc]

"""Tests for the FLOSS-style stack-string engine over tiny synthetic ELF samples.

Every sample is assembled byte by byte (the ``bytes.fromhex`` fixtures below
were hand-assembled) and written as a minimal ELF by this module, mirroring
``tests/test_emulate.py``: no shared fixtures, no real binaries, and no host
code is ever executed -- the bytes only ever run inside unicorn's emulator,
on the stack of the emulator's own private CPU.

The module is skipped wholesale when unicorn is not installed, exactly like
``tests/test_emulate.py``, so the rest of the suite keeps passing without the
optional extra.

Note for Windows runs: unicorn's ``mem_map`` raises and handles a first-chance
access violation internally, which CPython's ``faulthandler`` (enabled by
pytest) prints even though nothing failed. Run with ``-p no:faulthandler`` to
silence that message.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

import pytest

from codevanta.analysis import stackstrings
from codevanta.analysis.stackstrings import (
    MAX_FUNCTIONS,
    MAX_MAX_INSTRUCTIONS,
    MAX_STRINGS_PER_FUNCTION,
    MAX_VALUE_CHARS,
    StackStringReport,
    extract_stack_strings,
)
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError

pytest.importorskip("unicorn")

#: Virtual address of .text in the ELF64 samples (same as tests/test_emulate.py).
TEXT_VA = 0x401000

#: Virtual address of .text in the ELF32 samples.
TEXT32_VA = 0x8048000

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHT_PROGBITS = 1
SHT_STRTAB = 3

_TEXT_OFFSET = 0x40
_SHSTRTAB = b"\x00.text\x00.shstrtab\x00"
_NAME_TEXT = 1
_NAME_SHSTRTAB = 7

#: x86-64 (and x86) ``mov dword ptr [rsp+0x20], 'Hell'; mov dword ptr
#: [rsp+0x24], 'o Wo'; mov dword ptr [rsp+0x28], 'rld\0'; ret`` -- the stack
#: ends up holding ``Hello World\0``. The same encoding assembles for
#: ``[esp+0x20]`` in 32-bit mode (SIB byte 0x24 selects esp there).
CODE_HELLO_WORLD = bytes.fromhex(
    "c7442420" "48656c6c"  # mov dword ptr [rsp+0x20], "Hell"
    "c7442424" "6f20576f"  # mov dword ptr [rsp+0x24], "o Wo"
    "c7442428" "726c6400"  # mov dword ptr [rsp+0x28], "rld\0"
    "c3"                   # ret
)

#: ``mov dword ptr [rsp+0x30], 'A\0B\0'; mov dword ptr [rsp+0x34], 'C\0D\0';
#: ret`` -- a UTF-16LE ``ABCD`` on the stack (ASCII sees only 1-char runs).
CODE_UTF16_ABCD = bytes.fromhex(
    "c7442430" "41004200"  # mov dword ptr [rsp+0x30], "A\0B\0"
    "c7442434" "43004400"  # mov dword ptr [rsp+0x34], "C\0D\0"
    "c3"                   # ret
)

#: The same string written twice at different offsets: ``mov dword ptr
#: [rsp+0x20], 'Dupe'; mov dword ptr [rsp+0x28], 'Dupe'; ret``. The gap at
#: +0x24 stays zero, so two separate runs appear and must dedupe to one.
CODE_DUPE = bytes.fromhex(
    "c7442420" "44757065"  # mov dword ptr [rsp+0x20], "Dupe"
    "c7442428" "44757065"  # mov dword ptr [rsp+0x28], "Dupe"
    "c3"                   # ret
)

#: Two distinct strings: ``mov dword ptr [rsp+0x20], 'Firs'; mov dword ptr
#: [rsp+0x28], 'Seco'; ret`` -- used for the per-function cap test.
CODE_TWO_STRINGS = bytes.fromhex(
    "c7442420" "46697273"  # mov dword ptr [rsp+0x20], "Firs"
    "c7442428" "5365636f"  # mov dword ptr [rsp+0x28], "Seco"
    "c3"                   # ret
)

#: x86-64 ``mov eax, 42; ret`` (from tests/test_emulate.py): a function that
#: never writes the stack at all.
CODE_MOV_EAX_42 = bytes.fromhex("b82a000000c3")


def _write_elf(path: Path, code: bytes, *, bits: int, va: int) -> Path:
    """Write a tiny ELF (32- or 64-bit) whose .text holds ``code``.

    The same three-section layout ``tests/test_emulate.py`` builds: null,
    ``.text`` at ``va`` and ``.shstrtab``, no program headers -- enough for
    :class:`~codevanta.core.loader.BinaryLoader` and for emulation.
    """
    text_offset = _TEXT_OFFSET
    shstr_offset = text_offset + len(code)
    sh_offset = (shstr_offset + len(_SHSTRTAB) + 7) & ~7
    blob = bytearray(sh_offset)
    if bits == 64:
        ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
        header = ident + struct.pack(
            "<HHIQQQIHHHHHH",
            2,                  # e_type = ET_EXEC
            62,                 # e_machine = EM_X86_64
            1,                  # e_version
            va,                 # e_entry
            0,                  # e_phoff
            sh_offset,          # e_shoff
            0,                  # e_flags
            64,                 # e_ehsize
            56,                 # e_phentsize
            0,                  # e_phnum
            64,                 # e_shentsize
            3,                  # e_shnum: null, .text, .shstrtab
            2,                  # e_shstrndx
        )
        text_header = struct.pack(
            "<IIQQQQIIQQ",
            _NAME_TEXT, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
            va, text_offset, len(code), 0, 0, 16, 0,
        )
        str_header = struct.pack(
            "<IIQQQQIIQQ",
            _NAME_SHSTRTAB, SHT_STRTAB, 0, 0, shstr_offset, len(_SHSTRTAB), 0, 0, 1, 0,
        )
    else:
        ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + bytes(8)
        header = ident + struct.pack(
            "<HHIIIIIHHHHHH",
            2,                  # e_type = ET_EXEC
            3,                  # e_machine = EM_386
            1,                  # e_version
            va,                 # e_entry
            0,                  # e_phoff
            sh_offset,          # e_shoff
            0,                  # e_flags
            52,                 # e_ehsize
            40,                 # e_phentsize
            0,                  # e_phnum
            40,                 # e_shentsize
            3,                  # e_shnum: null, .text, .shstrtab
            2,                  # e_shstrndx
        )
        text_header = struct.pack(
            "<IIIIIIIIII",
            _NAME_TEXT, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
            va, text_offset, len(code), 0, 0, 16, 0,
        )
        str_header = struct.pack(
            "<IIIIIIIIII",
            _NAME_SHSTRTAB, SHT_STRTAB, 0, 0, shstr_offset, len(_SHSTRTAB), 0, 0, 1, 0,
        )
    blob[0 : len(header)] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[shstr_offset : shstr_offset + len(_SHSTRTAB)] = _SHSTRTAB
    blob += bytes(64 if bits == 64 else 40) + text_header + str_header
    path.write_bytes(bytes(blob))
    return path


def _sample(tmp_path: Path, code: bytes, *, bits: int = 64, name: str = "sample.elf") -> Path:
    """Write a sample ELF with ``code`` in ``.text`` at the matching base."""
    va = TEXT_VA if bits == 64 else TEXT32_VA
    return _write_elf(tmp_path / name, code, bits=bits, va=va)


def _load(path: Path) -> BinaryInfo:
    """Load a sample through the real loader."""
    return BinaryLoader().load(path)


# ---- end-to-end recovery ------------------------------------------------------


def test_recovers_ascii_stack_string_from_discovered_function(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_HELLO_WORLD, name="hello.elf")

    report = extract_stack_strings(path)

    assert isinstance(report, StackStringReport)
    assert report.functions_scanned == 1  # the entry point is the candidate
    assert report.functions_emulated == 1
    assert len(report.strings) == 1
    record = report.strings[0]
    assert record.value == "Hello World"
    assert record.encoding == "ascii"
    assert record.function_address == TEXT_VA
    assert isinstance(record.stack_offset, int) and record.stack_offset > 0
    scan = report.functions[0]
    assert scan.address == TEXT_VA
    assert scan.stop_reason == "return"
    assert scan.instructions == 3  # the three movs; the ret never ran
    assert scan.stack_writes == 3
    assert scan.string_count == 1
    assert scan.truncated is False
    assert report.truncated is False
    assert report.skipped_no_stack_writes == 0


def test_recovers_utf16le_stack_string(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_UTF16_ABCD, name="utf16.elf")

    report = extract_stack_strings(path, addresses=[TEXT_VA])

    assert report.functions_scanned == 1
    assert len(report.strings) == 1
    record = report.strings[0]
    assert record.value == "ABCD"
    assert record.encoding == "utf-16le"
    assert record.function_address == TEXT_VA
    assert report.functions[0].stop_reason == "return"


def test_elf32_sample_is_recovered(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_HELLO_WORLD, bits=32, name="hello32.elf")

    report = extract_stack_strings(path)

    assert report.bitness == 32
    assert report.architecture == "x86"
    assert [record.value for record in report.strings] == ["Hello World"]
    assert report.strings[0].encoding == "ascii"
    assert report.functions[0].address == TEXT32_VA


# ---- evidence ----------------------------------------------------------------


def test_records_carry_the_documented_evidence(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_HELLO_WORLD, name="evidence.elf")

    report = extract_stack_strings(path, addresses=[TEXT_VA], max_instructions=50)

    record = report.strings[0]
    assert record.evidence.source == "stackstrings.emulate"
    assert record.evidence.method == "unicorn_stack_scan"
    assert record.evidence.confidence.value == "medium"
    assert record.evidence.address == TEXT_VA
    assert record.evidence.extra["function"] == f"0x{TEXT_VA:x}"
    assert record.evidence.extra["stop_reason"] == "return"
    assert record.evidence.extra["stack_offset"] == record.stack_offset
    assert record.evidence.extra["encoding"] == "ascii"
    assert report.evidence.extra["max_instructions"] == 50
    assert report.evidence.extra["functions_emulated"] == 1


# ---- dedupe, caps and skipped counting ------------------------------------------


def test_deduplicates_identical_strings_per_function(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_DUPE, name="dupe.elf")

    report = extract_stack_strings(path, addresses=[TEXT_VA])

    assert len(report.strings) == 1
    assert report.strings[0].value == "Dupe"
    assert report.functions[0].string_count == 1  # the honest distinct total
    assert report.functions[0].truncated is False


def test_per_function_cap_keeps_counting_honestly(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_TWO_STRINGS, name="two.elf")

    report = extract_stack_strings(path, addresses=[TEXT_VA], max_strings_per_function=1)

    assert len(report.strings) == 1
    assert report.strings[0].value == "Firs"  # lowest stack offset wins
    assert report.functions[0].string_count == 2  # the cut is not hidden
    assert report.functions[0].truncated is True
    assert report.truncated is True
    assert any("max_strings_per_function" in warning for warning in report.warnings)


def test_function_that_never_writes_the_stack_is_counted(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="nowrite.elf")

    report = extract_stack_strings(path, addresses=[TEXT_VA])

    assert report.functions_emulated == 1
    assert report.strings == ()
    assert report.skipped_no_stack_writes == 1
    assert report.functions[0].stop_reason == "return"
    assert report.functions[0].stack_writes == 0
    assert report.functions[0].string_count == 0


# ---- target selection ------------------------------------------------------------


def test_explicit_addresses_skip_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _sample(tmp_path, CODE_HELLO_WORLD, name="explicit.elf")

    def _boom(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("discovery must not run for explicit addresses")

    monkeypatch.setattr(stackstrings, "discover_functions", _boom)

    report = extract_stack_strings(path, addresses=[TEXT_VA])

    assert report.functions_scanned == 1
    assert report.strings[0].value == "Hello World"


def test_explicit_addresses_are_capped_and_reported(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_HELLO_WORLD, name="capped.elf")

    report = extract_stack_strings(path, addresses=[TEXT_VA, TEXT_VA + 1], max_functions=1)

    assert report.functions_scanned == 1
    assert report.functions[0].address == TEXT_VA  # sorted; the lowest wins
    assert report.truncated is True
    assert any("max_functions" in warning for warning in report.warnings)


def test_explicit_address_outside_executable_section_raises(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_HELLO_WORLD, name="badsel.elf")
    info = _load(path)
    data_section = next(s for s in info.sections if s.name == ".shstrtab")

    with pytest.raises(AnalysisError):
        extract_stack_strings(path, addresses=[data_section.virtual_address])
    with pytest.raises(AnalysisError):
        extract_stack_strings(path, addresses=[0x900000])  # not mapped at all


def test_bad_address_entries_raise(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_HELLO_WORLD, name="badaddr.elf")

    with pytest.raises(AnalysisError, match="addresses"):
        extract_stack_strings(path, addresses=[0])
    with pytest.raises(AnalysisError, match="addresses"):
        extract_stack_strings(path, addresses=["0x401000"])
    with pytest.raises(AnalysisError, match="addresses"):
        extract_stack_strings(path, addresses=[True])


# ---- bounds validation ------------------------------------------------------------


def test_bounds_are_validated_with_the_argument_named(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_HELLO_WORLD, name="bounds.elf")

    with pytest.raises(AnalysisError, match="max_functions"):
        extract_stack_strings(path, max_functions=0)
    with pytest.raises(AnalysisError, match="max_functions"):
        extract_stack_strings(path, max_functions=MAX_FUNCTIONS + 1)
    with pytest.raises(AnalysisError, match="max_instructions"):
        extract_stack_strings(path, max_instructions=0)
    with pytest.raises(AnalysisError, match="max_instructions"):
        extract_stack_strings(path, max_instructions=MAX_MAX_INSTRUCTIONS + 1)
    with pytest.raises(AnalysisError, match="max_strings_per_function"):
        extract_stack_strings(path, max_strings_per_function=0)
    with pytest.raises(AnalysisError, match="max_strings_per_function"):
        extract_stack_strings(path, max_strings_per_function=MAX_STRINGS_PER_FUNCTION + 1)


# ---- degraded modes ------------------------------------------------------------


def test_missing_emulator_raises_with_the_install_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _sample(tmp_path, CODE_HELLO_WORLD, name="noemulator.elf")
    monkeypatch.setattr(stackstrings, "EMULATOR_AVAILABLE", False)

    with pytest.raises(AnalysisError) as excinfo:
        extract_stack_strings(path)

    message = str(excinfo.value)
    assert "unicorn" in message
    assert "pip install codevanta[emulation]" in message


def test_unsupported_architecture_returns_empty_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _sample(tmp_path, CODE_HELLO_WORLD, name="arm.elf")
    info = _load(path)
    monkeypatch.setattr(info, "architecture", "aarch64")

    report = stackstrings._extract(path, info, None, 16, 2000, 32)

    assert report.functions == ()
    assert report.strings == ()
    assert report.functions_scanned == 0
    assert report.functions_emulated == 0
    assert any("x86" in warning for warning in report.warnings)
    assert report.evidence.confidence.value == "unknown"


# ---- serialization ----------------------------------------------------------------


def test_to_dict_is_json_safe(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_TWO_STRINGS, name="json.elf")

    report = extract_stack_strings(path, addresses=[TEXT_VA])
    payload = report.to_dict()
    text = json.dumps(payload)  # no bytes, no Paths, no enums
    reloaded = json.loads(text)

    assert reloaded["path"] == str(path)
    assert reloaded["functions_scanned"] == 1
    assert reloaded["string_count"] == 2
    assert reloaded["strings"][0]["function"] == f"0x{TEXT_VA:x}"
    assert isinstance(reloaded["strings"][0]["stack_offset"], int)
    assert reloaded["skipped"]["no_stack_writes"] == 0
    assert reloaded["evidence"]["source"] == "stackstrings.emulate"
    assert reloaded["functions"][0]["address"] == f"0x{TEXT_VA:x}"


# ---- the scan primitives (direct, no emulation) ------------------------------------


def test_ascii_scan_finds_runs_of_minimum_length() -> None:
    assert stackstrings._scan_ascii_runs(b"ab\x00Hello World\x00cd") == ((3, "Hello World"),)
    assert stackstrings._scan_ascii_runs(b"abc\x00") == ()  # one char too short
    assert stackstrings._scan_ascii_runs(b"Tail") == ((0, "Tail"),)  # run at the end


def test_utf16_scan_finds_pair_runs() -> None:
    assert stackstrings._scan_utf16le_runs(b"A\x00B\x00C\x00D\x00X") == ((0, "ABCD"),)
    assert stackstrings._scan_utf16le_runs(b"A\x00B\x00C\x00") == ()  # one char too short
    assert stackstrings._scan_utf16le_runs(b"A\x00B\x00C\x00D\x00" b"ascii") == ((0, "ABCD"),)


def test_collect_handles_both_encodings_offsets_and_dedupe() -> None:
    data = b"Hello\x00\x00W\x00o\x00r\x00l\x00d\x00\x00"

    records = stackstrings._collect_stack_strings(data, 0x20, 0x1000, "return")

    assert [(record.encoding, record.value) for record in records] == [
        ("ascii", "Hello"),
        ("utf-16le", "World"),
    ]
    assert records[0].stack_offset == 0x20
    assert records[1].stack_offset == 0x20 + 7
    assert records[0].evidence.extra["stop_reason"] == "return"

    duped = stackstrings._collect_stack_strings(b"Dupe\x00\x00\x00\x00Dupe", 0, 0x2000, "budget")
    assert len(duped) == 1  # identical strings collapse onto the first offset
    assert duped[0].stack_offset == 0


def test_collect_truncates_values_at_the_cap() -> None:
    records = stackstrings._collect_stack_strings(b"A" * (MAX_VALUE_CHARS + 44), 0, 0x1000, "return")

    assert len(records) == 1
    assert len(records[0].value) == MAX_VALUE_CHARS
    assert records[0].evidence.extra["length"] == MAX_VALUE_CHARS + 44
    assert records[0].evidence.extra["value_truncated"] is True


# ---- CLI ------------------------------------------------------------------------


def test_cli_stackstrings_table_and_json(tmp_path: Path) -> None:
    """`codevanta stackstrings` renders the table and --json round-trips."""
    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    sample = _sample(tmp_path, CODE_HELLO_WORLD)
    result = runner.invoke(cli, ["stackstrings", str(sample)])
    assert result.exit_code == 0, result.output
    assert "ascii" in result.output

    result = runner.invoke(cli, ["stackstrings", str(sample), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["functions_emulated"] >= 1


def test_cli_stackstrings_rejects_bad_budget(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    sample = _sample(tmp_path, CODE_HELLO_WORLD)
    result = runner.invoke(cli, ["stackstrings", str(sample), "--max-functions", "0"])
    assert result.exit_code == 2
    assert "max_functions" in result.output

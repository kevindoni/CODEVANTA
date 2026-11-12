"""Tests for the phase 2 sections of the ``analyze`` JSON report.

The ELF64 samples that need executable content beyond the shared fixtures are
assembled byte-by-byte with :mod:`struct` inside this module so the tests stay
self-contained; the header-only and plain ``.text`` fixtures come from
``conftest.py``.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codevanta.cli.main import app
from codevanta.core.report import AnalysisError, build_report

runner = CliRunner()

TEXT_ADDRESS = 0x401000
#: `call 0x40100b; ret` — one direct call cross reference.
CALL_CODE = bytes.fromhex("e80b000000c3")
#: `test eax, eax; je 0x401006; nop; nop; ret` — one branch plus three blocks.
BRANCHY_CODE = bytes.fromhex("85c074029090c3")
#: `jmp 0x40100a; nop x8; call 0x40100f; ret` — two cross references.
TWO_XREF_CODE = bytes.fromhex("eb08" + "90" * 8 + "e800000000" + "c3")

PHASE1_STEPS = ["load_binary", "discover_functions", "extract_strings"]

#: The phase 2 sections are opt-in, exactly like ``include_callgraph``.
PHASE2 = {"include_xrefs": True, "include_cfg": True}


def _write_elf64(path: Path, code: bytes) -> Path:
    """Write a minimal ELF64 executable with one executable ``.text`` section."""
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_offset = 0x40
    shstrtab_offset = (text_offset + len(code) + 7) & ~7
    shoff = (shstrtab_offset + len(shstrtab) + 7) & ~7
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,             # e_type = ET_EXEC
        62,            # e_machine = EM_X86_64
        1,             # e_version
        TEXT_ADDRESS,  # e_entry
        0,             # e_phoff
        shoff,         # e_shoff
        0,             # e_flags
        64,            # e_ehsize
        56,            # e_phentsize
        0,             # e_phnum
        64,            # e_shentsize
        3,             # e_shnum (null, .text, .shstrtab)
        2,             # e_shstrndx
    )
    text_section = struct.pack(
        "<IIQQQQIIQQ",
        1,               # sh_name -> ".text"
        1,               # sh_type = SHT_PROGBITS
        6,               # sh_flags = SHF_ALLOC | SHF_EXECINSTR
        TEXT_ADDRESS,    # sh_addr
        text_offset,     # sh_offset
        len(code),       # sh_size
        0,               # sh_link
        0,               # sh_info
        16,              # sh_addralign
        0,               # sh_entsize
    )
    shstrtab_section = struct.pack(
        "<IIQQQQIIQQ",
        7,               # sh_name -> ".shstrtab"
        3,               # sh_type = SHT_STRTAB
        0,               # sh_flags
        0,               # sh_addr
        shstrtab_offset,  # sh_offset
        len(shstrtab),   # sh_size
        0,               # sh_link
        0,               # sh_info
        1,               # sh_addralign
        0,               # sh_entsize
    )
    blob = bytearray(shoff + 3 * 64)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob[shoff : shoff + 64] = bytes(64)
    blob[shoff + 64 : shoff + 128] = text_section
    blob[shoff + 128 : shoff + 192] = shstrtab_section
    path.write_bytes(bytes(blob))
    return path


def test_report_includes_xrefs_with_evidence(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "call.bin", CALL_CODE)

    report = build_report(sample, **PHASE2)

    xrefs = report["xrefs"]
    assert xrefs["count"] == 1
    assert xrefs["returned"] == 1
    assert xrefs["truncated"] is False
    assert xrefs["scan_truncated"] is False
    assert xrefs["scanned_sections"] == [".text"]
    assert xrefs["scanned_bytes"] == len(CALL_CODE)
    assert xrefs["warnings"] == []
    assert xrefs["evidence"]["source"] == "capstone.xref_scan"
    item = xrefs["items"][0]
    assert item["from_address"] == "0x401000"
    assert item["to_address"] == "0x401010"
    assert item["kind"] == "call"
    assert item["instruction"] == "call 0x401010"
    assert item["evidence"]["source"] == "capstone.direct_call"
    assert item["evidence"]["confidence"] == "certain"
    assert "function" not in item  # no candidate starts at the target


def test_report_includes_cfg_blocks(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "branchy.bin", BRANCHY_CODE)

    report = build_report(sample, **PHASE2)

    cfg = report["cfg"]
    assert cfg["function_address"] == "0x401000"
    assert cfg["block_count"] == 3
    assert cfg["instruction_count"] == 5  # test, je, nop, nop, ret
    assert cfg["truncated"] is False
    assert cfg["warnings"] == []
    assert cfg["evidence"]["source"] == "cfg.linear_sweep"
    first = cfg["blocks"][0]
    assert first["start"] == "0x401000"
    assert first["end"] == "0x401004"
    assert first["successors"] == ["0x401004", "0x401006"]
    assert first["evidence"]["source"] == "cfg.linear_sweep"


def test_report_provenance_lists_phase2_steps(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "steps.bin", CALL_CODE)

    report = build_report(sample, **PHASE2)

    steps = report["provenance"]["steps"]
    assert steps[:3] == PHASE1_STEPS
    assert steps[3:] == ["find_xrefs", "build_cfg"]


def test_report_on_text_fixture_keeps_phase1_keys(elf64_text_path: Path) -> None:
    report = build_report(elf64_text_path, **PHASE2)

    # Every phase 1 key is untouched.
    for key in ("provenance", "binary", "functions", "strings", "disassembly"):
        assert key in report
    assert report["disassembly"]["instruction_count"] == 3
    # Phase 2 keys are present even when there is nothing to find.
    assert report["xrefs"]["count"] == 0
    assert report["xrefs"]["items"] == []
    assert report["xrefs"]["evidence"]["source"] == "capstone.xref_scan"
    assert report["cfg"]["block_count"] == 1
    assert report["cfg"]["blocks"][0]["instruction_count"] == 3


def test_report_header_only_elf_degrades_to_warnings(elf64_path: Path) -> None:
    report = build_report(elf64_path, **PHASE2)

    assert report["disassembly"] is None  # pre-existing degraded behaviour
    xrefs = report["xrefs"]
    assert xrefs["count"] == 0
    assert xrefs["items"] == []
    assert xrefs["truncated"] is False
    assert any("no executable sections" in warning for warning in xrefs["warnings"])
    cfg = report["cfg"]
    assert cfg["block_count"] == 0
    assert cfg["blocks"] == []
    assert cfg["warnings"], "degraded cfg must explain why it is empty"
    assert cfg["evidence"]["source"] == "cfg.linear_sweep"
    assert report["provenance"]["steps"][3:] == ["find_xrefs", "build_cfg"]


def test_report_xref_limit_truncates_items(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "two.bin", TWO_XREF_CODE)

    report = build_report(sample, xref_limit=1, **PHASE2)

    xrefs = report["xrefs"]
    assert xrefs["count"] == 2
    assert xrefs["returned"] == 1
    assert xrefs["truncated"] is True
    assert len(xrefs["items"]) == 1


def test_report_without_flags_omits_keys_and_steps(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "call.bin", CALL_CODE)

    report = build_report(sample)

    assert "xrefs" not in report
    assert "cfg" not in report
    assert report["provenance"]["steps"] == PHASE1_STEPS
    assert report["functions"]  # phase 1 output still present


@pytest.mark.parametrize(
    ("kwargs", "present", "absent"),
    [
        ({"include_xrefs": True}, "xrefs", "cfg"),
        ({"include_cfg": True}, "cfg", "xrefs"),
    ],
)
def test_report_sections_are_independent(
    tmp_path: Path, kwargs: dict[str, bool], present: str, absent: str
) -> None:
    sample = _write_elf64(tmp_path / "split.bin", BRANCHY_CODE)

    report = build_report(sample, **kwargs)

    assert present in report
    assert absent not in report
    # Only the requested engine runs, so only its provenance step is recorded.
    assert report["provenance"]["steps"][3:] == [
        "find_xrefs" if present == "xrefs" else "build_cfg"
    ]


def test_report_xref_limit_is_validated_even_without_xrefs(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "limit.bin", CALL_CODE)

    with pytest.raises(AnalysisError):
        build_report(sample, xref_limit=-1)


@pytest.mark.parametrize("xref_limit", [-1, 200_001])
def test_report_rejects_invalid_xref_limit(tmp_path: Path, xref_limit: int) -> None:
    sample = _write_elf64(tmp_path / "reject.bin", CALL_CODE)

    with pytest.raises(AnalysisError):
        build_report(sample, xref_limit=xref_limit)


def test_report_on_pe_contains_phase2_keys(pe_path: Path) -> None:
    report = build_report(pe_path, **PHASE2)

    assert report["xrefs"]["evidence"]["source"] == "capstone.xref_scan"
    assert isinstance(report["xrefs"]["items"], list)
    assert report["cfg"]["evidence"]["source"] == "cfg.linear_sweep"
    assert isinstance(report["cfg"]["blocks"], list)


def test_cli_analyze_json_contains_phase2(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "call.bin", CALL_CODE)
    output = tmp_path / "report.json"

    result = runner.invoke(app, ["analyze", str(sample), "--output", str(output), "--xrefs", "--cfg"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["xrefs"]["count"] == 1
    assert payload["xrefs"]["items"][0]["kind"] == "call"
    assert payload["cfg"]["block_count"] == 1
    assert payload["provenance"]["steps"][3:] == ["find_xrefs", "build_cfg"]
    assert "xrefs:" in result.stdout
    assert "cfg:" in result.stdout


def test_cli_analyze_header_only_elf_exits_zero(elf64_path: Path, tmp_path: Path) -> None:
    output = tmp_path / "degraded.json"

    result = runner.invoke(
        app, ["analyze", str(elf64_path), "--output", str(output), "--xrefs", "--cfg"]
    )

    assert result.exit_code == 0, result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["xrefs"]["count"] == 0
    assert payload["xrefs"]["warnings"]
    assert payload["cfg"]["block_count"] == 0
    assert payload["cfg"]["warnings"]


def test_cli_analyze_without_phase2_flags_omits_keys(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "call.bin", CALL_CODE)
    output = tmp_path / "phase1.json"

    result = runner.invoke(app, ["analyze", str(sample), "--output", str(output)])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert "xrefs" not in payload
    assert "cfg" not in payload
    assert payload["provenance"]["steps"] == PHASE1_STEPS
    assert "xrefs:" not in result.stdout
    assert "cfg:" not in result.stdout


def test_cli_analyze_single_section_flag(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "call.bin", CALL_CODE)
    output = tmp_path / "xrefs-only.json"

    result = runner.invoke(app, ["analyze", str(sample), "--output", str(output), "--xrefs"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["xrefs"]["count"] == 1
    assert "cfg" not in payload
    assert payload["provenance"]["steps"][3:] == ["find_xrefs"]


def test_cli_analyze_json_flag_echoes_the_payload(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "call.bin", CALL_CODE)
    output = tmp_path / "echo.json"

    result = runner.invoke(
        app, ["analyze", str(sample), "--output", str(output), "--json", "--xrefs"]
    )

    assert result.exit_code == 0, result.stdout
    assert '"xrefs"' in result.stdout  # echoed next to the "report written" line
    assert json.loads(output.read_text(encoding="utf-8"))["xrefs"]["count"] == 1


def test_cli_analyze_invalid_xref_limit_fails(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "call.bin", CALL_CODE)

    result = runner.invoke(app, ["analyze", str(sample), "--xref-limit=-1"])

    assert result.exit_code != 0
    assert "xref_limit" in result.stdout

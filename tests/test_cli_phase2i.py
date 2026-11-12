"""CLI tests for the phase 2i ``struct`` footer: alignment and array candidates.

The ELF64 samples are assembled byte-by-byte with :mod:`struct` inside this
module, so the tests stay self-contained and never depend on a shared fixture,
a compiler or a real-world binary.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path

from typer.testing import CliRunner, Result

from codevanta.cli.main import app

runner = CliRunner()

TEXT_ADDRESS = 0x401000

#: ``mov rax, qword ptr [rdi + 0x10]`` -- read of field 0x10, 8 bytes wide.
MOV_RAX_RDI_10 = bytes.fromhex("488b4710")
#: ``mov qword ptr [rdi + 0x18], rbx`` -- write of field 0x18, 8 bytes wide.
MOV_RDI_18_RBX = bytes.fromhex("48895f18")
#: ``mov rax, qword ptr [rdi + 0x20]`` -- read of field 0x20, 8 bytes wide.
MOV_RAX_RDI_20 = bytes.fromhex("488b4720")
#: ``mov rax, qword ptr [rdi + 0x24]`` -- read of field 0x24, 8 bytes wide.
MOV_RAX_RDI_24 = bytes.fromhex("488b4724")
#: ``mov rax, qword ptr [rdi + 0x40]`` -- read of field 0x40, 8 bytes wide.
MOV_RAX_RDI_40 = bytes.fromhex("488b4740")
#: ``mov qword ptr [rdi + 0x48], rbx`` -- write of field 0x48, 8 bytes wide.
MOV_RDI_48_RBX = bytes.fromhex("48895f48")
#: ``mov rax, qword ptr [rdi + 0x50]`` -- read of field 0x50, 8 bytes wide.
MOV_RAX_RDI_50 = bytes.fromhex("488b4750")
#: ``ret``
RET = bytes.fromhex("c3")

#: The contract fixture: three evenly spaced, equally wide fields (one run).
WIDE_RUN = MOV_RAX_RDI_10 + MOV_RDI_18_RBX + MOV_RAX_RDI_20 + RET
#: Offsets 0x10/0x18/0x24 break the stride, so no run can span three fields.
IRREGULAR_STRIDE = MOV_RAX_RDI_10 + MOV_RDI_18_RBX + MOV_RAX_RDI_24 + RET
#: Two independent runs of three fields each, separated by a gap.
TWO_RUNS = (
    MOV_RAX_RDI_10
    + MOV_RDI_18_RBX
    + MOV_RAX_RDI_20
    + MOV_RAX_RDI_40
    + MOV_RDI_48_RBX
    + MOV_RAX_RDI_50
    + RET
)
#: A single field: one non-zero offset cannot distinguish an alignment.
ONE_FIELD = MOV_RAX_RDI_10 + RET

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _align(value: int, alignment: int) -> int:
    """Round ``value`` up to a multiple of ``alignment``."""
    return (value + alignment - 1) // alignment * alignment


def _write_elf64(path: Path, code: bytes, *, entry: int = TEXT_ADDRESS) -> Path:
    """Write a minimal ELF64 executable with one executable ``.text`` section."""
    if not code:
        raise ValueError("code must not be empty")
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_offset = 0x40
    shstrtab_offset = _align(text_offset + len(code), 8)
    shoff = _align(shstrtab_offset + len(shstrtab), 8)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,              # e_type = ET_EXEC
        62,             # e_machine = EM_X86_64
        1,              # e_version
        entry,          # e_entry
        0,              # e_phoff
        shoff,          # e_shoff
        0,              # e_flags
        64,             # e_ehsize
        56,             # e_phentsize
        0,              # e_phnum
        64,             # e_shentsize
        3,              # e_shnum: null, .text, .shstrtab
        2,              # e_shstrndx
    )
    sections = [
        bytes(64),  # SHT_NULL
        struct.pack(  # .text: SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR
            "<IIQQQQIIQQ", 1, 1, 6, entry, text_offset, len(code), 0, 0, 16, 0
        ),
        struct.pack(  # .shstrtab: SHT_STRTAB
            "<IIQQQQIIQQ", 7, 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0
        ),
    ]
    blob = bytearray(shoff)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob += b"".join(sections)
    path.write_bytes(bytes(blob))
    return path


def _sample(tmp_path: Path, name: str, code: bytes) -> Path:
    """Write one fixture binary under ``tmp_path``."""
    return _write_elf64(tmp_path / name, code)


def _plain(text: str) -> str:
    """Strip terminal escape sequences from ``text``."""
    return _ANSI_ESCAPE.sub("", text)


def _output(result: Result) -> str:
    """Return stdout and stderr merged, ANSI-stripped and whitespace-flattened."""
    stderr = getattr(result, "stderr", "") or ""
    return " ".join(_plain(f"{result.stdout} {stderr}").split())


def _payload(stdout: str) -> dict:
    """Return the parsed JSON object printed by a ``--json`` option."""
    text = _plain(stdout)
    return json.loads(text[text.index("{") : text.rindex("}") + 1])


def _table_rows(stdout: str, columns: int) -> list[list[str]]:
    """Return the cell lists of every data row in a Rich table."""
    rows: list[list[str]] = []
    for line in _plain(stdout).splitlines():
        stripped = line.strip()
        for bar in ("\u2502", "|"):
            if stripped.count(bar) != columns + 1:
                continue
            cells = [cell.strip() for cell in stripped.strip(bar).split(bar)]
            if len(cells) == columns:
                rows.append(cells)
            break
    return rows


def _field_rows(result: Result) -> list[list[str]]:
    """Return the Offset/Width/Reads/Writes rows of the ``struct`` table."""
    return [row for row in _table_rows(result.stdout, 4) if row[0].startswith(("0x", "-0x"))]


# ---- footer: alignment and array candidates --------------------------------


def test_struct_footer_reports_alignment_and_array_run(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "wide_run.bin", WIDE_RUN)

    result = runner.invoke(app, ["struct", str(sample)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "alignment: 8" in output, output
    assert "array at 0x10: 3 x 8-byte, stride 8" in output, output
    # A run was found, so the negative form must not appear.
    assert "arrays: none" not in output, output
    # The table itself is unchanged by the footer enrichment.
    assert _field_rows(result) == [
        ["0x10", "8", "1", "0"],
        ["0x18", "8", "0", "1"],
        ["0x20", "8", "1", "0"],
    ], result.stdout


def test_struct_footer_keeps_the_phase2h_summary_lines(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "summary.bin", WIDE_RUN)

    result = runner.invoke(app, ["struct", str(sample)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "base registers: rdi" in output, output
    assert "fields: 3" in output, output
    assert "instructions: 4" in output, output
    assert "truncated: no" in output, output
    assert "warning:" not in output, output


def test_struct_footer_prints_one_line_per_array_run(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "two_runs.bin", TWO_RUNS)

    result = runner.invoke(app, ["struct", str(sample)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "alignment: 8" in output, output
    assert output.count("array at 0x") == 2, output
    assert "array at 0x10: 3 x 8-byte, stride 8" in output, output
    assert "array at 0x40: 3 x 8-byte, stride 8" in output, output


def test_struct_irregular_offsets_report_no_array_run(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "irregular.bin", IRREGULAR_STRIDE)

    result = runner.invoke(app, ["struct", str(sample)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    # gcd(0x10, 0x18, 0x24) == 4, and the stride 8 then 12 run is not an array.
    assert "alignment: 4" in output, output
    assert "arrays: none" in output, output
    assert "array at 0x" not in output, output
    assert _field_rows(result) == [
        ["0x10", "8", "1", "0"],
        ["0x18", "8", "0", "1"],
        ["0x24", "8", "1", "0"],
    ], result.stdout


def test_struct_single_field_reports_unknown_alignment(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "one_field.bin", ONE_FIELD)

    result = runner.invoke(app, ["struct", str(sample)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "alignment: unknown" in output, output
    assert "arrays: none" in output, output


def test_struct_footer_is_deterministic(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "deterministic.bin", TWO_RUNS)

    first = runner.invoke(app, ["struct", str(sample)])
    second = runner.invoke(app, ["struct", str(sample)])

    assert first.exit_code == 0, _output(first)
    assert _output(first) == _output(second), first.stdout


# ---- JSON output -----------------------------------------------------------


def test_struct_json_carries_alignment_and_array_groups(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "wide_run_json.bin", WIDE_RUN)

    result = runner.invoke(app, ["struct", str(sample), "--json"])

    assert result.exit_code == 0, _output(result)
    payload = _payload(result.stdout)
    assert payload["alignment"] == 8, payload
    groups = payload["array_groups"]
    assert len(groups) == 1, payload
    group = groups[0]
    assert group["offset"] == "0x10", group
    assert group["stride"] == 8, group
    assert group["count"] == 3, group
    assert group["width"] == 8, group
    assert group["span"] == 24, group
    # --json still emits the suggestion only, never the rendered footer.
    assert "array at 0x10" not in _output(result), result.stdout


def test_struct_json_irregular_offsets_carry_no_array_groups(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "irregular_json.bin", IRREGULAR_STRIDE)

    result = runner.invoke(app, ["struct", str(sample), "--json"])

    assert result.exit_code == 0, _output(result)
    payload = _payload(result.stdout)
    assert payload["alignment"] == 4, payload
    assert payload["array_groups"] == [], payload


def test_struct_json_alignment_is_null_for_a_single_field(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "one_field_json.bin", ONE_FIELD)

    result = runner.invoke(app, ["struct", str(sample), "--json"])

    assert result.exit_code == 0, _output(result)
    payload = _payload(result.stdout)
    assert payload["alignment"] is None, payload
    assert payload["array_groups"] == [], payload

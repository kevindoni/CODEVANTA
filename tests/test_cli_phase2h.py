"""CLI tests for the phase 2h ``struct`` command.

The ELF64 samples are assembled byte-by-byte with :mod:`struct` inside this
module, so the tests stay self-contained and never depend on a shared fixture,
a compiler or a real-world binary.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from codevanta.cli.main import app

runner = CliRunner()

TEXT_ADDRESS = 0x401000

#: ``mov rax, qword ptr [rdi + 0x10]`` -- read of field 0x10, 8 bytes wide.
MOV_RAX_RDI_10 = bytes.fromhex("488b4710")
#: ``mov qword ptr [rdi + 0x18], rbx`` -- write of field 0x18, 8 bytes wide.
MOV_RDI_18_RBX = bytes.fromhex("48895f18")
#: ``mov ecx, dword ptr [rdi + 0x20]`` -- read of field 0x20, 4 bytes wide.
MOV_ECX_RDI_20 = bytes.fromhex("8b4f20")
#: ``mov rax, qword ptr [rbp + 8]`` -- a stack slot, not a struct field.
MOV_RAX_RBP_8 = bytes.fromhex("488b4508")
#: ``ret``
RET = bytes.fromhex("c3")

#: The three-field fixture from the task contract.
THREE_FIELDS = MOV_RAX_RDI_10 + MOV_RDI_18_RBX + MOV_ECX_RDI_20 + RET
#: The same three fields plus one ``[rbp + 8]`` stack slot.
WITH_STACK = MOV_RAX_RDI_10 + MOV_RDI_18_RBX + MOV_ECX_RDI_20 + MOV_RAX_RBP_8 + RET

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


# ---- table output ----------------------------------------------------------


def test_struct_entry_point_reports_three_fields(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "three_fields.bin", THREE_FIELDS)

    result = runner.invoke(app, ["struct", str(sample)])

    assert result.exit_code == 0, _output(result)
    assert _field_rows(result) == [
        ["0x10", "8", "1", "0"],
        ["0x18", "8", "0", "1"],
        ["0x20", "4", "1", "0"],
    ], result.stdout


def test_struct_footer_names_base_registers_and_truncation(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "footer.bin", THREE_FIELDS)

    result = runner.invoke(app, ["struct", str(sample)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "base registers: rdi" in output, output
    assert "fields: 3" in output, output
    assert "instructions: 4" in output, output
    assert "truncated: no" in output, output
    # The table title carries the resolved start address in hex.
    assert "0x401000" in output, output
    # No limitation is invented for a clean, untruncated suggestion.
    assert "warning:" not in output, output


@pytest.mark.parametrize("address_args", [["--address", "0x401000"], ["-a", "4198400"]])
def test_struct_address_accepts_hex_and_decimal(
    tmp_path: Path, address_args: list[str]
) -> None:
    sample = _sample(tmp_path, "address.bin", THREE_FIELDS)

    result = runner.invoke(app, ["struct", str(sample), *address_args])

    assert result.exit_code == 0, _output(result)
    assert [row[0] for row in _field_rows(result)] == ["0x10", "0x18", "0x20"], result.stdout


def test_struct_max_fields_truncates_and_warns(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "capped.bin", THREE_FIELDS)

    result = runner.invoke(app, ["struct", str(sample), "--max-fields", "2"])

    assert result.exit_code == 0, _output(result)
    assert [row[0] for row in _field_rows(result)] == ["0x10", "0x18"], result.stdout
    output = _output(result)
    assert "truncated: yes" in output, output
    assert "warning:" in output, output
    assert "--max-fields" in output, output


# ---- stack operands --------------------------------------------------------


def test_struct_excludes_stack_slots_by_default(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "stack_default.bin", WITH_STACK)

    result = runner.invoke(app, ["struct", str(sample)])

    assert result.exit_code == 0, _output(result)
    assert [row[0] for row in _field_rows(result)] == ["0x10", "0x18", "0x20"], result.stdout
    output = _output(result)
    assert "base registers: rdi" in output, output
    assert "rbp" not in output, output


def test_struct_include_stack_keeps_rbp_offsets(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "stack_included.bin", WITH_STACK)

    result = runner.invoke(app, ["struct", str(sample), "--include-stack"])

    assert result.exit_code == 0, _output(result)
    assert _field_rows(result) == [
        ["0x8", "8", "1", "0"],
        ["0x10", "8", "1", "0"],
        ["0x18", "8", "0", "1"],
        ["0x20", "4", "1", "0"],
    ], result.stdout
    output = _output(result)
    assert "base registers: rbp, rdi" in output, output
    assert "truncated: no" in output, output


# ---- json ------------------------------------------------------------------


def test_struct_json_payload_parses(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "three_fields_json.bin", THREE_FIELDS)

    result = runner.invoke(app, ["struct", str(sample), "--json"])

    assert result.exit_code == 0, _output(result)
    payload = _payload(result.stdout)
    assert payload["address"] == "0x401000"
    assert payload["field_count"] == 3
    assert payload["max_fields"] == 64
    assert payload["truncated"] is False
    assert payload["include_stack"] is False
    assert [field["offset"] for field in payload["fields"]] == ["0x10", "0x18", "0x20"]
    assert [field["width"] for field in payload["fields"]] == [8, 8, 4]
    assert [field["read_count"] for field in payload["fields"]] == [1, 0, 1]
    assert [field["write_count"] for field in payload["fields"]] == [0, 1, 0]
    assert payload["evidence"]["source"] == "type_recovery.suggestion"


def test_struct_json_include_stack_payload_parses(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "stack_json.bin", WITH_STACK)

    result = runner.invoke(app, ["struct", str(sample), "--json", "--include-stack"])

    assert result.exit_code == 0, _output(result)
    payload = _payload(result.stdout)
    assert payload["include_stack"] is True
    assert [field["offset"] for field in payload["fields"]] == ["0x8", "0x10", "0x18", "0x20"]


# ---- error handling --------------------------------------------------------


@pytest.mark.parametrize("bad_address", ["not-an-address", "-1", "0x900000"])
def test_struct_invalid_address_exits_two(tmp_path: Path, bad_address: str) -> None:
    sample = _sample(tmp_path, "bad_address.bin", THREE_FIELDS)

    result = runner.invoke(app, ["struct", str(sample), "--address", bad_address])

    assert result.exit_code == 2, _output(result)
    assert "error" in _output(result)


def test_struct_unknown_function_exits_two(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "unknown_function.bin", THREE_FIELDS)

    result = runner.invoke(app, ["struct", str(sample), "--function", "does_not_exist"])

    assert result.exit_code == 2, _output(result)
    assert "does_not_exist" in _output(result)


def test_struct_missing_file_exits_two(tmp_path: Path) -> None:
    result = runner.invoke(app, ["struct", str(tmp_path / "missing.bin")])

    assert result.exit_code == 2, _output(result)


@pytest.mark.parametrize(
    "option_args",
    [["--max-instructions", "0"], ["--max-fields", "0"], ["--max-fields", "100000"]],
)
def test_struct_out_of_range_budget_exits_two(
    tmp_path: Path, option_args: list[str]
) -> None:
    sample = _sample(tmp_path, "bad_budget.bin", THREE_FIELDS)

    result = runner.invoke(app, ["struct", str(sample), *option_args])

    assert result.exit_code == 2, _output(result)
    assert "error" in _output(result)


def test_struct_help_documents_every_option() -> None:
    result = runner.invoke(app, ["struct", "--help"])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    options = (
        "--address",
        "--function",
        "--max-instructions",
        "--max-fields",
        "--include-stack",
        "--json",
    )
    for option in options:
        assert option in output, output
    # Bracket operands must survive Rich markup, not vanish as unknown tags.
    assert "[rsp]/[rbp]-relative" in output, output
    assert "[reg + 0xNN]" in output, output


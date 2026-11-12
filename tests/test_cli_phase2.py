"""CLI tests for the phase 2 commands: xrefs, cfg and session storage.

The ELF64 samples are assembled byte-by-byte with :mod:`struct` inside this
module so the tests stay self-contained and never depend on shared fixtures.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

from typer.testing import CliRunner

from codevanta.cli.main import app

runner = CliRunner()

TEXT_ADDRESS = 0x401000
#: `call 0x40100b; ret` — one direct call cross reference.
CALL_CODE = bytes.fromhex("e80b000000c3")
#: `test eax, eax; je 0x401006; nop; nop; ret` — a conditional branch.
BRANCHY_CODE = bytes.fromhex("85c074029090c3")
#: `push rbp; mov rbp, rsp; ret` — plain code for session tests.
PLAIN_CODE = bytes.fromhex("554889e5c3")

_SESSION_ID = re.compile(r"session saved:\s*([0-9A-Za-z_-]+)")


def _align(value: int, alignment: int) -> int:
    """Round ``value`` up to a multiple of ``alignment``."""
    return (value + alignment - 1) // alignment * alignment


def _write_elf64(path: Path, code: bytes, *, text_address: int = TEXT_ADDRESS) -> Path:
    """Write a minimal ELF64 executable with one executable ``.text`` section."""
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_offset = 0x40
    shstrtab_offset = _align(text_offset + len(code), 8)
    shoff = _align(shstrtab_offset + len(shstrtab), 8)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,             # e_type = ET_EXEC
        62,            # e_machine = EM_X86_64
        1,             # e_version
        text_address,  # e_entry
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
    null_section = bytes(64)
    text_section = struct.pack(
        "<IIQQQQIIQQ",
        1,             # sh_name -> ".text"
        1,             # sh_type = SHT_PROGBITS
        6,             # sh_flags = SHF_ALLOC | SHF_EXECINSTR
        text_address,  # sh_addr
        text_offset,   # sh_offset
        len(code),     # sh_size
        0,             # sh_link
        0,             # sh_info
        16,            # sh_addralign
        0,             # sh_entsize
    )
    shstrtab_section = struct.pack(
        "<IIQQQQIIQQ",
        7,                 # sh_name -> ".shstrtab"
        3,                 # sh_type = SHT_STRTAB
        0,                 # sh_flags
        0,                 # sh_addr
        shstrtab_offset,   # sh_offset
        len(shstrtab),     # sh_size
        0,                 # sh_link
        0,                 # sh_info
        1,                 # sh_addralign
        0,                 # sh_entsize
    )
    blob = bytearray(shoff + 3 * 64)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob[shoff : shoff + 64] = null_section
    blob[shoff + 64 : shoff + 128] = text_section
    blob[shoff + 128 : shoff + 192] = shstrtab_section
    path.write_bytes(bytes(blob))
    return path


def _table_rows(stdout: str, columns: int) -> list[list[str]]:
    """Return the cell lists of every data row in a Rich table."""
    rows: list[list[str]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.count("│") != columns + 1:
            continue
        cells = [cell.strip() for cell in stripped.strip("│").split("│")]
        if len(cells) == columns:
            rows.append(cells)
    return rows


def test_xrefs_reports_call_on_call_bearing_sample(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "call.bin", CALL_CODE)

    result = runner.invoke(app, ["xrefs", str(sample)])

    assert result.exit_code == 0, result.stdout
    assert "call" in result.stdout
    rows = [row for row in _table_rows(result.stdout, 5) if row[0] == "0x401000"]
    assert rows, result.stdout
    # call at 0x401000 with rel32=0x0b -> 0x401005 + 11 = 0x401010
    assert rows[0][1] == "0x401010"


def test_xrefs_json_flag_emits_json(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "call_json.bin", CALL_CODE)

    result = runner.invoke(app, ["xrefs", str(sample), "--json"])

    assert result.exit_code == 0, result.stdout
    assert '"xref_count"' in result.stdout


def test_cfg_splits_branchy_sample_into_blocks(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "branchy.bin", BRANCHY_CODE)

    result = runner.invoke(app, ["cfg", str(sample)])

    assert result.exit_code == 0, result.stdout
    block_rows = [row for row in _table_rows(result.stdout, 5) if row[0].startswith("0x")]
    assert len(block_rows) >= 2, result.stdout
    assert block_rows[0][0] == "0x401000"


def test_cfg_address_option_targets_given_address(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "branchy_addr.bin", BRANCHY_CODE)

    result = runner.invoke(app, ["cfg", str(sample), "--address", str(TEXT_ADDRESS + 4)])

    assert result.exit_code == 0, result.stdout
    assert "0x401004" in result.stdout


def test_session_save_list_show_roundtrip(tmp_path: Path, monkeypatch) -> None:
    db = tmp_path / "sessions.db"
    monkeypatch.setenv("CODEVANTA_DB", str(db))
    # Widen the Rich console so table cells (notably the session id) never wrap.
    monkeypatch.setenv("COLUMNS", "200")
    sample = _write_elf64(tmp_path / "plain.bin", PLAIN_CODE)

    saved = runner.invoke(app, ["session", "save", str(sample), "--notes", "phase2"])
    assert saved.exit_code == 0, saved.stdout
    match = _SESSION_ID.search(saved.stdout)
    assert match is not None, saved.stdout
    session_id = match.group(1)
    assert db.exists()

    listed = runner.invoke(app, ["session", "list"])
    assert listed.exit_code == 0, listed.stdout
    assert session_id in listed.stdout
    assert "ELF" in listed.stdout

    shown = runner.invoke(app, ["session", "show", session_id])
    assert shown.exit_code == 0, shown.stdout
    assert session_id in shown.stdout
    assert "phase2" in shown.stdout


def test_session_show_unknown_id_exits_nonzero(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CODEVANTA_DB", str(tmp_path / "sessions.db"))

    result = runner.invoke(app, ["session", "show", "does-not-exist"])

    assert result.exit_code != 0


def test_missing_file_exits_nonzero() -> None:
    missing = "definitely-missing-phase2.bin"

    for args in (["xrefs", missing], ["cfg", missing], ["session", "save", missing]):
        result = runner.invoke(app, args)
        assert result.exit_code != 0, args

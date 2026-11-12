"""CLI tests for the phase 2e ``cfg --traversal`` option.

The ELF64 sample is assembled byte-by-byte with :mod:`struct` inside this module
so the tests stay self-contained and never depend on shared fixtures or
real-world binaries.
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
#: `test eax, eax; je 0x401006; nop; nop; ret` — one conditional branch, so a
#: traversal yields three blocks (condition, fallthrough, jump target).
BRANCHY_CODE = bytes.fromhex("85c074029090c3")

_BLOCK_COUNT = re.compile(r"Basic blocks \((\d+)\)")


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
    # The 64 bytes at ``shoff`` stay zero: that is the SHT_NULL section header.
    blob[shoff + 64 : shoff + 128] = text_section
    blob[shoff + 128 : shoff + 192] = shstrtab_section
    path.write_bytes(bytes(blob))
    return path


_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Strip terminal escape sequences from ``text``."""
    return _ANSI_ESCAPE.sub("", text)


def _table_rows(stdout: str, columns: int) -> list[list[str]]:
    """Return the cell lists of every data row in a Rich table.

    Both the Unicode and the ASCII border styles are accepted so the assertions
    do not depend on the console encoding of the platform running the tests.
    """
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


def _block_rows(stdout: str) -> list[list[str]]:
    """Return the CFG table rows whose first cell is a block start address."""
    return [row for row in _table_rows(stdout, 5) if row[0].startswith("0x")]


def _block_count(stdout: str) -> int:
    """Return the block count from the table title, or ``-1`` when absent."""
    match = _BLOCK_COUNT.search(_plain(stdout))
    assert match is not None, stdout
    return int(match.group(1))


def _payload(stdout: str) -> dict:
    """Return the parsed JSON object printed by ``cfg --json``."""
    text = _plain(stdout)
    return json.loads(text[text.index("{") : text.rindex("}") + 1])


def _output(result: Result) -> str:
    """Return stdout and stderr merged, ANSI-stripped and whitespace-flattened.

    Click writes usage errors to stderr (and Rich wraps and colorizes them), so
    both streams are combined and terminal escape sequences removed before
    matching text; otherwise ``--traversal`` can arrive as ``-\\x1b[..m-traversal``.
    """
    stderr = getattr(result, "stderr", "") or ""
    merged = _plain(f"{result.stdout} {stderr}")
    return " ".join(merged.split())


# ---- --traversal recursive -------------------------------------------------


def test_cfg_recursive_traversal_reports_at_least_two_blocks(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "branchy_recursive.bin", BRANCHY_CODE)

    result = runner.invoke(app, ["cfg", str(sample), "--traversal", "recursive"])

    assert result.exit_code == 0, result.stdout
    assert _block_count(result.stdout) >= 2, result.stdout
    block_rows = _block_rows(result.stdout)
    assert len(block_rows) >= 2, result.stdout
    assert block_rows[0][0] == "0x401000"


def test_cfg_recursive_json_uses_the_recursive_builder(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "branchy_recursive_json.bin", BRANCHY_CODE)

    result = runner.invoke(app, ["cfg", str(sample), "--traversal", "recursive", "--json"])

    assert result.exit_code == 0, result.stdout
    payload = _payload(result.stdout)
    assert payload["evidence"]["source"] == "cfg.recursive_traversal"
    assert payload["block_count"] >= 2, result.stdout
    assert payload["block_count"] == len(payload["blocks"])


# ---- default (linear) behaviour -------------------------------------------


def test_cfg_default_invocation_still_exits_zero(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "branchy_default.bin", BRANCHY_CODE)

    result = runner.invoke(app, ["cfg", str(sample)])

    assert result.exit_code == 0, result.stdout
    assert _block_count(result.stdout) >= 2, result.stdout


def test_cfg_default_traversal_is_linear(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "branchy_default_json.bin", BRANCHY_CODE)

    result = runner.invoke(app, ["cfg", str(sample), "--json"])

    assert result.exit_code == 0, result.stdout
    # Omitting --traversal must keep the pre-existing linear sweep.
    assert _payload(result.stdout)["evidence"]["source"] == "cfg.linear_sweep"


def test_cfg_explicit_linear_matches_default(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "branchy_linear.bin", BRANCHY_CODE)

    default = runner.invoke(app, ["cfg", str(sample), "--json"])
    explicit = runner.invoke(app, ["cfg", str(sample), "--traversal", "linear", "--json"])

    assert default.exit_code == 0, default.stdout
    assert explicit.exit_code == 0, explicit.stdout
    assert _payload(default.stdout) == _payload(explicit.stdout)


# ---- option validation ----------------------------------------------------


@pytest.mark.parametrize("bad_traversal", ["bogus", "depth-first", "Recursive"])
def test_cfg_invalid_traversal_exits_nonzero(tmp_path: Path, bad_traversal: str) -> None:
    sample = _write_elf64(tmp_path / "branchy_bad.bin", BRANCHY_CODE)

    result = runner.invoke(app, ["cfg", str(sample), "--traversal", bad_traversal])

    assert result.exit_code != 0, result.stdout
    # The rejection must name the offending option and its accepted values.
    output = _output(result)
    assert "--traversal" in output, output
    assert "linear" in output, output
    assert "recursive" in output, output


def test_cfg_help_documents_traversal() -> None:
    result = runner.invoke(app, ["cfg", "--help"])

    assert result.exit_code == 0, result.stdout
    output = _output(result)
    assert "--traversal" in output, output
    assert "linear" in output, output
    assert "recursive" in output, output

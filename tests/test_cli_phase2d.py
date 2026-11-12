"""CLI tests for the phase 2d addition: ``callgraph --format html``.

The ELF64 sample is assembled byte-by-byte with :mod:`struct` inside this module so
the tests stay self-contained: two direct ``call`` instructions with no shared
fixture or real-world binary involved.
"""

from __future__ import annotations

import struct
from pathlib import Path

from typer.testing import CliRunner

from codevanta.cli.main import app

runner = CliRunner()

TEXT_ADDRESS = 0x401000
#: ``a``: call 0x401010 ; ret — then 10 nops — then ``b``: call 0x401000 ; ret.
CALL_CODE = bytes.fromhex("e80b000000c3") + b"\x90" * 10 + bytes.fromhex("e8fbffffffc3")


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


def test_callgraph_html_stdout_is_self_contained(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "calls_html.bin", CALL_CODE)

    result = runner.invoke(app, ["callgraph", str(sample), "--format", "html"])

    assert result.exit_code == 0, result.stdout
    # The document itself, not a Rich-wrapped summary, comes first.
    assert result.stdout.startswith("<!DOCTYPE html>")
    assert "<svg" in result.stdout
    # Self-contained: no external CSS/JS/fonts/CDN references of any kind.
    assert "http://" not in result.stdout
    assert "https://" not in result.stdout


def test_callgraph_html_output_file(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "calls_html_file.bin", CALL_CODE)
    target = tmp_path / "graph.html"

    result = runner.invoke(
        app, ["callgraph", str(sample), "--format", "html", "--output", str(target)]
    )

    assert result.exit_code == 0, result.stdout
    assert target.exists()
    written = target.read_text(encoding="utf-8")
    assert written.startswith("<!DOCTYPE html>")
    assert "<svg" in written
    assert "graph written" in result.stdout
    # The document goes to the file, not to stdout.
    assert "<!DOCTYPE html>" not in result.stdout

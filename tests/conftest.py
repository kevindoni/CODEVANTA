"""Shared test fixtures for CODEVANTA."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest


def make_minimal_elf64(path: Path, *, entry: int = 0x401000) -> Path:
    """Write a header-only ELF64 file (no sections, no segments)."""
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,        # e_type = ET_EXEC
        62,       # e_machine = EM_X86_64
        1,        # e_version
        entry,    # e_entry
        0,        # e_phoff
        0,        # e_shoff
        0,        # e_flags
        64,       # e_ehsize
        56,       # e_phentsize
        0,        # e_phnum
        64,       # e_shentsize
        0,        # e_shnum
        0,        # e_shstrndx
    )
    path.write_bytes(ident + header)
    return path


@pytest.fixture
def elf64_path(tmp_path: Path) -> Path:
    return make_minimal_elf64(tmp_path / "sample_elf64.bin")


def make_elf64_with_text(path: Path, *, entry: int = 0x401000) -> Path:
    """Write an ELF64 file with one executable .text section."""
    text = bytes.fromhex("554889e5c3")  # push rbp; mov rbp, rsp; ret
    shstr = b"\x00.text\x00.shstrtab\x00"
    off_text = 0x40
    off_shstr = off_text + len(text)
    off_sh = 0x58
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, entry, 0, off_sh, 0, 64, 56, 0, 64, 3, 2
    )
    null_section = bytes(64)
    text_section = struct.pack(
        "<IIQQQQIIQQ", 1, 1, 6, entry, off_text, len(text), 0, 0, 16, 0
    )
    str_section = struct.pack(
        "<IIQQQQIIQQ", 7, 3, 0, 0, off_shstr, len(shstr), 0, 0, 1, 0
    )
    blob = bytearray(off_sh)
    blob[0:64] = header
    blob[off_text:off_text + len(text)] = text
    blob[off_shstr:off_shstr + len(shstr)] = shstr
    blob += null_section + text_section + str_section
    path.write_bytes(blob)
    return path


@pytest.fixture
def elf64_text_path(tmp_path: Path) -> Path:
    return make_elf64_with_text(tmp_path / "sample_elf64_text.bin")



@pytest.fixture
def pe_path() -> Path:
    """Use the running Python interpreter as a real PE sample on Windows."""
    if not sys.platform.startswith("win"):
        pytest.skip("PE sample tests require Windows")
    executable = Path(sys.executable)
    if executable.suffix.lower() != ".exe" or not executable.exists():
        pytest.skip("Python interpreter is not a PE executable")
    return executable

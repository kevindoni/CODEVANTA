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


@pytest.fixture
def pe_path() -> Path:
    """Use the running Python interpreter as a real PE sample on Windows."""
    if not sys.platform.startswith("win"):
        pytest.skip("PE sample tests require Windows")
    executable = Path(sys.executable)
    if executable.suffix.lower() != ".exe" or not executable.exists():
        pytest.skip("Python interpreter is not a PE executable")
    return executable

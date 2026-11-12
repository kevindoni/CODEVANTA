"""Loader tests for PE and ELF inputs."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.loader import BinaryLoader, BinaryLoadError


def test_load_minimal_elf64(elf64_path: Path) -> None:
    info = BinaryLoader().load(elf64_path)
    assert info.format == "ELF"
    assert info.architecture == "x86_64"
    assert info.bitness == 64
    assert info.endianness == "little"
    assert info.entry_point == 0x401000
    assert info.is_stripped is True
    assert "no symbol table" in " ".join(info.warnings).lower()


def test_load_pe(pe_path: Path) -> None:
    info = BinaryLoader().load(pe_path)
    assert info.format == "PE"
    assert info.bitness in (32, 64)
    assert info.image_base > 0
    assert info.entry_point is not None
    assert info.sections
    assert info.sha256
    assert info.file_size > 0


def test_va_offset_roundtrip_on_pe(pe_path: Path) -> None:
    info = BinaryLoader().load(pe_path)
    section = next(s for s in info.sections if s.raw_size > 0 and s.is_executable)
    offset = info.va_to_offset(section.virtual_address)
    assert offset == section.offset
    assert info.offset_to_va(offset) == section.virtual_address


def test_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(BinaryLoadError):
        BinaryLoader().load(tmp_path / "missing.bin")


def test_rejects_empty_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    with pytest.raises(BinaryLoadError):
        BinaryLoader().load(empty)


def test_rejects_non_binary(tmp_path: Path) -> None:
    sample = tmp_path / "text.bin"
    sample.write_text("this is definitely not a binary file")
    with pytest.raises(BinaryLoadError):
        BinaryLoader().load(sample)


def test_all_findings_carry_evidence(pe_path: Path) -> None:
    info = BinaryLoader().load(pe_path)
    assert info.sections
    assert all(section.evidence is not None for section in info.sections)
    assert all(imp.evidence is not None for imp in info.imports)
    assert all(sym.evidence is not None for sym in info.symbols)
    assert all(exp.evidence is not None for exp in info.exports)


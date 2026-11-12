"""Loader tests for PE and ELF inputs."""

from __future__ import annotations

from pathlib import Path

import pytest

from codevanta.core.loader import BinaryLoader, BinaryLoadError


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


def test_load_macho64(macho64_text_path: Path) -> None:
    info = BinaryLoader().load(macho64_text_path)
    assert info.format == "MachO"
    assert info.architecture == "x86_64"
    assert info.bitness == 64
    assert info.endianness == "little"
    assert info.image_base == 0x100000000
    assert info.entry_point is not None
    text = next(s for s in info.sections if s.name.endswith("__text"))
    assert text.is_executable
    assert not text.is_writable
    assert info.entry_point == text.virtual_address
    assert not info.is_stripped
    assert any(s.name == "_sample_main" and s.is_function for s in info.symbols)


def test_macho_va_offset_roundtrip(macho64_text_path: Path) -> None:
    info = BinaryLoader().load(macho64_text_path)
    text = next(s for s in info.sections if s.name.endswith("__text"))
    assert text.raw_size == text.size
    offset = info.va_to_offset(text.virtual_address)
    assert offset == text.offset
    assert info.offset_to_va(offset) == text.virtual_address


def test_macho_findings_carry_evidence(macho64_text_path: Path) -> None:
    info = BinaryLoader().load(macho64_text_path)
    assert all(section.evidence is not None for section in info.sections)
    assert all(sym.evidence is not None for sym in info.symbols)
    assert all(imp.evidence is not None for imp in info.imports)
    assert all(exp.evidence is not None for exp in info.exports)


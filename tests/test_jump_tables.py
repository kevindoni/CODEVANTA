"""Jump-table resolution tests over tiny synthetic ELF64 samples.

Every sample is assembled byte-by-byte with :mod:`struct` in this module (its
own section-header builder), so the tests stay self-contained: no shared
fixtures, no real binaries and nothing is ever executed.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from codevanta.analysis.jump_tables import (
    MAX_ENTRIES,
    JumpTableEntry,
    JumpTableResult,
    resolve_jump_table,
)
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence

TEXT_VA = 0x401000
RODATA_VA = 0x402000
UNMAPPED_VA = 0x500000

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHT_PROGBITS = 1
SHT_STRTAB = 3

#: File offsets used by the builder below.
_TEXT_OFFSET = 0x40
_TEXT_SIZE = 0x40
_RODATA_OFFSET = _TEXT_OFFSET + _TEXT_SIZE
_RODATA_SIZE = 0x40

_SHSTRTAB = b"\x00.text\x00.rodata\x00.shstrtab\x00"
_NAME_TEXT = 1
_NAME_RODATA = 7
_NAME_SHSTRTAB = 15


def _write_elf64_jump_table(
    path: Path,
    pointers: list[int],
    *,
    terminator: bool = True,
) -> Path:
    """Write an ELF64 file holding ``pointers`` as an 8-byte array in .rodata.

    Args:
        path: Destination file.
        pointers: Absolute 64-bit values stored back-to-back at :data:`RODATA_VA`.
        terminator: Append a zero pointer after ``pointers``.

    Returns:
        ``path``, written to disk.
    """
    table = b"".join(struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF) for value in pointers)
    if terminator:
        table += bytes(8)
    if len(table) > _RODATA_SIZE:
        raise AssertionError("test table does not fit in the synthetic .rodata")
    rodata = table.ljust(_RODATA_SIZE, b"\x00")
    text = b"\x90" * _TEXT_SIZE  # x86 nop sled: only the mapped bytes matter
    shstrtab_offset = _RODATA_OFFSET + len(rodata)
    section_headers_offset = (shstrtab_offset + len(_SHSTRTAB) + 7) & ~7

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,                             # e_type = ET_EXEC
        62,                            # e_machine = EM_X86_64
        1,                             # e_version
        TEXT_VA,                       # e_entry
        0,                             # e_phoff
        section_headers_offset,        # e_shoff
        0,                             # e_flags
        64,                            # e_ehsize
        56,                            # e_phentsize
        0,                             # e_phnum
        64,                            # e_shentsize
        4,                             # e_shnum: null, .text, .rodata, .shstrtab
        3,                             # e_shstrndx
    )

    blob = bytearray(section_headers_offset)
    blob[0:64] = header
    blob[_TEXT_OFFSET : _TEXT_OFFSET + len(text)] = text
    blob[_RODATA_OFFSET : _RODATA_OFFSET + len(rodata)] = rodata
    blob[shstrtab_offset : shstrtab_offset + len(_SHSTRTAB)] = _SHSTRTAB

    blob += bytes(64)  # SHT_NULL
    blob += struct.pack(
        "<IIQQQQIIQQ",
        _NAME_TEXT,                    # sh_name
        SHT_PROGBITS,                  # sh_type
        SHF_ALLOC | SHF_EXECINSTR,     # sh_flags
        TEXT_VA,                       # sh_addr
        _TEXT_OFFSET,                  # sh_offset
        len(text),                     # sh_size
        0,                             # sh_link
        0,                             # sh_info
        16,                            # sh_addralign
        0,                             # sh_entsize
    )
    blob += struct.pack(
        "<IIQQQQIIQQ",
        _NAME_RODATA,                  # sh_name
        SHT_PROGBITS,                  # sh_type
        SHF_ALLOC,                     # sh_flags (read-only data)
        RODATA_VA,                     # sh_addr
        _RODATA_OFFSET,                # sh_offset
        len(rodata),                   # sh_size
        0,                             # sh_link
        0,                             # sh_info
        8,                             # sh_addralign
        8,                             # sh_entsize
    )
    blob += struct.pack(
        "<IIQQQQIIQQ",
        _NAME_SHSTRTAB,                # sh_name
        SHT_STRTAB,                    # sh_type
        0,                             # sh_flags
        0,                             # sh_addr
        shstrtab_offset,               # sh_offset
        len(_SHSTRTAB),                # sh_size
        0,                             # sh_link
        0,                             # sh_info
        1,                             # sh_addralign
        0,                             # sh_entsize
    )
    path.write_bytes(bytes(blob))
    return path


def _load(path: Path) -> BinaryInfo:
    """Load synthetic metadata for ``path`` through the real loader."""
    return BinaryLoader().load(path)


def _three_target_sample(tmp_path: Path) -> Path:
    """Write the canonical sample: three .text pointers plus a terminator."""
    return _write_elf64_jump_table(
        tmp_path / "jump_table.bin", [TEXT_VA, TEXT_VA + 0x10, TEXT_VA + 0x20]
    )


def test_sample_sections_are_loaded_as_expected(tmp_path: Path) -> None:
    """Sanity-check the synthetic ELF before trusting the resolution tests."""
    path = _three_target_sample(tmp_path)
    info = _load(path)

    assert info.format == "ELF"
    assert info.bitness == 64
    assert info.endianness == "little"
    assert info.section_for_va(TEXT_VA) is not None
    assert info.section_for_va(TEXT_VA).is_executable is True
    assert info.section_for_va(RODATA_VA) is not None
    assert info.section_for_va(RODATA_VA).is_executable is False
    assert info.section_for_va(UNMAPPED_VA) is None


def test_resolves_three_text_targets(tmp_path: Path) -> None:
    path = _three_target_sample(tmp_path)
    info = _load(path)

    result = resolve_jump_table(path, info, RODATA_VA)

    assert isinstance(result, JumpTableResult)
    assert result.table_address == RODATA_VA
    assert result.pointer_size == 8
    assert [entry.index for entry in result.entries] == [0, 1, 2]
    assert [entry.target for entry in result.entries] == [
        TEXT_VA,
        TEXT_VA + 0x10,
        TEXT_VA + 0x20,
    ]
    assert result.truncated is False
    # Only the zero terminator stopped the scan.
    assert len(result.warnings) == 1
    assert "zero pointer" in result.warnings[0]


def test_entry_and_result_evidence_are_medium_confidence(tmp_path: Path) -> None:
    path = _three_target_sample(tmp_path)
    info = _load(path)

    result = resolve_jump_table(path, info, RODATA_VA)
    entry = result.entries[1]

    assert isinstance(entry, JumpTableEntry)
    assert entry.evidence.source == "jump_table.pointer_array"
    assert entry.evidence.method == "absolute_pointers"
    assert entry.evidence.confidence is Confidence.MEDIUM
    assert entry.evidence.address == RODATA_VA + 8
    assert result.evidence.source == "jump_table.pointer_array"
    assert result.evidence.method == "absolute_pointers"
    assert result.evidence.confidence is Confidence.MEDIUM
    assert result.evidence.address == RODATA_VA
    assert result.evidence.extra["entries"] == 3
    assert result.evidence.extra["pointer_size"] == 8
    assert result.evidence.extra["truncated"] is False


def test_to_dict_is_serializable_and_hex_formatted(tmp_path: Path) -> None:
    path = _three_target_sample(tmp_path)
    info = _load(path)

    payload = resolve_jump_table(path, info, RODATA_VA).to_dict()

    assert payload["table_address"] == "0x402000"
    assert payload["entry_count"] == 3
    assert payload["pointer_size"] == 8
    assert payload["truncated"] is False
    assert payload["entries"][2]["target"] == "0x401020"
    assert payload["entries"][2]["evidence"]["confidence"] == "medium"


def test_max_entries_truncates_the_table(tmp_path: Path) -> None:
    path = _three_target_sample(tmp_path)
    info = _load(path)

    result = resolve_jump_table(path, info, RODATA_VA, max_entries=2)

    assert [entry.target for entry in result.entries] == [TEXT_VA, TEXT_VA + 0x10]
    assert result.truncated is True
    assert result.warnings == ()


def test_max_entries_that_covers_the_table_is_not_truncated(tmp_path: Path) -> None:
    path = _three_target_sample(tmp_path)
    info = _load(path)

    result = resolve_jump_table(path, info, RODATA_VA, max_entries=3)

    assert len(result.entries) == 3
    assert result.truncated is False


def test_unmapped_table_address_raises(tmp_path: Path) -> None:
    path = _three_target_sample(tmp_path)
    info = _load(path)

    with pytest.raises(AnalysisError):
        resolve_jump_table(path, info, UNMAPPED_VA)


def test_address_past_every_section_raises(tmp_path: Path) -> None:
    """An address whose section maps no file byte cannot start a table."""
    path = _three_target_sample(tmp_path)
    info = _load(path)

    with pytest.raises(AnalysisError):
        # 0x404000 is past every section in the sample.
        resolve_jump_table(path, info, 0x404000)


def test_pointer_into_rodata_stops_with_warning(tmp_path: Path) -> None:
    path = _write_elf64_jump_table(
        tmp_path / "jump_table_rodata.bin", [TEXT_VA, RODATA_VA, TEXT_VA + 0x10]
    )
    info = _load(path)

    result = resolve_jump_table(path, info, RODATA_VA)

    assert [entry.target for entry in result.entries] == [TEXT_VA]
    assert result.truncated is False
    assert len(result.warnings) == 1
    assert "0x402000" in result.warnings[0]
    assert "non-executable" in result.warnings[0]
    assert ".rodata" in result.warnings[0]


def test_executable_only_false_accepts_data_targets(tmp_path: Path) -> None:
    path = _write_elf64_jump_table(
        tmp_path / "jump_table_any.bin", [TEXT_VA, RODATA_VA, TEXT_VA + 0x10]
    )
    info = _load(path)

    result = resolve_jump_table(path, info, RODATA_VA, executable_only=False)

    assert [entry.target for entry in result.entries] == [TEXT_VA, RODATA_VA, TEXT_VA + 0x10]
    assert len(result.warnings) == 1
    assert "zero pointer" in result.warnings[0]


def test_unmapped_target_stops_the_scan(tmp_path: Path) -> None:
    path = _write_elf64_jump_table(
        tmp_path / "jump_table_gap.bin", [TEXT_VA, UNMAPPED_VA, TEXT_VA + 0x10]
    )
    info = _load(path)

    result = resolve_jump_table(path, info, RODATA_VA)

    assert [entry.target for entry in result.entries] == [TEXT_VA]
    assert len(result.warnings) == 1
    assert "not mapped" in result.warnings[0]


def test_target_bounds_stop_the_scan(tmp_path: Path) -> None:
    path = _three_target_sample(tmp_path)
    info = _load(path)

    result = resolve_jump_table(
        path, info, RODATA_VA, min_target=TEXT_VA, max_target=TEXT_VA + 0x10
    )

    assert [entry.target for entry in result.entries] == [TEXT_VA, TEXT_VA + 0x10]
    assert len(result.warnings) == 1
    assert "max_target" in result.warnings[0]


def test_zero_terminator_only_yields_no_entries(tmp_path: Path) -> None:
    path = _write_elf64_jump_table(tmp_path / "jump_table_empty.bin", [])
    info = _load(path)

    result = resolve_jump_table(path, info, RODATA_VA)

    assert result.entries == []
    assert result.truncated is False
    assert len(result.warnings) == 1


@pytest.mark.parametrize("max_entries", [0, -1, MAX_ENTRIES + 1])
def test_invalid_max_entries_raises(tmp_path: Path, max_entries: int) -> None:
    path = _three_target_sample(tmp_path)
    info = _load(path)

    with pytest.raises(AnalysisError):
        resolve_jump_table(path, info, RODATA_VA, max_entries=max_entries)


@pytest.mark.parametrize("pointer_size", [1, 2, 16])
def test_invalid_pointer_size_raises(tmp_path: Path, pointer_size: int) -> None:
    path = _three_target_sample(tmp_path)
    info = _load(path)

    with pytest.raises(AnalysisError):
        resolve_jump_table(path, info, RODATA_VA, pointer_size=pointer_size)


def test_inverted_target_window_raises(tmp_path: Path) -> None:
    path = _three_target_sample(tmp_path)
    info = _load(path)

    with pytest.raises(AnalysisError):
        resolve_jump_table(path, info, RODATA_VA, min_target=0x402000, max_target=0x401000)


def test_explicit_pointer_size_is_honoured(tmp_path: Path) -> None:
    path = _three_target_sample(tmp_path)
    info = _load(path)

    result = resolve_jump_table(path, info, RODATA_VA, pointer_size=8)

    assert result.pointer_size == 8
    assert [entry.target for entry in result.entries] == [
        TEXT_VA,
        TEXT_VA + 0x10,
        TEXT_VA + 0x20,
    ]

"""Jump-table resolution tests over tiny synthetic ELF64 samples.

Every sample is assembled byte-by-byte with :mod:`struct` in this module (its
own section-header builder), so the tests stay self-contained: no shared
fixtures, no real binaries and nothing is ever executed. Both layouts are
covered: absolute 8-byte pointer arrays (``mode="absolute"``, the default) and
signed 4-byte offset tables resolved against a base (``mode="relative"``).
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

#: Relative offset from :data:`TEXT_VA` that still lands inside .text.
TEXT_DELTA = 0x10

#: Relative offset from :data:`TEXT_VA` that lands in .rodata (mapped, not
#: executable): ``0x401000 + 0x1000 == 0x402000``.
DATA_DELTA = 0x1000

#: Relative offset from :data:`TEXT_VA` that lands past every mapped section:
#: ``0x401000 + 0x2000 == 0x403000``.
OUT_OF_TEXT_DELTA = 0x2000

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
    return _write_elf64_rodata_table(path, table)


def _write_elf64_relative_table(path: Path, offsets: list[int]) -> Path:
    """Write an ELF64 file holding ``offsets`` as signed 4-byte slots in .rodata.

    The remaining .rodata bytes stay zero, and a zero offset is *not* a
    terminator in this layout, so samples that need a clean stop place a final
    offset that resolves outside .text.

    Args:
        path: Destination file.
        offsets: Signed 32-bit deltas stored back-to-back at :data:`RODATA_VA`.

    Returns:
        ``path``, written to disk.
    """
    table = b"".join(struct.pack("<i", value) for value in offsets)
    return _write_elf64_rodata_table(path, table)


def _write_elf64_rodata_table(path: Path, table: bytes) -> Path:
    """Write an ELF64 file whose .rodata starts with ``table``, zero-padded.

    Args:
        path: Destination file.
        table: Raw bytes to place at :data:`RODATA_VA`.

    Returns:
        ``path``, written to disk.
    """
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


def _relative_sample(tmp_path: Path) -> Path:
    """Write the canonical relative sample: two .text deltas plus a stop slot."""
    return _write_elf64_relative_table(
        tmp_path / "jump_table_relative.bin",
        [TEXT_DELTA, 0x20, OUT_OF_TEXT_DELTA],
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


# ---------------------------------------------------------------------------
# Relative mode: signed 32-bit offsets resolved against an explicit base
# ---------------------------------------------------------------------------


def test_relative_offsets_resolve_against_the_base_address(tmp_path: Path) -> None:
    path = _relative_sample(tmp_path)
    info = _load(path)

    result = resolve_jump_table(path, info, RODATA_VA, mode="relative", base_address=TEXT_VA)

    assert result.table_address == RODATA_VA
    assert result.pointer_size == 4
    assert [entry.index for entry in result.entries] == [0, 1]
    assert [entry.target for entry in result.entries] == [0x401010, 0x401020]
    assert result.truncated is False
    # The third slot resolves to 0x403000, which no section maps.
    assert len(result.warnings) == 1
    assert "0x403000" in result.warnings[0]
    assert "not mapped" in result.warnings[0]


def test_relative_evidence_labels_and_base_address(tmp_path: Path) -> None:
    path = _relative_sample(tmp_path)
    info = _load(path)

    result = resolve_jump_table(path, info, RODATA_VA, mode="relative", base_address=TEXT_VA)
    first = result.entries[0]

    assert first.evidence.source == "jump_table.relative_offsets"
    assert first.evidence.method == "signed_offsets"
    assert first.evidence.confidence is Confidence.MEDIUM
    assert first.evidence.address == RODATA_VA
    assert "0x401000" in (first.evidence.detail or "")
    assert first.evidence.extra["base"] == "0x401000"
    assert result.evidence.source == "jump_table.relative_offsets"
    assert result.evidence.method == "signed_offsets"
    assert result.evidence.confidence is Confidence.MEDIUM
    assert result.evidence.address == RODATA_VA
    assert "0x401000" in (result.evidence.detail or "")
    assert result.evidence.extra["base"] == "0x401000"
    assert result.evidence.extra["pointer_size"] == 4


def test_relative_offset_outside_text_stops_with_warning(tmp_path: Path) -> None:
    """An offset that lands in .rodata is mapped but not executable."""
    path = _write_elf64_relative_table(
        tmp_path / "jump_table_relative_data.bin", [TEXT_DELTA, DATA_DELTA]
    )
    info = _load(path)

    result = resolve_jump_table(path, info, RODATA_VA, mode="relative", base_address=TEXT_VA)

    assert [entry.target for entry in result.entries] == [TEXT_VA + TEXT_DELTA]
    assert result.truncated is False
    assert len(result.warnings) == 1
    assert f"0x{RODATA_VA:x}" in result.warnings[0]
    assert "non-executable" in result.warnings[0]
    assert ".rodata" in result.warnings[0]


def test_relative_max_entries_one_is_truncated(tmp_path: Path) -> None:
    path = _relative_sample(tmp_path)
    info = _load(path)

    result = resolve_jump_table(
        path, info, RODATA_VA, max_entries=1, mode="relative", base_address=TEXT_VA
    )

    assert [entry.target for entry in result.entries] == [0x401010]
    assert result.truncated is True
    assert result.warnings == ()


def test_relative_zero_offset_is_not_a_terminator(tmp_path: Path) -> None:
    path = _write_elf64_relative_table(
        tmp_path / "jump_table_relative_zero.bin", [TEXT_DELTA, 0, OUT_OF_TEXT_DELTA]
    )
    info = _load(path)

    result = resolve_jump_table(path, info, RODATA_VA, mode="relative", base_address=TEXT_VA)

    # The zero delta is a real entry pointing at the base address.
    assert [entry.target for entry in result.entries] == [TEXT_VA + TEXT_DELTA, TEXT_VA]
    assert all("zero pointer" not in warning for warning in result.warnings)
    assert len(result.warnings) == 1
    assert "0x403000" in result.warnings[0]


def test_relative_negative_offsets_are_decoded_as_signed(tmp_path: Path) -> None:
    path = _write_elf64_relative_table(
        tmp_path / "jump_table_relative_negative.bin",
        [-0x20, -0x10, OUT_OF_TEXT_DELTA],
    )
    info = _load(path)

    result = resolve_jump_table(
        path, info, RODATA_VA, mode="relative", base_address=TEXT_VA + 0x30
    )

    assert [entry.target for entry in result.entries] == [0x401010, 0x401020]


def test_relative_target_bounds_stop_the_scan(tmp_path: Path) -> None:
    path = _relative_sample(tmp_path)
    info = _load(path)

    result = resolve_jump_table(
        path,
        info,
        RODATA_VA,
        mode="relative",
        base_address=TEXT_VA,
        min_target=TEXT_VA,
        max_target=TEXT_VA + TEXT_DELTA,
    )

    assert [entry.target for entry in result.entries] == [0x401010]
    assert len(result.warnings) == 1
    assert "max_target" in result.warnings[0]


def test_relative_mode_requires_a_base_address(tmp_path: Path) -> None:
    path = _relative_sample(tmp_path)
    info = _load(path)

    with pytest.raises(AnalysisError):
        resolve_jump_table(path, info, RODATA_VA, mode="relative")


@pytest.mark.parametrize("pointer_size", [2, 8])
def test_relative_mode_rejects_other_pointer_sizes(
    tmp_path: Path, pointer_size: int
) -> None:
    path = _relative_sample(tmp_path)
    info = _load(path)

    with pytest.raises(AnalysisError):
        resolve_jump_table(
            path,
            info,
            RODATA_VA,
            pointer_size=pointer_size,
            mode="relative",
            base_address=TEXT_VA,
        )


def test_unknown_mode_raises(tmp_path: Path) -> None:
    path = _relative_sample(tmp_path)
    info = _load(path)

    with pytest.raises(AnalysisError):
        resolve_jump_table(path, info, RODATA_VA, mode="offset")


def test_absolute_mode_is_unchanged(tmp_path: Path) -> None:
    path = _three_target_sample(tmp_path)
    info = _load(path)

    default = resolve_jump_table(path, info, RODATA_VA)
    explicit = resolve_jump_table(path, info, RODATA_VA, mode="absolute")

    assert explicit.to_dict() == default.to_dict()
    assert default.pointer_size == 8
    assert default.evidence.source == "jump_table.pointer_array"
    assert default.evidence.method == "absolute_pointers"


def test_absolute_mode_ignores_base_address(tmp_path: Path) -> None:
    path = _three_target_sample(tmp_path)
    info = _load(path)

    baseline = resolve_jump_table(path, info, RODATA_VA)
    with_base = resolve_jump_table(path, info, RODATA_VA, base_address=TEXT_VA)

    assert with_base.to_dict() == baseline.to_dict()

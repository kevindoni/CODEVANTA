"""Loader tests for PE, ELF, thin Mach-O and fat (universal) Mach-O inputs."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from codevanta.core.loader import (
    FAT_MAGIC,
    MAX_FAT_ALIGN,
    MAX_FAT_SLICES,
    BinaryLoader,
    BinaryLoadError,
    FatArch,
    FatContainer,
)
from conftest import make_macho64_with_text

# ---- fat (universal) Mach-O builders ---------------------------------------

# Container name -> (on-disk magic bytes, struct byte order, 64-bit table entries).
# "CIGAM" containers store the table fields in little-endian order.
FAT_HEADERS = {
    "FAT_MAGIC": (b"\xca\xfe\xba\xbe", ">", False),
    "FAT_CIGAM": (b"\xbe\xba\xfe\xca", "<", False),
    "FAT_MAGIC_64": (b"\xca\xfe\xba\xbf", ">", True),
    "FAT_CIGAM_64": (b"\xbf\xba\xfe\xca", "<", True),
}
CPU_ARM = 0x0000000C
CPU_X86_64 = 0x01000007
SLICE_ALIGN = 4  # fat_arch.align is an exponent: 1 << 4 == 16-byte alignment


def thin_macho64(tmp_path: Path, name: str, *, base: int, symbol_name: str) -> bytes:
    """Build one thin 64-bit Mach-O slice with the shared fixture helper."""
    path = make_macho64_with_text(tmp_path / name, base=base, symbol_name=symbol_name)
    return path.read_bytes()


def thin_macho32_stub() -> bytes:
    """A 32-bit Mach-O header without load commands; a valid 32-bit slice."""
    return struct.pack("<IIIIIII", 0xFEEDFACE, CPU_ARM, 3, 2, 0, 0, 0)


def fat_blob(
    slices: list[tuple[int, bytes]],
    *,
    magic: str = "FAT_MAGIC",
) -> tuple[bytes, list[int]]:
    """Assemble a fat container for ``(cputype, data)`` slices.

    Returns the file content together with the file offset assigned to each
    slice, so tests can assert on the container-relative layout.
    """
    magic_bytes, order, wide = FAT_HEADERS[magic]
    entry_size = 32 if wide else 20
    offset = 8 + entry_size * len(slices)
    table = b""
    body = b""
    offsets: list[int] = []
    for cputype, data in slices:
        padding = (-offset) % (1 << SLICE_ALIGN)
        offset += padding
        if wide:
            table += struct.pack(
                f"{order}IIQQII", cputype, 3, offset, len(data), SLICE_ALIGN, 0
            )
        else:
            table += struct.pack(
                f"{order}IIIII", cputype, 3, offset, len(data), SLICE_ALIGN
            )
        body += b"\x00" * padding + data
        offsets.append(offset)
        offset += len(data)
    header = magic_bytes + struct.pack(f"{order}I", len(slices))
    return header + table + body, offsets


def write_fat(
    path: Path,
    slices: list[tuple[int, bytes]],
    *,
    magic: str = "FAT_MAGIC",
) -> tuple[Path, list[int]]:
    """Write a fat container to ``path`` and return it with the slice offsets."""
    blob, offsets = fat_blob(slices, magic=magic)
    path.write_bytes(blob)
    return path, offsets


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
    # A thin Mach-O has no container to explain.
    assert info.evidence is None


# ---- fat (universal) Mach-O ------------------------------------------------


def test_fat_macho_prefers_64bit_slice(tmp_path: Path) -> None:
    # The 32-bit slice sits at the lower offset, so only the 64-bit preference
    # can explain the selection.
    arm_slice = thin_macho32_stub()
    x86_slice = thin_macho64(
        tmp_path, "thin_x86_64.bin", base=0x100000000, symbol_name="_fat_main"
    )
    fat_path, offsets = write_fat(
        tmp_path / "fat_two_slices.bin",
        [(CPU_ARM, arm_slice), (CPU_X86_64, x86_slice)],
    )

    info = BinaryLoader().load(fat_path)

    assert info.format == "MachO"
    assert info.architecture == "x86_64"
    assert info.bitness == 64
    assert info.evidence is not None
    extra = info.evidence.extra
    assert extra["fat"] is True
    assert extra["slice_index"] == 1
    assert extra["slice_count"] == 2
    assert extra["slice_arch"] == "x86_64"
    assert extra["slice_offset"] == offsets[1]
    assert extra["slice_size"] == len(x86_slice)
    assert extra["available_arches"] == ["arm", "x86_64"]
    assert extra["selection_rule"] == "prefer_64bit"
    assert [entry["index"] for entry in extra["available_slices"]] == [0, 1]
    assert info.evidence.source == "macho.fat_header"
    assert info.evidence.method == "fat_arch_table"
    assert "slice 1 of 2" in (info.evidence.detail or "")
    # The container evidence survives serialization for reports.
    payload = info.to_dict()
    assert payload["evidence"]["extra"]["slice_index"] == 1
    assert payload["evidence"]["extra"]["fat"] is True


def test_fat_macho_slice_sections_entry_and_imports(tmp_path: Path) -> None:
    first = thin_macho64(
        tmp_path, "slice_first.bin", base=0x100000000, symbol_name="_first_slice"
    )
    second = thin_macho64(
        tmp_path, "slice_second.bin", base=0x200000000, symbol_name="_second_slice"
    )
    fat_path, offsets = write_fat(
        tmp_path / "fat_same_arch.bin", [(CPU_X86_64, first), (CPU_X86_64, second)]
    )

    info = BinaryLoader().load(fat_path)

    # Two 64-bit slices: the first one by file offset wins.
    assert info.evidence is not None
    assert info.evidence.extra["slice_index"] == 0
    assert info.evidence.extra["selection_rule"] == "prefer_64bit"
    assert info.image_base == 0x100000000
    assert info.file_size == fat_path.stat().st_size

    text = next(section for section in info.sections if section.name.endswith("__text"))
    assert info.entry_point == text.virtual_address
    assert text.is_executable
    # Parsed thin, the section offset is slice-relative; inside the container it
    # must be shifted by the fat offset so it still points at the same bytes.
    thin = BinaryLoader().load(tmp_path / "slice_first.bin")
    thin_text = next(s for s in thin.sections if s.name.endswith("__text"))
    assert text.offset == thin_text.offset + offsets[0]
    assert text.raw_size == text.size
    assert info.va_to_offset(text.virtual_address) == text.offset
    assert info.offset_to_va(text.offset) == text.virtual_address
    assert fat_path.read_bytes()[text.offset : text.offset + text.size] == bytes.fromhex(
        "554889e5c3"
    )

    # Symbols come from the chosen slice only.
    assert [symbol.name for symbol in info.symbols] == ["_first_slice"]
    assert all(symbol.evidence is not None for symbol in info.symbols)
    assert "slice 0 of 2" in (info.evidence.detail or "")
    # The fixture has no undefined symbols: imports stay empty and consistent.
    assert info.imports == []
    assert all(imp.evidence is not None for imp in info.imports)


def test_fat_macho_single_slice(tmp_path: Path) -> None:
    data = thin_macho64(tmp_path, "only.bin", base=0x100000000, symbol_name="_only")
    fat_path, offsets = write_fat(tmp_path / "fat_single.bin", [(CPU_X86_64, data)])

    info = BinaryLoader().load(fat_path)

    assert info.format == "MachO"
    assert info.sections
    assert info.entry_point is not None
    assert info.evidence is not None
    extra = info.evidence.extra
    assert extra["fat_magic_name"] == "FAT_MAGIC"
    assert extra["fat_arch_64"] is False
    assert extra["slice_index"] == 0
    assert extra["slice_count"] == 1
    assert extra["available_arches"] == ["x86_64"]
    assert extra["slice_offset"] == offsets[0]
    assert "slice 0 of 1" in (info.evidence.detail or "")


def test_fat_macho_cigam_byte_order(tmp_path: Path) -> None:
    data = thin_macho64(tmp_path, "cigam.bin", base=0x100000000, symbol_name="_cigam")
    fat_path, offsets = write_fat(
        tmp_path / "fat_cigam.bin", [(CPU_X86_64, data)], magic="FAT_CIGAM"
    )
    assert fat_path.read_bytes()[:4] == b"\xbe\xba\xfe\xca"

    info = BinaryLoader().load(fat_path)

    assert info.format == "MachO"
    assert info.bitness == 64
    assert info.evidence is not None
    extra = info.evidence.extra
    assert extra["fat_magic_name"] == "FAT_CIGAM"
    assert extra["fat_magic"] == "0xbebafeca"
    assert extra["slice_offset"] == offsets[0]
    assert extra["available_arches"] == ["x86_64"]
    text = next(section for section in info.sections if section.name.endswith("__text"))
    assert fat_path.read_bytes()[text.offset : text.offset + text.size] == bytes.fromhex(
        "554889e5c3"
    )


def test_fat_macho_64bit_arch_entry(tmp_path: Path) -> None:
    data = thin_macho64(tmp_path, "wide.bin", base=0x100000000, symbol_name="_wide")
    fat_path, offsets = write_fat(
        tmp_path / "fat64.bin", [(CPU_X86_64, data)], magic="FAT_MAGIC_64"
    )
    assert fat_path.read_bytes()[:4] == b"\xca\xfe\xba\xbf"

    info = BinaryLoader().load(fat_path)

    assert info.format == "MachO"
    assert info.entry_point is not None
    assert info.evidence is not None
    extra = info.evidence.extra
    assert extra["fat_arch_64"] is True
    assert extra["fat_magic_name"] == "FAT_MAGIC_64"
    assert extra["slice_cputype"] == "0x1000007"
    assert extra["slice_offset"] == offsets[0]
    assert extra["available_slices"][0]["arch"] == "x86_64"
    # fat_arch_64 entries are 32 bytes, so the slice starts after 8 + 32 bytes.
    assert offsets[0] >= 8 + 32


def test_fat_macho_rejects_truncated_header(tmp_path: Path) -> None:
    sample = tmp_path / "fat_header_only.bin"
    sample.write_bytes(b"\xca\xfe\xba\xbe")

    with pytest.raises(BinaryLoadError) as excinfo:
        BinaryLoader().load(sample)

    assert "nfat_arch" in str(excinfo.value)
    assert "truncated" in str(excinfo.value)


def test_fat_macho_rejects_truncated_arch_table(tmp_path: Path) -> None:
    # nfat_arch claims two slices but the file ends after the first entry.
    sample = tmp_path / "fat_truncated_table.bin"
    sample.write_bytes(struct.pack(">II", 0xCAFEBABE, 2) + bytes(20))

    with pytest.raises(BinaryLoadError) as excinfo:
        BinaryLoader().load(sample)

    assert "fat_arch table truncated" in str(excinfo.value)
    assert "nfat_arch=2" in str(excinfo.value)


def test_fat_macho_rejects_slice_outside_file(tmp_path: Path) -> None:
    sample = tmp_path / "fat_slice_oob.bin"
    header = struct.pack(">II", 0xCAFEBABE, 1)
    entry = struct.pack(">IIIII", CPU_X86_64, 3, 0x1000, 0x1000, SLICE_ALIGN)
    sample.write_bytes(header + entry)

    with pytest.raises(BinaryLoadError) as excinfo:
        BinaryLoader().load(sample)

    assert "fat_arch[0].offset/size" in str(excinfo.value)
    assert "outside the file" in str(excinfo.value)


def test_fat_macho_rejects_zero_slices(tmp_path: Path) -> None:
    sample = tmp_path / "fat_empty.bin"
    sample.write_bytes(struct.pack(">II", 0xCAFEBABE, 0))

    with pytest.raises(BinaryLoadError) as excinfo:
        BinaryLoader().load(sample)

    assert "nfat_arch" in str(excinfo.value)
    assert "zero" in str(excinfo.value)


def test_fat_macho_rejects_mismatched_cputype(tmp_path: Path) -> None:
    # The table entry claims arm, but the slice body is a 64-bit x86 image.
    data = thin_macho64(
        tmp_path, "mismatch_slice.bin", base=0x100000000, symbol_name="_mismatch"
    )
    fat_path, _ = write_fat(tmp_path / "fat_mismatch.bin", [(CPU_ARM, data)])

    with pytest.raises(BinaryLoadError) as excinfo:
        BinaryLoader().load(fat_path)

    message = str(excinfo.value)
    assert "fat_arch[0].cputype" in message
    # Both the claimed and the actually parsed cputype are named.
    assert "arm (0xc)" in message
    assert "x86_64 (0x1000007)" in message


def test_fat_macho_rejects_non_macho_slice(elf64_path: Path, tmp_path: Path) -> None:
    # An ELF payload inside a fat container would otherwise be reported as ELF
    # with offsets relative to the slice, i.e. the wrong bytes.
    fat_path, _ = write_fat(
        tmp_path / "fat_elf_slice.bin", [(CPU_X86_64, elf64_path.read_bytes())]
    )

    with pytest.raises(BinaryLoadError) as excinfo:
        BinaryLoader().load(fat_path)

    assert "fat slice is not a Mach-O image: ELF" in str(excinfo.value)


def test_fat_macho_rejects_too_many_slices(tmp_path: Path) -> None:
    assert MAX_FAT_SLICES == 32
    count = MAX_FAT_SLICES + 1
    sample = tmp_path / "fat_too_many.bin"
    entry = struct.pack(">IIIII", CPU_X86_64, 3, 0x100, 0x10, SLICE_ALIGN)
    # The architecture table itself fits in the file, so only the slice-count
    # bound can reject this container.
    sample.write_bytes(struct.pack(">II", FAT_MAGIC, count) + entry * count)

    with pytest.raises(BinaryLoadError) as excinfo:
        BinaryLoader().load(sample)

    message = str(excinfo.value)
    assert f"nfat_arch={count}" in message
    assert f"maximum of {MAX_FAT_SLICES} slices" in message


def test_fat_macho_rejects_oversized_align(tmp_path: Path) -> None:
    sample = tmp_path / "fat_align.bin"
    entry = struct.pack(">IIIII", CPU_X86_64, 3, 0x100, 0x10, MAX_FAT_ALIGN + 1)
    sample.write_bytes(struct.pack(">II", FAT_MAGIC, 1) + entry + bytes(0x100))

    with pytest.raises(BinaryLoadError) as excinfo:
        BinaryLoader().load(sample)

    message = str(excinfo.value)
    assert f"fat_arch[0].align is {MAX_FAT_ALIGN + 1}" in message
    assert f"maximum of {MAX_FAT_ALIGN}" in message


def test_fat_macho_rejects_misaligned_slice_offset(tmp_path: Path) -> None:
    sample = tmp_path / "fat_misaligned.bin"
    table_end = 8 + 20  # header plus one fat_arch entry
    offset = table_end + 8  # past the table but not a multiple of 1 << align
    entry = struct.pack(">IIIII", CPU_X86_64, 3, offset, 0x10, SLICE_ALIGN)
    sample.write_bytes(struct.pack(">II", FAT_MAGIC, 1) + entry + bytes(0x40))

    with pytest.raises(BinaryLoadError) as excinfo:
        BinaryLoader().load(sample)

    message = str(excinfo.value)
    assert f"fat_arch[0].offset 0x{offset:x} is not aligned to 16 bytes" in message
    assert f"(align={SLICE_ALIGN})" in message


def test_fat_macho_rejects_slice_offset_inside_table(tmp_path: Path) -> None:
    sample = tmp_path / "fat_overlapping.bin"
    table_end = 8 + 20  # header plus one fat_arch entry
    # offset 8 is aligned for align=0 but sits inside the header/table area.
    entry = struct.pack(">IIIII", CPU_X86_64, 3, 8, 0x10, 0)
    sample.write_bytes(struct.pack(">II", FAT_MAGIC, 1) + entry + bytes(0x40))

    with pytest.raises(BinaryLoadError) as excinfo:
        BinaryLoader().load(sample)

    message = str(excinfo.value)
    assert "fat_arch[0].offset" in message
    assert "points inside the fat header/table" in message
    assert f"ends at 0x{table_end:x}" in message


def test_fat_container_evidence_caps_available_slices() -> None:
    # Even if the hard slice bound were raised, container evidence stays bounded.
    arches = tuple(
        FatArch(
            index=index,
            cputype=CPU_X86_64,
            cpusubtype=3,
            offset=0x100 * (index + 1),
            size=0x100,
            align=SLICE_ALIGN,
        )
        for index in range(MAX_FAT_SLICES + 8)
    )
    container = FatContainer(
        magic=FAT_MAGIC,
        wide_entries=False,
        arches=arches,
        slice=arches[0],
        rule="prefer_64bit",
        reason="unit-test container",
    )

    extra = container.evidence_extra()

    # slice_count stays truthful while the per-slice list is capped.
    assert extra["slice_count"] == MAX_FAT_SLICES + 8
    assert len(extra["available_slices"]) == MAX_FAT_SLICES
    assert [entry["index"] for entry in extra["available_slices"]] == list(
        range(MAX_FAT_SLICES)
    )


# ---- DEX -------------------------------------------------------------------

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
HELLO_DEX = SAMPLES / "hello.dex"


def _skip_if_no_dex_sample() -> None:
    if not HELLO_DEX.exists():
        pytest.skip("samples/hello.dex is not checked out")


def test_load_real_dex_sample() -> None:
    _skip_if_no_dex_sample()
    info = BinaryLoader().load(HELLO_DEX)
    assert info.format == "DEX"
    assert info.architecture == "dalvik"
    assert info.bitness == 0
    assert info.endianness == "little"
    assert info.entry_point is None
    assert info.image_base == 0
    assert info.sections == []
    assert info.exports == []
    assert info.is_stripped is False
    assert info.sha256
    assert info.file_size == HELLO_DEX.stat().st_size
    assert any("file offsets" in w for w in info.warnings)


def test_dex_defined_methods_become_function_symbols() -> None:
    _skip_if_no_dex_sample()
    info = BinaryLoader().load(HELLO_DEX)
    names = {s.name: s for s in info.symbols}
    assert set(names) == {"LMain;-><init>", "LMain;->add", "LMain;->main"}
    add = names["LMain;->add"]
    assert add.address == 0x160
    assert add.is_function is True
    assert add.kind == "method"
    assert add.evidence.source == "dex.method_ids"
    assert add.evidence.confidence.value == "high"
    assert "file offset 0x160" in add.evidence.detail


def test_dex_external_methods_become_imports() -> None:
    _skip_if_no_dex_sample()
    info = BinaryLoader().load(HELLO_DEX)
    by_name = {i.name: i for i in info.imports}
    assert set(by_name) == {
        "Ljava/io/PrintStream;->println",
        "Ljava/lang/Object;-><init>",
    }
    println = by_name["Ljava/io/PrintStream;->println"]
    assert println.library == "Ljava/io/PrintStream;"
    assert println.address is None
    assert println.evidence.source == "dex.method_ids"
    assert "not defined in this container" in println.evidence.detail


def test_dex_function_discovery_uses_dex_sources() -> None:
    _skip_if_no_dex_sample()
    from codevanta.core.functions import discover_functions

    info = BinaryLoader().load(HELLO_DEX)
    candidates = discover_functions(info)
    assert [c.source for c in candidates] == ["dex.method_ids"] * 3
    assert all(c.confidence.value == "high" for c in candidates)
    by_name = {c.name: c for c in candidates}
    assert by_name["LMain;->add"].address == 0x160


def test_dex_magic_short_circuits_before_generic_parse(tmp_path: Path) -> None:
    # A file with a DEX magic must load as DEX even when the rest is garbage:
    # the dedicated parser decides, not the generic one.
    sample = tmp_path / "stub.dex"
    sample.write_bytes(b"dex\n035\x00" + b"\x00" * 0x68)
    info = BinaryLoader().load(sample)
    assert info.format == "DEX"
    assert info.symbols == []
    assert info.imports == []


"""Tests for codevanta.analysis.gosymbols (synthetic hand-built pclntabs).

No Go compiler is needed: every fixture is a minimal ELF64 whose ``.gopclntab``
(or ``.rodata``) section carries a hand-packed table for one of the supported
layouts, byte-for-byte matching the structures documented in Go's
``runtime/symtab.go`` and GoReSym's ``debug/gosym`` fork.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis.gosymbols import (
    MAGIC_GO12,
    MAGIC_GO116,
    MAGIC_GO118,
    MAGIC_GO120,
    PclntabLocation,
    decode_pclntab_header,
    find_pclntab,
    recover_go_symbols,
)
from codevanta.core.loader import BinaryLoader
from codevanta.core.report import AnalysisError

TEXT_VA = 0x401000
PCLNTAB_VA = 0x480000
RODATA_VA = 0x490000

FUNC_LIST = [("main.main", 0), ("runtime.nanotime1", 0x100)]
ENTRY_SPAN = 0x100
SOURCE_FILE = "/src/main.go"
SOURCE_LINE = 6


# ---- synthetic ELF builder -----------------------------------------------------


def _make_elf64(path: Path, sections: list[tuple[str, bytes, int, int]]) -> Path:
    """Write a minimal ELF64 LE ET_EXEC with the given (name, payload, flags, VA) sections."""
    names = [name for name, _, _, _ in sections] + [".shstrtab"]
    shstr = bytearray(b"\x00")
    name_offsets: dict[str, int] = {}
    for name in names:
        name_offsets[name] = len(shstr)
        shstr += name.encode() + b"\x00"

    blob = bytearray(bytes(0x40))  # room for the 64-byte ELF header
    placed: list[tuple[str, bytes, int, int, int]] = []
    for name, payload, flags, vaddr in sections:
        while len(blob) % 16:
            blob.append(0)
        placed.append((name, payload, flags, vaddr, len(blob)))
        blob.extend(payload)
    while len(blob) % 8:
        blob.append(0)
    blob.extend(shstr)
    shstrtab_offset = len(blob) - len(shstr)
    while len(blob) % 8:
        blob.append(0)
    shoff = len(blob)

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # ET_EXEC
        62,  # EM_X86_64
        1,  # e_version
        TEXT_VA,  # e_entry
        0,  # e_phoff
        shoff,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        0,  # e_phnum
        64,  # e_shentsize
        len(sections) + 2,  # e_shnum (null + sections + shstrtab)
        len(sections) + 1,  # e_shstrndx
    )
    blob[0:64] = header

    def shdr(name_off: int, sh_type: int, flags: int, vaddr: int, offset: int, size: int) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name_off, sh_type, flags, vaddr, offset, size, 0, 0, 1, 0)

    blob += bytes(64)  # null section header
    for name, payload, flags, vaddr, offset in placed:
        blob += shdr(name_offsets[name], 1, flags, vaddr, offset, len(payload))
    blob += shdr(name_offsets[".shstrtab"], 3, 0, 0, shstrtab_offset, len(shstr))
    path.write_bytes(bytes(blob))
    return path


def _elf_with_gopclntab(
    tmp_path: Path, tab: bytes, *, name: str = ".gopclntab", va: int = PCLNTAB_VA
) -> Path:
    return _make_elf64(
        tmp_path / "sample_go.bin",
        [
            (".text", bytes.fromhex("554889e5c3"), 0x6, TEXT_VA),
            (name, tab, 0x2, va),
        ],
    )


def _elf_with_text_only(tmp_path: Path) -> Path:
    return _make_elf64(
        tmp_path / "sample_notgo.bin",
        [(".text", bytes.fromhex("554889e5c3"), 0x6, TEXT_VA)],
    )


def _provider(path: Path):
    def data_provider(offset: int, length: int) -> bytes:
        if offset < 0 or length <= 0:
            return b""
        with path.open("rb") as handle:
            handle.seek(offset)
            return handle.read(length)

    return data_provider


# ---- synthetic pclntab builders --------------------------------------------------


def _funcname_parts() -> tuple[bytes, dict[str, int]]:
    """Leading-NUL funcnametab plus per-name offsets, like real tables."""
    table = bytearray(b"\x00")
    offsets: dict[str, int] = {}
    for name, _ in FUNC_LIST:
        offsets[name] = len(table)
        table += name.encode() + b"\x00"
    return bytes(table), offsets


def _pctab_parts() -> bytes:
    """pctab with a pcfile table at offset 2 (file 0) and a pcln table at 4 (line 6).

    Each table is one (zig-zag value delta, pc delta) varint pair; the delta
    encodes ``value - (-1)`` because values start at -1 (Go runtime ``step``).
    """
    file_delta = (0 + 1) * 2  # -> file number 0
    line_delta = (SOURCE_LINE + 1) * 2  # -> line 6
    return b"\x00\x00" + bytes([file_delta, 0x00]) + bytes([line_delta, 0x00])


def _build_tab_go118() -> bytes:
    """Hand-built go1.18-family table (magic 0xfffffff0, ptrSize 8, LE)."""
    funcnames, name_off = _funcname_parts()
    cutab = struct.pack("<I", 1)  # CU 0, file 0 -> filetab offset 1
    filetab = b"\x00" + SOURCE_FILE.encode() + b"\x00"
    pctab = _pctab_parts()
    header_size = 8 + 8 * 8
    parts = [funcnames, cutab, filetab, pctab]
    positions = []
    cursor = header_size
    for part in parts:
        positions.append(cursor)
        cursor += len(part)
    funcname_off, cu_off, filetab_off, pctab_off = positions
    pcln_off = cursor
    nfunc = len(FUNC_LIST)
    functab_size = (2 * nfunc + 1) * 4

    ftab = b""
    rows = b""
    for index, (name, entryoff) in enumerate(FUNC_LIST):
        # _func: entryOff u32, nameOff i32, args, deferreturn, pcsp, pcfile,
        # pcln, npcdata, cuOffset (all i32/u32) = 36 bytes.
        rows += struct.pack(
            "<IiiIIIIII",
            entryoff,
            name_off[name],
            0,
            0,
            0,
            2,  # pcfile table at pctab offset 2
            4,  # pcln table at pctab offset 4
            0,
            0,
        )
        ftab += struct.pack("<II", entryoff, functab_size + index * 36)
    sentinel = FUNC_LIST[-1][1] + ENTRY_SPAN
    ftab += struct.pack("<I", sentinel)  # lone sentinel entry pc, no funcoff

    header = struct.pack(
        "<IBBBB8Q",
        MAGIC_GO118,
        0,
        0,
        1,
        8,
        nfunc,
        1,
        TEXT_VA,
        funcname_off,
        cu_off,
        filetab_off,
        pctab_off,
        pcln_off,
    )
    return header + b"".join(parts) + ftab + rows


def _build_tab_go116() -> bytes:
    """Hand-built go1.16-family table (magic 0xfffffffa; absolute entry PCs)."""
    funcnames, name_off = _funcname_parts()
    cutab = struct.pack("<I", 1)
    filetab = b"\x00" + SOURCE_FILE.encode() + b"\x00"
    pctab = _pctab_parts()
    header_size = 8 + 7 * 8
    parts = [funcnames, cutab, filetab, pctab]
    positions = []
    cursor = header_size
    for part in parts:
        positions.append(cursor)
        cursor += len(part)
    funcname_off, cu_off, filetab_off, pctab_off = positions
    pcln_off = cursor
    nfunc = len(FUNC_LIST)
    functab_size = (2 * nfunc + 1) * 8

    ftab = b""
    rows = b""
    for index, (name, entryoff) in enumerate(FUNC_LIST):
        entry_va = TEXT_VA + entryoff
        # _func: entry uintptr, nameOff i32, then six i32/u32 fields = 40 bytes.
        rows += struct.pack(
            "<QiiIIIIII",
            entry_va,
            name_off[name],
            0,
            0,
            0,
            2,
            4,
            0,
            0,
        )
        ftab += struct.pack("<QQ", entry_va, functab_size + index * 40)
    sentinel = TEXT_VA + FUNC_LIST[-1][1] + ENTRY_SPAN
    ftab += struct.pack("<Q", sentinel)

    header = struct.pack(
        "<IBBBB7Q",
        MAGIC_GO116,
        0,
        0,
        1,
        8,
        nfunc,
        1,
        funcname_off,
        cu_off,
        filetab_off,
        pctab_off,
        pcln_off,
    )
    return header + b"".join(parts) + ftab + rows


def _build_tab_go12() -> bytes:
    """Hand-built go1.2-family table (magic 0xfffffffb; funcoff/nameoff blob-relative)."""
    ptr = 8
    nfunc = len(FUNC_LIST)
    header = struct.pack("<IBBBBQ", MAGIC_GO12, 0, 0, 1, ptr, nfunc)
    functab_size = (2 * nfunc + 1) * ptr
    rows_size = nfunc * 40
    names_base = len(header) + functab_size + rows_size
    names = bytearray()
    name_off: dict[str, int] = {}
    for name, _ in FUNC_LIST:
        name_off[name] = names_base + len(names)
        names += name.encode() + b"\x00"

    ftab = b""
    rows = b""
    for index, (name, entryoff) in enumerate(FUNC_LIST):
        entry_va = TEXT_VA + entryoff
        rows += struct.pack("<QiiIIIIII", entry_va, name_off[name], 0, 0, 0, 0, 0, 0, 0)
        ftab += struct.pack("<QQ", entry_va, len(header) + functab_size + index * 40)
    sentinel = TEXT_VA + FUNC_LIST[-1][1] + ENTRY_SPAN
    ftab += struct.pack("<Q", sentinel)
    return header + ftab + rows + bytes(names)


# ---- header decode unit tests (exact byte strings) ---------------------------------


def test_decode_header_go118_exact_bytes() -> None:
    data = struct.pack(
        "<IBBBB8Q",
        MAGIC_GO118,
        0,
        0,
        1,
        8,
        2,
        1,
        0x401000,
        72,
        101,
        105,
        120,
        124,
    )
    header = decode_pclntab_header(data)
    assert header is not None
    assert header.magic == MAGIC_GO118
    assert header.min_lc == 1
    assert header.ptr_size == 8
    assert header.little_endian is True
    assert header.nfunc == 2
    assert header.nfiles == 1
    assert header.text_start == 0x401000
    assert header.funcname_offset == 72
    assert header.cu_offset == 101
    assert header.filetab_offset == 105
    assert header.pctab_offset == 120
    assert header.pcln_offset == 124
    assert header.layout == "go1.18"
    assert header.header_size == 72
    assert header.entry_field_size == 4


def test_decode_header_go120_shares_go118_structure() -> None:
    # ptrSize 4: every header word is 4 bytes, header is 8 + 8*4 = 40 bytes.
    data = struct.pack(
        "<IBBBB8I",
        MAGIC_GO120,
        0,
        0,
        2,
        4,
        3,
        4,
        0x1000,
        40,
        48,
        52,
        60,
        64,
    )
    header = decode_pclntab_header(data)
    assert header is not None
    assert header.magic == MAGIC_GO120
    assert header.ptr_size == 4
    assert header.min_lc == 2
    assert header.nfunc == 3
    assert header.text_start == 0x1000
    assert header.header_size == 8 + 8 * 4
    assert header.entry_field_size == 4
    assert header.layout == "go1.20"


def test_decode_header_go116_exact_bytes() -> None:
    data = struct.pack(
        "<IBBBB7Q",
        MAGIC_GO116,
        0,
        0,
        1,
        8,
        2,
        1,
        64,
        93,
        97,
        112,
        120,
    )
    header = decode_pclntab_header(data)
    assert header is not None
    assert header.magic == MAGIC_GO116
    assert header.nfunc == 2
    assert header.text_start is None  # 1.16 has no textStart
    assert header.funcname_offset == 64
    assert header.cu_offset == 93
    assert header.filetab_offset == 97
    assert header.pctab_offset == 112
    assert header.pcln_offset == 120
    assert header.layout == "go1.16"
    assert header.header_size == 8 + 7 * 8
    assert header.entry_field_size == 8


def test_decode_header_go12_exact_bytes() -> None:
    data = struct.pack("<IBBBBQ", MAGIC_GO12, 0, 0, 1, 8, 5)
    header = decode_pclntab_header(data)
    assert header is not None
    assert header.magic == MAGIC_GO12
    assert header.nfunc == 5
    assert header.pcln_offset == 16  # derived: functab starts right after the count
    assert header.funcname_offset == 0  # names are blob-relative in 1.2
    assert header.cu_offset is None
    assert header.filetab_offset is None
    assert header.pctab_offset is None
    assert header.layout == "go1.2"
    assert header.header_size == 16
    assert header.entry_field_size == 8


def test_decode_header_big_endian_magic() -> None:
    words = (2, 1, 64, 93, 97, 112, 120)
    data = struct.pack(">IBBBB", MAGIC_GO116, 0, 0, 1, 8) + struct.pack(">7Q", *words)
    header = decode_pclntab_header(data)
    assert header is not None
    assert header.little_endian is False
    assert header.nfunc == 2
    assert header.funcname_offset == 64


@pytest.mark.parametrize(
    "data",
    [
        b"",  # too short
        b"\xfb\xff\xff\xff",  # still too short
        struct.pack("<IBBBBQ", 0xFFFFFFFB, 1, 0, 1, 8, 5),  # pad1 nonzero
        struct.pack("<IBBBBQ", 0xFFFFFFFB, 0, 2, 1, 8, 5),  # pad2 nonzero
        struct.pack("<IBBBBQ", 0xFFFFFFFB, 0, 0, 3, 8, 5),  # bad minLC
        struct.pack("<IBBBBQ", 0xFFFFFFFB, 0, 0, 1, 16, 5),  # bad ptrSize
        struct.pack("<IBBBBQ", 0x12345678, 0, 0, 1, 8, 5),  # unknown magic
        struct.pack("<IBBBB", MAGIC_GO118, 0, 0, 1, 8),  # header truncated
    ],
)
def test_decode_header_rejects_malformed(data: bytes) -> None:
    assert decode_pclntab_header(data) is None


# ---- recovery happy paths ------------------------------------------------------------


def test_recover_go118_from_named_section(tmp_path: Path) -> None:
    binary = _elf_with_gopclntab(tmp_path, _build_tab_go118())
    report = recover_go_symbols(binary)
    assert report.go_version_guess == "1.18"
    assert report.function_count == 2
    assert report.truncated is False
    assert report.ptr_size == 8
    assert report.endianness == "little"
    assert report.pclntab is not None
    assert report.pclntab.found_by == "section"
    assert report.pclntab.section_name == ".gopclntab"
    assert report.pclntab.va == PCLNTAB_VA
    assert report.pclntab.magic == MAGIC_GO118
    assert [(f.name, f.address, f.end_address) for f in report.functions] == [
        ("main.main", TEXT_VA, TEXT_VA + ENTRY_SPAN),
        ("runtime.nanotime1", TEXT_VA + ENTRY_SPAN, TEXT_VA + 2 * ENTRY_SPAN),
    ]
    for function in report.functions:
        assert function.file == SOURCE_FILE
        assert function.line == SOURCE_LINE
    assert report.evidence is not None
    assert report.evidence.source == "go.pclntab"
    assert report.evidence.method == "pclntab_walk"
    assert report.evidence.confidence.value == "medium"


def test_recover_go116_from_named_section(tmp_path: Path) -> None:
    binary = _elf_with_gopclntab(tmp_path, _build_tab_go116())
    report = recover_go_symbols(binary)
    assert report.go_version_guess == "1.16"
    assert report.function_count == 2
    assert [(f.name, f.address) for f in report.functions] == [
        ("main.main", TEXT_VA),
        ("runtime.nanotime1", TEXT_VA + ENTRY_SPAN),
    ]
    assert all(f.file == SOURCE_FILE and f.line == SOURCE_LINE for f in report.functions)
    assert report.evidence is not None
    assert report.evidence.confidence.value == "medium"


def test_recover_go12_from_named_section(tmp_path: Path) -> None:
    binary = _elf_with_gopclntab(tmp_path, _build_tab_go12())
    report = recover_go_symbols(binary)
    assert report.go_version_guess == "1.2"
    assert report.function_count == 2
    assert [(f.name, f.address) for f in report.functions] == [
        ("main.main", TEXT_VA),
        ("runtime.nanotime1", TEXT_VA + ENTRY_SPAN),
    ]
    # The legacy layout carries no file/line plumbing; the gap is honest.
    assert all(f.file is None and f.line is None for f in report.functions)
    assert report.evidence is not None
    assert report.evidence.confidence.value == "low"


def test_recover_go120_layout_uses_same_walk(tmp_path: Path) -> None:
    tab = _build_tab_go118()
    patched = struct.pack("<I", MAGIC_GO120) + tab[4:]
    binary = _elf_with_gopclntab(tmp_path, patched)
    report = recover_go_symbols(binary)
    assert report.go_version_guess == "1.20"
    assert [f.name for f in report.functions] == ["main.main", "runtime.nanotime1"]


# ---- locate strategy -----------------------------------------------------------------


def test_magic_scan_fallback_in_unnamed_section(tmp_path: Path) -> None:
    binary = _make_elf64(
        tmp_path / "sample_go_scan.bin",
        [
            (".text", bytes.fromhex("554889e5c3"), 0x6, TEXT_VA),
            (".rodata", _build_tab_go118(), 0x2, RODATA_VA),
        ],
    )
    report = recover_go_symbols(binary)
    assert report.pclntab is not None
    assert report.pclntab.found_by == "magic-scan"
    assert report.pclntab.section_name == ".rodata"
    assert report.pclntab.va == RODATA_VA
    assert report.function_count == 2
    assert [f.name for f in report.functions] == ["main.main", "runtime.nanotime1"]


def test_find_pclntab_direct(tmp_path: Path) -> None:
    binary = _elf_with_gopclntab(tmp_path, _build_tab_go118())
    info = BinaryLoader().load(binary)
    location = find_pclntab(info, _provider(binary))
    assert location == PclntabLocation(
        va=PCLNTAB_VA,
        file_offset=0x50,
        section_name=".gopclntab",
        found_by="section",
        magic=MAGIC_GO118,
    )


# ---- negatives -------------------------------------------------------------------------


def test_binary_without_pclntab_raises_typed_error(tmp_path: Path) -> None:
    binary = _elf_with_text_only(tmp_path)
    with pytest.raises(AnalysisError, match="no gopclntab found"):
        recover_go_symbols(binary)


def test_malformed_pad_bytes_reject_candidate(tmp_path: Path) -> None:
    tab = _build_tab_go118()
    binary = _elf_with_gopclntab(tmp_path, b"\xf0\xff\xff\xff\x01\x01" + tab[6:])
    with pytest.raises(AnalysisError, match="no gopclntab found"):
        recover_go_symbols(binary)


def test_truncated_functab_rejects_candidate(tmp_path: Path) -> None:
    # Header claims 2 functions but the blob ends inside the sentinel pc,
    # so the functab (nfunc pairs + lone sentinel) no longer fits.
    tab = _build_tab_go118()
    pcln_off = struct.unpack_from("<Q", tab, 8 + 7 * 8)[0]
    functab_end = pcln_off + (2 * len(FUNC_LIST) + 1) * 4
    binary = _elf_with_gopclntab(tmp_path, tab[: functab_end - 1])
    with pytest.raises(AnalysisError, match="no gopclntab found"):
        recover_go_symbols(binary)


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="not a readable file"):
        recover_go_symbols(tmp_path / "does_not_exist.bin")


@pytest.mark.parametrize("bad", [0, -1, 1_000_001])
def test_max_functions_out_of_range(bad: int, tmp_path: Path) -> None:
    binary = _elf_with_gopclntab(tmp_path, _build_tab_go118())
    with pytest.raises(AnalysisError, match="max_functions"):
        recover_go_symbols(binary, max_functions=bad)


# ---- bounds and output shape --------------------------------------------------------------


def test_max_functions_truncates_honestly(tmp_path: Path) -> None:
    binary = _elf_with_gopclntab(tmp_path, _build_tab_go118())
    report = recover_go_symbols(binary, max_functions=1)
    assert report.function_count == 2
    assert report.truncated is True
    assert len(report.functions) == 1
    assert report.functions[0].name == "main.main"  # lowest address wins
    assert report.functions[0].address == TEXT_VA


def test_hole_marker_entry_is_skipped_with_warning(tmp_path: Path) -> None:
    tab = bytearray(_build_tab_go116())
    # First functab entry's funcoff = all-ones hole marker (u64 at pcln base + 8).
    pcln_off = struct.unpack_from("<Q", tab, 8 + 6 * 8)[0]
    struct.pack_into("<Q", tab, pcln_off + 8, 0xFFFFFFFFFFFFFFFF)
    binary = _elf_with_gopclntab(tmp_path, bytes(tab))
    report = recover_go_symbols(binary)
    assert report.function_count == 1
    assert report.functions[0].name == "runtime.nanotime1"
    assert any("skipped 1 malformed functab entries" in w for w in report.warnings)


def test_report_to_dict_is_json_safe(tmp_path: Path) -> None:
    binary = _elf_with_gopclntab(tmp_path, _build_tab_go118())
    payload = recover_go_symbols(binary).to_dict()
    encoded = json.dumps(payload)
    assert json.loads(encoded) == payload
    assert payload["functions"][0]["address"] == f"0x{TEXT_VA:x}"
    assert payload["pclntab"]["va"] == f"0x{PCLNTAB_VA:x}"
    assert payload["go_version_guess"] == "1.18"
    assert payload["functions_kept"] == 2
    assert payload["truncated"] is False


# ---- CLI ------------------------------------------------------------------------


def test_cli_gosymbols_no_tab_and_error(tmp_path: Path) -> None:
    """`codevanta gosymbols` exits 2 with the typed error when no pclntab exists."""
    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    result = runner.invoke(cli, ["gosymbols", str(_elf_with_text_only(tmp_path))])
    assert result.exit_code == 2
    assert "no gopclntab found" in result.output

    result = runner.invoke(cli, ["gosymbols", str(tmp_path / "missing.bin")])
    assert result.exit_code == 2


def test_cli_gosymbols_json_on_fixture(tmp_path: Path) -> None:
    import json as _json

    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    sample = _elf_with_gopclntab(tmp_path, _build_tab_go118())
    result = runner.invoke(cli, ["gosymbols", str(sample), "--json"])
    assert result.exit_code == 0, result.output
    payload = _json.loads(result.output)
    assert payload["function_count"] >= 1

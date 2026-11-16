"""Mach-O nlist symbol table decoder tests (lane-machosym).

All fixtures are hand-built bytes written to ``tmp_path``: a thin 64-bit
little-endian Mach-O whose only load command is ``LC_SYMTAB`` carrying
three symbols (two defined in section 1 with values, one undefined
external import). Malformed cases (truncated symtab, truncated string
table, name offset past the string table, missing ``LC_SYMTAB``, bad
magic, missing file) prove the typed
:class:`~codevanta.core.report.AnalysisError`. No real binaries, no
network.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from codevanta.analysis import macho_symbols
from codevanta.core.report import AnalysisError

CPU_TYPE_X86_64 = 0x01000007
FILE_TYPE_EXECUTABLE = 2

N_EXT = 0x01
N_SECT = 0x0E


def _nlist64(n_strx: int, n_type: int, n_sect: int, n_desc: int, n_value: int) -> bytes:
    return struct.pack("<IBBhQ", n_strx, n_type, n_sect, n_desc, n_value)


def build_macho64_symtab(
    path: Path,
    *,
    symbols: list[tuple[str, int, int, int, int]] | None = None,
    strsize: int | None = None,
) -> Path:
    """Thin 64-bit LE Mach-O: header + ``LC_SYMTAB`` + symtab + strtab.

    Each ``symbols`` entry is ``(name, n_type, n_sect, n_desc, n_value)``;
    names are laid into a string table that starts with the mandatory NUL.
    """
    if symbols is None:
        symbols = [
            ("_main", N_SECT | N_EXT, 1, 0, 0x1000),
            ("_helper", N_SECT, 1, 0, 0x1040),
            ("_printf", N_EXT, 0, 0, 0),  # undefined external import
        ]
    strtab = bytearray(b"\x00")
    entries: list[bytes] = []
    for name, n_type, n_sect, n_desc, n_value in symbols:
        entries.append(_nlist64(len(strtab), n_type, n_sect, n_desc, n_value))
        strtab += name.encode() + b"\x00"
    size = len(strtab) if strsize is None else strsize
    symoff = 32 + 24
    nsyms = len(entries)
    stroff = symoff + nsyms * 16
    symtab_cmd = struct.pack("<IIIIII", 0x2, 24, symoff, nsyms, stroff, size)
    header = struct.pack(
        "<IIIIIIIi",
        0xFEEDFACF,
        CPU_TYPE_X86_64,
        3,
        FILE_TYPE_EXECUTABLE,
        1,
        len(symtab_cmd),
        0,
        0,
    )
    path.write_bytes(header + symtab_cmd + b"".join(entries) + bytes(strtab))
    return path


# ---- tests -------------------------------------------------------------------------


def test_macho_symbols_decode(tmp_path: Path) -> None:
    target = build_macho64_symtab(tmp_path / "hello.dylib")
    summary = macho_symbols.inspect_macho_symbols(target)
    assert summary.symbol_count == 3
    assert summary.symbols_walked == 3
    assert summary.is64 is True
    assert summary.endian == "little"
    assert [entry["name"] for entry in summary.defined] == ["_main", "_helper"]
    main = summary.defined[0]
    assert main["sect"] == 1
    assert main["value"] == 0x1000
    assert main["external"] is True
    assert main["type_name"] == "section"
    helper = summary.defined[1]
    assert helper["value"] == 0x1040
    assert helper["external"] is False
    assert [entry["name"] for entry in summary.undefined] == ["_printf"]
    assert summary.undefined[0]["external"] is True
    assert summary.defined_count == 2
    assert summary.undefined_count == 1
    assert summary.defined_truncated is False
    assert summary.undefined_truncated is False
    assert summary.warnings == ()
    assert summary.evidence.source == "macho.symbols"
    assert summary.evidence.confidence.value == "high"
    assert summary.symtab_offset == 32 + 24
    assert summary.symtab_entry_size == 16
    assert summary.strtab_size == 1 + len(b"_main\x00_helper\x00_printf\x00")


def test_macho_symbols_truncated_symtab(tmp_path: Path) -> None:
    target = build_macho64_symtab(tmp_path / "cut.dylib")
    raw = bytearray(target.read_bytes())
    struct.pack_into("<I", raw, 32 + 12, 5)  # claim 5 entries: symtab runs past EOF
    target.write_bytes(bytes(raw))
    with pytest.raises(AnalysisError, match="symbol table truncated"):
        macho_symbols.inspect_macho_symbols(target)


def test_macho_symbols_truncated_strtab(tmp_path: Path) -> None:
    target = build_macho64_symtab(tmp_path / "shortstr.dylib")
    raw = bytearray(target.read_bytes())
    struct.pack_into("<I", raw, 32 + 16, 0x1000)  # stroff beyond EOF
    target.write_bytes(bytes(raw))
    with pytest.raises(AnalysisError, match="string table truncated"):
        macho_symbols.inspect_macho_symbols(target)


def test_macho_symbols_name_past_strtab(tmp_path: Path) -> None:
    target = build_macho64_symtab(tmp_path / "badstr.dylib")
    raw = bytearray(target.read_bytes())
    raw[56] = 0xFF  # first entry's n_strx -> 255: past the string table end
    target.write_bytes(bytes(raw))
    with pytest.raises(AnalysisError, match="past the end of the string table"):
        macho_symbols.inspect_macho_symbols(target)


def test_macho_symbols_missing_symtab(tmp_path: Path) -> None:
    # A thin Mach-O whose only load command is an LC_SEGMENT: no symbol table.
    segment = struct.pack("<II", 0x19, 72) + bytes(68)
    header = struct.pack(
        "<IIIIIIIi", 0xFEEDFACF, CPU_TYPE_X86_64, 3, FILE_TYPE_EXECUTABLE, 1, len(segment), 0, 0
    )
    target = tmp_path / "noseg.bin"
    target.write_bytes(header + segment)
    with pytest.raises(AnalysisError, match="no LC_SYMTAB"):
        macho_symbols.inspect_macho_symbols(target)


def test_macho_symbols_bad_magic(tmp_path: Path) -> None:
    target = tmp_path / "fat.bin"
    target.write_bytes(b"\xca\xfe\xba\xbe" + bytes(60))  # fat big-endian magic
    with pytest.raises(AnalysisError, match="not a thin Mach-O"):
        macho_symbols.inspect_macho_symbols(target)


def test_macho_symbols_missing_file(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="file not found"):
        macho_symbols.inspect_macho_symbols(tmp_path / "ghost.dylib")


def test_macho_symbols_deterministic(tmp_path: Path) -> None:
    target = build_macho64_symtab(tmp_path / "same.dylib")
    first = macho_symbols.inspect_macho_symbols(target).to_dict()
    second = macho_symbols.inspect_macho_symbols(target).to_dict()
    assert first == second


def test_macho_symbols_output_bound(tmp_path: Path) -> None:
    symbols = [
        (f"_sym_{i:04d}", N_SECT | N_EXT, 1, 0, 0x1000 + i) for i in range(300)
    ]
    target = build_macho64_symtab(tmp_path / "many.dylib", symbols=symbols)
    summary = macho_symbols.inspect_macho_symbols(target)
    assert summary.symbol_count == 300
    assert summary.defined_count == 300
    assert len(summary.defined) == 256
    assert summary.defined_truncated is True

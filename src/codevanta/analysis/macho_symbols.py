"""Pure-Python Mach-O nlist symbol table decoder (lane-machosym).

Finds ``LC_SYMTAB`` (``cmd == 0x02``) in the load-command list of a thin
Mach-O and decodes its ``nlist_64`` entries (16 bytes: ``n_strx`` u32,
``n_type`` u8, ``n_sect`` u8, ``n_desc`` s16, ``n_value`` u64) plus the
NUL-terminated names they point into the string table. The typed
:class:`MachoSymbolsSummary` carries the symtab offset/size and string-table
size straight from the command, defined symbols (``N_SECT``/``N_ABS``) with
section, value and name, undefined external symbols (imports, name only),
counts, truncation flags, warnings and HIGH-confidence evidence.

Work is bounded (first :data:`MAX_SYMBOLS` entries walked, first
:data:`KEEP_SYMBOLS` kept per list, :data:`MAX_NAME_CHARS` per name).
Malformed input raises the typed
:class:`~codevanta.core.report.AnalysisError`: bad magic, a missing
``LC_SYMTAB``, a symtab/string table that runs off the file, a name offset
past the string-table end, an oversize file, or a missing path. Nothing is
executed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.analysis.containers import MAX_FILE_BYTES
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_SOURCE",
    "KEEP_SYMBOLS",
    "LC_SYMTAB",
    "MAX_LOAD_COMMANDS",
    "MAX_NAME_CHARS",
    "MAX_SYMBOLS",
    "MachoSymbolsSummary",
    "N_ABS",
    "N_EXT",
    "N_PEXT",
    "N_SECT",
    "N_TYPE_MASK",
    "N_UNDF",
    "inspect_macho_symbols",
    "n_type_name",
]

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "macho.symbols"

#: ``LC_SYMTAB`` load command value.
LC_SYMTAB = 0x02

#: Load commands walked per file (bounded work).
MAX_LOAD_COMMANDS = 512

#: nlist entries walked per symtab (bounded work; more is a truncation flag).
MAX_SYMBOLS = 1024

#: Entries kept per output list (bounded output); the rest is truncated.
KEEP_SYMBOLS = 256

#: Characters kept from one symbol name (bounded output).
MAX_NAME_CHARS = 128

#: ``n_type`` mask for the type field (``N_TYPE``).
N_TYPE_MASK = 0x0E

#: ``n_type`` values this decoder names.
N_UNDF = 0x00
N_ABS = 0x02
N_SECT = 0x0E

#: ``n_type`` flag bits: external and private-external.
N_EXT = 0x01
N_PEXT = 0x10

#: Mach-O header magic numbers (disk order, as read little-endian).
MACHO_MAGICS: dict[int, tuple[bool, bool]] = {
    0xFEEDFACE: (False, False),  # 32-bit, little-endian
    0xCEFAEDFE: (False, True),  # 32-bit, big-endian
    0xFEEDFACF: (True, False),  # 64-bit, little-endian
    0xCFFAEDFE: (True, True),  # 64-bit, big-endian
}


def n_type_name(n_type: int) -> str:
    """Human label for one ``n_type`` byte's type field."""
    return {N_UNDF: "undefined", N_ABS: "absolute", N_SECT: "section"}.get(
        n_type & N_TYPE_MASK, f"0x{n_type & N_TYPE_MASK:x}"
    )


# ---- typed results -----------------------------------------------------------


@dataclass(frozen=True)
class MachoSymbolsSummary:
    """Deep view of one thin Mach-O's symbol table. Parse-only, bounded."""

    path: str
    is64: bool
    endian: str
    file_type: int
    symtab_offset: int
    symtab_entry_size: int
    symbol_count: int
    strtab_offset: int
    strtab_size: int
    defined: tuple[dict[str, Any], ...]
    defined_count: int
    defined_truncated: bool
    undefined: tuple[dict[str, Any], ...]
    undefined_count: int
    undefined_truncated: bool
    symbols_walked: int
    symbols_truncated: bool
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "is64": self.is64,
            "endian": self.endian,
            "file_type": self.file_type,
            "symtab_offset": self.symtab_offset,
            "symtab_entry_size": self.symtab_entry_size,
            "symbol_count": self.symbol_count,
            "strtab_offset": self.strtab_offset,
            "strtab_size": self.strtab_size,
            "defined": [dict(entry) for entry in self.defined],
            "defined_count": self.defined_count,
            "defined_truncated": self.defined_truncated,
            "undefined": [dict(entry) for entry in self.undefined],
            "undefined_count": self.undefined_count,
            "undefined_truncated": self.undefined_truncated,
            "symbols_walked": self.symbols_walked,
            "symbols_truncated": self.symbols_truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


# ---- parsing ------------------------------------------------------------------


def _u32(data: bytes, offset: int, order: str) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise AnalysisError(f"truncated Mach-O: read past EOF at 0x{offset:x}")
    return struct.unpack_from(f"{order}I", data, offset)[0]


def _symtab_command(
    data: bytes, cursor: int, index: int, order: str
) -> tuple[int, int, int, int]:
    """Read the four ``symtab_command`` payload words at ``cursor``."""
    if cursor + 24 > len(data):
        raise AnalysisError(f"LC_SYMTAB command {index} truncated before symoff")
    return (
        _u32(data, cursor + 8, order),  # symoff
        _u32(data, cursor + 12, order),  # nsyms
        _u32(data, cursor + 16, order),  # stroff
        _u32(data, cursor + 20, order),  # strsize
    )


def _find_symtab(data: bytes, *, is64: bool, order: str) -> tuple[int, int, int, int]:
    """Locate ``LC_SYMTAB``; return ``(symoff, nsyms, stroff, strsize)``."""
    ncmds = _u32(data, 16, order)
    sizeofcmds = _u32(data, 20, order)
    if ncmds > MAX_LOAD_COMMANDS:
        raise AnalysisError(f"unreasonable load-command count {ncmds}")
    cursor = 32 if is64 else 28
    command_list_end = min(cursor + sizeofcmds, len(data))
    walked = 0
    while walked < ncmds and cursor + 8 <= command_list_end:
        cmd = _u32(data, cursor, order)
        cmdsize = _u32(data, cursor + 4, order)
        if cmdsize < 8:
            raise AnalysisError(f"load command {walked} has an impossible cmdsize {cmdsize}")
        if cursor + cmdsize > command_list_end:
            raise AnalysisError(f"load command {walked} runs past the command list")
        if cmd == LC_SYMTAB:
            return _symtab_command(data, cursor, walked, order)
        walked += 1
        cursor += cmdsize
    if walked < ncmds:
        raise AnalysisError(f"load-command list truncated after {walked} of {ncmds} commands")
    raise AnalysisError("no LC_SYMTAB in this Mach-O")


def _read_symbol_name(data: bytes, strtab_offset: int, strtab_size: int, n_strx: int) -> str:
    """Read one NUL-terminated symbol name from the string table."""
    start = strtab_offset + n_strx
    if n_strx >= strtab_size or start >= len(data):
        raise AnalysisError(f"symbol name offset {n_strx} past the end of the string table")
    end = data.find(b"\x00", start, start + MAX_NAME_CHARS)
    if end == -1:
        end = min(start + MAX_NAME_CHARS, strtab_offset + strtab_size, len(data))
    return data[start:end].decode("utf-8", errors="replace")


def inspect_macho_symbols(path: str | Path) -> MachoSymbolsSummary:
    """Parse one thin Mach-O file's symbol table (pure Python, offline).

    Raises:
        AnalysisError: When the path is missing, the file is oversize, the
            magic is unknown (fat binaries included), the load-command list
            is malformed, no ``LC_SYMTAB`` exists, the symtab or string
            table runs off the file, or a name offset points past the
            string table.
    """
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {target}")
    data = target.read_bytes()
    if len(data) > MAX_FILE_BYTES:
        raise AnalysisError(f"file too large: {len(data)} bytes (limit {MAX_FILE_BYTES})")
    if len(data) < 32:
        raise AnalysisError("Mach-O header truncated")
    (magic,) = struct.unpack_from("<I", data, 0)
    spec = MACHO_MAGICS.get(magic)
    if spec is None:
        raise AnalysisError(
            f"not a thin Mach-O (magic 0x{magic:x}); fat binaries are out of scope"
        )
    is64, swapped = spec
    order = ">" if swapped else "<"
    file_type = _u32(data, 12, order)
    symoff, nsyms, stroff, strsize = _find_symtab(data, is64=is64, order=order)
    entry_size = 16  # nlist_64
    if nsyms * entry_size > 1 << 24:  # >16 Mi entries cannot fit any accepted file
        raise AnalysisError(f"unreasonable symbol count {nsyms} (oversize symtab)")
    if symoff + nsyms * entry_size > len(data):
        raise AnalysisError(
            f"symbol table truncated: {nsyms} entries at 0x{symoff:x} run past EOF"
        )
    if stroff + strsize > len(data):
        raise AnalysisError(
            f"string table truncated: {strsize} bytes at 0x{stroff:x} run past EOF"
        )

    defined: list[dict[str, Any]] = []
    undefined: list[dict[str, Any]] = []
    warnings_list: list[str] = []
    walked = 0
    walk_target = min(nsyms, MAX_SYMBOLS)
    for index in range(walk_target):
        entry = symoff + index * entry_size
        n_strx = _u32(data, entry, order)
        n_type = data[entry + 4]
        n_sect = data[entry + 5]
        (n_desc,) = struct.unpack_from(f"{order}h", data, entry + 6)
        (n_value,) = struct.unpack_from(f"{order}Q", data, entry + 8)
        walked += 1
        name = _read_symbol_name(data, stroff, strsize, n_strx)
        kind = n_type & N_TYPE_MASK
        if kind == N_UNDF:
            undefined.append({"name": name, "external": bool(n_type & N_EXT)})
        elif kind in (N_SECT, N_ABS):
            defined.append(
                {
                    "name": name,
                    "sect": n_sect,
                    "value": n_value,
                    "type_name": n_type_name(n_type),
                    "external": bool(n_type & N_EXT),
                    "private": bool(n_type & N_PEXT),
                    "n_desc": n_desc,
                }
            )
        else:
            warnings_list.append(
                f"symbol {index} ({name!r}) has an unclassified n_type 0x{n_type:02x}; skipped"
            )
    detail = (
        f"symtab 0x{symoff:x} x{nsyms} nlist_64, strtab {strsize}B; "
        f"{len(defined)} defined, {len(undefined)} undefined"
    )
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="lc-symtab-nlist64",
        confidence=Confidence.HIGH,
        detail=detail,
        extra={"magic": f"0x{magic:x}", "cmd": f"0x{LC_SYMTAB:x}"},
    )
    return MachoSymbolsSummary(
        path=str(target),
        is64=is64,
        endian="big" if swapped else "little",
        file_type=file_type,
        symtab_offset=symoff,
        symtab_entry_size=entry_size,
        symbol_count=nsyms,
        strtab_offset=stroff,
        strtab_size=strsize,
        defined=tuple(defined[:KEEP_SYMBOLS]),
        defined_count=len(defined),
        defined_truncated=len(defined) > KEEP_SYMBOLS,
        undefined=tuple(undefined[:KEEP_SYMBOLS]),
        undefined_count=len(undefined),
        undefined_truncated=len(undefined) > KEEP_SYMBOLS,
        symbols_walked=walked,
        symbols_truncated=nsyms > MAX_SYMBOLS,
        warnings=tuple(warnings_list),
        evidence=evidence,
    )

"""Pure-Python Mach-O dylib load-command parser (lane-depth2).

Walks the Mach-O load-command list straight out of the file bytes (thin
files, 32/64-bit, little or big endian) and returns a typed
:class:`MachoDylibSummary`:

* every ``LC_LOAD_DYLIB``-family command (``LC_LOAD_DYLIB``,
  ``LC_LOAD_WEAK_DYLIB``, ``LC_REEXPORT_DYLIB``, ``LC_LOAD_UPWARD_DYLIB``,
  ``LC_LAZY_LOAD_DYLIB``) with the dylib name, timestamp,
  ``current_version`` and ``compatibility_version`` (bounded 32);
* the install-name identity from ``LC_ID_DYLIB``.

Versions are unpacked from the packed ``X.Y.Z`` dylib format. Malformed
headers, a load command shorter than 8 bytes, a ``cmdsize`` that would run
off the command list or a name offset outside the command raise the typed
:class:`~codevanta.core.report.AnalysisError`. Nothing is executed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_SOURCE",
    "LC_ID_DYLIB",
    "LC_KIND_NAMES",
    "LC_LOAD_DYLIB",
    "LC_LOAD_UPWARD_DYLIB",
    "LC_LOAD_WEAK_DYLIB",
    "LC_LAZY_LOAD_DYLIB",
    "LC_REEXPORT_DYLIB",
    "MAX_DYLIBS",
    "MachoDylibSummary",
    "inspect_macho_dylibs",
    "unpack_dylib_version",
]

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "meta.macho-dylibs"

#: dylib load commands kept (bounded work).
MAX_DYLIBS = 32

#: Load commands walked per file (bounded work).
MAX_LOAD_COMMANDS = 512

#: Characters kept from one dylib install name (bounded output).
MAX_NAME_CHARS = 512

#: ``dylib_command`` cmd values this parser reports on.
LC_LOAD_DYLIB = 0x0C
LC_ID_DYLIB = 0x0D
LC_LOAD_WEAK_DYLIB = 0x18
LC_REEXPORT_DYLIB = 0x1F
LC_LAZY_LOAD_DYLIB = 0x20
LC_LOAD_UPWARD_DYLIB = 0x25

#: Human labels for the dylib-family load commands.
LC_KIND_NAMES: dict[int, str] = {
    LC_LOAD_DYLIB: "load",
    LC_ID_DYLIB: "id",
    LC_LOAD_WEAK_DYLIB: "weak",
    LC_REEXPORT_DYLIB: "reexport",
    LC_LAZY_LOAD_DYLIB: "lazy",
    LC_LOAD_UPWARD_DYLIB: "upward",
}

#: Mach-O header magic numbers (native little-endian disk order and swapped).
MACHO_MAGICS: dict[int, tuple[bool, bool]] = {
    0xFEEDFACE: (False, False),  # 32-bit, little-endian
    0xCEFAEDFE: (False, True),  # 32-bit, big-endian
    0xFEEDFACF: (True, False),  # 64-bit, little-endian
    0xCFFAEDFE: (True, True),  # 64-bit, big-endian
}

#: Mach-O file types this summary names (MH_*).
FILE_TYPE_NAMES: dict[int, str] = {
    1: "relocatable",
    2: "executable",
    3: "fixed-vmlib",
    4: "core",
    5: "preload",
    6: "dylib",
    7: "dylinker",
    8: "bundle",
    9: "static-stub",
}


# ---- typed results -----------------------------------------------------------


@dataclass(frozen=True)
class MachoDylibSummary:
    """Deep view of one Mach-O's dylib load commands. Parse-only, bounded."""

    path: str
    is64: bool
    endian: str
    file_type: int
    file_type_name: str
    cpu_type: int
    load_command_count: int
    dylibs: tuple[dict[str, Any], ...]
    dylib_count: int
    dylibs_truncated: bool
    id_dylib: dict[str, Any] | None
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "is64": self.is64,
            "endian": self.endian,
            "file_type": self.file_type,
            "file_type_name": self.file_type_name,
            "cpu_type": f"0x{self.cpu_type:x}",
            "load_command_count": self.load_command_count,
            "dylibs": [dict(entry) for entry in self.dylibs],
            "dylib_count": self.dylib_count,
            "dylibs_truncated": self.dylib_count > MAX_DYLIBS,
            "id_dylib": dict(self.id_dylib) if self.id_dylib else None,
        }


def unpack_dylib_version(packed: int) -> str:
    """Unpack a dylib version word into its ``X.Y.Z`` decimal form."""
    return f"{packed >> 16}.{(packed >> 8) & 0xFF}.{packed & 0xFF}"


# ---- parsing ------------------------------------------------------------------


def _u32(data: bytes, offset: int, order: str) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise AnalysisError(f"truncated Mach-O: read past EOF at 0x{offset:x}")
    return struct.unpack_from(f"{order}I", data, offset)[0]


def _read_name(data: bytes, command_start: int, name_offset: int, order: str) -> str:
    """Read the NUL-terminated install name inside one dylib command."""
    start = command_start + name_offset
    if name_offset < 8 or start >= len(data):
        raise AnalysisError(f"dylib name offset {name_offset} outside its load command")
    end = data.find(b"\x00", start, start + MAX_NAME_CHARS)
    if end == -1:
        raise AnalysisError(f"unterminated dylib name at 0x{start:x}")
    return data[start:end].decode("utf-8", errors="replace")


def _dylib_record(data: bytes, command_start: int, cmdsize: int, cmd: int, order: str) -> dict[str, Any]:
    """Parse one ``dylib_command`` into its summary dict (bounds-checked)."""
    # dylib_command: lc_str(4), timestamp(4), current_version(4), compatibility_version(4)
    if command_start + 24 > len(data):
        raise AnalysisError(f"dylib command at 0x{command_start:x} truncated before its header")
    name_offset = _u32(data, command_start + 8, order)
    timestamp = _u32(data, command_start + 12, order)
    current_version = _u32(data, command_start + 16, order)
    compatibility_version = _u32(data, command_start + 20, order)
    return {
        "kind": LC_KIND_NAMES.get(cmd, f"0x{cmd:x}"),
        "name": _read_name(data, command_start, name_offset, order),
        "timestamp": timestamp,
        "current_version": unpack_dylib_version(current_version),
        "compatibility_version": unpack_dylib_version(compatibility_version),
        "cmdsize": cmdsize,
    }


def inspect_macho_dylibs(path: str | Path) -> MachoDylibSummary:
    """Parse one thin Mach-O file's dylib load commands (pure Python, offline).

    Raises:
        AnalysisError: When the file is not a Mach-O (unknown magic), is a
            fat multi-architecture binary, is truncated mid-header, or the
            load-command list is malformed.
    """
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {target}")
    data = target.read_bytes()
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
    cpu_type = _u32(data, 4, order)
    file_type = _u32(data, 12, order)
    ncmds = _u32(data, 16, order)
    sizeofcmds = _u32(data, 20, order)
    if ncmds > MAX_LOAD_COMMANDS:
        raise AnalysisError(f"unreasonable load-command count {ncmds}")
    dylibs: list[dict[str, Any]] = []
    id_dylib: dict[str, Any] | None = None
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
        if cmd == LC_ID_DYLIB:
            if id_dylib is not None:
                raise AnalysisError("duplicate LC_ID_DYLIB load command")
            id_dylib = _dylib_record(data, cursor, cmdsize, cmd, order)
        elif cmd in LC_KIND_NAMES:
            dylibs.append(_dylib_record(data, cursor, cmdsize, cmd, order))
        walked += 1
        cursor += cmdsize
    if walked < ncmds:
        raise AnalysisError(f"load-command list truncated after {walked} of {ncmds} commands")
    dylib_count = len(dylibs)
    detail = (
        f"{ncmds} load command(s); {dylib_count} dylib load(s), "
        f"id={id_dylib['name'] if id_dylib else None}"
    )
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="load-command-walk",
        confidence=Confidence.HIGH,
        detail=detail,
        extra={"magic": f"0x{magic:x}"},
    )
    return MachoDylibSummary(
        path=str(target),
        is64=is64,
        endian="big" if swapped else "little",
        file_type=file_type,
        file_type_name=FILE_TYPE_NAMES.get(file_type, f"0x{file_type:x}"),
        cpu_type=cpu_type,
        load_command_count=ncmds,
        dylibs=tuple(dylibs[:MAX_DYLIBS]),
        dylib_count=dylib_count,
        dylibs_truncated=dylib_count > MAX_DYLIBS,
        id_dylib=id_dylib,
        evidence=evidence,
    )

"""Pure-Python PE Rich header decoder (lane-rich).

Locates the undocumented ``Rich`` header between the DOS stub and the PE
signature, recovers the XOR key stored right after the ``Rich`` marker and
walks the ``@comp.id`` entry stream backwards until it decodes to the
``DanS`` marker. Each entry pair decodes to ``(product_id << 16) | build``
plus an object count; the summary reports the entries, a best-effort
compiler guess from a small table of commonly published product ids and the
total object count.

Structure follows the classic public documentation (Daniel Pistelli's
``Rich Signature`` write-up at ntcore.com): a 16-byte ``DanS`` block
(marker plus three padding DWORDs), the entry pairs, then ``Rich`` and the
key, before the PE signature. Work is bounded: the DOS-stub scan region and
the entry stream both have hard caps and oversize input is a typed error,
never a silent long scan. Unknown product ids stay honest -- the name table
is a community mapping, not ground truth.
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
    "DANS_MARKER",
    "EVIDENCE_SOURCE",
    "MAX_DOS_SCAN_BYTES",
    "MAX_ENTRIES",
    "PRODUCT_NAME_GUESSES",
    "RichEntry",
    "RichSummary",
    "inspect_rich_header",
]

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "pe.rich"

#: The decoded ``DanS`` marker (ASCII ``"DanS"``) that ends the backward walk.
DANS_MARKER = 0x536E6144

#: Entries kept in the summary (bounded work). The decoded stream may hold
#: more; that is reported as an honest truncation warning, not dropped
#: silently.
MAX_ENTRIES = 256

#: DWORD budget for the backward walk (entries plus the DanS padding).
#: Exceeding it without reaching ``DanS`` means the stream is oversize.
MAX_DECODE_DWORDS = 2 * (MAX_ENTRIES + 16)

#: DOS-stub region the ``Rich`` marker may live in (bounded work).
MAX_DOS_SCAN_BYTES = 0x10000

#: Best-effort names for commonly published product ids (the high word of an
#: entry's first DWORD). Community tables (hexacorn, GData, ntcore) agree on
#: these; every other id stays an honest ``None``.
PRODUCT_NAME_GUESSES: dict[int, str] = {
    0x0001: "Import",
    0x0002: "VC++ 5.0 (link 5.0)",
    0x0003: "CVTRES 5.0",
    0x0004: "Windows CE tools",
    0x0005: "Visual Basic 5.0",
    0x006E: "VC++ 6.0 (link 6.0)",
    0x0091: "Visual Basic 6.0",
    0x0104: "MSVC 14.x (VS2015+)",
}


# ---- typed results -----------------------------------------------------------


@dataclass(frozen=True)
class RichEntry:
    """One decoded ``@comp.id`` entry pair."""

    product_id: int
    build: int
    count: int
    name_guess: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "product_id": f"0x{self.product_id:04x}",
            "build": self.build,
            "count": self.count,
            "name_guess": self.name_guess,
        }


@dataclass(frozen=True)
class RichSummary:
    """Decoded Rich header view of one PE. Parse-only, bounded."""

    path: str
    xor_key: int
    valid: bool
    entries: tuple[RichEntry, ...]
    entries_total: int
    entries_truncated: bool
    total_object_count: int
    compiler_guess: str
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "xor_key": f"0x{self.xor_key:08x}",
            "valid": self.valid,
            "entries": [entry.to_dict() for entry in self.entries],
            "entries_total": self.entries_total,
            "entries_truncated": self.entries_truncated,
            "total_object_count": self.total_object_count,
            "compiler_guess": self.compiler_guess,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


# ---- decode -------------------------------------------------------------------


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise AnalysisError(f"truncated PE image: read past EOF at 0x{offset:x}")
    return struct.unpack_from("<I", data, offset)[0]


def _compiler_guess(entries: tuple[RichEntry, ...]) -> str:
    """Name the toolchain from the linker entry when known, honestly otherwise."""
    for entry in entries:
        if entry.product_id == 0x0104:
            # Modern link.exe encodes its tool version in the build word as
            # ``(major << 8) | minor``: build 0x0E24 is link 14.36.
            return f"MSVC 14.x link {entry.build >> 8}.{entry.build & 0xFF}"
        if entry.product_id == 0x006E:
            return "MSVC 6.0 (link 6.0)"
        if entry.product_id == 0x0002:
            return "MSVC 5.0 (link 5.0)"
    for entry in entries:
        if entry.name_guess is not None:
            return f"unknown linker, {entry.name_guess} objects present"
    return "unknown product id"


def inspect_rich_header(path: str | Path) -> RichSummary:
    """Decode one PE file's Rich header (pure Python, offline).

    Raises:
        AnalysisError: When the file is missing, has no MZ magic, carries no
            PE signature at ``e_lfanew``, has no ``Rich`` marker, its
            DOS-stub region is oversize for the bounded scan, or the XOR key
            never decodes the stream back to the ``DanS`` marker.
    """
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {target}")
    data = target.read_bytes()
    if len(data) < 0x40 or data[0:2] != b"MZ":
        raise AnalysisError("missing MZ magic")
    e_lfanew = _u32(data, 0x3C)
    if e_lfanew + 4 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise AnalysisError("PE signature not found at e_lfanew")
    if e_lfanew > MAX_DOS_SCAN_BYTES:
        raise AnalysisError(
            f"oversize Rich header scan: DOS stub region 0x{e_lfanew:x} exceeds "
            f"the {MAX_DOS_SCAN_BYTES:#x}-byte budget"
        )
    rich_off = data.find(b"Rich", 0, e_lfanew)
    if rich_off < 4:
        raise AnalysisError("no Rich header")
    key = _u32(data, rich_off + 4)

    # Walk backwards from ``Rich``: every DWORD XORs with the key and the walk
    # must end at the stored ``DanS`` marker. Anything else is a key mismatch.
    dwords: list[int] = []  # walk order: (count, id) pairs, then the padding
    dans_found = False
    pos = rich_off
    while pos >= 4:
        pos -= 4
        value = _u32(data, pos) ^ key
        if value == DANS_MARKER:
            dans_found = True
            break
        dwords.append(value)
        if len(dwords) > MAX_DECODE_DWORDS:
            break
    if not dans_found:
        if len(dwords) > MAX_DECODE_DWORDS:
            raise AnalysisError(
                f"oversize Rich header scan: more than {MAX_ENTRIES} entries before "
                "the DanS marker"
            )
        raise AnalysisError("Rich header key mismatch: decoded stream never reaches DanS")

    # The DanS block is 16 bytes: the marker plus three padding DWORDs that
    # sit between it and the first entry (walk order: they trail the list).
    if len(dwords) < 3:
        raise AnalysisError("Rich header key mismatch: DanS block truncated")
    stream = dwords[:-3]
    warnings: list[str] = []
    if len(stream) % 2:
        warnings.append("odd DWORD count in the Rich entry stream; trailing DWORD ignored")
        stream = stream[:-1]
    pairs: list[tuple[int, int, int]] = []
    for index in range(0, len(stream), 2):
        count = stream[index]
        encoded = stream[index + 1]
        pairs.append(((encoded >> 16) & 0xFFFF, encoded & 0xFFFF, count))
    pairs.reverse()  # walk order is N..1; the file order is 1..N

    entries = tuple(
        RichEntry(
            product_id=product_id,
            build=build,
            count=count,
            name_guess=PRODUCT_NAME_GUESSES.get(product_id),
        )
        for product_id, build, count in pairs
    )
    entries_total = len(entries)
    entries_truncated = entries_total > MAX_ENTRIES
    if entries_truncated:
        warnings.append(
            f"Rich entry stream holds {entries_total} entries; keeping the first "
            f"{MAX_ENTRIES}"
        )
        entries = entries[:MAX_ENTRIES]
    total_object_count = sum(entry.count for entry in entries)
    guess = _compiler_guess(entries)
    detail = (
        f"xor key 0x{key:08x}, {entries_total} @comp.id entries, "
        f"total {total_object_count} objects, guess: {guess}"
    )
    return RichSummary(
        path=str(target),
        xor_key=key,
        valid=True,  # always True on return: every failure path raises above
        entries=entries,
        entries_total=entries_total,
        entries_truncated=entries_truncated,
        total_object_count=total_object_count,
        compiler_guess=guess,
        warnings=tuple(warnings),
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="rich-header-xor-walk",
            confidence=Confidence.HIGH,
            detail=detail,
            extra={"xor_key": f"0x{key:08x}", "entries_total": entries_total},
        ),
    )

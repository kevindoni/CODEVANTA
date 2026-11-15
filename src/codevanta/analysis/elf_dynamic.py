"""Pure-Python ELF dynamic-section parser (lane-depth2).

Walks the ``PT_DYNAMIC`` segment (or the ``.dynamic``/``.dynstr`` section
fallback for stripped program headers) straight out of the file bytes - 32
and 64-bit, little and big endian - and returns a typed
:class:`ElfDynamicSummary`:

* ``DT_NEEDED`` library list (bounded 32, total count kept honestly);
* ``DT_RPATH`` / ``DT_RUNPATH`` / ``DT_SONAME`` strings;
* ``DT_INIT`` / ``DT_FINI`` addresses and the ``DT_INIT_ARRAY`` /
  ``DT_FINI_ARRAY`` pointer tables (bounded 8 each).

Malformed ELF headers, a truncated dynamic section, a ``DT_NEEDED`` without
``DT_STRTAB`` or an unreadable string offset raise the typed
:class:`~codevanta.core.report.AnalysisError`. Nothing is executed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_SOURCE",
    "MAX_ARRAY_ENTRIES",
    "MAX_NEEDED",
    "ElfDynamicSummary",
    "inspect_elf_dynamic",
]

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "meta.elf-dynamic"

#: ``DT_NEEDED`` names kept (bounded work).
MAX_NEEDED = 32

#: init/fini array pointers kept each (bounded work).
MAX_ARRAY_ENTRIES = 8

#: Dynamic-tag entries walked per section (bounded work).
MAX_DYN_ENTRIES = 512

#: Characters kept from one dynamic-string read (bounded output).
MAX_DYN_STRING_CHARS = 256

#: ``d_tag`` values this parser reports on.
DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28


# ---- typed results -----------------------------------------------------------


@dataclass(frozen=True)
class ElfDynamicSummary:
    """Deep view of one ELF's dynamic section. Parse-only, bounded."""

    path: str
    elf_class: str
    endian: str
    dynamic_source: str
    entries_walked: int
    needed: tuple[str, ...]
    needed_count: int
    needed_truncated: bool
    soname: str | None
    rpath: str | None
    runpath: str | None
    init_address: int | None
    fini_address: int | None
    init_array: tuple[int, ...]
    init_array_count: int
    init_array_truncated: bool
    fini_array: tuple[int, ...]
    fini_array_count: int
    fini_array_truncated: bool
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "elf_class": self.elf_class,
            "endian": self.endian,
            "dynamic_source": self.dynamic_source,
            "entries_walked": self.entries_walked,
            "needed": list(self.needed),
            "needed_count": self.needed_count,
            "needed_truncated": self.needed_truncated,
            "soname": self.soname,
            "rpath": self.rpath,
            "runpath": self.runpath,
            "init_address": self.init_address,
            "fini_address": self.fini_address,
            "init_array": [f"0x{va:x}" for va in self.init_array],
            "init_array_count": self.init_array_count,
            "init_array_truncated": self.init_array_truncated,
            "fini_array": [f"0x{va:x}" for va in self.fini_array],
            "fini_array_count": self.fini_array_count,
            "fini_array_truncated": self.fini_array_truncated,
            "warnings": list(self.warnings),
        }


# ---- ELF container walking ---------------------------------------------------


@dataclass(frozen=True)
class _ElfImage:
    """Validated ELF header facts the dynamic walker needs."""

    is64: bool
    order: str  # struct prefix "<" or ">"
    phdrs: tuple[tuple[int, int, int, int], ...]  # (type, offset, vaddr, filesz)
    sections: tuple[tuple[int, int, int, int, int], ...]  # (type, off, size, link, addr)

    @property
    def byteorder(self) -> Literal["little", "big"]:
        """``int.from_bytes``-compatible byte order for this image."""
        return "little" if self.order == "<" else "big"


def _u16(data: bytes, offset: int, order: str) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise AnalysisError(f"truncated ELF: read past EOF at 0x{offset:x}")
    return struct.unpack_from(f"{order}H", data, offset)[0]


def _u32(data: bytes, offset: int, order: str) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise AnalysisError(f"truncated ELF: read past EOF at 0x{offset:x}")
    return struct.unpack_from(f"{order}I", data, offset)[0]


def _u64(data: bytes, offset: int, order: str) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise AnalysisError(f"truncated ELF: read past EOF at 0x{offset:x}")
    return struct.unpack_from(f"{order}Q", data, offset)[0]


def _word(data: bytes, offset: int, order: str, wide: bool) -> int:
    return _u64(data, offset, order) if wide else _u32(data, offset, order)


def _parse_elf_image(data: bytes) -> _ElfImage:
    """Validate the ELF header and snapshot program + section header facts."""
    if len(data) < 52 or data[0:4] != b"\x7fELF":
        raise AnalysisError("missing ELF magic")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2):
        raise AnalysisError(f"unsupported EI_CLASS {ei_class}")
    if ei_data not in (1, 2):
        raise AnalysisError(f"unsupported EI_DATA {ei_data}")
    is64 = ei_class == 2
    order = "<" if ei_data == 1 else ">"
    e_phoff = _word(data, 32 if is64 else 28, order, is64)
    e_phentsize = _u16(data, 54 if is64 else 42, order)
    e_phnum = _u16(data, 56 if is64 else 44, order)
    e_shoff = _word(data, 40 if is64 else 32, order, is64)
    e_shentsize = _u16(data, 58 if is64 else 46, order)
    e_shnum = _u16(data, 60 if is64 else 48, order)
    phdrs: list[tuple[int, int, int, int]] = []
    for index in range(e_phnum):
        base = e_phoff + e_phentsize * index
        if is64:
            if base + 56 > len(data):
                raise AnalysisError(f"truncated program header {index}")
            p_type = _u32(data, base, order)
            p_offset = _u64(data, base + 8, order)
            p_vaddr = _u64(data, base + 16, order)
            p_filesz = _u64(data, base + 32, order)
        else:
            if base + 32 > len(data):
                raise AnalysisError(f"truncated program header {index}")
            p_type = _u32(data, base, order)
            p_offset = _u32(data, base + 4, order)
            p_vaddr = _u32(data, base + 8, order)
            p_filesz = _u32(data, base + 16, order)
        phdrs.append((p_type, p_offset, p_vaddr, p_filesz))
    sections: list[tuple[int, int, int, int, int]] = []
    for index in range(e_shnum):
        base = e_shoff + e_shentsize * index
        if is64:
            if base + 64 > len(data):
                raise AnalysisError(f"truncated section header {index}")
            sh_type = _u32(data, base + 4, order)
            sh_addr = _u64(data, base + 16, order)
            sh_offset = _u64(data, base + 24, order)
            sh_size = _u64(data, base + 32, order)
            sh_link = _u32(data, base + 40, order)
        else:
            if base + 40 > len(data):
                raise AnalysisError(f"truncated section header {index}")
            sh_type = _u32(data, base + 4, order)
            sh_addr = _u32(data, base + 12, order)
            sh_offset = _u32(data, base + 16, order)
            sh_size = _u32(data, base + 20, order)
            sh_link = _u32(data, base + 24, order)
        sections.append((sh_type, sh_offset, sh_size, sh_link, sh_addr))
    return _ElfImage(is64=is64, order=order, phdrs=tuple(phdrs), sections=tuple(sections))


def _va_to_offset(image: _ElfImage, va: int) -> int | None:
    """Map a virtual address into file bytes via ``PT_LOAD`` segments."""
    for p_type, offset, vaddr, filesz in image.phdrs:
        if p_type == 1 and vaddr <= va < vaddr + filesz:
            return offset + (va - vaddr)
    return None


# ---- dynamic-section parsing --------------------------------------------------


def _locate_dynamic(data: bytes, image: _ElfImage) -> tuple[bytes, str]:
    """Return the dynamic entry bytes plus where they came from (typed)."""
    for p_type, offset, _vaddr, filesz in image.phdrs:
        if p_type == 2:  # PT_DYNAMIC
            span = min(filesz, MAX_DYN_ENTRIES * 16)
            return data[offset : offset + span], "pt_dynamic"
    for sh_type, offset, size, _link, _addr in image.sections:
        if sh_type == 6:  # SHT_DYNAMIC
            span = min(size, MAX_DYN_ENTRIES * 16)
            return data[offset : offset + span], "sht_dynamic"
    raise AnalysisError("no PT_DYNAMIC segment or SHT_DYNAMIC section in this ELF")


def _dyn_entries(blob: bytes, image: _ElfImage) -> list[tuple[int, int]]:
    """Split the dynamic blob into ``(tag, value)`` pairs (bounded work)."""
    entry_size = 16 if image.is64 else 8
    entries: list[tuple[int, int]] = []
    for offset in range(0, len(blob) - entry_size + 1, entry_size):
        if image.is64:
            tag = struct.unpack_from(f"{image.order}Q", blob, offset)[0]
            value = struct.unpack_from(f"{image.order}Q", blob, offset + 8)[0]
        else:
            tag = struct.unpack_from(f"{image.order}I", blob, offset)[0]
            value = struct.unpack_from(f"{image.order}I", blob, offset + 4)[0]
        if tag == DT_NULL:
            break
        entries.append((tag, value))
        if len(entries) >= MAX_DYN_ENTRIES:
            break
    return entries


def _dyn_string(data: bytes, image: _ElfImage, strtab_va: int, offset: int) -> str:
    """Read one NUL-terminated string from the dynamic string table."""
    strtab_off = _va_to_offset(image, strtab_va)
    if strtab_off is None:
        raise AnalysisError(f"DT_STRTAB VA 0x{strtab_va:x} is not mapped to file bytes")
    start = strtab_off + offset
    if start >= len(data):
        raise AnalysisError(f"dynamic string offset {offset} points past EOF")
    end = data.find(b"\x00", start, start + MAX_DYN_STRING_CHARS)
    if end == -1:
        raise AnalysisError(f"unterminated dynamic string at offset {offset}")
    return data[start:end].decode("utf-8", errors="replace")


def _read_pointer_array(
    data: bytes,
    image: _ElfImage,
    array_va: int,
    count: int,
    label: str,
    warnings: list[str],
) -> tuple[int, ...]:
    """Read one init/fini pointer array (bounded 8, honest about truncation)."""
    array_off = _va_to_offset(image, array_va)
    if array_off is None:
        warnings.append(f"{label} VA 0x{array_va:x} is not mapped; entries unknown")
        return ()
    width = 8 if image.is64 else 4
    kept: list[int] = []
    truncated = False
    for index in range(count):
        if index >= MAX_ARRAY_ENTRIES:
            truncated = True
            break
        cursor = array_off + index * width
        if cursor + width > len(data):
            warnings.append(f"{label} truncated by EOF at entry {index}")
            truncated = True
            break
        kept.append(int.from_bytes(data[cursor : cursor + width], image.byteorder))
    if truncated:
        warnings.append(f"{label} kept {MAX_ARRAY_ENTRIES} of {count} entries")
    return tuple(kept[:MAX_ARRAY_ENTRIES])


def inspect_elf_dynamic(path: str | Path) -> ElfDynamicSummary:
    """Parse one ELF file's dynamic section (pure Python, offline).

    Raises:
        AnalysisError: When the file is not an ELF, is truncated mid-header,
            carries no dynamic section, references an unmapped ``DT_STRTAB``
            or an unreadable/unterminated string, or a ``DT_NEEDED`` entry
            exists without ``DT_STRTAB``.
    """
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {target}")
    data = target.read_bytes()
    image = _parse_elf_image(data)
    blob, source = _locate_dynamic(data, image)
    entries = _dyn_entries(blob, image)
    if not entries:
        raise AnalysisError("dynamic section carries no entries before DT_NULL")
    strtab_va: int | None = None
    needed_offsets: list[int] = []
    soname_offset: int | None = None
    rpath_offset: int | None = None
    runpath_offset: int | None = None
    init_address: int | None = None
    fini_address: int | None = None
    init_array_va = fini_array_va = 0
    init_array_size = fini_array_size = 0
    for tag, value in entries:
        if tag == DT_STRTAB:
            strtab_va = value
        elif tag == DT_NEEDED:
            needed_offsets.append(value)
        elif tag == DT_SONAME:
            soname_offset = value
        elif tag == DT_RPATH:
            rpath_offset = value
        elif tag == DT_RUNPATH:
            runpath_offset = value
        elif tag == DT_INIT:
            init_address = value
        elif tag == DT_FINI:
            fini_address = value
        elif tag == DT_INIT_ARRAY:
            init_array_va = value
        elif tag == DT_INIT_ARRAYSZ:
            init_array_size = value
        elif tag == DT_FINI_ARRAY:
            fini_array_va = value
        elif tag == DT_FINI_ARRAYSZ:
            fini_array_size = value
    if needed_offsets and strtab_va is None:
        raise AnalysisError("DT_NEEDED present without DT_STRTAB")

    def _string_or_none(offset: int | None) -> str | None:
        if offset is None or strtab_va is None:
            return None
        return _dyn_string(data, image, strtab_va, offset)

    warnings: list[str] = []
    init_array = _read_pointer_array(
        data, image, init_array_va, init_array_size, "DT_INIT_ARRAY", warnings
    )
    fini_array = _read_pointer_array(
        data, image, fini_array_va, fini_array_size, "DT_FINI_ARRAY", warnings
    )
    needed = tuple(_dyn_string(data, image, strtab_va or 0, off) for off in needed_offsets)
    kept_needed = needed[:MAX_NEEDED]
    detail = (
        f"{len(entries)} dynamic entries from {source}; needed={len(needed)}, "
        f"soname={'yes' if soname_offset is not None else 'no'}, "
        f"init/fini array sizes {init_array_size}/{fini_array_size}"
    )
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="dynamic-tag-walk",
        confidence=Confidence.HIGH,
        detail=detail,
        extra={"source": source},
    )
    return ElfDynamicSummary(
        path=str(target),
        elf_class="64" if image.is64 else "32",
        endian="little" if image.order == "<" else "big",
        dynamic_source=source,
        entries_walked=len(entries),
        needed=kept_needed,
        needed_count=len(needed),
        needed_truncated=len(needed) > MAX_NEEDED,
        soname=_string_or_none(soname_offset),
        rpath=_string_or_none(rpath_offset),
        runpath=_string_or_none(runpath_offset),
        init_address=init_address,
        fini_address=fini_address,
        init_array=init_array,
        init_array_count=init_array_size,
        init_array_truncated=init_array_size > MAX_ARRAY_ENTRIES,
        fini_array=fini_array,
        fini_array_count=fini_array_size,
        fini_array_truncated=fini_array_size > MAX_ARRAY_ENTRIES,
        warnings=tuple(warnings),
        evidence=evidence,
    )

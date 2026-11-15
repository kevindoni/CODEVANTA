"""Go pclntab symbol recovery for stripped Go binaries (offline, pure stdlib).

Go linkers embed a ``pclntab`` (program-counter / line-number table) in every
executable. It is *runtime data*, not debug info, so ``strip`` (and Go's own
``-ldflags "-s -w"``) leaves it behind: the table keeps every function's
package-qualified name and entry address even when ``.symtab`` is gone. This
module locates that table and walks it, recovering function names (and, for
the 1.16+ layouts, the source file and line in effect at each function's
entry PC) without executing anything.

Supported layouts (verified against Go's ``runtime/symtab.go`` and the
Mandiant GoReSym ``debug/gosym`` fork):

==================  ===========  =============================================
Magic               Go version   Structure
==================  ===========  =============================================
``0xfffffffb``      1.2-1.15     8-byte fixed header, then an ``nfunctab``
                                 word, then ``(pc, funcoff)`` uintptr pairs
                                 (absolute pc, offsets relative to the whole
                                 blob) plus one lone sentinel pc; names inline.
``0xfffffffa``      1.16-1.17    pcHeader without ``textStart``; functab pairs
                                 of uintptr ``(entry, funcoff)`` relative to
                                 ``pclnOffset``; ``nameOff`` at ``+ptrSize``.
``0xfffffff0``      1.18-1.19    pcHeader adds ``textStart``; functab pairs of
                                 u32 ``(entryoff, funcoff)`` relative to
                                 ``textStart`` / ``pclnOffset``.
``0xfffffff1``      1.20+        Same pcHeader and walk as 1.18 (see below).
==================  ===========  =============================================

go1.18 vs go1.20: Go 1.20 bumped the magic because the *trailing funcdata*
encoding changed, but ``runtime.pcHeader`` is byte-identical in field layout
and the functab/name walk is unchanged, so this engine treats the two
layouts as one structure and only differs in the reported version guess
(GoReSym makes the same call; its version map notes Go 1.21+ shares the
1.20 layout).

Guarantees:

* Nothing is executed and nothing is written; the file is only read.
* Location strategy: named sections first (``.gopclntab`` / ``__gopclntab``),
  then a bounded magic scan (64 MiB) over non-executable sections. Every
  magic candidate must pass a structural sanity check (zero pad bytes,
  sane ``nfunc``, offsets and the whole functab inside the section, and
  first entry pc < sentinel pc) before it is believed.
* A renamed or packed (e.g. UPX-compressed) table is **out of scope** -- the
  same "unpacked only" stance as GoReSym -- and reports as *not found*
  rather than as a guess.
* All work is bounded: function rows by ``max_functions``, name length by
  1024 bytes, the funcnametab read by 16 MiB and the magic scan by 64 MiB.
  Every cap that fires is reported through ``truncated`` flags or warnings,
  never silently.
* The go1.2-family walk is best-effort: it carries ``low`` confidence
  evidence because the magic spans four Go releases and the layout predates
  the pcHeader. A malformed walk degrades to a typed
  :class:`~codevanta.core.report.AnalysisError` instead of guessed symbols.

References: mandiant/GoReSym (``debug/gosym/pclntab.go``), riven-labs/unstrip,
``golang.org/s/go12symtab``, Go ``runtime/symtab.go`` (1.16 / 1.18 tags).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.core.loader import BinaryInfo, BinaryLoader, BinaryLoadError, SectionInfo
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_FUNCTIONS",
    "EVIDENCE_SOURCE",
    "GoFunction",
    "GoSymbolReport",
    "MAX_FUNCNAME_TAB_BYTES",
    "MAX_FUNCTIONS_CEILING",
    "MAX_NAME_LENGTH",
    "MAX_SCAN_BYTES",
    "MAX_WARNINGS",
    "MAGIC_GO116",
    "MAGIC_GO118",
    "MAGIC_GO12",
    "MAGIC_GO120",
    "PCLNTAB_SECTION_NAMES",
    "PcHeader",
    "PclntabLocation",
    "decode_pclntab_header",
    "find_pclntab",
    "recover_go_symbols",
]

#: go1.2-family magic (layout used unchanged through Go 1.15).
MAGIC_GO12 = 0xFFFFFFFB
#: go1.16-family magic (Go 1.16-1.17 pcHeader, no ``textStart``).
MAGIC_GO116 = 0xFFFFFFFA
#: go1.18-family magic (Go 1.18-1.19; ``textStart`` added to pcHeader).
MAGIC_GO118 = 0xFFFFFFF0
#: go1.20-family magic (Go 1.20+; same pcHeader structure as 1.18).
MAGIC_GO120 = 0xFFFFFFF1

#: Section names the locator checks before falling back to a magic scan.
PCLNTAB_SECTION_NAMES = frozenset({".gopclntab", "__gopclntab"})

#: Longest function/file name read, in bytes; longer unterminated names are
#: skipped as malformed rather than truncated.
MAX_NAME_LENGTH = 1024

#: Hard ceiling on the funcnametab slice held in memory for one walk.
MAX_FUNCNAME_TAB_BYTES = 16 * 1024 * 1024

#: Hard ceiling on the bytes searched by the magic-scan fallback (and on the
#: table blob read back for a walk).
MAX_SCAN_BYTES = 64 * 1024 * 1024

#: Largest ``nfunc`` accepted from a header, and the ceiling on
#: ``max_functions``; real Go binaries stay far below this.
MAX_FUNCTIONS_CEILING = 1_000_000

#: Default (and expected) ceiling on function rows kept in one report.
DEFAULT_MAX_FUNCTIONS = 65_536

#: Hard ceiling on warnings kept in the report.
MAX_WARNINGS = 32

#: Evidence source shared by the report; the method is ``pclntab_walk``.
EVIDENCE_SOURCE = "go.pclntab"

#: Largest pcHeader (go1.18+ layout, 8-byte pointers): 8 fixed + 8 words.
_MAX_HEADER_BYTES = 8 + 8 * 8

_KNOWN_MAGICS = frozenset({MAGIC_GO12, MAGIC_GO116, MAGIC_GO118, MAGIC_GO120})

#: magic -> (version guess, honest coverage note for the evidence record).
_VERSION_BY_MAGIC: dict[int, tuple[str, str]] = {
    MAGIC_GO12: ("1.2", "go1.2-family layout; this magic spans Go 1.2-1.15"),
    MAGIC_GO116: ("1.16", "go1.16-family layout; this magic spans Go 1.16-1.17"),
    MAGIC_GO118: ("1.18", "go1.18-family layout; this magic spans Go 1.18-1.19"),
    MAGIC_GO120: ("1.20", "go1.20-family layout; Go 1.20+ (GoReSym: 1.21+ shares it)"),
}

#: All-ones funcoff values used by the linker to mark functab holes.
_ALL_ONES = {4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}

#: (byte pattern, magic) for every magic in both byte orders; the magic is
#: stored native-endian, so either order can appear in a file.
_MAGIC_PATTERNS: tuple[tuple[bytes, int], ...] = tuple(
    (magic.to_bytes(4, order), magic)
    for magic in (MAGIC_GO12, MAGIC_GO116, MAGIC_GO118, MAGIC_GO120)
    for order in ("little", "big")
)


# ---- decoded header ----------------------------------------------------------


@dataclass(frozen=True)
class PcHeader:
    """Decoded pclntab header fields for one of the supported layouts.

    Attributes:
        magic: One of the four known magics.
        min_lc: Minimum instruction size in bytes (1, 2 or 4).
        ptr_size: Pointer size in bytes (4 or 8).
        little_endian: True when the table's integers are little-endian.
        nfunc: Number of functions claimed by the header.
        nfiles: Number of file-table entries (1.16+; 0 for the 1.2 layout).
        text_start: Base for entry-PC offsets (go1.18+ only). The value is
            the link-time VA; PIE relocation is not applied, matching how
            every other static lane in this package reports addresses.
        funcname_offset: Offset of the funcnametab from the header start
            (0 for the 1.2 layout, whose names are blob-relative).
        cu_offset: Offset of the cutab (1.16+; ``None`` for 1.2).
        filetab_offset: Offset of the filetab (1.16+; ``None`` for 1.2).
        pctab_offset: Offset of the pctab (1.16+; ``None`` for 1.2).
        pcln_offset: Offset of the functab (for the 1.2 layout this is the
            derived constant ``8 + ptr_size``, where its functab begins).
    """

    magic: int
    min_lc: int
    ptr_size: int
    little_endian: bool
    nfunc: int
    nfiles: int
    text_start: int | None
    funcname_offset: int
    cu_offset: int | None
    filetab_offset: int | None
    pctab_offset: int | None
    pcln_offset: int

    @property
    def layout(self) -> str:
        """Layout family name, e.g. ``"go1.18"``."""
        return f"go{_VERSION_BY_MAGIC[self.magic][0]}"

    @property
    def header_size(self) -> int:
        """Bytes occupied by the header (including the 8 fixed bytes)."""
        if self.magic == MAGIC_GO12:
            return 8 + self.ptr_size
        words = 8 if self.magic in (MAGIC_GO118, MAGIC_GO120) else 7
        return 8 + words * self.ptr_size

    @property
    def entry_field_size(self) -> int:
        """Size in bytes of one functab field (u32 for 1.18+, else uintptr)."""
        if self.magic in (MAGIC_GO118, MAGIC_GO120):
            return 4
        return self.ptr_size

    def to_dict(self) -> dict[str, Any]:
        return {
            "magic": f"0x{self.magic:08x}",
            "layout": self.layout,
            "min_lc": self.min_lc,
            "ptr_size": self.ptr_size,
            "endianness": "little" if self.little_endian else "big",
            "nfunc": self.nfunc,
            "nfiles": self.nfiles,
            "text_start": f"0x{self.text_start:x}" if self.text_start is not None else None,
            "funcname_offset": f"0x{self.funcname_offset:x}",
            "pcln_offset": f"0x{self.pcln_offset:x}",
        }


def _read_uint(data: bytes, offset: int, size: int, little: bool) -> int | None:
    """Bounds-checked unsigned integer read; ``None`` when out of range."""
    if offset < 0 or size < 1 or offset + size > len(data):
        return None
    return int.from_bytes(data[offset : offset + size], "little" if little else "big")


def _header_words(
    word: Callable[[int], int | None],
    count: int,
) -> tuple[int, ...] | None:
    """Read ``count`` pointer-sized header words, or ``None`` if any fail."""
    values: list[int] = []
    for index in range(count):
        value = word(index)
        if value is None:
            return None
        values.append(value)
    return tuple(values)


def decode_pclntab_header(data: bytes) -> PcHeader | None:
    """Decode a pclntab header from ``data``; ``None`` when not one of ours.

    The first 8 bytes are shared by every layout: a u32 magic (either byte
    order), two zero pad bytes, ``minLC`` in {1, 2, 4} and ``ptrSize`` in
    {4, 8}. What follows is layout-specific pointer-sized words; see the
    module docstring table.
    """
    if len(data) < 16:
        return None
    if data[4] != 0 or data[5] != 0:
        return None
    if data[6] not in (1, 2, 4) or data[7] not in (4, 8):
        return None
    little = True
    magic = int.from_bytes(data[:4], "little")
    if magic not in _KNOWN_MAGICS:
        magic = int.from_bytes(data[:4], "big")
        little = False
    if magic not in _KNOWN_MAGICS:
        return None
    ptr_size = data[7]

    def word(index: int) -> int | None:
        return _read_uint(data, 8 + index * ptr_size, ptr_size, little)

    if magic == MAGIC_GO12:
        # Legacy layout: the only header field is the functab entry count,
        # immediately followed by the functab itself (golang.org/s/go12symtab
        # as decoded by Go's debug/gosym and GoReSym).
        nfunc = word(0)
        if nfunc is None:
            return None
        return PcHeader(
            magic=magic,
            min_lc=data[6],
            ptr_size=ptr_size,
            little_endian=little,
            nfunc=nfunc,
            nfiles=0,
            text_start=None,
            funcname_offset=0,
            cu_offset=None,
            filetab_offset=None,
            pctab_offset=None,
            pcln_offset=8 + ptr_size,
        )
    if magic == MAGIC_GO116:
        need = 8 + 7 * ptr_size
        if len(data) < need:
            return None
        values = _header_words(word, 7)
        if values is None:
            return None
        nfunc, nfiles, funcname, cu, filetab, pctab, pcln = values
        return PcHeader(
            magic=magic,
            min_lc=data[6],
            ptr_size=ptr_size,
            little_endian=little,
            nfunc=nfunc,
            nfiles=nfiles,
            text_start=None,
            funcname_offset=funcname,
            cu_offset=cu,
            filetab_offset=filetab,
            pctab_offset=pctab,
            pcln_offset=pcln,
        )
    # go1.18 / go1.20 share this structure: nfunc, nfiles, textStart, then
    # the same four table offsets plus pclnOffset.
    need = 8 + 8 * ptr_size
    if len(data) < need:
        return None
    values = _header_words(word, 8)
    if values is None:
        return None
    nfunc, nfiles, text_start, funcname, cu, filetab, pctab, pcln = values
    return PcHeader(
        magic=magic,
        min_lc=data[6],
        ptr_size=ptr_size,
        little_endian=little,
        nfunc=nfunc,
        nfiles=nfiles,
        text_start=text_start,
        funcname_offset=funcname,
        cu_offset=cu,
        filetab_offset=filetab,
        pctab_offset=pctab,
        pcln_offset=pcln,
    )


# ---- results -----------------------------------------------------------------


@dataclass(frozen=True)
class PclntabLocation:
    """Where the pclntab was found.

    Attributes:
        va: Virtual address of the header.
        file_offset: File offset of the header.
        section_name: Section the header lives in (``.gopclntab``,
            ``__gopclntab``, or the section a magic scan hit).
        found_by: ``"section"`` (named-section hit) or ``"magic-scan"``.
        magic: The matched magic value.
    """

    va: int
    file_offset: int
    section_name: str
    found_by: str
    magic: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "va": f"0x{self.va:x}",
            "file_offset": f"0x{self.file_offset:x}",
            "section": self.section_name,
            "found_by": self.found_by,
            "magic": f"0x{self.magic:08x}",
        }


@dataclass(frozen=True)
class GoFunction:
    """One recovered function.

    Attributes:
        name: Package-qualified function name from the funcnametab.
        address: Entry virtual address (``textStart + entryoff`` for 1.18+,
            the absolute table pc for the older layouts).
        end_address: Entry of the next function -- an upper bound from the
            sorted table, not a verified end of code.
        file: Source file in effect at the entry PC (1.16+ layouts, when the
            cutab/filetab lookups succeeded; ``None`` otherwise).
        line: Line in effect at the entry PC (same conditions as ``file``).
    """

    name: str
    address: int
    end_address: int | None
    file: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "address": f"0x{self.address:x}",
            "end_address": f"0x{self.end_address:x}" if self.end_address is not None else None,
        }
        if self.file is not None:
            data["file"] = self.file
        if self.line is not None:
            data["line"] = self.line
        return data


@dataclass(frozen=True)
class GoSymbolReport:
    """Bounded symbol-recovery result for one Go binary.

    Attributes:
        path: Analysed file path.
        go_version_guess: Layout-family guess (``"1.2"``, ``"1.16"``,
            ``"1.18"``, ``"1.20"``); which Go releases each covers is stated
            in the evidence record and the module docs.
        pclntab: Where the table was found.
        functions: Rows sorted by address, bounded by ``max_functions``.
        function_count: Total valid functions the walk recovered (rows kept
            + rows cut), so truncation stays honest.
        truncated: ``True`` when ``max_functions`` cut the row set.
        ptr_size: Pointer size from the header.
        endianness: Integer byte order of the table.
        warnings: Non-fatal problems (skipped malformed entries, caps hit).
        evidence: Report-level evidence; the walk itself is real data, but
            the version/layout inference is a judgement, hence ``medium``
            (``low`` for the 1.2 family).
    """

    path: str
    go_version_guess: str
    pclntab: PclntabLocation
    functions: tuple[GoFunction, ...]
    function_count: int
    truncated: bool
    ptr_size: int
    endianness: str
    warnings: tuple[str, ...] = ()
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "go_version_guess": self.go_version_guess,
            "pclntab": self.pclntab.to_dict(),
            "ptr_size": self.ptr_size,
            "endianness": self.endianness,
            "function_count": self.function_count,
            "functions_kept": len(self.functions),
            "truncated": self.truncated,
            "functions": [function.to_dict() for function in self.functions],
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict() if self.evidence is not None else None,
        }


# ---- bounded byte helpers -----------------------------------------------------


def _read_cstr(region: bytes, offset: int, cap: int = MAX_NAME_LENGTH) -> str | None:
    """Read one NUL-terminated string at ``offset``; ``None`` when malformed."""
    if offset < 0 or offset >= len(region):
        return None
    end = region.find(b"\0", offset, offset + cap)
    if end == -1:
        return None
    return region[offset:end].decode("utf-8", errors="replace")


def _mapped_bytes(info: BinaryInfo, section: SectionInfo) -> int:
    """Bytes of ``section`` backed by the file (mirrors BinaryInfo logic)."""
    if section.raw_size > 0:
        return section.raw_size
    if info.format == "ELF":
        return section.size
    return 0


def _is_pclntab_section(name: str) -> bool:
    """True for the canonical section names (Mach-O fullname forms included)."""
    return (
        name in PCLNTAB_SECTION_NAMES
        or name.endswith(".__gopclntab")
        or name.endswith(",__gopclntab")
    )


# ---- candidate validation ------------------------------------------------------


def _structurally_valid(
    header: PcHeader,
    read_at: Callable[[int, int], bytes],
    available: int,
) -> bool:
    """Sanity-check a decoded header against the bytes actually available.

    Checks: the header fits, ``nfunc`` is plausible, every table offset lands
    inside the blob, the whole functab (nfunc pairs plus the lone sentinel
    pc) fits, and the first entry pc sorts strictly below the sentinel pc
    (minPC < maxPC). This is what separates a real table from a magic value
    that happens to appear in data.
    """
    if header.nfunc < 1 or header.nfunc > MAX_FUNCTIONS_CEILING:
        return False
    if header.header_size > available:
        return False
    field = header.entry_field_size
    functab_end = header.pcln_offset + (2 * header.nfunc + 1) * field
    if functab_end > available:
        return False
    if header.magic != MAGIC_GO12:
        if not header.header_size <= header.funcname_offset < available:
            return False
        for offset in (header.cu_offset, header.filetab_offset, header.pctab_offset):
            if offset is not None and not 0 <= offset < available:
                return False
    first = _read_uint(read_at(header.pcln_offset, field), 0, field, header.little_endian)
    sentinel = _read_uint(
        read_at(header.pcln_offset + 2 * header.nfunc * field, field),
        0,
        field,
        header.little_endian,
    )
    if first is None or sentinel is None or first >= sentinel:
        return False
    return True


def _validate_candidate(
    section: SectionInfo,
    data_provider: Callable[[int, int], bytes],
    header_offset: int,
    available: int,
    found_by: str,
    magic: int,
) -> PclntabLocation | None:
    """Turn a magic hit into a location, or ``None`` when it fails checks."""

    def read_at(relative: int, size: int) -> bytes:
        return data_provider(header_offset + relative, size)

    header = decode_pclntab_header(data_provider(header_offset, _MAX_HEADER_BYTES))
    if header is None or header.magic != magic:
        return None
    if not _structurally_valid(header, read_at, available):
        return None
    return PclntabLocation(
        va=section.virtual_address + (header_offset - section.offset),
        file_offset=header_offset,
        section_name=section.name,
        found_by=found_by,
        magic=magic,
    )


def _find_in_section(
    section: SectionInfo,
    mapped: int,
    data_provider: Callable[[int, int], bytes],
    found_by: str,
    budget: int,
) -> PclntabLocation | None:
    """Search ``budget`` bytes of one section for a valid pclntab header."""
    if budget <= 0 or section.offset < 0:
        return None
    data = data_provider(section.offset, min(budget, mapped))
    for pattern, magic in _MAGIC_PATTERNS:
        start = 0
        while True:
            index = data.find(pattern, start)
            if index == -1:
                break
            start = index + 1
            location = _validate_candidate(
                section,
                data_provider,
                section.offset + index,
                mapped - index,
                found_by,
                magic,
            )
            if location is not None:
                return location
    return None


def find_pclntab(
    info: BinaryInfo,
    data_provider: Callable[[int, int], bytes],
) -> PclntabLocation | None:
    """Locate a pclntab in a loaded binary.

    Args:
        info: Normalized binary metadata (sections drive the search).
        data_provider: Callable ``provider(file_offset, length) -> bytes``
            reading file bytes (short reads at EOF are tolerated).

    Returns:
        The first structurally valid location, or ``None``. Named sections
        (``.gopclntab`` / ``__gopclntab``) are searched first, then a
        bounded :data:`MAX_SCAN_BYTES` magic scan over non-executable
        sections. A packed or renamed table is out of scope and yields
        ``None``.
    """
    for section in info.sections:
        if not _is_pclntab_section(section.name):
            continue
        mapped = _mapped_bytes(info, section)
        if mapped <= 0:
            continue
        location = _find_in_section(
            section, mapped, data_provider, "section", min(mapped, MAX_SCAN_BYTES)
        )
        if location is not None:
            return location
    scanned = 0
    for section in sorted(info.sections, key=lambda item: item.offset):
        if section.is_executable or _is_pclntab_section(section.name):
            continue
        mapped = _mapped_bytes(info, section)
        if mapped <= 0:
            continue
        budget = min(mapped, MAX_SCAN_BYTES - scanned)
        if budget <= 0:
            break
        location = _find_in_section(section, mapped, data_provider, "magic-scan", budget)
        if location is not None:
            return location
        scanned += budget
    return None


# ---- pctab file/line plumbing (1.16+ layouts) ----------------------------------


def _first_pcvalue(blob: bytes, offset: int) -> int | None:
    """Value in effect at a function's entry PC from one pctab table.

    pctab tables are ``(zig-zag value delta, pc delta)`` varint pairs; the
    first pair's value applies at the entry PC, so only one pair is read.
    Returns the int32 value, or ``None`` when the table is absent or
    malformed (``-1`` means "no value" to the callers, as in Go's runtime).
    """
    if offset <= 0 or offset >= len(blob):
        return None
    value = 0
    shift = 0
    read = 0
    while read < 5:  # a u32 varint is at most 5 bytes
        byte = blob[offset + read]
        read += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            break
        shift += 7
    else:
        return None
    if offset + read >= len(blob):
        return None  # the pc-delta byte must exist even though unused here
    delta = (value >> 1) ^ -(value & 1)
    result = (-1 + delta) & 0xFFFFFFFF
    if result >= 0x80000000:
        result -= 0x100000000
    return result


def _entry_file_line(
    blob: bytes,
    header: PcHeader,
    row: int,
) -> tuple[str | None, int | None]:
    """Best-effort (file, line) in effect at a function's entry PC.

    Walks the pcfile/pcln varint tables one step each, maps the file number
    through the cutab into the filetab, and reads one bounded string. Every
    failure degrades to ``None`` for the missing half -- never to a guess,
    and never to a raised error.
    """
    sz0 = 4 if header.magic in (MAGIC_GO118, MAGIC_GO120) else header.ptr_size
    pctab_base = header.pctab_offset
    if pctab_base is None or row + sz0 + 32 > len(blob):
        return None, None
    pcfile = _read_uint(blob, row + sz0 + 16, 4, header.little_endian)
    pcln = _read_uint(blob, row + sz0 + 20, 4, header.little_endian)
    cu_offset = _read_uint(blob, row + sz0 + 28, 4, header.little_endian)
    line_value = _first_pcvalue(blob, pctab_base + pcln) if pcln else None
    line = line_value if line_value is not None and line_value > 0 else None
    file_number = _first_pcvalue(blob, pctab_base + pcfile) if pcfile else None
    if file_number is None or file_number < 0 or cu_offset is None:
        return None, line
    cutab_base = header.cu_offset
    filetab_base = header.filetab_offset
    if cutab_base is None or filetab_base is None:
        return None, line
    slot = cutab_base + (cu_offset + file_number) * 4
    file_offset = _read_uint(blob, slot, 4, header.little_endian)
    if file_offset is None or file_offset == 0xFFFFFFFF:
        return None, line
    name = _read_cstr(blob, filetab_base + file_offset)
    return (name if name else None), line


# ---- the walk ------------------------------------------------------------------


def _walk_functions(blob: bytes, header: PcHeader) -> tuple[list[GoFunction], int]:
    """Walk the functab and recover one :class:`GoFunction` per valid entry.

    Returns the recovered functions (unsorted) and the count of malformed
    entries skipped (bad funcoff / nameoff / name), so the caller can report
    both honestly.
    """
    little = header.little_endian
    field = header.entry_field_size
    modern = header.magic in (MAGIC_GO118, MAGIC_GO120)
    legacy = header.magic == MAGIC_GO12
    # funcoff is relative to the pcln base for the 1.16+ layouts, and to the
    # start of the whole blob for the 1.2 layout; likewise the name bases.
    funcdata_base = header.pcln_offset if not legacy else 0
    funcname_base = 0 if legacy else header.funcname_offset
    nameoff_at = 4 if modern else header.ptr_size
    text_start = header.text_start if modern else None
    funcnametab = blob[funcname_base : min(len(blob), funcname_base + MAX_FUNCNAME_TAB_BYTES)]

    functions: list[GoFunction] = []
    skipped = 0
    stride = 2 * field
    for index in range(header.nfunc):
        entry_at = header.pcln_offset + index * stride
        pc = _read_uint(blob, entry_at, field, little)
        next_pc = _read_uint(blob, entry_at + stride, field, little)
        funcoff = _read_uint(blob, entry_at + field, field, little)
        if pc is None or next_pc is None or funcoff is None or funcoff == _ALL_ONES[field]:
            skipped += 1
            continue
        row = funcdata_base + funcoff
        nameoff = _read_uint(blob, row + nameoff_at, 4, little)
        if nameoff is None or not 0 < nameoff < len(funcnametab):
            skipped += 1
            continue
        name = _read_cstr(funcnametab, nameoff)
        if not name:
            skipped += 1
            continue
        address = text_start + pc if text_start is not None else pc
        end_address = text_start + next_pc if text_start is not None else next_pc
        file_name, line = (None, None) if legacy else _entry_file_line(blob, header, row)
        functions.append(
            GoFunction(
                name=name,
                address=address,
                end_address=end_address,
                file=file_name,
                line=line,
            )
        )
    return functions, skipped


def _warn(warnings: list[str], message: str) -> None:
    """Append one warning unless the cap has been reached."""
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)


# ---- entry point ----------------------------------------------------------------


def recover_go_symbols(
    path: Path,
    *,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
) -> GoSymbolReport:
    """Recover function symbols from the pclntab of a stripped Go binary.

    Args:
        path: PE, ELF or Mach-O file to analyse (nothing is executed).
        max_functions: Ceiling on function rows kept (1..
            :data:`MAX_FUNCTIONS_CEILING`); the walk still counts the full
            table so ``function_count`` and ``truncated`` stay honest.

    Returns:
        A :class:`GoSymbolReport` with rows sorted by address.

    Raises:
        AnalysisError: ``path`` is not a readable supported binary,
            ``max_functions`` is out of range, no pclntab was found (named
            sections plus the bounded magic scan came up empty), or a table
            was located but its walk produced no valid functions.
    """
    if not 1 <= max_functions <= MAX_FUNCTIONS_CEILING:
        raise AnalysisError(f"max_functions must be between 1 and {MAX_FUNCTIONS_CEILING}")
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"not a readable file: {target}")
    try:
        info = BinaryLoader().load(target)
    except BinaryLoadError as exc:
        raise AnalysisError(f"cannot load {target}: {exc}") from exc

    with target.open("rb") as handle:

        def data_provider(offset: int, length: int) -> bytes:
            if offset < 0 or length <= 0:
                return b""
            handle.seek(offset)
            return handle.read(length)

        return _recover(target, info, data_provider, max_functions)


def _recover(
    target: Path,
    info: BinaryInfo,
    data_provider: Callable[[int, int], bytes],
    max_functions: int,
) -> GoSymbolReport:
    """Run the located table's walk and assemble the bounded report."""
    warnings: list[str] = []
    location = find_pclntab(info, data_provider)
    if location is None:
        raise AnalysisError(
            "no gopclntab found: searched sections "
            f"{sorted(PCLNTAB_SECTION_NAMES)} and a bounded "
            f"{MAX_SCAN_BYTES // (1024 * 1024)} MiB magic scan over "
            "non-executable sections; a renamed or packed "
            "(e.g. UPX-compressed) table is out of scope"
        )

    section = next(
        (
            candidate
            for candidate in info.sections
            if _mapped_bytes(info, candidate) > 0
            and candidate.offset
            <= location.file_offset
            < candidate.offset + _mapped_bytes(info, candidate)
        ),
        None,
    )
    if section is None:
        # Unreachable for locations returned by find_pclntab; kept honest.
        raise AnalysisError(f"pclntab location 0x{location.va:x} has no backing section")
    mapped = _mapped_bytes(info, section)
    available = max(0, mapped - (location.file_offset - section.offset))
    blob_budget = min(available, MAX_SCAN_BYTES)
    blob = data_provider(location.file_offset, blob_budget)
    if blob_budget < available:
        _warn(
            warnings,
            f"table blob read capped at {MAX_SCAN_BYTES // (1024 * 1024)} MiB "
            f"({available} bytes wanted)",
        )

    header = decode_pclntab_header(blob)
    if header is None or header.magic != location.magic:
        # Unreachable for locations returned by find_pclntab; kept honest.
        raise AnalysisError(f"pclntab at 0x{location.va:x} no longer decodes as a valid header")
    if header.funcname_offset + MAX_FUNCNAME_TAB_BYTES < len(blob):
        _warn(
            warnings,
            f"funcnametab read capped at {MAX_FUNCNAME_TAB_BYTES // (1024 * 1024)} MiB",
        )

    functions, skipped = _walk_functions(blob, header)
    if skipped:
        _warn(warnings, f"skipped {skipped} malformed functab entries")
    if not functions:
        raise AnalysisError(
            f"pclntab found at 0x{location.va:x} "
            f"({location.section_name}, magic 0x{location.magic:08x}) "
            "but its function table walk produced no valid entries"
        )

    functions.sort(key=lambda function: (function.address, function.name))
    total = len(functions)
    kept = functions[:max_functions]
    truncated = len(kept) < total

    version, note = _VERSION_BY_MAGIC[header.magic]
    confidence = Confidence.LOW if header.magic == MAGIC_GO12 else Confidence.MEDIUM
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="pclntab_walk",
        confidence=confidence,
        address=location.va,
        detail=(
            f"magic 0x{header.magic:08x} ({header.layout} family) found by "
            f"{location.found_by} in section {location.section_name!r}; "
            f"walked {total} functions"
        ),
        extra={
            "magic": f"0x{header.magic:08x}",
            "layout": header.layout,
            "version_note": note,
            "found_by": location.found_by,
            "nfunc": header.nfunc,
            "nfiles": header.nfiles,
            "ptr_size": header.ptr_size,
            "endianness": "little" if header.little_endian else "big",
            "text_start": f"0x{header.text_start:x}" if header.text_start is not None else None,
            "skipped_entries": skipped,
        },
    )
    return GoSymbolReport(
        path=str(target),
        go_version_guess=version,
        pclntab=location,
        functions=tuple(kept),
        function_count=total,
        truncated=truncated,
        ptr_size=header.ptr_size,
        endianness="little" if header.little_endian else "big",
        warnings=tuple(warnings),
        evidence=evidence,
    )

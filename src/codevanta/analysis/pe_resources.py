"""Pure-Python PE resource-section deep parser (lane-depth2).

Walks the resource data directory tree (type -> name -> language) straight
out of the file bytes - no lief, no external tool - and returns a typed
:class:`PeResourceSummary`:

* resource types present (bounded 16) with leaf entry records (bounded 64:
  type, name/id, language, size, RVA);
* icon/cursor counts (``RT_ICON``/``RT_CURSOR`` and their group tables);
* a shallow ``VS_VERSION_INFO`` walk (bounded key/value pairs plus the
  ``VS_FIXEDFILEINFO`` file version) - the version *resource* is parsed,
  its string values are never interpreted beyond that;
* the ``RT_MANIFEST`` payload as a bounded text preview;
* one bounded hex ``raw_preview`` per resource type.

Every bound is reported through a ``*_truncated`` flag. Malformed headers,
directories, data entries or version structures raise the typed
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
    "MAX_ENTRIES",
    "MAX_PREVIEW_BYTES",
    "MAX_TYPES",
    "MAX_VERSION_PAIRS",
    "PeResourceSummary",
    "RESOURCE_TYPE_NAMES",
    "inspect_pe_resources",
]

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "meta.pe-resources"

#: Resource types kept per summary (bounded work).
MAX_TYPES = 16

#: Leaf entries kept per summary across all types (bounded work).
MAX_ENTRIES = 64

#: ``VS_VERSION_INFO`` key/value pairs kept (bounded work).
MAX_VERSION_PAIRS = 32

#: Bytes shown in one ``raw_preview`` hex blob (bounded output).
MAX_PREVIEW_BYTES = 16

#: Manifest text kept in the summary (bounded output).
MAX_MANIFEST_CHARS = 256

#: Directories walked across the whole tree (bounded work).
MAX_DIRECTORIES = 64

#: Names for the well-known predefined resource type ids (winnt.h).
RESOURCE_TYPE_NAMES: dict[int, str] = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATOR",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    23: "HTML",
    24: "MANIFEST",
}


# ---- typed results -----------------------------------------------------------


@dataclass(frozen=True)
class PeResourceSummary:
    """Deep view of one PE's resource section. Parse-only, bounded."""

    path: str
    resource_table_present: bool
    type_count: int
    types: tuple[str, ...]
    types_truncated: bool
    entry_count: int
    entries: tuple[dict[str, Any], ...]
    entries_truncated: bool
    icon_count: int
    cursor_count: int
    group_icon_count: int
    group_cursor_count: int
    version_count: int
    manifest_count: int
    manifest_preview: str | None
    version_pairs: tuple[tuple[str, str], ...]
    version_pairs_truncated: bool
    file_version: str | None
    product_version: str | None
    previews: dict[str, str]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_table_present": self.resource_table_present,
            "type_count": self.type_count,
            "types": list(self.types),
            "types_truncated": self.types_truncated,
            "entry_count": self.entry_count,
            "entries": [dict(entry) for entry in self.entries],
            "entries_truncated": self.entries_truncated,
            "icon_count": self.icon_count,
            "cursor_count": self.cursor_count,
            "group_icon_count": self.group_icon_count,
            "group_cursor_count": self.group_cursor_count,
            "version_count": self.version_count,
            "manifest_count": self.manifest_count,
            "manifest_preview": self.manifest_preview,
            "version_pairs": [list(pair) for pair in self.version_pairs],
            "version_pairs_truncated": self.version_pairs_truncated,
            "file_version": self.file_version,
            "product_version": self.product_version,
            "previews": dict(self.previews),
        }


# ---- PE header walking -------------------------------------------------------


@dataclass(frozen=True)
class _PeImage:
    """The few PE header facts the resource walker needs (validated)."""

    opt_magic: int
    machine: int
    sections: tuple[tuple[int, int, int, int], ...]  # (va, vsize, off, rawsize)
    directories: tuple[tuple[int, int], ...]  # (rva, size) per index


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise AnalysisError(f"truncated PE image: read past EOF at 0x{offset:x}")
    return struct.unpack_from("<I", data, offset)[0]


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise AnalysisError(f"truncated PE image: read past EOF at 0x{offset:x}")
    return struct.unpack_from("<H", data, offset)[0]


def _parse_pe_image(data: bytes) -> _PeImage:
    """Validate the DOS/PE/COFF/optional headers and snapshot the facts."""
    if len(data) < 0x40 or data[0:2] != b"MZ":
        raise AnalysisError("missing MZ magic")
    e_lfanew = _u32(data, 0x3C)
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise AnalysisError("PE signature not found at e_lfanew")
    machine = _u16(data, e_lfanew + 4)
    num_sections = _u16(data, e_lfanew + 6)
    opt_off = e_lfanew + 24
    opt_magic = _u16(data, opt_off)
    if opt_magic not in (0x10B, 0x20B):
        raise AnalysisError(f"unsupported optional header magic 0x{opt_magic:x}")
    opt_size = _u16(data, e_lfanew + 20)
    num_dirs_off = opt_off + (92 if opt_magic == 0x10B else 108)
    dd_off = opt_off + (96 if opt_magic == 0x10B else 112)
    if num_dirs_off + 4 > len(data):
        raise AnalysisError("truncated before the data-directory count")
    num_dirs = _u32(data, num_dirs_off)
    if num_dirs > 16:
        raise AnalysisError(f"unreasonable data-directory count {num_dirs}")
    directories: list[tuple[int, int]] = []
    for index in range(num_dirs):
        rva = _u32(data, dd_off + 8 * index)
        size = _u32(data, dd_off + 8 * index + 4)
        directories.append((rva, size))
    sec_off = opt_off + opt_size
    if sec_off + 40 * num_sections > len(data):
        raise AnalysisError("truncated section table")
    sections: list[tuple[int, int, int, int]] = []
    for index in range(num_sections):
        base = sec_off + 40 * index
        vsize = _u32(data, base + 8)
        va = _u32(data, base + 12)
        rawsize = _u32(data, base + 16)
        offset = _u32(data, base + 20)
        sections.append((va, vsize, offset, rawsize))
    return _PeImage(
        opt_magic=opt_magic,
        machine=machine,
        sections=tuple(sections),
        directories=tuple(directories),
    )


def _rva_to_offset(image: _PeImage, rva: int) -> int | None:
    """Map an RVA into file bytes via the section table. ``None`` when unmapped."""
    for va, vsize, offset, rawsize in image.sections:
        span = max(vsize, rawsize)
        if va <= rva < va + span:
            delta = rva - va
            if delta >= rawsize:
                return None  # inside the virtual tail: no file bytes exist
            return offset + delta
    return None


# ---- resource directory walk -------------------------------------------------


@dataclass(frozen=True)
class _Leaf:
    """One resource leaf: a type/name/language chain ending in a data entry."""

    type_id: int
    type_name: str
    name: str
    language: int
    data_rva: int
    size: int


def dir_base_of(field: int) -> int:
    """Strip the high bit a resource directory entry uses as a flag."""
    return field & 0x7FFFFFFF


def _type_label(type_id: int) -> str:
    return RESOURCE_TYPE_NAMES.get(type_id, f"TYPE_{type_id}")


def _dir_entry_count(data: bytes, offset: int) -> int:
    """Named + id entry count of the ``IMAGE_RESOURCE_DIRECTORY`` at ``offset``."""
    if offset + 16 > len(data):
        raise AnalysisError(f"truncated resource directory at 0x{offset:x}")
    return _u16(data, offset + 12) + _u16(data, offset + 14)


def _read_utf16_name(data: bytes, offset: int) -> str:
    """Read one length-prefixed UTF-16 resource-directory name (bounds-checked)."""
    chars = _u16(data, offset)
    byte_len = 2 * chars
    if chars > 512 or offset + 2 + byte_len > len(data):
        raise AnalysisError(f"malformed resource name at 0x{offset:x}")
    raw = data[offset + 2 : offset + 2 + byte_len]
    return raw.decode("utf-16-le", errors="replace")


def _descend(
    data: bytes,
    root_off: int,
    offset_field: int,
    budget: dict[str, int],
    collector: list[_Leaf],
    type_id: int,
    type_name: str,
    name: str,
    language: int,
    level: int,
) -> None:
    """Follow one directory entry into its child node or its data entry."""
    if offset_field & 0x80000000:
        _walk_directory(
            data, root_off + dir_base_of(offset_field), root_off, budget, collector,
            type_id, type_name, name, language, level,
        )
        return
    # Leaf data entry (some trees skip the name or language level).
    data_off = root_off + dir_base_of(offset_field)
    collector.append(
        _Leaf(
            type_id=type_id,
            type_name=type_name,
            name=name,
            language=language,
            data_rva=_u32(data, data_off),
            size=_u32(data, data_off + 4),
        )
    )


def _walk_directory(
    data: bytes,
    dir_offset: int,
    root_off: int,
    budget: dict[str, int],
    collector: list[_Leaf],
    type_id: int,
    type_name: str,
    name: str,
    language: int,
    level: int,
) -> None:
    """Depth-first walk of one ``IMAGE_RESOURCE_DIRECTORY`` (bounded work).

    Entry semantics by ``level``: 0 = type, 1 = name, >= 2 = language.
    Sub-directory and data-entry offsets are relative to the resource root.
    """
    if budget["dirs"] <= 0:
        return
    budget["dirs"] -= 1
    count = _dir_entry_count(data, dir_offset)
    for index in range(count):
        entry = dir_offset + 16 + 8 * index
        if entry + 8 > len(data):
            raise AnalysisError(f"truncated resource directory entry at 0x{entry:x}")
        name_field = _u32(data, entry)
        offset_field = _u32(data, entry + 4)
        if name_field & 0x80000000:
            label: int | str = _read_utf16_name(data, root_off + dir_base_of(name_field))
        else:
            label = name_field
        if level == 0:
            next_id = label if isinstance(label, int) else -1
            next_type = _type_label(next_id) if isinstance(label, int) else label
            _descend(data, root_off, offset_field, budget, collector,
                     next_id, next_type, name, language, level + 1)
        elif level == 1:
            _descend(data, root_off, offset_field, budget, collector,
                     type_id, type_name, str(label), language, level + 1)
        else:
            lang = label if isinstance(label, int) else -1
            _descend(data, root_off, offset_field, budget, collector,
                     type_id, type_name, name, lang, level + 1)


# ---- shallow VS_VERSIONINFO walk ---------------------------------------------


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _version_string(blob: bytes, offset: int) -> str:
    """Read one NUL-terminated UTF-16 string (bounds-checked, bounded)."""
    chars: list[str] = []
    cursor = offset
    while cursor + 2 <= len(blob) and len(chars) < 256:
        code = struct.unpack_from("<H", blob, cursor)[0]
        if code == 0:
            return "".join(chars)
        chars.append(chr(code))
        cursor += 2
    raise AnalysisError(f"malformed version-info string at 0x{offset:x}")


def _version_pairs_from_string_table(
    blob: bytes, start: int, end: int, pairs: list[tuple[str, str]]
) -> None:
    """Collect the bounded key/value pairs of one ``StringTable`` block."""
    cursor = start
    while cursor + 6 <= end and len(pairs) < MAX_VERSION_PAIRS + 1:
        w_length = struct.unpack_from("<H", blob, cursor)[0]
        w_value_length = struct.unpack_from("<H", blob, cursor + 2)[0]
        w_type = struct.unpack_from("<H", blob, cursor + 4)[0]
        if w_length < 6 or cursor + w_length > len(blob):
            raise AnalysisError("malformed String block (impossible wLength)")
        key = _version_string(blob, cursor + 6)
        if w_value_length == 0 or w_type != 1:
            cursor = _align4(cursor + w_length)
            continue
        value_chars = w_value_length - 1  # includes the terminating NUL
        value_off = _align4(cursor + 6 + 2 * (len(key) + 1))
        if value_chars < 0 or value_off + 2 * value_chars > len(blob):
            raise AnalysisError("malformed String block (value extends past EOF)")
        value = blob[value_off : value_off + 2 * value_chars].decode(
            "utf-16-le", errors="replace"
        )
        pairs.append((key, value))
        cursor = _align4(cursor + w_length)


def _walk_version_children(
    blob: bytes, start: int, end: int, pairs: list[tuple[str, str]]
) -> None:
    """Walk ``StringFileInfo``/``StringTable`` children (bounded, defensive)."""
    cursor = start
    while cursor + 6 <= end and len(pairs) < MAX_VERSION_PAIRS + 1:
        w_length = struct.unpack_from("<H", blob, cursor)[0]
        w_value_length = struct.unpack_from("<H", blob, cursor + 2)[0]
        if w_length < 6 or cursor + w_length > end:
            raise AnalysisError("malformed version-info child (impossible wLength)")
        key = _version_string(blob, cursor + 6)
        child_start = _align4(cursor + 6 + 2 * (len(key) + 1) + 2 * w_value_length)
        child_end = min(cursor + w_length, end)
        if key in ("StringFileInfo", "VarFileInfo"):
            _walk_version_children(blob, child_start, child_end, pairs)
        else:
            _version_pairs_from_string_table(blob, child_start, child_end, pairs)
        cursor = _align4(cursor + w_length)


def _parse_version_resource(
    blob: bytes,
) -> tuple[str | None, str | None, list[tuple[str, str]]]:
    """Shallow ``VS_VERSION_INFO`` walk: fixed version plus key/value pairs."""
    if len(blob) < 40:
        raise AnalysisError("version resource smaller than its fixed header")
    w_length = struct.unpack_from("<H", blob, 0)[0]
    w_value_length = struct.unpack_from("<H", blob, 2)[0]
    if w_length == 0 or w_length > len(blob):
        raise AnalysisError("malformed VS_VERSIONINFO wLength")
    key = _version_string(blob, 6)
    if key != "VS_VERSION_INFO":
        raise AnalysisError(f"unexpected version-info key {key!r}")
    file_version = product_version = None
    cursor = _align4(6 + 2 * (len(key) + 1))
    if w_value_length == 52:
        if cursor + 52 > len(blob):
            raise AnalysisError("truncated VS_FIXEDFILEINFO")
        (signature,) = struct.unpack_from("<I", blob, cursor)
        if signature != 0xFEEF04BD:
            raise AnalysisError("bad VS_FIXEDFILEINFO signature")
        ms, ls, pms, pls = struct.unpack_from("<IIII", blob, cursor + 8)
        file_version = f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
        product_version = f"{pms >> 16}.{pms & 0xFFFF}.{pls >> 16}.{pls & 0xFFFF}"
        cursor = _align4(cursor + 52)
    pairs: list[tuple[str, str]] = []
    _walk_version_children(blob, cursor, min(w_length, len(blob)), pairs)
    return file_version, product_version, pairs[:MAX_VERSION_PAIRS]


# ---- public entry point -------------------------------------------------------


def _absent_summary(target: Path) -> PeResourceSummary:
    return PeResourceSummary(
        path=str(target),
        resource_table_present=False,
        type_count=0,
        types=(),
        types_truncated=False,
        entry_count=0,
        entries=(),
        entries_truncated=False,
        icon_count=0,
        cursor_count=0,
        group_icon_count=0,
        group_cursor_count=0,
        version_count=0,
        manifest_count=0,
        manifest_preview=None,
        version_pairs=(),
        version_pairs_truncated=False,
        file_version=None,
        product_version=None,
        previews={},
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="data-directory-2-empty",
            confidence=Confidence.HIGH,
            detail="PE has an empty resource data directory",
        ),
    )


def inspect_pe_resources(path: str | Path) -> PeResourceSummary:
    """Parse one PE file's resource section (pure Python, offline).

    Raises:
        AnalysisError: When the file is not a PE, is truncated mid-header,
            carries a malformed resource directory/version structure, or a
            resource RVA cannot be mapped into the section table.
    """
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {target}")
    data = target.read_bytes()
    image = _parse_pe_image(data)
    present = len(image.directories) > 2 and image.directories[2] != (0, 0)
    if not present:
        return _absent_summary(target)
    dir_rva, _dir_size = image.directories[2]
    root_off = _rva_to_offset(image, dir_rva)
    if root_off is None:
        raise AnalysisError(
            f"resource directory RVA 0x{dir_rva:x} is not mapped to file bytes"
        )
    collector: list[_Leaf] = []
    budget = {"dirs": MAX_DIRECTORIES}
    _walk_directory(data, root_off, root_off, budget, collector, -1, "", "", -1, 0)
    if not collector:
        raise AnalysisError("resource directory carries no data entries")
    type_order: list[int] = []
    seen_types: set[int] = set()
    for leaf in collector:
        if leaf.type_id not in seen_types:
            seen_types.add(leaf.type_id)
            type_order.append(leaf.type_id)
    previews: dict[str, str] = {}
    version_blob: bytes | None = None
    manifest_blob: bytes | None = None
    for type_id in type_order[:MAX_TYPES]:
        type_name = _type_label(type_id)
        first = next(leaf for leaf in collector if leaf.type_id == type_id)
        if first.data_rva == 0 or first.size == 0:
            raise AnalysisError(f"resource data entry for {type_name} has an empty payload")
        payload_off = _rva_to_offset(image, first.data_rva)
        if payload_off is None:
            raise AnalysisError(
                f"resource payload RVA 0x{first.data_rva:x} is not mapped to file bytes"
            )
        previews[type_name] = data[payload_off : payload_off + min(first.size, MAX_PREVIEW_BYTES)].hex()
        if type_id == 16 and version_blob is None:
            version_blob = data[payload_off : payload_off + min(first.size, 1 << 16)]
        elif type_id == 24 and manifest_blob is None:
            manifest_blob = data[payload_off : payload_off + min(first.size, 1 << 16)]
    file_version = product_version = None
    version_pairs: list[tuple[str, str]] = []
    version_truncated = False
    if version_blob is not None:
        file_version, product_version, version_pairs = _parse_version_resource(version_blob)
        version_truncated = len(version_pairs) >= MAX_VERSION_PAIRS
    manifest_preview = (
        manifest_blob.decode("utf-8", errors="replace")[:MAX_MANIFEST_CHARS]
        if manifest_blob is not None
        else None
    )
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="resource-directory-walk",
        confidence=Confidence.HIGH,
        detail=(
            f"{len(type_order)} type(s), {len(collector)} leaf entrie(s), "
            f"root RVA 0x{dir_rva:x}"
        ),
        extra={"root_rva": dir_rva},
    )
    return PeResourceSummary(
        path=str(target),
        resource_table_present=True,
        type_count=len(type_order),
        types=tuple(_type_label(t) for t in type_order[:MAX_TYPES]),
        types_truncated=len(type_order) > MAX_TYPES,
        entry_count=len(collector),
        entries=tuple(
            {
                "type": leaf.type_name,
                "name": leaf.name,
                "language": leaf.language,
                "size": leaf.size,
                "rva": leaf.data_rva,
            }
            for leaf in collector[:MAX_ENTRIES]
        ),
        entries_truncated=len(collector) > MAX_ENTRIES,
        icon_count=sum(1 for leaf in collector if leaf.type_id == 3),
        cursor_count=sum(1 for leaf in collector if leaf.type_id == 1),
        group_icon_count=sum(1 for leaf in collector if leaf.type_id == 14),
        group_cursor_count=sum(1 for leaf in collector if leaf.type_id == 12),
        version_count=sum(1 for leaf in collector if leaf.type_id == 16),
        manifest_count=sum(1 for leaf in collector if leaf.type_id == 24),
        manifest_preview=manifest_preview,
        version_pairs=tuple(version_pairs),
        version_pairs_truncated=version_truncated,
        file_version=file_version,
        product_version=product_version,
        previews=previews,
        evidence=evidence,
    )

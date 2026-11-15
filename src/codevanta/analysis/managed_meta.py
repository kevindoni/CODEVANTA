"""Pure-Python .NET/CLI metadata inspector (lane-depth2).

Follows the PE ``IMAGE_DIRECTORY_ENTRY_COMDESCRIPTOR`` (CLR header) to the
``BSJB`` metadata root, splits the stream directory and shallowly walks the
``#~`` (compressed tables) and ``#Strings`` heaps. Reported in a typed
:class:`ManagedMetaSummary`:

* the TypeDef list (bounded 64) with namespace and, where resolvable, the
  base type's full name (``TypeRef``/``TypeDef`` ``Extends`` targets);
* method and field counts straight from the table row counts;
* the distinct base types (bounded 16) across all TypeDef rows.

Row sizes are computed from the ECMA-335 table schema (heap sizes, simple
and coded indexes) so the TypeDef rows can be located without parsing
every table. Uncompressed ``#-`` streams, unknown tables or malformed
root/heap structures raise the typed
:class:`~codevanta.core.report.AnalysisError`; a plain PE without a CLR
directory is simply reported as ``None`` by the caller-side detector.
No code, IL or signatures are decoded.
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
    "MAX_BASE_TYPES",
    "MAX_TYPES",
    "ManagedMetaSummary",
    "TypeRow",
    "inspect_managed_metadata",
]

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "meta.managed"

#: TypeDef rows kept in the summary (bounded work).
MAX_TYPES = 64

#: Distinct base types kept (bounded work).
MAX_BASE_TYPES = 16

#: Metadata bytes the parser ever looks at (bounded work).
MAX_METADATA_BYTES = 1 << 20

#: Heap sizes bit flags (``HeapSizes`` byte of the ``#~`` header).
_HEAP_STRINGS_WIDE = 0x01
_HEAP_GUID_WIDE = 0x02
_HEAP_BLOB_WIDE = 0x04

#: Table ids this summary reports on.
TBL_MODULE = 0x00
TBL_TYPEREF = 0x01
TBL_TYPEDEF = 0x02
TBL_FIELD = 0x04
TBL_METHODDEF = 0x06

#: Coded index groups: tag bit count and member table ids (size-relevant).
_CODED_GROUPS: dict[str, tuple[int, tuple[int, ...]]] = {
    "TypeDefOrRef": (2, (TBL_TYPEDEF, TBL_TYPEREF, 0x1B)),
    "ResolutionScope": (2, (0x00, 0x1A, 0x23, 0x26)),
    "HasConstant": (2, (TBL_FIELD, 0x08, 0x17)),
    "HasCustomAttribute": (
        5,
        (0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14,
         0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2B, 0x2C),
    ),
    "HasFieldMarshal": (1, (TBL_FIELD, 0x08)),
    "HasDeclSecurity": (2, (TBL_TYPEDEF, TBL_METHODDEF)),
    "MemberRefParent": (3, (TBL_TYPEDEF, TBL_TYPEREF, 0x1B, TBL_METHODDEF, 0x1A)),
    "HasSemantics": (1, (0x14, 0x17)),
    "MethodDefOrRef": (1, (TBL_METHODDEF, 0x0A)),
    "MemberForwarded": (1, (TBL_FIELD, TBL_METHODDEF)),
    "Implementation": (2, (0x26, 0x27, 0x23)),
    "CustomAttributeType": (5, (TBL_METHODDEF, 0x0A, 0x1B)),
    "TypeOrMethodDef": (1, (TBL_TYPEDEF, TBL_METHODDEF)),
    "HasCustomDebugInformation": (5, (0x00, 0x01, 0x02, 0x04, 0x06, 0x08, 0x09,
                                      0x0A, 0x11, 0x14, 0x17, 0x1B, 0x20, 0x23,
                                      0x26, 0x27, 0x28, 0x2A, 0x2B, 0x2C)),
}

#: Column specs per table id: 'u1'/'u2'/'u4' fixed, 's' strings heap,
#: 'g' GUID heap, 'b' blob heap, 'S<n>' simple row index into table n,
#: 'C:<group>' coded index.
_TABLE_COLUMNS: dict[int, tuple[str, ...]] = {
    0x00: ("u2", "s", "g", "g", "g"),  # Module
    0x01: ("C:ResolutionScope", "s", "s"),  # TypeRef
    0x02: ("u4", "s", "s", "C:TypeDefOrRef", "S0x04", "S0x06"),  # TypeDef
    0x03: ("S0x04",),  # FieldPtr
    0x04: ("u2", "s", "b"),  # Field
    0x05: ("S0x06",),  # MethodPtr
    0x06: ("u4", "u2", "u2", "s", "b", "S0x08"),  # MethodDef
    0x07: ("S0x08",),  # ParamPtr
    0x08: ("u2", "u2", "s"),  # Param
    0x09: ("S0x02", "C:TypeDefOrRef"),  # InterfaceImpl
    0x0A: ("C:MemberRefParent", "s", "b"),  # MemberRef
    0x0B: ("u1", "u1", "C:HasConstant", "b"),  # Constant
    0x0C: ("C:HasCustomAttribute", "C:CustomAttributeType", "b"),  # CustomAttribute
    0x0D: ("C:HasFieldMarshal", "b"),  # FieldMarshal
    0x0E: ("u2", "C:HasDeclSecurity", "b"),  # DeclSecurity
    0x0F: ("u2", "u4", "S0x02"),  # ClassLayout
    0x10: ("u4", "S0x04"),  # FieldLayout
    0x11: ("b",),  # StandAloneSig
    0x12: ("S0x02", "S0x14"),  # EventMap
    0x13: ("S0x14",),  # EventPtr
    0x14: ("u2", "s", "C:TypeDefOrRef"),  # Event
    0x15: ("S0x02", "S0x17"),  # PropertyMap
    0x16: ("S0x17",),  # PropertyPtr
    0x17: ("u2", "s", "b"),  # Property
    0x18: ("u2", "S0x06", "C:HasSemantics"),  # MethodSemantics
    0x19: ("S0x02", "C:MethodDefOrRef", "C:MethodDefOrRef"),  # MethodImpl
    0x1A: ("s",),  # ModuleRef
    0x1B: ("b",),  # TypeSpec
    0x1C: ("u2", "C:MemberForwarded", "s", "S0x1A"),  # ImplMap
    0x1D: ("u4", "S0x04"),  # FieldRVA
    0x1E: ("u4", "u4"),  # ENCLog
    0x1F: ("u4",),  # ENCMap
    0x20: ("u4", "u2", "u2", "u2", "u2", "u4", "b", "s", "s"),  # Assembly
    0x21: ("u4",),  # AssemblyProcessor
    0x22: ("u4", "u4", "u4"),  # AssemblyOS
    0x23: ("u2", "u2", "u2", "u2", "u4", "b", "s", "s", "b"),  # AssemblyRef
    0x24: ("u4", "S0x23"),  # AssemblyRefProcessor
    0x25: ("u4", "u4", "u4", "S0x23"),  # AssemblyRefOS
    0x26: ("u4", "s", "b"),  # File
    0x27: ("u4", "u4", "s", "s", "C:Implementation"),  # ExportedType
    0x28: ("u4", "u4", "s", "C:Implementation"),  # ManifestResource
    0x29: ("S0x02", "S0x02"),  # NestedClass
    0x2A: ("u2", "u2", "C:TypeOrMethodDef", "s"),  # GenericParam
    0x2B: ("C:MethodDefOrRef", "b"),  # MethodSpec
    0x2C: ("S0x2A", "C:TypeDefOrRef"),  # GenericParamConstraint
}


# ---- typed results -----------------------------------------------------------


@dataclass(frozen=True)
class TypeRow:
    """One TypeDef row's shallow view (name/namespace/base resolution)."""

    name: str
    namespace: str
    base: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "namespace": self.namespace, "base": self.base}


@dataclass(frozen=True)
class ManagedMetaSummary:
    """Deep view of one .NET assembly's metadata. Parse-only, bounded."""

    path: str
    runtime_version: str
    metadata_version: str
    metadata_rva: int
    metadata_size: int
    entry_point_token: int
    streams: tuple[str, ...]
    type_count: int
    typeref_count: int
    method_count: int
    field_count: int
    types: tuple[TypeRow, ...]
    types_truncated: bool
    base_types: tuple[str, ...]
    base_types_truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime_version": self.runtime_version,
            "metadata_version": self.metadata_version,
            "metadata_rva": self.metadata_rva,
            "metadata_size": self.metadata_size,
            "entry_point_token": f"0x{self.entry_point_token:08x}",
            "streams": list(self.streams),
            "type_count": self.type_count,
            "typeref_count": self.typeref_count,
            "method_count": self.method_count,
            "field_count": self.field_count,
            "types": [row.to_dict() for row in self.types],
            "types_truncated": self.types_truncated,
            "base_types": list(self.base_types),
            "base_types_truncated": self.base_types_truncated,
        }


# ---- PE header walking -------------------------------------------------------


@dataclass(frozen=True)
class _PeImage:
    """The few PE header facts the CLR walker needs (validated)."""

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
    directories = [(_u32(data, dd_off + 8 * i), _u32(data, dd_off + 8 * i + 4)) for i in range(num_dirs)]
    sec_off = opt_off + opt_size
    if sec_off + 40 * num_sections > len(data):
        raise AnalysisError("truncated section table")
    sections: list[tuple[int, int, int, int]] = []
    for index in range(num_sections):
        base = sec_off + 40 * index
        sections.append(
            (
                _u32(data, base + 12),
                _u32(data, base + 8),
                _u32(data, base + 20),
                _u32(data, base + 16),
            )
        )
    return _PeImage(sections=tuple(sections), directories=tuple(directories))


def _rva_to_offset(image: _PeImage, rva: int) -> int | None:
    """Map an RVA into file bytes via the section table. ``None`` when unmapped."""
    for va, vsize, offset, rawsize in image.sections:
        span = max(vsize, rawsize)
        if va <= rva < va + span:
            delta = rva - va
            if delta >= rawsize:
                return None
            return offset + delta
    return None


# ---- metadata root + streams ---------------------------------------------------


def _read_cstring(blob: bytes, offset: int) -> str:
    """Read one NUL-terminated ASCII string (bounds-checked)."""
    end = blob.find(b"\x00", offset)
    if end == -1:
        raise AnalysisError(f"unterminated metadata string at 0x{offset:x}")
    return blob[offset:end].decode("utf-8", errors="replace")


@dataclass(frozen=True)
class _Streams:
    names: tuple[str, ...]
    tables: tuple[bytes, ...]  # "#~"/"#-" payload
    strings: tuple[bytes, ...]  # "#Strings" payload


def _parse_metadata_root(blob: bytes) -> tuple[str, _Streams]:
    """Parse the BSJB root and snapshot the stream payloads (bounded)."""
    if len(blob) < 16 or blob[0:4] != b"BSJB":
        raise AnalysisError("metadata root does not carry the BSJB signature")
    major, minor = struct.unpack_from("<HH", blob, 4)
    _reserved = struct.unpack_from("<I", blob, 8)[0]
    version_len = struct.unpack_from("<I", blob, 12)[0]
    if version_len > 1024 or 16 + version_len > len(blob):
        raise AnalysisError(f"unreasonable metadata version length {version_len}")
    cursor = 16 + version_len
    if cursor + 4 > len(blob):
        raise AnalysisError("metadata root truncated before stream count")
    _flags, stream_count = struct.unpack_from("<HH", blob, cursor)
    cursor += 4
    names: list[str] = []
    payloads: dict[str, bytes] = {}
    for _ in range(stream_count):
        if cursor + 8 > len(blob):
            raise AnalysisError("metadata stream directory truncated")
        offset, size = struct.unpack_from("<II", blob, cursor)
        cursor += 8
        name = _read_cstring(blob, cursor)
        cursor += (len(name) + 1 + 3) & ~3  # NUL + 4-byte alignment
        if offset + size > len(blob):
            raise AnalysisError(f"stream {name!r} extends past the metadata root")
        names.append(name)
        payloads[name] = blob[offset : offset + size]
    if stream_count == 0:
        raise AnalysisError("metadata root carries no streams")
    tables = tuple(payloads[name] for name in ("#~", "#-") if name in payloads)
    strings = tuple(payloads[name] for name in ("#Strings",) if name in payloads)
    return f"{major}.{minor}", _Streams(tuple(names), tables, strings)


# ---- #~ tables stream ---------------------------------------------------------


@dataclass(frozen=True)
class _Tables:
    heap_sizes: int
    row_counts: dict[int, int]


def _parse_tables_header(blob: bytes) -> _Tables:
    """Parse the ``#~`` stream header: heap sizes + per-table row counts."""
    if len(blob) < 24:
        raise AnalysisError("#~ stream smaller than its fixed header")
    heap_sizes = blob[6]
    valid, _sorted = struct.unpack_from("<QQ", blob, 8)
    row_counts: dict[int, int] = {}
    cursor = 24
    for table_id in range(64):
        if not valid & (1 << table_id):
            continue
        if cursor + 4 > len(blob):
            raise AnalysisError(f"#~ row counts truncated at table 0x{table_id:02x}")
        row_counts[table_id] = struct.unpack_from("<I", blob, cursor)[0]
        cursor += 4
    tables = _Tables(heap_sizes, row_counts)
    # Fail fast on ids outside the schema instead of failing mid-walk.
    guid_size = 4 if heap_sizes & _HEAP_GUID_WIDE else 2
    blob_size = 4 if heap_sizes & _HEAP_BLOB_WIDE else 2
    for table_id in row_counts:
        _row_size(table_id, tables, guid_size, blob_size)
    return tables


def _index_size(count: int) -> int:
    """Row-index byte width for a table with ``count`` rows."""
    return 4 if count >= 0x10000 else 2


def _column_size(
    spec: str, tables: _Tables, guid_size: int, blob_size: int
) -> int:
    """Byte width of one table column per its spec string."""
    if spec == "u1":
        return 1
    if spec == "u2":
        return 2
    if spec == "u4":
        return 4
    if spec == "s":
        return 4 if tables.heap_sizes & _HEAP_STRINGS_WIDE else 2
    if spec == "g":
        return guid_size
    if spec == "b":
        return blob_size
    if spec.startswith("S0x"):
        target = int(spec[1:], 16)
        return _index_size(tables.row_counts.get(target, 0))
    if spec.startswith("C:"):
        bits, members = _CODED_GROUPS[spec[2:]]
        widest = max(tables.row_counts.get(member, 0) for member in members)
        # A coded index is 2 bytes while the widest member rid + tag fits 16 bits.
        return 2 if widest < (1 << (16 - bits)) else 4
    raise AnalysisError(f"unknown column spec {spec!r}")


def _row_size(table_id: int, tables: _Tables, guid_size: int, blob_size: int) -> int:
    """Byte width of one row of ``table_id`` per the ECMA-335 schema."""
    columns = _TABLE_COLUMNS.get(table_id)
    if columns is None:
        raise AnalysisError(f"unknown metadata table 0x{table_id:02x}")
    return sum(_column_size(spec, tables, guid_size, blob_size) for spec in columns)


def _heap_string(strings_blob: bytes, offset: int) -> str:
    """Read one NUL-terminated UTF-8 string from the ``#Strings`` heap."""
    if offset >= len(strings_blob):
        raise AnalysisError(f"#Strings offset {offset} points past the heap")
    end = strings_blob.find(b"\x00", offset)
    if end == -1:
        raise AnalysisError(f"unterminated #Strings entry at offset {offset}")
    return strings_blob[offset:end].decode("utf-8", errors="replace")


def _tables_data_offset(tables: _Tables) -> int:
    """Offset of the first table row inside the ``#~`` stream."""
    return 24 + 4 * len(tables.row_counts)


def _parse_typedef_rows(
    blob: bytes, tables: _Tables, strings_blob: bytes
) -> list[dict[str, Any]]:
    """Walk the TypeDef rows shallowly: name, namespace, Extends target."""
    row_count = tables.row_counts.get(TBL_TYPEDEF, 0)
    if row_count == 0:
        return []
    guid_size = 4 if tables.heap_sizes & _HEAP_GUID_WIDE else 2
    blob_size = 4 if tables.heap_sizes & _HEAP_BLOB_WIDE else 2
    wide = bool(tables.heap_sizes & _HEAP_STRINGS_WIDE)
    name_size = 4 if wide else 2
    extends_size = _column_size("C:TypeDefOrRef", tables, guid_size, blob_size)
    cursor = _tables_data_offset(tables)
    for table_id in sorted(tables.row_counts):
        if table_id == TBL_TYPEDEF:
            break
        cursor += _row_size(table_id, tables, guid_size, blob_size) * tables.row_counts[table_id]
    typedef_width = _row_size(TBL_TYPEDEF, tables, guid_size, blob_size)
    rows: list[dict[str, Any]] = []
    for index in range(row_count):
        base = cursor + index * typedef_width
        if base + typedef_width > len(blob):
            raise AnalysisError(f"TypeDef row {index} extends past the #~ stream")
        name_offset = (
            struct.unpack_from("<I", blob, base + 4)[0]
            if wide
            else struct.unpack_from("<H", blob, base + 4)[0]
        )
        namespace_offset = (
            struct.unpack_from("<I", blob, base + 4 + name_size)[0]
            if wide
            else struct.unpack_from("<H", blob, base + 4 + name_size)[0]
        )
        extends_raw = (
            struct.unpack_from("<I", blob, base + 4 + 2 * name_size)[0]
            if extends_size == 4
            else struct.unpack_from("<H", blob, base + 4 + 2 * name_size)[0]
        )
        rows.append(
            {
                "name": _heap_string(strings_blob, name_offset),
                "namespace": _heap_string(strings_blob, namespace_offset),
                "extends_raw": extends_raw,
            }
        )
    return rows


def _decode_extends(extends_raw: int) -> tuple[int, int]:
    """Split a TypeDefOrRef coded index into ``(table_id, rid)``."""
    bits, members = _CODED_GROUPS["TypeDefOrRef"]
    tag = extends_raw & ((1 << bits) - 1)
    rid = extends_raw >> bits
    if tag >= len(members):
        raise AnalysisError(f"TypeDefOrRef tag {tag} out of range")
    return members[tag], rid


def _parse_typeref_rows(blob: bytes, tables: _Tables, strings_blob: bytes) -> list[dict[str, Any]]:
    """Walk TypeRef rows shallowly: full names for base-type resolution."""
    row_count = tables.row_counts.get(TBL_TYPEREF, 0)
    if row_count == 0:
        return []
    guid_size = 4 if tables.heap_sizes & _HEAP_GUID_WIDE else 2
    blob_size = 4 if tables.heap_sizes & _HEAP_BLOB_WIDE else 2
    wide = bool(tables.heap_sizes & _HEAP_STRINGS_WIDE)
    name_size = 4 if wide else 2
    cursor = _tables_data_offset(tables)
    for table_id in sorted(tables.row_counts):
        if table_id == TBL_TYPEREF:
            break
        cursor += _row_size(table_id, tables, guid_size, blob_size) * tables.row_counts[table_id]
    width = _row_size(TBL_TYPEREF, tables, guid_size, blob_size)
    rows: list[dict[str, Any]] = []
    for index in range(row_count):
        base = cursor + index * width
        if base + width > len(blob):
            raise AnalysisError(f"TypeRef row {index} extends past the #~ stream")
        name_offset = (
            struct.unpack_from("<I", blob, base + 2)[0]
            if wide
            else struct.unpack_from("<H", blob, base + 2)[0]
        )
        namespace_offset = (
            struct.unpack_from("<I", blob, base + 2 + name_size)[0]
            if wide
            else struct.unpack_from("<H", blob, base + 2 + name_size)[0]
        )
        rows.append(
            {
                "name": _heap_string(strings_blob, name_offset),
                "namespace": _heap_string(strings_blob, namespace_offset),
            }
        )
    return rows


# ---- public entry point -------------------------------------------------------


def inspect_managed_metadata(path: str | Path) -> ManagedMetaSummary | None:
    """Inspect one PE file's .NET metadata (pure Python, offline).

    Returns:
        ``None`` when the file is a valid PE without a CLR data directory
        (format does not match); a typed summary otherwise.

    Raises:
        AnalysisError: When the file is not a PE, is truncated mid-header,
            the CLR header or metadata root is malformed, a stream extends
            past the root, an unknown table id appears in the ``#~`` stream,
            or the TypeDef rows cannot be located.
    """
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {target}")
    data = target.read_bytes()
    image = _parse_pe_image(data)
    if len(image.directories) <= 14:
        return None
    clr_rva, clr_size = image.directories[14]
    if clr_rva == 0 or clr_size == 0:
        return None
    clr_off = _rva_to_offset(image, clr_rva)
    if clr_off is None:
        raise AnalysisError(f"CLR header RVA 0x{clr_rva:x} is not mapped to file bytes")
    if clr_off + 72 > len(data):
        raise AnalysisError("CLR header truncated")
    cb, rt_major, rt_minor, meta_rva, meta_size, _flags, entry_token = struct.unpack_from(
        "<IHHIIII", data, clr_off
    )
    if cb < 72:
        raise AnalysisError(f"CLR header size {cb} smaller than its fixed layout")
    meta_off = _rva_to_offset(image, meta_rva)
    if meta_off is None:
        raise AnalysisError(f"metadata RVA 0x{meta_rva:x} is not mapped to file bytes")
    blob = data[meta_off : meta_off + min(meta_size, MAX_METADATA_BYTES)]
    runtime_version = f"{rt_major}.{rt_minor}"
    root_version, streams = _parse_metadata_root(blob)
    if not streams.strings:
        raise AnalysisError("metadata root carries no #Strings heap")
    if not streams.tables:
        raise AnalysisError("metadata root carries no #~/#- table stream")
    if "#-" in streams.names:
        raise AnalysisError("uncompressed #- metadata stream is out of scope for this walk")
    tables_blob = streams.tables[0]
    tables = _parse_tables_header(tables_blob)
    typedef_rows = _parse_typedef_rows(tables_blob, tables, streams.strings[0])
    typeref_rows = _parse_typeref_rows(tables_blob, tables, streams.strings[0])
    types: list[TypeRow] = []
    base_seen: list[str] = []
    base_extra = 0
    for row in typedef_rows[:MAX_TYPES]:
        table_id, rid = _decode_extends(int(row["extends_raw"]))
        base = _resolve_base(table_id, rid, typedef_rows, typeref_rows)
        if base is not None:
            if len(base_seen) < MAX_BASE_TYPES:
                if base not in base_seen:
                    base_seen.append(base)
            elif base not in base_seen:
                base_extra += 1
        types.append(TypeRow(str(row["name"]), str(row["namespace"]), base))
    detail = (
        f"CLR {runtime_version}, metadata {root_version}; "
        f"{len(typedef_rows)} TypeDef, {len(typeref_rows)} TypeRef, "
        f"{tables.row_counts.get(TBL_METHODDEF, 0)} methods, "
        f"{tables.row_counts.get(TBL_FIELD, 0)} fields"
    )
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="metadata-root-walk",
        confidence=Confidence.HIGH,
        detail=detail,
        extra={"streams": list(streams.names)},
    )
    return ManagedMetaSummary(
        path=str(target),
        runtime_version=runtime_version,
        metadata_version=root_version,
        metadata_rva=meta_rva,
        metadata_size=meta_size,
        entry_point_token=entry_token,
        streams=streams.names,
        type_count=len(typedef_rows),
        typeref_count=len(typeref_rows),
        method_count=tables.row_counts.get(TBL_METHODDEF, 0),
        field_count=tables.row_counts.get(TBL_FIELD, 0),
        types=tuple(types),
        types_truncated=len(typedef_rows) > MAX_TYPES,
        base_types=tuple(base_seen),
        base_types_truncated=base_extra > 0,
        evidence=evidence,
    )


def _resolve_base(
    table_id: int,
    rid: int,
    typedef_rows: list[dict[str, Any]],
    typeref_rows: list[dict[str, Any]],
) -> str | None:
    """Resolve one TypeDefOrRef ``Extends`` target to a full name (or ``None``)."""
    if table_id == TBL_TYPEREF and 1 <= rid <= len(typeref_rows):
        ref = typeref_rows[rid - 1]
        return f"{ref['namespace']}.{ref['name']}" if ref["namespace"] else ref["name"]
    if table_id == TBL_TYPEDEF and 1 <= rid <= len(typedef_rows):
        row = typedef_rows[rid - 1]
        return f"{row['namespace']}.{row['name']}" if row["namespace"] else row["name"]
    return None

"""Android DEX header/index-tables parser (lane-dex).

Reads the fixed 112-byte DEX header (``dex\n035\0`` .. ``dex\n039\0``),
verifies the Adler-32 checksum over everything past it, extracts the SHA-1
signature and summarises the six index tables (string/type/proto/field/
method/class ids) into a bounded, JSON-safe :class:`DexSummary`. String data
is decoded with MUTF-8 -- the DEX variant of UTF-8 that encodes ``U+0000``
as ``0xC0 0x80`` and supplementary characters as UTF-16 surrogate pairs --
via a bounded uleb128 reader.

Everything is pure ``struct`` + ``bytes`` -- nothing is executed. Bounds
(8192 ids per table, 512 kept strings of 128 chars, 256 kept classes and
methods, 64 MiB input) are reported through ``*_truncated`` flags and
warnings instead of unbounded work. Malformed inputs raise the typed
:class:`~codevanta.core.report.AnalysisError` (bad magic, truncated header
or table, oversize file); a checksum mismatch is only a warning -- headers
are parsed, not trusted.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_SOURCE",
    "MAX_CLASSES_KEEP",
    "MAX_FILE_BYTES",
    "MAX_IDS",
    "MAX_METHODS_KEEP",
    "MAX_STRING_CHARS",
    "MAX_STRINGS_KEEP",
    "SUPPORTED_VERSIONS",
    "DexSummary",
    "parse_dex",
]

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "dex.header"

#: Hard ceiling on one input file (bounded work).
MAX_FILE_BYTES = 64 * 1024 * 1024

#: Maximum index-table entries read per table (bounded work).
MAX_IDS = 8192

#: Decoded string samples kept per summary (bounded output).
MAX_STRINGS_KEEP = 512

#: Characters kept per string sample (bounded output).
MAX_STRING_CHARS = 128

#: Method samples kept per summary (bounded output).
MAX_METHODS_KEEP = 256

#: Class-descriptor samples kept per summary (bounded output).
MAX_CLASSES_KEEP = 256

#: DEX file versions this parser understands (``dex\n<version>\0``).
SUPPORTED_VERSIONS = ("035", "037", "038", "039")

#: ``dex\n`` prefix of every DEX magic.
DEX_MAGIC = b"dex\n"

#: Fixed DEX header size in bytes (0x70).
HEADER_SIZE = 112

#: ``NO_INDEX`` sentinel used by DEX indexes (superclass, source file, ...).
NO_INDEX = 0xFFFFFFFF

#: Bytes scanned per string looking for the ``0x00`` terminator (bounded).
_MAX_STRING_SCAN_BYTES = 4096

#: Index-table layout: name -> entry size in bytes.
_ENTRY_SIZES: dict[str, int] = {
    "string_ids": 4,
    "type_ids": 4,
    "proto_ids": 12,
    "field_ids": 8,
    "method_ids": 8,
    "class_defs": 32,
}

# --- 8< --- low-level readers -------------------------------------------------


def _u16(data: bytes, offset: int, section: str) -> int:
    """Read one little-endian u16, raising the typed truncated error."""
    try:
        return struct.unpack_from("<H", data, offset)[0]
    except struct.error as exc:
        raise AnalysisError(f"truncated DEX {section} table") from exc


def _u32(data: bytes, offset: int, section: str) -> int:
    """Read one little-endian u32, raising the typed truncated error."""
    try:
        return struct.unpack_from("<I", data, offset)[0]
    except struct.error as exc:
        raise AnalysisError(f"truncated DEX {section} table") from exc


def _uleb128(data: bytes, offset: int, section: str) -> tuple[int, int]:
    """Read one uleb128 value, returning ``(value, next_offset)``.

    A u32 fits in five bytes; running past the file or past that budget is
    the typed truncated error for the section the read belongs to.
    """
    value = 0
    shift = 0
    position = offset
    for _ in range(5):
        if position >= len(data):
            raise AnalysisError(f"truncated DEX {section} table")
        byte = data[position]
        position += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, position
        shift += 7
    raise AnalysisError(f"truncated DEX {section} table (malformed uleb128)")


def _decode_mutf8(raw: bytes) -> str:
    """Decode one MUTF-8 byte string (DEX string_data payload, no NUL).

    MUTF-8 differs from UTF-8 in two ways: ``U+0000`` is ``0xC0 0x80`` and
    supplementary characters are UTF-16 surrogate pairs. Truncated
    multi-byte tails decode as ``U+FFFD`` rather than raising -- string
    decoding never turns a parseable file into an error.
    """
    chars: list[str] = []
    i = 0
    n = len(raw)
    while i < n:
        b0 = raw[i]
        if b0 < 0x80:
            chars.append(chr(b0))
            i += 1
        elif b0 < 0xE0:
            b1 = raw[i + 1] if i + 1 < n else 0
            chars.append(chr(((b0 & 0x1F) << 6) | (b1 & 0x3F)))
            i += 2
        elif b0 < 0xF0:
            b1 = raw[i + 1] if i + 1 < n else 0
            b2 = raw[i + 2] if i + 2 < n else 0
            chars.append(chr(((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F)))
            i += 3
        else:
            chars.append("\ufffd")  # MUTF-8 has no 4-byte sequences
            i += 1
    # Combine UTF-16 surrogate pairs into single code points.
    out: list[str] = []
    k = 0
    while k < len(chars):
        high = chars[k]
        if (
            "\ud800" <= high <= "\udbff"
            and k + 1 < len(chars)
            and "\udc00" <= chars[k + 1] <= "\udfff"
        ):
            code_point = 0x10000 + ((ord(high) - 0xD800) << 10) + (ord(chars[k + 1]) - 0xDC00)
            out.append(chr(code_point))
            k += 2
        else:
            out.append(high)
            k += 1
    return "".join(out)


def _read_string_at(data: bytes, offset: int, warnings: list[str]) -> str | None:
    """Decode the MUTF-8 string whose ``string_data_item`` starts at ``offset``."""
    section = "string_ids"
    _utf16_size, position = _uleb128(data, offset, section)
    end = data.find(b"\x00", position, position + _MAX_STRING_SCAN_BYTES)
    if end == -1:
        warnings.append(
            f"string data at 0x{offset:x} has no terminator within "
            f"{_MAX_STRING_SCAN_BYTES} bytes; skipped"
        )
        return None
    return _decode_mutf8(data[position:end])


def _check_table(data: bytes, offset: int, count: int, section: str) -> None:
    """Raise the typed truncated error when a table extent leaves the file."""
    entry = _ENTRY_SIZES[section]
    if count and offset == 0:
        raise AnalysisError(f"truncated DEX {section} table (declared {count}, off 0)")
    if offset and offset + count * entry > len(data):
        raise AnalysisError(
            f"truncated DEX {section} table: off 0x{offset:x} + {count} x {entry} "
            f"bytes exceeds file size {len(data)}"
        )

# --- 8< --- summary model -------------------------------------------------------


@dataclass(frozen=True)
class DexSummary:
    """Bounded, JSON-safe view of one DEX file's header and index tables."""

    path: str
    version: str
    checksum: int
    adler32_ok: bool
    sha1: str
    declared_file_size: int
    actual_file_size: int
    endian_tag: int
    string_count: int
    type_count: int
    proto_count: int
    field_count: int
    method_count: int
    class_count: int
    strings: tuple[str, ...]
    strings_truncated: bool
    classes: tuple[str, ...]
    classes_truncated: bool
    methods: tuple[str, ...]
    methods_truncated: bool
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "version": self.version,
            "checksum": self.checksum,
            "adler32_ok": self.adler32_ok,
            "sha1": self.sha1,
            "declared_file_size": self.declared_file_size,
            "actual_file_size": self.actual_file_size,
            "endian_tag": self.endian_tag,
            "counts": {
                "strings": self.string_count,
                "types": self.type_count,
                "protos": self.proto_count,
                "fields": self.field_count,
                "methods": self.method_count,
                "classes": self.class_count,
            },
            "strings": list(self.strings),
            "strings_truncated": self.strings_truncated,
            "classes": list(self.classes),
            "classes_truncated": self.classes_truncated,
            "methods": list(self.methods),
            "methods_truncated": self.methods_truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }

# --- 8< --- parser -----------------------------------------------------------------


def parse_dex(data: bytes, *, source: str = "<memory>") -> DexSummary:
    """Parse one DEX image's header and index tables into a summary.

    ``data`` is the whole file image; ``source`` labels it in the result.
    Raises the typed :class:`AnalysisError` for bad magic, an unsupported
    version, a truncated header/table or an oversize input; a checksum
    mismatch is only a warning.
    """
    if len(data) > MAX_FILE_BYTES:
        raise AnalysisError(f"file too large: {len(data)} bytes (limit {MAX_FILE_BYTES})")
    if len(data) < 4 or data[:4] != DEX_MAGIC:
        raise AnalysisError("not a DEX file")
    if len(data) < HEADER_SIZE:
        raise AnalysisError("truncated DEX header")

    (
        _magic,
        checksum,
        signature,
        declared_file_size,
        _header_size,
        endian_tag,
        _link_size,
        _link_off,
        _map_off,
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        proto_ids_size,
        proto_ids_off,
        field_ids_size,
        field_ids_off,
        method_ids_size,
        method_ids_off,
        class_defs_size,
        class_defs_off,
        _data_size,
        _data_off,
    ) = struct.unpack_from("<8sI20s20I", data, 0)

    version_bytes = data[4:7]
    if version_bytes not in tuple(v.encode("ascii") for v in SUPPORTED_VERSIONS):
        raise AnalysisError(
            f"unsupported DEX version: {version_bytes.decode('ascii', 'replace')!r}"
        )
    version = version_bytes.decode("ascii")

    warnings: list[str] = []
    body_adler = zlib.adler32(data[12:]) & 0xFFFFFFFF
    adler32_ok = body_adler == checksum
    if not adler32_ok:
        warnings.append(
            f"checksum mismatch: header says 0x{checksum:08x}, adler32 of the body is "
            f"0x{body_adler:08x}"
        )
    if endian_tag not in (0x12345678, 0x78563412):
        warnings.append(f"non-standard endian_tag 0x{endian_tag:08x}; parsed as little-endian")
    if declared_file_size != len(data):
        warnings.append(f"declared file_size {declared_file_size} != actual {len(data)}")

    counts = {
        "string_ids": string_ids_size,
        "type_ids": type_ids_size,
        "proto_ids": proto_ids_size,
        "field_ids": field_ids_size,
        "method_ids": method_ids_size,
        "class_defs": class_defs_size,
    }
    offsets = {
        "string_ids": string_ids_off,
        "type_ids": type_ids_off,
        "proto_ids": proto_ids_off,
        "field_ids": field_ids_off,
        "method_ids": method_ids_off,
        "class_defs": class_defs_off,
    }
    for section, count in counts.items():
        if count > MAX_IDS:
            warnings.append(f"{section} table bounded at {MAX_IDS} entries (declared {count})")
        _check_table(data, offsets[section], min(count, MAX_IDS), section)

    # string_ids: read up to the caps, keep the first samples.
    strings: list[str] = []
    for index in range(min(string_ids_size, MAX_IDS, MAX_STRINGS_KEEP)):
        string_off = _u32(data, string_ids_off + index * 4, "string_ids")
        decoded = _read_string_at(data, string_off, warnings)
        if decoded is None:
            break
        strings.append(decoded[:MAX_STRING_CHARS])
    strings_truncated = string_ids_size > len(strings)

    # type_ids: descriptor indexes, needed to resolve class/method samples.
    descriptors: list[int] = [
        _u32(data, type_ids_off + index * 4, "type_ids")
        for index in range(min(type_ids_size, MAX_IDS))
    ]

    def _descriptor(type_index: int) -> str | None:
        if 0 <= type_index < len(descriptors):
            string_index = descriptors[type_index]
            if 0 <= string_index < string_ids_size:
                offset = _u32(data, string_ids_off + string_index * 4, "string_ids")
                return _read_string_at(data, offset, warnings)
        return None

    # class_defs: keep the first descriptors ("Lcom/foo/Bar;").
    classes: list[str] = []
    for index in range(min(class_defs_size, MAX_IDS, MAX_CLASSES_KEEP)):
        class_index = _u32(data, class_defs_off + index * 32, "class_defs")
        descriptor = _descriptor(class_index)
        if descriptor is None:
            warnings.append(f"class_defs entry {index}: unresolved class_idx {class_index}")
            break
        classes.append(descriptor[:MAX_STRING_CHARS])
    classes_truncated = class_defs_size > len(classes)

    # method_ids: class descriptor -> name samples ("Lcom/foo/Bar;->name").
    methods: list[str] = []
    for index in range(min(method_ids_size, MAX_IDS, MAX_METHODS_KEEP)):
        base = method_ids_off + index * 8
        class_index = _u16(data, base, "method_ids")
        name_index = _u32(data, base + 4, "method_ids")
        class_desc = _descriptor(class_index)
        if class_desc is None or not 0 <= name_index < string_ids_size:
            warnings.append(f"method_ids entry {index}: unresolved indexes")
            break
        offset = _u32(data, string_ids_off + name_index * 4, "string_ids")
        name = _read_string_at(data, offset, warnings)
        if name is None:
            break
        methods.append(f"{class_desc}->{name[:MAX_STRING_CHARS]}")
    methods_truncated = method_ids_size > len(methods)

    sha1_hex = signature.hex()
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="dex-header+index-tables",
        confidence=Confidence.HIGH,
        detail=(
            f"DEX {version}: {string_ids_size} strings, {class_defs_size} classes, "
            f"{method_ids_size} methods"
        ),
        extra={"adler32_ok": adler32_ok, "version": version},
    )
    return DexSummary(
        path=source,
        version=version,
        checksum=checksum,
        adler32_ok=adler32_ok,
        sha1=sha1_hex,
        declared_file_size=declared_file_size,
        actual_file_size=len(data),
        endian_tag=endian_tag,
        string_count=string_ids_size,
        type_count=type_ids_size,
        proto_count=proto_ids_size,
        field_count=field_ids_size,
        method_count=method_ids_size,
        class_count=class_defs_size,
        strings=tuple(strings),
        strings_truncated=strings_truncated,
        classes=tuple(classes),
        classes_truncated=classes_truncated,
        methods=tuple(methods),
        methods_truncated=methods_truncated,
        warnings=tuple(warnings),
        evidence=evidence,
    )




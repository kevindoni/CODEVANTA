"""Apple binary property list (``bplist00``) decoding into a bounded tree.

One container family -- the ``*.plist`` / ``Info.plist`` sidecars of macOS and
iOS artifacts -- decoded with nothing but :mod:`struct` and ``bytes``. A
bplist00 file is an 8-byte ``bplist00`` magic, a flat object table (every
object starts with a marker byte: high nibble is the type, low nibble is
either an inline size or ``0xF`` meaning "an integer object with the real
size follows"), a big-endian offset table, and a fixed 32-byte trailer that
names the offset/reference sizes, the object count, the top object index and
the offset-table position.

API
---
``decode_bplist``
    Parse the header, trailer and offset table, then expand the top object
    into a bounded tree of JSON-safe nodes (null/bool/int/real/date/string/
    data/array/set/dict). Data becomes hex (truncated honestly past
    :data:`MAX_DATA_BYTES`), strings are clipped at :data:`MAX_STRING_CHARS`,
    collections are capped at :data:`MAX_COLLECTION` items, recursion stops
    at :data:`MAX_DEPTH` and the whole file at :data:`MAX_OBJECTS` objects.
    Anything past a bound is a ``truncated`` flag plus a warning, never a
    hard failure.

Bounds
------
Decoding is bounded (:data:`MAX_OBJECTS` objects, :data:`MAX_DEPTH` levels,
:data:`MAX_COLLECTION` items per collection, :data:`MAX_STRING_CHARS`
characters per string, :data:`MAX_DATA_BYTES` per data object); everything
past a bound is a ``truncated`` flag plus warning, in the style of the
container inspectors. The only exception raised is
:class:`~codevanta.core.report.AnalysisError` -- for a bad magic, a truncated
trailer, object/reference range errors, self-referencing cycles and
oversize inputs. Marker type ``0x8`` is not in the published grammar; it is
decoded as UTF-16BE (like ``0x6``) for robustness against real-world blobs.
Nothing is fetched or executed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_SOURCE",
    "MAX_COLLECTION",
    "MAX_DATA_BYTES",
    "MAX_DEPTH",
    "MAX_OBJECTS",
    "MAX_STRING_CHARS",
    "BplistSummary",
    "decode_bplist",
]

#: Objects decoded per file before the rest are refused (hard error, not a flag).
MAX_OBJECTS = 4096

#: Deepest nesting expanded before further descent is a typed error.
MAX_DEPTH = 64

#: Items expanded per array/set/dict; the rest become a ``truncated`` flag.
MAX_COLLECTION = 512

#: Longest string rendered in results; longer strings are clipped with a flag.
MAX_STRING_CHARS = 256

#: Data objects are hex-dumped in full up to this size; above it, preview only.
MAX_DATA_BYTES = 65536

#: Bytes of a data object kept in the hex preview once it exceeds the cap.
MAX_DATA_PREVIEW_BYTES = 64

#: Shared evidence ``source`` for this lane.
EVIDENCE_SOURCE = "bplist.decode"

#: Magic prefix every binary plist starts with (the tail is the version).
_MAGIC = b"bplist00"

#: Size of the fixed trailer (sortVersion + sizes + counts + offset-table position).
_TRAILER_BYTES = 32

#: Marker high nibbles, for readable dispatch.
_INT_TYPE = 0x1
_REAL_TYPE = 0x2
_DATE_TYPE = 0x3
_DATA_TYPE = 0x4
_STRING_TYPES = (0x5, 0x6, 0x8)  # 0x5 ascii, 0x6/0x8 UTF-16BE (see module docstring)
_ARRAY_TYPES = (0xA, 0xB)  # 0xA array, 0xB set
_DICT_TYPE = 0xD

#: Core Data date epoch: seconds are counted from 2001-01-01T00:00:00Z.
_CORE_DATE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class BplistSummary:
    """Bounded summary of a decoded ``bplist00`` document."""

    version: str
    num_objects: int
    top: dict[str, Any]
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "num_objects": self.num_objects,
            "top": self.top,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }

class _Parser:
    """One-pass expander over a parsed bplist00 object table."""

    def __init__(
        self, data: bytes, offsets: list[int], ref_size: int, num_objects: int
    ) -> None:
        self._blob = data
        self._offsets = offsets
        self._ref_size = ref_size
        self._num_objects = num_objects
        self.warnings: list[str] = []

    # -- raw access -------------------------------------------------------

    def _byte(self, offset: int) -> int:
        if offset < 0 or offset >= len(self._blob):
            raise AnalysisError(
                f"object range error: marker at offset {offset} is outside the file"
            )
        return self._blob[offset]

    def _slice(self, start: int, end: int) -> bytes:
        if start < 0 or end > len(self._blob) or start > end:
            raise AnalysisError(
                f"object range error: bytes {start}:{end} fall outside the file"
            )
        return self._blob[start:end]

    def _aux_int(self, start: int) -> tuple[int, int]:
        """Read the auxiliary integer object at ``start``; return (value, end)."""
        marker = self._byte(start)
        if marker >> 4 != _INT_TYPE:
            raise AnalysisError(
                f"expected an auxiliary size integer at offset {start}, "
                f"found marker 0x{marker:02X}"
            )
        size = 1 << (marker & 0xF)
        if size > 8:
            raise AnalysisError(
                f"auxiliary size integer at offset {start} is {size} bytes wide"
            )
        raw = self._slice(start + 1, start + 1 + size)
        return int.from_bytes(raw, "big"), start + 1 + size

    def _count(self, offset: int, info: int, kind: str) -> tuple[int, int]:
        """Resolve an inline or auxiliary element count; return (count, end)."""
        if info != 0xF:
            return info, offset + 1
        value, end = self._aux_int(offset + 1)
        return value, end

    def _refs(self, start: int, count: int) -> list[int]:
        raw = self._slice(start, start + count * self._ref_size)
        size = self._ref_size
        return [
            int.from_bytes(raw[i * size : (i + 1) * size], "big") for i in range(count)
        ]

    def _check_ref(self, index: int) -> None:
        if index >= self._num_objects:
            raise AnalysisError(
                f"object range error: reference {index} points past "
                f"{self._num_objects} objects"
            )

    # -- leaf objects -------------------------------------------------------

    def _string(self, offset: int, marker_type: int, info: int) -> dict[str, Any]:
        count, end = self._count(offset, info, "string")
        if marker_type == 0x5:
            raw = self._slice(end, end + count)
            text, encoding = raw.decode("latin-1"), "ascii"
        else:
            raw = self._slice(end, end + count * 2)
            try:
                text, encoding = raw.decode("utf-16-be"), "utf16"
            except UnicodeDecodeError as exc:
                raise AnalysisError(f"invalid UTF-16BE string: {exc}") from exc
        truncated = count > MAX_STRING_CHARS
        if truncated:
            self.warnings.append(
                f"string: {count} chars exceeds {MAX_STRING_CHARS}, clipped"
            )
        return {
            "kind": "string",
            "encoding": encoding,
            "value": text[:MAX_STRING_CHARS],
            "char_length": count,
            "truncated": truncated,
        }

    def _data(self, offset: int, info: int) -> dict[str, Any]:
        count, end = self._count(offset, info, "data")
        raw = self._slice(end, end + count)
        truncated = count > MAX_DATA_BYTES
        if truncated:
            self.warnings.append(
                f"data: {count} bytes exceeds {MAX_DATA_BYTES}, hex preview only"
            )
            hex_text = raw[:MAX_DATA_PREVIEW_BYTES].hex()
        else:
            hex_text = raw.hex()
        return {
            "kind": "data",
            "hex": hex_text,
            "byte_length": count,
            "truncated": truncated,
        }

    def _int(self, offset: int, info: int) -> dict[str, Any]:
        size = 1 << info
        if info > 4:
            raise AnalysisError(f"unsupported integer size {size} bytes")
        raw = self._slice(offset + 1, offset + 1 + size)
        # Only 8-byte integers are signed in the grammar; wider ones are unsigned.
        value = int.from_bytes(raw, "big", signed=size == 8)
        return {"kind": "int", "value": value, "byte_length": size}

    def _real(self, offset: int, info: int) -> dict[str, Any]:
        size = 1 << info
        # Real sizes follow the same 2**info rule as integers: 2 (float32)
        # and 3 (float64) are the ones real files carry.
        formats = {1: ">e", 2: ">f", 3: ">d"}
        if info not in formats:
            raise AnalysisError(f"unsupported real size {size} bytes")
        raw = self._slice(offset + 1, offset + 1 + size)
        return {"kind": "real", "value": struct.unpack(formats[info], raw)[0]}

    def _date(self, offset: int, info: int) -> dict[str, Any]:
        if info != 0x3:
            raise AnalysisError(f"unsupported date size {1 << info} bytes")
        raw = self._slice(offset + 1, offset + 9)
        seconds = struct.unpack(">d", raw)[0]
        try:
            rendered = (_CORE_DATE_EPOCH + timedelta(seconds=seconds)).isoformat()
        except (OverflowError, OSError, ValueError):
            rendered = f"core-time {seconds:+.3f}s"
        return {"kind": "date", "value": rendered, "core_seconds": seconds}

    # -- collections -------------------------------------------------------

    def _collection(
        self,
        offset: int,
        info: int,
        depth: int,
        on_path: frozenset[int],
        kind: str,
    ) -> dict[str, Any]:
        count, end = self._count(offset, info, kind)
        truncated = count > MAX_COLLECTION
        if truncated:
            self.warnings.append(
                f"{kind}: {count} entries exceeds {MAX_COLLECTION}, bounded"
            )
        take = min(count, MAX_COLLECTION)
        refs = self._refs(end, take)
        if kind == "dict":
            value_refs = self._refs(end + take * self._ref_size, take)
            entries = [
                {
                    "key": self._key_label(
                        self._object(key_ref, depth + 1, on_path)
                    ),
                    "value": self._object(value_ref, depth + 1, on_path),
                }
                for key_ref, value_ref in zip(refs, value_refs, strict=True)
            ]
            return {
                "kind": "dict",
                "length": count,
                "entries": entries,
                "truncated": truncated,
            }
        items = [self._object(ref, depth + 1, on_path) for ref in refs]
        return {"kind": kind, "length": count, "items": items, "truncated": truncated}

    @staticmethod
    def _key_label(node: dict[str, Any]) -> str:
        """Render a dictionary key; non-string keys are coerced honestly."""
        if node["kind"] == "string":
            return str(node["value"])
        value = node.get("value")
        return f"<{node['kind']}: {value!r}>" if value is not None else f"<{node['kind']}>"

    # -- dispatch ----------------------------------------------------------

    def _object(
        self, index: int, depth: int, on_path: frozenset[int]
    ) -> dict[str, Any]:
        self._check_ref(index)
        if index in on_path:
            raise AnalysisError(
                f"cycle detected: object {index} is re-entered via its own references"
            )
        if depth > MAX_DEPTH:
            raise AnalysisError(f"nesting deeper than {MAX_DEPTH} levels")
        offset = self._offsets[index]
        marker = self._byte(offset)
        marker_type = marker >> 4
        info = marker & 0xF
        on_path = on_path | {index}
        if marker in (0x00, 0x08, 0x09):
            if marker == 0x00:
                return {"kind": "null", "value": None}
            return {"kind": "bool", "value": marker == 0x09}
        if marker == 0x0F:
            raise AnalysisError(
                f"unexpected fill byte at offset {offset} "
                "(fill is padding, not an object)"
            )
        if marker_type == _INT_TYPE:
            return self._int(offset, info)
        if marker_type == _REAL_TYPE:
            return self._real(offset, info)
        if marker_type == _DATE_TYPE:
            return self._date(offset, info)
        if marker_type == _DATA_TYPE:
            return self._data(offset, info)
        if marker_type in _STRING_TYPES:
            return self._string(offset, marker_type, info)
        if marker_type in _ARRAY_TYPES:
            kind = "array" if marker_type == 0xA else "set"
            return self._collection(offset, info, depth, on_path, kind)
        if marker_type == _DICT_TYPE:
            return self._collection(offset, info, depth, on_path, "dict")
        raise AnalysisError(
            f"unsupported object marker 0x{marker:02X} at offset {offset}"
        )


def _parse_trailer(data: bytes) -> tuple[int, int, int, int, int]:
    """Parse the 32-byte trailer; return (offset_size, ref_size, n, top, oto)."""
    if len(data) < len(_MAGIC) + _TRAILER_BYTES:
        raise AnalysisError(
            f"truncated trailer: file is {len(data)} bytes, the 8-byte magic "
            f"plus a {_TRAILER_BYTES}-byte trailer are required"
        )
    trailer = data[-_TRAILER_BYTES:]
    offset_size, ref_size = trailer[6], trailer[7]
    num_objects = int.from_bytes(trailer[8:16], "big")
    top_object = int.from_bytes(trailer[16:24], "big")
    offset_table_offset = int.from_bytes(trailer[24:32], "big")
    if not 1 <= offset_size <= 8:
        raise AnalysisError(f"invalid offset integer size {offset_size}")
    if ref_size not in (1, 2, 4, 8):
        raise AnalysisError(f"invalid object reference size {ref_size}")
    return offset_size, ref_size, num_objects, top_object, offset_table_offset

def decode_bplist(data: bytes) -> BplistSummary:
    """Decode ``data`` (a ``bplist00`` document) into a bounded summary.

    The object table is expanded from the trailer's top object with the caps
    documented in the module docstring; anything past a bound becomes a
    ``truncated`` flag and warning, never a hard failure.
    """
    if len(data) < len(_MAGIC) or data[:8] != _MAGIC:
        got = data[:8]
        raise AnalysisError(
            f"bad magic: expected {_MAGIC!r}, got {got!r} ({len(data)} byte file)"
        )
    offset_size, ref_size, num_objects, top_object, offset_table_offset = (
        _parse_trailer(data)
    )
    if num_objects > MAX_OBJECTS:
        raise AnalysisError(f"too many objects: {num_objects} (limit {MAX_OBJECTS})")
    if num_objects == 0:
        raise AnalysisError("empty object table: trailer declares 0 objects")
    if top_object >= num_objects:
        raise AnalysisError(
            f"object range error: top object {top_object} points past "
            f"{num_objects} objects"
        )
    table_end = offset_table_offset + num_objects * offset_size
    if offset_table_offset < len(_MAGIC) or table_end > len(data):
        raise AnalysisError(
            f"object range error: offset table {offset_table_offset}..{table_end} "
            "falls outside the file"
        )
    offsets = [
        int.from_bytes(
            data[
                offset_table_offset
                + i * offset_size : offset_table_offset
                + (i + 1) * offset_size
            ],
            "big",
        )
        for i in range(num_objects)
    ]
    parser = _Parser(data, offsets, ref_size, num_objects)
    top = parser._object(top_object, 0, frozenset())

    kind = top.get("kind", "?")
    return BplistSummary(
        version=data[6:8].decode("ascii"),
        num_objects=num_objects,
        top=top,
        warnings=tuple(parser.warnings),
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="bplist00_decode",
            confidence=Confidence.HIGH,
            detail=(
                f"{num_objects} objects (refs {ref_size}B, offsets {offset_size}B); "
                f"top object {top_object} is a {kind}"
            ),
        ),
    )

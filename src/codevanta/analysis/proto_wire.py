"""Protobuf wire-format decoder (structure-only, pure Python, offline).

A protobuf message on the wire is a sequence of ``tag varint`` + payload
fields. The tag's low three bits are the *wire type* (0 varint, 1 fixed64,
2 length-delimited, 3 start-group, 4 end-group, 5 fixed32) and the rest is
the field number. This module walks that structure with nothing but
:mod:`struct` and ``bytes`` and produces a frozen, JSON-safe field tree:
field numbers, wire types and the decoded values (varints as ``int``, fixed
fields as IEEE-754 ``float``, length-delimited payloads as nested fields
when they parse cleanly as a message and as bounded hex otherwise, groups as
nested field tuples).

The decode is deliberately *structure-only*: field numbers are semantic-free
without the ``.proto`` schema, so every result carries
:class:`~codevanta.evidence.confidence.Confidence.MEDIUM` evidence -- shape,
never meaning. Malformed or exotic input never raises mid-walk: truncated
fields, invalid tags and unknown wire types (6/7) become ``warnings`` and
the walk stops at that point, keeping what decoded before it.

gRPC framing: :func:`strip_grpc_frame` detects and removes the 5-byte gRPC
frame prefix (1 flag byte in ``{0, 1}`` + 4-byte big-endian message length
matching the remaining bytes); :func:`decode_message` applies it first when
``strip_grpc=True`` and reports the frame in the result.

Guarantees:

* Pure decoding: no filesystem, no network, no execution.
* Bounded work: at most :data:`MAX_FIELDS` fields per message, nesting at
  most :data:`MAX_DEPTH` levels, hex previews cut at
  :data:`MAX_HEX_CHARS` characters.
* Only :class:`~codevanta.core.report.AnalysisError` is raised, and only
  for wrong input *types* or nonsensical bounds -- never for message
  content.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.analysis.har_capture import looks_like_grpc_frame
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_METHOD",
    "EVIDENCE_SOURCE",
    "MAX_DEPTH",
    "MAX_FIELDS",
    "MAX_FILE_BYTES",
    "MAX_HEX_CHARS",
    "WIRE_EGROUP",
    "WIRE_I32",
    "WIRE_I64",
    "WIRE_LEN",
    "WIRE_SGROUP",
    "WIRE_VARINT",
    "GrpcFrame",
    "ProtoField",
    "ProtoMessage",
    "decode_message",
    "load_proto_bytes",
    "strip_grpc_frame",
]

#: Wire type 0: variable-length integer.
WIRE_VARINT = 0
#: Wire type 1: 64-bit fixed (interpreted as IEEE-754 double).
WIRE_I64 = 1
#: Wire type 2: length-delimited (nested message or bytes).
WIRE_LEN = 2
#: Wire type 3: start of a group (legacy).
WIRE_SGROUP = 3
#: Wire type 4: end of a group (legacy).
WIRE_EGROUP = 4
#: Wire type 5: 32-bit fixed (interpreted as IEEE-754 single).
WIRE_I32 = 5

#: Hard ceiling on nesting depth; deeper payloads are reported as bytes.
MAX_DEPTH = 8

#: Hard ceiling on fields decoded per message (bounded work).
MAX_FIELDS = 256

#: Characters of one hex preview before it is cut (bounded output).
MAX_HEX_CHARS = 64

#: Hard ceiling on the bytes one :func:`load_proto_bytes` call will read.
MAX_FILE_BYTES = 8 * 1024 * 1024

#: Evidence source shared by every record in this module.
EVIDENCE_SOURCE = "web.proto"

#: Evidence method for wire-format walks.
EVIDENCE_METHOD = "wire_field_walk"

#: A protobuf varint may legally span at most 10 bytes (64 bits + slack).
_MAX_VARINT_BYTES = 10

_KIND_VARINT = "varint"
_KIND_I64 = "fixed64"
_KIND_LEN = "bytes"
_KIND_I32 = "fixed32"
_KIND_GROUP = "group"
_KIND_MESSAGE = "message"

_I64_STRUCT = struct.Struct("<d")
_I32_STRUCT = struct.Struct("<f")
@dataclass(frozen=True)
class GrpcFrame:
    """Result of a gRPC 5-byte frame-prefix check.

    Attributes:
        present: True when ``data`` carried a valid frame prefix.
        message_length: The prefix's big-endian length (present frames only).
        payload: The frame payload (``data`` itself when no prefix matched;
            never serialised -- see :meth:`to_dict`).
    """

    present: bool
    message_length: int | None
    payload: bytes

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record (payload stays out; size only)."""
        data: dict[str, Any] = {
            "present": self.present,
            "payload_size": len(self.payload),
        }
        if self.message_length is not None:
            data["message_length"] = self.message_length
        return data


@dataclass(frozen=True)
class ProtoField:
    """One wire-format field (possibly nesting further fields).

    Attributes:
        field_number: Protobuf field number from the tag.
        wire_type: The tag's low three bits (0-5).
        kind: Human label: ``varint``, ``fixed64``, ``fixed32``, ``bytes``
            or ``group``.
        value: ``int`` for varints, ``float`` for fixed fields, a bounded
            hex ``str`` for raw bytes, or a tuple of nested
            :class:`ProtoField` for messages/groups.
        depth: Nesting level (0 = top level; never above
            :data:`MAX_DEPTH`).
    """

    field_number: int
    wire_type: int
    kind: str
    value: int | float | str | tuple[ProtoField, ...]
    depth: int

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record (nested fields recurse)."""
        value = self.value
        if isinstance(value, tuple):
            payload: Any = [child.to_dict() for child in value]
        else:
            payload = value
        return {
            "field": self.field_number,
            "wire_type": self.wire_type,
            "kind": self.kind,
            "depth": self.depth,
            "value": payload,
        }


@dataclass(frozen=True)
class ProtoMessage:
    """Bounded structure-only decode of one protobuf message.

    Attributes:
        fields: Top-level fields in wire order.
        field_count: Total fields decoded (nested included).
        depth_reached: Deepest nesting level reached.
        grpc_frame: The stripped gRPC frame when ``strip_grpc`` removed a
            prefix, else ``None``.
        warnings: Structural problems met on the way (unknown wire types,
            truncated fields, budget/depth cuts) -- decode never raises for
            these.
        evidence: MEDIUM-confidence record: structure without schema.
    """

    fields: tuple[ProtoField, ...]
    field_count: int
    depth_reached: int
    grpc_frame: GrpcFrame | None
    warnings: tuple[str, ...] = ()
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record."""
        data: dict[str, Any] = {
            "field_count": self.field_count,
            "depth_reached": self.depth_reached,
            "fields": [item.to_dict() for item in self.fields],
        }
        if self.grpc_frame is not None:
            data["grpc_frame"] = self.grpc_frame.to_dict()
        if self.warnings:
            data["warnings"] = list(self.warnings)
        if self.evidence is not None:
            data["evidence"] = self.evidence.to_dict()
        return data


class _Walk:
    """Mutable per-decode state (never leaves this module)."""

    __slots__ = ("budget_left", "depth_cut", "max_depth_seen", "warnings")

    def __init__(self, budget: int) -> None:
        self.budget_left = budget
        self.depth_cut = False
        self.max_depth_seen = 0
        self.warnings: list[str] = []
def _read_varint(data: bytes, pos: int) -> tuple[int, int] | None:
    """Read one base-128 varint at ``pos``; ``None`` when malformed.

    Returns ``(value, next_pos)``. A varint that does not terminate within
    :data:`_MAX_VARINT_BYTES` bytes is malformed, not merely long.
    """
    result = 0
    shift = 0
    for offset in range(_MAX_VARINT_BYTES):
        index = pos + offset
        if index >= len(data):
            return None
        byte = data[index]
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, index + 1
        shift += 7
    return None


def _hex_bounded(payload: bytes) -> str:
    """Hex-encode ``payload`` cut at :data:`MAX_HEX_CHARS` characters."""
    hex_text = payload.hex()
    if len(hex_text) <= MAX_HEX_CHARS:
        return hex_text
    return hex_text[:MAX_HEX_CHARS] + "…"


def _decode_fields(
    data: bytes,
    start: int,
    depth: int,
    walk: _Walk,
    out: list[ProtoField],
    *,
    egroup_field: int | None = None,
) -> int | None:
    """Decode fields from ``data[start:]`` into ``out`` (appended in order).

    Returns the end position, or ``None`` after recording a warning in
    ``walk`` when the structure breaks (unknown wire type, truncated field,
    unmatched end-group, exhausted budget). Fields decoded before the break
    stay in ``out``; the caller decides whether a partial result is
    acceptable (top level) or the payload should be treated as raw bytes
    (nested probes).
    """
    pos = start
    if depth > walk.max_depth_seen:
        walk.max_depth_seen = depth
    while pos < len(data):
        if walk.budget_left <= 0:
            walk.warnings.append(
                f"field budget ({MAX_FIELDS}) exhausted at byte {pos}; "
                "remaining fields not visited"
            )
            return None
        tag = _read_varint(data, pos)
        if tag is None:
            walk.warnings.append(f"truncated or overlong tag varint at byte {pos}")
            return None
        tag_value, pos = tag
        field_number = tag_value >> 3
        wire_type = tag_value & 0x07
        if field_number <= 0:
            walk.warnings.append(f"invalid field number 0 at byte {pos}")
            return None
        if wire_type == WIRE_EGROUP:
            if egroup_field is not None:
                # Lenient: any end-group closes the innermost open group.
                return pos
            walk.warnings.append(f"unmatched end-group at byte {pos}")
            return None
        if wire_type == WIRE_VARINT:
            varint = _read_varint(data, pos)
            if varint is None:
                walk.warnings.append(
                    f"truncated varint payload for field {field_number} at byte {pos}"
                )
                return None
            value, pos = varint
            out.append(
                ProtoField(field_number, wire_type, _KIND_VARINT, value, depth)
            )
            walk.budget_left -= 1
        elif wire_type == WIRE_I64:
            if pos + 8 > len(data):
                walk.warnings.append(
                    f"truncated fixed64 payload for field {field_number} at byte {pos}"
                )
                return None
            value = _I64_STRUCT.unpack(data[pos : pos + 8])[0]
            pos += 8
            out.append(ProtoField(field_number, wire_type, _KIND_I64, value, depth))
            walk.budget_left -= 1
        elif wire_type == WIRE_I32:
            if pos + 4 > len(data):
                walk.warnings.append(
                    f"truncated fixed32 payload for field {field_number} at byte {pos}"
                )
                return None
            value = _I32_STRUCT.unpack(data[pos : pos + 4])[0]
            pos += 4
            out.append(ProtoField(field_number, wire_type, _KIND_I32, value, depth))
            walk.budget_left -= 1
        elif wire_type == WIRE_LEN:
            length = _read_varint(data, pos)
            if length is None:
                walk.warnings.append(
                    f"truncated length prefix for field {field_number} at byte {pos}"
                )
                return None
            payload_len, pos = length
            if pos + payload_len > len(data):
                walk.warnings.append(
                    f"truncated length-delimited field {field_number} at byte {pos}"
                )
                return None
            payload = data[pos : pos + payload_len]
            pos += payload_len
            out.append(_decode_len_field(field_number, payload, depth, walk))
            walk.budget_left -= 1
        elif wire_type == WIRE_SGROUP:
            children: list[ProtoField] = []
            group_end = _decode_fields(
                data, pos, depth + 1, walk, children, egroup_field=field_number
            )
            if group_end is None:
                # The inner walk already recorded what went wrong.
                return None
            pos = group_end
            out.append(
                ProtoField(field_number, wire_type, _KIND_GROUP, tuple(children), depth)
            )
            walk.budget_left -= 1
        else:
            # Wire types 6 and 7 do not exist; never crash, never resync.
            walk.warnings.append(
                f"unknown wire type {wire_type} for field {field_number} "
                f"at byte {pos}; stopping"
            )
            return None
    if egroup_field is not None:
        # Buffer exhausted without the closing end-group: unterminated group.
        walk.warnings.append(
            f"group field {egroup_field} never terminated (end of buffer)"
        )
        return None
    return pos


def _decode_len_field(
    field_number: int,
    payload: bytes,
    depth: int,
    walk: _Walk,
) -> ProtoField:
    """Decode one length-delimited field: nested message or bounded hex.

    A payload is reported as a nested message when it parses completely into
    at least one field (the probe is isolated: its budget spend and warnings
    only commit on success); anything else -- or a payload that would exceed
    :data:`MAX_DEPTH` -- is reported as a bounded hex string.
    """
    if depth + 1 < MAX_DEPTH:
        probe = _Walk(walk.budget_left)
        probe_out: list[ProtoField] = []
        probe_end = _decode_fields(payload, 0, depth + 1, probe, probe_out)
        if probe_end is not None and probe_out:
            walk.budget_left = probe.budget_left
            walk.max_depth_seen = max(walk.max_depth_seen, probe.max_depth_seen)
            walk.warnings.extend(probe.warnings)
            return ProtoField(
                field_number, WIRE_LEN, _KIND_MESSAGE, tuple(probe_out), depth
            )
    elif not walk.depth_cut:
        walk.depth_cut = True
        walk.warnings.append(
            f"max depth ({MAX_DEPTH}) reached; deeper payloads reported as bytes"
        )
    return ProtoField(field_number, WIRE_LEN, _KIND_LEN, _hex_bounded(payload), depth)


def _count_fields(fields: tuple[ProtoField, ...]) -> int:
    """Count ``fields`` including every nested field, recursively."""
    total = 0
    for item in fields:
        total += 1
        if isinstance(item.value, tuple):
            total += _count_fields(item.value)
    return total


def strip_grpc_frame(data: bytes) -> GrpcFrame:
    """Detect and strip a gRPC 5-byte frame prefix from ``data``.

    Returns the frame record: ``present`` with the big-endian message length
    and the payload with the prefix removed, or ``present=False`` with the
    input unchanged as payload (never raises for content).
    """
    if isinstance(data, (bytearray, memoryview)):
        data = bytes(data)
    if not looks_like_grpc_frame(data):
        return GrpcFrame(present=False, message_length=None, payload=data)
    return GrpcFrame(
        present=True,
        message_length=int.from_bytes(data[1:5], "big"),
        payload=data[5:],
    )


def decode_message(
    data: bytes,
    *,
    strip_grpc: bool = False,
    max_depth: int = MAX_DEPTH,
    max_fields: int = MAX_FIELDS,
) -> ProtoMessage:
    """Decode a protobuf message into a bounded structure-only field tree.

    Args:
        data: Raw message bytes (with or without gRPC framing).
        strip_grpc: Remove a leading 5-byte gRPC frame prefix first and
            report it in :attr:`ProtoMessage.grpc_frame`.
        max_depth: Nesting ceiling (1 .. :data:`MAX_DEPTH`).
        max_fields: Field budget (1 .. :data:`MAX_FIELDS`).

    Returns:
        A frozen :class:`ProtoMessage`; content problems (unknown wire
        types, truncated fields) surface as ``warnings``, never exceptions.

    Raises:
        AnalysisError: If ``data`` is not bytes-like or the bounds are
            nonsensical.
    """
    if isinstance(data, (bytearray, memoryview)):
        data = bytes(data)
    if not isinstance(data, bytes):
        raise AnalysisError(f"expected bytes, got {type(data).__name__}")
    if not 1 <= max_depth <= MAX_DEPTH:
        raise AnalysisError(f"max_depth must be between 1 and {MAX_DEPTH}")
    if not 1 <= max_fields <= MAX_FIELDS:
        raise AnalysisError(f"max_fields must be between 1 and {MAX_FIELDS}")

    frame: GrpcFrame | None = None
    if strip_grpc:
        candidate = strip_grpc_frame(data)
        if candidate.present:
            frame = candidate
            data = candidate.payload

    walk = _Walk(max_fields)
    fields: list[ProtoField] = []
    if data:
        _decode_fields(data, 0, 0, walk, fields)
    else:
        walk.warnings.append("empty message: no fields")
    field_count = _count_fields(tuple(fields))

    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method=EVIDENCE_METHOD,
        confidence=Confidence.MEDIUM,
        extra={"fields": field_count, "grpc_frame": frame is not None},
    )
    return ProtoMessage(
        fields=tuple(fields),
        field_count=field_count,
        depth_reached=walk.max_depth_seen,
        grpc_frame=frame,
        warnings=tuple(walk.warnings),
        evidence=evidence,
    )


def load_proto_bytes(path: Path) -> bytes:
    """Read one body file (bounded) for wire decoding (read-only)."""
    if not path.exists():
        raise AnalysisError(f"file not found: {path}")
    if not path.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise AnalysisError(
            f"body too large for wire decoding: {size} bytes (limit {MAX_FILE_BYTES})"
        )
    try:
        return path.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"cannot read {str(path)!r}: {exc}") from exc


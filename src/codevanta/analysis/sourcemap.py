"""JavaScript source-map (v3) decoding and generated-position tracing.

One JSON document family -- the ``sourceMappingURL`` sidecars of shipped web
bundles -- decoded with nothing but :mod:`json` and ``bytes``. The ``mappings``
field is a base64-VLQ stream: ``;`` separates generated lines, ``,`` separates
segments, and every segment is one, four or five signed variable-length
integers encoding (relative) generated column, source index, source line,
source column and name index. Only the generated column resets per line; all
other fields are running deltas across the whole map.

API
---
``decode_source_map``
    Parse the v3 JSON envelope and decode the mappings into a bounded
    :class:`SourceMapSummary`: the original sources, names, segment count,
    per-field truncation flags and evidence. Oversize inputs, non-v3
    versions, invalid VLQ, and segment indexes outside the sources/names
    tables are typed errors.
``trace_position``
    Map one 0-based generated ``(line, column)`` back to its origin: the
    nearest segment at or before that column on that line wins, and the
    result carries the original source path, line, column and symbol name.
    A miss -- no segment at or before the column, or the line beyond the
    map -- is a normal ``hit=False`` result, never an error.

Bounds
------
Decoding is bounded (:data:`MAX_SEGMENTS` segments, :data:`MAX_SOURCES`
sources, :data:`MAX_NAMES` names, :data:`MAX_NAME_CHARS` characters per
rendered name, :data:`MAX_MAP_BYTES` input bytes); everything past a bound is
a ``truncated`` flag plus warning, in the style of the container inspectors.
The only exception raised is
:class:`~codevanta.core.report.AnalysisError`. Nothing is fetched or executed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_SOURCE",
    "MAX_MAP_BYTES",
    "MAX_NAME_CHARS",
    "MAX_NAMES",
    "MAX_SEGMENTS",
    "MAX_SOURCES",
    "SourceMapSegment",
    "SourceMapSummary",
    "decode_source_map",
    "trace_position",
]

#: Segments decoded per map before the rest are skipped (truncated flag).
MAX_SEGMENTS = 20000

#: Source entries kept per map before the rest are dropped.
MAX_SOURCES = 512

#: Names kept per map before the rest are dropped.
MAX_NAMES = 512

#: Longest original name rendered in results; longer names are clipped.
MAX_NAME_CHARS = 128

#: Hard ceiling on the bytes one decode will accept (maps are refused above).
MAX_MAP_BYTES = 64 * 1024 * 1024

#: Shared evidence ``source`` for this lane.
EVIDENCE_SOURCE = "web.sourcemap"

_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64_VALUES: dict[str, int] = {char: index for index, char in enumerate(_B64_ALPHABET)}

#: 8 continuation digits cover every 32-bit value; a longer run is hostile.
_VLQ_CONTINUATION_LIMIT = 40


@dataclass(frozen=True)
class SourceMapSegment:
    """One decoded mapping segment (all positions 0-based).

    ``source_index``/``source_line``/``source_column`` are ``None`` for the
    one-field "generated column only" segments a map may interleave;
    ``name_index`` is ``None`` unless the segment carried a fifth field.
    """

    generated_line: int
    generated_column: int
    source_index: int | None = None
    source_line: int | None = None
    source_column: int | None = None
    name_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_line": self.generated_line,
            "generated_column": self.generated_column,
            "source_index": self.source_index,
            "source_line": self.source_line,
            "source_column": self.source_column,
            "name_index": self.name_index,
        }


@dataclass(frozen=True)
class SourceMapSummary:
    """Bounded summary of a decoded source map v3 document."""

    version: int
    source_root: str
    sources: tuple[str, ...]
    source_count: int
    names: tuple[str, ...]
    name_count: int
    segment_count: int
    generated_line_count: int
    segments_truncated: bool
    sources_truncated: bool
    names_truncated: bool
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "source_root": self.source_root,
            "sources": list(self.sources),
            "source_count": self.source_count,
            "names": list(self.names),
            "name_count": self.name_count,
            "segment_count": self.segment_count,
            "generated_line_count": self.generated_line_count,
            "truncated": {
                "segments": self.segments_truncated,
                "sources": self.sources_truncated,
                "names": self.names_truncated,
            },
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _parse_envelope(data: bytes) -> dict[str, Any]:
    """Decode ``data`` as a source-map JSON object (typed errors otherwise)."""
    if len(data) > MAX_MAP_BYTES:
        raise AnalysisError(
            f"source map too large: {len(data)} bytes (limit {MAX_MAP_BYTES})"
        )
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise AnalysisError(f"source map is not valid UTF-8: {exc}") from exc
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AnalysisError(f"source map is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise AnalysisError("source map must be a JSON object")
    return parsed


def _validate_version(parsed: dict[str, Any]) -> int:
    version = parsed.get("version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise AnalysisError(
            f"source map 'version' must be an integer, got {type(version).__name__}"
        )
    if version != 3:
        raise AnalysisError(
            f"unsupported source map version {version}; only v3 is implemented"
        )
    return version


def _string_list(parsed: dict[str, Any], key: str) -> list[str]:
    value = parsed.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise AnalysisError(f"source map {key!r} must be a list of strings")
    return value


def _decode_vlq_segment(token: str, where: str) -> list[int]:
    """Decode one base64-VLQ comma-free token into its signed field values."""
    values: list[int] = []
    shift = 0
    value = 0
    for char in token:
        digit = _B64_VALUES.get(char)
        if digit is None:
            raise AnalysisError(f"invalid base64 VLQ character {char!r} in {where}")
        value |= (digit & 0x1F) << shift
        if digit & 0x20:  # continuation bit: the value keeps going
            shift += 5
            if shift >= _VLQ_CONTINUATION_LIMIT:
                raise AnalysisError(
                    f"VLQ value in {where} uses too many continuation digits"
                )
        else:
            negative = value & 1
            magnitude = value >> 1
            values.append(-magnitude if negative else magnitude)
            value = 0
            shift = 0
    if shift:
        raise AnalysisError(f"VLQ segment {token!r} in {where} ends mid-value")
    return values


def _walk_mappings(
    mappings: str, source_count: int, name_count: int, limit: int
) -> tuple[list[SourceMapSegment], bool]:
    """Decode the ``mappings`` VLQ stream into segments, bounded at ``limit``.

    Running deltas: only the generated column resets at every ``;``; source
    index, source line, source column and name index carry across lines.
    """
    segments: list[SourceMapSegment] = []
    source_index = 0
    source_line = 0
    source_column = 0
    name_index = 0
    for generated_line, line_text in enumerate(mappings.split(";")):
        generated_column = 0
        if not line_text:
            continue
        for position, token in enumerate(line_text.split(",")):
            if not token:
                continue
            where = f"line {generated_line}, segment {position}"
            fields = _decode_vlq_segment(token, where)
            if len(fields) not in (1, 4, 5):
                raise AnalysisError(
                    f"segment {token!r} in {where} has {len(fields)} fields; "
                    "expected 1, 4 or 5"
                )
            generated_column += fields[0]
            if generated_column < 0:
                raise AnalysisError(
                    f"segment {token!r} in {where} moves the generated column "
                    "negative"
                )
            if len(fields) == 1:
                segments.append(SourceMapSegment(generated_line, generated_column))
            else:
                source_index += fields[1]
                source_line += fields[2]
                source_column += fields[3]
                if not 0 <= source_index < source_count:
                    raise AnalysisError(
                        f"segment {token!r} in {where} references source index "
                        f"{source_index}, but the map has {source_count} sources"
                    )
                if source_line < 0 or source_column < 0:
                    raise AnalysisError(
                        f"segment {token!r} in {where} moves the original "
                        "position negative"
                    )
                segment_name: int | None = None
                if len(fields) == 5:
                    name_index += fields[4]
                    if not 0 <= name_index < name_count:
                        raise AnalysisError(
                            f"segment {token!r} in {where} references name index "
                            f"{name_index}, but the map has {name_count} names"
                        )
                    segment_name = name_index
                segments.append(
                    SourceMapSegment(
                        generated_line,
                        generated_column,
                        source_index,
                        source_line,
                        source_column,
                        segment_name,
                    )
                )
            if len(segments) >= limit:
                return segments, True
    return segments, False


def _resolve_source(source_root: str, source: str) -> str:
    """Join ``sourceRoot`` with a source entry the way bundlers render it."""
    if source_root and not source.startswith("/") and "://" not in source:
        return f"{source_root.rstrip('/')}/{source}"
    return source


def _load_map(data: bytes) -> tuple[int, str, list[str], list[str], str]:
    """Parse and validate the v3 envelope shared by both public entry points."""
    parsed = _parse_envelope(data)
    version = _validate_version(parsed)
    mappings = parsed.get("mappings", "")
    if not isinstance(mappings, str):
        raise AnalysisError("source map 'mappings' must be a string")
    source_root = parsed.get("sourceRoot", "")
    if not isinstance(source_root, str):
        raise AnalysisError("source map 'sourceRoot' must be a string")
    sources = _string_list(parsed, "sources")
    names = _string_list(parsed, "names")
    return version, mappings, sources, names, source_root


def decode_source_map(data: bytes) -> SourceMapSummary:
    """Decode ``data`` (a source map v3 JSON document) into a bounded summary.

    The mappings stream is decoded with the caps documented in the module
    docstring; anything past a bound becomes a ``truncated`` flag and warning,
    never a hard failure.
    """
    version, mappings, raw_sources, raw_names, source_root = _load_map(data)
    warnings: list[str] = []

    sources_truncated = len(raw_sources) > MAX_SOURCES
    sources = tuple(raw_sources[:MAX_SOURCES])
    if sources_truncated:
        warnings.append(
            f"sources: output bounded at {MAX_SOURCES}, remaining entries dropped"
        )

    names_truncated = len(raw_names) > MAX_NAMES
    names = tuple(name[:MAX_NAME_CHARS] for name in raw_names[:MAX_NAMES])
    if names_truncated:
        warnings.append(
            f"names: output bounded at {MAX_NAMES}, remaining entries dropped"
        )
    if any(len(name) > MAX_NAME_CHARS for name in raw_names[:MAX_NAMES]):
        warnings.append(f"names clipped to {MAX_NAME_CHARS} characters")

    segments, segments_truncated = _walk_mappings(
        mappings, len(raw_sources), len(raw_names), MAX_SEGMENTS
    )
    if segments_truncated:
        warnings.append(
            f"mappings: output bounded at {MAX_SEGMENTS} segments, "
            "remaining segments skipped"
        )
    return SourceMapSummary(
        version=version,
        source_root=source_root,
        sources=sources,
        source_count=len(raw_sources),
        names=names,
        name_count=len(raw_names),
        segment_count=len(segments),
        generated_line_count=mappings.count(";") + 1 if mappings else 0,
        segments_truncated=segments_truncated,
        sources_truncated=sources_truncated,
        names_truncated=names_truncated,
        warnings=tuple(warnings),
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="base64_vlq_decode",
            confidence=Confidence.HIGH,
            detail=(
                f"{len(segments)} segments over {len(raw_sources)} sources; "
                f"{len(raw_names)} names"
            ),
        ),
    )


def trace_position(data: bytes, line: int, column: int) -> dict[str, Any]:
    """Trace a 0-based generated ``(line, column)`` back to its original source.

    The nearest segment at or before ``column`` on ``line`` wins (source maps
    mark mapping starts, not spans). A miss is a normal ``hit=False`` result
    carrying the reason; only structurally bad maps or arguments raise.
    """
    if isinstance(line, bool) or not isinstance(line, int):
        raise AnalysisError(f"line must be an integer, got {type(line).__name__}")
    if isinstance(column, bool) or not isinstance(column, int):
        raise AnalysisError(f"column must be an integer, got {type(column).__name__}")
    if line < 0 or column < 0:
        raise AnalysisError("line and column must be non-negative")

    _version, mappings, raw_sources, raw_names, source_root = _load_map(data)
    segments, _truncated = _walk_mappings(
        mappings, len(raw_sources), len(raw_names), MAX_SEGMENTS
    )
    line_segments = [seg for seg in segments if seg.generated_line == line]
    if not line_segments:
        line_count = mappings.count(";") + 1 if mappings else 0
        if line >= line_count:
            reason = (
                f"generated line {line} lies beyond the map "
                f"({line_count} mapping lines)"
            )
        else:
            reason = f"no mappings on generated line {line}"
        return _trace_miss(line, column, reason)
    candidates = [seg for seg in line_segments if seg.generated_column <= column]
    if not candidates:
        first = line_segments[0].generated_column
        reason = (
            f"column {column} is before the first mapping on line {line} "
            f"(column {first})"
        )
        return _trace_miss(line, column, reason)
    best = max(candidates, key=lambda seg: seg.generated_column)
    source_name = (
        raw_sources[best.source_index] if best.source_index is not None else None
    )
    name: str | None = None
    if best.name_index is not None and best.name_index < len(raw_names):
        name = raw_names[best.name_index][:MAX_NAME_CHARS]
    resolved = (
        _resolve_source(source_root, source_name) if source_name is not None else None
    )
    return {
        "hit": True,
        "generated_line": line,
        "generated_column": column,
        "source": resolved,
        "source_index": best.source_index,
        "source_line": best.source_line,
        "source_column": best.source_column,
        "name": name,
        "segment": best.to_dict(),
        "evidence": Evidence(
            source=EVIDENCE_SOURCE,
            method="vlq_trace",
            confidence=Confidence.HIGH,
            detail=(
                f"segment at generated column {best.generated_column} maps to "
                f"{resolved}:{best.source_line}:{best.source_column}"
            ),
        ).to_dict(),
    }


def _trace_miss(line: int, column: int, reason: str) -> dict[str, Any]:
    """Build the honest miss result (a miss is a value, not an error)."""
    return {
        "hit": False,
        "generated_line": line,
        "generated_column": column,
        "reason": reason,
        "evidence": Evidence(
            source=EVIDENCE_SOURCE,
            method="vlq_trace",
            confidence=Confidence.HIGH,
            detail=reason,
        ).to_dict(),
    }

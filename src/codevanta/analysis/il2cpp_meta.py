"""Deep structural parser for Unity IL2CPP ``global-metadata.dat``.

Structure only, honestly: the header pairs (offset, size) are walked and named
per the documented layout of each known version family. Readable name/string
decoding is deliberately NOT attempted (string tables are version-dependent
binary layouts that change between Unity releases), so the evidence states
what is certain (the container structure) and marks per-table row counts as
medium-confidence approximations derived from documented struct strides.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TABLES = 64

IL2CPP_MAGIC = 0xFAB11BAF

#: Documented global-metadata-header table order per version family.
_FAMILY_TABLES: dict[str, tuple[str, ...]] = {
    "24": (
        "string-literals", "string-literal-data", "string", "events", "properties",
        "fields", "parameter-default-values", "field-default-values",
        "field-and-parameter-default-value-data", "field-marshaled-sizes",
        "parameters", "methods", "classes", "images", "assemblies",
    ),
    "27": (
        "string-literals", "string-literal-data", "string", "events", "properties",
        "fields", "parameter-default-values", "field-default-values",
        "field-and-parameter-default-value-data", "field-marshaled-sizes",
        "parameters", "methods", "classes", "images", "assemblies", "field-offsets",
        "type-metadata-sizes", "referred-generic-collections", "metadata-usage",
        "metadata-usage-lists", "metadata-usage-pairs",
    ),
}

#: Header layouts that continue past the 27-family order (29/31/39 append these).
_V29_EXTRA: tuple[str, ...] = (
    "attribute-data", "attribute-data-ranges", "unresolved-virtual-call-parameter-types",
    "unresolved-virtual-call-parameter-ranges", "windows-runtime-type-names",
    "windows-runtime-strings", "exported-type-definitions",
)

#: Best-known struct strides (bytes per row) used for count approximations.
_STRIDES: dict[str, int] = {
    "string-literals": 8,
    "methods": 40,
    "images": 40,
    "assemblies": 40,
}

__all__ = ["Il2CppTable", "Il2CppMetaSummary", "parse_il2cpp_meta"]


class Il2CppTable:
    """One named (or honestly unnamed) header table."""

    __slots__ = ("name", "offset", "size", "count", "count_known")

    def __init__(self, name: str, offset: int, size: int, count: int | None, count_known: bool) -> None:
        self.name = name
        self.offset = offset
        self.size = size
        self.count = count
        self.count_known = count_known

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"name": self.name, "offset": self.offset, "size": self.size}
        if self.count is not None:
            data["count"] = self.count
            data["count_is_approximate"] = not self.count_known
        return data


class Il2CppMetaSummary:
    """The parsed global-metadata summary."""

    __slots__ = ("version", "family", "file_size", "tables", "warnings", "evidence")

    def __init__(
        self,
        version: int,
        family: str,
        file_size: int,
        tables: tuple[Il2CppTable, ...],
        warnings: tuple[str, ...],
        evidence: Evidence,
    ) -> None:
        self.version = version
        self.family = family
        self.file_size = file_size
        self.tables = tables
        self.warnings = warnings
        self.evidence = evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "family": self.family,
            "file_size": self.file_size,
            "table_count": len(self.tables),
            "tables": [t.to_dict() for t in self.tables],
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _family_for(version: int) -> str | None:
    if 24 <= version < 25:
        return "24"
    if 27 <= version < 28:
        return "27"
    if 29 <= version < 30:
        return "29"
    if 31 <= version < 32:
        return "31"
    if 39 <= version < 40:
        return "39"
    return None


def parse_il2cpp_meta(path: str | Path) -> Il2CppMetaSummary:
    """Parse the header-pair structure of a ``global-metadata.dat`` file.

    Raises:
        AnalysisError: non-file input, bad magic, truncated header, or file
            beyond :data:`MAX_FILE_BYTES`.
    """
    p = Path(path)
    if not p.is_file():
        raise AnalysisError(f"path is not a regular file: {p}")
    size = p.stat().st_size
    if size > MAX_FILE_BYTES:
        raise AnalysisError(f"metadata file exceeds the {MAX_FILE_BYTES} byte limit: {size}")
    data = p.read_bytes()
    if len(data) < 8:
        raise AnalysisError(f"metadata file too small ({len(data)} bytes); need at least 8")
    magic, version = struct.unpack_from("<II", data, 0)
    if magic != IL2CPP_MAGIC:
        raise AnalysisError(f"bad IL2CPP magic 0x{magic:08X} (expected 0x{IL2CPP_MAGIC:08X})")

    family = _family_for(version)
    warnings: list[str] = []
    if family is None:
        warnings.append(f"version {version} is not a known family; tables are unnamed")

    named = _FAMILY_TABLES.get(family or "", ())
    if family in {"29", "31", "39"}:
        named = _FAMILY_TABLES["27"] + _V29_EXTRA

    tables: list[Il2CppTable] = []
    cursor = 8
    index = 0
    while cursor + 8 <= len(data) and index < MAX_TABLES:
        offset, table_size = struct.unpack_from("<II", data, cursor)
        cursor += 8
        name = named[index] if index < len(named) else f"pair_{index:02d}"
        count = None
        count_known = False
        stride = _STRIDES.get(name)
        if table_size and stride:
            count = table_size // stride
            count_known = True
        if offset + table_size > len(data):
            warnings.append(f"table {name} (offset {offset}, size {table_size}) overruns the file")
        tables.append(Il2CppTable(name, offset, table_size, count, count_known))
        index += 1
    if cursor + 8 > len(data):
        warnings.append("header pair area reached end-of-file; remaining pairs unread")

    if not family:
        warnings.append("row counts omitted: unknown version family")
    detail = f"version {version} (family {family or chr(39) + 'unknown' + chr(39)}); {len(tables)} header tables"
    if warnings:
        detail += "; " + "; ".join(warnings[:8])
    evidence = Evidence(
        source="meta.il2cpp.deep",
        method="header-pair-walk",
        confidence=Confidence.HIGH,
        detail=detail,
        extra={"version": version, "family": family or "unknown"},
    )
    return Il2CppMetaSummary(
        version=version,
        family=family or "unknown",
        file_size=size,
        tables=tuple(tables),
        warnings=tuple(warnings),
        evidence=evidence,
    )

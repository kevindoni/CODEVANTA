"""MCP tool implementations (plain functions, no MCP imports)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.core.functions import discover_functions
from codevanta.core.report import (
    MAX_DISASSEMBLY_COUNT,
    MAX_STRING_LIMIT,
    AnalysisError,
    build_report,
    disassemble_region,
    load_binary,
    resolve_target,
)
from codevanta.core.strings import StringExtractor


def _validate_path(path: str) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.exists():
        raise AnalysisError(f"file not found: {path}")
    if not candidate.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    return candidate


def binary_info(path: str) -> dict[str, Any]:
    """Return format, architecture, sections, imports, exports, and symbols."""
    return load_binary(_validate_path(path)).to_dict()


def functions(path: str, limit: int = 200) -> dict[str, Any]:
    """Return function candidates with detection source and confidence."""
    if limit < 1 or limit > 100_000:
        raise AnalysisError("limit must be between 1 and 100000")
    info = load_binary(_validate_path(path))
    candidates = discover_functions(info)
    return {
        "count": len(candidates),
        "returned": min(limit, len(candidates)),
        "truncated": len(candidates) > limit,
        "items": [candidate.to_dict() for candidate in candidates[:limit]],
    }


def strings(path: str, min_length: int = 4, limit: int = 200) -> dict[str, Any]:
    """Return ASCII and UTF-16LE strings with file offset and mapped VA."""
    if min_length < 1:
        raise AnalysisError("min_length must be >= 1")
    if limit < 1 or limit > MAX_STRING_LIMIT:
        raise AnalysisError(f"limit must be between 1 and {MAX_STRING_LIMIT}")
    target = _validate_path(path)
    info = load_binary(target)
    results = StringExtractor(min_length=min_length).extract(target, info=info, limit=limit)
    return {
        "count": len(results),
        "limit": limit,
        "items": [item.to_dict() for item in results],
    }


def disasm(
    path: str,
    address: int | None = None,
    function: str | None = None,
    count: int = 50,
) -> dict[str, Any]:
    """Disassemble the entry point, a virtual address, or a named function."""
    if count < 1 or count > MAX_DISASSEMBLY_COUNT:
        raise AnalysisError(f"count must be between 1 and {MAX_DISASSEMBLY_COUNT}")
    target = _validate_path(path)
    info = load_binary(target)
    start = resolve_target(info, address, function)
    result = disassemble_region(target, info, start, count=count)
    return {
        "start": f"0x{start:x}",
        "count": len(result.instructions),
        "truncated": result.truncated,
        "instructions": [instruction.to_dict() for instruction in result.instructions],
        "evidence": result.evidence.to_dict(),
    }


def analyze(path: str, string_limit: int = 5000) -> dict[str, Any]:
    """Return the full phase 1 report with provenance and evidence."""
    return build_report(_validate_path(path), string_limit=string_limit)

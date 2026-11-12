"""MCP tool implementations (plain functions, no MCP imports)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis.cfg import build_cfg
from codevanta.analysis.xrefs import DEFAULT_MAX_BYTES, find_xrefs
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


def xrefs(
    path: str,
    limit: int = 100,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[str, Any]:
    """Return direct-branch cross references with evidence and callee names."""
    if limit < 1 or limit > 100_000:
        raise AnalysisError("limit must be between 1 and 100000")
    if max_bytes < 1:
        raise AnalysisError("max_bytes must be >= 1")
    target = _validate_path(path)
    info = load_binary(target)
    result = find_xrefs(target, info, max_bytes=max_bytes)
    kept = result.xrefs[:limit]
    return {
        "count": len(result.xrefs),
        "returned": len(kept),
        "truncated": len(kept) < len(result.xrefs),
        "xrefs": [xref.to_dict() for xref in kept],
        "scanned_sections": list(result.scanned_sections),
        "scanned_bytes": result.scanned_bytes,
        "scan_truncated": result.truncated,
        "warnings": list(result.warnings),
        "evidence": result.evidence.to_dict(),
    }


def cfg(
    path: str,
    address: int | None = None,
    function: str | None = None,
    max_instructions: int = 2000,
    max_blocks: int = 500,
) -> dict[str, Any]:
    """Build a control-flow graph for the entry point, a virtual address, or a named function."""
    if max_instructions < 1 or max_instructions > MAX_DISASSEMBLY_COUNT:
        raise AnalysisError(f"max_instructions must be between 1 and {MAX_DISASSEMBLY_COUNT}")
    if max_blocks < 1 or max_blocks > MAX_DISASSEMBLY_COUNT:
        raise AnalysisError(f"max_blocks must be between 1 and {MAX_DISASSEMBLY_COUNT}")
    target = _validate_path(path)
    info = load_binary(target)
    start = resolve_target(info, address, function)
    return build_cfg(
        target,
        info,
        start,
        max_instructions=max_instructions,
        max_blocks=max_blocks,
    ).to_dict()

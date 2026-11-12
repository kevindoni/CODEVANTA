"""MCP tool implementations (plain functions, no MCP imports)."""

from __future__ import annotations

import os
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
from codevanta.storage.session import MAX_LIMIT as MAX_SESSION_LIMIT
from codevanta.storage.session import SessionError, SessionStore

#: Environment variable that overrides the default session database location.
SESSION_DB_ENV = "CODEVANTA_DB"

#: Hard ceiling on reportable cross references so one call cannot exhaust memory.
MAX_XREF_LIMIT = 200_000

#: Hard ceiling on executable bytes decoded by one cross-reference scan (64 MiB).
MAX_XREF_BYTES = 64_000_000

#: Default session database file used when no explicit path is supplied.
DEFAULT_SESSION_DB = Path.home() / ".codevanta" / "sessions.db"


def _validate_path(path: str) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.exists():
        raise AnalysisError(f"file not found: {path}")
    if not candidate.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    return candidate


def _resolve_session_db(db: str | Path | None) -> Path:
    """Return ``db``, else ``$CODEVANTA_DB``, else ``~/.codevanta/sessions.db``."""
    if db is not None:
        if isinstance(db, Path):
            return db
        if not isinstance(db, str):
            raise SessionError(
                f"db must be a string or Path, not {type(db).__name__}"
            )
        text = db.strip()
        if not text:
            raise SessionError("db must not be empty")
        return Path(text).expanduser()
    configured = os.environ.get(SESSION_DB_ENV)
    if configured and configured.strip():
        return Path(configured.strip()).expanduser()
    return DEFAULT_SESSION_DB


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
    limit: int = 200,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[str, Any]:
    """Return direct call, jump, and branch cross references with evidence."""
    if limit < 1 or limit > MAX_XREF_LIMIT:
        raise AnalysisError(f"limit must be between 1 and {MAX_XREF_LIMIT}")
    if max_bytes < 1 or max_bytes > MAX_XREF_BYTES:
        raise AnalysisError(f"max_bytes must be between 1 and {MAX_XREF_BYTES}")
    target = _validate_path(path)
    info = load_binary(target)
    result = find_xrefs(target, info, max_bytes=max_bytes)
    total = len(result.xrefs)
    items = [xref.to_dict() for xref in result.xrefs[:limit]]
    return {
        "count": total,
        "returned": len(items),
        "truncated": result.truncated or total > limit,
        "items": items,
        "scanned_bytes": result.scanned_bytes,
        "warnings": list(result.warnings),
    }


def cfg(
    path: str,
    address: int | None = None,
    function: str | None = None,
    max_instructions: int = 2000,
    max_blocks: int = 500,
) -> dict[str, Any]:
    """Build a linear-sweep control-flow graph for an address or named function."""
    if max_instructions < 1 or max_instructions > MAX_DISASSEMBLY_COUNT:
        raise AnalysisError(
            f"max_instructions must be between 1 and {MAX_DISASSEMBLY_COUNT}"
        )
    if max_blocks < 1 or max_blocks > MAX_DISASSEMBLY_COUNT:
        raise AnalysisError(f"max_blocks must be between 1 and {MAX_DISASSEMBLY_COUNT}")
    target = _validate_path(path)
    info = load_binary(target)
    start = resolve_target(info, address, function)
    graph = build_cfg(
        target,
        info,
        start,
        max_instructions=max_instructions,
        max_blocks=max_blocks,
    )
    return {
        "start": f"0x{start:x}",
        "blocks": [block.to_dict() for block in graph.blocks],
        "instruction_count": graph.instruction_count,
        "truncated": graph.truncated,
        "warnings": list(graph.warnings),
    }


def session_save(
    path: str,
    db: str | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    """Analyze a binary and persist its fingerprint and counts as a session."""
    target = _validate_path(path)
    db_path = _resolve_session_db(db)
    info = load_binary(target)
    functions_count = len(discover_functions(info))
    strings_count = len(StringExtractor(min_length=4).extract(target, info=info))
    with SessionStore(db_path) as store:
        record = store.save(info, functions_count, strings_count, notes=notes)
    return {"session": record.to_dict(), "db": str(db_path)}


def session_list(db: str | None = None, limit: int = 20) -> dict[str, Any]:
    """List stored sessions newest first from the session database."""
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise SessionError("limit must be an integer")
    if limit < 1 or limit > MAX_SESSION_LIMIT:
        raise SessionError(f"limit must be between 1 and {MAX_SESSION_LIMIT}")
    db_path = _resolve_session_db(db)
    with SessionStore(db_path) as store:
        records = store.list(limit=limit)
    return {
        "count": len(records),
        "items": [record.to_dict() for record in records],
        "db": str(db_path),
    }

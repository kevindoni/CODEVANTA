"""MCP tools for the webfw lane (no MCP imports).

Two tools: ``codevanta_sourcemap`` (decode a JS source map v3, optionally
trace a generated position back to its original source) and
``codevanta_unpack`` (bounded recursive archive manifest, in memory only).
The registration imports live in :mod:`codevanta.mcp_server.tools`; the
``@server.tool`` wrappers live inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis import sourcemap, unpack
from codevanta.analysis.containers import MAX_FILE_BYTES
from codevanta.core.report import AnalysisError

TOOL_DESCRIPTION_SOURCEMAP = (
    "Decode a JavaScript source map (v3) fully offline and pure Python: "
    "base64-VLQ mappings are decoded into bounded segments (20000 max) and "
    "the original sources, names and sourceRoot are summarised with "
    "truncation flags and evidence. With line and column (0-based generated "
    "position) the nearest mapping at or before that column on that line is "
    "traced back to the original file path, line, column and symbol name; a "
    "miss is an honest hit=false result, never an error. Malformed maps "
    "(bad JSON, version != 3, invalid VLQ, out-of-range indexes) are typed "
    "errors. Nothing is executed."
)

TOOL_DESCRIPTION_UNPACK = (
    "Build a bounded recursive manifest of an archive in memory (nothing is "
    "written to disk): zip and tar (including gz/bz2/xz compressed tars), "
    "single-stream gzip/bzip2/xz payloads and cpio newc archives (headers "
    "only). Nested archives are followed up to depth 4, with 512 entries per "
    "archive and a 64 MiB total byte budget; compression-bomb suspects "
    "(declared/compressed ratio over 1000:1) are listed but never read, and "
    "oversized streams are truncated honestly rather than slurped. Entries "
    "carry path, kind, size and optional sha256 for small leaves. Pure "
    "stdlib parsing; nothing is executed or extracted."
)


def _read_bounded(path: str) -> bytes:
    """Read ``path`` once, refusing missing files and oversize reads."""
    candidate = Path(path).expanduser()
    if not candidate.exists():
        raise AnalysisError(f"file not found: {path}")
    if not candidate.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    size = candidate.stat().st_size
    if size > MAX_FILE_BYTES:
        raise AnalysisError(f"file too large: {size} bytes (limit {MAX_FILE_BYTES})")
    try:
        return candidate.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"cannot read {str(path)!r}: {exc}") from exc


def codevanta_sourcemap(
    path: str, line: int | None = None, column: int | None = None
) -> dict[str, Any]:
    """Decode a JS source map and optionally trace one generated position."""
    data = _read_bounded(path)
    if line is None and column is None:
        return sourcemap.decode_source_map(data).to_dict()
    if line is None or column is None:
        raise AnalysisError(
            "line and column must be provided together to trace a position"
        )
    return sourcemap.trace_position(data, line, column)


def codevanta_unpack(path: str, hashes: bool = True) -> dict[str, Any]:
    """Build a bounded recursive in-memory manifest for an archive file."""
    data = _read_bounded(path)
    return unpack.build_unpack_manifest(data, hashes=hashes).to_dict()

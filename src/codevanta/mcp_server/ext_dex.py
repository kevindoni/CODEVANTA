"""MCP tool for the dex lane (no MCP imports).

One tool: ``codevanta_dex`` (bounded Android DEX header/index-tables
summary). The registration import lives in
:mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrapper lives inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis import dex
from codevanta.core.report import AnalysisError

TOOL_DESCRIPTION_DEX = (
    "Summarise an Android DEX file fully offline and pure Python: the "
    "header (magic versions 035/037/038/039) is parsed with the Adler-32 "
    "checksum verified (mismatch is a warning, not an error), the SHA-1 "
    "signature extracted, and the six index tables (strings/types/protos/"
    "fields/methods/classes) bounded at 8192 ids each. The first 512 MUTF-8 "
    "strings (128 chars each, U+0000 as 0xC0 0x80) plus up to 256 class "
    "descriptors and 256 method samples are kept. Malformed inputs (bad "
    "magic, truncated header or tables, files over 64 MiB) are typed "
    "errors. Nothing is executed."
)


def _read_bounded(path: str) -> bytes:
    """Read ``path`` once, refusing missing files and oversize reads."""
    candidate = Path(path).expanduser()
    if not candidate.exists():
        raise AnalysisError(f"file not found: {path}")
    if not candidate.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    size = candidate.stat().st_size
    if size > dex.MAX_FILE_BYTES:
        raise AnalysisError(
            f"file too large: {size} bytes (limit {dex.MAX_FILE_BYTES})"
        )
    try:
        return candidate.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"cannot read {str(path)!r}: {exc}") from exc


def codevanta_dex(path: str) -> dict[str, Any]:
    """Parse a DEX file's header and index tables into a bounded summary."""
    data = _read_bounded(path)
    return dex.parse_dex(data, source=path).to_dict()

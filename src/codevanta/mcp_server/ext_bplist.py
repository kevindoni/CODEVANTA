"""MCP tool for the bplist lane (no MCP imports).

One tool: ``codevanta_bplist`` (decode an Apple binary property list
``bplist00`` into a bounded value tree). The registration import lives in
:mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrapper lives inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis import bplist
from codevanta.analysis.containers import MAX_FILE_BYTES
from codevanta.core.report import AnalysisError

TOOL_DESCRIPTION_BPLIST = (
    "Decode an Apple binary property list (bplist00) fully offline and pure "
    "Python: the 8-byte magic, marker-typed object table, big-endian offset "
    "table and 32-byte trailer are parsed and the top object is expanded into "
    "a bounded JSON-safe tree of dict/array/string/int/real/bool/date/data "
    "nodes. Bounds are honest: 4096 objects, 64 nesting levels, 512 entries "
    "per collection, 256 characters per string and 64 KiB per data object "
    "(larger data becomes a hex preview plus a truncated flag). Malformed "
    "files (bad magic, truncated trailer, out-of-range object references, "
    "self-referencing cycles, oversize tables) are typed errors. Nothing is "
    "executed."
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


def codevanta_bplist(path: str) -> dict[str, Any]:
    """Decode an Apple binary property list (bplist00) at ``path``."""
    data = _read_bounded(path)
    return bplist.decode_bplist(data).to_dict()

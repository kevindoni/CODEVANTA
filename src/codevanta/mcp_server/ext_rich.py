"""MCP tool exposing the PE Rich header decoder (no MCP imports).

One tool, ``codevanta_rich``: decodes the Rich header between the DOS stub
and the PE signature offline (pure Python) -- XOR key, ``@comp.id`` entries,
object totals and a best-effort compiler guess. The registration import
lives in :mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrapper
lives inside :func:`codevanta.mcp_server.server.build_server` -- imports
alone do not register anything.
"""

from __future__ import annotations

from typing import Any

from codevanta.analysis import rich_header

TOOL_DESCRIPTION_RICH = (
    "Decode a PE file's Rich header offline (pure Python): recover the XOR "
    "key stored right after the Rich marker, walk the @comp.id entry stream "
    "backwards to the DanS marker and report each entry's product id (hex), "
    "build number and object count, the total object count and a best-effort "
    "compiler guess from a table of commonly published product ids (e.g. "
    "'MSVC 14.x link 14.36'); unknown ids stay honest. Bounded to 256 "
    "entries. Always available, nothing is executed."
)


def codevanta_rich(path: str) -> dict[str, Any]:
    """Decode one PE file's Rich header (compiler fingerprint, offline)."""
    return rich_header.inspect_rich_header(path).to_dict()

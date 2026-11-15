"""MCP tools for the lane-assets (no MCP imports).

One tool: ``codevanta_pe_assets`` -- extracts the real visual assets of a PE
(RT_GROUP_ICON/RT_ICON, RT_GROUP_CURSOR/RT_CURSOR, RT_BITMAP) by decoding
their device-independent bitmaps into deterministic PNG artifacts written to
an output directory, with a manifest (dimensions, bit depth, cursor hotspots,
bytes, sha256). The registration import lives in :mod:
`codevanta.mcp_server.tools`; the ``@server.tool`` wrapper lives inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from typing import Any

from codevanta.analysis import winres_assets

TOOL_DESCRIPTION_PE_ASSETS = (
    "Extract the real visual assets of a PE fully offline and pure Python: "
    "RT_GROUP_ICON/RT_ICON, RT_GROUP_CURSOR/RT_CURSOR and RT_BITMAP resources "
    "are decoded from their device-independent bitmaps into PNG files written "
    "to <output_directory> as <group>_<id>_<w>x<h>.png, with a manifest "
    "carrying group name, resource kind, resource id, width, height, bit "
    "depth, cursor hotspots, file bytes and sha256 per asset. Bounded at 128 "
    "assets (32 entries per group); unsupported DIB variants are skipped with "
    "warnings, never crashing; a PE without image resources is a valid empty "
    "result. Nothing is executed."
)


def codevanta_pe_assets(path: str, output_directory: str) -> dict[str, Any]:
    """Extract one PE's icons/bitmaps/cursors as PNG artifacts + manifest."""
    return winres_assets.extract_visual_assets(
        path, output_directory
    ).to_dict()

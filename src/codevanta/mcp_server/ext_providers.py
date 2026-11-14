"""MCP tool exposing the decompiler provider report (no MCP imports).

One tool: ``codevanta_providers``. The registration line lives in
:mod:`codevanta.mcp_server.tools`; the MCP wrapper in
:mod:`codevanta.mcp_server.server` follows the existing tool-spec shape.
"""

from __future__ import annotations

from typing import Any

from codevanta.analysis.decompile_router import provider_report


def codevanta_providers() -> dict[str, Any]:
    """Report decompiler provider availability for this machine (read-only)."""
    return provider_report().to_dict()

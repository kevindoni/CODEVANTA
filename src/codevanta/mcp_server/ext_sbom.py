"""MCP tool exposing the CycloneDX SBOM export (no MCP imports).

One tool: ``codevanta_sbom`` (pure-Python inventory aggregation to a
CycloneDX 1.6 document, always available offline). The registration import
lives in :mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrapper
lives inside :func:`codevanta.mcp_server.server.build_server` -- imports
alone do not register anything.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from codevanta.analysis import sbom


def codevanta_sbom(
    paths: Sequence[str], max_components: int = sbom.DEFAULT_MAX_COMPONENTS
) -> dict[str, Any]:
    """Aggregate CODEVANTA inventories into a CycloneDX 1.6 SBOM document.

    Each path is a PE/ELF/Mach-O binary or a JavaScript application
    directory/.asar archive. Components come from JS external packages
    (versions only when ``package.json`` pins them exactly) and binary
    import libraries; the document is deterministic (serial derived from the
    input hashes, no timestamps), versions are never guessed, and every
    component carries its evidence as a property. Bounded by ``max_files``
    rows with honest truncation flags. Nothing is executed.
    """
    return sbom.build_sbom(
        [Path(p) for p in paths], max_components=max_components
    ).to_dict()

"""MCP tools exposing the SBOM export (no MCP imports).

Two tools: ``codevanta_sbom`` (the native CycloneDX/SPDX document, always
available offline) and ``codevanta_sbom_export`` (the typed, format-tagged
export with bounded package rows and licenses). The registration import
lives in :mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrappers
live inside :func:`codevanta.mcp_server.server.build_server` -- imports
alone do not register anything.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from codevanta.analysis import sbom
from codevanta.core.report import AnalysisError


def codevanta_sbom(
    paths: Sequence[str],
    max_components: int = sbom.DEFAULT_MAX_COMPONENTS,
    format: str = "cyclonedx",
) -> dict[str, Any]:
    """Aggregate CODEVANTA inventories into a deterministic SBOM document.

    Each path is a PE/ELF/Mach-O binary, a JavaScript application
    directory/.asar archive, or a package-manager manifest (npm
    ``package.json``, pip ``requirements.txt``, cargo ``Cargo.toml``, go
    ``go.mod``, maven ``pom.xml``). ``format`` selects the document shape:
    ``cyclonedx`` (CycloneDX 1.6, default) or ``spdx`` (SPDX 2.3 JSON, fixed
    epoch creation timestamp for determinism). Components come from JS
    external packages, manifest dependencies and binary import libraries
    (versions only when pinned exactly); the document is deterministic
    (serial derived from the input hashes, no timestamps), versions are never
    guessed, and every component carries its evidence as a property. Nothing
    is executed.
    """
    report = sbom.build_sbom(
        [Path(p) for p in paths], max_components=max_components
    )
    if format == "spdx":
        return report.to_spdx_dict()
    if format == "cyclonedx":
        return report.to_dict()
    raise AnalysisError(
        f"unsupported format {format!r}; expected one of "
        f"{', '.join(sbom.EXPORT_FORMATS)}"
    )


def codevanta_sbom_export(
    paths: Sequence[str],
    format: str = "cyclonedx",
    max_components: int = sbom.DEFAULT_MAX_COMPONENTS,
    max_packages: int = sbom.MAX_EXPORT_PACKAGES,
) -> dict[str, Any]:
    """Build the typed SBOM export (bounded package rows + licenses).

    Same aggregation as ``codevanta_sbom``, wrapped in the typed export:
    ``packages`` (bounded by ``max_packages``, 1..128) name/version/license
    rows, the sorted ``licenses`` union, honest ``truncated`` flags and the
    format-native ``document`` (CycloneDX 1.6 or SPDX 2.3 JSON). Licenses
    are ``NOASSERTION``: no aggregated source carries license facts.
    """
    report = sbom.build_sbom(
        [Path(p) for p in paths], max_components=max_components
    )
    return sbom.export_sbom(
        report, fmt=format, max_packages=max_packages
    ).to_dict()

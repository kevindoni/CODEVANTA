"""MCP tool for the format-2 lane (no MCP imports).

One tool: ``codevanta_codesign`` -- the Mach-O code-signature structure
summary (LC_CODE_SIGNATURE offset, SuperBlob slot table, code-directory
identifier, entitlements keys, CMS certificate count). Parse-only: no trust
verification happens here or anywhere downstream. The registration import
lives in :mod:`codevanta.mcp_server.tools`; the MCP wrapper in
:mod:`codevanta.mcp_server.server` follows the existing tool-spec shape.
"""

from __future__ import annotations

from typing import Any

from codevanta.analysis.codesign import inspect_codesign
from codevanta.core.report import AnalysisError

__all__ = ["codevanta_codesign"]


def codevanta_codesign(path: str) -> dict[str, Any]:
    """Summarise a Mach-O's embedded code signature (structure only).

    Args:
        path: Path to a thin Mach-O file on this host.

    Returns:
        A JSON-safe payload: ``macho_kind``/``endian``, the signature load
        command's offset and size, the bounded SuperBlob slot table, the
        code-directory ``identifier``, ``team_id`` when the entitlements
        plist carries one, the bounded entitlements key list and a
        certificates count from the CMS blob (no certificate is parsed and
        nothing is verified).

    Raises:
        AnalysisError: When the path does not exist, the file carries a
            malformed signature structure, or the file is a fat
            multi-architecture Mach-O (run the lane on a thin slice).
            Unsigned thin Mach-Os return ``None``-shaped absence via a typed
            "no embedded code signature" error only from the CLI; this tool
            surfaces unsigned binaries as ``{"unsigned": true, ...}``.
    """
    report = inspect_codesign(path)
    if report is None:
        raise AnalysisError(f"no embedded code signature found in {path}")
    return report.to_dict()

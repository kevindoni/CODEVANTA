"""MCP tool exposing the format-metadata inspectors (no MCP imports).

One tool: ``codevanta_metadata``. The registration line lives in
:mod:`codevanta.mcp_server.tools`; the MCP wrapper in
:mod:`codevanta.mcp_server.server` follows the existing tool-spec shape.
"""

from __future__ import annotations

from typing import Any

from codevanta.analysis import binmeta


def codevanta_metadata(path: str) -> dict[str, Any]:
    """Auto-detect format metadata for a file or directory.

    Detects APK signing blocks (v1/v2/v3), Go build info, Rust
    cargo-auditable payloads, Python ``.pyc`` headers (3.7-3.13), Electron
    fuse wires, ELF notes, kernel-module ``.modinfo`` keys, and desktop
    app layouts (Unity, IL2CPP, Unreal, Electron, .NET). Pure Python and
    fully offline. Raises ``AnalysisError`` for unknown or malformed
    inputs.
    """
    return binmeta.inspect_metadata(path).to_dict()

"""MCP tool exposing the capability rules engine (no MCP imports).

One tool: ``codevanta_capabilities`` (pure-Python, file-scope capability
detection over imports/strings/exports/sections, always available offline).
The registration import lives in :mod:`codevanta.mcp_server.tools`; the
``@server.tool`` wrapper lives inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis import capabilities


def codevanta_capabilities(
    path: str,
    extra_rules: str | None = None,
    string_limit: int = 5000,
) -> dict[str, Any]:
    """Detect file-scope capabilities in a binary via bounded rule matching.

    Evaluates the built-in rule pack (plus optional JSON extra rules) against
    the binary's imports, strings, exports and section names: HTTP/TCP
    communication, process creation, registry writes, service installs,
    keylogging, screenshots, reverse-shell and injection candidates, packing
    hints and more. Every match lists exactly which features fired and where
    (import table entries, string offsets) -- the feature evidence is
    certain, the capability conclusion is medium confidence. File scope
    only: no function-level attribution, unlike full capa.
    """
    return capabilities.detect_capabilities(
        Path(path),
        extra_rules=Path(extra_rules) if extra_rules else None,
        string_limit=string_limit,
    ).to_dict()

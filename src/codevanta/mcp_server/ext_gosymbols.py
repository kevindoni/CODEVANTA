"""MCP tool exposing the Go pclntab symbol recovery engine (no MCP imports).

One tool: ``codevanta_gosymbols`` (pure-Python, offline recovery of function
names from a stripped Go binary's pclntab). The registration import lives in
:mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrapper lives inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis import gosymbols


def codevanta_gosymbols(
    path: str, max_functions: int = gosymbols.DEFAULT_MAX_FUNCTIONS
) -> dict[str, Any]:
    """Recover function names from a Go binary's embedded pclntab.

    Locates the pclntab by section name, then a bounded magic scan, walks the
    go1.2 / 1.16 / 1.18+ / 1.20+ layouts, and reports each function's name,
    address and - from 1.16 on - file and line when the tables carry them.
    The go version is an evidence-backed guess; UPX-compressed and
    garble-obfuscated tables are out of scope. Nothing is executed.
    """
    return gosymbols.recover_go_symbols(Path(path), max_functions=max_functions).to_dict()

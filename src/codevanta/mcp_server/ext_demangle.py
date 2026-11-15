"""MCP tool exposing the pure-Python symbol demangler (no MCP imports).

One tool: ``codevanta_demangle`` (auto-detected Itanium / MSVC / Rust /
Swift decoding, offline and bounded). The registration import lives in
:mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrapper lives inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from typing import Any

from codevanta.analysis import demangle


def codevanta_demangle(symbols: list[str]) -> dict[str, Any]:
    """Auto-detect and decode mangled symbols, offline.

    Each symbol's mangling scheme is detected by prefix -- Itanium C++
    (``_Z...``), MSVC C++ (``?...@@``), Rust legacy (``_ZN...17h<hash>E``),
    Rust v0 (``_R...``, RFC 2603) or Swift (``_$s...`` / ``__T...``) -- and
    decoded by a bounded pure-Python parser (nested names, argument and
    return types, template arguments, well-known substitutions,
    constructors/destructors and operators). Undecodable or exotic input is
    never an error: it comes back as ``scheme="unknown"`` or with
    ``complete=false`` plus a note naming exactly what was not decoded.
    Non-string, empty or oversized input is a typed error. Pure string
    parsing; nothing is executed.
    """
    return demangle.demangle_symbols(symbols).to_dict()

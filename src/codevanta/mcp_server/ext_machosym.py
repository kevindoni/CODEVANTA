"""MCP tool for the Mach-O symbol-table lane (no MCP imports).

One tool: ``codevanta_macho_symbols`` (decode the ``LC_SYMTAB`` nlist_64
symbol table of a thin Mach-O, bounded and read-only). The registration
import lives in :mod:`codevanta.mcp_server.tools`; the ``@server.tool``
wrapper lives inside :func:`codevanta.mcp_server.server.build_server` --
imports alone do not register anything.
"""

from __future__ import annotations

from typing import Any

from codevanta.analysis import macho_symbols

TOOL_DESCRIPTION_MACHO_SYMBOLS = (
    "Decode a thin Mach-O's LC_SYMTAB symbol table (nlist_64 entries plus "
    "the NUL-terminated string table), pure Python and offline (nothing "
    "executed). Bounded and read-only: the symtab offset/size and string-"
    "table size straight from the load command, defined symbols (N_SECT/"
    "N_ABS) with section, value, external/private flags and name (bounded "
    "128 chars), undefined external symbols (imports) by name, counts, "
    "truncation flags (1024 entries walked, 256 kept per list) and "
    "HIGH-confidence evidence. Bad magic, a missing LC_SYMTAB, a truncated "
    "symtab/string table or a name offset past the string table end are "
    "typed errors, never a silent zero."
)


def codevanta_macho_symbols(path: str) -> dict[str, Any]:
    """Decode the LC_SYMTAB symbol table of the thin Mach-O at ``path``."""
    return macho_symbols.inspect_macho_symbols(path).to_dict()

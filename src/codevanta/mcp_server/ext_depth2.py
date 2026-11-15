"""MCP tools for the depth-2 format lane (no MCP imports).

Two tools: ``codevanta_pe_deep`` (auto-detects a PE and reports the
resource-section walk plus the load-config/TLS summary in one call) and
``codevanta_elf_macho`` (auto-detects ELF vs Mach-O by magic and returns
either the dynamic-section summary or the dylib load commands). The
registration import lives in :mod:`codevanta.mcp_server.tools`; the
``@server.tool`` wrappers live inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from codevanta.analysis import elf_dynamic, macho_dylibs, pe_loadconfig, pe_resources
from codevanta.core.report import AnalysisError

__all__ = ["codevanta_elf_macho", "codevanta_pe_deep"]

_MACHO_MAGICS = macho_dylibs.MACHO_MAGICS


def codevanta_pe_deep(path: str) -> dict[str, Any]:
    """Parse a PE's resource section and load config in one call (offline).

    Auto-detects the PE container (typed error when the file is not a PE or
    is malformed). A PE without a resource directory or load config reports
    ``resource_table_present: false`` / ``load_config_present: false``
    instead of failing; each summary is bounded and JSON-safe.

    Raises:
        AnalysisError: When the path is missing, the container headers are
            malformed, a resource RVA cannot be mapped, the load-config
            ``Size`` field contradicts the payload, or the TLS callback
            array is unreadable.
    """
    resources = pe_resources.inspect_pe_resources(path)
    loadconfig = pe_loadconfig.inspect_pe_load_config(path)
    return {
        "format": "pe",
        "resources": resources.to_dict(),
        "loadconfig": loadconfig.to_dict(),
    }


def codevanta_elf_macho(path: str) -> dict[str, Any]:
    """Parse an ELF dynamic section or Mach-O dylib commands (offline).

    Auto-detects the container by magic: ``\\x7fELF`` returns the
    ``elf-dynamic`` summary, a Mach-O magic returns the ``macho-dylibs``
    summary. Everything is bounded and read-only.

    Raises:
        AnalysisError: When the path is missing, the magic matches neither
            format (fat Mach-O binaries are out of scope), or the walked
            structure is malformed.
    """
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {target}")
    head = target.read_bytes()[:4]
    if head[:4] == b"\x7fELF":
        return {
            "format": "elf",
            "dynamic": elf_dynamic.inspect_elf_dynamic(target).to_dict(),
        }
    magic = struct.unpack("<I", head)[0] if len(head) == 4 else 0
    if magic in _MACHO_MAGICS:
        return {
            "format": "macho",
            "dylibs": macho_dylibs.inspect_macho_dylibs(target).to_dict(),
        }
    raise AnalysisError(
        f"{target} is neither an ELF nor a thin Mach-O (head {head.hex() or 'empty'})"
    )

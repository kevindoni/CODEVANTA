"""MCP tool exposing the stackstring recovery engine (no MCP imports).

One tool: ``codevanta_stackstrings`` (bounded offline emulation over a
private unicorn CPU, never executing on the host). The registration import
lives in :mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrapper
lives inside :func:`codevanta.mcp_server.server.build_server` -- imports
alone do not register anything.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from codevanta.analysis import stackstrings


def codevanta_stackstrings(
    path: str,
    addresses: Sequence[int] | None = None,
    max_functions: int = 16,
    max_instructions: int = 2000,
    max_strings: int = 32,
) -> dict[str, Any]:
    """Recover stack-constructed strings by bounded offline emulation.

    Each target function's bytes run on a private unicorn CPU (nothing
    executes on the host); emulated stack writes are tracked and printable
    ASCII / UTF-16LE runs in the written span become stackstrings with their
    function, stack offset, encoding and evidence. Results are medium
    confidence: the string provably appeared in emulated memory, but
    emulation is an approximation. Needs the optional ``emulation`` extra
    (``pip install codevanta[emulation]``); its absence is a typed error.
    """
    return stackstrings.extract_stack_strings(
        Path(path),
        addresses=list(addresses) if addresses else None,
        max_functions=max_functions,
        max_instructions=max_instructions,
        max_strings_per_function=max_strings,
    ).to_dict()

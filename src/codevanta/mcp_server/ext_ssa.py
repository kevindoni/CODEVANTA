"""MCP tool exposing the SSA IR view (no MCP imports).

One tool: ``codevanta_ssa`` -- read-only SSA (static single assignment)
construction over the existing recursive CFG for one function region. The
registration import lives in :mod:`codevanta.mcp_server.tools`; the
``@server.tool`` wrapper lives inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis.ir_ssa import (
    DEFAULT_MAX_BLOCKS,
    DEFAULT_MAX_INSTRUCTIONS,
    MAX_BLOCKS,
    MAX_INSTRUCTIONS,
    build_ssa,
)
from codevanta.core.loader import BinaryLoader, BinaryLoadError
from codevanta.core.report import AnalysisError

TOOL_DESCRIPTION_SSA = (
    "Build the typed SSA (static single assignment) view of one function "
    "region. Every register write becomes a versioned SSA value ('rax.3'); "
    "reads bind to the latest definition in walked order, with honest "
    "'undef'/'arg' references when a register was never defined in-region. A "
    "call records its Win64/Win32 argument registers as 'call_args' and "
    "clobbers the ABI-volatile registers (rbx and friends survive). Loop "
    "back-edges mark the target block with loop_boundary=true and a "
    "phi_required live-in set -- NO phi functions are constructed in this "
    "increment, so values inside a loop body still resolve to the single "
    "straight-line version and forward joins read the walked-order value. "
    "Optional type hints come from the type-propagation module. Results are "
    "medium confidence, bounded by max_blocks/max_instructions with honest "
    "truncation flags and warnings, and nothing is executed."
)


def _require_file(path: str) -> Path:
    """Return ``path`` as a :class:`~pathlib.Path` or raise the typed error."""
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {path}")
    return target


def _load_binary(target: Path) -> Any:
    """Load ``target`` and map :class:`BinaryLoadError` onto the typed error."""
    try:
        return BinaryLoader().load(target)
    except BinaryLoadError as exc:
        raise AnalysisError(f"cannot load {target}: {exc}") from exc


def codevanta_ssa(
    path: str,
    address: int,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
) -> dict[str, Any]:
    """Build the read-only SSA view of the function region at ``address``.

    The CFG is rebuilt with the same bounded recursive traversal the
    decompile tool uses, then converted to SSA: versioned register values,
    def-use chains, call clobbers per the Win64/Win32 ABI, FLAGS as a
    pseudo-register, optional type hints, and loop boundaries recorded as
    honest phi-required markers (no phi functions in this increment).
    Nothing is executed; the file is only read.

    Raises:
        AnalysisError: When ``address`` is not a positive integer, a budget
            is out of range, the file is missing, or the address is not
            decodable executable code.
    """
    if isinstance(address, bool) or not isinstance(address, int):
        raise AnalysisError(f"address must be an int, not {type(address).__name__}")
    if address <= 0:
        raise AnalysisError(f"address must be positive, got 0x{address:x}")
    if isinstance(max_blocks, bool) or not isinstance(max_blocks, int):
        raise AnalysisError("max_blocks must be an int")
    if not 1 <= max_blocks <= MAX_BLOCKS:
        raise AnalysisError(
            f"max_blocks must be between 1 and {MAX_BLOCKS}, got {max_blocks}"
        )
    if isinstance(max_instructions, bool) or not isinstance(max_instructions, int):
        raise AnalysisError("max_instructions must be an int")
    if not 1 <= max_instructions <= MAX_INSTRUCTIONS:
        raise AnalysisError(
            f"max_instructions must be between 1 and {MAX_INSTRUCTIONS}, "
            f"got {max_instructions}"
        )
    target = _require_file(path)
    info = _load_binary(target)
    return build_ssa(
        target,
        info,
        address,
        max_instructions=max_instructions,
        max_blocks=max_blocks,
    ).to_dict()

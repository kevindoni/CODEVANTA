"""MCP tool exposing the pseudo-C emitter (no MCP imports).

One tool: ``codevanta_pseudo_c`` -- read-only pseudo-C lowering of the SSA IR
for one function region. The registration import lives in
:mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrapper lives inside
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
from codevanta.analysis.pseudo_c import emit_pseudo_c
from codevanta.core.loader import BinaryLoader, BinaryLoadError
from codevanta.core.report import AnalysisError

TOOL_DESCRIPTION_PSEUDO_C = (
    "Emit readable pseudo-C text for one function region by lowering the "
    "typed SSA IR: every register definition prints as '<id> = <expr>; "
    "reusing the folded expressions (rax.2 = rax.1 + rbx.0;, xor "
    "self-clears to 0, lea builds ptr(...)). Control flow is rendered "
    "structured where the CFG vocabulary allows -- single-latch while loops "
    "from dominance back-edges and if/else diamonds whose arms reconverge at "
    "one merge block -- with an honest linear fallback elsewhere: annotated "
    "'if (left == right) { /* taken */ }' lines (signedness via casts), "
    "calls note their SSA argument registers and a clipped clobber list, "
    "phi joins print as 'id = phi(value @ block N, ...)' statements, and "
    "loop boundaries / undefined reads stay honest comments. Deterministic, "
    "bounded by max_blocks/max_instructions with truncation flags, medium "
    "confidence, offline; nothing is executed."
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


def codevanta_pseudo_c(
    path: str,
    address: int,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
) -> dict[str, Any]:
    """Emit the pseudo-C text of the function region at ``address``.

    The SSA view is rebuilt with the same bounded budgets the SSA tool uses,
    then lowered line-by-line. Raises:
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
    function = build_ssa(
        target,
        info,
        address,
        max_instructions=max_instructions,
        max_blocks=max_blocks,
    )
    return emit_pseudo_c(function).to_dict()

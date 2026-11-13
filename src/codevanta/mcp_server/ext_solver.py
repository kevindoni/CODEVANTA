"""MCP extension tool: solver-backed feasibility for symbolic path exploration.

One tool, :func:`codevanta_symbolic_solve`: it runs the same bounded unicorn
path exploration as ``codevanta symbolic`` and then -- when the optional
z3-solver package is importable -- checks every reported path's branch
constraints with the z3 BitVec solver, prunes the infeasible ones and
annotates the survivors with ``feasible``/``model``/``solver_ms`` (see
:mod:`codevanta.analysis.solver`). Without z3 the tool skip-gates to the
naive evaluation: the payload is exactly the naive exploration plus the
typed warning ``z3 not installed - naive evaluation``, and the tool
description below carries the same note so a client learns it before
calling. Enable the checker with ``python -m pip install z3-solver``.

The tool is registered in :mod:`codevanta.mcp_server.tools` with a single
line; the returned payload mirrors ``codevanta symbolic --json`` plus the
resolved address and the file path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis.solver import (
    DEFAULT_TIMEOUT_MS,
    HAS_Z3,
    Z3_INSTALL_HINT,
    solve_exploration,
)
from codevanta.analysis.symbolic import (
    DEFAULT_MAX_PATHS,
    DEFAULT_MAX_STEPS,
    explore_paths,
)
from codevanta.core.report import AnalysisError, load_binary, resolve_target

#: The one MCP tool this module contributes.
TOOL_NAME = "codevanta_symbolic_solve"

#: Skip-gated note appended to the description when z3 is not importable, so
#: a client sees the naive fallback before it calls.
_SKIP_GATED_NOTE = (
    ""
    if HAS_Z3
    else (
        " z3 is not importable in this environment: the tool skip-gates to the naive "
        "evaluation and returns the naive paths plus a typed warning; install it with "
        f"{Z3_INSTALL_HINT} to enable the feasibility checks."
    )
)

#: Description published for the tool (computed once, at import time).
TOOL_DESCRIPTION = (
    "Explore the paths through one function (bounded unicorn replay, mirroring "
    "'codevanta symbolic --json') and, when z3 is importable, check every path's "
    "branch constraints with the z3 BitVec solver: infeasible paths are pruned "
    "with a warning and survivors carry feasible/model/solver_ms. Every solver "
    "call is time- and memory-bounded." + _SKIP_GATED_NOTE
)


def _validated_target(path: str) -> Path:
    """Resolve one existing file path, else a typed error."""
    candidate = Path(str(path)).expanduser()
    if not candidate.is_file():
        raise AnalysisError(f"no such file: {path}")
    return candidate


def _validated_address(address: int) -> int:
    """Reject a non-positive or non-int start address."""
    if isinstance(address, bool) or not isinstance(address, int):
        raise AnalysisError(f"address must be an int, not {type(address).__name__}")
    if address <= 0:
        raise AnalysisError(f"address must be positive, got 0x{address:x}")
    return address


def codevanta_symbolic_solve(
    path: str,
    address: int | None = None,
    max_paths: int = DEFAULT_MAX_PATHS,
    max_steps: int = DEFAULT_MAX_STEPS,
    solver_mode: str = "auto",
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> dict[str, Any]:
    """Explore one function's paths and solve their branch feasibility.

    Args:
        path: PE or ELF file to read; its bytes only ever run inside the
            emulator, never on the host.
        address: Virtual address to start at; the entry point when omitted.
        max_paths: Path budget for the exploration.
        max_steps: Instruction budget for the whole exploration.
        solver_mode: ``auto`` checks paths with z3 when importable, ``naive``
            never does (the payload is then the plain exploration).
        timeout_ms: Time budget per z3 call.

    Returns:
        The exploration payload (``PathExploration.to_dict()``), the solver
        overlay applied additively (``solver`` section, per-entry
        ``feasible``/``model``/``solver_ms``, pruned paths removed with a
        warning), plus ``path`` and ``address_resolved``.

    Raises:
        AnalysisError: Missing file, bad address or budgets, unsupported
            architecture, a missing unicorn engine, an unknown ``solver_mode``
            or a solver failure -- never a bare ``ImportError``.
    """
    target = _validated_target(path)
    info = load_binary(target)
    requested = None if address is None else _validated_address(address)
    try:
        start = resolve_target(info, requested, None)
        exploration = explore_paths(
            target,
            info,
            start,
            max_paths=max_paths,
            max_steps=max_steps,
        )
        overlay = solve_exploration(
            exploration, mode=solver_mode, timeout_ms=timeout_ms
        )
    except AnalysisError:
        raise
    payload = overlay.augmented_dict(exploration)
    payload["path"] = str(target)
    payload["address_resolved"] = f"0x{start:x}"
    return payload

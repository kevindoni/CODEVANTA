"""Recursive-descent control-flow graph construction (phase 2).

While :mod:`codevanta.analysis.cfg` decodes one contiguous region with a linear
sweep, this module *walks* the code: it seeds a traversal at one start address
(an entry point, a function candidate, or any caller-supplied address) and
follows only statically known direct transfers.

- **Intra-function edges.** Conditional and unconditional jumps whose target is
  a literal become block edges of the function being walked, using the same
  leader/terminator rules as the linear sweep (shared through
  :mod:`codevanta.analysis._shared`).
- **Function boundaries.** A direct ``call`` target is recorded as a discovered
  :class:`~codevanta.core.functions.FunctionCandidate` (source
  ``cfg.recursive_descent``, confidence ``medium``) and enqueued as the next
  function seed — it never becomes an edge in the caller's graph.
- **Unresolved transfers.** Register- and memory-indirect transfers
  (``call rax``, ``jmp qword ptr [...]``) and targets outside executable code
  are reported as :class:`UnresolvedTransfer` records; no edge or function
  boundary is ever guessed for them.

The walk is bounded in four dimensions — instructions, blocks, functions, and
bytes read from disk — and every limit is validated before any decoding starts.
A cut walk is reported through ``RecursiveCFG.truncated`` plus warnings instead
of silently producing a complete-looking graph. The target binary is only ever
read from disk, never executed.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codevanta.analysis._shared import (
    direct_target,
    dropped_targets_warning,
    successors,
    terminator_kind,
    terminator_mnemonic,
    transfer_kind,
)
from codevanta.analysis.cfg import BasicBlock, FunctionCFG, _function_name_for
from codevanta.core.disassembler import Disassembler, DisassemblyError
from codevanta.core.functions import FunctionCandidate
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import MAX_DISASSEMBLY_COUNT, AnalysisError, read_code
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence
from codevanta.ir.instruction import IRInstruction

__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_FUNCTIONS",
    "RecursiveCFG",
    "UnresolvedTransfer",
    "build_recursive_cfg",
]

#: Evidence source label for every finding this module produces.
_SOURCE = "cfg.recursive_descent"

#: Default ceiling on how many bytes the walk may read from disk.
DEFAULT_MAX_BYTES = 1_000_000

#: Default ceiling on how many functions (seeds) one walk may traverse.
DEFAULT_MAX_FUNCTIONS = 32

#: Bytes fetched from disk per decode window. x86 instructions are at most 16
#: bytes, so one window usually covers a whole basic block; longer runs simply
#: continue with another window at the stopping address.
_WINDOW_BYTES = 256

#: How many call sites to name in a discovered boundary's evidence detail.
_MAX_CALL_SITES_IN_DETAIL = 4


@dataclass(frozen=True)
class UnresolvedTransfer:
    """A transfer whose target could not be resolved statically.

    Attributes:
        address: Virtual address of the transfer instruction.
        kind: ``"call"``, ``"jump"`` or ``"branch"``.
        mnemonic: The transfer mnemonic, e.g. ``"call"``.
        text: Full instruction text, e.g. ``"call rax"``.
        reason: Why the target is unknown, e.g. ``"indirect operand"``.
        evidence: Evidence record; no edge or boundary was derived from this.
    """

    address: int
    kind: str
    mnemonic: str
    text: str
    reason: str
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize the unresolved transfer for the JSON report."""
        return {
            "address": f"0x{self.address:x}",
            "kind": self.kind,
            "mnemonic": self.mnemonic,
            "text": self.text,
            "reason": self.reason,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class RecursiveCFG:
    """Result of one recursive-descent walk.

    Attributes:
        start: The caller-supplied seed address.
        functions: One :class:`FunctionCFG` per function actually walked, in
            walk order (the seed function first).
        discovered: Function-boundary candidates derived from direct call
            targets, sorted by address. The seed itself is not included unless
            the code contains a direct call to it.
        unresolved: Transfers whose target is not statically known.
        visited_instructions: Instructions decoded across all functions. A
            branch into the middle of an already decoded block re-decodes that
            range, so overlapping blocks count their instructions twice.
        truncated: ``True`` when any budget cut the walk short.
        evidence: Evidence for the walk as a whole.
        warnings: Global caveats (budget exhaustion, seeds not walked, ...).
    """

    start: int
    functions: list[FunctionCFG]
    discovered: list[FunctionCandidate]
    unresolved: list[UnresolvedTransfer]
    visited_instructions: int
    truncated: bool
    evidence: Evidence
    warnings: tuple[str, ...] = ()

    @property
    def block_count(self) -> int:
        """Total number of blocks across all walked functions."""
        return sum(len(function.blocks) for function in self.functions)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the walk for the JSON report."""
        return {
            "start": f"0x{self.start:x}",
            "function_count": len(self.functions),
            "block_count": self.block_count,
            "visited_instructions": self.visited_instructions,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "functions": [function.to_dict() for function in self.functions],
            "discovered_functions": [candidate.to_dict() for candidate in self.discovered],
            "unresolved_transfers": [transfer.to_dict() for transfer in self.unresolved],
            "evidence": self.evidence.to_dict(),
        }


@dataclass
class _WalkState:
    """Mutable budgets and findings shared by every function walk."""

    instructions_left: int
    blocks_left: int
    bytes_left: int
    max_instructions: int
    max_blocks: int
    max_bytes: int
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)
    unresolved: dict[int, UnresolvedTransfer] = field(default_factory=dict)
    call_sites: dict[int, list[int]] = field(default_factory=dict)
    pending_seeds: deque[int] = field(default_factory=deque)
    queued_seeds: set[int] = field(default_factory=set)

    def note_budget(self, message: str) -> None:
        """Flag truncation and record ``message`` once."""
        self.truncated = True
        if message not in self.warnings:
            self.warnings.append(message)

    def add_unresolved(
        self, instruction: IRInstruction, kind: str, reason: str
    ) -> None:
        """Record a transfer whose target is not statically known."""
        if instruction.address in self.unresolved:
            return
        self.unresolved[instruction.address] = UnresolvedTransfer(
            address=instruction.address,
            kind=kind,
            mnemonic=instruction.mnemonic,
            text=instruction.text,
            reason=reason,
            evidence=Evidence(
                source=_SOURCE,
                method="unresolved_transfer",
                confidence=Confidence.MEDIUM,
                address=instruction.address,
                detail=f"target not statically known ({reason}); no edge or boundary derived",
            ),
        )

    def record_call(self, target: int, from_address: int) -> None:
        """Remember that the instruction at ``from_address`` calls ``target``."""
        self.call_sites.setdefault(target, []).append(from_address)

    def enqueue_function(self, address: int) -> None:
        """Queue ``address`` as the next function seed, deduplicated."""
        if address not in self.queued_seeds:
            self.queued_seeds.add(address)
            self.pending_seeds.append(address)


def build_recursive_cfg(
    path: str | Path,
    info: BinaryInfo,
    start: int,
    *,
    max_instructions: int = 2000,
    max_blocks: int = 500,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> RecursiveCFG:
    """Build CFGs by recursive descent from a single seed address.

    The walk follows only statically known direct transfers: jump targets
    become intra-function block edges, direct call targets become discovered
    function-boundary candidates (and the next walk seeds), and everything
    else stays explicitly unresolved.

    Args:
        path: File the bytes are read from (read-only; never executed).
        info: Loaded binary metadata used for address mapping and decoding.
        start: Virtual address of the seed (entry point, function candidate,
            or any caller-supplied address); must be inside an executable
            section.
        max_instructions: Total instruction budget across all functions
            (1 .. ``MAX_DISASSEMBLY_COUNT``).
        max_blocks: Total block budget across all functions (>= 1).
        max_functions: Maximum number of functions (seeds) to walk (>= 1).
        max_bytes: Hard ceiling on bytes read from disk during the walk.

    Returns:
        The :class:`RecursiveCFG` with per-function graphs, discovered
        boundaries, unresolved transfers, and honest truncation flags.

    Raises:
        AnalysisError: When ``start`` is not executable code, when a limit is
            out of range, or when the architecture cannot be disassembled.
    """
    for name, value in (
        ("max_instructions", max_instructions),
        ("max_blocks", max_blocks),
        ("max_functions", max_functions),
    ):
        if value < 1:
            raise AnalysisError(f"{name} must be >= 1")
        if value > MAX_DISASSEMBLY_COUNT:
            raise AnalysisError(f"{name} too large (limit {MAX_DISASSEMBLY_COUNT})")
    if max_bytes < 1:
        raise AnalysisError("max_bytes must be >= 1")

    section = info.section_for_va(start)
    if section is None or not section.is_executable:
        raise AnalysisError(f"address 0x{start:x} is not inside an executable section")

    try:
        disassembler = Disassembler(info.architecture, info.bitness, info.endianness)
    except DisassemblyError as exc:
        raise AnalysisError(f"cannot disassemble 0x{start:x}: {exc}") from exc

    state = _WalkState(
        instructions_left=max_instructions,
        blocks_left=max_blocks,
        bytes_left=max_bytes,
        max_instructions=max_instructions,
        max_blocks=max_blocks,
        max_bytes=max_bytes,
    )
    functions: list[FunctionCFG] = []
    visited_functions: set[int] = set()
    state.enqueue_function(start)

    while state.pending_seeds:
        if len(functions) >= max_functions:
            state.truncated = True
            state.warnings.append(
                f"function limit reached (max_functions={max_functions}); "
                f"{len(state.pending_seeds)} discovered seed(s) not walked"
            )
            break
        if (
            state.instructions_left <= 0
            or state.blocks_left <= 0
            or state.bytes_left <= 0
        ):
            state.truncated = True
            state.warnings.append(
                "a budget was exhausted before "
                f"{len(state.pending_seeds)} discovered seed(s) could be walked"
            )
            break
        seed = state.pending_seeds.popleft()
        if seed in visited_functions:
            continue
        visited_functions.add(seed)
        functions.append(_walk_function(path, info, disassembler, seed, state))

    discovered = [
        _boundary_candidate(target, sites) for target, sites in sorted(state.call_sites.items())
    ]
    visited_instructions = sum(graph.instruction_count for graph in functions)
    block_count = sum(len(graph.blocks) for graph in functions)
    return RecursiveCFG(
        start=start,
        functions=functions,
        discovered=discovered,
        unresolved=list(state.unresolved.values()),
        visited_instructions=visited_instructions,
        truncated=state.truncated,
        evidence=Evidence(
            source=_SOURCE,
            method="recursive_descent",
            confidence=Confidence.MEDIUM,
            address=start,
            detail=(
                f"recursive descent from 0x{start:x} walked {len(functions)} function(s) "
                f"into {block_count} block(s) covering {visited_instructions} instruction(s); "
                "boundaries and edges are heuristic"
            ),
        ),
        warnings=tuple(state.warnings),
    )


def _walk_function(
    path: str | Path,
    info: BinaryInfo,
    disassembler: Disassembler,
    seed: int,
    state: _WalkState,
) -> FunctionCFG:
    """Walk one function from ``seed`` and return its control-flow graph."""
    warnings: list[str] = []
    block_instructions: dict[int, list[IRInstruction]] = {}
    known_leaders: set[int] = {seed}
    frontier: deque[int] = deque([seed])
    function_truncated = False

    while frontier:
        if state.blocks_left <= 0:
            state.note_budget(
                f"block limit reached (max_blocks={state.max_blocks}); "
                "later blocks were not reported"
            )
            function_truncated = True
            break
        if state.instructions_left <= 0:
            state.note_budget(
                f"instruction budget reached (max_instructions={state.max_instructions}); "
                "the walk stopped early"
            )
            function_truncated = True
            break
        current = frontier.popleft()
        run, reason = _decode_run(
            path, info, disassembler, current, known_leaders, state, warnings
        )
        if not run:
            warnings.append(f"no instructions decoded at 0x{current:x}")
            continue
        state.blocks_left -= 1
        block_instructions[current] = run
        _follow_transfers(run, reason, info, state, frontier, known_leaders)

    blocks, dropped = _finalize_blocks(block_instructions)
    dropped_warning = dropped_targets_warning(dropped)
    if dropped_warning:
        warnings.append(dropped_warning)
    instruction_count = sum(len(run) for run in block_instructions.values())
    return FunctionCFG(
        function_address=seed,
        function_name=_function_name_for(info, seed),
        blocks=blocks,
        instruction_count=instruction_count,
        truncated=function_truncated,
        evidence=Evidence(
            source=_SOURCE,
            method="recursive_descent",
            confidence=Confidence.MEDIUM,
            address=seed,
            detail=(
                f"recursive descent decoded {instruction_count} instruction(s) into "
                f"{len(blocks)} block(s); block boundaries are heuristic "
                "(leader/terminator rules, phase 2)"
            ),
        ),
        warnings=tuple(warnings),
    )


def _decode_run(
    path: str | Path,
    info: BinaryInfo,
    disassembler: Disassembler,
    address: int,
    known_leaders: set[int],
    state: _WalkState,
    warnings: list[str],
) -> tuple[list[IRInstruction], str]:
    """Decode one instruction run from ``address`` until a block boundary.

    Returns the decoded instructions and why the run stopped:

    - ``"terminator"``: the last instruction ends the block (``ret``, jumps).
    - ``"leader"``: the next decoded instruction opens another block.
    - ``"budget"``: the instruction or byte budget cut the run short.
    - ``"undecodable"``: bytes at the cursor cannot be decoded.
    - ``"no_bytes"``: the cursor has no file bytes (section end or unmapped).
    """
    run: list[IRInstruction] = []
    cursor = address
    while True:
        if state.instructions_left <= 0:
            state.note_budget(
                f"instruction budget reached (max_instructions={state.max_instructions}); "
                "the walk stopped early"
            )
            return run, "budget"
        if state.bytes_left <= 0:
            state.note_budget(
                f"byte budget exhausted (max_bytes={state.max_bytes}); "
                "the walk stopped early"
            )
            return run, "budget"
        try:
            window = read_code(
                path, info, cursor, min(_WINDOW_BYTES, state.bytes_left)
            )
        except (AnalysisError, OSError) as exc:
            warnings.append(f"no file bytes at 0x{cursor:x} ({exc})")
            return run, "no_bytes"
        if not window:
            warnings.append(f"no file bytes at 0x{cursor:x}")
            return run, "no_bytes"
        state.bytes_left -= len(window)
        try:
            result = disassembler.disassemble(
                window, base_address=cursor, max_instructions=state.instructions_left
            )
        except DisassemblyError as exc:
            warnings.append(f"cannot decode 0x{cursor:x}: {exc}")
            return run, "undecodable"
        if not result.instructions:
            warnings.append(
                f"cannot decode instruction at 0x{cursor:x}; the walk stops along this path"
            )
            return run, "undecodable"
        for instruction in result.instructions:
            if instruction.address != address and instruction.address in known_leaders:
                return run, "leader"
            run.append(instruction)
            state.instructions_left -= 1
            if terminator_kind(instruction.mnemonic) is not None:
                return run, "terminator"
            if state.instructions_left <= 0:
                state.note_budget(
                    f"instruction budget reached "
                    f"(max_instructions={state.max_instructions}); the walk stopped early"
                )
                return run, "budget"
        # The whole window decoded without a terminator: keep decoding from the
        # next address. A fresh window also disambiguates a window edge cut
        # mid-instruction from genuinely undecodable bytes.
        cursor = run[-1].address + run[-1].size


def _follow_transfers(
    run: list[IRInstruction],
    reason: str,
    info: BinaryInfo,
    state: _WalkState,
    frontier: deque[int],
    known_leaders: set[int],
) -> None:
    """Queue block frontiers and function seeds for one freshly decoded run."""

    def enqueue(block_address: int) -> None:
        if block_address not in known_leaders:
            known_leaders.add(block_address)
            frontier.append(block_address)

    last = run[-1]
    kind = terminator_kind(last.mnemonic)
    if kind == "jmp":
        _follow_jump(last, kind, info, enqueue, state)
    elif kind == "cond":
        enqueue(last.address + last.size)
        _follow_jump(last, kind, info, enqueue, state)
    elif reason == "leader":
        # The run stopped because the next instruction opens another block.
        enqueue(last.address + last.size)
    # A "ret" terminator ends the path; runs stopped by a budget, undecodable
    # bytes, or missing bytes have no continuation to queue.

    for instruction in run:
        if transfer_kind(instruction.mnemonic) != "call":
            continue
        target = direct_target(instruction.operands)
        if target is None:
            state.add_unresolved(instruction, "call", "indirect operand")
        elif _is_executable(info, target):
            state.record_call(target, instruction.address)
            state.enqueue_function(target)
        else:
            state.add_unresolved(instruction, "call", "target is outside executable code")


def _follow_jump(
    last: IRInstruction,
    kind: str,
    info: BinaryInfo,
    enqueue: Callable[[int], None],
    state: _WalkState,
) -> None:
    """Enqueue the direct target of a jump terminator, or record it unresolved."""
    target = direct_target(last.operands)
    if target is None:
        state.add_unresolved(
            last, "jump" if kind == "jmp" else "branch", "indirect operand"
        )
    elif _is_executable(info, target):
        enqueue(target)
    # A statically known target outside executable code cannot become a block;
    # ``_finalize_blocks`` drops the edge and the dropped-targets warning
    # reports the address.


def _finalize_blocks(
    block_instructions: dict[int, list[IRInstruction]],
) -> tuple[list[BasicBlock], list[int]]:
    """Turn decoded runs into address-sorted blocks with successor edges."""
    dropped: list[int] = []
    blocks: list[BasicBlock] = []
    block_starts = set(block_instructions)
    for start in sorted(block_instructions):
        chunk = block_instructions[start]
        blocks.append(
            BasicBlock(
                start=start,
                end=chunk[-1].address + chunk[-1].size,
                instructions=[instruction.to_dict() for instruction in chunk],
                successors=successors(chunk[-1], block_starts, dropped),
                terminator=terminator_mnemonic(chunk[-1].mnemonic),
                evidence=Evidence(
                    source=_SOURCE,
                    method="basic_block",
                    confidence=Confidence.MEDIUM,
                    address=start,
                    detail=f"{len(chunk)} instructions",
                ),
            )
        )
    return blocks, dropped


def _is_executable(info: BinaryInfo, address: int) -> bool:
    """Return whether ``address`` falls inside an executable section."""
    section = info.section_for_va(address)
    return section is not None and section.is_executable


def _boundary_candidate(target: int, sites: list[int]) -> FunctionCandidate:
    """Build the function-boundary candidate for one direct call target."""
    unique_sites = list(dict.fromkeys(sites))
    shown = ", ".join(f"0x{site:x}" for site in unique_sites[:_MAX_CALL_SITES_IN_DETAIL])
    extra = (
        f" (+{len(unique_sites) - _MAX_CALL_SITES_IN_DETAIL} more)"
        if len(unique_sites) > _MAX_CALL_SITES_IN_DETAIL
        else ""
    )
    return FunctionCandidate(
        address=target,
        name=None,
        size=None,
        source=_SOURCE,
        confidence=Confidence.MEDIUM,
        evidence=Evidence(
            source=_SOURCE,
            method="direct_call_target",
            confidence=Confidence.MEDIUM,
            address=target,
            detail=f"direct call from {shown}{extra}; boundary not proven",
        ),
    )

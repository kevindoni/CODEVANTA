"""Control-flow graph construction by linear sweep (phase 2).

This module is a *phase 2* analysis step. It decodes one contiguous region of
an executable section with :class:`~codevanta.core.disassembler.Disassembler`
and derives basic blocks from purely local rules:

1. **Linear sweep.** ``max_instructions`` instruction slots are read from the
   file (bounded by the section's file-backed bytes) and decoded sequentially
   from ``start``. The sweep stops at ``max_instructions`` or at the end of the
   section; ``FunctionCFG.truncated`` says whether the sweep stopped early.
2. **Leaders.** ``start``; the instruction that follows any terminator; and the
   direct target of a branch when that target is itself a decoded instruction
   address.
3. **Blocks.** Consecutive instructions between two leaders form one
   :class:`BasicBlock`; the block ``end`` is the address just past its last
   instruction (exclusive).
4. **Successors.** ``ret``-like instructions and unconditional jumps have no
   fallthrough; conditional jumps and ordinary instructions fall through to the
   next instruction; unconditional and conditional jumps additionally gain
   their direct branch target. Successors are deduplicated, sorted, and always
   reference a decoded block start.

The sweep is deliberately conservative: block boundaries, terminators, and
successors are heuristic (mnemonic based), never proof of the true control
flow. Every block and the function carry :class:`Evidence` stating exactly how
they were produced, and the target binary is only ever read, never executed.
Indirect branches (``jmp rax``, ``jmp qword ptr [...]``, jump tables) are not
resolved in phase 2, so their blocks end with an unresolved terminator.

:func:`build_recursive_cfg` offers the same block model from a different
traversal: instead of sweeping a contiguous window it *follows* control flow
from ``start`` with a worklist of block starts and a visited set, so
unreachable bytes (padding, alignment tables, data embedded in ``.text``) are
never reported as code. ``build_cfg`` stays the flat-window baseline.

A traversal can decode one block *past* a leader it only discovers later (a
backward ``jmp`` into the middle of an already decoded run). A post-traversal
split pass therefore cuts every block at the leaders inside it, so the reported
ranges are disjoint and every instruction address is reported exactly once.

:func:`build_recursive_cfg` can *optionally* resolve indirect jumps through
pointer tables (``jmp qword ptr [rip + disp]``, ``jmp qword ptr [abs]``) with
:func:`codevanta.analysis.jump_tables.resolve_jump_table`. The behaviour is
opt-in (``resolve_indirect=False`` by default, so every pre-existing call and
its results are unchanged): when enabled, the memory operand is turned into an
absolute table address, the table is decoded, and the executable targets become
successors -- deduplicated, sorted and followed by the traversal like any other
leader. Resolution is bounded per traversal (``max_jump_tables`` tables,
``max_table_entries`` slots each). Register-indirect jumps (``jmp rax``,
``jmp qword ptr [rax]``), unresolvable expressions and tables beyond the budget
leave the block without those successors and are reported once through
``FunctionCFG.warnings``. Nothing is executed; a table is only read through the
containing section's file bytes.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.analysis.jump_tables import MAX_ENTRIES as _JUMP_TABLE_MAX_ENTRIES
from codevanta.analysis.jump_tables import resolve_jump_table
from codevanta.core.disassembler import Disassembler, DisassemblyError
from codevanta.core.functions import discover_functions
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import MAX_DISASSEMBLY_COUNT, AnalysisError, read_code
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence
from codevanta.ir.instruction import IRInstruction

__all__ = ["BasicBlock", "FunctionCFG", "build_cfg", "build_recursive_cfg"]

#: Widest instruction any supported architecture can decode (x86 allows 15).
_MAX_INSTRUCTION_BYTES = 16

#: Decode window for a single recursively traversed block. A block normally
#: ends at a terminator long before this, so the cap only bounds pathological
#: runs of unterminated instructions (such a run is simply split into more
#: blocks at the fallthrough, which yields the same successors).
_MAX_BLOCK_INSTRUCTIONS = 256

#: Mnemonics that unconditionally end a block and never fall through.
_RET_MNEMONICS = frozenset(
    {"ret", "retn", "retf", "retq", "iret", "iretd", "iretq", "eret"}
)

#: Unconditional jump mnemonics per supported architecture (x86 / ARM / AArch64).
_UNCONDITIONAL_JUMPS = frozenset({"jmp", "ljmp", "b", "br", "bx"})

#: Conditional branch mnemonics that are not covered by a ``j``/``b.`` prefix.
_CONDITIONAL_JUMP_MNEMONICS = frozenset(
    {
        # AArch64 compare-and-branch / test-and-branch
        "cbz",
        "cbnz",
        "tbz",
        "tbnz",
        # ARM (A32/T32) conditional branches, written without the "b." infix
        "beq",
        "bne",
        "bhs",
        "blo",
        "bcs",
        "bcc",
        "bmi",
        "bpl",
        "bvs",
        "bvc",
        "bhi",
        "bls",
        "bge",
        "blt",
        "bgt",
        "ble",
        "bal",
    }
)


#: Default cap on jump tables resolved during one recursive traversal.
_DEFAULT_MAX_JUMP_TABLES = 8

#: Default cap on pointer slots decoded from a single jump table.
_DEFAULT_MAX_TABLE_ENTRIES = 256

#: ``ptr`` size keyword that denotes a pointer-sized memory read, by width.
_POINTER_SIZE_KEYWORDS = {4: "dword", 8: "qword"}


@dataclass(frozen=True)
class BasicBlock:
    """A single-entry run of instructions with its outgoing edges.

    Attributes:
        start: Virtual address of the first instruction in the block.
        end: Virtual address just past the last instruction (exclusive).
        instructions: Decoded instructions as ``IRInstruction.to_dict()`` data.
        successors: Sorted, deduplicated successor block addresses.
        terminator: Mnemonic of the block's final instruction when it ends the
            block unconditionally or conditionally, else ``None``.
        evidence: How this block was derived.
    """

    start: int
    end: int
    instructions: list[dict[str, Any]]
    successors: tuple[int, ...]
    terminator: str | None
    evidence: Evidence

    @property
    def instruction_count(self) -> int:
        """Number of instructions in the block."""
        return len(self.instructions)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the block for the JSON report."""
        return {
            "start": f"0x{self.start:x}",
            "end": f"0x{self.end:x}",
            "instruction_count": self.instruction_count,
            "terminator": self.terminator,
            "successors": [f"0x{address:x}" for address in self.successors],
            "instructions": list(self.instructions),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class FunctionCFG:
    """Control-flow graph for one function region.

    Attributes:
        function_address: Requested start address (also the entry block start).
        function_name: Name from function discovery when a candidate starts at
            ``function_address``, else ``None``.
        blocks: Blocks in ascending address order with disjoint ranges.
        instruction_count: Total number of decoded instructions; for
            :func:`build_recursive_cfg` this counts *unique* instruction
            addresses across the disjoint blocks.
        truncated: ``True`` when instruction decoding or block reporting was
            cut short by a limit, so the graph may be incomplete.
        evidence: How the graph as a whole was derived.
        warnings: Human-readable caveats about the sweep.
    """

    function_address: int
    function_name: str | None
    blocks: list[BasicBlock]
    instruction_count: int
    truncated: bool
    evidence: Evidence
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize the CFG for the JSON report."""
        return {
            "function_address": f"0x{self.function_address:x}",
            "function_name": self.function_name,
            "block_count": len(self.blocks),
            "instruction_count": self.instruction_count,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "blocks": [block.to_dict() for block in self.blocks],
            "evidence": self.evidence.to_dict(),
        }


def build_cfg(
    path: str | Path,
    info: BinaryInfo,
    start: int,
    max_instructions: int = 2000,
    max_blocks: int = 500,
) -> FunctionCFG:
    """Build a CFG for the region starting at ``start`` by linear sweep.

    Args:
        path: File the bytes are read from (read-only; never executed).
        info: Loaded binary metadata used for address mapping and decoding.
        start: Virtual address of the first instruction; must be inside an
            executable section.
        max_instructions: Instruction budget for the sweep (1 ..
            ``MAX_DISASSEMBLY_COUNT``).
        max_blocks: Maximum number of blocks to report (>= 1). When the sweep
            yields more blocks the graph is cut and marked ``truncated``.

    Returns:
        The reconstructed :class:`FunctionCFG`.

    Raises:
        AnalysisError: When ``start`` is not executable code, when a limit is
            out of range, when the start address has no file bytes, or when the
            architecture cannot be disassembled.
    """
    if max_instructions < 1:
        raise AnalysisError("max_instructions must be >= 1")
    if max_instructions > MAX_DISASSEMBLY_COUNT:
        raise AnalysisError(f"max_instructions too large (limit {MAX_DISASSEMBLY_COUNT})")
    if max_blocks < 1:
        raise AnalysisError("max_blocks must be >= 1")
    if max_blocks > MAX_DISASSEMBLY_COUNT:
        raise AnalysisError(f"max_blocks too large (limit {MAX_DISASSEMBLY_COUNT})")

    section = info.section_for_va(start)
    if section is None or not section.is_executable:
        raise AnalysisError(f"address 0x{start:x} is not inside an executable section")

    code = read_code(path, info, start, max_instructions * _MAX_INSTRUCTION_BYTES)
    try:
        disassembler = Disassembler(info.architecture, info.bitness, info.endianness)
        result = disassembler.disassemble(
            code,
            base_address=start,
            max_instructions=max_instructions,
        )
    except DisassemblyError as exc:
        raise AnalysisError(f"cannot disassemble 0x{start:x}: {exc}") from exc

    instructions = list(result.instructions)
    warnings: list[str] = []
    truncated = bool(result.truncated)
    if truncated:
        warnings.append(
            f"linear sweep stopped after {len(instructions)} instruction(s) "
            f"(max_instructions={max_instructions}); the graph may be incomplete"
        )
    elif instructions and result.consumed_bytes < len(code):
        warnings.append(
            f"linear sweep stopped at 0x{start + result.consumed_bytes:x} before the end "
            "of the section (undecodable bytes)"
        )

    blocks, blocks_truncated, block_warnings = _split_blocks(instructions, max_blocks)
    truncated = truncated or blocks_truncated
    warnings.extend(block_warnings)
    if not instructions:
        warnings.append(f"no instructions decoded at 0x{start:x}")

    evidence = Evidence(
        source="cfg.linear_sweep",
        method="linear_sweep",
        confidence=Confidence.MEDIUM,
        address=start,
        detail=(
            f"linear sweep decoded {len(instructions)} instruction(s) into {len(blocks)} "
            "block(s); block boundaries are heuristic (leader/terminator rules, phase 2)"
        ),
    )
    return FunctionCFG(
        function_address=start,
        function_name=_function_name_for(info, start),
        blocks=blocks,
        instruction_count=len(instructions),
        truncated=truncated,
        evidence=evidence,
        warnings=tuple(warnings),
    )


def build_recursive_cfg(
    path: str | Path,
    info: BinaryInfo,
    start: int,
    max_instructions: int = 2000,
    max_blocks: int = 500,
    resolve_indirect: bool = False,
    max_jump_tables: int = _DEFAULT_MAX_JUMP_TABLES,
    max_table_entries: int = _DEFAULT_MAX_TABLE_ENTRIES,
) -> FunctionCFG:
    """Build a CFG by *following* control flow from ``start`` (recursive traversal).

    Unlike :func:`build_cfg` this never sweeps a contiguous window: a worklist
    of block starts plus a visited set drive the traversal, so only code
    reachable from ``start`` becomes a block.

    Traversal rules:

    1. **Worklist.** ``start`` is the first leader. Each block is decoded from
       its leader until a terminator mnemonic, the instruction budget, an
       already-visited leader (the block ends just before it), or the end of an
       executable section.
    2. **Successors.** A conditional jump leads to its fallthrough *and* its
       direct target, an unconditional jump to its direct target only (no
       fallthrough), a return to nothing, and any other instruction to its
       fallthrough. Only targets inside an executable, file-backed section are
       kept.
    3. **Calls stay flat.** ``call`` is an ordinary instruction: the return
       address is the fallthrough and the callee is *not* followed.
    4. **Bounded.** ``max_instructions`` caps decoded instructions and
       ``max_blocks`` caps reported blocks; the visited set plus the worklist
       make cycles terminate. Hitting either limit marks the graph
       ``truncated``.
    5. **Disjoint blocks.** Traversal hypotheses can overlap: a block decoded
       before a backward ``jmp`` is discovered runs past that target. A post-
       traversal split pass cuts every block at the leaders inside it (a split
       leading segment falls through to the split address and has no
       terminator, the trailing segment keeps the original terminator and
       successors), then keeps the most complete block per start address. The
       reported ranges therefore never overlap and ``instruction_count`` counts
       unique instruction addresses.
    6. **Indirect jumps (opt-in).** With ``resolve_indirect=True`` an indirect
       ``jmp`` through a pointer-sized memory operand (``jmp qword ptr [rip +
       disp]`` or ``jmp qword ptr [abs]``) becomes a jump-table lookup: the
       operand is turned into an absolute table address and
       :func:`~codevanta.analysis.jump_tables.resolve_jump_table` decodes up to
       ``max_table_entries`` slots from it. Executable, file-backed targets
       become that block's successors (deduplicated, sorted) and are followed
       like any other leader. At most ``max_jump_tables`` tables are resolved
       per traversal; register/indexed operands, unreadable tables and tables
       past the budget leave the block without those successors, and every such
       limitation is reported once (prefixed with the block start) in
       :attr:`FunctionCFG.warnings`. Nothing is executed.

    Args:
        path: File the bytes are read from (read-only; never executed).
        info: Loaded binary metadata used for address mapping and decoding.
        start: Virtual address of the first instruction; must be inside an
            executable section.
        max_instructions: Total instruction budget (1 ..
            ``MAX_DISASSEMBLY_COUNT``).
        max_blocks: Maximum number of blocks to report (1 ..
            ``MAX_DISASSEMBLY_COUNT``).
        resolve_indirect: When true, indirect jumps through a pointer table are
            resolved (see rule 6). ``False`` (the default) keeps the historical
            behaviour exactly: an indirect jump simply has no successor and is
            counted as unresolved.
        max_jump_tables: Maximum number of jump tables resolved during this
            traversal (1 .. ``MAX_DISASSEMBLY_COUNT``); ignored unless
            ``resolve_indirect`` is true.
        max_table_entries: Maximum pointer slots decoded per table (1 ..
            ``jump_tables.MAX_ENTRIES``); ignored unless ``resolve_indirect`` is
            true.

    Returns:
        The reconstructed :class:`FunctionCFG` with blocks in ascending
        address order.

    Raises:
        AnalysisError: When ``start`` is not executable code, when a limit is
            out of range (including the jump-table limits), or when the
            architecture cannot be disassembled.
    """
    _validate_limits(max_instructions, max_blocks)
    _validate_indirect_limits(max_jump_tables, max_table_entries)

    section = info.section_for_va(start)
    if section is None or not section.is_executable:
        raise AnalysisError(f"address 0x{start:x} is not inside an executable section")

    try:
        disassembler = Disassembler(info.architecture, info.bitness, info.endianness)
    except DisassemblyError as exc:
        raise AnalysisError(f"cannot disassemble 0x{start:x}: {exc}") from exc

    # Leaders already queued are block starts: this set *is* the visited set.
    leaders: set[int] = {start}
    worklist: deque[int] = deque([start])
    decoded: dict[int, _Segment] = {}
    remaining = max_instructions
    indirect_unresolved = 0
    budget_exhausted = False
    dropped: list[int] = []
    warnings: list[str] = []
    tables: _JumpTableBudget | None = (
        _JumpTableBudget(max_tables=max_jump_tables, max_entries=max_table_entries)
        if resolve_indirect
        else None
    )

    while worklist and remaining > 0 and len(decoded) < max_blocks:
        leader = worklist.popleft()
        if leader in decoded:  # pragma: no cover - a leader is queued once
            continue
        chunk, reason = _decode_block(path, info, disassembler, leader, leaders, remaining)
        if not chunk:
            warnings.append(f"no decodable instruction at block start 0x{leader:x}")
            continue
        if reason == "budget":
            budget_exhausted = True
        remaining -= len(chunk)
        last = chunk[-1]
        table_targets: tuple[int, ...] | None = None
        if (
            tables is not None
            and _terminator_kind(last.mnemonic) == "jmp"
            and _direct_target(last.operands) is None
        ):
            table_targets = _jump_table_successors(
                path, info, tables, leader, last, warnings
            )
        successors, unresolved = _recursive_successors(
            info, last, dropped, table_targets
        )
        indirect_unresolved += int(unresolved)
        decoded[leader] = _Segment(
            instructions=tuple(chunk),
            successors=successors,
            terminator=_terminator_mnemonic(last.mnemonic),
        )
        for successor in successors:  # sorted, so queue order stays deterministic
            if successor not in leaders:
                leaders.add(successor)
                worklist.append(successor)

    # Overlapping traversal hypotheses become disjoint blocks here.
    segments = _split_at_leaders(list(decoded.values()))
    block_limit_from_split = len(segments) > max_blocks
    if block_limit_from_split:
        segments = segments[:max_blocks]
    blocks = [_to_block(segment) for segment in segments]
    # Disjoint ranges mean each instruction address is reported exactly once.
    instruction_count = len(
        {instruction.address for segment in segments for instruction in segment.instructions}
    )
    if worklist and not remaining:
        budget_exhausted = True
    block_limit_reached = bool(worklist) and len(decoded) >= max_blocks
    truncated = budget_exhausted or bool(worklist) or block_limit_from_split

    if budget_exhausted:
        warnings.append(
            f"instruction limit reached (max_instructions={max_instructions}); "
            "the graph may be incomplete"
        )
    if block_limit_reached:
        warnings.append(
            f"block limit reached (max_blocks={max_blocks}); {len(worklist)} reached "
            "block(s) were not decoded and the graph may be incomplete"
        )
    if block_limit_from_split:
        warnings.append(
            f"block limit reached (max_blocks={max_blocks}); splitting blocks at "
            "interior leaders produced more blocks and later ones were not reported"
        )
    if dropped:
        warnings.append(
            f"edge target(s) {_address_sample(dropped)} are outside any executable "
            "section; those edges are omitted"
        )
    missing = sorted(
        {address for block in blocks for address in block.successors}
        - {block.start for block in blocks}
    )
    if missing and not truncated:
        warnings.append(
            f"edge(s) to {_address_sample(missing)} have no reported block; those edges are kept"
        )
    if indirect_unresolved:
        warnings.append(
            f"{indirect_unresolved} indirect branch target(s) were not resolved "
            "(register/memory operands) and those edges are omitted"
        )

    # Only mention jump tables when the caller asked for them, so the evidence
    # text of a default traversal stays byte-for-byte what it used to be.
    table_detail = ""
    if tables is not None:
        table_detail = (
            f"; {tables.resolved} jump table(s) resolved from indirect jumps "
            f"({tables.entries} pointer slot(s) decoded, bounded by "
            f"max_jump_tables={max_jump_tables} and max_table_entries={max_table_entries})"
        )

    evidence = Evidence(
        source="cfg.recursive_traversal",
        method="recursive_traversal",
        confidence=Confidence.MEDIUM,
        address=start,
        detail=(
            f"recursive traversal from 0x{start:x} followed control flow into {len(blocks)} "
            f"block(s) / {instruction_count} unique instruction(s); bounded by "
            f"max_instructions={max_instructions} and max_blocks={max_blocks}; "
            f"{indirect_unresolved} indirect target(s) unresolved and call targets not "
            "followed; blocks split at interior leaders so reported ranges are disjoint"
            f"{table_detail}; boundaries are heuristic"
        ),
    )
    return FunctionCFG(
        function_address=start,
        function_name=_function_name_for(info, start),
        blocks=blocks,
        instruction_count=instruction_count,
        truncated=truncated,
        evidence=evidence,
        warnings=tuple(warnings),
    )


def _validate_limits(max_instructions: int, max_blocks: int) -> None:
    """Reject out-of-range traversal limits."""
    if max_instructions < 1:
        raise AnalysisError("max_instructions must be >= 1")
    if max_instructions > MAX_DISASSEMBLY_COUNT:
        raise AnalysisError(f"max_instructions too large (limit {MAX_DISASSEMBLY_COUNT})")
    if max_blocks < 1:
        raise AnalysisError("max_blocks must be >= 1")
    if max_blocks > MAX_DISASSEMBLY_COUNT:
        raise AnalysisError(f"max_blocks too large (limit {MAX_DISASSEMBLY_COUNT})")


def _validate_indirect_limits(max_jump_tables: int, max_table_entries: int) -> None:
    """Reject out-of-range jump-table limits.

    Validated unconditionally (even for ``resolve_indirect=False``) so a caller
    can pre-check its bounds without having to branch on the flag.
    """
    if max_jump_tables < 1:
        raise AnalysisError("max_jump_tables must be >= 1")
    if max_jump_tables > MAX_DISASSEMBLY_COUNT:
        raise AnalysisError(
            f"max_jump_tables too large (limit {MAX_DISASSEMBLY_COUNT})"
        )
    if max_table_entries < 1:
        raise AnalysisError("max_table_entries must be >= 1")
    if max_table_entries > _JUMP_TABLE_MAX_ENTRIES:
        raise AnalysisError(
            f"max_table_entries too large (limit {_JUMP_TABLE_MAX_ENTRIES})"
        )


def _decode_block(
    path: str | Path,
    info: BinaryInfo,
    disassembler: Disassembler,
    leader: int,
    known_starts: set[int],
    budget: int,
) -> tuple[list[IRInstruction], str]:
    """Decode the single basic block that begins at ``leader``.

    Args:
        path: File the bytes are read from (read-only).
        info: Loaded binary metadata.
        disassembler: Decoder already bound to the binary's architecture.
        leader: Block start; assumed to be executable and file-backed.
        known_starts: Leaders already queued, i.e. addresses that must begin a
            block. Decoding stops *before* re-entering one of them.
        budget: Instructions still available in the overall budget.

    Returns:
        ``(instructions, reason)`` where ``reason`` is ``"terminator"``,
        ``"leader"``, ``"budget"``, ``"section"``, ``"window"`` (the per-block
        decode window filled up, so the block continues at the fallthrough) or
        ``"empty"``.
    """
    if budget <= 0:
        return [], "budget"
    window = min(budget, _MAX_BLOCK_INSTRUCTIONS)
    try:
        code = read_code(path, info, leader, window * _MAX_INSTRUCTION_BYTES)
    except AnalysisError:
        return [], "empty"
    try:
        result = disassembler.disassemble(code, base_address=leader, max_instructions=window)
    except DisassemblyError as exc:  # pragma: no cover - decoder is already validated
        raise AnalysisError(f"cannot disassemble 0x{leader:x}: {exc}") from exc

    chunk: list[IRInstruction] = []
    for instruction in result.instructions:
        if len(chunk) >= budget:
            return chunk, "budget"
        if chunk and instruction.address in known_starts:
            return chunk, "leader"
        chunk.append(instruction)
        if _terminator_kind(instruction.mnemonic) is not None:
            return chunk, "terminator"
        if not _is_executable_address(info, instruction.address + instruction.size):
            return chunk, "section"
    return chunk, "window" if chunk else "empty"


def _recursive_successors(
    info: BinaryInfo,
    last: IRInstruction,
    dropped: list[int],
    indirect_targets: tuple[int, ...] | None = None,
) -> tuple[tuple[int, ...], bool]:
    """Return ``(successors, indirect_unresolved)`` for a block's final instruction.

    Conditional jumps yield fallthrough *and* target, unconditional jumps only
    their direct target (never a fallthrough), returns nothing, and ordinary
    instructions (calls included) only the fallthrough. Targets outside an
    executable, file-backed section are discarded and recorded in ``dropped``.

    Args:
        info: Loaded binary metadata used for the executable/file-backed check.
        last: Final instruction of the block.
        dropped: Collector for edge targets that are not executable code.
        indirect_targets: Already-resolved targets of an indirect ``jmp`` (a jump
            table), or ``None`` when indirect branches are not resolved. ``None``
            keeps the historical behaviour: an indirect ``jmp``/``Jcc`` gets no
            successor and is reported as unresolved. An empty tuple means "the
            jump was resolved and really leads nowhere", which is *not* counted
            as unresolved.
    """
    kind = _terminator_kind(last.mnemonic)
    candidates: list[int] = []
    unresolved = False

    if kind in (None, "cond"):  # ordinary instructions and conditional jumps fall through
        candidates.append(last.address + last.size)
    if kind in ("jmp", "cond"):  # direct branch targets only
        target = _direct_target(last.operands)
        if target is not None:
            candidates.append(target)
        elif indirect_targets is None:
            unresolved = True
        else:
            candidates.extend(indirect_targets)

    kept: set[int] = set()
    for address in candidates:
        if _is_executable_address(info, address):
            kept.add(address)
        else:
            dropped.append(address)
    return tuple(sorted(kept)), unresolved


@dataclass
class _JumpTableBudget:
    """Book-keeping for jump-table resolution during one traversal.

    Attributes:
        max_tables: Tables that may still be resolved (``max_jump_tables``).
        max_entries: Slots decoded per table (``max_table_entries``).
        resolved: Tables actually resolved so far.
        entries: Pointer slots decoded across every resolved table.
        limit_warned: ``True`` once the ``max_tables`` warning was emitted, so it
            is reported exactly once per traversal.
    """

    max_tables: int
    max_entries: int
    resolved: int = 0
    entries: int = 0
    limit_warned: bool = False

    @property
    def exhausted(self) -> bool:
        """``True`` once no further table may be resolved."""
        return self.resolved >= self.max_tables


def _jump_table_successors(
    path: str | Path,
    info: BinaryInfo,
    budget: _JumpTableBudget,
    block_start: int,
    last: IRInstruction,
    warnings: list[str],
) -> tuple[int, ...] | None:
    """Resolve the pointer table behind one indirect ``jmp`` into block starts.

    The dispatch operand is turned into an absolute table address, the table is
    decoded with :func:`~codevanta.analysis.jump_tables.resolve_jump_table`
    (bounded by ``budget.max_entries``) and the executable, file-backed targets
    are returned deduplicated and sorted. Every table-level problem is appended
    to ``warnings`` prefixed with ``block_start``, so the caveat can be traced
    back to the block that caused it. The table module's own warnings are
    surfaced verbatim, including the conventional zero terminator: "the scan
    ended where a terminator was expected" is still a statement about how much
    of the graph is guesswork, and dropping it would hide the reason a table
    looked short.

    Args:
        path: Binary to read (read-only; never executed).
        info: Loaded binary metadata.
        budget: Per-traversal jump-table budget, updated in place.
        block_start: Start address of the block, used as the warning prefix.
        last: Final instruction of the block (an indirect ``jmp``).
        warnings: Collector for human-readable caveats.

    Returns:
        The resolved successor addresses, an empty tuple when the table yielded
        no usable target, or ``None`` when the jump could not be resolved at all
        (register/indexed operand, unreadable table, or spent budget). ``None``
        makes the caller count the block as an unresolved indirect branch.
    """
    table_address = _indirect_table_address(info, last)
    if table_address is None:
        return None
    if budget.exhausted:
        if not budget.limit_warned:
            budget.limit_warned = True
            warnings.append(
                f"block 0x{block_start:x}: jump-table limit reached "
                f"(max_jump_tables={budget.max_tables}); further indirect jumps were "
                "left unresolved"
            )
        return None

    try:
        result = resolve_jump_table(path, info, table_address, max_entries=budget.max_entries)
    except AnalysisError as exc:
        warnings.append(
            f"block 0x{block_start:x}: jump table at 0x{table_address:x} could not be "
            f"read ({exc}); that edge is omitted"
        )
        return None

    budget.resolved += 1
    budget.entries += len(result.entries)
    if result.truncated:
        warnings.append(
            f"block 0x{block_start:x}: jump table at 0x{table_address:x} was truncated at "
            f"max_table_entries={budget.max_entries}; some targets are missing"
        )
    for warning in result.warnings:
        warnings.append(
            f"block 0x{block_start:x}: jump table at 0x{table_address:x}: {warning}"
        )

    targets: list[int] = []
    unusable: list[int] = []
    for entry in result.entries:
        if _is_executable_address(info, entry.target):
            targets.append(entry.target)
        else:
            unusable.append(entry.target)
    if unusable:  # bounded: one warning, at most eight addresses named
        warnings.append(
            f"block 0x{block_start:x}: jump-table target(s) {_address_sample(unusable)} "
            "are not executable file bytes; those edges are omitted"
        )
    return tuple(sorted(set(targets)))


@dataclass(frozen=True)
class _Segment:
    """One decoded instruction run with the edges the traversal gave it.

    Internal to :func:`build_recursive_cfg`: the traversal records raw runs and
    only turns them into :class:`BasicBlock` objects after the split pass, so the
    split can discard instructions without touching serialized data.
    """

    instructions: tuple[IRInstruction, ...]
    successors: tuple[int, ...]
    terminator: str | None
    split: bool = False

    @property
    def start(self) -> int:
        """Virtual address of the first instruction in the run."""
        return self.instructions[0].address

    @property
    def end(self) -> int:
        """Virtual address just past the last instruction (exclusive)."""
        last = self.instructions[-1]
        return last.address + last.size


def _split_at_leaders(decoded: list[_Segment]) -> list[_Segment]:
    """Turn traversed runs into blocks with disjoint address ranges.

    Traversal is driven by a worklist, so a run decoded early can reach past a
    leader that is only discovered later (a backward ``jmp`` into an already
    decoded region); two reported blocks would then claim the same instruction
    addresses. This pass removes that overlap:

    1. **Leaders.** Every traversed block start is a leader.
    2. **Split.** Each run is cut at every leader that appears strictly inside
       it. The leading piece of such a cut falls through to the split address
       (its only successor) and reports no terminator; the trailing piece keeps
       the original terminator and successor set.
    3. **Dedupe.** Pieces sharing a start address collapse to the most complete
       one (most instructions, then farthest end, then most successors), which
       is deterministic because the input is ordered by start first.
    4. **Order and clip.** The result is sorted by start and clipped so ranges
       never overlap.

    Args:
        decoded: Runs exactly as the traversal decoded them, in any order.

    Returns:
        Disjoint segments in ascending address order.
    """
    ordered = sorted(decoded, key=lambda segment: segment.start)
    leaders = {segment.start for segment in ordered}
    candidates = [piece for segment in ordered for piece in _cut_segment(segment, leaders)]
    return _clip_overlaps(_most_complete(candidates))


def _cut_segment(segment: _Segment, leaders: set[int]) -> list[_Segment]:
    """Cut one run at every leader that is strictly inside it."""
    instructions = segment.instructions
    cuts = [
        index
        for index, instruction in enumerate(instructions)
        if index > 0 and instruction.address in leaders
    ]
    if not cuts:
        return [segment]

    bounds = [0, *cuts, len(instructions)]
    pieces: list[_Segment] = []
    for position in range(len(bounds) - 1):
        piece = instructions[bounds[position] : bounds[position + 1]]
        trailing = position + 2 >= len(bounds)
        pieces.append(
            _Segment(
                instructions=piece,
                # Only the tail keeps the original edges; a cut piece simply
                # falls through to the split address.
                successors=segment.successors
                if trailing
                else (instructions[bounds[position + 1]].address,),
                terminator=segment.terminator if trailing else None,
                split=True,
            )
        )
    return pieces


def _most_complete(segments: list[_Segment]) -> list[_Segment]:
    """Keep the most complete segment per start address, ordered by start."""
    best: dict[int, _Segment] = {}
    for segment in segments:  # deterministic input order breaks exact ties
        current = best.get(segment.start)
        if current is None or _completeness(segment) > _completeness(current):
            best[segment.start] = segment
    return sorted(best.values(), key=lambda segment: segment.start)


def _completeness(segment: _Segment) -> tuple[int, int, int]:
    """Ranking key used to choose between segments that share a start address."""
    return (len(segment.instructions), segment.end, len(segment.successors))


def _clip_overlaps(segments: list[_Segment]) -> list[_Segment]:
    """Trim a run whose instructions still reach into the next kept block.

    The split already guarantees disjointness whenever leaders land on
    instruction boundaries of the containing run. Overlapping decodes of the
    same bytes can disagree about boundaries, so any instruction that would
    cross the next block start is dropped here and the run simply falls through
    to it. A run is never emptied: an undecodable first instruction is kept as
    is and reported through the traversal's warnings.
    """
    clipped: list[_Segment] = []
    for index, segment in enumerate(segments):
        if index + 1 >= len(segments):
            clipped.append(segment)
            continue
        next_start = segments[index + 1].start
        kept = tuple(
            instruction
            for instruction in segment.instructions
            if instruction.address + instruction.size <= next_start
        )
        if not kept or len(kept) == len(segment.instructions):
            clipped.append(segment)
            continue
        clipped.append(
            _Segment(
                instructions=kept,
                successors=(next_start,),
                terminator=None,
                split=True,
            )
        )
    return clipped


def _to_block(segment: _Segment) -> BasicBlock:
    """Serialize one disjoint segment into a :class:`BasicBlock`."""
    detail = f"{len(segment.instructions)} instructions reached by recursive traversal"
    if segment.split:
        detail += " and split at interior leaders"
    return BasicBlock(
        start=segment.start,
        end=segment.end,
        instructions=[instruction.to_dict() for instruction in segment.instructions],
        successors=segment.successors,
        terminator=segment.terminator,
        evidence=Evidence(
            source="cfg.recursive_traversal",
            method="basic_block",
            confidence=Confidence.MEDIUM,
            address=segment.start,
            detail=detail,
        ),
    )


def _split_blocks(
    instructions: list[IRInstruction],
    max_blocks: int,
) -> tuple[list[BasicBlock], bool, list[str]]:
    """Split one linear instruction stream into blocks with successors."""
    if not instructions:
        return [], False, []

    addresses = [instruction.address for instruction in instructions]
    decoded = set(addresses)

    leaders: set[int] = {addresses[0]}
    for index, instruction in enumerate(instructions):
        if _terminator_kind(instruction.mnemonic) is None:
            continue
        if index + 1 < len(instructions):
            leaders.add(addresses[index + 1])
        target = _direct_target(instruction.operands)
        if target is not None and target in decoded:
            leaders.add(target)

    start_indexes = [index for index, address in enumerate(addresses) if address in leaders]

    blocks: list[BasicBlock] = []
    dropped: list[int] = []
    for position, first in enumerate(start_indexes):
        last = (
            start_indexes[position + 1] - 1
            if position + 1 < len(start_indexes)
            else len(instructions) - 1
        )
        chunk = instructions[first : last + 1]
        if not chunk:  # pragma: no cover - leaders are instruction indexes
            continue
        blocks.append(
            BasicBlock(
                start=chunk[0].address,
                end=chunk[-1].address + chunk[-1].size,
                instructions=[instruction.to_dict() for instruction in chunk],
                successors=_successors(chunk[-1], leaders, dropped),
                terminator=_terminator_mnemonic(chunk[-1].mnemonic),
                evidence=Evidence(
                    source="cfg.linear_sweep",
                    method="basic_block",
                    confidence=Confidence.MEDIUM,
                    address=chunk[0].address,
                    detail=f"{len(chunk)} instructions",
                ),
            )
        )

    warnings: list[str] = []
    if dropped:  # bounded: only the first few unresolved edge targets are listed
        unique = list(dict.fromkeys(dropped))
        shown = ", ".join(f"0x{address:x}" for address in unique[:8])
        extra = f" (+{len(unique) - 8} more)" if len(unique) > 8 else ""
        warnings.append(
            f"edge target(s) {shown}{extra} were not decoded; those edges are omitted"
        )

    truncated = False
    if len(blocks) > max_blocks:
        blocks = blocks[:max_blocks]
        truncated = True
        warnings.append(
            f"block limit reached (max_blocks={max_blocks}); later blocks were not reported"
        )
    return blocks, truncated, warnings


def _successors(
    last: IRInstruction,
    block_starts: set[int],
    dropped: list[int],
) -> tuple[int, ...]:
    """Compute the sorted, deduplicated successor set of a final instruction."""
    kind = _terminator_kind(last.mnemonic)
    candidates: list[int] = []

    if kind in (None, "cond"):  # ordinary instructions and conditional jumps fall through
        candidates.append(last.address + last.size)
    if kind in ("jmp", "cond"):  # direct branch targets
        target = _direct_target(last.operands)
        if target is not None:
            candidates.append(target)

    successors: set[int] = set()
    for address in candidates:
        if address in block_starts:
            successors.add(address)
        else:
            dropped.append(address)
    return tuple(sorted(successors))


def _terminator_kind(mnemonic: str) -> str | None:
    """Classify a mnemonic as ``"ret"``, ``"jmp"``, ``"cond"`` or ``None``."""
    name = (mnemonic or "").strip().lower()
    if not name:
        return None
    if name in _RET_MNEMONICS or name.startswith("ret"):
        return "ret"
    if name in _UNCONDITIONAL_JUMPS:
        return "jmp"
    if name in _CONDITIONAL_JUMP_MNEMONICS or name.startswith("b."):
        return "cond"
    if name.startswith("j"):  # x86 Jcc family: je, jne, jle, jrcxz, ...
        return "cond"
    return None


def _terminator_mnemonic(mnemonic: str) -> str | None:
    """Return the normalized terminator mnemonic, or ``None`` for a fallthrough end."""
    name = (mnemonic or "").strip().lower()
    if not name or _terminator_kind(name) is None:
        return None
    return name


def _direct_target(operands: str) -> int | None:
    """Return the immediate branch target encoded in ``operands``, if any.

    Only straight hexadecimal immediates are accepted (``jmp 0x401006``,
    ``b.eq #0x401006``). Register and memory operands (``jmp rax``,
    ``jmp qword ptr [rip + 0x20]``) are indirect and therefore unresolved.
    """
    text = (operands or "").strip()
    if not text:
        return None
    lowered = text.lower()
    if any(marker in lowered for marker in ("[", "]", "ptr", ":")):
        return None
    if "," in text:
        return None
    token = text.lstrip("#").strip().lower()
    if not token.startswith("0x"):
        return None
    try:
        return int(token, 16)
    except ValueError:
        return None


def _pointer_width(info: BinaryInfo) -> int | None:
    """Return the pointer width in bytes implied by ``info.bitness``."""
    bitness = int(getattr(info, "bitness", 0) or 0)
    if bitness == 64:
        return 8
    if bitness == 32:
        return 4
    return None


def _split_terms(text: str) -> list[tuple[int, str]]:
    """Split a memory-operand body into ``(sign, term)`` pairs.

    ``"rip + 0xffa"`` becomes ``[(1, "rip "), (1, " 0xffa")]`` and
    ``"0x401000 - 0x10"`` becomes ``[(1, "0x401000 "), (-1, " 0x10")]``. Only
    ``+``/``-`` separate terms; everything else stays in the term so the caller
    can accept or reject it.
    """
    terms: list[tuple[int, str]] = []
    sign = 1
    current = ""
    for char in text:
        if char in "+-":
            terms.append((sign, current))
            sign = -1 if char == "-" else 1
            current = ""
            continue
        current += char
    terms.append((sign, current))
    return terms


def _hex_operand(term: str) -> int | None:
    """Return the value of a ``0x``-prefixed hexadecimal term, else ``None``."""
    token = term.strip()
    if not token.startswith("0x"):
        return None
    try:
        return int(token, 16)
    except ValueError:
        return None


def _indirect_table_address(info: BinaryInfo, last: IRInstruction) -> int | None:
    """Return the table address an indirect ``jmp`` reads through, if it is one.

    Only a pointer-sized memory operand is accepted: ``jmp qword ptr [rip +
    disp]`` on a 64-bit binary (``dword ptr [abs]`` on a 32-bit one) or its
    absolute form ``jmp qword ptr [0x402000]``. A RIP-relative displacement is
    resolved against the address of the *next* instruction, exactly as the CPU
    would. Everything else -- ``jmp rax``, an indexed operand such as ``jmp
    qword ptr [rax*8 + 0x402000]``, a symbol expression, a narrower or wider
    read -- returns ``None``: the operand may still be a dispatcher, but this
    function cannot justify a table address for it.

    Args:
        info: Loaded binary metadata; only ``bitness`` is used, to know which
            ``ptr`` size keyword denotes a pointer read.
        last: Instruction whose operands are inspected.

    Returns:
        The absolute table address, or ``None`` when the operand cannot be
        resolved to one.
    """
    width = _pointer_width(info)
    if width is None:
        return None
    keyword = _POINTER_SIZE_KEYWORDS[width]
    operands = (last.operands or "").strip().lower()
    if "[" not in operands or "]" not in operands:
        return None
    head, _, rest = operands.partition("[")
    inside, _, tail = rest.partition("]")
    if tail.strip():  # trailing syntax we do not model
        return None
    if "ptr" not in head:
        return None
    if head.split("ptr")[0].strip() != keyword:
        return None

    base: str | None = None
    displacement = 0
    for sign, term in _split_terms(inside):
        term = term.strip()
        if not term:
            continue
        if term == "rip":
            if base is not None:
                return None
            base = term
            continue
        value = _hex_operand(term)
        if value is None:
            return None  # register, symbol, scaled index or non-hex literal
        displacement += sign * value

    address = last.address + last.size + displacement if base == "rip" else displacement
    return address if address > 0 else None


def _is_executable_address(info: BinaryInfo, address: int) -> bool:
    """Return ``True`` when ``address`` is executable *and* backed by file bytes."""
    if address < 0:
        return False
    section = info.section_for_va(address)
    if section is None or not section.is_executable:
        return False
    return info.va_to_offset(address) is not None


def _address_sample(addresses: list[int]) -> str:
    """Format at most eight addresses for a warning, noting how many were cut."""
    unique = list(dict.fromkeys(addresses))
    shown = ", ".join(f"0x{address:x}" for address in unique[:8])
    return f"{shown} (+{len(unique) - 8} more)" if len(unique) > 8 else shown


def _function_name_for(info: BinaryInfo, start: int) -> str | None:
    """Return the discovered function name for ``start``, if there is one."""
    try:
        candidates = discover_functions(info)
    except Exception:  # pragma: no cover - discovery must never break CFG building
        return None
    for candidate in candidates:
        if candidate.address == start and candidate.name:
            return candidate.name
    return None


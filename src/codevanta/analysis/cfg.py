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
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.core.disassembler import Disassembler, DisassemblyError
from codevanta.core.functions import discover_functions
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import MAX_DISASSEMBLY_COUNT, AnalysisError, read_code
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence
from codevanta.ir.instruction import IRInstruction

__all__ = ["BasicBlock", "FunctionCFG", "build_cfg"]

#: Widest instruction any supported architecture can decode (x86 allows 15).
_MAX_INSTRUCTION_BYTES = 16

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
    """Control-flow graph for one function region produced by linear sweep.

    Attributes:
        function_address: Requested start address (also the entry block start).
        function_name: Name from function discovery when a candidate starts at
            ``function_address``, else ``None``.
        blocks: Blocks in ascending address order.
        instruction_count: Total number of decoded instructions.
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


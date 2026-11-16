"""Typed SSA intermediate representation over the CFG (decompiler v2, increments 1-6).

This module is one *decompiler-v2 foundation* step between the CFG (phase 2)
and the future pseudo-C lowering: it re-walks the blocks a recursive CFG
traversal produced (:func:`codevanta.analysis.cfg.build_recursive_cfg`) and
names every register definition once, so later increments can build on stable
value ids (``rax.3``) instead of register names.

Implemented semantics (increment 1 -- deliberately narrow):

1. **Straight-line versioning.** Blocks are walked in the CFG's deterministic
   ascending-address order, instructions in order. Every instruction that
   writes a GP register creates a new SSA version under the register's
   canonical name (64-bit names on a 64-bit binary, 32-bit names on a 32-bit
   one): ``rax.1``, ``rax.2``, ... Version ``0`` is reserved: a read of a
   register with no earlier definition resolves to ``"<reg>.0"`` with kind
   ``"undef"`` (or ``"arg"`` for the ABI argument registers, which hold the
   caller's arguments at function entry). Sub-register aliases (``eax``,
   ``ax``, ``al``) version their canonical register; widening/narrowing
   semantics of alias writes are *not* modelled.
2. **FLAGS.** The bounded mnemonic table maps ``cmp/test/add/sub/and/or/xor/
   inc/dec`` to writes of a pseudo-register ``FLAGS`` that conditional jumps,
   ``setcc`` and ``cmovcc`` read. ``adc``/``sbb`` read it too.
3. **Calls.** A ``call`` reads the ABI argument registers' current versions
   (Win64: ``rcx, rdx, r8, r9``; Win32: ``ecx, edx``) -- recorded on the call
   node as ``call_args`` -- and then clobbers the ABI's volatile registers
   (Win64: ``rax, rcx, rdx, r8-r11``; Win32: ``eax, ecx, edx``) plus ``FLAGS``
   with fresh ``"clobber"`` versions. Non-volatile registers (``rbx, rbp,
   rdi, rsi, r12-r15``) keep their version across the call. Implicit stack
   pointer updates are not modelled.
4. **Dominance-ordered rename with phi functions (increment 6).** Reachable
   blocks are renamed in dominator-tree pre-order; at every dominance
   frontier of a multi-predecessor join, phi values merge the versions
   reaching each predecessor, so loop bodies and forward joins read the
   merged value instead of whatever the address order said. Branches that
   target a block at or before the current block still mark the target
   ``loop_boundary`` with its ``phi_required`` live-in hint. Unreachable
   blocks are renamed linearly afterwards from entry state, with a warning.
5. **Types (optional).** A definition's ``type_hint`` uses the vocabulary of
   :mod:`codevanta.analysis.type_propagation`: the written alias's width
   (``mov eax, ...`` -> ``uint32_t``), ``lea`` -> the pointer type, and the
   ABI argument registers get whatever
   :func:`~codevanta.analysis.type_propagation.infer_argument_types` infers
   from use evidence. Absent evidence -> ``None``.
6. **Expression folding (increment 2).** Arithmetic writes carry a bounded
   symbolic ``expr`` string on the SSA value: ``add rax, 0x10`` -> ``"rax.1 +
   0x10"``, ``and rcx, rbx`` -> ``"rax.1 & rbx.1"``, ``xor reg, reg`` folds to
   the constant ``"0"`` (self-clear), ``add/sub/or/xor/shift by 0`` folds to
   the input value, ``mov reg, reg`` aliases the source's version (mov chains
   collapse one link per move) and ``lea`` builds a ``ptr(...)`` expression
   with base/index/displacement. Unknown sources (memory loads, width-changing
   moves, call clobbers, FLAGS) keep ``expr = None`` -- honest, never guessed.
   Every expression is clipped to :data:`MAX_EXPR_CHARS` characters.
7. **Condition recovery (increment 2).** A ``cmp``/``test`` followed by a
   conditional jump from the supported ``je/jne/jg/jl/jge/jle/ja/jb/jae/jbe``
   set *within the same block* attaches a ``condition`` dict to the block's
   terminator instruction: ``{"cond", "left", "right", "raw"}`` with SSA
   value ids (or the immediate token) and the raw instruction text.
   ``test X, X`` compares ``X`` against itself. Any intervening instruction
   that writes ``FLAGS`` (or a call) invalidates the pending comparison, and
   a conditional jump without one keeps ``condition = None``.

Every step is bounded (:data:`MAX_BLOCKS`, :data:`MAX_INSTRUCTIONS`,
:data:`MAX_VALUES`, :data:`MAX_USES_PER_VALUE`); hitting a bound sets a
truncation flag and records a warning -- never silently. Nothing is executed
and the target file is only ever read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codevanta.analysis.cfg import build_recursive_cfg
from codevanta.analysis.type_propagation import (
    INTEGER_C_TYPES,
    POINTER_C_TYPES,
    infer_argument_types,
)
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_BLOCKS",
    "DEFAULT_MAX_INSTRUCTIONS",
    "FLAGS_REGISTER",
    "MAX_BLOCKS",
    "MAX_EXPR_CHARS",
    "MAX_INSTRUCTIONS",
    "MAX_USES_PER_VALUE",
    "MAX_VALUES",
    "SSABlock",
    "SSAFunction",
    "SSAInstruction",
    "SSAPhiValue",
    "SSAValue",
    "abi_name",
    "abi_volatile_registers",
    "build_ssa",
]

#: Cap on CFG blocks converted into SSA blocks (SSA construction stops after).
MAX_BLOCKS = 512

#: Cap on instructions converted into SSA instructions (walk stops early).
MAX_INSTRUCTIONS = 20_000

#: Cap on distinct SSA values; construction stops when the next def overflows.
MAX_VALUES = 4_096

#: Cap on recorded uses per value; further uses are dropped and flagged.
MAX_USES_PER_VALUE = 64

#: Cap on a folded symbolic expression string. Longer expressions are clipped
#: with a trailing ``"..."`` -- bounded output, never silently unbounded.
MAX_EXPR_CHARS = 128

#: Default block budget for :func:`build_ssa` (also the MCP tool default).
DEFAULT_MAX_BLOCKS = 512

#: Default instruction budget for :func:`build_ssa` (also the MCP tool default).
DEFAULT_MAX_INSTRUCTIONS = 2_000

#: Canonical name of the flags pseudo-register in SSA value ids.
FLAGS_REGISTER = "FLAGS"

_SOURCE = "ir.ssa"
_METHOD = "cfg-dominance-ssa"

# ---------------------------------------------------------------------------
# bounded register and mnemonic tables (x86 / x64 only, increment 1)
# ---------------------------------------------------------------------------

#: 64-bit canonical register -> {alias as disassemblers print it: width in bytes}.
_ALIAS_WIDTHS_64: dict[str, dict[str, int]] = {
    "rax": {"rax": 8, "eax": 4, "ax": 2, "al": 1, "ah": 1},
    "rbx": {"rbx": 8, "ebx": 4, "bx": 2, "bl": 1, "bh": 1},
    "rcx": {"rcx": 8, "ecx": 4, "cx": 2, "cl": 1, "ch": 1},
    "rdx": {"rdx": 8, "edx": 4, "dx": 2, "dl": 1, "dh": 1},
    "rsi": {"rsi": 8, "esi": 4, "si": 2, "sil": 1},
    "rdi": {"rdi": 8, "edi": 4, "di": 2, "dil": 1},
    "rbp": {"rbp": 8, "ebp": 4, "bp": 2, "bpl": 1},
    "rsp": {"rsp": 8, "esp": 4, "sp": 2, "spl": 1},
}
for _index in range(8, 16):
    _name = f"r{_index}"
    _ALIAS_WIDTHS_64[_name] = {
        _name: 8,
        f"{_name}d": 4,
        f"{_name}w": 2,
        f"{_name}b": 1,
    }

#: 32-bit canonical register -> {alias: width in bytes} (no r8-r15 on i386).
_32BIT_ONLY_ALIASES = (
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
)
_ALIAS_WIDTHS_32: dict[str, dict[str, int]] = {
    canonical: {
        alias: width
        for alias, width in aliases.items()
        if alias in _32BIT_ONLY_ALIASES
    }
    for canonical, aliases in _ALIAS_WIDTHS_64.items()
    if canonical in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp")
}

#: Operand tokens that look like words but are never GP registers.
_NOT_REGISTERS = frozenset({"ptr", "byte", "word", "dword", "qword", "rip", "far"})

#: Mnemonics whose first operand is written but never read (destination-only).
_WRITE_ONLY_FIRST = frozenset(
    {"mov", "movabs", "movbe", "movsx", "movsxd", "movzx", "movq", "lea", "pop"}
)

#: Mnemonics whose first operand is both read and written (read-modify-write).
#: ``imul`` is listed for its 2-operand form; the 3-operand form's destination
#: is write-only, which this bounded table approximates (documented limitation).
_WRITE_READ_FIRST = frozenset(
    {
        "add", "and", "adc", "dec", "imul", "inc", "neg", "not",
        "or", "rol", "ror", "sal", "sar", "sbb", "shl", "shr", "sub", "xor",
    }
)

#: Mnemonics that write every register operand (read and written).
_SWAP_MNEMONICS = frozenset({"xchg", "xadd"})

#: Mnemonics that write the ``FLAGS`` pseudo-register (bounded, increment 1).
_FLAGS_WRITERS = frozenset({"cmp", "test", "add", "sub", "and", "or", "xor", "inc", "dec"})

#: Unconditional jumps and loop-family branches that do NOT read FLAGS.
_FLAGS_FREE_BRANCHES = frozenset({"jmp", "ljmp", "jrcxz", "jecxz"})

#: Mnemonics that transfer control to a subroutine.
_CALL_MNEMONICS = frozenset({"call", "callq"})

#: Two-operand arithmetic mnemonics -> the symbolic operator they fold to.
_ARITHMETIC_OPERATORS: dict[str, str] = {
    "add": "+",
    "sub": "-",
    "and": "&",
    "or": "|",
    "xor": "^",
    "shl": "<<",
    "shr": ">>",
    "sal": "<<",
    "sar": ">>",
}

#: Symbolic operators with an ``x <op> 0 == x`` identity (constants fold away).
_IDENTITY_WITH_ZERO = frozenset({"+", "-", "|", "^", "<<", ">>"})

#: One-operand arithmetic mnemonics -> symbolic rendering of their effect.
_UNARY_EXPRESSIONS: dict[str, str] = {
    "inc": " + 1",
    "dec": " - 1",
    "neg": "-",
    "not": "~",
}

#: Mnemonics whose destination is a plain copy of the source operand.
_MOV_COPIES = frozenset({"mov", "movabs"})

#: Conditional jumps condition recovery understands (bounded, increment 2).
_CONDITION_JUMPS = frozenset(
    {"je", "jne", "jg", "jl", "jge", "jle", "ja", "jb", "jae", "jbe"}
)

#: Immediate operand token scanner (hex or decimal, optionally negative).
_IMMEDIATE_TOKEN = re.compile(r"-?(?:0x[0-9a-f]+|\d+)")

#: Bracketed memory expression of a ``lea`` operand.
_LEA_MEMORY = re.compile(r"\[([^\]]*)\]")

#: ``index*scale`` suffix inside a lea memory expression.
_LEA_SCALE = re.compile(r"\*(\d+)\Z")

#: Win64 ABI (Microsoft x64): caller-saved registers a call clobbers.
_WIN64_VOLATILE: tuple[str, ...] = ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")

#: Win64 ABI argument registers, in argument order.
_WIN64_ARGUMENTS: tuple[str, ...] = ("rcx", "rdx", "r8", "r9")

#: Win32 ABI: caller-saved registers a call clobbers.
_WIN32_VOLATILE: tuple[str, ...] = ("eax", "ecx", "edx")

#: Win32 ABI argument registers, in argument order.
_WIN32_ARGUMENTS: tuple[str, ...] = ("ecx", "edx")

#: Register-name token scanner for operand text.
_WORD = re.compile(r"[a-z][a-z0-9]*")

#: Bracketed memory expression (removed before destination detection).
_MEMORY = re.compile(r"\[[^\]]*\]")

def abi_name(bitness: int) -> str:
    """Return the Windows calling convention name for ``bitness``."""
    return "win64" if bitness >= 64 else "win32"


def abi_volatile_registers(bitness: int) -> tuple[str, ...]:
    """Return the canonical registers a call clobbers under the Win ABI."""
    return _WIN64_VOLATILE if bitness >= 64 else _WIN32_VOLATILE


def _abi_argument_registers(bitness: int) -> tuple[str, ...]:
    """Return the canonical argument registers in ABI order."""
    return _WIN64_ARGUMENTS if bitness >= 64 else _WIN32_ARGUMENTS


def _alias_map(bitness: int) -> dict[str, tuple[str, int]]:
    """Map every register alias to ``(canonical name, width in bytes)``."""
    table: dict[str, tuple[str, int]] = {}
    aliases = _ALIAS_WIDTHS_64 if bitness >= 64 else _ALIAS_WIDTHS_32
    for canonical, widths in aliases.items():
        for alias, width in widths.items():
            table.setdefault(alias, (canonical, width))
    return table


def _reads_flags(mnemonic: str) -> bool:
    """Whether ``mnemonic`` consumes the ``FLAGS`` pseudo-register."""
    name = (mnemonic or "").strip().lower()
    if not name:
        return False
    if name in ("adc", "sbb"):
        return True
    if name.startswith("set") or name.startswith("cmov"):
        return True
    return name.startswith("j") and name not in _FLAGS_FREE_BRANCHES


def _split_operands(operands: str) -> list[str]:
    """Split an operand string on top-level commas."""
    text = (operands or "").strip()
    if not text:
        return []
    return [part.strip() for part in text.split(",")]


def _register_mentions(operand: str, aliases: dict[str, tuple[str, int]]) -> list[str]:
    """Canonical registers mentioned in ``operand``, in first-mention order."""
    found: list[str] = []
    for token in _WORD.findall(operand.lower()):
        if token in _NOT_REGISTERS:
            continue
        resolved = aliases.get(token)
        if resolved is not None and resolved[0] not in found:
            found.append(resolved[0])
    return found


def _destination_registers(
    operand: str, aliases: dict[str, tuple[str, int]]
) -> list[tuple[str, str, int]]:
    """``(canonical, alias, width)`` registers written via ``operand``.

    Registers inside a bracketed memory expression are address components,
    never the written destination, so the brackets are stripped first.
    """
    outside = _MEMORY.sub(" ", operand)
    hits: list[tuple[str, str, int]] = []
    for token in _WORD.findall(outside.lower()):
        if token in _NOT_REGISTERS:
            continue
        resolved = aliases.get(token)
        if resolved is not None and all(hit[0] != resolved[0] for hit in hits):
            hits.append((resolved[0], token, resolved[1]))
    return hits


def _direct_target(operands: str) -> int | None:
    """Return the immediate branch target in ``operands`` (hex only), if any.

    Mirrors :func:`codevanta.analysis.cfg._direct_target`: register and memory
    operands are indirect and therefore unresolved.
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


def _clip_expr(expr: str) -> str:
    """Clip a folded expression to :data:`MAX_EXPR_CHARS` (deterministic)."""
    if len(expr) <= MAX_EXPR_CHARS:
        return expr
    return f"{expr[: MAX_EXPR_CHARS - 3]}..."


def _immediate_value(token: str) -> int | None:
    """Parse an immediate operand token (hex or decimal), else ``None``."""
    text = token.strip()
    if _IMMEDIATE_TOKEN.fullmatch(text) is None:
        return None
    try:
        return int(text, 16) if text.lower().startswith(("0x", "-0x")) else int(text, 10)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# public SSA dataclasses (all JSON-safe, deterministic ordering)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SSAValue:
    """One SSA-named value: a definition, a phi, an undef, a clobber or an argument.

    Attributes:
        id: Stable name ``"<register>.<version>"``, e.g. ``"rax.3"``. Version
            ``0`` is the incoming/undefined value.
        kind: ``"def"`` (instruction write), ``"phi"`` (dominance-frontier
            merge, increment 6), ``"undef"`` (read before any definition in
            walked order), ``"clobber"`` (call side effect) or ``"arg"`` (ABI
            argument register at function entry).
        type_hint: Optional C type from :mod:`codevanta.analysis.type_propagation`,
            ``None`` when nothing types the definition.
        expr: Bounded symbolic expression the definition folds to (increment 2),
            e.g. ``"rax.1 + 0x10"``, ``"0"`` for ``xor reg, reg`` or
            ``"ptr(rbx.0 + 0x10)"`` for ``lea``; ``None`` when unknown.
        def_block: Index of the defining SSA block, ``None`` for undef/arg
            values (defined outside the walked region).
        def_insn_index: Index of the defining instruction within its block.
        uses: ``(block index, instruction index)`` pairs, in walk order.
    """

    id: str
    kind: str
    type_hint: str | None
    def_block: int | None
    def_insn_index: int | None
    uses: tuple[tuple[int, int], ...]
    expr: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the value for the JSON report."""
        return {
            "id": self.id,
            "kind": self.kind,
            "type_hint": self.type_hint,
            "expr": self.expr,
            "def_block": self.def_block,
            "def_insn_index": self.def_insn_index,
            "uses": [[block, insn] for block, insn in self.uses],
        }


@dataclass(frozen=True)
class SSAInstruction:
    """One decoded instruction with SSA-resolved reads and writes.

    Attributes:
        address: Virtual address of the instruction.
        mnemonic: Lowercase mnemonic as the disassembler printed it.
        reads: SSA value ids consumed (``undef``/``arg`` versions included).
        writes: SSA value ids produced (``clobber`` versions included).
        text: Raw ``"mnemonic operands"`` text of the instruction.
        call_args: For a ``call``, the argument-register value ids in ABI
            order; ``None`` for every other instruction.
        condition: For a conditional-jump terminator, the recovered
            ``{"cond", "left", "right", "raw"}`` comparison from the preceding
            ``cmp``/``test`` (increment 2); ``None`` when there is none.
    """

    address: int
    mnemonic: str
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    text: str
    call_args: tuple[str, ...] | None = None
    condition: dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the instruction for the JSON report."""
        data: dict[str, Any] = {
            "address": f"0x{self.address:x}",
            "mnemonic": self.mnemonic,
            "reads": list(self.reads),
            "writes": list(self.writes),
            "text": self.text,
        }
        if self.call_args is not None:
            data["call_args"] = list(self.call_args)
        if self.condition is not None:
            data["condition"] = dict(self.condition)
        return data


@dataclass(frozen=True)
class SSAPhiValue:
    """One phi function at a dominance frontier (increment 6).

    Attributes:
        id: The SSA value id the phi defines (``"rax.2"``).
        register: Canonical register the phi merges.
        args: ``(predecessor_block_index, value_id)`` for every reachable
            predecessor, sorted by block index -- the versions the join
            merges.
    """

    id: str
    register: str
    args: tuple[tuple[int, str], ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the phi for the JSON report."""
        return {
            "id": self.id,
            "register": self.register,
            "args": [
                [pred_index, value_id] for pred_index, value_id in self.args
            ],
        }


@dataclass(frozen=True)
class SSABlock:
    """One CFG block converted to SSA instructions.

    Attributes:
        index: Position of the block in the CFG's deterministic order.
        start: Virtual address of the first instruction.
        instructions: The block's SSA instructions in address order.
        loop_boundary: ``True`` when some branch jumps back into this block.
        phi_required: Registers locally live-in at the loop head; kept as a
            live-in hint alongside the real phi functions (increment 6).
        phis: Phi values this join block defines, register-sorted.
    """

    index: int
    start: int
    instructions: tuple[SSAInstruction, ...]
    loop_boundary: bool = False
    phi_required: tuple[str, ...] = ()
    phis: tuple[SSAPhiValue, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize the block for the JSON report."""
        return {
            "index": self.index,
            "start": f"0x{self.start:x}",
            "instruction_count": len(self.instructions),
            "instructions": [instruction.to_dict() for instruction in self.instructions],
            "loop_boundary": self.loop_boundary,
            "phi_required": list(self.phi_required),
            "phis": [phi.to_dict() for phi in self.phis],
        }


@dataclass(frozen=True)
class SSAFunction:
    """The SSA view of one function region.

    Attributes:
        address: Function start address the SSA was built for.
        name: Function name from discovery when a candidate starts here.
        blocks: SSA blocks in the CFG's deterministic order.
        values: Every SSA value in first-appearance (walk) order.
        loop_count: Number of backward branches (loop boundaries) seen.
        truncated_blocks: Block budget was hit; blocks were left out.
        truncated_instructions: Instruction budget was hit; the walk stopped.
        truncated_values: Value budget was hit; construction stopped early.
        uses_truncated: At least one value dropped uses past the per-value cap.
        warnings: Human-readable caveats, bounds first.
        evidence: How this SSA was derived (source ``ir.ssa``).
    """

    address: int
    name: str | None
    blocks: tuple[SSABlock, ...]
    values: tuple[SSAValue, ...]
    loop_count: int
    truncated_blocks: bool
    truncated_instructions: bool
    truncated_values: bool
    uses_truncated: bool
    warnings: tuple[str, ...]
    evidence: Evidence

    @property
    def instruction_count(self) -> int:
        """Number of instructions converted to SSA."""
        return sum(len(block.instructions) for block in self.blocks)

    @property
    def use_count(self) -> int:
        """Number of recorded def-use edges over all values."""
        return sum(len(value.uses) for value in self.values)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the SSA function for the JSON report."""
        kinds = [value.kind for value in self.values]
        return {
            "address": f"0x{self.address:x}",
            "function_name": self.name,
            "block_count": len(self.blocks),
            "instruction_count": self.instruction_count,
            "blocks": [block.to_dict() for block in self.blocks],
            "values": [value.to_dict() for value in self.values],
            "stats": {
                "value_count": len(self.values),
                "def_count": kinds.count("def"),
                "clobber_count": kinds.count("clobber"),
                "undef_count": kinds.count("undef"),
                "arg_count": kinds.count("arg"),
                "use_count": self.use_count,
                "loop_count": self.loop_count,
                "truncated_blocks": self.truncated_blocks,
                "truncated_instructions": self.truncated_instructions,
                "truncated_values": self.truncated_values,
                "uses_truncated": self.uses_truncated,
            },
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


# ---------------------------------------------------------------------------
# construction
# ---------------------------------------------------------------------------


@dataclass
class _ValueRecord:
    """Mutable accumulation slot frozen into an :class:`SSAValue`."""

    id: str
    kind: str
    type_hint: str | None
    def_block: int | None
    def_insn_index: int | None
    uses: list[tuple[int, int]] = field(default_factory=list)
    expr: str | None = None


class _BudgetStopError(Exception):
    """Internal control flow: the value budget was hit; construction stops."""


class _SSABuilder:
    """Straight-line SSA construction over one ``FunctionCFG``."""

    def __init__(
        self,
        cfg: Any,
        *,
        bitness: int,
        max_instructions: int,
        max_blocks: int,
        max_values: int,
        max_uses_per_value: int,
        attach_types: bool,
    ) -> None:
        self._cfg = cfg
        self._bitness = bitness
        self._max_instructions = max_instructions
        self._max_blocks = max_blocks
        self._max_values = max_values
        self._max_uses = max_uses_per_value
        self._attach_types = attach_types
        self._aliases = _alias_map(bitness)
        self._arguments = _abi_argument_registers(bitness)
        self._arg_hints: dict[str, str | None] = {}
        self._versions: dict[str, int] = {}
        self._values: dict[str, _ValueRecord] = {}
        self._warnings: list[str] = []
        self._cursor = 0
        self._pending_condition: dict[str, str] | None = None
        self.truncated_blocks = False
        self.truncated_instructions = False
        self.truncated_values = False
        self.uses_truncated = False
        self.loop_count = 0
        self._loop_flags: dict[int, bool] = {}
        self._phi_required: dict[int, tuple[str, ...]] = {}
        self._def_stacks: dict[str, list[int]] = {}
        self._block_push_stack: list[str] = []
        self._block_scope_depth = 0

    # -- value table -------------------------------------------------------

    def _warn(self, message: str) -> None:
        self._warnings.append(message)

    def _new_value(
        self,
        canonical: str,
        kind: str,
        block_index: int | None,
        insn_index: int | None,
        type_hint: str | None,
        expr: str | None = None,
    ) -> str:
        """Create the next version of ``canonical`` or stop on the value cap."""
        if len(self._values) >= self._max_values:
            self.truncated_values = True
            self._warn(
                f"value budget max_values={self._max_values} reached at "
                f"0x{self._cursor:x}; SSA construction stopped early"
            )
            raise _BudgetStopError
        version = self._versions.get(canonical, 0) + 1
        value_id = f"{canonical}.{version}"
        self._versions[canonical] = version
        self._values[value_id] = _ValueRecord(
            id=value_id,
            kind=kind,
            type_hint=type_hint,
            def_block=block_index,
            def_insn_index=insn_index,
            expr=expr,
        )
        self._def_stacks.setdefault(canonical, []).append(version)
        if self._block_scope_depth > 0:
            self._block_push_stack.append(canonical)
        return value_id

    def _seed_incoming(self, canonical: str, kind: str, type_hint: str | None) -> None:
        """Record version 0 of ``canonical`` (undef or incoming argument)."""
        value_id = f"{canonical}.0"
        self._values.setdefault(
            value_id,
            _ValueRecord(
                id=value_id,
                kind=kind,
                type_hint=type_hint,
                def_block=None,
                def_insn_index=None,
            ),
        )

    def _current_version(self, canonical: str) -> str:
        """Resolve a read of ``canonical`` to its current SSA value id.

        With stack-based renaming (increment 6) the current version is the
        top of the register's definition stack -- dominance order decides it,
        not address order. An empty stack resolves to the lazily recorded
        version-0 value: ``"arg"`` for ABI argument registers (the caller
        defined them), ``"undef"`` for everything else.
        """
        stack = self._def_stacks.get(canonical)
        if stack:
            return f"{canonical}.{stack[-1]}"
        zero_id = f"{canonical}.0"
        if zero_id not in self._values:
            if canonical in self._arguments:
                self._values[zero_id] = _ValueRecord(
                    id=zero_id,
                    kind="arg",
                    type_hint=self._arg_hints.get(canonical),
                    def_block=None,
                    def_insn_index=None,
                )
            else:
                self._values[zero_id] = _ValueRecord(
                    id=zero_id,
                    kind="undef",
                    type_hint=None,
                    def_block=None,
                    def_insn_index=None,
                )
        return zero_id

    def _record_use(self, value_id: str, block_index: int, insn_index: int) -> None:
        record = self._values[value_id]
        if len(record.uses) >= self._max_uses:
            if not self.uses_truncated:
                self.uses_truncated = True
                self._warn(
                    f"use budget max_uses_per_value={self._max_uses} reached; further "
                    f"uses of {value_id} are dropped (flagged once)"
                )
            return
        record.uses.append((block_index, insn_index))

    def _read(self, canonical: str, reads: list[str]) -> None:
        value_id = self._current_version(canonical)
        if value_id not in reads:
            reads.append(value_id)

    def _resolve_reads(self, mnemonic: str, parts: list[str]) -> list[str]:
        """Resolve every register the instruction reads, in operand order."""
        reads: list[str] = []
        destination_only = mnemonic in _WRITE_ONLY_FIRST
        for position, part in enumerate(parts):
            if position == 0 and destination_only:
                # A bare destination register is not read, but registers inside
                # a bracketed destination are address components, which are.
                for match in _MEMORY.finditer(part):
                    for canonical in _register_mentions(match.group(0), self._aliases):
                        self._read(canonical, reads)
                continue
            for canonical in _register_mentions(part, self._aliases):
                self._read(canonical, reads)
        return reads

    def _register_writes(
        self, mnemonic: str, parts: list[str]
    ) -> list[tuple[str, str, int]]:
        """``(canonical, alias, width)`` register writes of the instruction."""
        if mnemonic in _WRITE_ONLY_FIRST or mnemonic in _WRITE_READ_FIRST:
            return _destination_registers(parts[0], self._aliases) if parts else []
        if mnemonic in _SWAP_MNEMONICS or mnemonic.startswith("cmov"):
            writes: list[tuple[str, str, int]] = []
            for part in parts[:2]:
                for hit in _destination_registers(part, self._aliases):
                    if all(existing[0] != hit[0] for existing in writes):
                        writes.append(hit)
            return writes
        if mnemonic.startswith("set"):
            return _destination_registers(parts[0], self._aliases) if parts else []
        return []

    def _type_hint_for(self, mnemonic: str, writes: list[tuple[str, str, int]]) -> str | None:
        """Best width/pointer type for one definition, or ``None``."""
        if not self._attach_types or not writes:
            return None
        if mnemonic == "lea":
            pointer_width = 8 if self._bitness >= 64 else 4
            return POINTER_C_TYPES.get(pointer_width)
        return INTEGER_C_TYPES.get(writes[0][2])

    # -- expression folding (increment 2) ------------------------------------

    def _expr_read_ids(self, parts: list[str]) -> dict[str, str]:
        """Map canonical register -> current value id for the operand text.

        Registers without a prior version seed their ``.0`` undef value (the
        SSA convention already names honest unknowns ``<reg>.0``), so an
        ``add rax, rbx`` with an undefined ``rbx`` still folds to
        ``"rax.N + rbx.0"`` instead of a ``None`` operand.
        """
        ids: dict[str, str] = {}
        for part in parts:
            for canonical in _register_mentions(part, self._aliases):
                if canonical not in ids:
                    stack = self._def_stacks.get(canonical)
                    version = stack[-1] if stack else 0
                    ids[canonical] = f"{canonical}.{version}"
        return ids

    def _expr_for(
        self, mnemonic: str, parts: list[str], read_ids: dict[str, str]
    ) -> str | None:
        """Fold one definition into a bounded symbolic expression, or ``None``."""
        if mnemonic in _CALL_MNEMONICS or not parts:
            return None
        if mnemonic in _MOV_COPIES:
            return self._copy_expr(parts[1], read_ids) if len(parts) > 1 else None
        if mnemonic == "lea":
            return self._lea_expr(parts[1], read_ids) if len(parts) > 1 else None
        if mnemonic in _ARITHMETIC_OPERATORS:
            return self._binary_expr(mnemonic, parts, read_ids)
        if mnemonic in _UNARY_EXPRESSIONS:
            return self._unary_expr(mnemonic, parts, read_ids)
        return None

    def _copy_expr(self, operand: str, read_ids: dict[str, str]) -> str | None:
        """``mov`` source expression: the source value id or immediate token."""
        regs = _register_mentions(operand, self._aliases)
        if regs:
            return read_ids.get(regs[0])
        token = (operand or "").strip()
        if _IMMEDIATE_TOKEN.fullmatch(token):
            return token
        return None  # memory source or exotic operand: honest unknown

    def _binary_expr(
        self, mnemonic: str, parts: list[str], read_ids: dict[str, str]
    ) -> str | None:
        """``op dst, src`` -> ``"{left} {operator} {right}"`` with folds."""
        if len(parts) < 2:
            return None
        dest = _register_mentions(_MEMORY.sub(" ", parts[0]), self._aliases)
        if not dest:
            return None
        left = read_ids.get(dest[0])
        if left is None:
            return None
        source_regs = _register_mentions(_MEMORY.sub(" ", parts[1]), self._aliases)
        if source_regs:
            right = read_ids.get(source_regs[0])
            right_value: int | None = None
        else:
            right = parts[1].strip()
            right_value = _immediate_value(right)
            if right_value is None:
                return None  # memory source: honest unknown
        operator = _ARITHMETIC_OPERATORS[mnemonic]
        if mnemonic == "xor" and source_regs and source_regs[0] == dest[0]:
            return "0"  # xor reg, reg self-clears to the zero constant
        if right_value == 0:
            if operator == "&":
                return "0"  # and x, 0 clears to the zero constant
            if operator in _IDENTITY_WITH_ZERO:
                return left  # x + 0 / x | 0 / shifts by 0 keep x
        return _clip_expr(f"{left} {operator} {right}")

    def _unary_expr(
        self, mnemonic: str, parts: list[str], read_ids: dict[str, str]
    ) -> str | None:
        """``inc/dec/neg/not dst`` -> a one-operand symbolic expression."""
        dest = _register_mentions(_MEMORY.sub(" ", parts[0]), self._aliases)
        if not dest:
            return None
        left = read_ids.get(dest[0])
        if left is None:
            return None
        suffix = _UNARY_EXPRESSIONS[mnemonic]
        if suffix.startswith(" "):
            return _clip_expr(f"{left}{suffix}")
        return _clip_expr(f"{suffix}{left}")

    def _lea_expr(self, operand: str, read_ids: dict[str, str]) -> str | None:
        """``lea`` -> ``ptr(base + index*scale + disp)`` with zero terms dropped."""
        match = _LEA_MEMORY.search(operand)
        if match is None:
            return None
        terms: list[tuple[str, str]] = []
        for piece in re.findall(r"[+-]?[^+-]+", match.group(1).replace(" ", "")):
            sign = ""
            if piece.startswith("+"):
                piece = piece[1:]
            elif piece.startswith("-"):
                sign = "-"
                piece = piece[1:]
            if not piece:
                continue
            regs = _register_mentions(piece, self._aliases)
            if regs:
                if len(regs) != 1:
                    return None
                base_id = read_ids.get(regs[0])
                if base_id is None:
                    return None
                scale = _LEA_SCALE.search(piece)
                term = (
                    base_id
                    if scale is None or scale.group(1) == "1"
                    else f"{base_id}*{scale.group(1)}"
                )
                terms.append((sign, term))
                continue
            immediate = _immediate_value(piece)
            if immediate is None:
                return None  # rip-relative or unmatched shape: honest unknown
            if immediate == 0:
                continue  # zero displacement folds away
            terms.append((sign, piece))
        if not terms:
            return None
        head_sign, head = terms[0]
        body = f"-{head}" if head_sign == "-" else head
        for sign, term in terms[1:]:
            body += f" {sign} {term}" if sign == "-" else f" + {term}"
        return _clip_expr(f"ptr({body})")

    # -- condition recovery (increment 2) -------------------------------------

    def _comparison_operands(
        self, parts: list[str], read_ids: dict[str, str]
    ) -> tuple[str, str] | None:
        """``(left, right)`` value ids / immediate token of a ``cmp``/``test``.

        Memory operands are not expressible as SSA ids, so comparisons over
        them stay ``None``; ``test X, X`` naturally yields ``X`` twice.
        """
        if len(parts) < 2:
            return None
        left_regs = _register_mentions(_MEMORY.sub(" ", parts[0]), self._aliases)
        left = read_ids.get(left_regs[0]) if left_regs else None
        if left is None:
            return None
        right_regs = _register_mentions(_MEMORY.sub(" ", parts[1]), self._aliases)
        if right_regs:
            right = read_ids.get(right_regs[0])
            return None if right is None else (left, right)
        token = parts[1].strip()
        if _IMMEDIATE_TOKEN.fullmatch(token):
            return left, token
        return None

    def _advance_condition(
        self, mnemonic: str, parts: list[str], text: str
    ) -> dict[str, str] | None:
        """Track the pending ``cmp``/``test`` and attach it to a ``jcc``.

        Returns the ``condition`` dict for the current instruction when it is
        a supported conditional jump consuming the pending comparison (which
        is then marked consumed); otherwise ``None``.
        """
        if mnemonic in ("cmp", "test"):
            pair = self._comparison_operands(parts, self._expr_read_ids(parts))
            self._pending_condition = (
                {"left": pair[0], "right": pair[1], "raw": text} if pair else None
            )
        elif mnemonic in _FLAGS_WRITERS or mnemonic in _CALL_MNEMONICS:
            self._pending_condition = None  # FLAGS rewritten: comparison stale
        if mnemonic in _CONDITION_JUMPS and self._pending_condition is not None:
            pending = self._pending_condition
            self._pending_condition = None  # consumed by the first jump only
            return {
                "cond": mnemonic,
                "left": pending["left"],
                "right": pending["right"],
                "raw": pending["raw"],
            }
        return None

    # -- driver -------------------------------------------------------------

    def run(self) -> tuple[list[SSABlock], dict[str, _ValueRecord]]:
        """Rename reachable blocks in dominator order; linearly the rest."""
        cfg_blocks = list(self._cfg.blocks)
        order = sorted(range(len(cfg_blocks)), key=lambda i: cfg_blocks[i].start)
        self._seed_arguments()
        block_starts = {cfg_blocks[index].start: index for index in order}
        raw_by_index = {index: cfg_blocks[index].instructions for index in order}

        successors = self._cfg_edges(order, cfg_blocks, block_starts)
        entry, reachable, preds, idom, children = self._dominance(order, successors)
        unreachable = [index for index in order if index not in reachable]
        if unreachable:
            self._warn(
                f"{len(unreachable)} unreachable block(s) renamed linearly after "
                f"the dominance walk (entry = block {entry}); their reads resolve "
                "from entry state, never from unreachable definitions"
            )

        frontiers = self._frontiers(order, reachable, preds, idom)
        definitions = self._definition_sites(reachable, raw_by_index)
        phi_sites = self._place_phis(definitions, frontiers)
        phi_ids: dict[tuple[int, str], str] = {}
        phi_args: dict[tuple[int, str], dict[int, str]] = {
            (block_index, register): {}
            for block_index, registers in phi_sites.items()
            for register in registers
        }

        converted: dict[int, list[SSAInstruction]] = {index: [] for index in order}
        total = 0
        stop = False
        processed = 0

        def rename(block_index: int) -> None:
            """Rename one block, then its dominator-tree children."""
            nonlocal total, stop, processed
            if stop:
                return
            if processed >= self._max_blocks:
                if not self.truncated_blocks:
                    self.truncated_blocks = True
                    self._warn(
                        f"block budget max_blocks={self._max_blocks} reached; "
                        "further reachable blocks were left out of the SSA view"
                    )
                return
            processed += 1
            self._pending_condition = None  # comparisons never cross block edges
            self._block_scope_depth += 1
            phi_pushes: list[str] = []
            try:
                for register in phi_sites.get(block_index, ()):
                    value_id = self._new_phi_value(register, block_index)
                    phi_ids[(block_index, register)] = value_id
                    self._def_stacks.setdefault(register, []).append(
                        int(value_id.rsplit(".", 1)[1])
                    )
                    phi_pushes.append(register)
            except _BudgetStopError:
                stop = True
            for local_index, payload in enumerate(raw_by_index[block_index]):
                if stop or total >= self._max_instructions:
                    if total >= self._max_instructions:
                        self.truncated_instructions = True
                        self._warn(
                            f"instruction budget max_instructions="
                            f"{self._max_instructions} reached; SSA construction "
                            "stopped before the end of the CFG"
                        )
                    stop = True
                    break
                address = _payload_address(payload)
                self._cursor = address
                mnemonic = (payload.get("mnemonic") or "").strip().lower()
                operands = payload.get("operands") or ""
                instruction = self._convert(
                    mnemonic,
                    _split_operands(operands),
                    payload,
                    block_index,
                    local_index,
                )
                if instruction is None:  # value budget hit inside _convert
                    stop = True
                    break
                converted[block_index].append(instruction)
                total += 1
                self._note_loop_edge(
                    mnemonic, operands, address, block_index, block_starts,
                    raw_by_index[block_index],
                )
            own_pushes = self._block_push_stack[:]
            self._block_push_stack.clear()
            for successor in sorted(successors.get(block_index, ())):
                for register in phi_sites.get(successor, ()):
                    phi_args[(successor, register)][block_index] = (
                        self._current_version(register)
                    )
            for child in children.get(block_index, []):
                rename(child)
            for register in reversed(phi_pushes):
                self._def_stacks[register].pop()
            for register in reversed(own_pushes):
                self._def_stacks[register].pop()
            self._block_scope_depth -= 1

        rename(entry)

        for block_index in unreachable:
            if stop or processed >= self._max_blocks:
                if not self.truncated_blocks:
                    self.truncated_blocks = True
                    self._warn(
                        f"block budget max_blocks={self._max_blocks} reached; "
                        "further blocks were left out of the SSA view"
                    )
                break
            processed += 1
            self._pending_condition = None
            self._block_scope_depth += 1
            for local_index, payload in enumerate(raw_by_index[block_index]):
                if stop or total >= self._max_instructions:
                    if total >= self._max_instructions:
                        self.truncated_instructions = True
                        self._warn(
                            f"instruction budget max_instructions="
                            f"{self._max_instructions} reached; SSA construction "
                            "stopped before the end of the CFG"
                        )
                    stop = True
                    break
                address = _payload_address(payload)
                self._cursor = address
                mnemonic = (payload.get("mnemonic") or "").strip().lower()
                operands = payload.get("operands") or ""
                instruction = self._convert(
                    mnemonic,
                    _split_operands(operands),
                    payload,
                    block_index,
                    local_index,
                )
                if instruction is None:
                    stop = True
                    break
                converted[block_index].append(instruction)
                total += 1
            for register in reversed(self._block_push_stack):
                self._def_stacks[register].pop()
            self._block_push_stack.clear()
            self._block_scope_depth -= 1

        phis_by_block: dict[int, list[SSAPhiValue]] = {}
        for (block_index, register), pred_map in phi_args.items():
            phis_by_block.setdefault(block_index, []).append(
                SSAPhiValue(
                    id=phi_ids[(block_index, register)],
                    register=register,
                    args=tuple(sorted(pred_map.items())),
                )
            )
        ssa_blocks = [
            SSABlock(
                index=block_index,
                start=cfg_blocks[block_index].start,
                instructions=tuple(converted[block_index]),
                loop_boundary=self._loop_flags.get(block_index, False),
                phi_required=self._phi_required.get(block_index, ()),
                phis=tuple(
                    sorted(
                        phis_by_block.get(block_index, []),
                        key=lambda phi: phi.register,
                    )
                ),
            )
            for block_index in order
        ]
        return ssa_blocks, self._values

    def _cfg_edges(
        self,
        order: list[int],
        cfg_blocks: list[Any],
        block_starts: dict[int, int],
    ) -> dict[int, tuple[int, ...]]:
        """``index -> sorted successor indexes`` from direct branches + falls."""
        successors: dict[int, set[int]] = {index: set() for index in order}
        for position, index in enumerate(order):
            instructions = cfg_blocks[index].instructions
            for payload in instructions:
                mnemonic = (payload.get("mnemonic") or "").strip().lower()
                if not mnemonic.startswith("j"):
                    continue
                target = _direct_target(payload.get("operands") or "")
                target_index = (
                    block_starts.get(target) if target is not None else None
                )
                if target_index is not None:
                    successors[index].add(target_index)
            if position + 1 >= len(order):
                continue
            last = ""
            if instructions:
                last = (instructions[-1].get("mnemonic") or "").strip().lower()
            if last in {"jmp", "ret", "hlt", "ud2"}:
                continue
            successors[index].add(order[position + 1])
        return {
            index: tuple(sorted(targets)) for index, targets in successors.items()
        }

    def _dominance(
        self, order: list[int], successors: dict[int, tuple[int, ...]]
    ) -> tuple[int, set[int], dict[int, set[int]], dict[int, int], dict[int, list[int]]]:
        """Entry, reachable set, preds, immediate dominators, dom-tree children."""
        entry = order[0]
        reachable = {entry}
        pending = [entry]
        while pending:
            block_index = pending.pop()
            for successor in successors.get(block_index, ()):
                if successor not in reachable:
                    reachable.add(successor)
                    pending.append(successor)
        preds: dict[int, set[int]] = {index: set() for index in reachable}
        for block_index in reachable:
            for successor in successors.get(block_index, ()):
                if successor in reachable:
                    preds[successor].add(block_index)
        dom = {index: set(reachable) for index in reachable}
        dom[entry] = {entry}
        changed = True
        while changed:
            changed = False
            for block_index in order:
                if block_index not in reachable or block_index == entry:
                    continue
                pred_doms = [dom[p] for p in preds[block_index] if p in dom]
                if not pred_doms:
                    continue
                new_dom = set.intersection(*pred_doms) | {block_index}
                if new_dom != dom[block_index]:
                    dom[block_index] = new_dom
                    changed = True
        idom: dict[int, int] = {}
        for block_index in reachable:
            if block_index == entry:
                continue
            strict = dom[block_index] - {block_index}
            idom[block_index] = max(strict, key=lambda d: len(dom[d]))
        position_of = {index: position for position, index in enumerate(order)}
        children: dict[int, list[int]] = {}
        for block_index in sorted(reachable, key=lambda i: position_of[i]):
            parent = idom.get(block_index)
            if parent is not None:
                children.setdefault(parent, []).append(block_index)
        return entry, reachable, preds, idom, children

    def _frontiers(
        self,
        order: list[int],
        reachable: set[int],
        preds: dict[int, set[int]],
        idom: dict[int, int],
    ) -> dict[int, set[int]]:
        """Dominance frontiers via the idom walk per multi-predecessor join."""
        position_of = {index: position for position, index in enumerate(order)}
        frontiers: dict[int, set[int]] = {}
        for block_index in sorted(reachable, key=lambda i: position_of[i]):
            if len(preds[block_index]) < 2:
                continue
            for predecessor in preds[block_index]:
                runner: int | None = predecessor
                while runner is not None and runner != idom.get(block_index):
                    frontiers.setdefault(runner, set()).add(block_index)
                    runner = idom.get(runner)
        return frontiers

    def _definition_sites(
        self, reachable: set[int], raw_by_index: dict[int, list[dict[str, Any]]]
    ) -> dict[str, set[int]]:
        """Registers defined per reachable block (mirrors _convert's writes)."""
        definitions: dict[str, set[int]] = {}
        for block_index, instructions in raw_by_index.items():
            if block_index not in reachable:
                continue
            for payload in instructions:
                mnemonic = (payload.get("mnemonic") or "").strip().lower()
                parts = _split_operands(payload.get("operands") or "")
                if mnemonic in _CALL_MNEMONICS:
                    registers = list(abi_volatile_registers(self._bitness))
                    registers.append(FLAGS_REGISTER)
                else:
                    registers = [
                        hit[0] for hit in self._register_writes(mnemonic, parts)
                    ]
                    if mnemonic in _FLAGS_WRITERS:
                        registers.append(FLAGS_REGISTER)
                for canonical in registers:
                    definitions.setdefault(canonical, set()).add(block_index)
        return definitions

    def _place_phis(
        self,
        definitions: dict[str, set[int]],
        frontiers: dict[int, set[int]],
    ) -> dict[int, list[str]]:
        """Cytron worklist: phi sites per block, registers in sorted order."""
        sites: dict[int, list[str]] = {}
        for register in sorted(definitions):
            work = sorted(definitions[register])
            placed: set[int] = set()
            while work:
                block_index = work.pop()
                for frontier in sorted(frontiers.get(block_index, ())):
                    if frontier not in placed:
                        placed.add(frontier)
                        sites.setdefault(frontier, []).append(register)
                        if frontier not in definitions[register]:
                            work.append(frontier)
        return sites

    def _new_phi_value(self, canonical: str, block_index: int) -> str:
        """Create the phi value a join block defines (no stack push here)."""
        if len(self._values) >= self._max_values:
            self.truncated_values = True
            self._warn(
                f"value budget max_values={self._max_values} reached at "
                f"0x{self._cursor:x}; SSA construction stopped early"
            )
            raise _BudgetStopError
        version = self._versions.get(canonical, 0) + 1
        value_id = f"{canonical}.{version}"
        self._versions[canonical] = version
        self._values[value_id] = _ValueRecord(
            id=value_id,
            kind="phi",
            type_hint=None,
            def_block=block_index,
            def_insn_index=None,
        )
        return value_id

    def _seed_arguments(self) -> None:
        """Reserve the ABI argument registers' version 0 with inferred types."""
        if not self._attach_types:
            return
        try:
            inferred = infer_argument_types(
                self._instruction_stream(),
                8 if self._bitness >= 64 else 4,
                abi="ms64",
            )
        except AnalysisError:
            inferred = ()
        for argument in inferred:
            self._arg_hints[argument.register] = argument.c_type

    def _instruction_stream(self) -> list[dict[str, Any]]:
        """The raw instruction payloads, in walked order, for type inference."""
        stream: list[dict[str, Any]] = []
        for block in self._cfg.blocks:
            stream.extend(block.instructions)
        return stream

    def _convert(
        self,
        mnemonic: str,
        parts: list[str],
        payload: dict[str, Any],
        block_index: int,
        local_index: int,
    ) -> SSAInstruction | None:
        """Convert one instruction, or return ``None`` when the value cap hit."""
        text = payload.get("text") or f"{mnemonic} {' '.join(parts)}".strip()
        try:
            # Expression reads resolve BEFORE the writes create new versions.
            read_ids = self._expr_read_ids(parts)
            condition = self._advance_condition(mnemonic, parts, text)
            if mnemonic in _CALL_MNEMONICS:
                reads, writes, call_args = self._convert_call(parts, block_index, local_index)
            else:
                call_args = None
                reads = self._resolve_reads(mnemonic, parts)
                if _reads_flags(mnemonic):
                    self._read(FLAGS_REGISTER, reads)
                expr = self._expr_for(mnemonic, parts, read_ids)
                writes = []
                for canonical, alias, width in self._register_writes(mnemonic, parts):
                    hint = self._type_hint_for(mnemonic, [(canonical, alias, width)])
                    writes.append(
                        self._new_value(
                            canonical, "def", block_index, local_index, hint, expr=expr
                        )
                    )
                if mnemonic in _FLAGS_WRITERS:
                    writes.append(
                        self._new_value(
                            FLAGS_REGISTER, "def", block_index, local_index, None
                        )
                    )
            for value_id in reads:
                self._record_use(value_id, block_index, local_index)
        except _BudgetStopError:
            return None
        return SSAInstruction(
            address=_payload_address(payload),
            mnemonic=mnemonic,
            reads=tuple(reads),
            writes=tuple(writes),
            text=text,
            call_args=call_args,
            condition=condition,
        )

    def _convert_call(
        self, parts: list[str], block_index: int, local_index: int
    ) -> tuple[list[str], list[str], tuple[str, ...]]:
        """Resolve a call: argument-register reads first, then volatile clobbers."""
        reads: list[str] = []
        call_args: list[str] = []
        for canonical in self._arguments:
            value_id = self._current_version(canonical)
            call_args.append(value_id)
            self._read(canonical, reads)
        for part in parts:
            for canonical in _register_mentions(part, self._aliases):
                self._read(canonical, reads)
        writes: list[str] = [
            self._new_value(canonical, "clobber", block_index, local_index, None)
            for canonical in abi_volatile_registers(self._bitness)
        ]
        writes.append(
            self._new_value(FLAGS_REGISTER, "clobber", block_index, local_index, None)
        )
        return reads, writes, tuple(call_args)

    def _note_loop_edge(
        self,
        mnemonic: str,
        operands: str,
        address: int,
        block_index: int,
        block_starts: dict[int, int],
        raw_instructions: list[dict[str, Any]],
    ) -> None:
        """Record an honest loop boundary when a branch jumps backward."""
        if mnemonic in _CALL_MNEMONICS:
            return
        target = _direct_target(operands)
        if target is None:
            return
        target_index = block_starts.get(target)
        if target_index is None or target_index > block_index:
            return
        self.loop_count += 1
        self._loop_flags[target_index] = True
        if target_index not in self._phi_required:
            live = self._live_in_registers(raw_instructions)
            self._phi_required[target_index] = tuple(sorted(live))
        self._warn(
            f"loop back-edge from 0x{address:x} into block {target_index} "
            f"(0x{target:x}): loop boundary recorded; reaching versions merge "
            "through phi values at dominance-frontier joins (increment 6)"
        )

    def _live_in_registers(self, instructions: list[dict[str, Any]]) -> set[str]:
        """Registers locally live-in per a raw scan of the block's instructions."""
        live: set[str] = set()
        for payload in instructions:
            mnemonic = (payload.get("mnemonic") or "").strip().lower()
            for canonical in _register_mentions(payload.get("operands") or "", self._aliases):
                live.add(canonical)
            if _reads_flags(mnemonic):
                live.add(FLAGS_REGISTER)
        return live


def _payload_address(payload: dict[str, Any]) -> int:
    """Parse the ``"0x..."`` address of one ``IRInstruction.to_dict()`` payload."""
    raw = payload.get("address")
    if isinstance(raw, int):
        return raw
    try:
        return int(str(raw), 16)
    except (TypeError, ValueError) as exc:
        raise AnalysisError(f"instruction payload has no usable address: {raw!r}") from exc

def build_ssa(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    *,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_values: int = MAX_VALUES,
    max_uses_per_value: int = MAX_USES_PER_VALUE,
    attach_types: bool = True,
) -> SSAFunction:
    """Build the straight-line SSA view of the function region at ``address``.

    Args:
        path: File the bytes are read from (read-only; never executed).
        info: Loaded binary metadata used for address mapping and decoding.
        address: Virtual address of the function's first instruction; must be
            inside an executable section.
        max_instructions: Instruction budget for the SSA walk (1 ..
            :data:`MAX_INSTRUCTIONS`).
        max_blocks: Block budget for the SSA view (1 .. :data:`MAX_BLOCKS`).
        max_values: Value budget (1 .. :data:`MAX_VALUES`); the walk stops at
            the first definition past it.
        max_uses_per_value: Per-value use budget (1 ..
            :data:`MAX_USES_PER_VALUE`); further uses are dropped and flagged.
        attach_types: When true, definitions carry ``type_hint`` values from
            :mod:`codevanta.analysis.type_propagation`.

    Returns:
        The :class:`SSAFunction` for the region.

    Raises:
        AnalysisError: When a budget is out of range, when ``address`` is not
            executable code, or when the region decodes to no instruction.
    """
    _check_budget("max_instructions", max_instructions, MAX_INSTRUCTIONS)
    _check_budget("max_blocks", max_blocks, MAX_BLOCKS)
    _check_budget("max_values", max_values, MAX_VALUES)
    _check_budget("max_uses_per_value", max_uses_per_value, MAX_USES_PER_VALUE)

    cfg = build_recursive_cfg(
        path,
        info,
        address,
        max_instructions=max_instructions,
        max_blocks=max_blocks,
    )
    if cfg.instruction_count == 0:
        raise AnalysisError(f"no decodable instruction at 0x{address:x}")

    builder = _SSABuilder(
        cfg,
        bitness=info.bitness,
        max_instructions=max_instructions,
        max_blocks=max_blocks,
        max_values=max_values,
        max_uses_per_value=max_uses_per_value,
        attach_types=attach_types,
    )
    blocks, values = builder.run()

    value_tuple = tuple(
        SSAValue(
            id=record.id,
            kind=record.kind,
            type_hint=record.type_hint,
            expr=record.expr,
            def_block=record.def_block,
            def_insn_index=record.def_insn_index,
            uses=tuple(record.uses),
        )
        for record in values.values()
    )
    warnings = list(builder._warnings)
    if cfg.truncated:
        warnings.append(
            "the underlying CFG traversal was truncated; the SSA view covers only "
            "the reported blocks"
        )
    warnings.extend(cfg.warnings)

    evidence = Evidence(
        source=_SOURCE,
        method=_METHOD,
        confidence=Confidence.MEDIUM,
        address=address,
        detail=(
            f"dominance-ordered SSA over {len(blocks)} CFG block(s): reads resolve "
            "to the top of the per-register definition stack in dominator order, "
            "multi-predecessor joins define phi values merging the versions each "
            "reachable predecessor reaches, calls clobber the ABI-volatile "
            "registers, loop back-edges still mark loop boundaries with their "
            "live-in hints, unreachable blocks rename linearly from entry state; "
            "nothing is executed"
        ),
    )
    return SSAFunction(
        address=address,
        name=cfg.function_name,
        blocks=tuple(blocks),
        values=value_tuple,
        loop_count=builder.loop_count,
        truncated_blocks=builder.truncated_blocks,
        # The instruction budget is enforced by the underlying CFG traversal
        # first (the SSA walk consumes its output); when the traversal hit it,
        # the SSA view covers exactly that many instructions and no more.
        truncated_instructions=(
            builder.truncated_instructions
            or (cfg.truncated and cfg.instruction_count >= max_instructions)
        ),
        truncated_values=builder.truncated_values,
        uses_truncated=builder.uses_truncated,
        warnings=tuple(warnings),
        evidence=evidence,
    )


def _check_budget(name: str, value: int, maximum: int) -> None:
    """Reject a non-integer or out-of-range SSA budget."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError(f"{name} must be an int, got {value!r}")
    if not 1 <= value <= maximum:
        raise AnalysisError(f"{name} must be between 1 and {maximum}, got {value}")










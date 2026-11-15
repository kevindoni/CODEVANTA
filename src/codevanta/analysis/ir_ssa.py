"""Typed SSA intermediate representation over the CFG (decompiler v2, increment 1).

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
4. **Loop boundaries (honest limit).** When a branch targets a block at or
   before the current block (a back-edge), the target block is marked
   ``loop_boundary`` and gets a ``phi_required`` set naming every register
   locally live-in there. **No phi functions are constructed**: reads inside a
   loop body still resolve to the single straight-line version and a forward
   control-flow join reads whatever the walked order says. The loop boundary
   notes plus the MEDIUM-confidence evidence state exactly where that is
   unsound; a later increment replaces this with a dominance-ordered walk.
5. **Types (optional).** A definition's ``type_hint`` uses the vocabulary of
   :mod:`codevanta.analysis.type_propagation`: the written alias's width
   (``mov eax, ...`` -> ``uint32_t``), ``lea`` -> the pointer type, and the
   ABI argument registers get whatever
   :func:`~codevanta.analysis.type_propagation.infer_argument_types` infers
   from use evidence. Absent evidence -> ``None``.

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
    "MAX_INSTRUCTIONS",
    "MAX_USES_PER_VALUE",
    "MAX_VALUES",
    "SSABlock",
    "SSAFunction",
    "SSAInstruction",
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

#: Default block budget for :func:`build_ssa` (also the MCP tool default).
DEFAULT_MAX_BLOCKS = 512

#: Default instruction budget for :func:`build_ssa` (also the MCP tool default).
DEFAULT_MAX_INSTRUCTIONS = 2_000

#: Canonical name of the flags pseudo-register in SSA value ids.
FLAGS_REGISTER = "FLAGS"

_SOURCE = "ir.ssa"
_METHOD = "cfg-straight-line-ssa"

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


# ---------------------------------------------------------------------------
# public SSA dataclasses (all JSON-safe, deterministic ordering)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SSAValue:
    """One SSA-named value: a definition, an undef, a clobber or an argument.

    Attributes:
        id: Stable name ``"<register>.<version>"``, e.g. ``"rax.3"``. Version
            ``0`` is the incoming/undefined value.
        kind: ``"def"`` (instruction write), ``"undef"`` (read before any
            definition in walked order), ``"clobber"`` (call side effect) or
            ``"arg"`` (ABI argument register at function entry).
        type_hint: Optional C type from :mod:`codevanta.analysis.type_propagation`,
            ``None`` when nothing types the definition.
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

    def to_dict(self) -> dict[str, Any]:
        """Serialize the value for the JSON report."""
        return {
            "id": self.id,
            "kind": self.kind,
            "type_hint": self.type_hint,
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
    """

    address: int
    mnemonic: str
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    text: str
    call_args: tuple[str, ...] | None = None

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
        return data


@dataclass(frozen=True)
class SSABlock:
    """One CFG block converted to SSA instructions.

    Attributes:
        index: Position of the block in the CFG's deterministic order.
        start: Virtual address of the first instruction.
        instructions: The block's SSA instructions in address order.
        loop_boundary: ``True`` when some branch jumps back into this block.
        phi_required: Registers locally live-in at the loop head; a later
            increment must place phi functions for them.
    """

    index: int
    start: int
    instructions: tuple[SSAInstruction, ...]
    loop_boundary: bool = False
    phi_required: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize the block for the JSON report."""
        return {
            "index": self.index,
            "start": f"0x{self.start:x}",
            "instruction_count": len(self.instructions),
            "instructions": [instruction.to_dict() for instruction in self.instructions],
            "loop_boundary": self.loop_boundary,
            "phi_required": list(self.phi_required),
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
        self.truncated_blocks = False
        self.truncated_instructions = False
        self.truncated_values = False
        self.uses_truncated = False
        self.loop_count = 0
        self._loop_flags: dict[int, bool] = {}
        self._phi_required: dict[int, tuple[str, ...]] = {}

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
        )
        return value_id

    def _seed_incoming(self, canonical: str, kind: str, type_hint: str | None) -> None:
        """Reserve version 0 of ``canonical`` (undef or incoming argument)."""
        self._versions[canonical] = 0
        self._values[f"{canonical}.0"] = _ValueRecord(
            id=f"{canonical}.0",
            kind=kind,
            type_hint=type_hint,
            def_block=None,
            def_insn_index=None,
        )

    def _current_version(self, canonical: str) -> str:
        """Resolve a read of ``canonical`` to its current SSA value id.

        A register never defined in the walked order resolves to its lazily
        created version-0 value: ``"arg"`` for ABI argument registers (the
        caller defined them), ``"undef"`` for everything else.
        """
        if canonical not in self._versions:
            if canonical in self._arguments:
                self._seed_incoming(canonical, "arg", self._arg_hints.get(canonical))
            else:
                self._seed_incoming(canonical, "undef", None)
        return f"{canonical}.{self._versions[canonical]}"

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

    # -- driver -------------------------------------------------------------

    def run(self) -> tuple[list[SSABlock], dict[str, _ValueRecord]]:
        """Walk the CFG blocks in deterministic order and build the SSA."""
        cfg_blocks = list(self._cfg.blocks)
        order = sorted(range(len(cfg_blocks)), key=lambda i: cfg_blocks[i].start)
        self._seed_arguments()
        block_starts = {cfg_blocks[index].start: index for index in order}
        raw_blocks = [cfg_blocks[index].instructions for index in order]

        converted: list[list[SSAInstruction]] = [[] for _ in order]
        total = 0
        stop = False
        for position, block_index in enumerate(order):
            if stop or position >= self._max_blocks:
                if not stop:
                    self.truncated_blocks = True
                    self._warn(
                        f"block budget max_blocks={self._max_blocks} reached; "
                        f"{len(order) - position} CFG block(s) left out of the SSA view"
                    )
                break
            for local_index, payload in enumerate(raw_blocks[position]):
                if total >= self._max_instructions:
                    self.truncated_instructions = True
                    self._warn(
                        f"instruction budget max_instructions={self._max_instructions} "
                        "reached; SSA construction stopped before the end of the CFG"
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
                converted[position].append(instruction)
                total += 1
                self._note_loop_edge(
                    mnemonic, operands, address, block_index, block_starts,
                    raw_blocks[position],
                )

        ssa_blocks = [
            SSABlock(
                index=block_index,
                start=cfg_blocks[block_index].start,
                instructions=tuple(converted[position]),
                loop_boundary=self._loop_flags.get(block_index, False),
                phi_required=self._phi_required.get(block_index, ()),
            )
            for position, block_index in enumerate(order)
        ]
        return ssa_blocks, self._values

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
        try:
            if mnemonic in _CALL_MNEMONICS:
                reads, writes, call_args = self._convert_call(parts, block_index, local_index)
            else:
                call_args = None
                reads = self._resolve_reads(mnemonic, parts)
                if _reads_flags(mnemonic):
                    self._read(FLAGS_REGISTER, reads)
                writes = []
                for canonical, alias, width in self._register_writes(mnemonic, parts):
                    hint = self._type_hint_for(mnemonic, [(canonical, alias, width)])
                    writes.append(
                        self._new_value(canonical, "def", block_index, local_index, hint)
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
        text = payload.get("text") or f"{mnemonic} {' '.join(parts)}".strip()
        return SSAInstruction(
            address=_payload_address(payload),
            mnemonic=mnemonic,
            reads=tuple(reads),
            writes=tuple(writes),
            text=text,
            call_args=call_args,
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
            f"(0x{target:x}): loop boundary recorded, phi functions are not "
            "constructed (increment 1 limitation); reads inside the loop body "
            "still resolve to the straight-line version"
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
            f"straight-line SSA over {len(blocks)} CFG block(s): reads resolve to the "
            "latest definition in walked order, calls clobber the ABI-volatile "
            "registers, loop back-edges are recorded as boundaries with phi-required "
            "markers but no phi functions are constructed (increment 1 limitation); "
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










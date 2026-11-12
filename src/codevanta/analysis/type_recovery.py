"""Heuristic struct-field recovery from memory operands (phase 2h).

:func:`suggest_struct` disassembles a *bounded* window of a function and reads
the memory operands of every decoded instruction:

1. Only three addressing shapes are understood: ``[reg]``, ``[reg + 0xNN]`` and
   ``[reg - 0xNN]`` (a decimal displacement -- ``[rbp - 8]`` -- is accepted
   exactly like a hexadecimal one). Anything with an index register, a scale or
   a segment prefix (``[rdi + rcx*4]``, ``fs:[rax]``) is skipped rather than
   guessed.
2. The field **width** comes from the Intel size keyword on the operand
   (``byte``/``word``/``dword``/``qword`` = 1/2/4/8), falling back to the
   pointer width of the binary when the operand carries no keyword.
3. The access **direction** is a write when the memory operand is the *first*
   operand, and a read otherwise. Instructions that only compare -- ``cmp``,
   ``cmpsb``/``cmpsw``/``cmpsd``/``cmpsq``, ``test`` -- are always reads, even
   though the memory operand comes first.

The accesses are then aggregated **per offset**: the dominant width of an offset
is the one seen most often (ties go to the wider access, which is the safer
assumption), and the read/write counts are totals for that offset over all
widths. Fields are returned sorted by ascending offset, so the result is
deterministic for a given input.

Everything here is a *heuristic*: a struct field recovered from operand shapes
is a hypothesis about how a function treats memory around one base register. It
is not a verified type, and it says nothing about a field's signedness, purpose
or lifetime. Every evidence record says so and sits at
:attr:`~codevanta.evidence.confidence.Confidence.MEDIUM`, never higher.

Work is bounded three ways: the caller's ``max_instructions`` budget (default
:data:`DEFAULT_MAX_INSTRUCTIONS`), the ``max_fields`` cap (default
:data:`DEFAULT_MAX_FIELDS`; extras are dropped and reported through
:attr:`StructSuggestion.truncated`), and the file-backed bytes of the containing
section -- at most ``max_instructions * 16`` bytes are read. The analysed file
is only ever read from disk, never mapped or executed.

Known, deliberate limits: ``lea`` and ``nop`` are skipped because their bracket
operands are not memory accesses; read-modify-write instructions (``add ...,
[rdi+8]``, ``cmpxchg``) count as writes only; operand syntax from other
architectures (ARM/MIPS ``[x0, #0x10]``) does not match at all, so a
non-Intel-shaped binary simply yields no fields instead of wrong ones.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.core.disassembler import Disassembler, DisassemblyError
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import MAX_DISASSEMBLY_COUNT, AnalysisError, read_code
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence
from codevanta.ir.instruction import IRInstruction

__all__ = [
    "DEFAULT_MAX_FIELDS",
    "DEFAULT_MAX_INSTRUCTIONS",
    "MAX_MAX_FIELDS",
    "MAX_MAX_INSTRUCTIONS",
    "MIN_MAX_FIELDS",
    "MIN_MAX_INSTRUCTIONS",
    "READ",
    "STACK_REGISTERS",
    "WRITE",
    "FieldAccess",
    "StructSuggestion",
    "SuggestedField",
    "parse_memory_operands",
    "suggest_struct",
]

#: Default instruction budget for one suggestion.
DEFAULT_MAX_INSTRUCTIONS = 2_000

#: Smallest accepted ``max_instructions``; smaller requests are rejected.
MIN_MAX_INSTRUCTIONS = 1

#: Largest accepted ``max_instructions``; larger requests are rejected.
MAX_MAX_INSTRUCTIONS = MAX_DISASSEMBLY_COUNT

#: Default ceiling on distinct field offsets kept in one suggestion.
DEFAULT_MAX_FIELDS = 64

#: Smallest accepted ``max_fields``; smaller requests are rejected.
MIN_MAX_FIELDS = 1

#: Largest accepted ``max_fields``; larger requests are rejected.
MAX_MAX_FIELDS = 512

#: Direction label for a memory operand that is only read.
READ = "read"

#: Direction label for a memory operand that is written (possibly read-modify-write).
WRITE = "write"

#: Longest possible encoding of one instruction on a supported architecture.
#: Used to size the read window for the instruction budget.
_MAX_INSTRUCTION_BYTES = 16

#: Intel size keyword -> width in bytes.
_SIZE_KEYWORD_WIDTHS: dict[str, int] = {
    "byte": 1,
    "word": 2,
    "dword": 4,
    "qword": 8,
}

#: Pointer width in bytes, keyed by bitness. Unknown bitness falls back to 8.
_POINTER_WIDTH_BY_BITNESS: dict[int, int] = {16: 2, 32: 4, 64: 8}

#: Registers treated as frame pointers. Operands based on them describe a stack
#: slot or a spilled local, not a struct field, so they are skipped unless the
#: caller passes ``include_stack=True``.
STACK_REGISTERS = frozenset({"sp", "esp", "rsp", "bp", "ebp", "rbp"})

#: Instruction-pointer registers. ``[rip + disp]`` addresses a global, not a
#: field of the pointer argument, so these bases are always skipped.
INSTRUCTION_POINTER_REGISTERS = frozenset({"ip", "eip", "rip"})

#: Mnemonics whose memory operands are only compared, never assigned.
_COMPARE_MNEMONICS = frozenset({"cmp", "cmps", "cmpsb", "cmpsw", "cmpsd", "cmpsq", "test"})

#: Mnemonics that carry a bracket expression without touching memory.
_NON_ACCESSING_MNEMONICS = frozenset({"lea", "nop"})

#: A memory operand with an optional size keyword, a single base register and an
#: optional signed displacement: ``qword ptr [rdi + 0x18]``, ``[rax]``,
#: ``dword ptr [rbp - 8]``.
#:
#: An index register (``[rdi + rcx*4]``) or a segment prefix never matches, so
#: those operands are skipped instead of being mis-attributed to a field.
_MEMORY_OPERAND = re.compile(
    r"^(?:(?P<size>byte|word|dword|qword)\s+ptr\s+)?"
    r"\[\s*(?P<base>[A-Za-z][A-Za-z0-9]*)"
    r"(?:\s*(?P<sign>[+-])\s*(?P<displacement>0x[0-9a-fA-F]+|[0-9]+))?"
    r"\s*\]$"
)

_FIELD_EVIDENCE_SOURCE = "type_recovery.memory_operand"
_FIELD_EVIDENCE_METHOD = "operand_scan"
_SUGGESTION_EVIDENCE_SOURCE = "type_recovery.suggestion"
_SUGGESTION_EVIDENCE_METHOD = "operand_aggregation"


@dataclass(frozen=True)
class FieldAccess:
    """One observed access to a field-shaped memory operand.

    Attributes:
        offset: Displacement relative to ``base_register``; negative for
            ``[reg - N]``.
        width: Access width in bytes (1, 2, 4, 8, or the pointer width).
        direction: :data:`READ` or :data:`WRITE`, decided from the operand
            position and the mnemonic.
        base_register: Lowercase base register of the operand, e.g. ``"rdi"``.
        address: Virtual address of the instruction that performed the access.
        instruction: Instruction text, e.g. ``"mov rax, qword ptr [rdi + 0x10]"``.
    """

    offset: int
    width: int
    direction: str
    base_register: str
    address: int
    instruction: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "offset": f"0x{self.offset:x}",
            "width": self.width,
            "direction": self.direction,
            "base_register": self.base_register,
            "address": f"0x{self.address:x}",
            "instruction": self.instruction,
        }


@dataclass(frozen=True)
class SuggestedField:
    """A struct field suggested by aggregating accesses at one offset.

    Attributes:
        offset: Displacement of the field inside the struct.
        width: Dominant access width in bytes.
        read_count: Accesses classified as reads at this offset (all widths).
        write_count: Accesses classified as writes at this offset (all widths).
        first_access: Virtual address of the first instruction that touched the
            offset, or ``None`` when no access was recorded.
        evidence: Justification, always at ``Confidence.MEDIUM``.
    """

    offset: int
    width: int
    read_count: int
    write_count: int
    first_access: int | None
    evidence: Evidence

    @property
    def access_count(self) -> int:
        """Total number of accesses (reads plus writes) at this offset."""
        return self.read_count + self.write_count

    def to_dict(self) -> dict[str, Any]:
        first = self.first_access
        return {
            "offset": f"0x{self.offset:x}",
            "width": self.width,
            "read_count": self.read_count,
            "write_count": self.write_count,
            "access_count": self.access_count,
            "first_access": f"0x{first:x}" if first is not None else None,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class StructSuggestion:
    """The fields suggested for the struct a function receives in a register.

    Attributes:
        address: Virtual address the sweep started at.
        fields: Suggested fields sorted by ascending offset (at most
            ``max_fields`` entries).
        instruction_count: Number of decoded instructions the sweep considered.
        max_fields: Field cap that was applied.
        truncated: True when distinct offsets were dropped by ``max_fields``.
            Instruction-budget exhaustion is not reported here.
        include_stack: Whether stack-based operands were kept.
        evidence: Justification for the suggestion as a whole.
    """

    address: int
    fields: tuple[SuggestedField, ...]
    instruction_count: int
    max_fields: int
    truncated: bool
    include_stack: bool
    evidence: Evidence

    @property
    def field_count(self) -> int:
        """Number of suggested fields."""
        return len(self.fields)

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": f"0x{self.address:x}",
            "instruction_count": self.instruction_count,
            "field_count": self.field_count,
            "max_fields": self.max_fields,
            "truncated": self.truncated,
            "include_stack": self.include_stack,
            "fields": [field.to_dict() for field in self.fields],
            "evidence": self.evidence.to_dict(),
        }


def _split_operands(operands: str) -> list[str]:
    """Split an operand list on top-level commas, keeping bracket groups intact."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for char in operands:
        if char == "[":
            depth += 1
        elif char == "]":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _pointer_width(bitness: int) -> int:
    """Return the pointer width in bytes for ``bitness`` (8 when unknown)."""
    return _POINTER_WIDTH_BY_BITNESS.get(bitness, 8)


def _parse_displacement(sign: str | None, displacement: str | None) -> int:
    """Turn a matched ``+``/``-`` displacement into a signed offset."""
    if sign is None or displacement is None:
        return 0
    base = 16 if displacement.lower().startswith("0x") else 10
    value = int(displacement, base)
    return -value if sign == "-" else value


#: Mnemonics whose memory operands are read even when they appear first.
_READ_ONLY_MNEMONICS = frozenset({"call", "jmp", "push"})


def _direction(mnemonic: str, operand_index: int) -> str:
    """Classify an access: writes are first operands, compares/calls are reads."""
    if mnemonic in _COMPARE_MNEMONICS or mnemonic in _READ_ONLY_MNEMONICS:
        return READ
    return WRITE if operand_index == 0 else READ


def _width(match: re.Match[str], pointer_width: int) -> int:
    """Width from the operand's size keyword, else the pointer width."""
    size_keyword = match.group("size")
    if size_keyword:
        width = _SIZE_KEYWORD_WIDTHS.get(size_keyword.lower())
        if width is not None:
            return width
    return max(1, pointer_width)


def parse_memory_operands(
    instruction: IRInstruction,
    *,
    include_stack: bool = False,
    pointer_width: int = 8,
) -> tuple[FieldAccess, ...]:
    """Extract field-shaped memory accesses from a single instruction.

    Args:
        instruction: Decoded instruction to inspect.
        include_stack: When true, operands based on :data:`STACK_REGISTERS` are
            kept; by default they are dropped because they usually describe
            stack slots rather than struct fields.
        pointer_width: Width in bytes used when the operand carries no size
            keyword, i.e. ``[rdi + 0x10]`` without ``qword ptr``.

    Returns:
        One :class:`FieldAccess` per memory operand, in operand order. Empty for
        instructions without a supported memory operand, for stack-based
        operands when ``include_stack`` is false, and for mnemonics that carry a
        bracket expression without touching memory (``lea``, ``nop``).
    """
    mnemonic = instruction.mnemonic.strip().lower()
    if not mnemonic or mnemonic in _NON_ACCESSING_MNEMONICS or mnemonic.startswith("prefetch"):
        return ()
    accesses: list[FieldAccess] = []
    for index, operand in enumerate(_split_operands(instruction.operands)):
        match = _MEMORY_OPERAND.match(operand)
        if match is None:
            continue
        base = match.group("base").lower()
        if base in INSTRUCTION_POINTER_REGISTERS:
            continue
        if base in STACK_REGISTERS and not include_stack:
            continue
        accesses.append(
            FieldAccess(
                offset=_parse_displacement(match.group("sign"), match.group("displacement")),
                width=_width(match, pointer_width),
                direction=_direction(mnemonic, index),
                base_register=base,
                address=instruction.address,
                instruction=instruction.text,
            )
        )
    return tuple(accesses)


def _aggregate(accesses: Iterable[FieldAccess]) -> list[SuggestedField]:
    """Reduce accesses to one field per offset, sorted by ascending offset."""
    per_offset: dict[int, dict[int, list[int]]] = {}
    first_access: dict[int, int] = {}
    for access in accesses:
        counts = per_offset.setdefault(access.offset, {}).setdefault(access.width, [0, 0])
        if access.direction == WRITE:
            counts[1] += 1
        else:
            counts[0] += 1
        first_access.setdefault(access.offset, access.address)
    fields: list[SuggestedField] = []
    for offset in sorted(per_offset):
        widths = per_offset[offset]
        # Dominant width: most frequent, ties resolved to the wider access.
        dominant = max(widths.items(), key=lambda item: (item[1][0] + item[1][1], item[0]))[0]
        reads = sum(count[0] for count in widths.values())
        writes = sum(count[1] for count in widths.values())
        first = first_access.get(offset)
        fields.append(
            SuggestedField(
                offset=offset,
                width=dominant,
                read_count=reads,
                write_count=writes,
                first_access=first,
                evidence=Evidence(
                    source=_FIELD_EVIDENCE_SOURCE,
                    method=_FIELD_EVIDENCE_METHOD,
                    confidence=Confidence.MEDIUM,
                    address=first,
                    detail=(
                        f"offset 0x{offset:x}: {dominant}-byte field, "
                        f"{reads} read(s), {writes} write(s); "
                        "field is heuristic, not a verified type"
                    ),
                    extra={
                        "offset": offset,
                        "width": dominant,
                        "read_count": reads,
                        "write_count": writes,
                    },
                ),
            )
        )
    return fields


def _require_int(name: str, value: object, minimum: int, maximum: int) -> int:
    """Validate an integer option and return it as ``int``."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError(f"{name} must be an integer, got {value!r}")
    if value < minimum:
        raise AnalysisError(f"{name} must be >= {minimum}, got {value}")
    if value > maximum:
        raise AnalysisError(f"{name} too large (limit {maximum}), got {value}")
    return value


def suggest_struct(
    path: str | Path,
    info: BinaryInfo,
    start: int,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    max_fields: int = DEFAULT_MAX_FIELDS,
    include_stack: bool = False,
) -> StructSuggestion:
    """Suggest the struct fields a function accesses through memory operands.

    Args:
        path: Binary file the bytes are read from.
        info: Loaded metadata used for address mapping, section bounds, the
            decoder and the pointer width.
        start: Virtual address of the first instruction; must be inside an
            executable section.
        max_instructions: Instruction budget
            (``MIN_MAX_INSTRUCTIONS`` .. ``MAX_MAX_INSTRUCTIONS``).
        max_fields: Ceiling on distinct field offsets kept
            (``MIN_MAX_FIELDS`` .. ``MAX_MAX_FIELDS``). Lower offsets win, the
            rest are dropped and reported through ``truncated``.
        include_stack: When true, ``[rsp]``/``[rbp]``-relative operands are kept
            instead of being treated as stack slots.

    Returns:
        The :class:`StructSuggestion` for the region, with fields sorted by
        ascending offset.

    Raises:
        AnalysisError: When ``start``, ``max_instructions`` or ``max_fields`` is
            invalid, when ``start`` is not inside an executable section, when
            the address has no file bytes, when the architecture cannot be
            disassembled, or when no instruction could be decoded.

    Note:
        Two calls with the same arguments always produce the same suggestion:
        the sweep is linear, aggregation is per offset, and fields, widths and
        counters are all ordered deterministically.
    """
    if isinstance(start, bool) or not isinstance(start, int):
        raise AnalysisError(f"start must be an integer, got {start!r}")
    if start < 0:
        raise AnalysisError(f"start must be non-negative, got {start}")
    instruction_budget = _require_int(
        "max_instructions", max_instructions, MIN_MAX_INSTRUCTIONS, MAX_MAX_INSTRUCTIONS
    )
    field_cap = _require_int("max_fields", max_fields, MIN_MAX_FIELDS, MAX_MAX_FIELDS)
    if not isinstance(include_stack, bool):
        raise AnalysisError(f"include_stack must be a boolean, got {include_stack!r}")

    section = info.section_for_va(start)
    if section is None or not section.is_executable:
        raise AnalysisError(f"address 0x{start:x} is not inside an executable section")

    code = read_code(path, info, start, instruction_budget * _MAX_INSTRUCTION_BYTES)
    try:
        disassembler = Disassembler(info.architecture, info.bitness, info.endianness)
        result = disassembler.disassemble(
            code, base_address=start, max_instructions=instruction_budget
        )
    except DisassemblyError as exc:
        raise AnalysisError(f"cannot disassemble 0x{start:x}: {exc}") from exc

    instructions = list(result.instructions)
    if not instructions:
        raise AnalysisError(f"no instruction decoded at 0x{start:x}")

    pointer_width = _pointer_width(info.bitness)
    accesses = [
        access
        for instruction in instructions
        for access in parse_memory_operands(
            instruction, include_stack=include_stack, pointer_width=pointer_width
        )
    ]
    all_fields = _aggregate(accesses)
    fields = tuple(all_fields[:field_cap])
    truncated = len(all_fields) > field_cap

    evidence = Evidence(
        source=_SUGGESTION_EVIDENCE_SOURCE,
        method=_SUGGESTION_EVIDENCE_METHOD,
        confidence=Confidence.MEDIUM,
        address=start,
        detail=(
            f"{len(fields)} suggested field(s) from {len(accesses)} memory access(es) "
            f"over {len(instructions)} instruction(s) at 0x{start:x}"
            + (" (field cap reached)" if truncated else "")
            + "; fields are heuristic from operand shapes, not verified types"
        ),
        extra={
            "max_instructions": instruction_budget,
            "max_fields": field_cap,
            "instruction_count": len(instructions),
            "memory_access_count": len(accesses),
            "field_count": len(fields),
            "truncated": truncated,
            "include_stack": include_stack,
        },
    )
    return StructSuggestion(
        address=start,
        fields=fields,
        instruction_count=len(instructions),
        max_fields=field_cap,
        truncated=truncated,
        include_stack=include_stack,
        evidence=evidence,
    )

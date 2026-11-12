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
   operand, and a read otherwise. Instructions that only dereference a memory
   operand -- ``cmp``, ``cmpsb``/``cmpsw``/``cmpsd``/``cmpsq``, ``test``,
   ``call``, ``jmp`` and ``push`` -- are always reads, even though the memory
   operand comes first.
4. The signedness of an access comes from the **mnemonic**: sign-extending
   operations (``movsx``, ``movsxd``, ``sar``, ``idiv``, ``cqo``, ``cdq``,
   ``cwd``, ``cbw``) mark the operand as signed, zero-extending or unsigned
   operations (``movzx``, ``shr``, ``div``, ``mul``) mark it as unsigned, and
   every other mnemonic (``mov``, ``add``, ``cmp``, ...) carries no hint at all.
   The hint is aggregated per offset like the width: only-signed accesses give
   ``signed=True``, only-unsigned accesses give ``signed=False``, no hint gives
   ``None``, and a contradiction gives ``None`` plus a
   :class:`SignednessConflictWarning` naming the offset.

The accesses are then aggregated **per offset**: the dominant width of an offset
is the one seen most often (ties go to the wider access, which is the safer
assumption), and the read/write counts are totals for that offset over all
widths. Fields are returned sorted by ascending offset, so the result is
deterministic for a given input.

Two cheap layout hints are derived from those fields:

* ``alignment`` is the greatest common divisor of the **absolute** offsets,
  ignoring offset 0 (which is a multiple of everything). It is ``None`` when
  fewer than two distinct absolute non-zero offsets were seen, because a single
  offset carries no information about a layout. Natural alignment therefore shows up as
  a power-of-two gcd; odd offsets collapse it to 1.
* ``array_groups`` are **maximal runs** of at least
  :data:`_MIN_ARRAY_ELEMENTS` consecutive fields (in ascending offset order)
  that share one width *and* one stride between neighbours. Each run becomes one
  :class:`ArrayGroup` starting at its first field. A run is never extended past a
  width change or a stride change, and never overlaps the next group.

Both hints are computed from the fields that are actually reported, i.e. after
the ``max_fields`` cap, so a group never refers to a field that was dropped.

:func:`suggest_structs` merges several windows -- one per address of the same
binary -- into a single :class:`StructSuggestion`. Each address is decoded
exactly once with the same budget, and the per-window fields are folded
together:

* There is one merged field per offset. Its read/write counters are the sums
  over the windows that saw the offset, and its ``first_access`` is the earliest
  access any window recorded.
* Equal per-window widths are kept as they are. When the windows disagree the
  widest width wins and a :class:`WidthConflictWarning` names the offset and the
  widths: a window that only ever saw a ``dword`` is not evidence *against* the
  ``qword`` another window saw.
* Signedness is folded with the rule used inside one window -- consistent hints
  survive, no hint stays unknown, and a contradiction becomes ``None`` plus one
  :class:`SignednessConflictWarning`. A contradiction *inside* a window has
  already warned during that window's own aggregation; the merge does not warn
  about it a second time, because it only sees the resolved per-window hints.
* ``alignment``, ``array_groups`` and ``truncated`` are recomputed from the
  merged fields, so a run that only becomes visible across windows is still
  found.

The merged work is bounded too: at most ``max_windows`` addresses are accepted
(:data:`MAX_MERGED_WINDOWS`), duplicate addresses are rejected instead of being
merged twice, and every window costs at most one decode of ``max_instructions``
instructions. The merged field set stays capped at :data:`DEFAULT_MAX_FIELDS`
distinct offsets, which is lossless: each window is capped there as well and the
cap always keeps the *lowest* offsets, so an offset a window dropped cannot
belong to the lowest merged offsets either.

Everything here is a *heuristic*: a struct field recovered from operand shapes
is a hypothesis about how a function treats memory around one base register. It
is not a verified type, and it says nothing about a field's purpose or lifetime.
The ``signed`` hint is only a reading of the mnemonics that happened to be in the
window, so ``None`` there means "no signedness evidence", never "safe", and a
sign-extending *read* does not prove the field is a signed integer. Every
evidence record says so and sits at
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
import warnings
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass
from math import gcd
from pathlib import Path
from typing import Any

from codevanta.core.disassembler import Disassembler, DisassemblyError
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import MAX_DISASSEMBLY_COUNT, AnalysisError, read_code
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence
from codevanta.ir.instruction import IRInstruction

__all__ = [
    "ArrayGroup",
    "DEFAULT_MAX_FIELDS",
    "DEFAULT_MAX_INSTRUCTIONS",
    "MAX_MAX_FIELDS",
    "MAX_MAX_INSTRUCTIONS",
    "MAX_MERGED_WINDOWS",
    "MIN_MAX_FIELDS",
    "MIN_MAX_INSTRUCTIONS",
    "MIN_MERGED_WINDOWS",
    "READ",
    "SignednessConflictWarning",
    "STACK_REGISTERS",
    "WRITE",
    "FieldAccess",
    "StructSuggestion",
    "SuggestedField",
    "WidthConflictWarning",
    "WindowOverlapWarning",
    "parse_memory_operands",
    "suggest_struct",
    "suggest_structs",
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

#: Default *and* largest number of windows :func:`suggest_structs` merges. Each
#: window costs one bounded decode, so this is the knob that keeps a merge cheap.
MAX_MERGED_WINDOWS = 16

#: Smallest accepted ``max_windows``; smaller requests are rejected.
MIN_MERGED_WINDOWS = 1

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

#: Mnemonics whose result is sign-extended from the memory operand, or which do
#: signed arithmetic on it. Any access they make is treated as ``signed=True``.
#:
#: The implicit-operand sign-extension mnemonics (``cbw``, ``cwd``, ``cdq``,
#: ``cqo``) are absent on purpose: they never carry a memory operand, so they can
#: neither label a field nor appear in an access record.
_SIGNED_MNEMONICS = frozenset({"movsx", "movsxd", "sar", "idiv", "imul"})

#: Mnemonics whose result is zero-extended from the memory operand, or which do
#: unsigned arithmetic on it. Any access they make is treated as ``signed=False``.
_UNSIGNED_MNEMONICS = frozenset({"movzx", "shr", "div", "mul"})

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
_ARRAY_EVIDENCE_SOURCE = "type_recovery.array_run"
_ARRAY_EVIDENCE_METHOD = "stride_run_detection"
_MERGED_FIELD_EVIDENCE_SOURCE = "type_recovery.merged_field"
_MERGED_FIELD_EVIDENCE_METHOD = "window_merge"
_MERGED_SUGGESTION_EVIDENCE_SOURCE = "type_recovery.merged_suggestion"
_MERGED_SUGGESTION_EVIDENCE_METHOD = "window_merge"

#: Smallest number of equally spaced, equally wide fields that is reported as an
#: :class:`ArrayGroup`. Two fields are only a coincidence; three is the minimum
#: at which a repeated stride starts to carry information.
_MIN_ARRAY_ELEMENTS = 3


class SignednessConflictWarning(UserWarning):
    """Emitted when one field offset is accessed as both signed and unsigned.

    The two sources of evidence contradict each other, so the offset is reported
    with ``signed=None`` -- exactly like an offset with no evidence at all --
    and this warning says which offset lost its hint. It is a
    :class:`UserWarning`, so callers that do not care about signedness can
    ignore it; callers that do can filter on it.
    """


class WindowOverlapWarning(UserWarning):
    """Emitted when two merged windows decode the same instruction bytes.

    A partial overlap is not rejected the way a duplicate address is -- looking
    further into the same function is a legitimate second window -- but the shared
    instructions are then counted by both windows, so the per-offset counters are
    per-window sums and can exceed the number of distinct accesses.
    """


class WidthConflictWarning(UserWarning):
    """Emitted when merged windows disagree about one field's dominant width.

    A wider access is never contradicted by a narrower one -- a window that only
    saw ``dword ptr [rdi + 0x10]`` does not prove the field is 4 bytes wide -- so
    the merged field keeps the **widest** per-window width while this warning
    records the offset together with every width that was seen. It is a
    :class:`UserWarning`, so it stays silent unless somebody listens.
    """


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
        signed: ``True`` when every signedness hint recorded at this offset came
            from a sign-extending mnemonic, ``False`` when every hint came from a
            zero-extending/unsigned one, and ``None`` when there was no hint or
            the hints contradicted each other (in which case
            :class:`SignednessConflictWarning` was raised). Omitted from
            :meth:`to_dict` when ``None``.
    """

    offset: int
    width: int
    read_count: int
    write_count: int
    first_access: int | None
    evidence: Evidence
    signed: bool | None = None

    @property
    def access_count(self) -> int:
        """Total number of accesses (reads plus writes) at this offset."""
        return self.read_count + self.write_count

    def to_dict(self) -> dict[str, Any]:
        first = self.first_access
        payload: dict[str, Any] = {
            "offset": f"0x{self.offset:x}",
            "width": self.width,
            "read_count": self.read_count,
            "write_count": self.write_count,
            "access_count": self.access_count,
            "first_access": f"0x{first:x}" if first is not None else None,
            "evidence": self.evidence.to_dict(),
        }
        # An unknown signedness is an absent key, not a ``null``: it keeps the
        # JSON of an unclassified field byte-identical to the pre-signedness one.
        if self.signed is not None:
            payload["signed"] = self.signed
        return payload


@dataclass(frozen=True)
class ArrayGroup:
    """A run of equally spaced, equally wide fields that looks like an array.

    The run is *maximal*: it cannot be extended left or right by another field
    with the same width and stride, and it never overlaps another group.

    Attributes:
        offset: Offset of the first field of the run.
        stride: Distance in bytes between consecutive fields; always positive.
        count: Number of fields in the run (at least
            :data:`_MIN_ARRAY_ELEMENTS`).
        width: Shared dominant width of the run's fields, in bytes.
        evidence: Justification, always at ``Confidence.MEDIUM`` and always
            carrying a heuristic caveat.
    """

    offset: int
    stride: int
    count: int
    width: int
    evidence: Evidence

    @property
    def span(self) -> int:
        """Total byte span covered by the run, i.e. ``stride * (count - 1) + width``."""
        return self.stride * (self.count - 1) + self.width

    def to_dict(self) -> dict[str, Any]:
        return {
            "offset": f"0x{self.offset:x}",
            "stride": self.stride,
            "count": self.count,
            "width": self.width,
            "span": self.span,
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
        memory_access_count: Number of memory accesses the sweep recorded after
            the stack and instruction-pointer filters.
        max_fields: Field cap that was applied.
        truncated: True when distinct offsets were dropped by ``max_fields``.
            Instruction-budget exhaustion is not reported here.
        include_stack: Whether stack-based operands were kept.
        evidence: Justification for the suggestion as a whole.
        alignment: GCD of the absolute non-zero field offsets, or ``None`` when
            fewer than two distinct non-zero offsets were found.
        array_groups: Maximal runs of at least :data:`_MIN_ARRAY_ELEMENTS`
            equally wide, equally spaced fields, in ascending offset order.
    """

    address: int
    fields: tuple[SuggestedField, ...]
    instruction_count: int
    max_fields: int
    truncated: bool
    include_stack: bool
    evidence: Evidence
    alignment: int | None = None
    array_groups: tuple[ArrayGroup, ...] = ()
    memory_access_count: int = 0

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
            "alignment": self.alignment,
            "array_groups": [group.to_dict() for group in self.array_groups],
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


def _signedness(mnemonic: str) -> bool | None:
    """Signedness hint for one mnemonic: ``True``, ``False``, or ``None``.

    The hint is read off the mnemonic alone, because that is all the decoder
    tells us: a sign-extending operation (``movsx``, ``movsxd``, ``sar``,
    ``idiv``, ``cqo``, ``cdq``, ``cwd``, ``cbw``) is evidence for a signed
    field, a zero-extending or unsigned one (``movzx``, ``shr``, ``div``,
    ``mul``) is evidence for an unsigned field, and everything else is no
    evidence either way.
    """
    name = mnemonic.strip().lower()
    if name in _SIGNED_MNEMONICS:
        return True
    if name in _UNSIGNED_MNEMONICS:
        return False
    return None


def _signedness_text(signed: bool | None) -> str:
    """Render a signedness hint for evidence prose."""
    if signed is None:
        return "unknown"
    return "signed" if signed else "unsigned"


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


def _resolve_signedness(
    offset: int, observed: Collection[bool], *, stacklevel: int = 4
) -> bool | None:
    """Collapse the signedness hints of one offset, warning on a contradiction.

    One kind of hint means the offset is taken to be signed (or unsigned), no
    hint means it stays unknown, and a mix is reported as unknown *and*
    announced through :class:`SignednessConflictWarning` -- a contradictory
    offset is not the same thing as an unclassified one, even though both end up
    as ``None``. ``stacklevel`` only moves the warning's reported location.
    """
    if len(observed) == 1:
        return next(iter(observed))
    if len(observed) > 1:
        warnings.warn(
            f"offset 0x{offset:x} is accessed both as signed and as unsigned; "
            "reporting its signedness as unknown",
            SignednessConflictWarning,
            stacklevel=stacklevel,
        )
    return None


def _aggregate(accesses: Iterable[tuple[FieldAccess, bool | None]]) -> list[SuggestedField]:
    """Reduce ``(access, signedness hint)`` pairs to one field per offset.

    Fields come back sorted by ascending offset, so the result is deterministic.
    Widths are collapsed per offset (dominant width wins, ties go to the wider
    access), read/write counters are totals over all widths, and signedness is
    resolved by :func:`_resolve_signedness`.
    """
    per_offset: dict[int, dict[int, list[int]]] = {}
    hints: dict[int, set[bool]] = {}
    first_access: dict[int, int] = {}
    for access, signed in accesses:
        counts = per_offset.setdefault(access.offset, {}).setdefault(access.width, [0, 0])
        if access.direction == WRITE:
            counts[1] += 1
        else:
            counts[0] += 1
        if signed is not None:
            hints.setdefault(access.offset, set()).add(signed)
        first_access.setdefault(access.offset, access.address)
    fields: list[SuggestedField] = []
    for offset in sorted(per_offset):
        widths = per_offset[offset]
        # Dominant width: most frequent, ties resolved to the wider access.
        dominant = max(widths.items(), key=lambda item: (item[1][0] + item[1][1], item[0]))[0]
        reads = sum(count[0] for count in widths.values())
        writes = sum(count[1] for count in widths.values())
        first = first_access.get(offset)
        signed = _resolve_signedness(offset, hints.get(offset, ()))
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
                        f"{reads} read(s), {writes} write(s), "
                        f"signedness {_signedness_text(signed)}; "
                        "field is heuristic, not a verified type"
                    ),
                    extra={
                        "offset": offset,
                        "width": dominant,
                        "read_count": reads,
                        "write_count": writes,
                        "signed": signed,
                        "signed_conflict": len(hints.get(offset, ())) > 1,
                    },
                ),
                signed=signed,
            )
        )
    return fields


def _alignment(fields: Sequence[SuggestedField]) -> int | None:
    """GCD of the absolute non-zero field offsets, or ``None`` when too few.

    Offset 0 is ignored because it is a multiple of every candidate alignment and
    would therefore contribute nothing. Fewer than two distinct non-zero offsets
    cannot distinguish an alignment from the offset itself, so the answer is
    ``None`` instead of a guess.
    """
    magnitudes = sorted({abs(field.offset) for field in fields if field.offset != 0})
    if len(magnitudes) < 2:
        return None
    result = magnitudes[0]
    for magnitude in magnitudes[1:]:
        result = gcd(result, magnitude)
    return result


def _array_group_evidence(
    first: SuggestedField, stride: int, count: int, width: int
) -> Evidence:
    """Build the MEDIUM-confidence evidence record for one array run."""
    return Evidence(
        source=_ARRAY_EVIDENCE_SOURCE,
        method=_ARRAY_EVIDENCE_METHOD,
        confidence=Confidence.MEDIUM,
        address=first.first_access,
        detail=(
            f"array candidate at offset 0x{first.offset:x}: {count} fields of "
            f"{width} byte(s) spaced {stride} byte(s) apart; run heuristic only, "
            "it cannot tell an array from repeated struct members and is not a "
            "verified type"
        ),
        extra={
            "offset": first.offset,
            "stride": stride,
            "count": count,
            "width": width,
        },
    )


def _array_groups(fields: Sequence[SuggestedField]) -> tuple[ArrayGroup, ...]:
    """Group maximal runs of equally wide, equally spaced fields.

    Fields must already be sorted by ascending offset, which
    :func:`_aggregate` guarantees. A run needs at least
    :data:`_MIN_ARRAY_ELEMENTS` fields with one shared width and one shared
    stride between neighbours; the scan is linear, and every field belongs to at
    most one group, so the result is deterministic.
    """
    groups: list[ArrayGroup] = []
    total = len(fields)
    start = 0
    while start < total:
        width = fields[start].width
        end = start
        stride: int | None = None
        while end + 1 < total:
            following = fields[end + 1]
            if following.width != width:
                break
            step = following.offset - fields[end].offset
            if stride is None:
                stride = step
            elif step != stride:
                break
            end += 1
        count = end - start + 1
        if stride is not None and count >= _MIN_ARRAY_ELEMENTS:
            first = fields[start]
            groups.append(
                ArrayGroup(
                    offset=first.offset,
                    stride=stride,
                    count=count,
                    width=width,
                    evidence=_array_group_evidence(first, stride, count, width),
                )
            )
            start = end + 1
        else:
            # No run here: retry from the next field, a shorter run may start there.
            start += 1
    return tuple(groups)


def _merged_width(offset: int, widths: Sequence[int]) -> int:
    """Widest of the per-window widths, warning when the windows disagree.

    A wide access is stronger evidence than a narrow one -- seeing a ``qword``
    proves at least eight bytes, seeing a ``dword`` elsewhere proves nothing
    against it -- so the widest width is kept. The disagreement is still
    reported, because it says how much of the field the code was seen touching.
    """
    widest = max(widths)
    distinct = sorted(set(widths))
    if len(distinct) > 1:
        rendered = ", ".join(f"{width}-byte" for width in distinct)
        warnings.warn(
            f"offset 0x{offset:x} is accessed with different widths ({rendered}); "
            f"keeping the widest, {widest} byte(s)",
            WidthConflictWarning,
            stacklevel=5,
        )
    return widest


def _merge_field(offset: int, parts: Sequence[SuggestedField]) -> SuggestedField:
    """Fold the per-window fields of one offset into a single merged field.

    ``parts`` holds one field per window that saw ``offset``, in ascending
    window-address order. Counters are summed, the widest width wins (see
    :func:`_merged_width`), the earliest access is kept, and signedness is folded
    with the same rule as inside one window (:func:`_resolve_signedness`).
    """
    width = _merged_width(offset, [part.width for part in parts])
    reads = sum(part.read_count for part in parts)
    writes = sum(part.write_count for part in parts)
    hints = {part.signed for part in parts if part.signed is not None}
    window_conflict = any(
        bool(part.evidence.extra.get("signed_conflict")) for part in parts
    )
    if window_conflict:
        # A window whose own accesses contradicted each other must not lose that
        # contradiction to a window that only ever hinted one way.
        if hints:
            warnings.warn(
                f"offset 0x{offset:x} was accessed as signed and unsigned inside one "
                "window, so no merged signedness hint is kept",
                SignednessConflictWarning,
                stacklevel=5,
            )
        signed = None
    else:
        signed = _resolve_signedness(offset, hints, stacklevel=5)
    first = min(
        (part.first_access for part in parts if part.first_access is not None),
        default=None,
    )
    widths = sorted({part.width for part in parts})
    rendered = ", ".join(str(width_seen) for width_seen in widths)
    return SuggestedField(
        offset=offset,
        width=width,
        read_count=reads,
        write_count=writes,
        first_access=first,
        evidence=Evidence(
            source=_MERGED_FIELD_EVIDENCE_SOURCE,
            method=_MERGED_FIELD_EVIDENCE_METHOD,
            confidence=Confidence.MEDIUM,
            address=first,
            detail=(
                f"offset 0x{offset:x}: {width}-byte field merged from "
                f"{len(parts)} window(s) reporting width(s) {rendered}, "
                f"{reads} read(s), {writes} write(s), "
                f"signedness {_signedness_text(signed)}; "
                "field is heuristic, not a verified type"
            ),
            extra={
                "offset": offset,
                "width": width,
                "widths": widths,
                "read_count": reads,
                "write_count": writes,
                "signed": signed,
                "signed_conflict": window_conflict or len(hints) > 1,
                "window_count": len(parts),
            },
        ),
        signed=signed,
    )


def _merge_window_fields(
    windows: Sequence[tuple[int, StructSuggestion]],
) -> tuple[tuple[SuggestedField, ...], bool]:
    """Fold every window's fields into one field per offset.

    Windows must already be in ascending address order. Offsets are visited in
    ascending order, so the warnings raised by :func:`_merge_field` -- and the
    merged fields themselves -- are identical for the same set of addresses
    regardless of the order the caller passed them in.

    Returns:
        Tuple of the merged fields (sorted by ascending offset, capped at
        :data:`DEFAULT_MAX_FIELDS`) and whether offsets were dropped by the cap.
    """
    per_offset: dict[int, list[SuggestedField]] = {}
    for _address, suggestion in windows:
        for field in suggestion.fields:
            per_offset.setdefault(field.offset, []).append(field)
    merged = [_merge_field(offset, per_offset[offset]) for offset in sorted(per_offset)]
    return tuple(merged[:DEFAULT_MAX_FIELDS]), len(merged) > DEFAULT_MAX_FIELDS


def _validate_window_addresses(addresses: object, limit: int) -> tuple[int, ...]:
    """Validate merged window addresses and return them in ascending order.

    Every address is checked for type and sign, duplicates are rejected (a second
    decode of the same address would only double-count its evidence), and the
    number of windows is capped at ``limit`` so the total decode work stays
    bounded by ``limit * max_instructions`` instructions. Sorting makes the merge
    -- including the warnings it raises -- independent of the caller's order.
    """
    if isinstance(addresses, (str, bytes, bytearray)) or not isinstance(
        addresses, Collection
    ):
        raise AnalysisError(f"addresses must be a collection of integers, got {addresses!r}")
    targets: list[int] = []
    seen: set[int] = set()
    for address in addresses:
        if isinstance(address, bool) or not isinstance(address, int):
            raise AnalysisError(f"address must be an integer, got {address!r}")
        if address < 0:
            raise AnalysisError(f"address must be non-negative, got {address}")
        if address in seen:
            raise AnalysisError(f"window address 0x{address:x} appears more than once")
        seen.add(address)
        targets.append(address)
    if not targets:
        raise AnalysisError("addresses must contain at least one window address")
    if len(targets) > limit:
        raise AnalysisError(f"too many window addresses (limit {limit}), got {len(targets)}")
    return tuple(sorted(targets))


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
        ascending offset, each carrying its aggregated ``signed`` hint, plus the
        offset-gcd ``alignment`` and the ``array_groups`` runs derived from those
        reported fields.

    Raises:
        AnalysisError: When ``start``, ``max_instructions`` or ``max_fields`` is
            invalid, when ``start`` is not inside an executable section, when
            the address has no file bytes, when the architecture cannot be
            disassembled, or when no instruction could be decoded.

    Warns:
        SignednessConflictWarning: Once per offset that is accessed both as
            signed and as unsigned. Warnings are resolved during aggregation,
            i.e. before the ``max_fields`` cap, so they are bounded by the
            number of distinct offsets in the window rather than by the cap. The
            warning is informational: the suggestion itself is still returned,
            with ``signed=None`` at the contradictory offsets.

    Note:
        Two calls with the same arguments always produce the same suggestion:
        the sweep is linear, aggregation is per offset, and fields, widths,
        counters and warnings are all ordered deterministically. ``alignment``
        and ``array_groups`` are derived from the reported fields only, so
        capping with ``max_fields`` cannot leave a group pointing at a dropped
        field.
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
        (access, _signedness(instruction.mnemonic))
        for instruction in instructions
        for access in parse_memory_operands(
            instruction, include_stack=include_stack, pointer_width=pointer_width
        )
    ]
    all_fields = _aggregate(accesses)
    fields = tuple(all_fields[:field_cap])
    truncated = len(all_fields) > field_cap
    alignment = _alignment(fields)
    array_groups = _array_groups(fields)

    evidence = Evidence(
        source=_SUGGESTION_EVIDENCE_SOURCE,
        method=_SUGGESTION_EVIDENCE_METHOD,
        confidence=Confidence.MEDIUM,
        address=start,
        detail=(
            f"{len(fields)} suggested field(s) from {len(accesses)} memory access(es) "
            f"over {len(instructions)} instruction(s) at 0x{start:x}"
            + (f", alignment {alignment}" if alignment is not None else "")
            + f", {len(array_groups)} array candidate(s)"
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
            "alignment": alignment,
            "array_group_count": len(array_groups),
            "decoded_bytes": result.consumed_bytes,
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
        alignment=alignment,
        array_groups=array_groups,
        memory_access_count=len(accesses),
    )


def _warn_on_overlapping_windows(
    windows: Sequence[tuple[int, StructSuggestion]],
) -> None:
    """Warn once for every window that starts inside its predecessor's decode.

    Duplicate addresses are rejected outright, because a second decode of the same
    address only double counts. A partial overlap is a legitimate way to look
    further into one function, so it is announced instead of refused: the shared
    instructions are counted by both windows.
    """
    previous_start: int | None = None
    previous_end: int | None = None
    for start, suggestion in windows:
        if previous_end is not None and start < previous_end:
            warnings.warn(
                f"window 0x{start:x} overlaps window 0x{previous_start:x}: the shared "
                "instructions are counted by both windows, so per-offset counters are "
                "per-window sums and may exceed the number of distinct accesses",
                WindowOverlapWarning,
                stacklevel=5,
            )
        decoded = int(suggestion.evidence.extra.get("decoded_bytes") or 0)
        previous_start = start
        previous_end = start + decoded if decoded else None


def suggest_structs(
    path: str | Path,
    info: BinaryInfo,
    addresses: Collection[int],
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    include_stack: bool = False,
    max_windows: int = MAX_MERGED_WINDOWS,
) -> StructSuggestion:
    """Merge the struct evidence of several windows into one suggestion.

    Every address is inspected with exactly one :func:`suggest_struct` call --
    same budget, same stack policy -- and the per-window fields are then folded
    into one field per offset: counters are summed, the widest per-window width
    wins, the earliest access is kept, and signedness is combined with the
    single-window rule. ``alignment``, ``array_groups`` and ``truncated`` are
    recomputed from the merged fields, so a layout that only becomes visible
    across windows is still reported.

    Args:
        path: Binary file the bytes are read from.
        info: Loaded metadata used for address mapping, section bounds, the
            decoder and the pointer width.
        addresses: Window start addresses inside the same binary. Each must be
            inside an executable section; duplicates are rejected instead of
            being counted twice.
        max_instructions: Per-window instruction budget
            (``MIN_MAX_INSTRUCTIONS`` .. ``MAX_MAX_INSTRUCTIONS``). Every window
            is decoded once with this budget, never more.
        include_stack: When true, ``[rsp]``/``[rbp]``-relative operands are kept.
        max_windows: Ceiling on the number of merged windows
            (``MIN_MERGED_WINDOWS`` .. :data:`MAX_MERGED_WINDOWS`).

    Returns:
        A :class:`StructSuggestion` whose ``address`` is the **lowest** merged
        address, whose ``instruction_count`` is the total over all windows, and
        whose fields are sorted by ascending offset and capped at
        :data:`DEFAULT_MAX_FIELDS`. ``max_fields`` reports that cap. The evidence
        lists the window count and every merged address in ``extra``.

    Raises:
        AnalysisError: When ``addresses`` is not a non-empty collection of
            non-negative integers, when an address appears twice, when more than
            ``max_windows`` addresses are given, when ``max_instructions`` or
            ``max_windows`` is out of range, when ``include_stack`` is not a
            bool, or when any single window fails the :func:`suggest_struct`
            checks (not executable, no bytes, undecodable).

    Warns:
        WidthConflictWarning: Once per offset whose per-window dominant widths
            differ; the merged field keeps the widest one.
        SignednessConflictWarning: Once per offset whose surviving per-window
            hints disagree, including an offset that contradicted itself inside one
            window while another window hinted only one way.
        WindowOverlapWarning: Once per window that starts inside its predecessor's
            decoded range; the shared instructions are then counted by both
            windows.

    Note:
        Work is bounded four ways: at most ``max_windows`` windows
        (:data:`MAX_MERGED_WINDOWS`), at most one decode of ``max_instructions``
        instructions per window, at most :data:`DEFAULT_MAX_FIELDS` reported
        offsets per window, and therefore at most ``max_windows *
        max_instructions`` decoded instructions in total. Addresses are sorted
        before the merge, so the result -- including the order of warnings -- is
        identical for any permutation of the same address set. A window that hit
        its own field cap cannot contribute the offsets it dropped, so the merged
        ``truncated`` is the OR of the merge cap and every window cap, and
        ``window_truncated`` names the windows that hit theirs. The result is still
        a heuristic, never a verified type.
    """
    instruction_budget = _require_int(
        "max_instructions", max_instructions, MIN_MAX_INSTRUCTIONS, MAX_MAX_INSTRUCTIONS
    )
    window_budget = _require_int(
        "max_windows", max_windows, MIN_MERGED_WINDOWS, MAX_MERGED_WINDOWS
    )
    if not isinstance(include_stack, bool):
        raise AnalysisError(f"include_stack must be a boolean, got {include_stack!r}")
    targets = _validate_window_addresses(addresses, window_budget)

    windows = [
        (
            start,
            suggest_struct(
                path,
                info,
                start,
                max_instructions=instruction_budget,
                max_fields=DEFAULT_MAX_FIELDS,
                include_stack=include_stack,
            ),
        )
        for start in targets
    ]
    fields, merged_truncated = _merge_window_fields(windows)
    alignment = _alignment(fields)
    array_groups = _array_groups(fields)
    _warn_on_overlapping_windows(windows)
    instruction_count = sum(suggestion.instruction_count for _start, suggestion in windows)
    access_count = sum(suggestion.memory_access_count for _start, suggestion in windows)
    capped_windows = [start for start, suggestion in windows if suggestion.truncated]
    truncated = merged_truncated or bool(capped_windows)
    primary = targets[0]

    evidence = Evidence(
        source=_MERGED_SUGGESTION_EVIDENCE_SOURCE,
        method=_MERGED_SUGGESTION_EVIDENCE_METHOD,
        confidence=Confidence.MEDIUM,
        address=primary,
        detail=(
            f"{len(fields)} merged field(s) from {len(windows)} window(s) "
            f"({', '.join(f'0x{start:x}' for start in targets)}) over "
            f"{instruction_count} instruction(s)"
            + (f", alignment {alignment}" if alignment is not None else "")
            + f", {len(array_groups)} array candidate(s)"
            + (" (field cap reached)" if truncated else "")
            + "; one field per offset with the widest width winning, fields are "
            "heuristic from operand shapes, not verified types"
        ),
        extra={
            "window_count": len(windows),
            "windows": [f"0x{start:x}" for start in targets],
            "max_windows": window_budget,
            "max_instructions": instruction_budget,
            "max_fields": DEFAULT_MAX_FIELDS,
            "instruction_count": instruction_count,
            "memory_access_count": access_count,
            "field_count": len(fields),
            "truncated": truncated,
            "window_truncated": [f"0x{start:x}" for start in capped_windows],
            "include_stack": include_stack,
            "alignment": alignment,
            "array_group_count": len(array_groups),
        },
    )
    return StructSuggestion(
        address=primary,
        fields=fields,
        instruction_count=instruction_count,
        max_fields=DEFAULT_MAX_FIELDS,
        truncated=truncated,
        include_stack=include_stack,
        evidence=evidence,
        alignment=alignment,
        array_groups=array_groups,
    )



"""Definition-use chains, constant propagation and reaching definitions (phase 6).

This module turns the phase 2 control-flow graph back into per-instruction data
flow: which register a definition writes, which constant (if any) it holds, which
uses read that register, and which definition reached each read. It is the
foundation for the typed IR step, because a type can only be attached to a value
once the value's origin is known.

The analysis is a *single forward pass*: blocks are visited in ascending address
order and the instructions of a block in ascending address order. The register
file is a map from canonical register name to the :class:`Definition` that
currently holds the value, so a later write *kills* the earlier definition --
only the most recent definition can be reached by a later read, and the summary
records at most that one per read in ``reaching_definition``.

Folding rules (a folded value is always masked to the width of the written
register, and constants are computed exactly, never heuristically)::

    instruction                         definition kind   folded value
    ----------------------------------  ----------------  ---------------------
    mov rax, 5                          const             5
    mov eax, 5                          const             5 (zero-extends)
    movabs rax, 0x1122334455667788      const             that immediate
    mov rax, rdi                        copy              rdi's constant, if any
    lea rax, [rip + 0x10]               const             next instruction + 0x10
    add rax, 3     (rax known)          arithmetic        rax + 3
    sub rax, 3     (rax known)          arithmetic        rax - 3
    xor rax, 3     (rax known)          arithmetic        rax ^ 3
    xor rax, rax / sub rax, rax         arithmetic        0
    add rax, rbx   (both known)         arithmetic        rax + rbx
    any other register write            unknown           none

Everything else stays ``unknown`` on purpose. ``movzx``/``movsx``/``movsxd`` are
never classed as ``copy`` because the extension changes the value; ``and``, ``or``
and the shifts keep their ``arithmetic`` kind but no value, and a write narrower
than four bytes (``al``, ``ax``) drops its value while keeping its kind, because a
partial write cannot leave a whole-register constant. ``lea`` is only folded when
the address expression is a RIP-relative displacement; an indexed or
base-relative ``lea`` is an unknown address.

Register names are canonicalized before they are reported: on a 64-bit binary
``eax``/``ax``/``al`` are aliases of ``rax``, on a 32-bit one ``ax``/``al`` are
aliases of ``eax``. A read of a narrow alias is a read of the canonical register,
but a constant is only propagated through it when the alias is the whole register,
because the upper bytes of the canonical register are not visible through it.

Two instruction shapes are deliberately *not* definitions: a memory destination
(``mov [rdi], rax`` writes memory, not a register -- its address registers are
reads) and any mnemonic that does not write its first operand (``cmp``, ``test``,
``push``, ``jcc``, ``ret``, ...). A ``call`` additionally invalidates the
caller-saved registers (``rax``, ``rcx``, ``rdx``, ``rsi``, ``rdi``, ``r8`` ..
``r11`` and their 32-bit forms), because whatever the callee left there is not
the constant the caller stored.

Every read whose register has no definition in the analysed region is reported
through ``DataFlowSummary.warnings`` -- bounded and never silent -- and simply has
no entry in ``reaching_definition``. A truncated CFG is reported the same way,
because definitions past the instruction or block limit are not modelled at all.

Nothing is executed: decoding comes from
:func:`codevanta.analysis.cfg.build_recursive_cfg`, operand parsing is shared with
:mod:`codevanta.analysis.type_propagation`, and the result is a pure function of
the file bytes, the address and the two limits.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.analysis.cfg import build_recursive_cfg
from codevanta.analysis.type_propagation import (
    _ADDRESS_TERM,
    _ARITHMETIC_MNEMONICS,
    _MOV_MNEMONICS,
    _WORD,
    _instruction_parts,
    _is_plain_register,
    _parse_memory,
    _split_operands,
    _writes_first_operand,
)
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_BLOCKS",
    "DEFAULT_MAX_INSTRUCTIONS",
    "KIND_ARITHMETIC",
    "KIND_CONST",
    "KIND_COPY",
    "KIND_UNKNOWN",
    "MAX_MAX_BLOCKS",
    "MAX_MAX_INSTRUCTIONS",
    "MAX_UNDEFINED_WARNINGS",
    "MIN_MAX_BLOCKS",
    "MIN_MAX_INSTRUCTIONS",
    "READ",
    "WRITE",
    "DataFlowSummary",
    "Definition",
    "Use",
    "analyze_dataflow",
]


#: Default instruction budget of one analysis.
DEFAULT_MAX_INSTRUCTIONS = 2000

#: Default ceiling on the number of blocks one analysis will visit.
DEFAULT_MAX_BLOCKS = 500

#: Smallest accepted ``max_instructions`` / ``max_blocks``.
MIN_MAX_INSTRUCTIONS = 1
MIN_MAX_BLOCKS = 1

#: Hard ceilings on the budgets (bounded work per call).
MAX_MAX_INSTRUCTIONS = 8192
MAX_MAX_BLOCKS = 4096

#: ``Definition.kind``: the instruction writes an immediate or a RIP-relative
#: address, so the value is known exactly.
KIND_CONST = "const"

#: ``Definition.kind``: the instruction copies another register.
KIND_COPY = "copy"

#: ``Definition.kind``: the instruction combines its operand with the current
#: value of the register (a folded value is present only when both are known).
KIND_ARITHMETIC = "arithmetic"

#: ``Definition.kind``: the write is not modelled, so its value is unknown.
KIND_UNKNOWN = "unknown"

#: ``Use.read_or_write``: the instruction reads the register.
READ = "read"

#: ``Use.read_or_write``: the instruction writes the register.
WRITE = "write"

#: How many "no reaching definition" warnings one summary may carry before the
#: rest are collapsed into a single count (bounded, deterministic prose).
MAX_UNDEFINED_WARNINGS = 8

#: A write of this many bytes or more replaces the whole canonical register
#: (``eax`` zero-extends into ``rax``), so it may leave a known constant.
FULL_CONSTANT_WIDTH = 4

#: Mnemonics whose value is folded when both sides are known.
_FOLDING_MNEMONICS = frozenset({"add", "sub", "xor"})

#: ``mov``-family mnemonics that change the value even when copying a register.
_EXTENDING_MNEMONICS = frozenset({"movsx", "movsxd", "movzx"})

#: An immediate as Capstone or a MASM-style printer renders it: ``5``, ``-1``,
#: ``0x10``, ``0ffh``.
_IMMEDIATE = re.compile(r"^(?P<sign>[+-]?)(?P<body>0x[0-9a-f]+|[0-9]+)(?P<suffix>h?)$", re.IGNORECASE)

#: Canonical 64-bit general-purpose registers -> {alias as printed: width}.
_ALIAS_WIDTHS: dict[str, dict[str, int]] = {
    "rax": {"rax": 8, "eax": 4, "ax": 2, "al": 1, "ah": 1},
    "rbx": {"rbx": 8, "ebx": 4, "bx": 2, "bl": 1, "bh": 1},
    "rcx": {"rcx": 8, "ecx": 4, "cx": 2, "cl": 1, "ch": 1},
    "rdx": {"rdx": 8, "edx": 4, "dx": 2, "dl": 1, "dh": 1},
    "rsi": {"rsi": 8, "esi": 4, "si": 2, "sil": 1},
    "rdi": {"rdi": 8, "edi": 4, "di": 2, "dil": 1},
    "rbp": {"rbp": 8, "ebp": 4, "bp": 2, "bpl": 1},
    "rsp": {"rsp": 8, "esp": 4, "sp": 2, "spl": 1},
    "r8": {"r8": 8, "r8d": 4, "r8w": 2, "r8b": 1},
    "r9": {"r9": 8, "r9d": 4, "r9w": 2, "r9b": 1},
    "r10": {"r10": 8, "r10d": 4, "r10w": 2, "r10b": 1},
    "r11": {"r11": 8, "r11d": 4, "r11w": 2, "r11b": 1},
    "r12": {"r12": 8, "r12d": 4, "r12w": 2, "r12b": 1},
    "r13": {"r13": 8, "r13d": 4, "r13w": 2, "r13b": 1},
    "r14": {"r14": 8, "r14d": 4, "r14w": 2, "r14b": 1},
    "r15": {"r15": 8, "r15d": 4, "r15w": 2, "r15b": 1},
}

#: Registers a ``call`` invalidates, spelled as aliases so the set can be
#: resolved for whichever pointer width the binary uses.
_CALL_CLOBBER_ALIASES = (
    "rax",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "eax",
    "ecx",
    "edx",
)

#: Mnemonics that transfer control to a subroutine and therefore clobber the
#: caller-saved registers.
_CALL_MNEMONICS = frozenset({"call", "callq"})


@dataclass(frozen=True)
class Definition:
    """One register definition, i.e. the value an instruction leaves behind.

    Attributes:
        address: Virtual address of the defining instruction.
        register: Canonical register name (``rax``, ``rdi``, ``r8``, ...); aliases
            such as ``eax``/``ax``/``al`` are normalized to it.
        kind: Shape of the definition: :data:`KIND_CONST`, :data:`KIND_COPY`,
            :data:`KIND_ARITHMETIC` or :data:`KIND_UNKNOWN`.
        value: The constant this definition provably writes, or ``None`` when the
            value is not known. Present only for full-width writes, so a
            ``mov al, 1`` keeps its kind but carries no value.
        source_register: Canonical register a :data:`KIND_COPY` definition copies,
            else ``None``.
    """

    address: int
    register: str
    kind: str
    value: int | None
    source_register: str | None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the definition for the JSON report."""
        return {
            "address": f"0x{self.address:x}",
            "register": self.register,
            "kind": self.kind,
            "value": self.value,
            "source_register": self.source_register,
        }


@dataclass(frozen=True)
class Use:
    """One read or write of a register by a single instruction.

    Attributes:
        address: Virtual address of the instruction that uses the register.
        register: Canonical register name, aliases normalized as in
            :class:`Definition`.
        read_or_write: :data:`READ` or :data:`WRITE`.
    """

    address: int
    register: str
    read_or_write: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the use for the JSON report."""
        return {
            "address": f"0x{self.address:x}",
            "register": self.register,
            "read_or_write": self.read_or_write,
        }


@dataclass(frozen=True)
class DataFlowSummary:
    """Definition-use chains, constants and reaching definitions of one function.

    Attributes:
        address: Function address the analysis started from.
        definitions: Every register definition, in ascending address order.
        uses: Every read and write, in ascending address order; within one
            instruction the reads come before the write it makes.
        constant_registers: Canonical register -> constant still known after the
            forward pass, sorted by register name. Only provable constants appear.
        reaching_definition: ``(canonical register, use address)`` -> address of
            the definition that reaches that read. Reads with no definition in
            the analysed region are absent and reported in ``warnings`` instead.
        warnings: Bounded, human-readable caveats (undefined reads, a truncated
            CFG), each stated once.
        evidence: How the summary as a whole was derived.
    """

    address: int
    definitions: tuple[Definition, ...]
    uses: tuple[Use, ...]
    constant_registers: Mapping[str, int]
    reaching_definition: Mapping[tuple[str, int], int]
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize the summary for the JSON report (JSON-safe, sorted)."""
        return {
            "address": f"0x{self.address:x}",
            "definition_count": len(self.definitions),
            "use_count": len(self.uses),
            "definitions": [definition.to_dict() for definition in self.definitions],
            "uses": [use.to_dict() for use in self.uses],
            "constant_registers": dict(self.constant_registers),
            "reaching_definition": {
                f"{register}@0x{use:x}": f"0x{definition:x}"
                for (register, use), definition in self.reaching_definition.items()
            },
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


# ---------------------------------------------------------------------------
# input validation and register name normalization
# ---------------------------------------------------------------------------


def _pointer_width(info: BinaryInfo) -> int:
    """Return the pointer width in bytes implied by ``info.bitness``."""
    bitness = int(getattr(info, "bitness", 0) or 0)
    if bitness == 64:
        return 8
    if bitness == 32:
        return 4
    raise AnalysisError(f"data flow needs a 32-bit or 64-bit binary, got bitness {bitness}")


def _require_limit(name: str, value: object, minimum: int, maximum: int) -> int:
    """Validate an integer budget and return it as ``int``."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError(f"{name} must be an integer, got {value!r}")
    if value < minimum:
        raise AnalysisError(f"{name} must be >= {minimum}, got {value}")
    if value > maximum:
        raise AnalysisError(f"{name} too large (limit {maximum}), got {value}")
    return value


def _alias_table(pointer_width: int) -> dict[str, tuple[str, int]]:
    """Map every general-purpose register alias to ``(canonical register, width)``.

    The table is built per pointer width so the canonical names match the binary:
    ``eax`` is canonical on a 32-bit binary and an alias of ``rax`` on a 64-bit
    one, and ``r8`` .. ``r15`` only exist above 32 bits.
    """
    table: dict[str, tuple[str, int]] = {}
    for canonical, aliases in _ALIAS_WIDTHS.items():
        if pointer_width < 8:
            if canonical[1:].isdigit():  # r8 .. r15 do not exist below 64-bit
                continue
            wide = [alias for alias, width in aliases.items() if width == 4]
            if not wide:  # pragma: no cover - every legacy family has a 32-bit name
                continue
            canonical = wide[0]
            aliases = {alias: width for alias, width in aliases.items() if width <= 4}
        for alias, width in aliases.items():
            table.setdefault(alias, (canonical, width))
    return table


def _lookup(
    operand: str, aliases: Mapping[str, tuple[str, int]], pointer_width: int
) -> tuple[str, int]:
    """Return ``(canonical register, width)`` of a register operand.

    Registers outside the general-purpose set (``xmm0``, ``st0``, ...) are still
    tracked, under their own lowercased name at the pointer width, so that a
    write to them kills a previous definition instead of being ignored.
    """
    name = operand.strip().lower()
    hit = aliases.get(name)
    if hit is not None:
        return hit
    return name, pointer_width


def _full_width(register: str, aliases: Mapping[str, tuple[str, int]], pointer_width: int) -> int:
    """Return the whole-register width of a canonical register."""
    hit = aliases.get(register)
    return hit[1] if hit is not None else pointer_width


def _mask(value: int, width: int) -> int:
    """Truncate ``value`` to the ``width``-byte register it is written to."""
    return value & ((1 << (max(width, 1) * 8)) - 1)


def _immediate(text: str) -> int | None:
    """Parse an immediate operand, or return ``None`` when it is not one."""
    match = _IMMEDIATE.match((text or "").strip())
    if match is None:
        return None
    body = match.group("body").lower()
    try:
        value = int(body, 16) if body.startswith("0x") or match.group("suffix") else int(body, 10)
    except ValueError:  # pragma: no cover - the pattern already restricts the digits
        return None
    return -value if match.group("sign") == "-" else value


def _rip_displacement(operand: str, pointer_width: int) -> int | None:
    """Return the displacement of a ``[rip +/- disp]`` operand, else ``None``.

    Only a bare RIP base with a constant displacement is understood -- the shape
    of ``lea rax, [rip + 0x10]`` and of a RIP-relative load. A base register, an
    index, a symbol or a segment override returns ``None`` rather than a guess.
    """
    memory = _parse_memory(operand, pointer_width)
    if memory is None or memory.base != "rip" or memory.index is not None:
        return None
    text = operand.strip()
    body = text[text.index("[") + 1 : text.rindex("]")]
    displacement = 0
    for term in _ADDRESS_TERM.finditer(body):
        value = term.group("value")
        if not value[0].isdigit():  # the RIP term itself
            continue
        parsed = _immediate(value)
        if parsed is None:
            return None
        displacement += -parsed if term.group("sign") == "-" else parsed
    return displacement


# ---------------------------------------------------------------------------
# reading the decoded instructions
# ---------------------------------------------------------------------------


def _instruction_address(instruction: Mapping[str, Any]) -> int:
    """Return the integer address of an ``IRInstruction.to_dict()`` payload."""
    raw = instruction.get("address")
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    token = str(raw or "").strip().lower()
    if not token:
        raise AnalysisError(f"instruction has no address: {instruction!r}")
    try:
        return int(token, 16) if token.startswith("0x") else int(token, 10)
    except ValueError as exc:
        raise AnalysisError(f"instruction has an unreadable address: {instruction!r}") from exc


def _instruction_size(instruction: Mapping[str, Any]) -> int:
    """Return the encoded size of an instruction, ``0`` when it is not reported."""
    size = instruction.get("size")
    if isinstance(size, int) and not isinstance(size, bool) and size > 0:
        return size
    return 0


def _read_registers(
    mnemonic: str, parts: Sequence[str], aliases: Mapping[str, tuple[str, int]]
) -> tuple[str, ...]:
    """Return the canonical registers one instruction reads, sorted.

    The first operand is only skipped when the mnemonic writes it *and* it is a
    plain register: ``mov [rdi], rax`` still reads ``rdi``, because that operand
    is an address. Operands are scanned for register tokens, so a bracketed
    expression contributes its address registers and ``qword``/``ptr``/``rip``
    are dropped by the alias table.
    """
    destination_only = (
        mnemonic in _MOV_MNEMONICS or mnemonic in {"lea", "pop"} or mnemonic.startswith("set")
    )
    found: set[str] = set()
    for position, operand in enumerate(parts):
        if position == 0 and destination_only and _is_plain_register(operand):
            continue
        for token in _WORD.findall(operand):
            hit = aliases.get(token.lower())
            if hit is not None:
                found.add(hit[0])
    return tuple(sorted(found))


# ---------------------------------------------------------------------------
# classification of one write
# ---------------------------------------------------------------------------


def _copied_value(
    state: Mapping[str, Definition],
    source: str,
    source_width: int,
    width: int,
    aliases: Mapping[str, tuple[str, int]],
    pointer_width: int,
) -> int | None:
    """Return the constant a register copy carries, or ``None`` when unknown."""
    if source_width != _full_width(source, aliases, pointer_width):
        return None  # a narrow alias does not expose the whole register
    if width < source_width:
        return None  # the copy would truncate the source value
    definition = state.get(source)
    if definition is None or definition.value is None:
        return None
    return _mask(definition.value, width)


def _folded_value(
    mnemonic: str,
    register: str,
    width: int,
    previous: int | None,
    source: str,
    state: Mapping[str, Definition],
    aliases: Mapping[str, tuple[str, int]],
    pointer_width: int,
) -> int | None:
    """Fold ``add``/``sub``/``xor`` of a known operand, or return ``None``."""
    if mnemonic not in _FOLDING_MNEMONICS:
        return None
    if _is_plain_register(source):
        source_register, source_width = _lookup(source, aliases, pointer_width)
        if source_register == register and mnemonic in {"xor", "sub"}:
            return 0  # a register xor/sub itself
        if source_width != _full_width(source_register, aliases, pointer_width):
            return None
        operand: int | None = None
        definition = state.get(source_register)
        if definition is not None:
            operand = definition.value
    else:
        operand = _immediate(source)
    if previous is None or operand is None:
        return None
    if mnemonic == "add":
        return _mask(previous + operand, width)
    if mnemonic == "sub":
        return _mask(previous - operand, width)
    return _mask(previous ^ operand, width)


def _classify(
    instruction: Mapping[str, Any],
    mnemonic: str,
    parts: Sequence[str],
    address: int,
    state: Mapping[str, Definition],
    aliases: Mapping[str, tuple[str, int]],
    pointer_width: int,
) -> Definition | None:
    """Turn one instruction into a :class:`Definition`, or ``None`` if it writes none."""
    if not parts or not _writes_first_operand(mnemonic):
        return None
    destination = parts[0].strip().lower()
    if not _is_plain_register(destination):
        return None  # a memory or implicit destination defines no register

    register, width = _lookup(destination, aliases, pointer_width)
    source = parts[1].strip().lower() if len(parts) > 1 else ""
    kind = KIND_UNKNOWN
    value: int | None = None
    source_register: str | None = None

    previous = state.get(register)
    previous_value = previous.value if previous is not None else None

    if mnemonic in _MOV_MNEMONICS and mnemonic not in _EXTENDING_MNEMONICS and source:
        if _is_plain_register(source):
            source_register, source_width = _lookup(source, aliases, pointer_width)
            kind = KIND_COPY
            value = _copied_value(
                state, source_register, source_width, width, aliases, pointer_width
            )
        else:
            immediate = _immediate(source)
            if immediate is not None:
                kind = KIND_CONST
                value = _mask(immediate, width)
    elif mnemonic == "lea" and source:
        displacement = _rip_displacement(source, pointer_width)
        if displacement is not None:
            kind = KIND_CONST
            value = _mask(address + _instruction_size(instruction) + displacement, width)
    elif mnemonic in _ARITHMETIC_MNEMONICS and source:
        kind = KIND_ARITHMETIC
        value = _folded_value(
            mnemonic, register, width, previous_value, source, state, aliases, pointer_width
        )

    if width < FULL_CONSTANT_WIDTH:
        value = None  # a partial write leaves the upper bytes of the value unknown

    return Definition(
        address=address,
        register=register,
        kind=kind,
        value=value,
        source_register=source_register,
    )


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------


def analyze_dataflow(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
) -> DataFlowSummary:
    """Recover definitions, uses, constants and reaching definitions of a function.

    The CFG is built with :func:`~codevanta.analysis.cfg.build_recursive_cfg` and
    then walked once, forward, block by block in ascending address order and
    instruction by instruction inside a block. Each instruction contributes its
    read uses, which are resolved against the definitions seen so far, and -- when
    it writes a register -- one :class:`Definition` that replaces (kills) whatever
    the register held before. A folded value is masked to the written register's
    width, and only the cases listed in the module docstring are folded.

    Args:
        path: File the bytes are read from (read-only; never executed).
        info: Loaded metadata used for address mapping, decoding and the pointer
            width; 32-bit and 64-bit binaries are supported.
        address: Virtual address of the first instruction; must be inside an
            executable section.
        max_instructions: Instruction budget
            (``MIN_MAX_INSTRUCTIONS`` .. ``MAX_MAX_INSTRUCTIONS``).
        max_blocks: Block budget (``MIN_MAX_BLOCKS`` .. ``MAX_MAX_BLOCKS``).

    Returns:
        The :class:`DataFlowSummary` of the region: definitions and uses in
        address order, the constants still known after the pass, one reaching
        definition per resolved read, the bounded warnings and the evidence.

    Raises:
        AnalysisError: When ``address`` is not a non-negative integer, when a
            budget is out of range or not an integer, when the binary is neither
            32- nor 64-bit, when ``address`` is not inside an executable section,
            or when the CFG cannot be built.

    Note:
        The pass is a linearization of the CFG, not a fixpoint: state flows into a
        block from the block that precedes it in address order, so a join is
        approximated by whichever predecessor has the highest address. What is
        reported stays sound one definition at a time: a value is only folded
        from instructions the summary itself proves, and only the *last*
        definition of a register survives, so ``constant_registers`` and
        ``reaching_definition`` never claim two conflicting origins for one
        value. Two calls with the same arguments always produce the same summary.
    """
    if isinstance(address, bool) or not isinstance(address, int):
        raise AnalysisError(f"address must be an integer, got {address!r}")
    if address < 0:
        raise AnalysisError(f"address must be non-negative, got {address}")
    instruction_budget = _require_limit(
        "max_instructions", max_instructions, MIN_MAX_INSTRUCTIONS, MAX_MAX_INSTRUCTIONS
    )
    block_budget = _require_limit("max_blocks", max_blocks, MIN_MAX_BLOCKS, MAX_MAX_BLOCKS)
    pointer_width = _pointer_width(info)

    section = info.section_for_va(address)
    if section is None or not section.is_executable:
        raise AnalysisError(f"address 0x{address:x} is not inside an executable section")

    cfg = build_recursive_cfg(
        path,
        info,
        address,
        max_instructions=instruction_budget,
        max_blocks=block_budget,
    )

    aliases = _alias_table(pointer_width)
    clobbers = frozenset(
        hit[0] for alias in _CALL_CLOBBER_ALIASES if (hit := aliases.get(alias)) is not None
    )
    state: dict[str, Definition] = {}
    definitions: list[Definition] = []
    uses: list[Use] = []
    reaching: dict[tuple[str, int], int] = {}
    undefined: list[tuple[str, int]] = []

    for block in sorted(cfg.blocks, key=lambda item: item.start):
        for instruction in sorted(block.instructions, key=_instruction_address):
            mnemonic, operands = _instruction_parts(instruction)
            if not mnemonic:  # pragma: no cover - the decoder always names a mnemonic
                continue
            current = _instruction_address(instruction)
            parts = _split_operands(operands)

            for register in _read_registers(mnemonic, parts, aliases):
                uses.append(Use(current, register, READ))
                known = state.get(register)
                if known is None:
                    undefined.append((register, current))
                else:
                    reaching[(register, current)] = known.address

            definition = _classify(
                instruction, mnemonic, parts, current, state, aliases, pointer_width
            )
            if definition is not None:
                definitions.append(definition)
                uses.append(Use(current, definition.register, WRITE))
                state[definition.register] = definition

            if mnemonic in _CALL_MNEMONICS:
                for register in clobbers:
                    state.pop(register, None)

    warnings = _undefined_warnings(undefined)
    if cfg.truncated:
        warnings.append(
            "the CFG was truncated at the instruction or block budget; "
            "definitions past that point are not modelled"
        )

    constants = {
        register: definition.value
        for register, definition in sorted(state.items(), key=lambda item: item[0])
        if definition.value is not None
    }
    evidence = Evidence(
        source="dataflow.def_use",
        method="forward_propagation",
        confidence=Confidence.MEDIUM,
        address=address,
        detail=(
            f"{len(definitions)} definition(s) and {len(uses)} use(s) over "
            f"{len(cfg.blocks)} block(s); {len(reaching)} read(s) resolved to a "
            f"definition and {len(constants)} register constant(s) survived"
        ),
        extra={
            "pointer_width": pointer_width,
            "blocks": len(cfg.blocks),
            "instructions": cfg.instruction_count,
            "definitions": len(definitions),
            "uses": len(uses),
            "constant_registers": len(constants),
            "constant_definitions": sum(1 for item in definitions if item.value is not None),
            "reaching_definitions": len(reaching),
            "undefined_reads": len(undefined),
            "truncated": cfg.truncated,
        },
    )
    return DataFlowSummary(
        address=address,
        definitions=tuple(definitions),
        uses=tuple(uses),
        constant_registers=constants,
        reaching_definition=reaching,
        warnings=tuple(warnings),
        evidence=evidence,
    )


def _undefined_warnings(undefined: Sequence[tuple[str, int]]) -> list[str]:
    """Render the bounded "no reaching definition" warnings of one summary."""
    warnings = [
        f"read of {register} at 0x{address:x} has no reaching definition "
        "in the analysed region"
        for register, address in undefined[:MAX_UNDEFINED_WARNINGS]
    ]
    remaining = len(undefined) - MAX_UNDEFINED_WARNINGS
    if remaining > 0:
        warnings.append(
            f"{remaining} further read(s) have no reaching definition in the analysed region"
        )
    return warnings

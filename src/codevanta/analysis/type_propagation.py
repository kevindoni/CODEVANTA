"""Heuristic argument and return type inference from register use (phase 4).

A mnemonic-level renderer can never recover real C types, but it *can* report
how each ABI argument register is used, and the use is a type witness.
:func:`infer_argument_types` walks the decoded instructions of one function,
records one observation per use and turns the strongest observation into a C
type; :func:`infer_return_type` does the same for the value left in the return
register. Nothing is executed and nothing is invented: every emitted type
carries the observation that produced it.

Rule table for one argument register::

    observation                           example                      C type
    ------------------------------------  ---------------------------  -----------
    dereferenced at pointer width         mov rax, [rdi]               uint64_t *
    dereferenced narrower than a pointer  mov eax, dword ptr [rdi]     void *
    used as a scaled index                [rdi + rsi*4]                size_t
    only arithmetic on it                 add rdi, 1                   uint64_t
    copied whole, never narrowed          mov rax, rdi                 uint64_t
    compared and branched on              test rdi, rdi / je           int32_t
    no usable observation                 never read, or opaque use    unknown64

The C type of a rule is *width-aware*: the width of the register alias and of
the memory operand decide the type, so ``add edi, 1`` is ``uint32_t`` and
``dword ptr [ecx]`` on a 32-bit binary is a ``uint32_t *``. The pointer forms
and the ``unknownNN`` placeholder are keyed by the binary's pointer width.

When more than one rule fires, the most specific one wins -- pointers before
plain integers, integers before comparisons -- and every other observation is
kept in the evidence note together with the type it would have produced, so a
conflict is never resolved silently. The ranking (:data:`RULE_RANKS`) is::

    pointer_deref > narrow_deref > index > arithmetic > copy > compare

Return type inference is deliberately simpler because there is one register to
watch: scanning stops at the first ``ret``, the last write to the return
register decides the width (``rax`` -> ``uint64_t``, ``eax`` -> ``uint32_t``,
``ax`` -> ``uint16_t``, ``al`` -> ``uint8_t``), a ``setcc`` write is called out
as an ``int32_t`` boolean, and a function that never writes the register before
a ``ret`` returns ``void``. A ``call`` right before the ``ret`` is mentioned in
the note, because whatever the callee left in the register is not ours.

Accepted instruction shapes are the ones the rest of the engine already uses:
``IRInstruction.to_dict()`` payloads (``{"mnemonic", "operands", ...}``),
:class:`~codevanta.ir.instruction.IRInstruction` objects, or a plain
``"mnemonic operands"`` string.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence

__all__ = [
    "ABI_ARGUMENT_REGISTERS",
    "C_TYPE_INT32",
    "C_TYPE_POINTER_32",
    "C_TYPE_POINTER_64",
    "C_TYPE_SIZE_T",
    "C_TYPE_UINT8",
    "C_TYPE_UINT16",
    "C_TYPE_UINT32",
    "C_TYPE_UINT64",
    "C_TYPE_UNKNOWN_32",
    "C_TYPE_UNKNOWN_64",
    "C_TYPE_VOID",
    "C_TYPE_VOID_POINTER",
    "INTEGER_C_TYPES",
    "POINTER_C_TYPES",
    "RULE_RANKS",
    "UNKNOWN_C_TYPES",
    "ArgumentType",
    "ReturnType",
    "infer_argument_types",
    "infer_return_type",
]

# ---------------------------------------------------------------------------
# emitted C type names
# ---------------------------------------------------------------------------

#: Unsigned integer of exactly one byte.
C_TYPE_UINT8 = "uint8_t"

#: Unsigned integer of exactly two bytes.
C_TYPE_UINT16 = "uint16_t"

#: Unsigned integer of exactly four bytes.
C_TYPE_UINT32 = "uint32_t"

#: Unsigned integer of exactly eight bytes.
C_TYPE_UINT64 = "uint64_t"

#: Signed 32-bit integer, emitted for comparison/boolean evidence.
C_TYPE_INT32 = "int32_t"

#: ``size_t``, emitted for a register used as an address index.
C_TYPE_SIZE_T = "size_t"

#: ``void``, emitted for a function that never writes its return register.
C_TYPE_VOID = "void"

#: A pointer to nothing in particular, emitted for a sub-pointer-width deref.
C_TYPE_VOID_POINTER = "void *"

#: Pointer type of a 64-bit binary.
C_TYPE_POINTER_64 = "uint64_t *"

#: Pointer type of a 32-bit binary.
C_TYPE_POINTER_32 = "uint32_t *"

#: Placeholder emitted when no rule fires on a 64-bit binary.
C_TYPE_UNKNOWN_64 = "unknown64"

#: Placeholder emitted when no rule fires on a 32-bit binary.
C_TYPE_UNKNOWN_32 = "unknown32"

#: Access width in bytes -> the unsigned C integer of that width.
INTEGER_C_TYPES: dict[int, str] = {
    1: C_TYPE_UINT8,
    2: C_TYPE_UINT16,
    4: C_TYPE_UINT32,
    8: C_TYPE_UINT64,
}

#: Pointer width in bytes -> the pointer type of a pointer-width dereference.
POINTER_C_TYPES: dict[int, str] = {
    1: "uint8_t *",
    2: "uint16_t *",
    4: C_TYPE_POINTER_32,
    8: C_TYPE_POINTER_64,
}

#: Pointer width in bytes -> the placeholder type of an unproven argument.
UNKNOWN_C_TYPES: dict[int, str] = {
    4: C_TYPE_UNKNOWN_32,
    8: C_TYPE_UNKNOWN_64,
}

# ---------------------------------------------------------------------------
# ABI tables
# ---------------------------------------------------------------------------

#: Argument registers per ABI, in argument order, for a 64-bit binary.
ABI_ARGUMENT_REGISTERS: dict[str, tuple[str, ...]] = {
    "sysv": ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    "ms64": ("rcx", "rdx", "r8", "r9"),
}

#: Argument registers used for a 32-bit binary, whatever the ABI is called.
_ARGUMENTS_32: tuple[str, ...] = ("ecx", "edx")

#: Accepted spellings of an ABI name, lowercased and without separators.
_ABI_SPELLINGS: dict[str, str] = {
    "sysv": "sysv",
    "systemv": "sysv",
    "amd64": "sysv",
    "ms": "ms64",
    "ms64": "ms64",
    "win64": "ms64",
    "microsoft": "ms64",
}

#: Canonical argument register -> {alias as Capstone prints it: width in bytes}.
_REGISTER_ALIAS_WIDTHS: dict[str, dict[str, int]] = {
    "rdi": {"rdi": 8, "edi": 4, "di": 2, "dil": 1},
    "rsi": {"rsi": 8, "esi": 4, "si": 2, "sil": 1},
    "rdx": {"rdx": 8, "edx": 4, "dx": 2, "dl": 1, "dh": 1},
    "rcx": {"rcx": 8, "ecx": 4, "cx": 2, "cl": 1, "ch": 1},
    "r8": {"r8": 8, "r8d": 4, "r8w": 2, "r8b": 1},
    "r9": {"r9": 8, "r9d": 4, "r9w": 2, "r9b": 1},
    "ecx": {"ecx": 4, "cx": 2, "cl": 1, "ch": 1},
    "edx": {"edx": 4, "dx": 2, "dl": 1, "dh": 1},
}

#: Alias -> width in bytes, unioned over every supported register set. Widths
#: do not conflict between sets (``edx`` is four bytes either way), only the
#: canonical name does, which is why :func:`_alias_table` is built per ABI.
_ARGUMENT_ALIAS_WIDTHS: dict[str, int] = {
    alias: width
    for aliases in _REGISTER_ALIAS_WIDTHS.values()
    for alias, width in aliases.items()
}

#: Return register aliases, keyed by pointer width.
_RETURN_ALIAS_WIDTHS: dict[int, dict[str, int]] = {
    8: {"rax": 8, "eax": 4, "ax": 2, "al": 1, "ah": 1},
    4: {"eax": 4, "ax": 2, "al": 1, "ah": 1},
    2: {"ax": 2, "al": 1, "ah": 1},
    1: {"al": 1, "ah": 1},
}

#: Name used in evidence prose for the return register, keyed by pointer width.
_RETURN_REGISTER: dict[int, str] = {1: "al", 2: "ax", 4: "eax", 8: "rax"}

# ---------------------------------------------------------------------------
# mnemonic tables
# ---------------------------------------------------------------------------

#: ``mov``-style mnemonics: the first operand is only ever written.
_MOV_MNEMONICS = frozenset({"mov", "movabs", "movbe", "movsx", "movsxd", "movzx", "movq"})

#: Mnemonics that transfer control to a subroutine.
_CALL_MNEMONICS = frozenset({"call", "callq", "bl", "blx", "blr"})

#: Mnemonics that end the scanned region with a plain return.
_RET_MNEMONICS = frozenset({"ret", "retn", "retf", "retq", "iret", "iretd", "iretq", "eret"})

#: Mnemonics that only compare their operands and set flags.
_COMPARE_MNEMONICS = frozenset({"cmp", "test", "comiss", "comisd", "ucomiss", "ucomisd"})

#: Mnemonics that never write their first operand.
_READ_ONLY_MNEMONICS = frozenset(
    {
        "bt",
        "call",
        "callq",
        "cmp",
        "comisd",
        "comiss",
        "int",
        "int3",
        "jmp",
        "ljmp",
        "nop",
        "push",
        "ret",
        "test",
        "ucomisd",
        "ucomiss",
        "ud2",
        "xlat",
    }
)

#: Unconditional jumps; any other ``j*`` mnemonic branches on the flags.
_UNCONDITIONAL_JUMPS = frozenset({"jmp", "ljmp", "b", "br", "bx"})

#: Integer operations a value can take part in without leaving its width.
_ARITHMETIC_MNEMONICS = frozenset(
    {
        "adc",
        "add",
        "and",
        "dec",
        "div",
        "idiv",
        "imul",
        "inc",
        "mul",
        "neg",
        "not",
        "or",
        "rol",
        "ror",
        "sal",
        "sar",
        "sbb",
        "shl",
        "shr",
        "sub",
        "xor",
    }
)

# ---------------------------------------------------------------------------
# rule names and ranking
# ---------------------------------------------------------------------------

_RULE_POINTER_DEREF = "pointer_deref"
_RULE_NARROW_DEREF = "narrow_deref"
_RULE_INDEX = "index"
_RULE_ARITHMETIC = "arithmetic"
_RULE_COPY = "copy"
_RULE_COMPARE = "compare"

#: Specificity of every rule: the highest rank wins when several rules fire.
RULE_RANKS: dict[str, int] = {
    _RULE_POINTER_DEREF: 7,
    _RULE_NARROW_DEREF: 6,
    _RULE_INDEX: 5,
    _RULE_ARITHMETIC: 4,
    _RULE_COPY: 3,
    _RULE_COMPARE: 2,
}


@dataclass(frozen=True)
class ArgumentType:
    """An inferred C type for one argument of the rendered function.

    Attributes:
        register: Canonical ABI argument register, e.g. ``"rdi"``.
        name: Parameter name used by the pseudo-C renderer, e.g. ``"a0"``.
        c_type: Emitted C type, e.g. :data:`C_TYPE_POINTER_64`.
        evidence_note: The observation that produced ``c_type``; when several
            rules fired, the losing observations and their types are listed
            too, so a conflict is never hidden.
        confidence: How strongly ``c_type`` is supported. ``MEDIUM`` for a use
            that fixes a width (dereference, index, arithmetic), ``LOW`` for a
            weaker hint (a whole-register copy, a comparison, no evidence).
    """

    register: str
    name: str
    c_type: str
    evidence_note: str
    confidence: Confidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize the inferred argument type for the JSON report."""
        return {
            "register": self.register,
            "name": self.name,
            "c_type": self.c_type,
            "evidence_note": self.evidence_note,
            "confidence": self.confidence.value,
        }


@dataclass(frozen=True)
class ReturnType:
    """An inferred C return type for the rendered function.

    Attributes:
        c_type: Emitted C type: ``void``, a width-matched unsigned integer or
            :data:`C_TYPE_INT32` for a ``setcc`` boolean.
        evidence_note: The observation that produced ``c_type``.
        confidence: ``MEDIUM`` when an instruction writes the return register
            with an observable width, ``LOW`` for ``void`` (absence of a write
            is weaker evidence than a write).
    """

    c_type: str
    evidence_note: str
    confidence: Confidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize the inferred return type for the JSON report."""
        return {
            "c_type": self.c_type,
            "evidence_note": self.evidence_note,
            "confidence": self.confidence.value,
        }


def _unsigned_type(width: int) -> str:
    """Return the unsigned C integer of ``width`` bytes."""
    return INTEGER_C_TYPES.get(width, C_TYPE_UINT64)


def _pointer_type(width: int) -> str:
    """Return the pointer C type of a ``width``-byte pointer."""
    return POINTER_C_TYPES.get(width, f"{_unsigned_type(width)} *")


def _unknown_type(width: int) -> str:
    """Return the placeholder type for a pointer width with no evidence."""
    return UNKNOWN_C_TYPES.get(width, f"unknown{width * 8}")


# ---------------------------------------------------------------------------
# input normalization and operand parsing
# ---------------------------------------------------------------------------

#: Intel size keyword -> access width in bytes. Keywords that are not listed
#: (``tbyte``, ``xmmword``, ...) fall back to the pointer width.
_SIZE_KEYWORD_WIDTHS: dict[str, int] = {
    "byte": 1,
    "word": 2,
    "dword": 4,
    "qword": 8,
}

#: A memory operand: an optional size keyword plus a bracketed expression.
_MEMORY_OPERAND = re.compile(
    r"^(?:(?P<size>byte|word|dword|qword|tbyte|xmmword|oword|fword)\s+ptr\s+)?"
    r"\[\s*(?P<body>[^]]*?)\s*\]$",
    re.IGNORECASE,
)

#: One term of a bracketed address expression.
_ADDRESS_TERM = re.compile(
    r"(?P<sign>[+-])?\s*(?P<value>0x[0-9a-fA-F]+|\d+|[a-zA-Z][a-zA-Z0-9]*)"
    r"(?:\s*\*\s*(?P<scale>\d+))?"
)

#: A whole identifier-ish token, used to find register mentions.
_WORD = re.compile(r"[a-zA-Z][a-zA-Z0-9]*")

#: Immediates that mean "zero" once Capstone has printed them.
_ZERO_TOKENS = frozenset({"0", "0x0", "0h", "-0"})

#: How many touched instructions one "no evidence" note may remember.
_MAX_USES = 4


def _instruction_parts(instruction: Any) -> tuple[str, str]:
    """Return the lowercased mnemonic and the operand text of one instruction.

    ``IRInstruction.to_dict()`` payloads, :class:`~codevanta.ir.instruction.
    IRInstruction` objects and plain ``"mnemonic operands"`` strings are all
    accepted, because that is what the callers in this package already hold.
    """
    if isinstance(instruction, str):
        head, _, tail = instruction.strip().partition(" ")
        return head.lower(), tail.strip()
    mnemonic: Any = None
    operands: Any = None
    if isinstance(instruction, Mapping):
        mnemonic = instruction.get("mnemonic")
        operands = instruction.get("operands")
    else:
        mnemonic = getattr(instruction, "mnemonic", None)
        operands = getattr(instruction, "operands", None)
    return str(mnemonic or "").strip().lower(), str(operands or "").strip()


def _split_operands(text: str) -> list[str]:
    """Split Capstone operand text on top-level commas."""
    text = (text or "").strip()
    if not text:
        return []
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for character in text:
        if character == "[":
            depth += 1
        elif character == "]":
            depth = max(0, depth - 1)
        if character == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(character)
    parts.append("".join(current).strip())
    return [part for part in parts if part]


def _stream(instructions: Iterable[Any]) -> list[tuple[str, str]]:
    """Materialize the instruction stream as ``(mnemonic, operands)`` pairs."""
    if isinstance(instructions, (str, bytes)):
        raise AnalysisError("instructions must be an iterable of instructions, not a string")
    stream: list[tuple[str, str]] = []
    for instruction in instructions:
        mnemonic, operands = _instruction_parts(instruction)
        if mnemonic:
            stream.append((mnemonic, operands))
    return stream


def _text(mnemonic: str, operands: str) -> str:
    """Return ``"mnemonic operands"`` of one instruction, for evidence prose."""
    return f"{mnemonic} {operands}".strip()


@dataclass(frozen=True)
class _Memory:
    """A parsed bracketed address expression.

    Attributes:
        base: Base register, lowercased, or ``None`` for an index-only or
            absolute operand.
        index: Index register, lowercased, or ``None``.
        scale: Index scale, ``1`` when the operand carries none.
        width: Access width in bytes: the size keyword, else the pointer width.
        text: The operand as it was printed, for evidence prose.
    """

    base: str | None
    index: str | None
    scale: int
    width: int
    text: str


def _parse_memory(operand: str, pointer_width: int) -> _Memory | None:
    """Parse a bracketed address expression, or return ``None`` if unhandled.

    ``[base]``, ``[base +/- disp]``, ``[index]``, ``[index*scale]`` and
    ``[base + index*scale +/- disp]`` are understood. Segment prefixes and
    expressions with more than a base and an index are skipped rather than
    guessed at.
    """
    match = _MEMORY_OPERAND.match(operand.strip())
    if match is None:
        return None
    body = match.group("body")
    if ":" in body:  # a segment override is never guessed at
        return None
    base: str | None = None
    index: str | None = None
    scale = 1
    for term in _ADDRESS_TERM.finditer(body):
        value = term.group("value")
        if value[0].isdigit():  # a displacement, not a register
            continue
        register = value.lower()
        term_scale = int(term.group("scale")) if term.group("scale") else 1
        if base is None and term_scale == 1:
            base = register
        elif index is None:
            index = register
            scale = term_scale
        else:  # more than a base and an index: not modelled
            return None
    keyword = match.group("size")
    width = _SIZE_KEYWORD_WIDTHS.get(keyword.lower(), 0) if keyword else 0
    return _Memory(base, index, scale, width or pointer_width, operand.strip())


# ---------------------------------------------------------------------------
# register aliases and operand scanning
# ---------------------------------------------------------------------------


def _alias_table(registers: Sequence[str]) -> dict[str, tuple[str, int]]:
    """Map every alias of ``registers`` to ``(canonical register, width)``.

    The table is built per register set, so ``edx`` is *canonical* on a 32-bit
    binary (``ecx``/``edx``) and an alias of ``rdx`` on a 64-bit one.
    """
    table: dict[str, tuple[str, int]] = {}
    for canonical in registers:
        for alias, width in _REGISTER_ALIAS_WIDTHS.get(canonical, {canonical: 8}).items():
            table.setdefault(alias, (canonical, width))
    return table


def _register_read_tokens(mnemonic: str, parts: Sequence[str]) -> set[str]:
    """Return the lowercased tokens an instruction *reads*.

    The first operand is skipped for the mnemonics that only write it
    (``mov``-family, ``lea``, ``pop``, ``setcc``), so ``mov rdi, rax`` does not
    count as a read of ``rdi``. This mirrors the argument counter in
    :mod:`codevanta.analysis.decompile`, so the signature keeps agreeing with
    the rendered body.
    """
    destination_only = (
        mnemonic in _MOV_MNEMONICS or mnemonic in {"lea", "pop"} or mnemonic.startswith("set")
    )
    tokens: set[str] = set()
    for position, operand in enumerate(parts):
        if position == 0 and destination_only:
            continue
        tokens.update(token.lower() for token in _WORD.findall(operand))
    return tokens


def _plain_operands(parts: Sequence[str], *, skip_first: bool) -> list[tuple[str, int]]:
    """Return ``(alias, width)`` for every register mentioned outside brackets.

    Bracket expressions are handled by the dereference and index rules; a token
    inside them is an address component, not the value itself.
    """
    hits: list[tuple[str, int]] = []
    for position, operand in enumerate(parts):
        if position == 0 and skip_first:
            continue
        if "[" in operand:
            continue
        for token in _WORD.findall(operand):
            name = token.lower()
            width = _ARGUMENT_ALIAS_WIDTHS.get(name)
            if width is not None:
                hits.append((name, width))
    return hits


def _is_plain_register(operand: str) -> bool:
    """Whether an operand is a bare register name."""
    return bool(_WORD.fullmatch(operand.strip()))


def _compare_targets(mnemonic: str, parts: Sequence[str]) -> list[tuple[str, bool]]:
    """Return ``(alias, compares_against_zero)`` for a comparison's operands."""
    if mnemonic not in _COMPARE_MNEMONICS or len(parts) != 2:
        return []
    left, right = (part.strip().lower() for part in parts)
    left_is_zero = left in _ZERO_TOKENS
    right_is_zero = right in _ZERO_TOKENS
    if mnemonic == "test" and (left == right or (left_is_zero and right_is_zero)):
        return [(left, True)] if _is_plain_register(left) else []
    if left_is_zero and not right_is_zero:
        return [(right, True)] if _is_plain_register(right) else []
    if right_is_zero and not left_is_zero:
        return [(left, True)] if _is_plain_register(left) else []
    targets: list[tuple[str, bool]] = []
    for operand in (left, right):
        if _is_plain_register(operand):
            targets.append((operand, False))
    return targets


# ---------------------------------------------------------------------------
# observations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Observation:
    """One use of an argument register, as a candidate type.

    Attributes:
        rule: Which inference rule fired, a key of :data:`RULE_RANKS`.
        c_type: The C type this observation alone would emit.
        note: The observation itself, e.g. ``"dereferenced at pointer width ..."``.
        confidence: How strong this kind of evidence is on its own.
        width: Width in bytes the observation was made at; breaks rank ties.
    """

    rule: str
    c_type: str
    note: str
    confidence: Confidence
    width: int

    @property
    def rank(self) -> int:
        """Specificity of the rule that produced this observation."""
        return RULE_RANKS[self.rule]


def _deref_observation(memory: _Memory, pointer_width: int, text: str) -> _Observation:
    """Turn a pointer-width or narrow dereference into one observation."""
    if memory.width >= pointer_width:
        return _Observation(
            rule=_RULE_POINTER_DEREF,
            c_type=_pointer_type(pointer_width),
            note=f"dereferenced at pointer width ({memory.text}) in '{text}'",
            confidence=Confidence.MEDIUM,
            width=pointer_width,
        )
    return _Observation(
        rule=_RULE_NARROW_DEREF,
        c_type=C_TYPE_VOID_POINTER,
        note=(
            f"dereferenced at {memory.width} byte(s), narrower than the "
            f"{pointer_width}-byte pointer ({memory.text}) in '{text}'"
        ),
        confidence=Confidence.MEDIUM,
        width=memory.width,
    )


def _index_observation(memory: _Memory, text: str) -> _Observation:
    """Turn a register used as an address index into a ``size_t`` observation."""
    scale = f"x{memory.scale}" if memory.scale > 1 else "x1"
    return _Observation(
        rule=_RULE_INDEX,
        c_type=C_TYPE_SIZE_T,
        note=f"used as a scaled address index ({scale}) in '{text}'",
        confidence=Confidence.MEDIUM,
        width=4,
    )


def _address_arithmetic(text: str, pointer_width: int) -> _Observation:
    """Turn a base register of a ``lea`` (no dereference) into an observation."""
    return _Observation(
        rule=_RULE_ARITHMETIC,
        c_type=_unsigned_type(pointer_width),
        note=f"used in address arithmetic only, never dereferenced ({text})",
        confidence=Confidence.MEDIUM,
        width=pointer_width,
    )


def _arithmetic_observation(text: str, width: int) -> _Observation:
    """Turn integer arithmetic on a register into a width-matched observation."""
    return _Observation(
        rule=_RULE_ARITHMETIC,
        c_type=_unsigned_type(width),
        note=f"only integer arithmetic on it at {width * 8} bits ({text})",
        confidence=Confidence.MEDIUM,
        width=width,
    )


def _copy_observation(text: str, alias: str, width: int) -> _Observation:
    """Turn a whole-register copy into a width-matched observation.

    A copy narrows nothing on its own: ``mov rax, rdi`` moves eight bytes, so the
    value is at least a 64-bit integer. It is weaker evidence than arithmetic,
    hence ``Confidence.LOW``.
    """
    return _Observation(
        rule=_RULE_COPY,
        c_type=_unsigned_type(width),
        note=f"copied whole through {alias} at {width * 8} bits ({text})",
        confidence=Confidence.LOW,
        width=width,
    )


class _RegisterEvidence:
    """Everything observed about one argument register."""

    def __init__(self) -> None:
        self.observations: dict[tuple[str, str], tuple[_Observation, int]] = {}
        self.uses: list[str] = []

    def record(self, observation: _Observation) -> None:
        """Add one observation, counting repeats of the same rule and type."""
        key = (observation.rule, observation.c_type)
        existing = self.observations.get(key)
        if existing is None:
            self.observations[key] = (observation, 1)
        else:
            self.observations[key] = (existing[0], existing[1] + 1)

    def touch(self, text: str) -> None:
        """Remember an instruction that mentions the register."""
        if text and text not in self.uses and len(self.uses) < _MAX_USES:
            self.uses.append(text)

    def best(self) -> _Observation | None:
        """Return the winning observation: highest rank, then widest, then first."""
        winner: _Observation | None = None
        best_key: tuple[int, int, int] | None = None
        for order, (observation, _count) in enumerate(self.observations.values()):
            key = (observation.rank, observation.width, -order)
            if best_key is None or key > best_key:
                best_key = key
                winner = observation
        return winner

    def describe(self, primary: _Observation) -> str:
        """Render the primary observation together with every conflicting one."""
        note = ""
        others: list[str] = []
        for observation, count in self.observations.values():
            label = observation.note if count == 1 else f"{observation.note} (x{count})"
            if observation is primary:
                note = label
            else:
                others.append(f"{label} -> {observation.c_type}")
        if not others:
            return note
        listed = "; ".join(others[:2])
        if len(others) > 2:
            listed = f"{listed}; +{len(others) - 2} more"
        return f"{note}; also observed: {listed}"


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


def _require_pointer_width(pointer_width: object) -> int:
    """Validate the pointer width in bytes (1, 2, 4 or 8)."""
    if isinstance(pointer_width, bool) or not isinstance(pointer_width, int):
        raise AnalysisError(f"pointer_width must be an integer, got {pointer_width!r}")
    if pointer_width not in INTEGER_C_TYPES:
        raise AnalysisError(
            f"pointer_width must be one of {sorted(INTEGER_C_TYPES)}, got {pointer_width}"
        )
    return pointer_width


def _argument_registers(abi: object, pointer_width: int) -> tuple[str, ...]:
    """Return the argument registers of ``abi`` for a binary of that width.

    A 32-bit binary always uses ``ecx``/``edx``, whatever the ABI is called: the
    register file only has the 32-bit aliases, and those are what the renderer
    names ``a0``/``a1``.
    """
    if pointer_width < 8:
        return _ARGUMENTS_32
    spelling = str(abi).strip().lower().replace("-", "").replace("_", "").replace(" ", "")
    name = _ABI_SPELLINGS.get(spelling)
    if name is None:
        accepted = ", ".join(sorted(ABI_ARGUMENT_REGISTERS))
        raise AnalysisError(f"unknown ABI {abi!r}; expected one of {accepted}")
    return ABI_ARGUMENT_REGISTERS[name]


# ---------------------------------------------------------------------------
# argument inference
# ---------------------------------------------------------------------------


def _collect(
    stream: Sequence[tuple[str, str]],
    pointer_width: int,
    registers: Sequence[str],
) -> tuple[dict[str, _RegisterEvidence], int]:
    """Scan the stream once and return the per-register evidence and the count.

    The argument count is the highest argument register read *before the first
    ``call``, plus one -- exactly the rule the pseudo-C renderer uses -- so the
    signature and the rendered body always name the same parameters. Registers
    below the count that are never read are still reported, as ``unknown64``.
    """
    evidence = {register: _RegisterEvidence() for register in registers}
    aliases = _alias_table(registers)
    positions = {register: index for index, register in enumerate(registers)}
    count = 0
    call_seen = False
    for position, (mnemonic, operands) in enumerate(stream):
        parts = _split_operands(operands)
        text = _text(mnemonic, operands)
        if mnemonic in _CALL_MNEMONICS:
            call_seen = True
        elif not call_seen:
            for token in _register_read_tokens(mnemonic, parts):
                resolved = aliases.get(token)
                if resolved is not None:
                    count = max(count, positions[resolved[0]] + 1)

        for token in set(_WORD.findall(operands.lower())):
            resolved = aliases.get(token)
            if resolved is not None:
                evidence[resolved[0]].touch(text)

        for operand in parts:
            memory = _parse_memory(operand, pointer_width)
            if memory is None:
                continue
            if memory.base is not None:
                resolved = aliases.get(memory.base)
                if resolved is not None:
                    if mnemonic == "lea":
                        evidence[resolved[0]].record(_address_arithmetic(text, pointer_width))
                    else:
                        evidence[resolved[0]].record(
                            _deref_observation(memory, pointer_width, text)
                        )
            if memory.index is not None:
                resolved = aliases.get(memory.index)
                if resolved is not None:
                    evidence[resolved[0]].record(_index_observation(memory, text))

        if mnemonic in _ARITHMETIC_MNEMONICS:
            for alias, width in _plain_operands(parts, skip_first=False):
                resolved = aliases.get(alias)
                if resolved is not None:
                    evidence[resolved[0]].record(_arithmetic_observation(text, width))
        elif mnemonic in _MOV_MNEMONICS:
            for alias, width in _plain_operands(parts, skip_first=True):
                resolved = aliases.get(alias)
                if resolved is not None:
                    evidence[resolved[0]].record(_copy_observation(text, alias, width))

        if mnemonic in _COMPARE_MNEMONICS:
            following = stream[position + 1][0] if position + 1 < len(stream) else ""
            if following.startswith("j") and following not in _UNCONDITIONAL_JUMPS:
                for alias, zero in _compare_targets(mnemonic, parts):
                    resolved = aliases.get(alias)
                    if resolved is not None:
                        if zero:
                            note = (
                                f"compared with zero and branched on "
                                f"({text} then {following})"
                            )
                        else:
                            note = (
                                f"compared with another operand and branched on "
                                f"({text} then {following})"
                            )
                        evidence[resolved[0]].record(
                            _Observation(
                                rule=_RULE_COMPARE,
                                c_type=C_TYPE_INT32,
                                note=note,
                                confidence=Confidence.LOW,
                                width=4,
                            )
                        )
    return evidence, count


def _argument_type(
    register: str, index: int, evidence: _RegisterEvidence, pointer_width: int
) -> ArgumentType:
    """Turn one register's evidence into the reported argument type."""
    best = evidence.best()
    if best is None:
        if evidence.uses:
            note = (
                f"read without a usable type witness (first use: '{evidence.uses[0]}'); "
                "no rule applies"
            )
        else:
            note = f"argument register {register} is never read; nothing to infer from"
        return ArgumentType(
            register=register,
            name=f"a{index}",
            c_type=_unknown_type(pointer_width),
            evidence_note=note,
            confidence=Confidence.LOW,
        )
    return ArgumentType(
        register=register,
        name=f"a{index}",
        c_type=best.c_type,
        evidence_note=evidence.describe(best),
        confidence=best.confidence,
    )


def infer_argument_types(
    instructions: Iterable[Any],
    pointer_width: int,
    *,
    abi: str = "sysv",
) -> tuple[ArgumentType, ...]:
    """Infer the C type of every argument of one function.

    Args:
        instructions: The decoded instructions of the function, in ascending
            address order: ``IRInstruction.to_dict()`` payloads,
            :class:`~codevanta.ir.instruction.IRInstruction` objects or
            ``"mnemonic operands"`` strings.
        pointer_width: Pointer width of the binary in bytes (``8`` for x86_64,
            ``4`` for 32-bit code). It decides the pointer type and the
            ``unknownNN`` placeholder.
        abi: Calling convention naming the argument registers. ``"sysv"`` (the
            default) and its spellings use ``rdi``/``rsi``/``rdx``/``rcx``/
            ``r8``/``r9``; ``"ms64"``/``"win64"`` use ``rcx``/``rdx``/``r8``/
            ``r9``. A 32-bit binary always uses ``ecx``/``edx``.

    Returns:
        One :class:`ArgumentType` per argument, in argument order, named
        ``a0``..``a5``. The count is the highest argument register read before
        the first ``call`` plus one, i.e. the same rule the pseudo-C renderer
        uses for the signature; a lower register that is never read is still
        reported, as the ``unknownNN`` placeholder with ``Confidence.LOW``.

    Raises:
        AnalysisError: When ``pointer_width`` is not 1, 2, 4 or 8, when ``abi``
            is not a known calling convention, or when ``instructions`` is a
            string instead of an iterable of instructions.

    Note:
        The same instructions always give the same result: the scan is linear,
        observations are aggregated per rule and the winner is chosen by
        :data:`RULE_RANKS` with deterministic tie-breaks.
    """
    width = _require_pointer_width(pointer_width)
    registers = _argument_registers(abi, width)
    stream = _stream(instructions)
    evidence, count = _collect(stream, width, registers)
    return tuple(
        _argument_type(register, index, evidence[register], width)
        for index, register in enumerate(registers[:count])
    )


def _writes_first_operand(mnemonic: str) -> bool:
    """Whether a mnemonic writes its first operand."""
    if mnemonic in _READ_ONLY_MNEMONICS or mnemonic in _RET_MNEMONICS:
        return False
    return not (mnemonic.startswith("j") or mnemonic.startswith("loop"))


def _last_return_write(
    stream: Sequence[tuple[str, str]], pointer_width: int
) -> tuple[int, str, str, bool] | None:
    """Return the last write to the return register before the first ``ret``.

    Returns ``(width, alias, instruction text, is_setcc)`` or ``None`` when no
    instruction writes the register.
    """
    aliases = _RETURN_ALIAS_WIDTHS.get(pointer_width, _RETURN_ALIAS_WIDTHS[8])
    last: tuple[int, str, str, bool] | None = None
    for mnemonic, operands in stream:
        if mnemonic in _RET_MNEMONICS:
            break
        if not _writes_first_operand(mnemonic):
            continue
        parts = _split_operands(operands)
        if not parts:
            continue
        destination = parts[0].strip().lower()
        if "[" in destination:  # a memory destination only *reads* the register
            continue
        width = aliases.get(destination)
        if width is None:
            continue
        last = (width, destination, _text(mnemonic, operands), mnemonic.startswith("set"))
    return last


def _first_call_before_ret(stream: Sequence[tuple[str, str]]) -> str:
    """Return the text of the first ``call`` before the first ``ret``, if any."""
    for mnemonic, operands in stream:
        if mnemonic in _RET_MNEMONICS:
            return ""
        if mnemonic in _CALL_MNEMONICS:
            return _text(mnemonic, operands)
    return ""


def infer_return_type(instructions: Iterable[Any], pointer_width: int) -> ReturnType:
    """Infer the C return type of one function.

    The scan stops at the first ``ret`` and the **last write** to the return
    register decides the type: ``rax`` -> ``uint64_t``, ``eax`` -> ``uint32_t``,
    ``ax`` -> ``uint16_t``, ``al`` -> ``uint8_t``. A ``setcc`` write is reported
    as :data:`C_TYPE_INT32`, because it leaves a 0/1 boolean that C returns as an
    ``int``. A function that never writes the register returns
    :data:`C_TYPE_VOID` with ``Confidence.LOW`` -- the absence of a write is
    weaker evidence than a write -- and a ``call`` before the ``ret`` is named in
    the note, because the value would then be the callee's.

    Args:
        instructions: The decoded instructions of the function, in ascending
            address order (see :func:`infer_argument_types` for the accepted
            shapes).
        pointer_width: Pointer width of the binary in bytes; it selects the
            return register (``rax`` on 64-bit, ``eax`` on 32-bit) and its
            aliases.

    Returns:
        The :class:`ReturnType` together with the observation that produced it.

    Raises:
        AnalysisError: When ``pointer_width`` is not 1, 2, 4 or 8, or when
            ``instructions`` is a string instead of an instruction iterable.
    """
    width = _require_pointer_width(pointer_width)
    stream = _stream(instructions)
    register = _RETURN_REGISTER.get(width, "rax")
    decision = _last_return_write(stream, width)
    if decision is None:
        note = f"no instruction writes {register} before the first ret"
        call = _first_call_before_ret(stream)
        if call:
            note = (
                f"no instruction writes {register} before the first ret; the value "
                f"would come from '{call}' and is left to the callee"
            )
        return ReturnType(c_type=C_TYPE_VOID, evidence_note=note, confidence=Confidence.LOW)
    write_width, alias, text, boolean = decision
    if boolean:
        return ReturnType(
            c_type=C_TYPE_INT32,
            evidence_note=f"last write to {register} is the setcc boolean '{text}' ({alias})",
            confidence=Confidence.MEDIUM,
        )
    return ReturnType(
        c_type=_unsigned_type(write_width),
        evidence_note=(
            f"last write to {register} before the ret is {write_width * 8}-bit: '{text}'"
        ),
        confidence=Confidence.MEDIUM,
    )

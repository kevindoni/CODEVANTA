"""Heuristic pseudo-C decompilation of one function (phase 3).

:func:`decompile_function` renders a single function as readable pseudo-C. It
never re-implements decoding: the recursive CFG
(:func:`codevanta.analysis.cfg.build_recursive_cfg`) supplies the instructions
and the block structure, function discovery supplies symbol names, and this
module only *shapes* that structure into text.

1. **Signature.** The argument count is inferred from the ABI argument registers
   read before the first ``call`` (``rdi``/``rsi``/``rdx``/``rcx``/``r8``/``r9``
   plus their 32/16/8-bit aliases on x86_64, ``ecx``/``edx`` on x86), capped at
   six. A register counts as *read* unless it is only the destination of the
   instruction, so ``mov rax, rdi`` reads ``rdi`` while ``mov rdi, rax`` does
   not. The name comes from the discovered function candidate, else
   ``sub_<address>``. Every parameter and the return value then carry an inferred
   C type from :mod:`codevanta.analysis.type_propagation` -- the count rule is
   shared with it, so the signature and the rendered ``a0``..``a5`` operands
   always agree -- and the header repeats one short line per argument. An
   argument nothing can be proven about keeps the ``unknown<bitness>``
   placeholder with a low confidence rather than a guess.
2. **Operands.** Argument registers become ``a0``..``a5``; every other register
   keeps its architectural name. ``[rbp - 8]``-style operands become frame slots
   (``local_0x8`` below the frame pointer, ``arg_0x8`` above it) and other
   memory operands become ``*(u64*)(a0 + 0x10)`` dereferences with the pointer
   width of the binary (``u32`` for 32-bit files).
3. **Statements.** Only semantics that the mnemonic alone justifies are
   rendered: ``mov``/``lea``/compound assignments and unary updates. Every other
   instruction keeps its comment but produces no statement, so nothing is
   invented. Every emitted source line carries the raw instruction text as a
   trailing ``/* mov rax, rdi */`` comment.
4. **Control flow.** A forward conditional branch with two decoded successors
   opens ``if (<condition>) {`` with the *inverted* condition (the fallthrough is
   the then-branch) and closes with ``}``; when the then-branch jumps over an
   exclusive else region the two halves are joined as ``} else {``. A block that
   is the target of a back edge opens ``while (1) {``; the latch renders
   ``continue;`` or ``if (<exit condition>) { break; }``. Anything left over --
   irreducible edges, forward branches that cross an enclosing region, targets
   outside the decoded window -- is rendered as ``goto LABEL_<addr>;`` with a
   matching ``LABEL_<addr>:``.
5. **Conditions.** ``cmp``/``test`` operands feed the following branch:
   ``je``/``jne`` give ``==``/``!=``, ``jl``..``jg`` give signed ``< <= > >=``
   and ``jb``..``ja`` give the ``(unsigned)`` forms. When no comparison can be
   justified the condition is ``flag_from_<mnemonic>`` (or
   ``!flag_from_<mnemonic>`` for an inverted branch).
6. **Calls.** ``call_<target>();`` for a direct target, ``<import_name>()`` when
   the target matches an entry of ``BinaryInfo.imports`` and ``(*ptr)();`` for an
   indirect one (recorded as :class:`CallSite` with ``target=None``).

Every result carries :class:`Evidence`; the confidence is :attr:`Confidence.LOW`
because the whole rendering is a mnemonic-level heuristic. The header comment
block repeats the address, the confidence and the evidence note, and the target
binary is only ever read, never executed. ``evidence.extra`` carries the
inferred signature as data (``argument_types``, ``return_type``) so JSON
consumers do not have to parse the pseudo-C.

Work is bounded by ``max_instructions`` and ``max_blocks`` (defaults
:data:`DEFAULT_MAX_INSTRUCTIONS` / :data:`DEFAULT_MAX_BLOCKS`); a cut-short
rendering sets :attr:`PseudoFunction.truncated` and adds a ``warning:`` line to
the header. An address that is not executable code, a budget out of range and a
region that decodes to nothing all raise :class:`AnalysisError`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from codevanta.analysis.cfg import BasicBlock, FunctionCFG, build_recursive_cfg
from codevanta.analysis.type_propagation import (
    ArgumentType,
    ReturnType,
    infer_argument_types,
    infer_return_type,
)
from codevanta.core.functions import discover_functions
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import MAX_DISASSEMBLY_COUNT, AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "CallSite",
    "DEFAULT_MAX_BLOCKS",
    "DEFAULT_MAX_INSTRUCTIONS",
    "MAX_MAX_BLOCKS",
    "MAX_MAX_INSTRUCTIONS",
    "PseudoFunction",
    "decompile_function",
]

#: Default instruction budget for one rendering.
DEFAULT_MAX_INSTRUCTIONS = 2_000

#: Largest accepted ``max_instructions``; larger requests are rejected.
MAX_MAX_INSTRUCTIONS = MAX_DISASSEMBLY_COUNT

#: Default block budget for one rendering.
DEFAULT_MAX_BLOCKS = 500

#: Largest accepted ``max_blocks``; larger requests are rejected.
MAX_MAX_BLOCKS = MAX_DISASSEMBLY_COUNT

#: One indentation step, in spaces.
_INDENT = "    "

#: Evidence source label for a rendered function.
_SOURCE = "decompile.pseudo_c"

#: Evidence method label for a rendered function.
_METHOD = "mnemonic_heuristic"

#: Mnemonics that end a block with a plain return.
_RET_MNEMONICS = frozenset({"ret", "retn", "retf", "retq", "iret", "iretd", "iretq", "eret"})

#: Mnemonics that are an unconditional jump.
_UNCONDITIONAL_JUMPS = frozenset({"jmp", "ljmp", "b", "br", "bx"})

#: Mnemonics that transfer control to a subroutine.
_CALL_MNEMONICS = frozenset({"call", "callq", "bl", "blx", "blr"})

#: ``mov``-style mnemonics: the first operand is only ever written.
_MOV_MNEMONICS = frozenset({"mov", "movabs", "movbe", "movsx", "movsxd", "movzx", "movq"})

#: Read-modify-write mnemonics rendered as ``dst <op>= src``.
_COMPOUND_ASSIGN: dict[str, str] = {
    "add": "+=",
    "sub": "-=",
    "and": "&=",
    "or": "|=",
    "xor": "^=",
    "imul": "*=",
    "shl": "<<=",
    "sal": "<<=",
    "shr": ">>=",
    "sar": ">>=",
}

#: Unary mnemonics rendered as ``dst = <prefix>dst``.
_UNARY_ASSIGN: dict[str, str] = {"neg": "-", "not": "~"}

#: Unary increment/decrement mnemonics.
_STEP_ASSIGN: dict[str, str] = {"inc": "++", "dec": "--"}

#: SysV argument registers, in argument order, for x86_64.
_ARG_REGISTERS_64 = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")

#: Argument registers used for 32-bit x86 (``__thiscall``/``__fastcall`` order).
_ARG_REGISTERS_32 = ("ecx", "edx")

#: Every name a canonical argument register can appear under in Capstone text.
_ARG_ALIASES: dict[str, tuple[str, ...]] = {
    "rdi": ("rdi", "edi", "di", "dil"),
    "rsi": ("rsi", "esi", "si", "sil"),
    "rdx": ("rdx", "edx", "dx", "dl"),
    "rcx": ("rcx", "ecx", "cx", "cl"),
    "r8": ("r8", "r8d", "r8w", "r8b"),
    "r9": ("r9", "r9d", "r9w", "r9b"),
    "ecx": ("ecx", "cx", "cl"),
    "edx": ("edx", "dx", "dl"),
}

#: Registers whose relative operands denote stack slots.
_STACK_REGISTERS = frozenset({"rbp", "ebp", "rsp", "esp"})

#: Instruction-pointer register names (RIP-relative operands hold a global).
_PC_REGISTERS = frozenset({"rip", "eip"})

#: Capstone size keywords that may prefix a memory operand.
_SIZE_KEYWORDS = "byte|word|dword|qword|tbyte|xmmword|oword|fword"

#: A single address operand, e.g. ``0x401010`` (the only direct form accepted).
_DIRECT_OPERAND = re.compile(r"^0x[0-9a-fA-F]+$")

#: A memory operand: an optional size keyword plus a bracketed expression.
_MEMORY_OPERAND = re.compile(
    rf"^(?:(?:{_SIZE_KEYWORDS})\s+ptr\s+)?\[\s*(?P<body>[^\]]*?)\s*\]$",
    re.IGNORECASE,
)

#: One term of a bracketed address expression.
_ADDRESS_TERM = re.compile(
    r"(?P<sign>[+-])?\s*(?P<value>0x[0-9a-fA-F]+|\d+|[a-zA-Z][a-zA-Z0-9]*)"
    r"(?:\s*\*\s*(?P<scale>\d+))?"
)

#: An operand that is exactly one register or one immediate.
_SIMPLE_OPERAND = re.compile(r"^(?:[a-z][a-z0-9]*|-?(?:0x[0-9a-f]+|\d+))$")

#: Maximum number of arguments rendered in a signature.
_MAX_ARGUMENTS = 6

#: Branch mnemonic -> (operator, unsigned) for a condition built from ``cmp``.
_COMPARISONS: dict[str, tuple[str, bool]] = {
    "je": ("==", False),
    "jz": ("==", False),
    "jne": ("!=", False),
    "jnz": ("!=", False),
    "jl": ("<", False),
    "jle": ("<=", False),
    "jg": (">", False),
    "jge": (">=", False),
    "jb": ("<", True),
    "jbe": ("<=", True),
    "ja": (">", True),
    "jae": (">=", True),
}

#: Branch mnemonic -> the mnemonic with the opposite polarity.
_INVERSES: dict[str, str] = {
    "je": "jne",
    "jne": "je",
    "jz": "jnz",
    "jnz": "jz",
    "jl": "jge",
    "jge": "jl",
    "jle": "jg",
    "jg": "jle",
    "jb": "jae",
    "jae": "jb",
    "jbe": "ja",
    "ja": "jbe",
    "js": "jns",
    "jns": "js",
    "jo": "jno",
    "jno": "jo",
    "jp": "jnp",
    "jnp": "jp",
}

#: Mnemonics whose only side effect on a condition is a comparison/test.
_COMPARE_MNEMONICS = frozenset({"cmp", "test", "comiss", "comisd", "ucomiss", "ucomisd"})


@dataclass(frozen=True)
class CallSite:
    """One control transfer out of, or into, the rendered function.

    Attributes:
        address: Virtual address of the transferring instruction.
        target: Absolute destination for a direct transfer, ``None`` when the
            destination is only known at run time (a register or memory
            operand).
        name: Import or function-symbol name known for ``target``, if any.
        kind: ``"call"`` for a subroutine call, ``"jump"`` for a direct jump out
            of the function (a tail call), ``"unknown"`` for an indirect jump
            whose destination could not be resolved.
    """

    address: int
    target: int | None
    name: str | None
    kind: Literal["call", "jump", "unknown"]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the call site for the JSON report."""
        return {
            "address": f"0x{self.address:x}",
            "target": None if self.target is None else f"0x{self.target:x}",
            "name": self.name,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class PseudoFunction:
    """Readable pseudo-C rendering of one function.

    Attributes:
        address: Virtual address the rendering starts at.
        name: Function name from discovery, or ``None`` when unnamed.
        lines: Rendered body lines in source order; each carries the raw
            instruction text as a trailing comment.
        body: Complete text: header comment block, signature, braces and body.
        call_sites: Control transfers in ascending address order.
        block_count: Blocks reported by the underlying CFG.
        instruction_count: Unique instructions reported by the CFG.
        truncated: ``True`` when a limit cut the rendering short.
        evidence: How the rendering was produced.
    """

    address: int
    name: str | None
    lines: tuple[str, ...]
    body: str
    call_sites: tuple[CallSite, ...]
    block_count: int
    instruction_count: int
    truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize the rendering for the JSON report."""
        return {
            "address": f"0x{self.address:x}",
            "name": self.name,
            "block_count": self.block_count,
            "instruction_count": self.instruction_count,
            "truncated": self.truncated,
            "lines": list(self.lines),
            "body": self.body,
            "call_sites": [site.to_dict() for site in self.call_sites],
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class _Memory:
    """A parsed bracketed address expression.

    Attributes:
        base: Base register (already lowercased), or ``None`` for an absolute.
        index: Index register, or ``None``.
        scale: Index scale, ``1`` when absent.
        displacement: Signed displacement added to the base.
        absolute: Literal address for absolute operands, else ``None``.
    """

    base: str | None
    index: str | None
    scale: int
    displacement: int
    absolute: int | None


@dataclass
class _Frame:
    """One open structured construct while rendering.

    Attributes:
        kind: ``"if"``, ``"else"`` or ``"while"``.
        stop: Address at which the construct closes (``None`` means "at the end
            of the function", used by a loop whose exit is not known).
        block: Start address of the block that opened the construct.
        merge: For an ``"if"`` frame, the address its else region merges at.
    """

    kind: Literal["if", "else", "while"]
    stop: int | None
    block: int
    merge: int | None = None


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


def _to_int(token: str) -> int | None:
    """Parse a hexadecimal or decimal token, returning ``None`` on junk."""
    try:
        if token[:2].lower() == "0x":
            return int(token, 16)
        return int(token, 10)
    except ValueError:  # pragma: no cover - callers only pass matched digits
        return None


def _parse_memory(operand: str) -> _Memory | None:
    """Parse a bracketed address expression, or return ``None`` if unhandled.

    Only ``[base]``, ``[base +/- disp]``, ``[base + index]`` and
    ``[base + index*scale +/- disp]`` shapes are understood. Absolute operands
    keep their literal address in :attr:`_Memory.absolute`; segment prefixes and
    expressions with more than a base and an index are left to the caller.

    Args:
        operand: Capstone operand text, e.g. ``"qword ptr [rdi + 0x10]"``.
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
    displacement = 0
    for term in _ADDRESS_TERM.finditer(body):
        value = term.group("value")
        sign = -1 if term.group("sign") == "-" else 1
        if value[0].isdigit():
            number = _to_int(value)
            if number is None:  # pragma: no cover - the regex only matches digits
                return None
            displacement += sign * number
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
    if base is None and index is None:
        return _Memory(None, None, 1, 0, displacement)
    return _Memory(base, index, scale, displacement, None)


def _instruction_text(instruction: dict[str, Any]) -> str:
    """Return the raw ``"mnemonic operands"`` text of a decoded instruction."""
    text = str(instruction.get("text") or "").strip()
    if text:
        return text
    mnemonic = str(instruction.get("mnemonic") or "").strip()
    operands = str(instruction.get("operands") or "").strip()
    return f"{mnemonic} {operands}".strip()


def _mnemonic(instruction: dict[str, Any]) -> str:
    """Return the lowercased mnemonic of a decoded instruction."""
    return str(instruction.get("mnemonic") or "").strip().lower()


def _operands(instruction: dict[str, Any]) -> str:
    """Return the operand text of a decoded instruction."""
    return str(instruction.get("operands") or "")


def _address(instruction: dict[str, Any]) -> int:
    """Return the virtual address of a decoded instruction.

    ``BasicBlock.instructions`` holds ``IRInstruction.to_dict()`` payloads, where
    the address is a hexadecimal string, so both shapes are accepted.
    """
    value = instruction.get("address")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return _to_int(value.strip()) or 0
    return 0  # pragma: no cover - defensive


def _size(instruction: dict[str, Any]) -> int:
    """Return the encoded length of a decoded instruction."""
    return int(instruction.get("size") or 0)


def _direct_target(operands: str) -> int | None:
    """Return the absolute target encoded in ``operands``, if any.

    Only a straight hexadecimal immediate is accepted (``jmp 0x401006``);
    register and memory operands are indirect and yield ``None``.
    """
    text = (operands or "").strip()
    if not _DIRECT_OPERAND.match(text):
        return None
    return _to_int(text)


def _argument_names(bitness: int) -> dict[str, str]:
    """Map every alias of an ABI argument register to ``a0``..``a5``."""
    registers = _ARG_REGISTERS_64 if bitness >= 64 else _ARG_REGISTERS_32
    names: dict[str, str] = {}
    for position, register in enumerate(registers[:_MAX_ARGUMENTS]):
        for alias in _ARG_ALIASES.get(register, (register,)):
            names.setdefault(alias, f"a{position}")
        names.setdefault(register, f"a{position}")
    return names


def _identifier(name: str | None, fallback: str) -> str:
    """Return an ASCII C-ish identifier for a symbol name."""
    if not name:
        return fallback
    clean = re.sub(r"[^0-9A-Za-z_]", "_", name.strip())
    if not clean:
        return fallback
    return f"_{clean}" if clean[0].isdigit() else clean


def _slot(displacement: int) -> str:
    """Name a frame-relative stack slot."""
    if displacement < 0:
        return f"local_0x{-displacement:x}"
    if displacement == 0:
        return "local_0x0"
    return f"arg_0x{displacement:x}"


def _loop_exits(
    blocks: list[BasicBlock], by_address: dict[int, BasicBlock]
) -> dict[int, int | None]:
    """Map every loop header to the lowest exit address its latches reveal."""
    candidates: dict[int, list[int]] = {}
    for block in blocks:
        for successor in block.successors:
            if successor > block.start or successor not in by_address:
                continue
            forwards = [
                value for value in block.successors if value > block.start and value in by_address
            ]
            candidates.setdefault(successor, []).append(min(forwards) if forwards else -1)
    exits: dict[int, int | None] = {}
    for header, values in candidates.items():
        known = [value for value in values if value >= 0]
        exits[header] = min(known) if known else None
    return exits


def _require_int(name: str, value: int, maximum: int) -> int:
    """Validate one budget argument against its hard limits."""
    if value < 1:
        raise AnalysisError(f"{name} must be >= 1")
    if value > maximum:
        raise AnalysisError(f"{name} too large (limit {maximum})")
    return value


class _Renderer:
    """Shapes one function's blocks into pseudo-C lines.

    The renderer walks the blocks of a
    :class:`~codevanta.analysis.cfg.FunctionCFG` in ascending address order and
    keeps a stack of open constructs. Blocks are never re-ordered, so every line
    stays in instruction order; a construct closes at the address the branch
    structure predicts, and every edge that cannot be nested inside the current
    region becomes a ``goto``/``LABEL_<addr>`` pair.
    """

    def __init__(
        self,
        address: int,
        blocks: list[BasicBlock],
        argument_names: dict[str, str],
        pointer_width: int,
        names: dict[int, str],
        imports: dict[int, str],
    ) -> None:
        self.address = address
        self.blocks = blocks
        self.by_address = {block.start: block for block in blocks}
        self.argument_names = argument_names
        self.pointer_width = pointer_width
        self.names = names
        self.imports = imports
        self.preds: dict[int, set[int]] = {block.start: set() for block in blocks}
        #: Edges whose control transfer is already expressed by the structure.
        self.consumed: dict[int, set[int]] = {block.start: set() for block in blocks}
        for block in blocks:
            for successor in block.successors:
                if successor not in self.by_address:
                    continue
                self.preds[successor].add(block.start)
                if successor == block.end:
                    # Falling through to the next block needs no label.
                    self.consumed[successor].add(block.start)
        self.loops = _loop_exits(blocks, self.by_address)
        self.lines: list[str] = []
        self.calls: list[CallSite] = []
        self.stack: list[_Frame] = []
        self.indent = 0
        self.opened_loops: set[int] = set()
        self.consumed_jumps: set[int] = set()

    # -- public ---------------------------------------------------------

    def render(self) -> tuple[tuple[str, ...], tuple[CallSite, ...]]:
        """Render every block and return the body lines plus the call sites."""
        for block in self.blocks:
            self._close_frames(block.start)
            opened = self._open_loop(block.start)
            if not opened and self._needs_label(block.start):
                self._emit(f"LABEL_{block.start:x}:")
            self._render_block(block)
        self._close_all()
        return tuple(self.lines), tuple(self.calls)

    # -- structure bookkeeping ------------------------------------------

    def _emit(self, text: str) -> None:
        """Append one already-composed line with the current indentation."""
        self.lines.append(f"{_INDENT * self.indent}{text}")

    def _line(self, statement: str | None, instruction: dict[str, Any]) -> None:
        """Append one source line with the raw instruction as a trailing comment."""
        text = _instruction_text(instruction)
        if statement is None:
            self._emit(f"/* {text} */")
        else:
            self._emit(f"{statement}  /* {text} */")

    def _consume(self, target: int, source: int) -> None:
        """Record that the edge ``source -> target`` is expressed by structure."""
        self.consumed.setdefault(target, set()).add(source)

    def _needs_label(self, start: int) -> bool:
        """Whether a block needs ``LABEL_<addr>:`` because something jumps to it."""
        if start == self.address or start in self.opened_loops:
            return False
        return bool(self.preds.get(start, set()) - self.consumed.get(start, set()))

    def _close_frames(self, address: int) -> None:
        """Close every construct that ends at or before ``address``."""
        while self.stack:
            frame = self.stack[-1]
            if frame.stop is None or frame.stop > address:
                return
            self.stack.pop()
            self.indent -= 1
            if frame.kind == "if" and frame.merge is not None and frame.merge > address:
                self._emit("} else {")
                self.indent += 1
                self.stack.append(_Frame("else", frame.merge, frame.block))
            else:
                self._emit("}")

    def _close_all(self) -> None:
        """Close every construct still open at the end of the function."""
        while self.stack:
            self.stack.pop()
            self.indent -= 1
            self._emit("}")

    def _open_loop(self, start: int) -> bool:
        """Open ``while (1) {`` when ``start`` is the target of a back edge."""
        if start not in self.loops or start in self.opened_loops:
            return False
        self.opened_loops.add(start)
        self._emit("while (1) {")
        self.indent += 1
        self.stack.append(_Frame("while", self.loops[start], start))
        for block in self.blocks:
            if start in block.successors and start <= block.start:
                self._consume(start, block.start)
        return True

    def _limit(self) -> int | None:
        """Return the address of the innermost enclosing region's end, if any."""
        for frame in reversed(self.stack):
            if frame.stop is not None:
                return frame.stop
        return None

    def _loop_stop(self) -> int | None:
        """Return the exit address of the innermost open loop, if any."""
        for frame in reversed(self.stack):
            if frame.kind == "while":
                return frame.stop
        return None

    # -- blocks ---------------------------------------------------------

    def _render_block(self, block: BasicBlock) -> None:
        """Render one block's body and its terminator."""
        instructions = block.instructions
        if not instructions:
            return
        body = instructions[:-1] if block.terminator else instructions
        compare: dict[str, Any] | None = None
        for instruction in body:
            if (
                _mnemonic(instruction) in _COMPARE_MNEMONICS
                and len(_split_operands(_operands(instruction))) == 2
            ):
                compare = instruction
            self._line(self._statement(instruction), instruction)
        if not block.terminator:
            return
        last = instructions[-1]
        mnemonic = _mnemonic(last)
        if mnemonic in _RET_MNEMONICS:
            self._line("return;", last)
        elif mnemonic in _UNCONDITIONAL_JUMPS:
            self._jump(block, last)
        else:
            self._branch(block, last, compare)

    def _statement(self, instruction: dict[str, Any]) -> str | None:
        """Return the C statement for an instruction, or ``None`` when it has none."""
        mnemonic = _mnemonic(instruction)
        operands = _split_operands(_operands(instruction))
        if mnemonic in _CALL_MNEMONICS:
            return self._call(instruction)
        if mnemonic in _MOV_MNEMONICS and len(operands) == 2:
            target = self._operand(operands[0], instruction)
            source = self._operand(operands[1], instruction)
            return f"{target} = {source};"
        if mnemonic == "lea" and len(operands) == 2:
            target = self._operand(operands[0], instruction)
            return f"{target} = {self._address_of(operands[1], instruction)};"
        if mnemonic == "imul" and len(operands) == 3:
            target = self._operand(operands[0], instruction)
            left = self._operand(operands[1], instruction)
            right = self._operand(operands[2], instruction)
            return f"{target} = {left} * {right};"
        if mnemonic in _COMPOUND_ASSIGN and len(operands) == 2:
            target = self._operand(operands[0], instruction)
            source = self._operand(operands[1], instruction)
            return f"{target} {_COMPOUND_ASSIGN[mnemonic]} {source};"
        if mnemonic in _UNARY_ASSIGN and len(operands) == 1:
            target = self._operand(operands[0], instruction)
            return f"{target} = {_UNARY_ASSIGN[mnemonic]}{target};"
        if mnemonic in _STEP_ASSIGN and len(operands) == 1:
            target = self._operand(operands[0], instruction)
            return f"{target}{_STEP_ASSIGN[mnemonic]};"
        return None

    def _call(self, instruction: dict[str, Any]) -> str:
        """Render a call and record it as a :class:`CallSite`."""
        address = _address(instruction)
        target = _direct_target(_operands(instruction))
        if target is None:
            self.calls.append(CallSite(address, None, None, "call"))
            return "(*ptr)();"
        imported = self.imports.get(target)
        if imported is not None:
            self.calls.append(CallSite(address, target, imported, "call"))
            return f"{imported}();"
        self.calls.append(CallSite(address, target, self.names.get(target), "call"))
        return f"call_{target:x}();"

    def _jump(self, block: BasicBlock, instruction: dict[str, Any]) -> None:
        """Render an unconditional jump as ``continue``, ``goto`` or a tail call."""
        address = _address(instruction)
        target = _direct_target(_operands(instruction))
        if target is None:
            self.calls.append(CallSite(address, None, None, "unknown"))
            self._line(None, instruction)
            return
        if block.start in self.consumed_jumps:
            # The enclosing if/else structure already expresses this transfer.
            self._line(None, instruction)
            return
        if target <= block.start and target in self.opened_loops:
            self._consume(target, block.start)
            self._line("continue;", instruction)
            return
        if target in self.by_address:
            self._line(f"goto LABEL_{target:x};", instruction)
            return
        self.calls.append(CallSite(address, target, self.imports.get(target), "jump"))
        self._line(f"goto 0x{target:x};", instruction)

    def _branch(
        self,
        block: BasicBlock,
        instruction: dict[str, Any],
        compare: dict[str, Any] | None,
    ) -> None:
        """Render a conditional branch as a loop exit, an ``if`` or a ``goto``."""
        mnemonic = _mnemonic(instruction)
        target = _direct_target(_operands(instruction))
        if target is None:
            self._line(None, instruction)
            return
        loop_stop = self._loop_stop()
        if loop_stop is not None and target == loop_stop:
            self._consume(target, block.start)
            self._break(self._condition(mnemonic, compare, invert=False), instruction)
            return
        if target <= block.start and target in self.opened_loops:
            self._consume(target, block.start)
            self._break(self._condition(mnemonic, compare, invert=True), instruction)
            return
        if self._can_structure(block, target):
            self._structure_if(block, instruction, compare, target)
            return
        condition = self._condition(mnemonic, compare, invert=False)
        self._line(f"if ({condition}) {{", instruction)
        self.indent += 1
        if target in self.by_address:
            self._emit(f"goto LABEL_{target:x};")
        else:
            self._emit(f"goto 0x{target:x};")
        self.indent -= 1
        self._emit("}")

    def _break(self, condition: str, instruction: dict[str, Any]) -> None:
        """Emit one loop-exit test followed by ``break;``."""
        self._line(f"if ({condition}) {{", instruction)
        self.indent += 1
        self._emit("break;")
        self.indent -= 1
        self._emit("}")

    def _can_structure(self, block: BasicBlock, target: int) -> bool:
        """Whether a forward branch fits inside the current region as an ``if``."""
        if target <= block.start:
            return False
        if target not in self.by_address or block.end not in self.by_address:
            return False
        limit = self._limit()
        return limit is None or target <= limit

    def _structure_if(
        self,
        block: BasicBlock,
        instruction: dict[str, Any],
        compare: dict[str, Any] | None,
        target: int,
    ) -> None:
        """Open ``if (<inverted condition>) {`` for a forward branch.

        The condition is inverted because the *fallthrough* path is rendered as
        the then-branch: instruction order then equals source order and the
        branch target stays the else/merge address.
        """
        condition = self._condition(_mnemonic(instruction), compare, invert=True)
        fallthrough = self.by_address[block.end]
        merge = self._merge_address(block, fallthrough, target)
        self._line(f"if ({condition}) {{", instruction)
        self.indent += 1
        self.stack.append(_Frame("if", target, block.start, merge))
        self._consume(target, block.start)
        if merge is not None:
            self._consume(merge, fallthrough.start)
            self.consumed_jumps.add(fallthrough.start)

    def _merge_address(self, block: BasicBlock, fallthrough: BasicBlock, target: int) -> int | None:
        """Return the address an if/else pair merges at, or ``None`` if it cannot.

        ``} else {`` is only honest when the then-branch is a single block that
        jumps over a region only this branch reaches, so the two halves are
        mutually exclusive.
        """
        if self.preds.get(target, set()) != {block.start}:
            return None
        if not fallthrough.instructions:
            return None
        last = fallthrough.instructions[-1]
        if _mnemonic(last) not in _UNCONDITIONAL_JUMPS:
            return None
        merge = _direct_target(_operands(last))
        if merge is None or merge <= target or merge not in self.by_address:
            return None
        return merge

    # -- operands -------------------------------------------------------

    def _register(self, name: str) -> str:
        """Name a register from the ABI, falling back to its architectural name."""
        lowered = name.lower()
        return self.argument_names.get(lowered, lowered)

    def _operand(self, operand: str, instruction: dict[str, Any]) -> str:
        """Render one operand as a pseudo-C expression."""
        text = operand.strip()
        memory = _parse_memory(text)
        if memory is not None:
            expression = self._address_of(text, instruction)
            if memory.base in _STACK_REGISTERS and memory.index is None:
                # A frame slot already *is* the value; only real pointers dereference.
                return expression
            width = self.pointer_width * 8
            return f"*(u{width}*)({expression})"
        lowered = text.lower()
        if not lowered:
            return ""
        if not _SIMPLE_OPERAND.match(lowered):
            # An operand shape the renderer does not model (a segment override, an
            # unsupported expression): keep the raw text instead of guessing.
            return text
        return self._register(lowered)

    def _address_of(self, operand: str, instruction: dict[str, Any]) -> str:
        """Render a bracketed operand as a plain address expression (no deref)."""
        memory = _parse_memory(operand)
        if memory is None:
            return self._operand(operand, instruction)
        if memory.base in _PC_REGISTERS:
            return f"0x{_address(instruction) + _size(instruction) + memory.displacement:x}"
        if memory.absolute is not None:
            return f"0x{memory.absolute:x}"
        if memory.base is None and memory.index is None:  # pragma: no cover - defensive
            return f"0x{memory.displacement:x}"
        if memory.base in _STACK_REGISTERS and memory.index is None:
            return _slot(memory.displacement)
        parts: list[str] = []
        if memory.base is not None:
            parts.append(self._register(memory.base))
        if memory.index is not None:
            index = self._register(memory.index)
            parts.append(index if memory.scale == 1 else f"{index} * {memory.scale}")
        expression = " + ".join(parts)
        if memory.displacement > 0:
            expression = f"{expression} + 0x{memory.displacement:x}"
        elif memory.displacement < 0:
            expression = f"{expression} - 0x{-memory.displacement:x}"
        return expression

    def _condition(
        self,
        mnemonic: str,
        compare: dict[str, Any] | None,
        *,
        invert: bool,
    ) -> str:
        """Build a condition from a branch mnemonic and the comparison feeding it."""
        name = mnemonic.lower()
        if invert:
            inverse = _INVERSES.get(name)
            if inverse is None:
                return f"!flag_from_{name}"
            name = inverse
        operators = _COMPARISONS.get(name)
        if operators is not None and compare is not None:
            text = self._comparison(operators, compare)
            if text is not None:
                return text
        return f"flag_from_{name}"

    def _comparison(self, operators: tuple[str, bool], compare: dict[str, Any]) -> str | None:
        """Render ``cmp``/``test`` operands as a comparison, or ``None``."""
        operands = _split_operands(_operands(compare))
        if len(operands) != 2:
            return None
        operator, unsigned = operators
        left = self._operand(operands[0], compare)
        right = self._operand(operands[1], compare)
        if _mnemonic(compare) == "test":
            if operator not in ("==", "!="):
                return None
            return f"({left} & {right}) {operator} 0"
        cast = "(unsigned) " if unsigned else ""
        return f"{cast}{left} {operator} {right}"


def _header(
    evidence: Evidence,
    display: str,
    cfg: FunctionCFG,
    truncated: bool,
    argument_types: tuple[ArgumentType, ...] = (),
    return_type: ReturnType | None = None,
) -> list[str]:
    """Build the header comment block (ASCII only)."""
    warnings = list(cfg.warnings)
    if truncated and not warnings:
        warnings.append(
            "rendering stopped at the instruction/block budget; the output is incomplete"
        )
    lines = [
        "/*",
        " * CODEVANTA pseudo-C decompilation (heuristic, phase 3)",
        f" * address: 0x{cfg.function_address:x}",
        f" * symbol: {display}",
        f" * confidence: {evidence.confidence.value}",
        f" * evidence: {evidence.source} / {evidence.method} - {evidence.detail}",
        f" * blocks: {len(cfg.blocks)}  instructions: {cfg.instruction_count}"
        f"  truncated: {str(truncated).lower()}",
        " * caveat: control flow, argument count and types are inferred from mnemonics;"
        " nothing is executed",
    ]
    for argument in argument_types:
        lines.append(
            f" * argument {argument.name} ({argument.register}): {argument.c_type} "
            f"[{argument.confidence.value}] - {argument.evidence_note}"
        )
    if return_type is not None:
        lines.append(
            f" * return: {return_type.c_type} [{return_type.confidence.value}] - "
            f"{return_type.evidence_note}"
        )
    for warning in warnings[:6]:
        lines.append(f" * warning: {warning}")
    if len(warnings) > 6:
        lines.append(f" * warning: (+{len(warnings) - 6} more)")
    lines.append(" */")
    return lines


def decompile_function(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
) -> PseudoFunction:
    """Render one function as pseudo-C.

    Args:
        path: File the bytes are read from (read-only; never executed).
        info: Loaded binary metadata used for address mapping, decoding, symbol
            names and imports.
        address: Virtual address of the function; must be inside an executable
            section.
        max_instructions: Instruction budget for the recursive traversal
            (``1`` .. :data:`MAX_MAX_INSTRUCTIONS`).
        max_blocks: Block budget for the recursive traversal
            (``1`` .. :data:`MAX_MAX_BLOCKS`).

    Returns:
        The rendered :class:`PseudoFunction`.

    Raises:
        AnalysisError: When ``address`` is not executable code, when a budget is
            out of range, or when the region decodes to no instruction at all.
    """
    instruction_budget = _require_int("max_instructions", max_instructions, MAX_MAX_INSTRUCTIONS)
    block_budget = _require_int("max_blocks", max_blocks, MAX_MAX_BLOCKS)
    cfg = build_recursive_cfg(
        path,
        info,
        address,
        max_instructions=instruction_budget,
        max_blocks=block_budget,
    )
    if cfg.instruction_count == 0:
        raise AnalysisError(f"no decodable instruction at 0x{address:x}")

    pointer_width = 8 if info.bitness >= 64 else 4
    argument_names = _argument_names(info.bitness)
    names: dict[int, str] = {}
    for candidate in discover_functions(info):
        if candidate.name:
            names[candidate.address] = candidate.name
    imports: dict[int, str] = {}
    for item in info.imports:
        if not item.address:
            continue
        printable = _identifier(item.name, "")
        if printable:
            imports[int(item.address)] = printable

    blocks = list(cfg.blocks)
    renderer = _Renderer(
        address=address,
        blocks=blocks,
        argument_names=argument_names,
        pointer_width=pointer_width,
        names=names,
        imports=imports,
    )
    lines, call_sites = renderer.render()

    display = _identifier(cfg.function_name, f"sub_{address:x}")
    instructions = [
        instruction for block in blocks for instruction in block.instructions
    ]
    argument_types = infer_argument_types(instructions, pointer_width)
    return_type = infer_return_type(instructions, pointer_width)
    parameters = ", ".join(
        f"{argument.c_type} {argument.name}" for argument in argument_types
    )
    if not parameters:
        parameters = "void"
    truncated = cfg.truncated
    evidence = Evidence(
        source=_SOURCE,
        method=_METHOD,
        confidence=Confidence.LOW,
        address=address,
        detail=(
            f"pseudo-C rendered from {cfg.instruction_count} instruction(s) in "
            f"{len(blocks)} block(s) of a recursive traversal; argument count and "
            "argument/return types from register use, control flow from branch "
            "targets, widths from the pointer size; mnemonics only, nothing is "
            "executed"
        ),
        extra={
            "argument_types": [argument.to_dict() for argument in argument_types],
            "return_type": return_type.to_dict(),
        },
    )

    body_lines = _header(evidence, display, cfg, truncated, argument_types, return_type)
    body_lines.append(f"{return_type.c_type} {display}({parameters})")
    body_lines.append("{")
    for line in lines:
        body_lines.append(f"{_INDENT}{line}" if line else "")
    body_lines.append("}")
    return PseudoFunction(
        address=address,
        name=cfg.function_name,
        lines=lines,
        body="\n".join(body_lines),
        call_sites=call_sites,
        block_count=len(blocks),
        instruction_count=cfg.instruction_count,
        truncated=truncated,
        evidence=evidence,
    )

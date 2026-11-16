"""Readable pseudo-C emission from the SSA IR (decompiler v2 increment 3).

One deterministic lowering: :func:`emit_pseudo_c` walks the SSA blocks and
instructions that :func:`codevanta.analysis.ir_ssa.build_ssa` produced and
prints one pseudo-C statement per definition, reusing the increment-2 folded
``expr`` strings verbatim (``rax.2 = rax.1 + rbx.0;``, ``rcx.1 = 0;``,
``rax.1 = ptr(rbx.0 + 0x10);``). Recovered conditions render as bounded
``if (...) { /* taken: signed */ }`` lines whose operands are cast to the
jump's signedness at the SSA type-hint width (or the canonical register's
width when untyped; immediates stay uncased); calls render their SSA argument
registers and a bounded clobber note; phi joins render as
``id = phi(value @ block N, ...)`` statements; control flow is rendered
structured where the CFG vocabulary allows -- single-latch ``while`` loops
from dominance back-edges and if/else diamonds whose arms reconverge at one
merge block -- with an honest linear fallback (annotated ``if`` lines, loop
boundaries, undefined reads as comments) for every shape outside it; nothing
is guessed and nothing is executed.

Deliberate v1 limits (stated in the evidence detail): the output is *linear*
-- no structured if/else joins, no phi insertion, no loop reconstruction --
and the clobber/undef note lists are clipped so the text stays bounded
(:data:`MAX_LINES`, :data:`MAX_LINE_CHARS`, :data:`MAX_UNDEF_MARKS`,
:data:`MAX_CLOBBER_NOTES`). Nothing is executed; the SSA is pure input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from codevanta.analysis.ir_ssa import (
    FLAGS_REGISTER,
    SSAFunction,
    compute_dominance,
)
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "MAX_CLOBBER_NOTES",
    "MAX_LINES",
    "MAX_LINE_CHARS",
    "MAX_UNDEF_MARKS",
    "PseudoCResult",
    "emit_pseudo_c",
]

#: Hard cap on emitted lines; further instructions set the truncated flag.
MAX_LINES = 2000

#: Hard cap per emitted line; longer lines are clipped with a trailing
#: ``...`` marker and set the ``lines_clipped`` flag.
MAX_LINE_CHARS = 160

#: Cap on the reported undefined-read markers; the rest are dropped (with a
#: warning) rather than growing the result without bound.
MAX_UNDEF_MARKS = 16

#: Cap on the per-call clobber note; further clobbers collapse into ``...``.
MAX_CLOBBER_NOTES = 8

_SOURCE = "pseudo_c.emit"
_METHOD = "ssa-structured-lowering"

#: Bounded conditional-jump mnemonic -> C comparison operator. The operator
#: itself is sign-agnostic; the signedness comes from the jump mnemonic and is
#: rendered as a taken-annotation on the if-line (casts are deliberately
#: deferred -- the raw ``cmp`` text stays in the SSA for disambiguation).
_CONDITION_OPS: dict[str, str] = {
    "je": "==",
    "jne": "!=",
    "jg": ">",
    "jnle": ">",
    "jge": ">=",
    "jnl": ">=",
    "jl": "<",
    "jnge": "<",
    "jle": "<=",
    "jng": "<=",
    "ja": ">",
    "jnbe": ">",
    "jae": ">=",
    "jnb": ">=",
    "jnc": ">=",
    "jb": "<",
    "jnae": "<",
    "jc": "<",
    "jbe": "<=",
    "jna": "<=",
}

#: Order-comparison jumps whose operands the CPU compares as signed integers
#: (``jg``/``jge``/``jl``/``jle`` plus their negated aliases).
_SIGNED_JCC: frozenset[str] = frozenset(
    {"jg", "jnle", "jge", "jnl", "jl", "jnge", "jle", "jng"}
)

#: Order-comparison jumps whose operands the CPU compares as unsigned
#: integers (``ja``/``jae``/``jb``/``jbe`` plus their negated aliases).
_UNSIGNED_JCC: frozenset[str] = frozenset(
    {"ja", "jnbe", "jae", "jnb", "jnc", "jb", "jnae", "jc", "jbe", "jna"}
)

#: Canonical x86 GP register -> width in bytes. SSA ids use the canonical
#: name for the binary's bitness (64-bit names on a 64-bit binary, 32-bit
#: ones on a 32-bit binary), so the name itself is the honest width source
#: when a value carries no type hint.
_REGISTER_WIDTHS: dict[str, int] = {
    "rax": 8,
    "rbx": 8,
    "rcx": 8,
    "rdx": 8,
    "rsi": 8,
    "rdi": 8,
    "rbp": 8,
    "rsp": 8,
    "r8": 8,
    "r9": 8,
    "r10": 8,
    "r11": 8,
    "r12": 8,
    "r13": 8,
    "r14": 8,
    "r15": 8,
    "eax": 4,
    "ebx": 4,
    "ecx": 4,
    "edx": 4,
    "esi": 4,
    "edi": 4,
    "ebp": 4,
    "esp": 4,
}

#: C integer types by width in bytes, per comparison signedness.
_SIGNED_C_TYPES: dict[int, str] = {
    1: "int8_t",
    2: "int16_t",
    4: "int32_t",
    8: "int64_t",
}
_UNSIGNED_C_TYPES: dict[int, str] = {
    1: "uint8_t",
    2: "uint16_t",
    4: "uint32_t",
    8: "uint64_t",
}

#: An SSA value id: ``<register>.<version>`` (immediates never match).
_SSA_ID_RE = re.compile(r"^([A-Za-z][A-Za-z0-9]*)\.(0|[1-9][0-9]*)$")

#: A bit width inside a type-propagation hint (``int32_t``, ``uint64_t *``).
_HINT_WIDTH_RE = re.compile(r"(8|16|32|64)")


def _operand_width(operand: str, hint_by_id: dict[str, str | None]) -> int | None:
    """Width in bytes for one condition operand, or ``None`` to leave it uncased.

    A type hint wins (its stated width, pointers included); an untyped SSA id
    falls back to its canonical register's width; immediates and other tokens
    have no width at all.
    """
    match = _SSA_ID_RE.match(operand)
    if match is None:
        return None
    hint = hint_by_id.get(operand)
    if hint:
        width_match = _HINT_WIDTH_RE.search(hint)
        if width_match:
            return int(width_match.group(1)) // 8
    return _REGISTER_WIDTHS.get(match.group(1))


def _cast_operand(
    operand: str,
    c_types: dict[int, str],
    hint_by_id: dict[str, str | None],
) -> str:
    """Prefix ``operand`` with the signedness's C type at its resolved width.

    Operands without a width (immediates, FLAGS, unknown tokens) render
    unchanged -- the comparison keeps its meaning through the other operand's
    cast plus the taken annotation.
    """
    width = _operand_width(operand, hint_by_id)
    c_type = c_types.get(width) if width is not None else None
    if c_type is None:
        return operand
    return f"({c_type}){operand}"


#: A direct branch target address inside an instruction's rendered text.
_TARGET_ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")

#: C operator for the negated form of a comparison (do-while exit edges).
_NEGATED_OPS: dict[str, str] = {
    "==": "!=",
    "!=": "==",
    "<": ">=",
    "<=": ">",
    ">": "<=",
    ">=": "<",
}


def _condition_expr(cond: dict[str, str], hint_by_id: dict[str, str | None]) -> str | None:
    """C condition text for a recovered comparison, ``None`` if unsupported.

    ``"((int64_t)rax.2 < 5)"``-shaped after the caller wraps it in ``if`` or
    ``while``; operands are cast to the jump's signedness at hint-or-register
    width, immediates stay uncased.
    """
    mnemonic = cond.get("cond", "")
    op = _CONDITION_OPS.get(mnemonic)
    if op is None:
        return None
    if mnemonic in _SIGNED_JCC:
        c_types = _SIGNED_C_TYPES
    elif mnemonic in _UNSIGNED_JCC:
        c_types = _UNSIGNED_C_TYPES
    else:
        c_types = None
    if c_types is None:
        left = cond.get("left", "???")
        right = cond.get("right", "???")
    else:
        left = _cast_operand(cond.get("left", "???"), c_types, hint_by_id)
        right = _cast_operand(cond.get("right", "???"), c_types, hint_by_id)
    return f"{left} {op} {right}"


def _negated_condition_expr(
    cond: dict[str, str], hint_by_id: dict[str, str | None]
) -> str | None:
    """The comparison with its operator negated (loop-exit condition)."""
    expr = _condition_expr(cond, hint_by_id)
    op = _CONDITION_OPS.get(cond.get("cond", ""))
    negated = _NEGATED_OPS.get(op) if op is not None else None
    if expr is None or negated is None:
        return None
    return expr.replace(f" {op} ", f" {negated} ", 1)


@dataclass(frozen=True)
class PseudoCResult:
    """The deterministic pseudo-C text for one SSA function plus metadata.

    Attributes:
        text: The emitted pseudo-C body (without a trailing newline).
        line_count: Number of emitted lines (header and block comments count).
        function_address: ``"0x..."`` form of the SSA function address.
        function_name: Discovery name, ``None`` when the address had none.
        condition_count: Number of ``if (...)`` lines emitted from recovered
            conditions.
        call_count: Number of ``call(...)`` lines emitted.
        undef_markers: Sorted SSA ids read before any definition in-region
            (``kind == "undef"``), clipped to :data:`MAX_UNDEF_MARKS`.
        loop_markers: Human-readable markers for every loop-boundary block.
        lines_clipped: At least one line hit :data:`MAX_LINE_CHARS`.
        truncated: The line budget was hit, or the underlying SSA was itself
            truncated (blocks/instructions/values/uses).
        warnings: The SSA warnings plus any emitter-level clipping warnings.
        evidence: How this text was derived (source ``pseudo_c.emit``).
    """

    text: str
    line_count: int
    function_address: str
    function_name: str | None
    condition_count: int
    call_count: int
    undef_markers: tuple[str, ...]
    loop_markers: tuple[str, ...]
    lines_clipped: bool
    truncated: bool
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize the result for the JSON report."""
        return {
            "text": self.text,
            "line_count": self.line_count,
            "function_address": self.function_address,
            "function_name": self.function_name,
            "condition_count": self.condition_count,
            "call_count": self.call_count,
            "undef_markers": list(self.undef_markers),
            "loop_markers": list(self.loop_markers),
            "lines_clipped": self.lines_clipped,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _structured_lines(
    fn: SSAFunction,
    order: list[int],
    hint_by_id: dict[str, str | None],
    expr_by_id: dict[str, str | None],
) -> tuple[list[str], int, int, bool, bool] | None:
    """Structured body lines, or ``None`` when a shape falls outside.

    Vocabulary (increment 7): single-latch ``while`` loops whose header
    comparison was recovered, and if/else diamonds whose arms are linear
    chains reconverging at one merge block. Everything else -- unrecovered
    loop conditions, nested constructs, multi-latch loops, out-of-window
    targets -- returns ``None`` so the caller falls back to the honest
    linear rendering.
    """
    blocks_by_index = {block.index: block for block in fn.blocks}
    succ = {block.index: block.successors for block in fn.blocks}
    if any(index not in succ for index in order):
        return None
    entry, reachable, preds, idom, _children = compute_dominance(order, succ)

    def dominates(ancestor: int, node: int) -> bool:
        current: int | None = node
        while current is not None:
            if current == ancestor:
                return True
            current = idom.get(current)
        return False

    latch_by_header: dict[int, int] = {}
    for node in reachable:
        for successor in succ.get(node, ()):
            if successor == node or successor not in reachable:
                continue
            if dominates(successor, node):
                if successor in latch_by_header and latch_by_header[successor] != node:
                    return None  # multi-latch loops are out of vocabulary
                latch_by_header[successor] = node

    lines: list[str] = []
    condition_count = 0
    call_count = 0
    lines_clipped = False
    stop = False
    done: set[int] = set()
    position_of = {index: position for position, index in enumerate(order)}

    def clip(line: str) -> str:
        nonlocal lines_clipped
        if len(line) > MAX_LINE_CHARS:
            lines_clipped = True
            return line[: MAX_LINE_CHARS - 4] + " ..."
        return line

    # SENTINEL_HELPERS

    def block_branch(block: Any) -> tuple[dict[str, str], int, int] | None:
        ins = block.instructions
        if not ins:
            return None
        last = ins[-1]
        mnemonic = last.mnemonic
        if not mnemonic.startswith("j") or mnemonic == "jmp":
            return None
        if last.condition is None or len(block.successors) != 2:
            return None
        addresses = _TARGET_ADDR_RE.findall(last.text)
        if not addresses:
            return None
        start_to_index = {b.start: b.index for b in fn.blocks}
        taken = start_to_index.get(int(addresses[-1], 16))
        if taken is None or taken not in block.successors:
            return None
        fall = next(s for s in block.successors if s != taken)
        return last.condition, taken, fall

    def natural_loop(header: int, latch: int) -> set[int]:
        body = {header, latch}
        stack = [latch]
        while stack:
            node = stack.pop()
            for pred in preds.get(node, ()):
                if pred not in body:
                    body.add(pred)
                    stack.append(pred)
        return body

    def render_block_header(block: Any, indent: str) -> None:
        header = f"{indent}/* block {block.index} @ 0x{block.start:x}"
        if block.loop_boundary:
            header += " -- LOOP BOUNDARY"
            if block.phi_required:
                header += ": phi required for " + ", ".join(block.phi_required)
        lines.append(clip(header + " */"))
        for phi in block.phis:
            rendered = ", ".join(
                f"{value_id} @ block {pred_index}"
                for pred_index, value_id in phi.args
            )
            lines.append(clip(f"{indent}{phi.id} = phi({rendered});"))

    def render_instructions(block: Any, indent: str) -> bool:
        nonlocal call_count, stop
        for instruction in block.instructions:
            if len(lines) >= MAX_LINES:
                stop = True
                return False
            if instruction.call_args is not None:
                call_count += 1
                clobbers = list(instruction.writes)
                note = ", ".join(clobbers[:MAX_CLOBBER_NOTES])
                if len(clobbers) > MAX_CLOBBER_NOTES:
                    note += ", ..."
                lines.append(
                    clip(
                        f"{indent}call({', '.join(instruction.call_args)});"
                        f" /* clobbers: {note} */"
                    )
                )
            elif instruction.writes:
                gp_writes = tuple(
                    written
                    for written in instruction.writes
                    if not written.startswith(FLAGS_REGISTER + ".")
                )
                if gp_writes:
                    for written in gp_writes:
                        expr = expr_by_id.get(written)
                        lines.append(
                            clip(f"{indent}{written} = {expr if expr else written};")
                        )
                    if any(
                        written.startswith(FLAGS_REGISTER + ".")
                        for written in instruction.writes
                    ):
                        lines[-1] = clip(f"{lines[-1]} /* {instruction.text} */")
                else:
                    lines.append(clip(f"{indent}/* {instruction.text} */"))
            else:
                lines.append(clip(f"{indent}/* {instruction.text} */"))
        return True

    def arm_chain(target: int) -> tuple[list[int], int | None] | None:
        chain: list[int] = []
        node: int | None = target
        while node is not None and node not in done:
            block = blocks_by_index[node]
            if len(preds.get(node, set())) >= 2:
                return chain, node
            if block_branch(block) is not None or block.phis:
                return None
            if node in latch_by_header:
                return None
            chain.append(node)
            successors = succ.get(node, ())
            if len(successors) != 1:
                return chain, None
            node = successors[0]
        return chain, None

    current = entry
    steps = 0
    while True:
        steps += 1
        if stop or steps > len(order) + 2:
            return None
        block = blocks_by_index[current]
        if current in done:
            return None
        done.add(current)
        render_block_header(block, "")
        if not render_instructions(block, ""):
            return None
        branch = block_branch(block)
        if branch is None:
            last = block.instructions[-1] if block.instructions else None
            if (
                last is not None
                and last.mnemonic.startswith("j")
                and last.mnemonic != "jmp"
                and last.condition is not None
            ):
                return None  # a conditional outside the structuring vocabulary
            successors = succ.get(current, ())
            if not successors:
                break  # function end
            if len(successors) == 1:
                nxt = successors[0]
                if nxt in done or nxt not in blocks_by_index:
                    break  # rejoins something already rendered, or leaves
                current = nxt
                continue
            return None  # two exits without a recovered condition
        cond, taken_index, fall_index = branch
        expr = _condition_expr(cond, hint_by_id)
        if expr is None:
            return None
        if current in latch_by_header:
            latch = latch_by_header[current]
            body = natural_loop(current, latch)
            body.discard(current)
            taken_continues = taken_index in body or taken_index == current
            exit_index = fall_index if taken_continues else taken_index
            if not taken_continues:
                expr = _negated_condition_expr(cond, hint_by_id)
                if expr is None:
                    return None
            for member in body:
                member_block = blocks_by_index[member]
                if block_branch(member_block) is not None or member_block.phis:
                    return None
                if not set(member_block.successors) <= (body | {current}):
                    return None
            condition_count += 1
            lines.append(clip(f"while ({expr}) {{"))
            for member in sorted(body, key=lambda i: position_of[i]):
                member_block = blocks_by_index[member]
                done.add(member)
                render_block_header(member_block, "    ")
                if not render_instructions(member_block, "    "):
                    return None
            lines.append(clip("}"))
            if exit_index is None or exit_index in done:
                break
            if exit_index not in blocks_by_index:
                return None
            current = exit_index
            continue
        chain_result = arm_chain(taken_index)
        if chain_result is None:
            return None
        chain_t, merge_t = chain_result
        fall_result = arm_chain(fall_index)
        if fall_result is None:
            return None
        chain_f, merge_f = fall_result
        if merge_t is None or merge_f != merge_t:
            return None
        if set(chain_t) & set(chain_f):
            return None
        condition_count += 1
        lines.append(clip(f"if ({expr}) {{"))
        for member in chain_t:
            member_block = blocks_by_index[member]
            done.add(member)
            render_block_header(member_block, "    ")
            if not render_instructions(member_block, "    "):
                return None
        if chain_f:
            lines.append(clip("} else {"))
            for member in chain_f:
                member_block = blocks_by_index[member]
                done.add(member)
                render_block_header(member_block, "    ")
                if not render_instructions(member_block, "    "):
                    return None
        lines.append(clip("}"))
        if merge_t in done or merge_t not in blocks_by_index:
            break
        current = merge_t
    if set(reachable) - done:
        return None  # some reachable block was never rendered
    return lines, condition_count, call_count, lines_clipped, stop



def emit_pseudo_c(fn: SSAFunction) -> PseudoCResult:
    """Lower one SSA function to deterministic, bounded pseudo-C text.

    The walk is strictly linear over ``fn.blocks`` in the SSA's deterministic
    order: every definition prints ``<id> = <expr>;`` (the folded increment-2
    expression when present, the raw id otherwise), a call prints its SSA
    argument registers plus a bounded clobber note, a terminator with a
    recovered condition prints ``if (...) { /* taken */ }``, and everything
    else prints as a comment. No statement is ever guessed.
    """
    expr_by_id = {value.id: value.expr for value in fn.values}
    hint_by_id = {value.id: value.type_hint for value in fn.values}
    undef_markers = sorted(
        value.id for value in fn.values if value.kind == "undef"
    )
    warnings = list(fn.warnings)
    if len(undef_markers) > MAX_UNDEF_MARKS:
        warnings.append(
            f"undef-marker list clipped from {len(undef_markers)} to "
            f"{MAX_UNDEF_MARKS} entries"
        )
        undef_markers = undef_markers[:MAX_UNDEF_MARKS]

    loop_markers = tuple(
        f"block {block.index} @ 0x{block.start:x}"
        for block in fn.blocks
        if block.loop_boundary
    )
    order = [block.index for block in fn.blocks]
    header = (
        f"/* function 0x{fn.address:x} ({fn.name or 'unknown'}) -- "
        "pseudo-C from SSA (structured where possible; linear fallback) */"
    )
    structured = _structured_lines(fn, order, hint_by_id, expr_by_id)
    if structured is not None:
        body_lines, condition_count, call_count, lines_clipped, stop = structured
        truncated = stop or (
            fn.truncated_blocks
            or fn.truncated_instructions
            or fn.truncated_values
            or fn.uses_truncated
        )
        lines = [header] + body_lines
        evidence = Evidence(
            source=_SOURCE,
            method=_METHOD,
            confidence=Confidence.MEDIUM,
            address=fn.address,
            detail=(
                "pseudo-C with structured control flow where the CFG "
                "vocabulary allows (single-latch while loops from dominance "
                "back-edges, if/else diamonds over linear arms), honest "
                "linear fallback elsewhere; definitions reuse the folded "
                "expressions verbatim and nothing is executed"
            ),
        )
        return PseudoCResult(
            text="\n".join(lines),
            line_count=len(lines),
            function_address=f"0x{fn.address:x}",
            function_name=fn.name,
            condition_count=condition_count,
            call_count=call_count,
            undef_markers=tuple(undef_markers),
            loop_markers=loop_markers,
            lines_clipped=lines_clipped,
            truncated=truncated,
            warnings=tuple(warnings),
            evidence=evidence,
        )

    lines = [header]
    condition_count = 0
    call_count = 0
    lines_clipped = False
    truncated = False

    def _clip(line: str) -> str:
        nonlocal lines_clipped
        if len(line) > MAX_LINE_CHARS:
            lines_clipped = True
            return line[: MAX_LINE_CHARS - 4] + " ..."
        return line

    block: Any
    for block in fn.blocks:
        if truncated or len(lines) >= MAX_LINES:
            truncated = True
            break
        header = f"/* block {block.index} @ 0x{block.start:x}"
        if block.loop_boundary:
            header += " -- LOOP BOUNDARY"
            if block.phi_required:
                header += ": phi required for " + ", ".join(block.phi_required)
        header += " */"
        lines.append(_clip(header))
        for phi in block.phis:
            rendered = ", ".join(
                f"{value_id} @ block {pred_index}"
                for pred_index, value_id in phi.args
            )
            lines.append(_clip(f"{phi.id} = phi({rendered});"))
        for instruction in block.instructions:
            if len(lines) >= MAX_LINES:
                truncated = True
                warnings.append(
                    f"line budget MAX_LINES={MAX_LINES} reached; the rest of "
                    "the function was left out of the pseudo-C view"
                )
                break
            if instruction.call_args is not None:
                call_count += 1
                clobbers = list(instruction.writes)
                note = ", ".join(clobbers[:MAX_CLOBBER_NOTES])
                if len(clobbers) > MAX_CLOBBER_NOTES:
                    note += ", ..."
                lines.append(
                    _clip(
                        f"call({', '.join(instruction.call_args)});"
                        f" /* clobbers: {note} */"
                    )
                )
            elif instruction.condition is not None:
                condition_count += 1
                cond = instruction.condition
                expr = _condition_expr(cond, hint_by_id)
                if expr is not None:
                    mnemonic = cond.get("cond", "")
                    if mnemonic in _SIGNED_JCC:
                        note = " /* taken: signed */"
                    elif mnemonic in _UNSIGNED_JCC:
                        note = " /* taken: unsigned */"
                    else:
                        note = " /* taken */"
                    lines.append(_clip(f"if ({expr}) {{{note} }}"))
                else:
                    # An unsupported mnemonic keeps its honest raw form.
                    lines.append(_clip(f"/* {cond.get('raw', instruction.text)} */"))
            elif instruction.writes:
                # A pure FLAGS write (cmp/test and friends) reads far better
                # as its raw instruction comment than as a pseudo-register
                # assignment; GP definitions keep the expression form.
                gp_writes = tuple(
                    written
                    for written in instruction.writes
                    if not written.startswith(FLAGS_REGISTER + ".")
                )
                if gp_writes:
                    for written in gp_writes:
                        expr = expr_by_id.get(written)
                        lines.append(
                            _clip(f"{written} = {expr if expr else written};")
                        )
                    if any(
                        written.startswith(FLAGS_REGISTER + ".")
                        for written in instruction.writes
                    ):
                        # A FLAGS-writer with a GP definition (add/sub/...)
                        # keeps the raw mnemonic visible next to its fold.
                        lines[-1] = _clip(
                            f"{lines[-1]} /* {instruction.text} */"
                        )
                else:
                    lines.append(_clip(f"/* {instruction.text} */"))
            else:
                lines.append(_clip(f"/* {instruction.text} */"))

    truncated = truncated or (
        fn.truncated_blocks
        or fn.truncated_instructions
        or fn.truncated_values
        or fn.uses_truncated
    )
    evidence = Evidence(
        source=_SOURCE,
        method=_METHOD,
        confidence=Confidence.MEDIUM,
        address=fn.address,
        detail=(
            "linear pseudo-C fallback: this function contained a shape "
            "outside the structured vocabulary, so definitions reuse the "
            "folded expressions verbatim with annotated if-lines whose "
            "operands are cast to the jump's signedness at hint-or-register "
            "width (immediates and equality jumps stay uncased; the raw cmp "
            "text stays in the SSA), calls note their SSA arguments and "
            "clipped clobbers, phi joins render their merged arguments, and "
            "loop boundaries plus undefined reads stay honest comments; "
            "nothing is executed"
        ),
    )
    return PseudoCResult(
        text="\n".join(lines),
        line_count=len(lines),
        function_address=f"0x{fn.address:x}",
        function_name=fn.name,
        condition_count=condition_count,
        call_count=call_count,
        undef_markers=tuple(undef_markers),
        loop_markers=loop_markers,
        lines_clipped=lines_clipped,
        truncated=truncated,
        warnings=tuple(warnings),
        evidence=evidence,
    )

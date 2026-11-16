"""Readable pseudo-C emission from the SSA IR (decompiler v2 increment 3).

One deterministic lowering: :func:`emit_pseudo_c` walks the SSA blocks and
instructions that :func:`codevanta.analysis.ir_ssa.build_ssa` produced and
prints one pseudo-C statement per definition, reusing the increment-2 folded
``expr`` strings verbatim (``rax.2 = rax.1 + rbx.0;``, ``rcx.1 = 0;``,
``rax.1 = ptr(rbx.0 + 0x10);``). Recovered conditions render as bounded
``if (left == right) { /* taken */ }`` lines annotated with the comparison's
signedness (``/* taken: signed */`` / ``/* taken: unsigned */`` for the
order-comparison jumps); calls render their SSA argument
registers and a bounded clobber note; loop-boundary blocks and undefined
reads are flagged as honest comments, never guessed away.

Deliberate v1 limits (stated in the evidence detail): the output is *linear*
-- no structured if/else joins, no phi insertion, no loop reconstruction --
and the clobber/undef note lists are clipped so the text stays bounded
(:data:`MAX_LINES`, :data:`MAX_LINE_CHARS`, :data:`MAX_UNDEF_MARKS`,
:data:`MAX_CLOBBER_NOTES`). Nothing is executed; the SSA is pure input.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from codevanta.analysis.ir_ssa import FLAGS_REGISTER, SSAFunction
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
_METHOD = "ssa-linear-lowering"

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

    lines: list[str] = [
        (
            f"/* function 0x{fn.address:x} ({fn.name or 'unknown'}) -- "
            "pseudo-C from SSA (linear lowering; unstructured) */"
        )
    ]
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
                mnemonic = cond.get("cond", "")
                op = _CONDITION_OPS.get(mnemonic)
                if op is not None:
                    if mnemonic in _SIGNED_JCC:
                        note = " /* taken: signed */"
                    elif mnemonic in _UNSIGNED_JCC:
                        note = " /* taken: unsigned */"
                    else:
                        note = " /* taken */"
                    lines.append(
                        _clip(
                            f"if ({cond.get('left', '???')} {op} "
                            f"{cond.get('right', '???')}) {{{note} }}"
                        )
                    )
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
    loop_markers = tuple(
        f"block {block.index} @ 0x{block.start:x}"
        for block in fn.blocks
        if block.loop_boundary
    )
    evidence = Evidence(
        source=_SOURCE,
        method=_METHOD,
        confidence=Confidence.MEDIUM,
        address=fn.address,
        detail=(
            "linear pseudo-C lowering over the SSA IR: definitions reuse the "
            "folded expressions verbatim, recovered conditions render as "
            "bounded if-lines annotated with the comparison's signedness "
            "(casts deliberately deferred; the raw cmp text stays in the "
            "SSA), calls note their SSA arguments and clipped clobbers, "
            "loop boundaries and undefined reads stay honest comments; "
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

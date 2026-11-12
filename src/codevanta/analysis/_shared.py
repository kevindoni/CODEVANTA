"""Transfer-instruction helpers shared by the analysis modules.

The xref scanner, the linear-sweep CFG, and the recursive-descent CFG must all
answer the same two questions — *is this mnemonic a control transfer, and is
its target statically known?* — so the answers live here once instead of being
re-derived (and slowly drifting apart) in each module.
"""

from __future__ import annotations

from codevanta.ir.instruction import IRInstruction

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

#: Conditional x86 branch mnemonics, mapped to the ``branch`` xref kind.
_BRANCH_MNEMONICS = frozenset(
    {
        "je",
        "jne",
        "jz",
        "jnz",
        "jb",
        "jbe",
        "ja",
        "jae",
        "jl",
        "jle",
        "jg",
        "jge",
        "js",
        "jns",
        "jo",
        "jno",
        "jp",
        "jnp",
        "jcxz",
        "jecxz",
        "jrcxz",
    }
)

#: Maps a lowercase mnemonic to the cross-reference kind it produces.
_KIND_BY_MNEMONIC: dict[str, str] = {
    "call": "call",
    "jmp": "jump",
    **{mnemonic: "branch" for mnemonic in _BRANCH_MNEMONICS},
}


def direct_target(operands: str) -> int | None:
    """Return the immediate transfer target encoded in ``operands``, if any.

    Only a single hexadecimal literal is accepted, with an optional leading
    ``#`` for ARM-style syntax (``jmp 0x401006``, ``bl #0x8500``). Register and
    memory operands (``call rax``, ``jmp qword ptr [rip + 0x20]``) are indirect
    and therefore return ``None``: their target is not statically known at this
    layer, so callers must leave them unresolved instead of guessing.
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


def transfer_kind(mnemonic: str) -> str | None:
    """Return the transfer kind for ``mnemonic``, or ``None`` if it is not one.

    Kinds are ``"call"``, ``"jump"`` (unconditional), and ``"branch"``
    (conditional); they mirror the xref kinds in
    :mod:`codevanta.analysis.xrefs`.
    """
    return _KIND_BY_MNEMONIC.get((mnemonic or "").strip().lower())


def terminator_kind(mnemonic: str) -> str | None:
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


def terminator_mnemonic(mnemonic: str) -> str | None:
    """Return the normalized terminator mnemonic, or ``None`` for a fallthrough end."""
    name = (mnemonic or "").strip().lower()
    if not name or terminator_kind(name) is None:
        return None
    return name


def successors(
    last: IRInstruction,
    block_starts: set[int],
    dropped: list[int],
) -> tuple[int, ...]:
    """Compute the sorted, deduplicated successor set of a block-final instruction."""
    kind = terminator_kind(last.mnemonic)
    candidates: list[int] = []

    if kind in (None, "cond"):  # ordinary instructions and conditional jumps fall through
        candidates.append(last.address + last.size)
    if kind in ("jmp", "cond"):  # direct branch targets
        target = direct_target(last.operands)
        if target is not None:
            candidates.append(target)

    resolved: set[int] = set()
    for address in candidates:
        if address in block_starts:
            resolved.add(address)
        else:
            dropped.append(address)
    return tuple(sorted(resolved))


def dropped_targets_warning(dropped: list[int]) -> str | None:
    """Format the bounded warning for edge targets that were never decoded."""
    if not dropped:
        return None
    unique = list(dict.fromkeys(dropped))
    shown = ", ".join(f"0x{address:x}" for address in unique[:8])
    extra = f" (+{len(unique) - 8} more)" if len(unique) > 8 else ""
    return f"edge target(s) {shown}{extra} were not decoded; those edges are omitted"

"""Content fingerprints for a single function region (phase 2g).

:func:`function_fingerprint` disassembles the function that starts at an address
with a bounded *linear sweep* and reduces the decoded instructions to one
SHA-256 digest over their **normalized shape**:

1. Every instruction is rendered as ``"<mnemonic> <operands>"``.
2. Numeric literals are masked: ``0x401030``, ``-0x10`` and ``42`` all become
   ``#``. Consecutive masks are collapsed and whitespace is normalized, so
   ``mov eax, [rbp - 0x10]`` and ``mov eax, [rbp - 0x8]`` render identically.
3. The masked instructions are joined with ``"\\n"`` and hashed with SHA-256.

That makes the digest a *shape* fingerprint: two functions with the same
mnemonic/operand structure compare equal even when their immediates, branch
targets or frame offsets differ. This is what makes the digest useful for a
recompiled or relocated build -- and exactly why equal digests are **not** byte
equality and different digests are **not** a semantic difference. Every
fingerprint carries that caveat in its evidence at ``Confidence.MEDIUM``.

Work is bounded twice: the caller's ``max_instructions`` budget (default
:data:`DEFAULT_MAX_INSTRUCTIONS`) and the file-backed bytes of the containing
section, so at most ``max_instructions * 16`` bytes are read.
:attr:`FunctionFingerprint.truncated` says whether the digest covers only a
prefix of the function.

Nothing is mapped or executed: bytes are read with
:func:`~codevanta.core.report.read_code`, which only ever reads the file, and
the target architecture is decoded by
:class:`~codevanta.core.disassembler.Disassembler`.
"""

from __future__ import annotations

import hashlib
import re
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
    "DEFAULT_MAX_INSTRUCTIONS",
    "DIGEST_ALGORITHM",
    "MAX_MAX_INSTRUCTIONS",
    "MIN_MAX_INSTRUCTIONS",
    "FunctionFingerprint",
    "function_fingerprint",
    "normalize_instruction",
]

#: Default instruction budget for one fingerprint.
DEFAULT_MAX_INSTRUCTIONS = 2_000

#: Smallest accepted ``max_instructions``; smaller requests are rejected.
MIN_MAX_INSTRUCTIONS = 1

#: Largest accepted ``max_instructions``; larger requests are rejected.
MAX_MAX_INSTRUCTIONS = MAX_DISASSEMBLY_COUNT

#: Hash used for the digest, recorded in :attr:`FunctionFingerprint.algorithm`.
DIGEST_ALGORITHM = "sha256"

#: Longest possible encoding of one instruction on a supported architecture.
#: Used to size the read window for the instruction budget.
_MAX_INSTRUCTION_BYTES = 16

#: ``0x401030``, ``-0x10``, ``+0X1F`` -> one mask. Hex is masked before bare
#: numbers so the ``0x`` form never leaves a trailing digit behind.
_HEX_LITERAL = re.compile(r"[-+]?0[xX][0-9a-fA-F]+")

#: A bare decimal literal (``42``, ARM's ``#-1``). The lookarounds keep register
#: and operand names that merely contain digits -- ``x29``, ``dword``, ``q3`` --
#: intact.
_BARE_NUMBER = re.compile(r"(?<![0-9A-Za-z_])[-+]?[0-9]+(?![0-9A-Za-z_])")

#: Consecutive masks collapse, so ARM's ``#0x1`` (which normalizes to ``##``)
#: and x86's ``0x1`` (which normalizes to ``#``) agree.
_REPEATED_MASK = re.compile(r"#+")

_EVIDENCE_SOURCE = "function_hash.normalized"
_EVIDENCE_METHOD = "normalized_linear_disassembly"
_CAVEAT = (
    "shape-based fingerprint: instructions are normalized and numeric literals are masked "
    "to '#', so an equal digest is not byte equality and a different digest is not a "
    "semantic difference; nothing was executed"
)


@dataclass(frozen=True)
class FunctionFingerprint:
    """A normalized-content fingerprint for one function region.

    Attributes:
        address: Virtual address the sweep started at (the requested address).
        digest: Lower-case hexadecimal SHA-256 of the newline-joined, normalized
            instruction stream.
        instruction_count: Number of instructions that contributed to
            ``digest``.
        truncated: ``True`` when the sweep stopped before the end of the
            available bytes -- the instruction budget was reached, the section's
            file-backed bytes ran out, or trailing bytes could not be decoded.
            The digest then covers only a prefix of the function.
        evidence: How the digest was produced, including the shape caveat and
            the applied bounds.
    """

    address: int
    digest: str
    instruction_count: int
    truncated: bool
    evidence: Evidence

    @property
    def algorithm(self) -> str:
        """Name of the hash used for :attr:`digest`."""
        return DIGEST_ALGORITHM

    def to_dict(self) -> dict[str, Any]:
        """Serialize the fingerprint for the JSON report."""
        return {
            "address": f"0x{self.address:x}",
            "algorithm": self.algorithm,
            "digest": self.digest,
            "instruction_count": self.instruction_count,
            "truncated": self.truncated,
            "evidence": self.evidence.to_dict(),
        }


def normalize_instruction(instruction: IRInstruction) -> str:
    """Render one instruction with every numeric literal masked to ``#``.

    The mnemonic is lower-cased and kept verbatim (it is the instruction's
    identity); only the operand text is masked, so ``mov eax, 0x2a`` and
    ``mov eax, 0x63`` both normalize to ``"mov eax, #"``. Whitespace inside the
    operands is collapsed, which makes the result independent of the
    disassembler's spacing.

    Args:
        instruction: Decoded instruction to normalize.

    Returns:
        ``"<mnemonic> <masked operands>"``, or just the mnemonic when the
        instruction takes no operands.
    """
    mnemonic = (instruction.mnemonic or "").strip().lower()
    masked = _HEX_LITERAL.sub("#", instruction.operands or "")
    masked = _BARE_NUMBER.sub("#", masked)
    masked = _REPEATED_MASK.sub("#", masked)
    masked = " ".join(masked.split())
    return f"{mnemonic} {masked}".strip()


def function_fingerprint(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
) -> FunctionFingerprint:
    """Fingerprint the normalized instruction stream that starts at ``address``.

    The sweep is a plain linear disassembly of the executable section's file
    bytes starting at ``address``: it does not follow branches, so bytes that
    belong to a neighbouring function are included when ``address`` is not a
    real function entry, and a function longer than the budget is fingerprinted
    from its prefix only (``truncated`` is then ``True``).

    Args:
        path: File the bytes are read from (read-only; never executed).
        info: Loaded metadata used for address mapping and for choosing the
            decoder.
        address: Virtual address of the first instruction; must be inside an
            executable section.
        max_instructions: Instruction budget
            (``MIN_MAX_INSTRUCTIONS`` .. ``MAX_MAX_INSTRUCTIONS``).

    Returns:
        The :class:`FunctionFingerprint` for the region.

    Raises:
        AnalysisError: When ``address`` or ``max_instructions`` is invalid, when
            ``address`` is not inside an executable section, when the address
            has no file bytes, when the architecture cannot be disassembled, or
            when no instruction could be decoded.

    Note:
        An empty stream is an error rather than an empty digest: every
        undecodable region would otherwise share one digest and appear to
        "match" every other such region.
    """
    if isinstance(address, bool) or not isinstance(address, int):
        raise AnalysisError(f"address must be an integer, got {address!r}")
    if address < 0:
        raise AnalysisError(f"address must be non-negative, got {address}")
    if isinstance(max_instructions, bool) or not isinstance(max_instructions, int):
        raise AnalysisError(f"max_instructions must be an integer, got {max_instructions!r}")
    if max_instructions < MIN_MAX_INSTRUCTIONS:
        raise AnalysisError("max_instructions must be >= 1")
    if max_instructions > MAX_MAX_INSTRUCTIONS:
        raise AnalysisError(f"max_instructions too large (limit {MAX_MAX_INSTRUCTIONS})")

    section = info.section_for_va(address)
    if section is None or not section.is_executable:
        raise AnalysisError(f"address 0x{address:x} is not inside an executable section")

    code = read_code(path, info, address, max_instructions * _MAX_INSTRUCTION_BYTES)
    try:
        disassembler = Disassembler(info.architecture, info.bitness, info.endianness)
        result = disassembler.disassemble(
            code,
            base_address=address,
            max_instructions=max_instructions,
        )
    except DisassemblyError as exc:
        raise AnalysisError(f"cannot disassemble 0x{address:x}: {exc}") from exc

    instructions = list(result.instructions)
    if not instructions:
        raise AnalysisError(f"no instruction decoded at 0x{address:x}")

    stream = "\n".join(normalize_instruction(instruction) for instruction in instructions)
    digest = hashlib.sha256(stream.encode("utf-8")).hexdigest()
    truncated = (
        bool(result.truncated)
        or len(instructions) >= max_instructions
        or result.consumed_bytes < len(code)
    )

    evidence = Evidence(
        source=_EVIDENCE_SOURCE,
        method=_EVIDENCE_METHOD,
        confidence=Confidence.MEDIUM,
        address=address,
        detail=(
            f"sha256 over {len(instructions)} normalized instruction(s)"
            + (" from a truncated sweep (prefix only)" if truncated else "")
            + f"; {_CAVEAT}"
        ),
        extra={
            "algorithm": DIGEST_ALGORITHM,
            "max_instructions": max_instructions,
            "instruction_count": len(instructions),
            "consumed_bytes": result.consumed_bytes,
            "truncated": truncated,
        },
    )
    return FunctionFingerprint(
        address=address,
        digest=digest,
        instruction_count=len(instructions),
        truncated=truncated,
        evidence=evidence,
    )


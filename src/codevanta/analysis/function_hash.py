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

:func:`normalized_tokens` exposes the token stream those steps build, and
:func:`function_similarity` compares two regions as **multisets** of normalized
instructions (``collections.Counter``): the score is
``sum(min(counts)) / sum(max(counts))``, i.e. the Jaccard overlap of the two
token multisets, where ``1.0`` means both sides share every token with the same
multiplicity and ``0.0`` means they share none. The score is therefore a
*shape* measure exactly like the digest -- see
:data:`~codevanta.analysis.function_hash.SimilarityResult` -- and never a
semantic comparison.

Nothing is mapped or executed: bytes are read with
:func:`~codevanta.core.report.read_code`, which only ever reads the file, and
the target architecture is decoded by
:class:`~codevanta.core.disassembler.Disassembler`.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
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
    "SimilarityResult",
    "function_fingerprint",
    "function_similarity",
    "normalize_instruction",
    "normalized_tokens",
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

_EVIDENCE_SIMILARITY_SOURCE = "function_hash.similarity"
_EVIDENCE_SIMILARITY_METHOD = "token_multiset"
_SIMILARITY_CAVEAT = (
    "shape-not-semantics comparison: the score is the multiset overlap of normalized "
    "instructions with numeric literals masked to '#', so a high score is structural "
    "resemblance and not proven semantic equivalence, and a low score is not proof of "
    "different behaviour; sweeps are bounded prefixes and nothing was executed"
)

#: Decimals kept when a similarity score is serialized.
_SCORE_DECIMALS = 4


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


@dataclass(frozen=True)
class SimilarityResult:
    """Shape similarity between the instruction streams of two regions.

    The comparison is a **multiset** comparison of the normalized instruction
    tokens of both regions, so both the identities and the multiplicities of the
    instructions matter::

        shared = sum((left_counts & right_counts).values())   # sum(min)
        union  = sum((left_counts | right_counts).values())   # sum(max)
        score  = shared / union

    ``score`` is therefore ``1.0`` for two regions that agree token for token and
    ``0.0`` for two regions that share no token at all. It is a *shape* measure:
    immediates, frame offsets and branch targets are masked away before the
    comparison, so equal scores are not byte equality and different scores are
    not a semantic difference.

    Attributes:
        score: ``sum(min) / sum(max)`` of the two token multisets, in ``[0, 1]``.
        shared: Number of token occurrences both sides share (``sum(min)``).
        left_total: Number of token occurrences in the left region.
        right_total: Number of token occurrences in the right region.
        evidence: How the score was produced, including the shape caveat and the
            applied bounds. Its ``address`` is the *left* region's start.
        warnings: Human-readable notes about the measurement -- for example that
            one side was truncated to the instruction budget, so the score
            compares prefixes. Empty when neither side was cut short.
    """

    score: float
    shared: int
    left_total: int
    right_total: int
    evidence: Evidence
    warnings: tuple[str, ...] = ()

    @property
    def union(self) -> int:
        """Number of token occurrences in the union (``sum(max)``)."""
        return self.left_total + self.right_total - self.shared

    def to_dict(self) -> dict[str, Any]:
        """Serialize the similarity for the JSON report (``score`` to 4 decimals)."""
        return {
            "score": round(self.score, _SCORE_DECIMALS),
            "shared": self.shared,
            "left_total": self.left_total,
            "right_total": self.right_total,
            "union": self.union,
            "warnings": list(self.warnings),
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


@dataclass(frozen=True)
class _Sweep:
    """Outcome of one bounded linear sweep (internal to this module).

    Attributes:
        address: Requested start address of the sweep.
        tokens: Normalized instruction tokens in decoding order.
        consumed_bytes: Bytes the decoder consumed.
        buffer_bytes: Bytes read from the file for the sweep.
        truncated: ``True`` when the sweep stopped before the end of the
            available bytes -- the instruction budget was reached, the section's
            file-backed bytes ran out, or trailing bytes could not be decoded.
        max_instructions: Instruction budget that was applied.
    """

    address: int
    tokens: tuple[str, ...]
    consumed_bytes: int
    buffer_bytes: int
    truncated: bool
    max_instructions: int


def _validate_bounds(address: int, max_instructions: int) -> None:
    """Reject an invalid address or instruction budget.

    Raises:
        AnalysisError: When ``address`` is not a non-negative integer or
            ``max_instructions`` is outside
            ``MIN_MAX_INSTRUCTIONS`` .. ``MAX_MAX_INSTRUCTIONS``.
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


def _sweep(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    max_instructions: int,
) -> _Sweep:
    """Disassemble and normalize one bounded linear sweep at ``address``.

    This is the only place a region is decoded, so :func:`normalized_tokens`,
    :func:`function_fingerprint` and :func:`function_similarity` can never
    disagree about which instructions a region contains or about the bounds that
    were applied. At most ``max_instructions * 16`` file bytes are read and the
    bytes are never mapped or executed.

    Args:
        path: File the bytes are read from (read-only).
        info: Loaded metadata used for address mapping and for choosing the
            decoder.
        address: Virtual address of the first instruction; must be inside an
            executable section.
        max_instructions: Instruction budget
            (``MIN_MAX_INSTRUCTIONS`` .. ``MAX_MAX_INSTRUCTIONS``).

    Returns:
        The normalized tokens of the region together with the applied bounds.

    Raises:
        AnalysisError: When ``address`` or ``max_instructions`` is invalid, when
            ``address`` is not inside an executable section, when the address has
            no file bytes, when the architecture cannot be disassembled, or when
            no instruction could be decoded.
    """
    _validate_bounds(address, max_instructions)

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

    instructions = tuple(result.instructions)
    if not instructions:
        raise AnalysisError(f"no instruction decoded at 0x{address:x}")

    tokens = tuple(normalize_instruction(instruction) for instruction in instructions)
    truncated = (
        bool(result.truncated)
        or len(tokens) >= max_instructions
        or result.consumed_bytes < len(code)
    )
    return _Sweep(
        address=address,
        tokens=tokens,
        consumed_bytes=result.consumed_bytes,
        buffer_bytes=len(code),
        truncated=truncated,
        max_instructions=max_instructions,
    )


def normalized_tokens(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
) -> tuple[str, ...]:
    """Return the normalized instruction tokens of the region at ``address``.

    The tokens are exactly the strings :func:`function_fingerprint` hashes, so
    ``sha256("\\n".join(normalized_tokens(...)))`` reproduces the digest. They are
    reusable on their own for multiset comparisons (see
    :func:`function_similarity`) or for reporting which instructions two
    regions have in common.

    Args:
        path: File the bytes are read from (read-only; never executed).
        info: Loaded metadata used for address mapping and for choosing the
            decoder.
        address: Virtual address of the first instruction; must be inside an
            executable section.
        max_instructions: Instruction budget
            (``MIN_MAX_INSTRUCTIONS`` .. ``MAX_MAX_INSTRUCTIONS``).

    Returns:
        The tokens in decoding order -- never empty, because a region without a
        decodable instruction raises instead of returning ``()``.

    Raises:
        AnalysisError: When ``address`` or ``max_instructions`` is invalid, when
            ``address`` is not inside an executable section, when the address has
            no file bytes, when the architecture cannot be disassembled, or when
            no instruction could be decoded.
    """
    return _sweep(path, info, address, max_instructions).tokens


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
    sweep = _sweep(path, info, address, max_instructions)
    digest = hashlib.sha256("\n".join(sweep.tokens).encode("utf-8")).hexdigest()
    truncated = sweep.truncated

    evidence = Evidence(
        source=_EVIDENCE_SOURCE,
        method=_EVIDENCE_METHOD,
        confidence=Confidence.MEDIUM,
        address=address,
        detail=(
            f"sha256 over {len(sweep.tokens)} normalized instruction(s)"
            + (" from a truncated sweep (prefix only)" if truncated else "")
            + f"; {_CAVEAT}"
        ),
        extra={
            "algorithm": DIGEST_ALGORITHM,
            "max_instructions": max_instructions,
            "instruction_count": len(sweep.tokens),
            "consumed_bytes": sweep.consumed_bytes,
            "truncated": truncated,
        },
    )
    return FunctionFingerprint(
        address=address,
        digest=digest,
        instruction_count=len(sweep.tokens),
        truncated=truncated,
        evidence=evidence,
    )


def function_similarity(
    path_a: str | Path,
    info_a: BinaryInfo,
    address_a: int,
    path_b: str | Path,
    info_b: BinaryInfo,
    address_b: int,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
) -> SimilarityResult:
    """Compare two function regions as multisets of normalized instructions.

    Both regions are swept with the same bounded linear sweep as
    :func:`normalized_tokens` and their tokens are counted with
    :class:`collections.Counter`::

        shared = sum((left & right).values())   # sum(min), shared occurrences
        union  = sum((left | right).values())   # sum(max), union size
        score  = shared / union

    Multiplicity matters, so ``nop; nop; ret`` is only half similar to
    ``nop; ret``. Immediates, frame offsets and branch targets are masked before
    counting, so a recompiled or relocated copy of a function usually scores
    ``1.0``. The score describes *shape*, not semantics -- see
    :class:`SimilarityResult`.

    Args:
        path_a: File of the left region (read-only; never executed).
        info_a: Loaded metadata of ``path_a``.
        address_a: Start address of the left region.
        path_b: File of the right region (read-only; never executed).
        info_b: Loaded metadata of ``path_b``.
        address_b: Start address of the right region.
        max_instructions: Per-side instruction budget
            (``MIN_MAX_INSTRUCTIONS`` .. ``MAX_MAX_INSTRUCTIONS``).

    Returns:
        The :class:`SimilarityResult`; ``1.0`` when both token multisets are
        identical and ``0.0`` when they share no token.

    Raises:
        AnalysisError: When either side cannot be swept (invalid address or
            budget, address outside an executable section, no file bytes,
            undecodable architecture), or when either side yields no tokens.

    Note:
        Every side is bound by ``max_instructions``, so a full comparison
        decodes at most ``2 * max_instructions`` instructions and reads at most
        ``2 * max_instructions * 16`` bytes. When a side was truncated, the
        result carries a warning and the score compares prefixes only.
    """
    left = _sweep(path_a, info_a, address_a, max_instructions)
    right = _sweep(path_b, info_b, address_b, max_instructions)
    if not left.tokens or not right.tokens:
        # Defensive: _sweep already refuses an empty region, but a score against
        # an empty multiset would be a meaningless 0.0 rather than an error.
        side = "left" if not left.tokens else "right"
        raise AnalysisError(f"{side} region produced no instruction tokens to compare")

    left_counts = Counter(left.tokens)
    right_counts = Counter(right.tokens)
    shared = sum((left_counts & right_counts).values())
    union = sum((left_counts | right_counts).values())
    score = shared / union if union else 0.0

    warnings: list[str] = []
    if left.truncated:
        warnings.append(
            f"left region 0x{address_a:x} was truncated to {len(left.tokens)} "
            "instruction(s); the score compares prefixes"
        )
    if right.truncated:
        warnings.append(
            f"right region 0x{address_b:x} was truncated to {len(right.tokens)} "
            "instruction(s); the score compares prefixes"
        )

    evidence = Evidence(
        source=_EVIDENCE_SIMILARITY_SOURCE,
        method=_EVIDENCE_SIMILARITY_METHOD,
        confidence=Confidence.MEDIUM,
        address=address_a,
        detail=(
            f"{shared} shared of {union} token occurrence(s) in the union "
            f"(left {len(left.tokens)}, right {len(right.tokens)}): "
            f"score {score:.{_SCORE_DECIMALS}f}; {_SIMILARITY_CAVEAT}"
        ),
        extra={
            "left_address": f"0x{address_a:x}",
            "right_address": f"0x{address_b:x}",
            "shared": shared,
            "left_total": len(left.tokens),
            "right_total": len(right.tokens),
            "union": union,
            "max_instructions": max_instructions,
            "left_truncated": left.truncated,
            "right_truncated": right.truncated,
        },
    )
    return SimilarityResult(
        score=score,
        shared=shared,
        left_total=len(left.tokens),
        right_total=len(right.tokens),
        evidence=evidence,
        warnings=tuple(warnings),
    )

"""Cross-reference extraction from direct branches in executable sections.

The scan is deliberately conservative: a cross reference is only emitted when
the *entire* operand text of a transfer instruction is a hexadecimal literal
(``^0x[0-9a-fA-F]+$``). Register-indirect (``call rax``) and memory-indirect
(``jmp qword ptr [rax]``) transfers are therefore ignored rather than guessed,
because their target is not statically known at this layer.

Every step is bounded (``max_bytes``) and the analysed file is only ever read
from disk; nothing is loaded or executed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.core.disassembler import Disassembler, DisassemblyError
from codevanta.core.functions import FunctionCandidate, discover_functions
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError, read_code
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = ["DEFAULT_MAX_BYTES", "Xref", "XrefResult", "find_xrefs"]

#: Default ceiling on how many executable bytes a single scan will decode.
DEFAULT_MAX_BYTES = 4_000_000

#: Operand text that denotes an absolute, statically known target.
_DIRECT_OPERAND = re.compile(r"^0x[0-9a-fA-F]+$")

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

#: Maps a cross-reference kind to the evidence source that justifies it.
_SOURCE_BY_KIND: dict[str, str] = {
    "call": "capstone.direct_call",
    "jump": "capstone.direct_jump",
    "branch": "capstone.conditional_branch",
}

_EVIDENCE_METHOD = "linear_disassembly"
_RESULT_EVIDENCE_SOURCE = "capstone.xref_scan"


@dataclass(frozen=True)
class Xref:
    """A single directed reference from one instruction to another address.

    Attributes:
        from_address: Virtual address of the referring instruction.
        to_address: Virtual address the instruction transfers control to.
        kind: ``"call"``, ``"jump"`` or ``"branch"``.
        instruction: Disassembled instruction text, e.g. ``"call 0x401010"``.
        source: Evidence source label for this specific reference.
        evidence: Full evidence record for the reference.
        function: Name of the function candidate located at ``to_address``.
    """

    from_address: int
    to_address: int
    kind: str
    instruction: str
    source: str
    evidence: Evidence
    function: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "from_address": f"0x{self.from_address:x}",
            "to_address": f"0x{self.to_address:x}",
            "kind": self.kind,
            "instruction": self.instruction,
            "source": self.source,
            "evidence": self.evidence.to_dict(),
        }
        if self.function:
            data["function"] = self.function
        return data


@dataclass(frozen=True)
class XrefResult:
    """Outcome of one cross-reference scan.

    Attributes:
        xrefs: References sorted by ``from_address``.
        scanned_sections: Names of the sections that were successfully decoded.
        scanned_bytes: Number of bytes actually decoded into instructions.
        truncated: ``True`` when ``max_bytes`` or a decoder limit cut the scan.
        evidence: Evidence describing the scan as a whole.
        warnings: Non-fatal problems encountered while scanning.
    """

    xrefs: list[Xref]
    scanned_sections: list[str]
    scanned_bytes: int
    truncated: bool
    evidence: Evidence
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "xref_count": len(self.xrefs),
            "xrefs": [xref.to_dict() for xref in self.xrefs],
            "scanned_sections": list(self.scanned_sections),
            "scanned_bytes": self.scanned_bytes,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _kind_for(mnemonic: str) -> str | None:
    """Return the cross-reference kind for ``mnemonic`` if it is a transfer."""
    return _KIND_BY_MNEMONIC.get(mnemonic.strip().lower())


def _direct_target(operands: str) -> int | None:
    """Parse an absolute target from ``operands``; ignore registers/memory."""
    text = operands.strip()
    if not _DIRECT_OPERAND.match(text):
        return None
    try:
        return int(text, 16)
    except ValueError:  # pragma: no cover - the regex guarantees hex digits
        return None


def _scan_evidence(xref_count: int) -> Evidence:
    """Build the evidence record for the scan as a whole.

    The confidence is ``CERTAIN`` because every emitted reference is a direct
    read of the decoded operand stream; incomplete coverage is reported through
    ``XrefResult.warnings`` and ``XrefResult.truncated`` instead.
    """
    return Evidence(
        source=_RESULT_EVIDENCE_SOURCE,
        method=_EVIDENCE_METHOD,
        confidence=Confidence.CERTAIN,
        detail=f"{xref_count} xrefs",
    )


def find_xrefs(
    path: str | Path,
    info: BinaryInfo,
    functions: list[FunctionCandidate] | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> XrefResult:
    """Collect direct-branch cross references from executable sections.

    Args:
        path: File the metadata in ``info`` was loaded from.
        info: Normalized binary metadata.
        functions: Pre-computed candidates used to name targets;
            :func:`~codevanta.core.functions.discover_functions` runs when omitted.
        max_bytes: Hard ceiling on executable bytes read and decoded.

    Returns:
        An :class:`XrefResult` with references sorted by ``from_address``.

    Raises:
        AnalysisError: If ``max_bytes`` is not positive.
    """
    if max_bytes < 1:
        raise AnalysisError("max_bytes must be >= 1")

    candidates = list(functions) if functions is not None else discover_functions(info)
    names_by_address: dict[int, str] = {
        candidate.address: candidate.name for candidate in candidates if candidate.name
    }

    warnings: list[str] = []
    executable_sections = [
        section
        for section in info.sections
        if section.is_executable and (section.raw_size or section.size) > 0
    ]
    if not executable_sections:
        warnings.append("no executable sections with file bytes were found")
        return XrefResult(
            xrefs=[],
            scanned_sections=[],
            scanned_bytes=0,
            truncated=False,
            evidence=_scan_evidence(0),
            warnings=tuple(warnings),
        )

    try:
        disassembler = Disassembler(info.architecture, info.bitness, info.endianness)
    except DisassemblyError as exc:
        warnings.append(f"disassembly unavailable: {exc}")
        return XrefResult(
            xrefs=[],
            scanned_sections=[],
            scanned_bytes=0,
            truncated=False,
            evidence=_scan_evidence(0),
            warnings=tuple(warnings),
        )

    total_bytes = sum(section.raw_size or section.size for section in executable_sections)
    remaining = max_bytes
    truncated = total_bytes > max_bytes
    scanned_sections: list[str] = []
    scanned_bytes = 0
    xrefs: list[Xref] = []

    for section in executable_sections:
        span = section.raw_size or section.size
        if remaining <= 0:
            truncated = True
            break
        budget = min(remaining, span)
        if budget < span:
            truncated = True
        try:
            data = read_code(path, info, section.virtual_address, budget)
        except (AnalysisError, OSError) as exc:
            warnings.append(f"section {section.name!r}: cannot read bytes ({exc})")
            continue
        if not data:
            warnings.append(f"section {section.name!r}: no file bytes available")
            continue
        remaining -= len(data)
        try:
            disassembly = disassembler.disassemble(data, base_address=section.virtual_address)
        except DisassemblyError as exc:
            warnings.append(f"section {section.name!r}: disassembly failed ({exc})")
            continue

        scanned_sections.append(section.name)
        scanned_bytes += disassembly.consumed_bytes
        truncated = truncated or disassembly.truncated

        for instruction in disassembly.instructions:
            kind = _kind_for(instruction.mnemonic)
            if kind is None:
                continue
            to_address = _direct_target(instruction.operands)
            if to_address is None:
                continue
            text = instruction.text
            source = _SOURCE_BY_KIND[kind]
            xrefs.append(
                Xref(
                    from_address=instruction.address,
                    to_address=to_address,
                    kind=kind,
                    instruction=text,
                    source=source,
                    evidence=Evidence(
                        source=source,
                        method=_EVIDENCE_METHOD,
                        confidence=Confidence.CERTAIN,
                        address=instruction.address,
                        detail=text,
                    ),
                    function=names_by_address.get(to_address),
                )
            )

    xrefs.sort(key=lambda xref: (xref.from_address, xref.to_address))
    return XrefResult(
        xrefs=xrefs,
        scanned_sections=scanned_sections,
        scanned_bytes=scanned_bytes,
        truncated=truncated,
        evidence=_scan_evidence(len(xrefs)),
        warnings=tuple(warnings),
    )


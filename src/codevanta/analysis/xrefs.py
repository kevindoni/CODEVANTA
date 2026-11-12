"""Cross-reference extraction from direct and memory-indirect transfers.

The scan stays conservative. Two operand shapes are resolved:

1. A direct literal target (``^0x[0-9a-fA-F]+$``) for ``call``/``jmp``/
   conditional jumps.
2. A ``call`` through an absolute or RIP-relative pointer slot, i.e.
   ``(byte|word|dword|qword) ptr [0x...]`` or
   ``(byte|word|dword|qword) ptr [rip +/- 0x...]``. The reported
   ``to_address`` is the address of that slot, not of the callee: the pointer
   is read from memory at run time, so the callee itself is unknown here. When
   the slot address matches an ``info.imports`` entry the reference is tagged
   ``call_import`` and named after the import; otherwise it is ``call_indirect``.

Everything else (``call rax``, ``call qword ptr [rax + 8]``, and any indirect
``jmp``/conditional jump) is skipped rather than guessed. Skipped indirect
*calls* are counted in :attr:`XrefResult.indirect_skipped` so callers can see
how much of the call graph was left unresolved.

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
from codevanta.ir.instruction import IRInstruction

__all__ = ["DEFAULT_MAX_BYTES", "Xref", "XrefResult", "find_xrefs"]

#: Default ceiling on how many executable bytes a single scan will decode.
DEFAULT_MAX_BYTES = 4_000_000

#: Operand text that denotes an absolute, statically known target.
_DIRECT_OPERAND = re.compile(r"^0x[0-9a-fA-F]+$")

#: Operand text of a pointer slot: absolute or RIP-relative, sized explicitly.
#:
#: Examples matched: ``qword ptr [0x401000]``, ``qword ptr [rip + 0xa]``,
#: ``dword ptr [rip - 0xa]``. Anything with a register base or index
#: (``qword ptr [rax]``, ``qword ptr [rax + rcx*8]``) deliberately misses,
#: because the slot address is not statically known.
_MEMORY_POINTER = re.compile(
    r"^(?:byte|word|dword|qword)\s+ptr\s*\[\s*"
    r"(?:(?P<absolute>0x[0-9a-fA-F]+)|rip\s*(?P<sign>[+-])\s*(?P<displacement>0x[0-9a-fA-F]+))"
    r"\s*\]$",
    re.IGNORECASE,
)

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
    "call_import": "capstone.import_call",
    "call_indirect": "capstone.indirect_call",
}

_EVIDENCE_METHOD = "linear_disassembly"
_RESULT_EVIDENCE_SOURCE = "capstone.xref_scan"


@dataclass(frozen=True)
class Xref:
    """A single directed reference from one instruction to another address.

    Attributes:
        from_address: Virtual address of the referring instruction.
        to_address: Virtual address the instruction transfers control to. For
            ``call_import``/``call_indirect`` this is the *pointer slot*, since
            the callee is only known at run time.
        kind: ``"call"``, ``"jump"``, ``"branch"``, ``"call_import"`` or
            ``"call_indirect"``.
        instruction: Disassembled instruction text, e.g. ``"call 0x401010"``.
        source: Evidence source label for this specific reference.
        evidence: Full evidence record for the reference.
        function: Name of the function candidate located at ``to_address``.
        target_name: Import name when the call goes through a known import slot,
            otherwise ``None``.
    """

    from_address: int
    to_address: int
    kind: str
    instruction: str
    source: str
    evidence: Evidence
    function: str | None = None
    target_name: str | None = None

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
        if self.target_name:
            data["target_name"] = self.target_name
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
        indirect_skipped: Number of indirect ``call`` instructions whose target
            could not be resolved statically (register operands, indexed memory
            operands, ...). Such calls emit no :class:`Xref`.
    """

    xrefs: list[Xref]
    scanned_sections: list[str]
    scanned_bytes: int
    truncated: bool
    evidence: Evidence
    warnings: tuple[str, ...] = ()
    indirect_skipped: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "xref_count": len(self.xrefs),
            "xrefs": [xref.to_dict() for xref in self.xrefs],
            "scanned_sections": list(self.scanned_sections),
            "scanned_bytes": self.scanned_bytes,
            "truncated": self.truncated,
            "indirect_skipped": self.indirect_skipped,
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


def _memory_pointer_target(operands: str, address: int, size: int) -> int | None:
    """Resolve the pointer-slot address of an indirect memory operand.

    Args:
        operands: Capstone operand text, e.g. ``"qword ptr [rip + 0xa]"``.
        address: Virtual address of the instruction itself.
        size: Length of the instruction in bytes, used as the RIP bias.

    Returns:
        The absolute address of the pointer slot, or ``None`` when the operand
        is not an absolute/RIP-relative sized memory pointer. Note that the
        value stored in the slot (the real callee) is unknown here.
    """
    match = _MEMORY_POINTER.match(operands.strip())
    if match is None:
        return None
    absolute = match.group("absolute")
    try:
        if absolute is not None:
            return int(absolute, 16)
        displacement = int(match.group("displacement"), 16)
    except ValueError:  # pragma: no cover - the regex guarantees hex digits
        return None
    # RIP-relative operands are encoded relative to the next instruction.
    base = address + size
    return base + displacement if match.group("sign") == "+" else base - displacement


def _build_xref(
    instruction: IRInstruction,
    to_address: int,
    kind: str,
    names_by_address: dict[int, str],
    target_name: str | None = None,
    confidence: Confidence = Confidence.CERTAIN,
) -> Xref:
    """Assemble one :class:`Xref` together with its evidence record."""
    text = instruction.text
    source = _SOURCE_BY_KIND[kind]
    return Xref(
        from_address=instruction.address,
        to_address=to_address,
        kind=kind,
        instruction=text,
        source=source,
        evidence=Evidence(
            source=source,
            method=_EVIDENCE_METHOD,
            confidence=confidence,
            address=instruction.address,
            detail=text,
        ),
        function=names_by_address.get(to_address),
        target_name=target_name,
    )


def _scan_evidence(xref_count: int) -> Evidence:
    """Build the evidence record for the scan as a whole.

    The confidence is ``CERTAIN`` because every emitted reference is a read of
    the decoded operand stream; individual indirect references may lower their
    own confidence. Incomplete coverage is reported through
    ``XrefResult.warnings``, ``XrefResult.truncated`` and
    ``XrefResult.indirect_skipped`` instead.
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
    """Collect cross references from executable sections.

    Direct transfers (``call``/``jmp``/conditional jumps to a literal address)
    and ``call`` instructions through an absolute or RIP-relative pointer slot
    are recorded. Indirect calls that cannot be resolved statically are skipped
    and counted in :attr:`XrefResult.indirect_skipped`.

    Args:
        path: File the metadata in ``info`` was loaded from.
        info: Normalized binary metadata. Its ``imports`` list is used to name
            indirect calls whose pointer slot matches an import address.
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
    # Built once: absolute pointer-slot address -> import name.
    import_names_by_address: dict[int, str] = {
        imported.address: imported.name
        for imported in info.imports
        if imported.address is not None and imported.name
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
    indirect_skipped = 0
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
            if to_address is not None:
                xrefs.append(_build_xref(instruction, to_address, kind, names_by_address))
                continue
            # From here on only indirect calls are interesting; indirect jumps
            # and conditional branches stay unresolved without being counted.
            if kind != "call":
                continue
            slot_address = _memory_pointer_target(
                instruction.operands, instruction.address, instruction.size
            )
            if slot_address is None:
                indirect_skipped += 1
                continue
            import_name = import_names_by_address.get(slot_address)
            if import_name is not None:
                xrefs.append(
                    _build_xref(
                        instruction,
                        slot_address,
                        "call_import",
                        names_by_address,
                        target_name=import_name,
                    )
                )
            else:
                # The slot address is certain, the callee it holds is not.
                xrefs.append(
                    _build_xref(
                        instruction,
                        slot_address,
                        "call_indirect",
                        names_by_address,
                        confidence=Confidence.HIGH,
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
        indirect_skipped=indirect_skipped,
    )


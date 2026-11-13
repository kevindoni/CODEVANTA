"""Vtable discovery and thunk-chain resolution (indirect xref heuristics).

A C++ virtual table is a run of pointer-sized slots in a non-executable data
section where every slot holds the address of a function. Neither fact alone
proves a vtable, so the discovery here is an explicitly **medium**-confidence
heuristic (source ``vtable.candidate`` / ``vtable.slot_ref``), never merged
into the certain xref stream: a data run of code pointers is also what a
hand-built callback array looks like.

Thunk resolution rides on top. Many slot targets are one-instruction
tail-call stubs (``jmp``/``b <target>``) that forward to the real override.
Following the chain recovers the final callee; every hop is a direct operand
read, but the *judgment* that a one-instruction function is a thunk is
heuristic, so the resolved target is reported separately (``resolved_target``
plus ``vtable.thunk_chain`` evidence at medium confidence) instead of
rewriting the slot target.

The analysed file is only ever read from disk; nothing is executed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from codevanta.core.disassembler import Disassembler, DisassemblyError
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError, read_code
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_SLOTS",
    "DEFAULT_MAX_TABLES",
    "DEFAULT_MIN_SLOTS",
    "MAX_SLOTS_LIMIT",
    "VtableCandidate",
    "VtableScanResult",
    "VtableSlot",
    "find_vtables",
    "resolve_thunk",
]

#: Fewest consecutive code pointers for a run to count as a vtable candidate.
DEFAULT_MIN_SLOTS = 3

#: Default cap on slots decoded per candidate table.
DEFAULT_MAX_SLOTS = 256

#: Hard ceiling accepted for ``max_slots`` (bounded-resource rule).
MAX_SLOTS_LIMIT = 4_096

#: Default cap on candidate tables in scan mode.
DEFAULT_MAX_TABLES = 64

#: Default cap on bytes read per scanned section.
DEFAULT_MAX_SCAN_BYTES = 1_000_000

#: Hard ceiling accepted for ``max_scan_bytes`` per section.
MAX_SCAN_BYTES_LIMIT = 16_000_000

#: One-instruction mnemonics that mean "tail-call forwarding" to this layer.
_THUNK_MNEMONICS = frozenset({"jmp", "b"})

_SOURCE = "vtable.candidate"
_SLOT_SOURCE = "vtable.slot_ref"
_THUNK_SOURCE = "vtable.thunk_chain"


@dataclass(frozen=True)
class VtableSlot:
    """One decoded slot: a data word that points into executable code."""

    index: int
    slot_address: int
    target: int
    resolved_target: int | None
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "index": self.index,
            "slot_address": f"0x{self.slot_address:x}",
            "target": f"0x{self.target:x}",
            "evidence": self.evidence.to_dict(),
        }
        if self.resolved_target is not None:
            data["resolved_target"] = f"0x{self.resolved_target:x}"
        return data


@dataclass(frozen=True)
class VtableCandidate:
    """One discovered run of consecutive code pointers.

    ``header_slots`` records how many leading non-code slots (the Itanium
    layout's offset-to-top and RTTI pointer) were skipped before the run.
    """

    address: int
    slots: list[VtableSlot]
    slot_size: int
    section_name: str
    header_slots: int
    truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": f"0x{self.address:x}",
            "slot_count": len(self.slots),
            "slot_size": self.slot_size,
            "section": self.section_name,
            "header_slots": self.header_slots,
            "truncated": self.truncated,
            "slots": [slot.to_dict() for slot in self.slots],
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class VtableScanResult:
    """Outcome of one discovery run (address mode or whole-binary scan)."""

    tables: list[VtableCandidate]
    scanned_sections: list[str]
    scanned_bytes: int
    truncated: bool
    evidence: Evidence
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "table_count": len(self.tables),
            "tables": [table.to_dict() for table in self.tables],
            "scanned_sections": list(self.scanned_sections),
            "scanned_bytes": self.scanned_bytes,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _byteorder(info: BinaryInfo) -> Literal["little", "big"]:
    text = str(getattr(info, "endianness", "") or "").strip().lower()
    return "big" if text.startswith(("big", "msb", "be")) else "little"


def _relocation_overlay(path: str | Path) -> dict[int, int]:
    """Map slot VA -> value for position-independent pointer fills.

    PIE/shared objects keep pointer slots zero in the file and fill them at
    load time through dynamic relocations whose ``addend`` is the target VA.
    LIEF's relocation table gives that mapping directly, so static analysis
    can see the pointers a loader would create. Only symbol-less relocations
    with a non-zero addend are used (``R_*_RELATIVE`` semantics across
    architectures); anything else is not a pointer fill and stays untouched.
    """
    try:
        import lief

        binary = lief.parse(str(path))
    except Exception:
        return {}
    if binary is None:
        return {}
    overlay: dict[int, int] = {}
    for relocation in getattr(binary, "relocations", []) or []:
        symbol = getattr(relocation, "symbol", None)
        if symbol is not None and getattr(symbol, "name", None):
            continue
        addend = int(getattr(relocation, "addend", 0) or 0)
        if addend <= 0:
            continue
        slot_address = int(getattr(relocation, "address", 0) or 0)
        if slot_address > 0:
            overlay[slot_address] = addend
    return overlay


def _pointer_size(info: BinaryInfo) -> int:
    return 8 if info.bitness >= 64 else 4


def _target_in_executable(info: BinaryInfo, target: int) -> bool:
    section = info.section_for_va(target)
    return section is not None and section.is_executable


def _new_disassembler(info: BinaryInfo) -> Disassembler | None:
    try:
        return Disassembler(info.architecture, info.bitness, info.endianness)
    except DisassemblyError:
        return None


def _read_slots(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    *,
    pointer_size: int,
    byteorder: Literal["little", "big"],
    min_slots: int,
    max_slots: int,
    resolve_thunks: bool,
    max_thunk_depth: int,
    disassembler: Disassembler | None,
    section_name: str,
    overlay: dict[int, int] | None = None,
    skip_header: bool = False,
) -> tuple[list[VtableSlot], int] | None:
    """Read consecutive code-pointer slots from ``address``.

    With ``skip_header`` (address mode), up to two leading non-code slots —
    the Itanium layout's offset-to-top and RTTI pointer — are skipped before
    the run must start. ``overlay`` supplies relocation-filled pointer values
    for PIE files whose slots are zero on disk. Returns ``None`` when fewer
    than ``min_slots`` valid slots were found, else the decoded slots and the
    number of skipped header slots.
    """
    slots: list[VtableSlot] = []
    cursor = address
    header_slots = 0
    while len(slots) < max_slots:
        try:
            raw = read_code(path, info, cursor, pointer_size)
        except (AnalysisError, OSError):
            break
        if len(raw) < pointer_size:
            break
        value = int.from_bytes(raw, byteorder)
        relocated = bool(overlay and cursor in overlay)
        if relocated:
            value = int(overlay[cursor])  # type: ignore[index]
        is_code = value != 0 and _target_in_executable(info, value)
        if not is_code and skip_header and not slots and header_slots < 2:
            header_slots += 1
            cursor += pointer_size
            continue
        if not is_code:
            break
        resolved: int | None = None
        if resolve_thunks and disassembler is not None:
            resolved = resolve_thunk(
                path,
                info,
                value,
                disassembler=disassembler,
                max_depth=max_thunk_depth,
            )
            if resolved == value:
                resolved = None  # no forwarding hop: not a thunk
        slots.append(
            VtableSlot(
                index=len(slots),
                slot_address=cursor,
                target=value,
                resolved_target=resolved,
                evidence=Evidence(
                    source=_SLOT_SOURCE,
                    method="pointer_array_run",
                    confidence=Confidence.MEDIUM,
                    address=cursor,
                    detail=(
                        f"slot {len(slots)} points at code 0x{value:x}"
                        + (" via dynamic relocation" if relocated else "")
                        + (f" via thunk chain to 0x{resolved:x}" if resolved else "")
                        + "; data-pointer run, not proof of a vtable"
                    ),
                ),
            )
        )
        cursor += pointer_size
    if len(slots) < min_slots:
        return None
    return slots, header_slots


def resolve_thunk(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    *,
    disassembler: Disassembler | None = None,
    max_depth: int = 4,
) -> int | None:
    """Follow a tail-call chain from ``address``.

    A thunk here means the *first* instruction at ``address`` is a direct
    ``jmp``/``b <target>`` — real binaries pack these stubs tightly, so no
    claim is made about what follows. The final non-thunk address is returned,
    or ``None`` when ``address`` does not start with a direct tail-call. The
    heuristic judgment (one branch = thunk) lives in the caller's evidence,
    not in this return value.
    """
    if max_depth < 1:
        raise AnalysisError("max_depth must be >= 1")
    disassembler = disassembler or _new_disassembler(info)
    if disassembler is None:
        return None
    current = address
    hops = 0
    while hops < max_depth:
        try:
            code = read_code(path, info, current, 16)
        except (AnalysisError, OSError):
            break
        if not code:
            break
        try:
            result = disassembler.disassemble(code, base_address=current, max_instructions=1)
        except DisassemblyError:
            break
        if not result.instructions:
            break
        only = result.instructions[0]
        mnemonic = only.mnemonic.strip().lower()
        operand = only.operands.strip().lstrip("#")
        if (
            mnemonic not in _THUNK_MNEMONICS
            or not operand.startswith("0x")
            or any(ch in operand for ch in "[]+:")
        ):
            break  # not a forwarding hop: this address is the chain's end
        try:
            target = int(operand, 16)
        except ValueError:
            break
        if not _target_in_executable(info, target) or target == current:
            break
        hops += 1
        current = target
    return current if hops > 0 else None


def find_vtables(
    path: str | Path,
    info: BinaryInfo,
    *,
    address: int | None = None,
    min_slots: int = DEFAULT_MIN_SLOTS,
    max_slots: int = DEFAULT_MAX_SLOTS,
    max_tables: int = DEFAULT_MAX_TABLES,
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
    resolve_thunks: bool = True,
    max_thunk_depth: int = 4,
) -> VtableScanResult:
    """Discover vtable candidates at ``address`` or across data sections.

    Args:
        path: File the metadata in ``info`` was loaded from (read-only).
        info: Normalized binary metadata.
        address: Exact vtable address to decode; ``None`` sweeps every
            non-executable section with file bytes for candidate runs.
        min_slots: Fewest consecutive code pointers that count as a table.
        max_slots: Cap on slots decoded per candidate.
        max_tables: Cap on candidates in scan mode.
        max_scan_bytes: Cap on bytes read per scanned section.
        resolve_thunks: Follow one-instruction tail-call chains from slot
            targets and report the final callee as ``resolved_target``.
        max_thunk_depth: Cap on thunk-chain hops.

    Returns:
        A :class:`VtableScanResult` with candidate tables in address order.

    Raises:
        AnalysisError: If any bound is out of range, or address mode found no
            plausible table at ``address``.
    """
    if min_slots < 2:
        raise AnalysisError("min_slots must be >= 2")
    if max_slots < min_slots:
        raise AnalysisError("max_slots must be >= min_slots")
    if max_slots > MAX_SLOTS_LIMIT:
        raise AnalysisError(f"max_slots too large (limit {MAX_SLOTS_LIMIT})")
    if max_tables < 1 or max_tables > 1024:
        raise AnalysisError("max_tables must be between 1 and 1024")
    if max_scan_bytes < pointer_size_of(info):
        raise AnalysisError("max_scan_bytes is smaller than one pointer")
    if max_scan_bytes > MAX_SCAN_BYTES_LIMIT:
        raise AnalysisError(f"max_scan_bytes too large (limit {MAX_SCAN_BYTES_LIMIT})")
    if max_thunk_depth < 1 or max_thunk_depth > 16:
        raise AnalysisError("max_thunk_depth must be between 1 and 16")

    byteorder = _byteorder(info)
    pointer_size = pointer_size_of(info)
    overlay = _relocation_overlay(path)
    disassembler: Disassembler | None = None
    if resolve_thunks:
        try:
            disassembler = Disassembler(info.architecture, info.bitness, info.endianness)
        except DisassemblyError as exc:
            return VtableScanResult(
                tables=[],
                scanned_sections=[],
                scanned_bytes=0,
                truncated=False,
                evidence=Evidence(
                    source=_SOURCE,
                    method="pointer_array_scan",
                    confidence=Confidence.MEDIUM,
                    detail=f"vtable scan unavailable: {exc}",
                ),
                warnings=(f"disassembly unavailable: {exc}",),
            )

    scanned_sections: list[str] = []
    scanned_bytes = 0
    truncated = False
    warnings: list[str] = []
    tables: list[VtableCandidate] = []

    if address is not None:
        section = info.section_for_va(address)
        if section is None:
            raise AnalysisError(f"address 0x{address:x} is not mapped")
        read = _read_slots(
            path,
            info,
            address,
            pointer_size=pointer_size,
            byteorder=byteorder,
            min_slots=min_slots,
            max_slots=max_slots,
            resolve_thunks=resolve_thunks,
            max_thunk_depth=max_thunk_depth,
            disassembler=disassembler,
            section_name=section.name,
            overlay=overlay,
            skip_header=True,
        )
        if read is None:
            raise AnalysisError(
                f"address 0x{address:x} does not start a plausible vtable "
                f"(fewer than {min_slots} consecutive code pointers within the "
                "2-slot Itanium header window)"
            )
        slots, header_slots = read
        truncated = len(slots) >= max_slots
        tables.append(
            VtableCandidate(
                address=address,
                slots=slots,
                slot_size=pointer_size,
                section_name=section.name,
                header_slots=header_slots,
                truncated=truncated,
                evidence=Evidence(
                    source=_SOURCE,
                    method="pointer_array_scan",
                    confidence=Confidence.MEDIUM,
                    address=address,
                    detail=(
                        f"{len(slots)} slot(s) at caller-supplied address "
                        f"({header_slots} header slot(s) skipped); "
                        "heuristic candidate, not proof"
                    ),
                ),
            )
        )
        scanned_sections.append(section.name)
        scanned_bytes = (len(slots) + header_slots) * pointer_size
    else:
        data_sections = [
            section
            for section in info.sections
            if not section.is_executable
            and section.size > 0
            and (section.raw_size > 0 or info.format == "ELF")
        ]
        for section in data_sections:
            if len(tables) >= max_tables:
                truncated = True
                warnings.append(f"table limit {max_tables} reached; scan stopped early")
                break
            budget = min(max_scan_bytes, section.size)
            try:
                data = read_code(path, info, section.virtual_address, budget)
            except (AnalysisError, OSError) as exc:
                warnings.append(
                    f"section {section.name!r}: cannot read bytes ({exc})"
                )
                continue
            if not data:
                continue
            scanned_sections.append(section.name)
            scanned_bytes += len(data)
            step = pointer_size
            run_start: int | None = None
            run_length = 0
            for offset in range(0, len(data) - step + 1, step):
                target_va = section.virtual_address + offset
                value = int.from_bytes(data[offset : offset + step], byteorder)
                if target_va in overlay:
                    value = overlay[target_va]
                valid = value != 0 and _target_in_executable(info, value)
                if valid:
                    if run_start is None:
                        run_start = target_va
                    run_length += 1
                    continue
                if run_start is not None and run_length >= min_slots:
                    read = _read_slots(
                        path,
                        info,
                        run_start,
                        pointer_size=pointer_size,
                        byteorder=byteorder,
                        min_slots=min_slots,
                        max_slots=max_slots,
                        resolve_thunks=resolve_thunks,
                        max_thunk_depth=max_thunk_depth,
                        disassembler=disassembler,
                        section_name=section.name,
                        overlay=overlay,
                    )
                    if read is not None:
                        slots, _header = read
                        if len(tables) >= max_tables:
                            truncated = True
                            warnings.append(
                                f"table limit {max_tables} reached; scan stopped early"
                            )
                            break
                        truncated = truncated or len(slots) >= max_slots
                        tables.append(
                            VtableCandidate(
                                address=run_start,
                                slots=slots,
                                slot_size=pointer_size,
                                section_name=section.name,
                                header_slots=0,
                                truncated=truncated,
                                evidence=Evidence(
                                    source=_SOURCE,
                                    method="pointer_array_scan",
                                    confidence=Confidence.MEDIUM,
                                    address=run_start,
                                    detail=(
                                        f"{len(slots)} consecutive code pointer(s) in "
                                        f"{section.name!r}; heuristic candidate, not proof"
                                    ),
                                ),
                            )
                        )
                run_start = None
                run_length = 0

    tables.sort(key=lambda table: table.address)
    return VtableScanResult(
        tables=tables,
        scanned_sections=scanned_sections,
        scanned_bytes=scanned_bytes,
        truncated=truncated,
        evidence=Evidence(
            source=_SOURCE,
            method="pointer_array_scan",
            confidence=Confidence.MEDIUM,
            detail=(
                f"{len(tables)} vtable candidate(s) across {len(scanned_sections)} "
                "data section(s); runs of code pointers are a heuristic, not proof"
            ),
        ),
        warnings=tuple(warnings),
    )


def pointer_size_of(info: BinaryInfo) -> int:
    """Public alias for the pointer-size helper used by callers and tests."""
    return 8 if info.bitness >= 64 else 4

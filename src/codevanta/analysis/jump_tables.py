"""Jump-table (absolute pointer array) resolution.

A jump table is a run of ``pointer_size``-wide values that each hold an absolute
virtual address a dispatcher branches to. This module decodes one such array,
starting at a caller-supplied ``table_address``, and reports the targets it
could justify:

* Every slot is decoded with :func:`codevanta.core.report.read_code`, so all
  reads are bounded by the containing section's file bytes and nothing is ever
  mapped or executed. The whole window is ``max_entries * pointer_size`` bytes
  and the table address is validated against the binary map before a byte is
  read.
* The scan stops at the first slot that is *not* a usable target: a zero
  pointer (the conventional table terminator), a pointer outside the caller's
  ``min_target``/``max_target`` window, a pointer no section maps, or -- when
  ``executable_only`` is true -- a pointer into a non-executable section. Every
  such stop is recorded in :attr:`JumpTableResult.warnings`, so a caller can
  tell a short table from one that ran into something unexpected.
* ``truncated`` is true only when the entry ceiling was reached *and* the next
  slot still holds a non-zero pointer, i.e. more entries really were available.

Entries carry :attr:`codevanta.evidence.confidence.Confidence.MEDIUM`: a pointer
array found by shape is evidence of a dispatch table, not proof of one, and
nothing here shows that a dispatcher actually indexes the array.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.core.loader import BinaryInfo, SectionInfo
from codevanta.core.report import AnalysisError, read_code
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_ENTRIES",
    "EVIDENCE_METHOD",
    "EVIDENCE_SOURCE",
    "MAX_ENTRIES",
    "JumpTableEntry",
    "JumpTableResult",
    "resolve_jump_table",
]

#: Default number of pointers a single resolution will decode.
DEFAULT_MAX_ENTRIES = 256

#: Hard ceiling on ``max_entries`` (bounded work: at most 32 KiB per call).
MAX_ENTRIES = 4096

#: Pointer widths accepted for ``pointer_size``.
_ALLOWED_POINTER_SIZES = (4, 8)

#: Evidence source label shared by every record produced here.
EVIDENCE_SOURCE = "jump_table.pointer_array"

#: Evidence method label shared by every record produced here.
EVIDENCE_METHOD = "absolute_pointers"

#: Endianness words that mean big-endian; everything else decodes little-endian.
_BIG_ENDIAN_MARKERS = ("big", "msb", "be")


@dataclass(frozen=True)
class JumpTableEntry:
    """One decoded pointer slot of a jump table.

    Attributes:
        index: Zero-based slot index inside the table, relative to
            ``table_address``.
        target: Absolute virtual address stored in the slot.
        evidence: Evidence record for this slot, pinned to the slot address and
            carrying the decoded index and target.
    """

    index: int
    target: int
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "target": f"0x{self.target:x}",
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class JumpTableResult:
    """Outcome of one jump-table resolution.

    Attributes:
        table_address: Absolute virtual address of the first decoded pointer.
        entries: Decoded entries in slot order (possibly empty).
        pointer_size: Pointer width in bytes used to decode the table.
        truncated: ``True`` when ``max_entries`` cut the table short even though
            a further non-zero pointer was still available.
        evidence: Evidence describing the resolution as a whole.
        warnings: Non-fatal reasons that stopped the scan early, or that made
            the result incomplete.
    """

    table_address: int
    entries: list[JumpTableEntry]
    pointer_size: int
    truncated: bool
    evidence: Evidence
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "table_address": f"0x{self.table_address:x}",
            "entry_count": len(self.entries),
            "entries": [entry.to_dict() for entry in self.entries],
            "pointer_size": self.pointer_size,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _byteorder(info: BinaryInfo) -> str:
    """Return the ``int.from_bytes`` byte order implied by ``info.endianness``."""
    text = str(getattr(info, "endianness", "") or "").strip().lower()
    return "big" if any(text.startswith(marker) for marker in _BIG_ENDIAN_MARKERS) else "little"


def _int_argument(name: str, value: Any) -> int:
    """Convert an argument to ``int`` or raise :class:`AnalysisError`."""
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise AnalysisError(f"{name} must be an integer, got {value!r}") from exc


def _resolve_pointer_size(info: BinaryInfo, pointer_size: int | None) -> int:
    """Validate ``pointer_size``, defaulting it from the binary's bitness."""
    if pointer_size is None:
        bitness = int(getattr(info, "bitness", 0) or 0)
        if bitness == 64:
            return 8
        if bitness == 32:
            return 4
        raise AnalysisError(
            f"cannot infer pointer size from bitness {bitness}; pass pointer_size explicitly"
        )
    size = _int_argument("pointer_size", pointer_size)
    if size not in _ALLOWED_POINTER_SIZES:
        raise AnalysisError(f"pointer_size must be 4 or 8, got {pointer_size}")
    return size


def _validate_table_address(info: BinaryInfo, table_address: int) -> SectionInfo:
    """Return the section backing ``table_address`` or raise :class:`AnalysisError`."""
    address = _int_argument("table_address", table_address)
    if address < 0:
        raise AnalysisError(f"invalid table_address 0x{address:x}")
    section = info.section_for_va(address)
    if section is None:
        raise AnalysisError(f"table address 0x{address:x} is not inside any section")
    if info.va_to_offset(address) is None:
        raise AnalysisError(f"table address 0x{address:x} is not mapped to file bytes")
    return section


def _entry_evidence(index: int, slot_address: int, target: int) -> Evidence:
    """Build the evidence record for one decoded pointer slot."""
    return Evidence(
        source=EVIDENCE_SOURCE,
        method=EVIDENCE_METHOD,
        confidence=Confidence.MEDIUM,
        address=slot_address,
        detail=f"pointer #{index} at 0x{slot_address:x} -> 0x{target:x}",
        extra={"index": index, "target": f"0x{target:x}"},
    )


def _result_evidence(
    table_address: int, entry_count: int, pointer_size: int, truncated: bool
) -> Evidence:
    """Build the evidence record describing the resolution as a whole."""
    return Evidence(
        source=EVIDENCE_SOURCE,
        method=EVIDENCE_METHOD,
        confidence=Confidence.MEDIUM,
        address=table_address,
        detail=(
            f"decoded {entry_count} absolute pointer(s) of {pointer_size} byte(s) "
            f"from 0x{table_address:x}"
        ),
        extra={
            "entries": entry_count,
            "pointer_size": pointer_size,
            "truncated": truncated,
        },
    )


def resolve_jump_table(
    path: str | Path,
    info: BinaryInfo,
    table_address: int,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    pointer_size: int | None = None,
    executable_only: bool = True,
    min_target: int | None = None,
    max_target: int | None = None,
) -> JumpTableResult:
    """Decode an absolute-pointer jump table starting at ``table_address``.

    The table is read as ``max_entries`` consecutive ``pointer_size``-wide
    values, decoded with ``info.endianness``. The scan stops at the first slot
    that cannot be a target: a zero pointer, a pointer outside
    ``[min_target, max_target]``, a pointer no section maps, or -- with
    ``executable_only`` -- a pointer into a non-executable section. Each stop is
    explained in :attr:`JumpTableResult.warnings`.

    Args:
        path: Binary to read.
        info: Metadata for ``path``; its ``bitness``, ``endianness`` and
            ``sections`` drive the decode.
        table_address: Absolute virtual address of the first pointer slot.
        max_entries: Maximum number of slots to decode, ``1 .. MAX_ENTRIES``.
        pointer_size: Pointer width in bytes, ``4`` or ``8``. ``None`` selects 8
            for a 64-bit binary and 4 for a 32-bit one.
        executable_only: When true (default), a pointer into a non-executable
            section ends the scan with a warning.
        min_target: Optional inclusive lower bound for accepted targets.
        max_target: Optional inclusive upper bound for accepted targets.

    Returns:
        The decoded table with per-slot and summary evidence.

    Raises:
        AnalysisError: If ``max_entries``, ``pointer_size``, ``table_address``
            or the ``min_target``/``max_target`` window is invalid, or if the
            table address is not backed by file bytes.

    Note:
        **Bounded work.** At most ``max_entries * pointer_size`` bytes are read
        for the table itself, plus a single pointer-sized peek used to decide
        ``truncated``. Nothing is loaded or executed; the file is only read
        through :func:`codevanta.core.report.read_code`, which never returns
        more bytes than the containing section maps.
    """
    limit = _int_argument("max_entries", max_entries)
    if limit < 1:
        raise AnalysisError("max_entries must be >= 1")
    if limit > MAX_ENTRIES:
        raise AnalysisError(f"max_entries too large (limit {MAX_ENTRIES})")
    size = _resolve_pointer_size(info, pointer_size)
    low = None if min_target is None else _int_argument("min_target", min_target)
    high = None if max_target is None else _int_argument("max_target", max_target)
    if low is not None and high is not None and low > high:
        raise AnalysisError("min_target must be <= max_target")
    section = _validate_table_address(info, table_address)
    table = _int_argument("table_address", table_address)
    byteorder = _byteorder(info)

    window = limit * size
    data = read_code(path, info, table, window)
    slots = len(data) // size
    if slots < 1:
        raise AnalysisError(
            f"table address 0x{table:x} has fewer than {size} file bytes "
            f"in section {section.name!r}"
        )

    entries: list[JumpTableEntry] = []
    warnings: list[str] = []
    stopped = False

    for index in range(slots):
        slot_address = table + index * size
        target = int.from_bytes(data[index * size : (index + 1) * size], byteorder)
        if target == 0:
            warnings.append(
                f"zero pointer at index {index} (0x{slot_address:x}) terminates the table"
            )
            stopped = True
            break
        if low is not None and target < low:
            warnings.append(
                f"index {index}: target 0x{target:x} is below min_target 0x{low:x}; "
                "table scan stopped"
            )
            stopped = True
            break
        if high is not None and target > high:
            warnings.append(
                f"index {index}: target 0x{target:x} is above max_target 0x{high:x}; "
                "table scan stopped"
            )
            stopped = True
            break
        target_section = info.section_for_va(target)
        if target_section is None:
            warnings.append(
                f"index {index}: target 0x{target:x} is not mapped by any section; "
                "table scan stopped"
            )
            stopped = True
            break
        if executable_only and not target_section.is_executable:
            warnings.append(
                f"index {index}: target 0x{target:x} is inside non-executable section "
                f"{target_section.name!r}; table scan stopped"
            )
            stopped = True
            break
        entries.append(
            JumpTableEntry(
                index=index,
                target=target,
                evidence=_entry_evidence(index, slot_address, target),
            )
        )

    truncated = False
    if not stopped and slots >= limit:
        # The ceiling ended the scan; only call it truncated when a further
        # non-zero pointer is actually readable past the requested window.
        try:
            peek = read_code(path, info, table + limit * size, size)
        except (AnalysisError, OSError):
            peek = b""
        if len(peek) == size:
            truncated = int.from_bytes(peek, byteorder) != 0

    if not stopped and len(data) < window:
        # The section ended before the requested window: a short table is
        # indistinguishable from one that is cut off, so say so explicitly.
        warnings.append(
            f"table scan reached the end of section {section.name!r} after {slots} "
            "slot(s); the table may be cut off"
        )

    return JumpTableResult(
        table_address=table,
        entries=entries,
        pointer_size=size,
        truncated=truncated,
        evidence=_result_evidence(table, len(entries), size, truncated),
        warnings=tuple(warnings),
    )

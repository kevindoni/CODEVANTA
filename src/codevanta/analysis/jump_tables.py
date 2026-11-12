"""Jump-table resolution for absolute pointer arrays and signed 32-bit offsets.

A jump table is a run of fixed-width slots that a dispatcher indexes to reach a
case target. Two layouts are supported, selected by ``mode``:

* ``"absolute"`` (the default) -- each slot is a ``pointer_size``-wide absolute
  virtual address a dispatcher branches to.
* ``"relative"`` -- each slot is a *signed 32-bit* offset added to a
  caller-supplied ``base_address``, so ``target = base_address + offset``. This
  is the shape compilers emit for position-independent switch tables, where the
  slots stay valid under relocation because they store deltas, not addresses.

Both modes share the same guarantees:

* Every slot is decoded with :func:`codevanta.core.report.read_code`, so all
  reads are bounded by the containing section's file bytes and nothing is ever
  mapped or executed. The whole window is ``max_entries * pointer_size`` bytes
  and the table address is validated against the binary map before a byte is
  read.
* The scan stops at the first slot that is *not* a usable target: a value
  outside the caller's ``min_target``/``max_target`` window, a target no section
  maps, or -- when ``executable_only`` is true -- a target inside a
  non-executable section. Every such stop is recorded in
  :attr:`JumpTableResult.warnings`, so a caller can tell a short table from one
  that ran into something unexpected.
* In absolute mode a zero pointer (the conventional table terminator) also ends
  the scan. In relative mode a zero offset is *not* a terminator: it is a
  legitimate delta that resolves to ``base_address``, so only the rules above
  can end such a table.
* ``truncated`` is true only when the entry ceiling was reached *and* a further
  slot was still usable: in absolute mode the next slot still holds a non-zero
  pointer, in relative mode the next slot decodes to a target that passes the
  same stop rules.

Entries carry :attr:`codevanta.evidence.confidence.Confidence.MEDIUM`: a run of
same-width slots found by shape is evidence of a dispatch table, not proof of
one, and nothing here shows that a dispatcher actually indexes the array.
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
    "EVIDENCE_METHOD_RELATIVE",
    "EVIDENCE_SOURCE",
    "EVIDENCE_SOURCE_RELATIVE",
    "MAX_ENTRIES",
    "MODES",
    "MODE_ABSOLUTE",
    "MODE_RELATIVE",
    "RELATIVE_OFFSET_SIZE",
    "JumpTableEntry",
    "JumpTableResult",
    "resolve_jump_table",
]

#: Default number of slots a single resolution will decode.
DEFAULT_MAX_ENTRIES = 256

#: Hard ceiling on ``max_entries`` (bounded work: at most 32 KiB per call).
MAX_ENTRIES = 4096

#: Pointer widths accepted for ``pointer_size`` in absolute mode.
_ALLOWED_POINTER_SIZES = (4, 8)

#: Table layout used when each slot is an absolute virtual address.
MODE_ABSOLUTE = "absolute"

#: Table layout used when each slot is a signed 32-bit offset from a base.
MODE_RELATIVE = "relative"

#: Table layouts accepted for ``mode``.
MODES = (MODE_ABSOLUTE, MODE_RELATIVE)

#: Slot width, in bytes, of a relative table (one signed 32-bit offset).
RELATIVE_OFFSET_SIZE = 4

#: Evidence source label shared by every absolute-pointer record.
EVIDENCE_SOURCE = "jump_table.pointer_array"

#: Evidence method label shared by every absolute-pointer record.
EVIDENCE_METHOD = "absolute_pointers"

#: Evidence source label shared by every relative-offset record.
EVIDENCE_SOURCE_RELATIVE = "jump_table.relative_offsets"

#: Evidence method label shared by every relative-offset record.
EVIDENCE_METHOD_RELATIVE = "signed_offsets"

#: Endianness words that mean big-endian; everything else decodes little-endian.
_BIG_ENDIAN_MARKERS = ("big", "msb", "be")


@dataclass(frozen=True)
class JumpTableEntry:
    """One decoded slot of a jump table.

    Attributes:
        index: Zero-based slot index inside the table, relative to
            ``table_address``.
        target: Absolute virtual address the slot resolves to. In absolute mode
            that is the value stored in the slot; in relative mode it is
            ``base_address + offset``.
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
        table_address: Absolute virtual address of the first decoded slot.
        entries: Decoded entries in slot order (possibly empty).
        pointer_size: Slot width in bytes used to decode the table (``4`` for a
            relative table).
        truncated: ``True`` when ``max_entries`` cut the table short even though
            a further usable slot was still available.
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
    """Return ``value`` when it is a plain integer, else raise."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError(f"{name} must be an integer, got {value!r}")
    return value


def _target_section(info: BinaryInfo, target: int) -> Any | None:
    """Return the section that maps ``target`` for jump-table purposes.

    Sections whose ``virtual_address`` is zero are ignored: non-allocated
    sections (symbol and string tables) are commonly reported at address 0 and
    would otherwise swallow small bogus targets.
    """
    section = info.section_for_va(target)
    if section is None or section.virtual_address == 0:
        return None
    return section


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


def _resolve_mode(mode: str) -> str:
    """Normalise ``mode`` to one of :data:`MODES` or raise :class:`AnalysisError`."""
    if not isinstance(mode, str):
        raise AnalysisError(f"mode must be one of {MODES}, got {mode!r}")
    text = mode.strip().lower()
    if text not in MODES:
        raise AnalysisError(f"mode must be one of {MODES}, got {mode!r}")
    return text


def _resolve_relative_pointer_size(pointer_size: int | None) -> int:
    """Return :data:`RELATIVE_OFFSET_SIZE`, rejecting any other explicit width."""
    if pointer_size is None:
        return RELATIVE_OFFSET_SIZE
    size = _int_argument("pointer_size", pointer_size)
    if size != RELATIVE_OFFSET_SIZE:
        raise AnalysisError(
            f"pointer_size must be {RELATIVE_OFFSET_SIZE} in relative mode "
            f"(signed 32-bit offsets), got {pointer_size}"
        )
    return size


def _resolve_base_address(base_address: int | None) -> int:
    """Return the required origin of a relative table or raise :class:`AnalysisError`."""
    if base_address is None:
        raise AnalysisError("relative mode requires base_address")
    base = _int_argument("base_address", base_address)
    if base < 0:
        raise AnalysisError(f"invalid base_address 0x{base:x}")
    return base


def _stop_reason(
    index: int,
    target: int,
    info: BinaryInfo,
    low: int | None,
    high: int | None,
    executable_only: bool,
) -> str | None:
    """Return why ``target`` cannot extend the table, or ``None`` when it can.

    The checks are purely metadata lookups: the target is never read, mapped or
    executed. They are shared by both table layouts, so a relative table stops on
    exactly the same boundaries as an absolute one.
    """
    if low is not None and target < low:
        return (
            f"index {index}: target 0x{target:x} is below min_target 0x{low:x}; "
            "table scan stopped"
        )
    if high is not None and target > high:
        return (
            f"index {index}: target 0x{target:x} is above max_target 0x{high:x}; "
            "table scan stopped"
        )
    target_section = _target_section(info, target)
    if target_section is None:
        return (
            f"index {index}: target 0x{target:x} is not mapped by any section; "
            "table scan stopped"
        )
    if executable_only and not target_section.is_executable:
        return (
            f"index {index}: target 0x{target:x} is inside non-executable section "
            f"{target_section.name!r}; table scan stopped"
        )
    return None


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


def _relative_entry_evidence(
    index: int, slot_address: int, target: int, base_address: int
) -> Evidence:
    """Build the evidence record for one signed-offset slot."""
    return Evidence(
        source=EVIDENCE_SOURCE_RELATIVE,
        method=EVIDENCE_METHOD_RELATIVE,
        confidence=Confidence.MEDIUM,
        address=slot_address,
        detail=(
            f"offset #{index} at 0x{slot_address:x} against base 0x{base_address:x} "
            f"-> 0x{target:x}"
        ),
        extra={
            "index": index,
            "target": f"0x{target:x}",
            "base": f"0x{base_address:x}",
        },
    )


def _relative_result_evidence(
    table_address: int, entry_count: int, base_address: int, truncated: bool
) -> Evidence:
    """Build the evidence record describing a whole relative resolution."""
    return Evidence(
        source=EVIDENCE_SOURCE_RELATIVE,
        method=EVIDENCE_METHOD_RELATIVE,
        confidence=Confidence.MEDIUM,
        address=table_address,
        detail=(
            f"resolved {entry_count} signed 32-bit offset(s) against base "
            f"0x{base_address:x} from 0x{table_address:x}"
        ),
        extra={
            "entries": entry_count,
            "pointer_size": RELATIVE_OFFSET_SIZE,
            "truncated": truncated,
            "base": f"0x{base_address:x}",
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
    mode: str = MODE_ABSOLUTE,
    base_address: int | None = None,
) -> JumpTableResult:
    """Decode a jump table starting at ``table_address``.

    With ``mode="absolute"`` (the default) the table is read as ``max_entries``
    consecutive ``pointer_size``-wide absolute addresses. With
    ``mode="relative"`` it is read as consecutive *signed 32-bit* offsets, each
    resolved against ``base_address``.

    Values are decoded with ``info.endianness``. In both modes the scan stops at
    the first slot that cannot be a target: a value outside
    ``[min_target, max_target]``, a target no section maps, or -- with
    ``executable_only`` -- a target inside a non-executable section. Each stop is
    explained in :attr:`JumpTableResult.warnings`. A zero slot additionally
    terminates an absolute table; a zero offset in a relative table is a real
    delta that resolves to ``base_address`` and terminates nothing.

    Args:
        path: Binary to read.
        info: Metadata for ``path``; its ``bitness``, ``endianness`` and
            ``sections`` drive the decode.
        table_address: Absolute virtual address of the first slot.
        max_entries: Maximum number of slots to decode, ``1 .. MAX_ENTRIES``.
        pointer_size: Slot width in bytes. In absolute mode ``4`` or ``8``, with
            ``None`` selecting 8 for a 64-bit binary and 4 for a 32-bit one. In
            relative mode only ``4`` is valid, and ``None`` selects it.
        executable_only: When true (default), a target inside a non-executable
            section ends the scan with a warning.
        min_target: Optional inclusive lower bound for accepted targets, in
            absolute address space in both modes.
        max_target: Optional inclusive upper bound for accepted targets.
        mode: ``"absolute"`` (default) or ``"relative"``; case-insensitive.
        base_address: Origin the signed offsets of a relative table are added to.
            Required in relative mode; ignored in absolute mode.

    Returns:
        The decoded table with per-slot and summary evidence. Relative records
        use source ``jump_table.relative_offsets`` and method
        ``signed_offsets``, with the base in the detail.

    Raises:
        AnalysisError: If ``mode`` is unknown, if ``max_entries``,
            ``pointer_size``, ``table_address`` or the
            ``min_target``/``max_target`` window is invalid, if the table
            address is not backed by file bytes, or if relative mode is
            requested without a usable ``base_address``.

    Note:
        **Bounded work.** At most ``max_entries * pointer_size`` bytes are read
        for the table itself, plus a single slot-sized peek used to decide
        ``truncated``. Nothing is loaded, mapped or executed; the file is only
        read through :func:`codevanta.core.report.read_code`, which never
        returns more bytes than the containing section maps. Relative targets
        are validated by metadata lookup only, so a table cannot make this
        function read code at the addresses it names.
    """
    relative = _resolve_mode(mode) == MODE_RELATIVE
    limit = _int_argument("max_entries", max_entries)
    if limit < 1:
        raise AnalysisError("max_entries must be >= 1")
    if limit > MAX_ENTRIES:
        raise AnalysisError(f"max_entries too large (limit {MAX_ENTRIES})")
    # ``base`` is not None exactly when the table is relative; that single fact
    # selects signed decoding, offset arithmetic and the evidence labels below.
    base: int | None = None
    if relative:
        size = _resolve_relative_pointer_size(pointer_size)
        base = _resolve_base_address(base_address)
    else:
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
        raw = data[index * size : (index + 1) * size]
        value = (
            int.from_bytes(raw, byteorder, signed=True)
            if relative
            else int.from_bytes(raw, byteorder)
        )
        target = value if base is None else base + value
        if not relative and target == 0:
            warnings.append(
                f"zero pointer at index {index} (0x{slot_address:x}) terminates the table"
            )
            stopped = True
            break
        reason = _stop_reason(index, target, info, low, high, executable_only)
        if reason is not None:
            warnings.append(reason)
            stopped = True
            break
        entries.append(
            JumpTableEntry(
                index=index,
                target=target,
                evidence=(
                    _entry_evidence(index, slot_address, target)
                    if base is None
                    else _relative_entry_evidence(index, slot_address, target, base)
                ),
            )
        )

    truncated = False
    if not stopped and slots >= limit:
        # The ceiling ended the scan; only call it truncated when a further slot
        # is actually readable past the requested window and still usable.
        try:
            peek = read_code(path, info, table + limit * size, size)
        except (AnalysisError, OSError):
            peek = b""
        if len(peek) == size:
            if base is None:
                truncated = int.from_bytes(peek, byteorder) != 0
            else:
                # No zero terminator exists here: only a delta that resolves to
                # an acceptable target proves the table continues.
                truncated = (
                    _stop_reason(
                        limit,
                        base + int.from_bytes(peek, byteorder, signed=True),
                        info,
                        low,
                        high,
                        executable_only,
                    )
                    is None
                )

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
        evidence=(
            _result_evidence(table, len(entries), size, truncated)
            if base is None
            else _relative_result_evidence(table, len(entries), base, truncated)
        ),
        warnings=tuple(warnings),
    )

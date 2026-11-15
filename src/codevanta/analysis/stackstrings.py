"""FLOSS-style stack-string recovery on the existing bounded emulator.

Malware routinely builds strings at runtime instead of storing them: a function
moves immediate characters onto its stack frame (``mov dword ptr [rsp+0x20],
'Hell'``), decodes them, then uses the buffer. A static string scan never sees
them -- the bytes simply do not exist in the file. This module recovers them
the way Mandiant FLARE's ``floss/stackstrings.py`` does (see
`flare-floss <https://github.com/mandiant/flare-floss>`_, the direct
inspiration): it *emulates* each candidate function and then scans the emulated
stack for printable runs.

The engine does not build a second CPU. It reuses
:mod:`codevanta.analysis.emulate` end to end: the target function runs on a
private unicorn CPU whose image sections are mapped exactly the way
``emulate_function`` maps them, with the same ABI register seeding, the same
instruction budget enforcement, the same stop-reason classification and the
same Windows ``faulthandler`` suppression. The only specialisation is the
memory-write hook: instead of the 256-entry write transcript, the subclass
tracked here records the byte *span* of the stack the function wrote, and the
final stack bytes are read straight out of the emulator once the run stops.
Nothing is ever executed on the host; only file bytes are read (through the
production loader) and copied into emulator memory.

Algorithm
---------
1. Load the binary with :class:`~codevanta.core.loader.BinaryLoader` (the
   production loader; a file it cannot parse raises
   :class:`~codevanta.core.loader.BinaryLoadError`).
2. Choose target functions: the caller's explicit ``addresses`` when given,
   otherwise the executable-section candidates of
   :func:`codevanta.core.functions.discover_functions`, sorted by address and
   capped at ``max_functions``.
3. Emulate each function from its start under an instruction budget
   (:data:`MAX_MAX_INSTRUCTIONS`). Whatever the stop reason -- ``return``,
   ``budget``, ``unmapped``, ``unsupported`` or ``error`` -- the tracked stack
   span is scanned for printable ASCII and UTF-16LE runs of at least
   :data:`MIN_STRING_CHARS` characters.
4. Identical strings are deduplicated per function (first occurrence kept);
   at most ``max_strings_per_function`` distinct strings are kept per function
   while ``string_count`` keeps reporting the honest distinct total.
5. Every record carries an :class:`~codevanta.evidence.models.Evidence` with
   ``source="stackstrings.emulate"``, ``method="unicorn_stack_scan"`` and
   *medium* confidence: the string provably appeared in emulated stack memory,
   but emulation is an approximation (one entry state, one path, bounded
   instructions), so the run that produced it is not proof of runtime behaviour.

Guarantees
----------
* **Offline.** The bytes only ever run inside unicorn; no host process,
  syscall or library is invoked.
* **Bounded.** Function count, per-function instructions, per-function
  strings, value length, the stack read-back window and the warning list all
  carry hard caps, and every cap that fires is reported -- never silently.
* **Honest.** Functions that never wrote the stack, emulator setup failures
  and non-executable candidates are counted in the report's ``skipped``
  fields rather than hidden. A missing unicorn build raises
  :class:`~codevanta.core.report.AnalysisError` with the emulator's own
  install hint; a non-x86/x86-64 binary yields an empty report with a
  warning (the same degradation :mod:`codevanta.analysis.emulate` uses),
  because the register and stack vocabulary of the runner is x86-specific.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from codevanta.analysis import emulate
from codevanta.core.functions import discover_functions
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_FUNCTIONS",
    "DEFAULT_MAX_INSTRUCTIONS",
    "DEFAULT_MAX_STRINGS_PER_FUNCTION",
    "MAX_FUNCTIONS",
    "MAX_MAX_INSTRUCTIONS",
    "MAX_STACK_SCAN_BYTES",
    "MAX_STRINGS_PER_FUNCTION",
    "MAX_VALUE_CHARS",
    "MIN_STRING_CHARS",
    "MAX_WARNINGS",
    "FunctionScan",
    "StackString",
    "StackStringReport",
    "StackStringEncoding",
    "extract_stack_strings",
]


# ---- limits ---------------------------------------------------------------

#: Functions scanned when the caller does not pass ``max_functions``.
DEFAULT_MAX_FUNCTIONS = 16

#: Hard ceiling on ``max_functions`` (bounded work, whatever the caller asks).
MAX_FUNCTIONS = 64

#: Instruction budget per function when the caller does not pass one (the same
#: default :mod:`codevanta.analysis.emulate` uses).
DEFAULT_MAX_INSTRUCTIONS = emulate.DEFAULT_MAX_INSTRUCTIONS

#: Hard ceiling on ``max_instructions``. Tighter than emulate's own ceiling
#: because a stack-string sweep runs this budget once per scanned function.
MAX_MAX_INSTRUCTIONS = 10_000

#: Strings kept per function when the caller does not pass
#: ``max_strings_per_function``.
DEFAULT_MAX_STRINGS_PER_FUNCTION = 32

#: Hard ceiling on ``max_strings_per_function``.
MAX_STRINGS_PER_FUNCTION = 128

#: Shortest printable run, in characters, that becomes a record.
MIN_STRING_CHARS = 4

#: Longest string value kept in a record; longer runs are cut and flagged.
MAX_VALUE_CHARS = 256

#: Most stack bytes read back and scanned per function. The default emulated
#: stack is exactly this large (``emulate.DEFAULT_STACK_SIZE``), so the cap is
#: defensive: it keeps a pathological scatter of writes bounded.
MAX_STACK_SCAN_BYTES = 0x10000

#: Hard ceiling on warnings kept in one report.
MAX_WARNINGS = 32

#: Encodings a recovered run can carry.
StackStringEncoding = Literal["ascii", "utf-16le"]

#: Evidence identity shared by every record in this module.
_EVIDENCE_SOURCE = "stackstrings.emulate"
_EVIDENCE_METHOD = "unicorn_stack_scan"

#: Stop reasons a per-function scan can report (the emulator's public set).
_PUBLIC_REASONS = frozenset({"return", "budget", "unmapped", "unsupported", "error"})

#: True when a unicorn build is importable; mirrors
#: :data:`codevanta.analysis.emulate.EMULATOR_AVAILABLE`, which this module
#: reuses rather than re-probing.
EMULATOR_AVAILABLE = emulate.EMULATOR_AVAILABLE


# ---- records --------------------------------------------------------------


@dataclass(frozen=True)
class StackString:
    """One printable run recovered from a function's emulated stack.

    Attributes:
        function_address: Virtual address of the emulated function.
        stack_offset: Byte offset of the run from the *base of the emulated
            stack region* (``emulate.STACK_BASE_64``/``STACK_BASE_32``), so
            the value is stable and comparable across runs. The absolute
            address is in the evidence ``extra``.
        encoding: ``"ascii"`` or ``"utf-16le"``.
        value: The decoded characters, cut at :data:`MAX_VALUE_CHARS`
            (``value_truncated`` in the evidence ``extra`` says so).
        evidence: Provenance for the recovery.
    """

    function_address: int
    stack_offset: int
    encoding: StackStringEncoding
    value: str
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict (addresses become hex strings)."""
        return {
            "function": f"0x{self.function_address:x}",
            "stack_offset": self.stack_offset,
            "encoding": self.encoding,
            "value": self.value,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class FunctionScan:
    """What one emulated function contributed to the report.

    Attributes:
        address: Virtual address the scan started at.
        stop_reason: Why emulation ended (an emulate ``StopReason`` value).
        instructions: Instructions that completed (the stopper is not counted,
            exactly like :class:`emulate.EmulationResult`).
        stack_writes: Stores the function performed into the stack region.
        string_count: Distinct strings found *before* the per-function cap;
            ``len(strings kept)`` is derivable, the honest total is not.
        truncated: True when ``string_count`` exceeded the per-function cap
            and only the first ``max_strings_per_function`` records were kept.
    """

    address: int
    stop_reason: str
    instructions: int
    stack_writes: int
    string_count: int
    truncated: bool

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "address": f"0x{self.address:x}",
            "stop_reason": self.stop_reason,
            "instructions": self.instructions,
            "stack_writes": self.stack_writes,
            "string_count": self.string_count,
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class StackStringReport:
    """The bounded stack-string inventory of one binary.

    Attributes:
        path: The analysed file, as given.
        architecture: The loader's architecture string for the binary.
        bitness: The loader's bitness (32/64).
        functions_scanned: Functions selected for scanning (explicit addresses
            or discovered candidates, after dedup and the ``max_functions``
            cap).
        functions_emulated: Functions whose emulation actually ran (setup
            failures are counted in ``skipped_setup`` instead).
        functions: Per-function summaries, sorted by address.
        strings: Every kept record, in function order then by stack offset.
        skipped_not_executable: Discovered candidates that do not live in an
            executable section with file bytes (never counted for explicit
            addresses -- those raise instead, a caller mistake).
        skipped_setup: Functions whose emulator could not be prepared.
        skipped_no_stack_writes: Functions that ran but never wrote the stack,
            so there is nothing to recover.
        warnings: Every degradation, bounded by :data:`MAX_WARNINGS`.
        truncated: True when any cap fired (function list, per-function
            strings, or the stack read-back window).
        evidence: Provenance for the whole scan.
    """

    path: str
    architecture: str
    bitness: int
    functions_scanned: int
    functions_emulated: int
    functions: tuple[FunctionScan, ...]
    strings: tuple[StackString, ...]
    evidence: Evidence
    skipped_not_executable: int = 0
    skipped_setup: int = 0
    skipped_no_stack_writes: int = 0
    warnings: tuple[str, ...] = ()
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "path": self.path,
            "architecture": self.architecture,
            "bitness": self.bitness,
            "functions_scanned": self.functions_scanned,
            "functions_emulated": self.functions_emulated,
            "functions": [scan.to_dict() for scan in self.functions],
            "string_count": len(self.strings),
            "strings": [record.to_dict() for record in self.strings],
            "skipped": {
                "not_executable": self.skipped_not_executable,
                "setup": self.skipped_setup,
                "no_stack_writes": self.skipped_no_stack_writes,
            },
            "warnings": list(self.warnings),
            "truncated": self.truncated,
            "evidence": self.evidence.to_dict(),
        }


# ---- the tracking runner --------------------------------------------------


class _StackTracker(emulate._Runner):
    """One :class:`emulate._Runner` session that also tracks the stack writes.

    The emulator's public API deliberately reports stores as a bounded
    transcript (:data:`emulate.MAX_MEMORY_WRITES` entries, wide stores cut to
    their low 8 bytes) -- a transcript, not memory, and not enough to recover
    strings. Subclassing the private runner is the tight-coupling point this
    module is built on: image/stack mapping, register seeding, hook
    installation, budget enforcement and error classification are all reused
    verbatim, and only ``_on_write`` is specialised -- it extends the tracked
    *span* of the stack the code writes (a span has no entry cap). If
    ``emulate._Runner`` ever changes shape, the tests fail loudly here rather
    than the recovery quietly drifting.

    A note on the parent's write transcript: the override does not call
    ``super()._on_write``, so ``memory_writes`` stays empty and its
    dropped-write warnings never fire -- the span is this class's record.
    """

    def __init__(
        self,
        path: str | Path,
        info: BinaryInfo,
        address: int,
        *,
        bits: int,
        max_instructions: int,
    ) -> None:
        super().__init__(
            path,
            info,
            address,
            bits=bits,
            max_instructions=max_instructions,
            stack_size=emulate.DEFAULT_STACK_SIZE,
            stop_at_indirect=False,
        )
        self.stack_writes = 0
        self.stack_write_lo: int | None = None
        self.stack_write_hi: int | None = None

    def _on_write(
        self,
        uc: Any,
        access: int,
        address: int,
        size: int,
        value: int,
        user_data: Any,
    ) -> None:
        """Widen the tracked stack span; stores outside the stack are ignored."""
        if size <= 0:
            return
        lo = max(address, self.stack_base)
        hi = min(address + size, self.stack_top)
        if lo >= hi:  # the store does not touch the stack region
            return
        self.stack_writes += 1
        if self.stack_write_lo is None or lo < self.stack_write_lo:
            self.stack_write_lo = lo
        if self.stack_write_hi is None or hi > self.stack_write_hi:
            self.stack_write_hi = hi

    def written_span(self) -> tuple[int, int] | None:
        """Return the ``[lo, hi)`` byte span of the stack the code wrote."""
        if self.stack_write_lo is None or self.stack_write_hi is None:
            return None
        return self.stack_write_lo, self.stack_write_hi

    def read_span_bytes(self, start: int, end: int) -> bytes:
        """Read the written stack span back from the emulator, bounded.

        The read is capped at :data:`MAX_STACK_SCAN_BYTES` from ``start``
        (deterministically favouring the lowest written address); the caller
        warns when that cap fires.
        """
        if self.uc is None or end <= start:
            return b""
        length = min(end - start, MAX_STACK_SCAN_BYTES)
        try:
            return bytes(self.uc.mem_read(start, length))
        except Exception:  # pragma: no cover - defensive
            return b""


# ---- printable-run scanning -------------------------------------------------


def _is_printable_ascii(byte: int) -> bool:
    """True for the printable ASCII range a recovered character must be in."""
    return 0x20 <= byte <= 0x7E


def _scan_ascii_runs(data: bytes) -> tuple[tuple[int, str], ...]:
    """Find maximal printable-ASCII runs of at least :data:`MIN_STRING_CHARS`.

    Returns:
        ``(index, text)`` pairs, ``index`` being the run's offset inside
        ``data``, in ascending order.
    """
    runs: list[tuple[int, str]] = []
    start: int | None = None
    for index, byte in enumerate(data):
        if _is_printable_ascii(byte):
            if start is None:
                start = index
            continue
        if start is not None and index - start >= MIN_STRING_CHARS:
            runs.append((start, data[start:index].decode("ascii")))
        start = None
    if start is not None and len(data) - start >= MIN_STRING_CHARS:
        runs.append((start, data[start:].decode("ascii")))
    return tuple(runs)


def _scan_utf16le_runs(data: bytes) -> tuple[tuple[int, str], ...]:
    """Find UTF-16LE runs (printable char, zero byte) of ``MIN_STRING_CHARS``.

    The two passes are independent on purpose, the way FLOSS runs them: a
    UTF-16 run is *not* an ASCII run (the interleaved zeroes break it), so
    each encoding gets its own scan of the same bytes.

    Returns:
        ``(index, text)`` pairs in ascending order.
    """
    runs: list[tuple[int, str]] = []
    index = 0
    size = len(data)
    while index + 1 < size:
        if _is_printable_ascii(data[index]) and data[index + 1] == 0:
            start = index
            chars: list[str] = []
            while (
                index + 1 < size
                and _is_printable_ascii(data[index])
                and data[index + 1] == 0
            ):
                chars.append(chr(data[index]))
                index += 2
            if len(chars) >= MIN_STRING_CHARS:
                runs.append((start, "".join(chars)))
        else:
            index += 1
    return tuple(runs)


def _collect_stack_strings(
    data: bytes,
    base_offset: int,
    function_address: int,
    stop_reason: str,
) -> tuple[StackString, ...]:
    """Turn one scanned stack buffer into deduplicated records.

    Candidates from both encodings are ordered by ``(offset, encoding)``,
    then identical ``(encoding, value)`` pairs collapse onto their first
    occurrence. Values longer than :data:`MAX_VALUE_CHARS` are cut and the
    record's evidence says so. No per-function cap here -- the caller owns
    that budget and the honest ``string_count``.
    """
    candidates: list[tuple[int, StackStringEncoding, str]] = []
    for index, text in _scan_ascii_runs(data):
        candidates.append((base_offset + index, "ascii", text))
    for index, text in _scan_utf16le_runs(data):
        candidates.append((base_offset + index, "utf-16le", text))
    candidates.sort(key=lambda item: (item[0], item[1], item[2]))
    records: list[StackString] = []
    seen: set[tuple[str, str]] = set()
    for offset, encoding, value in candidates:
        key = (encoding, value)
        if key in seen:
            continue
        seen.add(key)
        records.append(
            StackString(
                function_address=function_address,
                stack_offset=offset,
                encoding=encoding,
                value=value[:MAX_VALUE_CHARS],
                evidence=Evidence(
                    source=_EVIDENCE_SOURCE,
                    method=_EVIDENCE_METHOD,
                    confidence=Confidence.MEDIUM,
                    address=function_address,
                    detail=(
                        f"{len(value)}-character {encoding} run recovered from "
                        "emulated stack memory"
                    ),
                    extra={
                        "function": f"0x{function_address:x}",
                        "stop_reason": stop_reason,
                        "stack_offset": offset,
                        "encoding": encoding,
                        "length": len(value),
                        "value_truncated": len(value) > MAX_VALUE_CHARS,
                    },
                ),
            )
        )
    return tuple(records)


# ---- validation -------------------------------------------------------------


def _validated_limit(name: str, value: int, ceiling: int) -> int:
    """Validate one budget argument against the documented limits."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError(f"{name} must be an int")
    if value < 1:
        raise AnalysisError(f"{name} must be >= 1")
    if value > ceiling:
        raise AnalysisError(f"{name} too large ({value}); limit is {ceiling}")
    return value


def _validated_addresses(addresses: Sequence[int]) -> list[int]:
    """Validate explicit addresses and return them unique and sorted."""
    unique: set[int] = set()
    for entry in addresses:
        if isinstance(entry, bool) or not isinstance(entry, int):
            raise AnalysisError(
                f"addresses must contain ints, not {type(entry).__name__}"
            )
        if entry <= 0:
            raise AnalysisError(f"addresses must be positive, got 0x{entry:x}")
        unique.add(entry)
    return sorted(unique)


def _validated_target(info: BinaryInfo, address: int) -> None:
    """Reject an address no emulation could start at (a caller mistake)."""
    section = info.section_for_va(address)
    if section is None:
        raise AnalysisError(f"address 0x{address:x} is not mapped by any section")
    if not section.is_executable:
        raise AnalysisError(
            f"address 0x{address:x} is inside section {section.name!r}, "
            "which is not executable"
        )
    if info.va_to_offset(address) is None:
        raise AnalysisError(f"address 0x{address:x} has no file bytes to execute")


def _warn(warnings: list[str], message: str) -> None:
    """Append one warning unless the cap has been reached."""
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)


def _public_reason(reason: str | None) -> str:
    """Map a runner stop reason onto the public set."""
    if reason in _PUBLIC_REASONS:
        return reason
    return "error"


# ---- target selection -------------------------------------------------------


def _discovered_targets(info: BinaryInfo) -> tuple[list[int], int]:
    """Return executable, file-backed, unique discovered addresses.

    Returns:
        ``(targets, skipped)`` where ``skipped`` counts unique candidates that
        do not live in an executable section with file bytes.
    """
    targets: list[int] = []
    seen: set[int] = set()
    for candidate in discover_functions(info):
        address = candidate.address
        if address <= 0 or address in seen:
            continue
        seen.add(address)
        section = info.section_for_va(address)
        if section is None or not section.is_executable:
            continue
        if info.va_to_offset(address) is None:
            continue
        targets.append(address)
    targets.sort()
    return targets, len(seen) - len(targets)


# ---- the scan ----------------------------------------------------------------


def _empty_report(path: Path, info: BinaryInfo, warnings: list[str]) -> StackStringReport:
    """Build the nothing-ran report used for binaries this module cannot emulate."""
    return StackStringReport(
        path=str(path),
        architecture=info.architecture or "unknown",
        bitness=info.bitness,
        functions_scanned=0,
        functions_emulated=0,
        functions=(),
        strings=(),
        evidence=Evidence(
            source=_EVIDENCE_SOURCE,
            method=_EVIDENCE_METHOD,
            confidence=Confidence.UNKNOWN,
            detail="no function was emulated",
            extra={
                "architecture": info.architecture,
                "bitness": info.bitness,
                "emulator_status": emulate.emulator_status(),
            },
        ),
        warnings=tuple(warnings),
    )


def _extract(
    path: Path,
    info: BinaryInfo,
    addresses: Sequence[int] | None,
    max_functions: int,
    max_instructions: int,
    max_strings_per_function: int,
) -> StackStringReport:
    """Run the scan over ``info`` (already validated and loaded)."""
    warnings: list[str] = []
    truncated = False
    bits = emulate._machine_bits(info)
    if bits is None or not EMULATOR_AVAILABLE:
        _warn(
            warnings,
            f"cannot emulate {info.architecture or 'unknown'} ({info.bitness}-bit); "
            "stack-string extraction emulates x86 and x86-64 only, so no code was run",
        )
        return _empty_report(path, info, warnings)

    skipped_not_executable = 0
    if addresses:
        targets = _validated_addresses(addresses)
        for address in targets:
            _validated_target(info, address)
        if len(targets) > max_functions:
            truncated = True
            _warn(
                warnings,
                f"{len(targets)} explicit address(es) cut to the max_functions="
                f"{max_functions} budget; the rest were not scanned",
            )
            targets = targets[:max_functions]
    else:
        discovered, skipped_not_executable = _discovered_targets(info)
        targets = discovered
        if not targets:
            _warn(
                warnings,
                "no executable function candidates discovered; nothing to scan",
            )
        if skipped_not_executable:
            _warn(
                warnings,
                f"{skipped_not_executable} discovered candidate(s) are not inside an "
                "executable section with file bytes and were skipped",
            )
        if len(targets) > max_functions:
            truncated = True
            _warn(
                warnings,
                f"{len(targets)} discovered function(s) cut to the max_functions="
                f"{max_functions} budget; the rest were not scanned",
            )
            targets = targets[:max_functions]

    scans: list[FunctionScan] = []
    strings: list[StackString] = []
    functions_emulated = 0
    skipped_setup = 0
    skipped_no_writes = 0

    for address in targets:
        tracker = _StackTracker(
            path, info, address, bits=bits, max_instructions=max_instructions
        )
        ran = False
        try:
            try:
                tracker.setup({}, {})
                ran = True
            except emulate._unicorn.UcError as exc:  # pragma: no cover - defensive
                tracker.warnings.append(f"the emulator could not be prepared: {exc}")
                tracker.reason = "error"
                skipped_setup += 1
            if ran:
                tracker.run()
                functions_emulated += 1
            reason = _public_reason(tracker.reason)
            for warning in tracker.warnings:
                _warn(warnings, f"0x{address:x}: {warning}")

            records: tuple[StackString, ...] = ()
            string_count = 0
            function_truncated = False
            span = tracker.written_span()
            if ran and span is not None:
                lo, hi = span
                if hi - lo > MAX_STACK_SCAN_BYTES:
                    truncated = True
                    _warn(
                        warnings,
                        f"0x{address:x}: stack write span of {hi - lo} byte(s) cut to "
                        f"the {MAX_STACK_SCAN_BYTES}-byte read-back budget",
                    )
                data = tracker.read_span_bytes(lo, hi)
                if data:
                    records = _collect_stack_strings(
                        data, lo - tracker.stack_base, address, reason
                    )
                    string_count = len(records)
                    if string_count > max_strings_per_function:
                        function_truncated = True
                        _warn(
                            warnings,
                            f"0x{address:x}: {string_count} distinct string(s) cut to "
                            f"max_strings_per_function={max_strings_per_function}",
                        )
                        records = records[:max_strings_per_function]
            elif ran:
                skipped_no_writes += 1

            truncated = truncated or function_truncated
            scans.append(
                FunctionScan(
                    address=address,
                    stop_reason=reason,
                    instructions=tracker.completed,
                    stack_writes=tracker.stack_writes,
                    string_count=string_count,
                    truncated=function_truncated,
                )
            )
            strings.extend(records)
        finally:
            tracker.close()

    evidence = Evidence(
        source=_EVIDENCE_SOURCE,
        method=_EVIDENCE_METHOD,
        confidence=Confidence.MEDIUM,
        detail=(
            f"{functions_emulated} function(s) emulated on a private unicorn CPU; "
            f"{len(strings)} stack string(s) recovered"
        ),
        extra={
            "functions_scanned": len(targets),
            "functions_emulated": functions_emulated,
            "strings_found": len(strings),
            "max_functions": max_functions,
            "max_instructions": max_instructions,
            "max_strings_per_function": max_strings_per_function,
            "min_string_chars": MIN_STRING_CHARS,
            "architecture": info.architecture,
            "bitness": bits,
            "skipped": {
                "not_executable": skipped_not_executable,
                "setup": skipped_setup,
                "no_stack_writes": skipped_no_writes,
            },
        },
    )
    return StackStringReport(
        path=str(path),
        architecture=info.architecture or "unknown",
        bitness=bits,
        functions_scanned=len(targets),
        functions_emulated=functions_emulated,
        functions=tuple(scans),
        strings=tuple(strings),
        evidence=evidence,
        skipped_not_executable=skipped_not_executable,
        skipped_setup=skipped_setup,
        skipped_no_stack_writes=skipped_no_writes,
        warnings=tuple(warnings),
        truncated=truncated,
    )

# ---- public API --------------------------------------------------------------


def extract_stack_strings(
    path: Path,
    *,
    addresses: Sequence[int] | None = None,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    max_strings_per_function: int = DEFAULT_MAX_STRINGS_PER_FUNCTION,
) -> StackStringReport:
    """Recover strings functions build on their stack, by emulating them.

    The binary is loaded with the production loader, each target function is
    emulated on a private unicorn CPU (the
    :mod:`codevanta.analysis.emulate` machinery: same image/stack mapping,
    same ABI seeding, same budget and stop-reason handling), and the stack
    bytes each function wrote are scanned for printable ASCII and UTF-16LE
    runs of at least :data:`MIN_STRING_CHARS` characters.

    Args:
        path: Binary to analyse (only its bytes are read; nothing runs on the
            host).
        addresses: Explicit function start addresses. When given, function
            discovery is skipped entirely, the addresses are validated like
            :func:`emulate.emulate_function` validates its own (an address
            outside an executable section raises), deduplicated and sorted.
            ``None`` or an empty sequence selects discovered candidates
            instead.
        max_functions: Functions to scan at most (1..:data:`MAX_FUNCTIONS`);
            the cut is reported through ``truncated`` and a warning.
        max_instructions: Instruction budget per function
            (1..:data:`MAX_MAX_INSTRUCTIONS`).
        max_strings_per_function: Distinct strings kept per function
            (1..:data:`MAX_STRINGS_PER_FUNCTION`); ``string_count`` keeps
            reporting the honest total.

    Returns:
        A :class:`StackStringReport`. Limitations are never raised: they are
        reported through ``warnings``, the ``skipped`` counters and the
        per-function ``truncated`` flags.

    Raises:
        AnalysisError: When a budget argument is out of range, ``addresses``
            contains a non-positive or non-int entry, an explicit address is
            not inside an executable section with file bytes, or the optional
            unicorn engine is not installed (the message carries the
            emulator's own status and install hint). A file the loader cannot
            parse raises :class:`~codevanta.core.loader.BinaryLoadError`.
    """
    function_limit = _validated_limit("max_functions", max_functions, MAX_FUNCTIONS)
    instruction_limit = _validated_limit(
        "max_instructions", max_instructions, MAX_MAX_INSTRUCTIONS
    )
    string_limit = _validated_limit(
        "max_strings_per_function",
        max_strings_per_function,
        MAX_STRINGS_PER_FUNCTION,
    )
    if addresses:
        _validated_addresses(addresses)
    if not EMULATOR_AVAILABLE:
        raise AnalysisError(
            "stack-string extraction needs the optional unicorn engine: "
            f"{emulate.emulator_status() or 'the unicorn engine could not be imported'}; "
            "install it with 'pip install codevanta[emulation]'"
        )
    info = BinaryLoader().load(path)
    return _extract(
        Path(path),
        info,
        addresses,
        function_limit,
        instruction_limit,
        string_limit,
    )

"""Parse what a dynamic session produced into a bounded, attributable report.

:mod:`codevanta.analysis.dynamic` writes the script; this module reads what the
script printed. It never runs anything, so it is the half of dynamic analysis
that can be tested deterministically and replayed from a saved log.

Two providers, two formats
--------------------------
``gdb``
    :func:`parse_gdb_trace` reads the ``HIT <address> <reg>=<value> ...`` lines the
    generated script prints, the ``BACKTRACE`` marker that follows each one, and
    the ``#N  0x... in ...`` frames ``bt`` emits. Everything else gdb says
    (breakpoint notices, ``Inferior 1 exited``, ``DONE n hits``) is noise and is
    skipped. A ``LIMIT`` line means the session stopped at its own hit ceiling, so
    the report is marked ``truncated``.
``frida``
    :func:`parse_frida_trace` reads the JSON-lines messages the generated hook
    sends (``{"hit": N, "address": "0x...", "tid": ..., "args": [...]}``). A
    malformed line is skipped with a warning instead of aborting the parse;
    ``{"event": "limit"}`` marks the report truncated and ``{"event": "error"}``
    becomes a warning.

Mapping hits onto functions
---------------------------
When a function list (usually :func:`codevanta.core.functions.discover_functions`)
is supplied, every hit is attributed to the candidate that encloses its address:
the greatest candidate start ``<= address`` that either contains the address
within its known ``size`` or, when the size is unknown, still starts before the
next candidate. Addresses outside every candidate stay unattributed rather than
being guessed onto the nearest symbol. ``function_coverage`` counts hits per
attributed function, so a caller can see where a session actually went.

Bounds
------
A parse never reads more than :data:`MAX_TRACE_LINES` lines, keeps at most
:data:`MAX_TRACE_HITS` hits and at most :data:`MAX_BACKTRACE_FRAMES` frames per
hit; a cut is reported through ``truncated`` plus a warning, never silently.
Warnings are capped too, so a corrupt log cannot turn into unbounded memory. The
only exception raised is :class:`~codevanta.core.report.AnalysisError`, and only
for a caller mistake (an out-of-range ``max_lines``/``max_hits``).
"""

from __future__ import annotations

import json
import re
from bisect import bisect_right
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from codevanta.analysis.dynamic import MAX_FRIDA_ARGS
from codevanta.core.functions import FunctionCandidate
from codevanta.core.loader import BinaryInfo, SectionInfo
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "MAX_BACKTRACE_FRAMES",
    "MAX_TRACE_HITS",
    "MAX_TRACE_LINES",
    "MAX_WARNINGS",
    "TraceHit",
    "TraceReport",
    "parse_frida_trace",
    "parse_gdb_trace",
]

#: Hard ceiling on the lines one parse will read.
MAX_TRACE_LINES = 100_000

#: Hard ceiling on the hits one parse will keep.
MAX_TRACE_HITS = 100_000

#: Frames kept per hit, whatever the session printed.
MAX_BACKTRACE_FRAMES = 64

#: Warnings kept per report before the rest are summarised away.
MAX_WARNINGS = 50

#: Longest input snippet echoed back in a warning.
_SNIPPET = 120

#: ``HIT 0x401000 pc=0x401000 sp=0x7ffd...`` -- the line the gdb script prints.
_HIT_LINE = re.compile(
    r"^HIT\s+(?P<address>0x[0-9a-fA-F]+)"
    r"(?P<registers>(?:\s+[A-Za-z][A-Za-z0-9_]*=(?:0x[0-9a-fA-F]+|\d+))*)\s*$"
)

#: ``name=value`` inside a ``HIT`` line's register snapshot.
_REGISTER = re.compile(r"([A-Za-z][A-Za-z0-9_]*)=(0x[0-9a-fA-F]+|\d+)")

#: A line that starts like a hit but does not parse as one.
_HIT_PREFIX = re.compile(r"^HIT\b")

#: The marker the gdb script prints before its ``bt`` frames.
_BACKTRACE_MARKER = re.compile(r"^BACKTRACE\b")

#: ``#3  0x0000000000401000 in ?? ()`` -- one gdb backtrace frame.
_FRAME_LINE = re.compile(r"^#\d+\s+0x(?P<address>[0-9a-fA-F]+)")

#: The line the gdb script prints when it stops at its hit ceiling.
_LIMIT_MARKER = re.compile(r"^LIMIT\b")


@dataclass(frozen=True)
class TraceHit:
    """One recorded visit to one address.

    Attributes:
        index: Position of the hit in the session, as the provider numbered it
            (gdb hits are numbered in parse order; Frida reports its own counter
            and the parser falls back to parse order when that counter is absent).
        kind: ``"breakpoint"`` for a gdb hit, ``"message"`` for a Frida message.
        address: The address the session reported: a file virtual address for gdb
            (its breakpoints are absolute) and a runtime address for Frida.
        function: Start address of the function candidate that encloses
            ``address``, or ``None`` when no candidate does.
        function_name: Name of that candidate, when the candidate has one.
        registers: Register snapshot. gdb supplies the registers its script
            printed; Frida supplies ``tid`` plus ``arg0``..``arg3`` from the
            message, because its messages carry no register dump.
        backtrace: Frame addresses in call order, innermost first; empty for
            Frida, whose messages carry no stack.
    """

    index: int
    kind: str
    address: int
    function: int | None = None
    function_name: str | None = None
    registers: Mapping[str, int] = field(default_factory=dict)
    backtrace: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize the hit for the JSON report (hex addresses, int registers)."""
        return {
            "index": self.index,
            "kind": self.kind,
            "address": f"0x{self.address:x}",
            "function": f"0x{self.function:x}" if self.function is not None else None,
            "function_name": self.function_name,
            "registers": dict(self.registers),
            "backtrace": [f"0x{address:x}" for address in self.backtrace],
        }


@dataclass(frozen=True)
class TraceReport:
    """Everything one session produced, honestly bounded.

    Attributes:
        provider: ``"gdb"`` or ``"frida"``.
        hits: The hits that were kept, in session order.
        total_hits: Hits the parser saw. It exceeds ``len(hits)`` only when a
            ``max_hits`` bound stopped the parser from keeping the tail.
        truncated: ``True`` when the input was cut -- by ``max_lines``, by
            ``max_hits``, or by the session's own ``LIMIT``/``limit`` marker.
        unique_addresses: Distinct hit addresses, ascending.
        function_coverage: Hits per attributed function start address. Functions
            with no hits are absent, and unattributed hits are counted nowhere.
        warnings: Everything that went wrong: malformed lines, foreign messages,
            limits that cut the session.
        evidence: How the report was produced, including the budgets that were in
            effect and, when ``info`` was supplied, the binary it belongs to.
    """

    provider: str
    hits: tuple[TraceHit, ...]
    total_hits: int
    truncated: bool
    unique_addresses: tuple[int, ...]
    function_coverage: Mapping[int, int]
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report for the JSON report (JSON-safe values only)."""
        return {
            "provider": self.provider,
            "hits": [hit.to_dict() for hit in self.hits],
            "total_hits": self.total_hits,
            "truncated": self.truncated,
            "unique_addresses": [f"0x{address:x}" for address in self.unique_addresses],
            "function_coverage": {
                f"0x{address:x}": count for address, count in self.function_coverage.items()
            },
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


class _FunctionIndex:
    """Bisect-based lookup from an address to the candidate that encloses it.

    A candidate's extent comes from its symbol size when the loader knows it, and
    otherwise from the executable section that contains it: a function cannot run
    past the end of its own section. When neither is available the extent is
    unknown, and an address above the start is reported as unattributed instead of
    being guessed onto the function.
    """

    def __init__(
        self,
        functions: Sequence[FunctionCandidate],
        info: BinaryInfo | None = None,
    ) -> None:
        self._starts: list[int] = []
        self._ends: list[int | None] = []
        self._names: list[str | None] = []
        sections = (
            [section for section in getattr(info, "sections", ()) if section.is_executable]
            if info is not None
            else []
        )
        for candidate in sorted(functions, key=lambda item: item.address):
            if candidate.address <= 0:
                continue
            if self._starts and self._starts[-1] == candidate.address:
                continue
            self._starts.append(candidate.address)
            self._ends.append(_candidate_end(candidate, sections))
            self._names.append(candidate.name)

    def locate(self, address: int) -> tuple[int, str | None] | None:
        """Return ``(start, name)`` for the enclosing candidate, or ``None``."""
        position = bisect_right(self._starts, address) - 1
        if position < 0:
            return None
        start = self._starts[position]
        end = self._ends[position]
        if end is not None:
            inside = address < end
        elif position + 1 < len(self._starts):
            # No size and no section: the next candidate's start is the boundary.
            inside = address < self._starts[position + 1]
        else:
            inside = False
        if not inside:
            return None
        return start, self._names[position]


def _candidate_end(candidate: FunctionCandidate, sections: Sequence[SectionInfo]) -> int | None:
    """Return the last address a candidate can occupy, or ``None`` when unknown."""
    size = getattr(candidate, "size", None)
    if isinstance(size, int) and size > 0:
        return candidate.address + size
    for section in sections:
        start = section.virtual_address
        end = start + section.size
        if start <= candidate.address < end:
            return end
    return None


def _snippet(line: str) -> str:
    """Return a quoted, length-bounded excerpt of ``line`` for a warning."""
    text = line if len(line) <= _SNIPPET else line[: _SNIPPET - 3] + "..."
    return repr(text)


def _warn(warnings: list[str], message: str) -> None:
    """Append ``message`` to ``warnings``, capping the list at :data:`MAX_WARNINGS`."""
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)
    elif len(warnings) == MAX_WARNINGS:
        warnings.append(f"further warnings suppressed after {MAX_WARNINGS}")


def _as_int(value: Any) -> int | None:
    """Return ``value`` as an int, accepting ``int`` and ``"0x1f"``-style text."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            return None
    return None


def _require_max_lines(max_lines: int) -> int:
    """Return ``max_lines`` after checking it is a sane positive bound."""
    if isinstance(max_lines, bool) or not isinstance(max_lines, int):
        raise AnalysisError(
            f"max_lines must be an int, got {type(max_lines).__name__}: {max_lines!r}"
        )
    if max_lines < 1:
        raise AnalysisError(f"max_lines must be >= 1, got {max_lines}")
    if max_lines > MAX_TRACE_LINES:
        raise AnalysisError(f"max_lines must be <= {MAX_TRACE_LINES}, got {max_lines}")
    return max_lines


def _require_max_hits(max_hits: int | None) -> int | None:
    """Return ``max_hits`` after checking it is ``None`` or a sane positive bound."""
    if max_hits is None:
        return None
    if isinstance(max_hits, bool) or not isinstance(max_hits, int):
        raise AnalysisError(
            f"max_hits must be an int or None, got {type(max_hits).__name__}: {max_hits!r}"
        )
    if max_hits < 1:
        raise AnalysisError(f"max_hits must be >= 1, got {max_hits}")
    if max_hits > MAX_TRACE_HITS:
        raise AnalysisError(f"max_hits must be <= {MAX_TRACE_HITS}, got {max_hits}")
    return max_hits


def _make_hit(draft: dict[str, Any], functions: _FunctionIndex, kind: str) -> TraceHit:
    """Freeze one parsed draft into a :class:`TraceHit`, attributing its address."""
    address: int = draft["address"]
    located = functions.locate(address)
    start, name = located if located is not None else (None, None)
    return TraceHit(
        index=int(draft["index"]),
        kind=kind,
        address=address,
        function=start,
        function_name=name,
        registers=dict(draft["registers"]),
        backtrace=tuple(draft["backtrace"]),
    )


def _build_report(
    provider: str,
    hits: list[TraceHit],
    *,
    total_hits: int,
    truncated: bool,
    warnings: list[str],
    info: BinaryInfo | None,
    lines_scanned: int,
    max_lines: int,
) -> TraceReport:
    """Assemble the report, counting coverage and building the evidence record."""
    coverage: dict[int, int] = {}
    for hit in hits:
        if hit.function is None:
            continue
        coverage[hit.function] = coverage.get(hit.function, 0) + 1
    extra: dict[str, Any] = {
        "provider": provider,
        "lines_scanned": lines_scanned,
        "line_limit": max_lines,
        "truncated": truncated,
        "hits": total_hits,
        "kept_hits": len(hits),
        "warning_count": len(warnings),
    }
    if info is not None:
        extra["format"] = info.format
        extra["architecture"] = info.architecture
        extra["image_base"] = f"0x{info.image_base:x}"
    evidence = Evidence(
        source=f"{provider}.trace",
        method=f"parse_{provider}_trace",
        confidence=Confidence.HIGH if warnings else Confidence.CERTAIN,
        detail=f"parsed {total_hits} hit(s) from {lines_scanned} line(s)",
        extra=extra,
    )
    return TraceReport(
        provider=provider,
        hits=tuple(hits),
        total_hits=total_hits,
        truncated=truncated,
        unique_addresses=tuple(sorted({hit.address for hit in hits})),
        function_coverage=coverage,
        warnings=tuple(warnings),
        evidence=evidence,
    )


# --------------------------------------------------------------------------- #
# gdb traces
# --------------------------------------------------------------------------- #


def parse_gdb_trace(
    text: str,
    *,
    info: BinaryInfo | None = None,
    functions: Sequence[FunctionCandidate] = (),
    max_lines: int = MAX_TRACE_LINES,
    max_hits: int | None = None,
) -> TraceReport:
    """Parse the output of a generated gdb session script.

    One ``HIT 0x... name=0x...`` line becomes one :class:`TraceHit` of kind
    ``"breakpoint"``; the frames printed after the following ``BACKTRACE`` marker
    become its ``backtrace``. Everything else is ignored, except a ``LIMIT`` line,
    which marks the report ``truncated`` because the session stopped at its own
    ceiling. A line that starts with ``HIT`` but does not parse produces a warning
    and never raises.

    Args:
        text: The captured gdb output.
        info: Binary metadata for context. It never changes which hits are
            reported; it is recorded in the evidence so the report can be tied to
            the file the session ran against.
        functions: Candidates used to attribute each hit to a function.
        max_lines: Line budget, ``1 <= max_lines <=`` :data:`MAX_TRACE_LINES`.
        max_hits: Hit budget, or ``None``. Hits beyond it are counted in
            ``total_hits`` but not kept, and the report is ``truncated``.

    Raises:
        AnalysisError: ``max_lines`` or ``max_hits`` is out of range.
    """
    line_limit = _require_max_lines(max_lines)
    hit_limit = _require_max_hits(max_hits)
    index = _FunctionIndex(functions, info)

    lines = text.splitlines()
    warnings: list[str] = []
    truncated = False
    if len(lines) > line_limit:
        lines = lines[:line_limit]
        truncated = True
        _warn(warnings, f"input truncated to the first {line_limit} line(s)")

    hits: list[TraceHit] = []
    total_hits = 0
    draft: dict[str, Any] | None = None
    in_backtrace = False
    hit_limit_reported = False

    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        match = _HIT_LINE.match(stripped)
        if match is not None:
            if draft is not None:
                hits.append(_make_hit(draft, index, "breakpoint"))
                draft = None
            total_hits += 1
            if hit_limit is not None and len(hits) >= hit_limit:
                if not hit_limit_reported:
                    truncated = True
                    hit_limit_reported = True
                    _warn(
                        warnings,
                        f"hit limit {hit_limit} reached; further hits are counted but "
                        "not kept",
                    )
                continue
            draft = {
                "index": total_hits,
                "address": int(match.group("address"), 16),
                "registers": {
                    name: int(value, 0)
                    for name, value in _REGISTER.findall(match.group("registers"))
                },
                "backtrace": [],
            }
            in_backtrace = False
            continue
        if _HIT_PREFIX.match(stripped):
            _warn(warnings, f"line {number}: unparseable HIT line {_snippet(stripped)}")
            continue
        if _LIMIT_MARKER.match(stripped):
            truncated = True
            _warn(
                warnings,
                f"line {number}: the session stopped at its hit limit ({_snippet(stripped)})",
            )
            continue
        if _BACKTRACE_MARKER.match(stripped):
            in_backtrace = True
            continue
        if in_backtrace:
            frame = _FRAME_LINE.match(stripped)
            if frame is not None:
                if draft is not None and len(draft["backtrace"]) < MAX_BACKTRACE_FRAMES:
                    draft["backtrace"].append(int(frame.group("address"), 16))
                continue
        # Anything else is gdb noise: breakpoint notices, exit messages, "DONE".

    if draft is not None:
        hits.append(_make_hit(draft, index, "breakpoint"))

    return _build_report(
        "gdb",
        hits,
        total_hits=total_hits,
        truncated=truncated,
        warnings=warnings,
        info=info,
        lines_scanned=len(lines),
        max_lines=line_limit,
    )


# --------------------------------------------------------------------------- #
# frida traces
# --------------------------------------------------------------------------- #


def parse_frida_trace(
    text: str,
    *,
    info: BinaryInfo | None = None,
    functions: Sequence[FunctionCandidate] = (),
    max_lines: int = MAX_TRACE_LINES,
    max_hits: int | None = None,
) -> TraceReport:
    """Parse the JSON-lines messages a generated Frida script sends.

    One ``{"hit": N, "address": "0x...", "tid": ..., "args": [...]}`` message
    becomes one :class:`TraceHit` of kind ``"message"``, with ``tid`` and
    ``arg0``..``arg3`` in ``registers`` (Frida messages carry no register dump and
    no stack). ``{"event": "limit"}`` marks the report ``truncated``;
    ``{"event": "error"}`` and any other unrecognised message become warnings. A
    malformed line is skipped with a warning instead of aborting the parse.

    Args:
        text: The captured frida output, one JSON message per line.
        info: Binary metadata for context; recorded in the evidence only.
        functions: Candidates used to attribute each hit to a function.
        max_lines: Line budget, ``1 <= max_lines <=`` :data:`MAX_TRACE_LINES`.
        max_hits: Hit budget, or ``None``. Hits beyond it are counted in
            ``total_hits`` but not kept, and the report is ``truncated``.

    Raises:
        AnalysisError: ``max_lines`` or ``max_hits`` is out of range.
    """
    line_limit = _require_max_lines(max_lines)
    hit_limit = _require_max_hits(max_hits)
    index = _FunctionIndex(functions, info)

    lines = text.splitlines()
    warnings: list[str] = []
    truncated = False
    if len(lines) > line_limit:
        lines = lines[:line_limit]
        truncated = True
        _warn(warnings, f"input truncated to the first {line_limit} line(s)")

    hits: list[TraceHit] = []
    total_hits = 0
    hit_limit_reported = False

    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except ValueError:
            _warn(warnings, f"line {number}: malformed JSON message {_snippet(stripped)}")
            continue
        if not isinstance(payload, dict):
            _warn(
                warnings,
                f"line {number}: message is not a JSON object {_snippet(stripped)}",
            )
            continue
        if "hit" not in payload:
            event = payload.get("event")
            if event == "limit":
                truncated = True
                _warn(warnings, f"line {number}: the session detached its hooks at the hit limit")
            elif event == "error":
                message = payload.get("message") or "no message"
                _warn(warnings, f"line {number}: provider error: {message}")
            else:
                _warn(
                    warnings,
                    f"line {number}: message without a hit or a known event "
                    f"{_snippet(stripped)}",
                )
            continue
        address = _as_int(payload.get("address"))
        if address is None:
            _warn(
                warnings,
                f"line {number}: hit without a usable address {_snippet(stripped)}",
            )
            continue
        total_hits += 1
        if hit_limit is not None and len(hits) >= hit_limit:
            if not hit_limit_reported:
                truncated = True
                hit_limit_reported = True
                _warn(
                    warnings,
                    f"hit limit {hit_limit} reached; further hits are counted but not kept",
                )
            continue

        registers: dict[str, int] = {}
        tid = _as_int(payload.get("tid"))
        if tid is not None:
            registers["tid"] = tid
        arguments = payload.get("args")
        if isinstance(arguments, list):
            for position, value in enumerate(arguments[:MAX_FRIDA_ARGS]):
                parsed = _as_int(value)
                if parsed is None:
                    _warn(
                        warnings,
                        f"line {number}: argument {position} is not a number "
                        f"({value!r}); skipped",
                    )
                    continue
                registers[f"arg{position}"] = parsed
        elif arguments is not None:
            _warn(warnings, f"line {number}: 'args' is not a list; ignored")

        reported = _as_int(payload.get("hit"))
        hits.append(
            _make_hit(
                {
                    "index": reported if reported is not None else total_hits,
                    "address": address,
                    "registers": registers,
                    "backtrace": [],
                },
                index,
                "message",
            )
        )

    return _build_report(
        "frida",
        hits,
        total_hits=total_hits,
        truncated=truncated,
        warnings=warnings,
        info=info,
        lines_scanned=len(lines),
        max_lines=line_limit,
    )

"""Live gdb debug sessions over the GDB/MI machine interface.

:mod:`codevanta.analysis.dynamic` *writes* session scripts and
:mod:`codevanta.analysis.debugger` runs them batch-style; this module is the one
layer that **owns** a live gdb process: it launches the target under
``gdb --interpreter=mi2``, speaks the machine interface over the debugger's
stdio pipes, and shuts the process down again, verifying the exit. It closes the
gap where ``codevanta attach`` only ever *printed* a command line and nothing in
the codebase actually launched anything.

What a session can do
---------------------

Each capability is one method returning a frozen, JSON-safe dataclass whose
provenance is an :class:`~codevanta.evidence.models.Evidence` record naming the
MI command that produced it:

* :meth:`DebugSession.break_at` -- ``-break-insert`` at a function name or
  ``*<address>``;
* :meth:`DebugSession.run`, :meth:`DebugSession.continue_execution`,
  :meth:`DebugSession.step_into`, :meth:`DebugSession.step_over` -- the
  ``-exec-*`` family, each waiting for the matching ``*stopped`` record;
* :meth:`DebugSession.read_registers` -- ``-data-list-register-names`` plus
  ``-data-list-register-values``;
* :meth:`DebugSession.read_memory` -- ``-data-read-memory-bytes``;
* :meth:`DebugSession.backtrace` -- ``-stack-list-frames``;
* :meth:`DebugSession.quit` -- ``-gdb-exit`` plus clean-shutdown verification.

Bounded by construction
-----------------------

Every command runs under a wall-clock budget: the live transport reads MI
output on a private thread and raises
:class:`~codevanta.core.report.AnalysisError` when the prompt does not come
back in time. Memory reads, frame lists and warning lists are capped. Nothing
here grows without bound, and a timed-out session is still torn down.

Typed failures, never tracebacks
--------------------------------

A missing gdb executable, a target gdb refuses to load, an MI ``^error`` or a
command that misses its budget all raise :class:`AnalysisError` naming what is
missing or wrong -- the same contract the ``attach``/``trace`` precedent uses,
so a Windows workstation (a slim CI host) without gdb gets a clean,
caller-correctable error instead of a traceback. :func:`gdb_available` and
:func:`gdb_status` probe ``PATH`` with ``shutil.which`` and never run gdb.

Testing without gdb
-------------------

The transport is injectable: anything honouring the :class:`MITransport`
protocol (``send`` / ``read_until_prompt`` / ``shutdown``) drives a
:class:`DebugSession` identically. The MI *parsers* are pure functions
(:func:`parse_mi_line`, :func:`parse_mi_value`, :func:`parse_mi_transcript` and
the ``*_from_payload`` helpers), so canned MI transcripts -- byte for byte as
gdb prints them -- exercise the whole result-building pipeline on a machine
with no debugger at all.
"""

from __future__ import annotations

import queue
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEBUG_ACTIONS",
    "DEFAULT_TIMEOUT",
    "MAX_BACKTRACE_FRAMES",
    "MAX_MEMORY_BYTES",
    "MAX_REGISTERS",
    "MITransport",
    "BacktraceResult",
    "BreakpointInfo",
    "BreakpointResult",
    "DebugSession",
    "FrameInfo",
    "GdbMiProcess",
    "MemoryResult",
    "QuitResult",
    "RegistersResult",
    "RegisterValue",
    "StopInfo",
    "StopResult",
    "backtrace_from_payload",
    "breakpoint_from_payload",
    "gdb_available",
    "gdb_status",
    "memory_from_payload",
    "parse_location",
    "parse_mi_line",
    "parse_mi_transcript",
    "parse_mi_value",
    "registers_from_payloads",
    "run_debug",
    "stop_from_payload",
]

#: Default wall-clock budget for one MI command, in seconds.
DEFAULT_TIMEOUT = 60.0

#: The prompt the machine interface prints when it is ready for the next command.
PROMPT = "(gdb) "

#: Hard ceiling on the bytes one memory read may request.
MAX_MEMORY_BYTES = 4096

#: Hard ceiling on the frames one backtrace may request.
MAX_BACKTRACE_FRAMES = 64

#: Hard ceiling on the registers one read keeps.
MAX_REGISTERS = 200

#: Hard ceiling on the MI lines one command will read back.
MAX_MI_LINES = 100_000

#: Warnings kept on one result before the rest are summarised away.
MAX_WARNINGS = 20

#: ``gdb`` argument vector prefix: quiet, no init files, machine interface.
_MI_ARGV_PREFIX = ("gdb", "-q", "--nx", "--interpreter=mi2")

_GDB_INSTALL_HINT = (
    "'apt install gdb' (Linux), 'brew install gdb' (macOS) or the MinGW gdb package (Windows)"
)

#: Where every live result's evidence comes from: the MI channel itself.
_EVIDENCE_SOURCE = "gdb.mi2"


def _mi_evidence(method: str, detail: str) -> Evidence:
    """Return the provenance record one live result carries.

    Live debugger observations are the strongest evidence a dynamic analysis
    can produce -- the debugger itself read the register/memory/stack -- but
    they describe *one run*, so the detail always says so.
    """
    return Evidence(
        source=_EVIDENCE_SOURCE,
        method=method,
        confidence=Confidence.HIGH,
        address=None,
        detail=f"{detail} (one-run runtime evidence, not a static property)",
    )


def _cap_warnings(warnings: list[str]) -> tuple[str, ...]:
    """Fold a warning list down to :data:`MAX_WARNINGS`, never silently."""
    if len(warnings) <= MAX_WARNINGS:
        return tuple(warnings)
    hidden = len(warnings) - MAX_WARNINGS
    return (*warnings[:MAX_WARNINGS], f"{hidden} further warning(s) suppressed")


# --------------------------------------------------------------------------- #
# MI transcript parsing (pure functions, no process involved)
# --------------------------------------------------------------------------- #

#: C-style escapes MI string literals use; anything else decodes to itself.
_MI_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "'": "'", "\\": "\\"}

#: Result record prefix: the synchronous answer to one command (``token^done``).
_RESULT_RECORD = re.compile(r"^(?P<token>\d*)\^(?P<class>done|error|connected|running|exit)")

#: Async/status record prefix: ``*stopped`` / ``*running`` / ``=breakpoint-created``.
_ASYNC_RECORD = re.compile(r"^(?P<token>\d*)(?P<mark>[*=])(?P<name>[a-z-]+)")

#: Stream output: console ``~``, log ``&``, target ``@``.
_STREAM_RECORD = re.compile(r"^(?P<stream>[~&@])(?P<body>.*)")


class _MIParser:
    """Recursive-descent parser over one MI value expression.

    MI values are ``"strings"`` (C-style escapes), ``[lists,of,values]`` and
    ``{tuples="of",results}``. A list may mix bare values and ``key=value``
    results. Parsing a malformed expression raises :class:`AnalysisError`
    naming the problem -- it never returns a partial value, because a
    mis-parsed register or memory payload would be dressed up as evidence.
    """

    def __init__(self, text: str) -> None:
        self._text = text
        self._pos = 0

    def parse(self) -> Any:
        """Parse the whole text as one value; trailing garbage is an error."""
        value = self._parse_value()
        self._skip_spaces()
        if self._pos != len(self._text):
            raise AnalysisError(
                f"malformed MI value: unexpected {self._text[self._pos:]!r} "
                f"after the value in {self._text[:80]!r}"
            )
        return value

    def _skip_spaces(self) -> None:
        while self._pos < len(self._text) and self._text[self._pos] == " ":
            self._pos += 1

    def _parse_value(self) -> Any:
        self._skip_spaces()
        if self._pos >= len(self._text):
            raise AnalysisError(
                f"malformed MI value: {self._text[:80]!r} ends where a value was expected"
            )
        current = self._text[self._pos]
        if current == '"':
            return self._parse_string()
        if current == "[":
            return self._parse_list()
        if current == "{":
            return self._parse_tuple()
        raise AnalysisError(
            "malformed MI value: expected a string, list or tuple, got "
            f"{self._text[self._pos : self._pos + 12]!r}"
        )

    def _parse_string(self) -> str:
        self._pos += 1  # opening quote
        chunks: list[str] = []
        while self._pos < len(self._text):
            current = self._text[self._pos]
            if current == '"':
                self._pos += 1
                return "".join(chunks)
            if current == "\\":
                self._pos += 1
                if self._pos >= len(self._text):
                    break
                escape = self._text[self._pos]
                chunks.append(_MI_ESCAPES.get(escape, escape))
                self._pos += 1
                continue
            chunks.append(current)
            self._pos += 1
        raise AnalysisError(f"malformed MI value: unterminated string in {self._text[:80]!r}")

    def _parse_list(self) -> list[Any]:
        self._pos += 1  # opening bracket
        items: list[Any] = []
        while True:
            self._skip_spaces()
            if self._pos >= len(self._text):
                raise AnalysisError("malformed MI value: unterminated list")
            if self._text[self._pos] == "]":
                self._pos += 1
                return items
            items.append(self._parse_element())
            self._skip_spaces()
            if self._pos < len(self._text) and self._text[self._pos] == ",":
                self._pos += 1

    def _parse_tuple(self) -> dict[str, Any]:
        self._pos += 1  # opening brace
        results: dict[str, Any] = {}
        while True:
            self._skip_spaces()
            if self._pos >= len(self._text):
                raise AnalysisError("malformed MI value: unterminated tuple")
            if self._text[self._pos] == "}":
                self._pos += 1
                return results
            key = self._parse_key()
            self._skip_spaces()
            if self._pos >= len(self._text) or self._text[self._pos] != "=":
                raise AnalysisError(f"malformed MI value: expected '=' after {key!r}")
            self._pos += 1
            results[key] = self._parse_value()
            self._skip_spaces()
            if self._pos < len(self._text) and self._text[self._pos] == ",":
                self._pos += 1

    def _parse_key(self) -> str:
        match = re.match(r"[-_.\w]+", self._text[self._pos :])
        if match is None:
            raise AnalysisError(
                "malformed MI value: expected a result key at "
                f"{self._text[self._pos : self._pos + 12]!r}"
            )
        self._pos += len(match.group(0))
        return match.group(0)

    def _parse_element(self) -> Any:
        """Parse one list element: a bare value or a ``key=value`` result."""
        match = re.match(r"([-_.\w]+)=(?=[\"[{])", self._text[self._pos :])
        if match is not None:
            key = match.group(1)
            self._pos += len(match.group(0))
            return {key: self._parse_value()}
        return self._parse_value()


def parse_mi_value(text: str) -> Any:
    """Parse one complete MI value expression into ``str``/``list``/``dict``.

    Raises:
        AnalysisError: The expression is malformed or has trailing characters.
    """
    return _MIParser(text).parse()



@dataclass(frozen=True)
class MIRecord:
    """One classified line of MI output.

    Attributes:
        kind: ``"result"`` (synchronous answer), ``"exec"`` (``*stopped`` ...),
            ``"notify"`` (``=breakpoint-created`` ...), ``"console"``/``"log"``/
            ``"target"`` (stream output), ``"prompt"`` (ready) or ``"noise"``
            (anything the machine interface itself would drop, such as a
            residual CLI banner line).
        token: The command token the record answers, when it carried one.
        result_class: For ``kind == "result"``: ``done``, ``error``, ...
        async_class: For exec/notify records: ``stopped``, ``running``, ...
        text: Stream-output payload (already unescaped), ``""`` otherwise.
        payload: Parsed ``key=value`` results; ``None`` when there is no
            payload or parsing it failed (``raw`` keeps the line for warnings).
        raw: The line exactly as gdb printed it.
    """

    kind: str
    token: str = ""
    result_class: str | None = None
    async_class: str | None = None
    text: str = ""
    payload: Any = None
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the record (JSON-safe; payload kept only when parsed)."""
        return {
            "kind": self.kind,
            "token": self.token,
            "result_class": self.result_class,
            "async_class": self.async_class,
            "text": self.text,
            "payload": self.payload,
        }


def parse_mi_line(line: str) -> MIRecord:
    """Classify one line of MI output without ever raising.

    A line the machine interface would itself drop -- a CLI banner gdb prints
    before the interpreter takes over, a blank line -- classifies as
    ``"noise"``; a syntactically broken record still classifies by its prefix
    but carries ``payload=None``, so callers warn instead of guessing.
    """
    raw = line.rstrip("\r\n")
    if not raw.strip():
        return MIRecord(kind="noise", raw=raw)
    if raw.strip() == PROMPT.strip():
        return MIRecord(kind="prompt", raw=raw)
    stream = _STREAM_RECORD.match(raw)
    if stream is not None:
        body = stream.group("body")
        text: str = body
        if body.startswith('"'):
            try:
                parsed = parse_mi_value(body)
                if isinstance(parsed, str):
                    text = parsed
            except AnalysisError:
                text = body
        kinds = {"~": "console", "&": "log", "@": "target"}
        return MIRecord(kind=kinds[stream.group("stream")], text=text, raw=raw)
    result = _RESULT_RECORD.match(raw)
    if result is not None:
        return MIRecord(
            kind="result",
            token=result.group("token"),
            result_class=result.group("class"),
            payload=_parse_record_payload(raw, result.end()),
            raw=raw,
        )
    async_record = _ASYNC_RECORD.match(raw)
    if async_record is not None:
        mark = async_record.group("mark")
        return MIRecord(
            kind="exec" if mark == "*" else "notify",
            token=async_record.group("token"),
            async_class=async_record.group("name"),
            payload=_parse_record_payload(raw, async_record.end()),
            raw=raw,
        )
    return MIRecord(kind="noise", raw=raw)


def _parse_record_payload(raw: str, after: int) -> Any:
    """Parse the ``,{...}`` payload after a record prefix, ``None`` on failure."""
    payload_text = raw[after:]
    if not payload_text.startswith(","):
        return None
    try:
        parsed = parse_mi_value("{" + payload_text[1:] + "}")
    except AnalysisError:
        return None
    return parsed if isinstance(parsed, dict) else None


def parse_mi_transcript(lines: list[str]) -> list[MIRecord]:
    """Classify a whole transcript, bounded by :data:`MAX_MI_LINES` lines.

    Lines past the bound are dropped -- a command consumer notices through the
    missing prompt or result record and raises, so the bound can never
    silently truncate a live result into a wrong one.
    """
    return [parse_mi_line(line) for line in lines[:MAX_MI_LINES]]


def _payload_dict(record: MIRecord) -> dict[str, Any]:
    """Return a record's parsed payload dict, or a typed error."""
    if isinstance(record.payload, dict):
        return record.payload
    raise AnalysisError(
        f"malformed MI {record.kind} record could not be parsed into a payload: "
        f"{record.raw[:120]!r}"
    )



# --------------------------------------------------------------------------- #
# Result builders (pure: payload dicts in, typed results out)
# --------------------------------------------------------------------------- #


def _mi_int(text: Any) -> int | None:
    """Parse an MI numeric field like ``"0x401000"`` or ``"1"``, else ``None``."""
    if not isinstance(text, str) or not text:
        return None
    stripped = text.strip()
    try:
        return int(stripped, 16) if stripped.lower().startswith("0x") else int(stripped, 10)
    except ValueError:
        return None


def breakpoint_from_payload(payload: dict[str, Any]) -> BreakpointInfo:
    """Build a :class:`BreakpointInfo` from an MI ``bkpt={...}`` tuple.

    gdb reports a pending breakpoint with ``addr="<PENDING><location>"``; that
    becomes ``address=None`` with ``pending`` set -- honest about what the
    debugger actually created rather than invented.
    """
    raw_addr = payload.get("addr")
    pending = isinstance(raw_addr, str) and raw_addr.startswith("<PENDING>")
    address = None if pending else _mi_int(raw_addr)
    number = _mi_int(payload.get("number"))
    return BreakpointInfo(
        number=0 if number is None else number,
        address=address,
        function=payload.get("func") if isinstance(payload.get("func"), str) else None,
        pending=pending or address is None,
    )


def stop_from_payload(payload: dict[str, Any]) -> StopInfo:
    """Build a :class:`StopInfo` from a ``*stopped,...`` payload."""
    frame = payload.get("frame")
    frame_dict = frame if isinstance(frame, dict) else {}
    reason = payload.get("reason")
    thread_id = payload.get("thread-id")
    return StopInfo(
        reason=reason if isinstance(reason, str) else "unknown",
        breakpoint_number=_mi_int(payload.get("bkptno")),
        address=_mi_int(frame_dict.get("addr")),
        function=frame_dict.get("func") if isinstance(frame_dict.get("func"), str) else None,
        thread_id=thread_id if isinstance(thread_id, str) else None,
    )


def backtrace_from_payload(payload: dict[str, Any], *, requested: int) -> BacktraceResult:
    """Build frames from a ``-stack-list-frames`` payload, capped as requested."""
    stack = payload.get("stack")
    entries = stack if isinstance(stack, list) else []
    frames: list[FrameInfo] = []
    for entry in entries[:requested]:
        if not isinstance(entry, dict):
            continue
        frame = entry.get("frame")
        if not isinstance(frame, dict):
            frame = entry
        file_name = frame.get("file")
        line = frame.get("line")
        frames.append(
            FrameInfo(
                level=_mi_int(frame.get("level")),
                address=_mi_int(frame.get("addr")),
                function=frame.get("func") if isinstance(frame.get("func"), str) else None,
                source=(
                    f"{file_name}:{line}"
                    if isinstance(file_name, str) and line is not None
                    else None
                ),
            )
        )
    return BacktraceResult(frames=tuple(frames), truncated=len(entries) > requested)


def registers_from_payloads(names: Any, values: Any) -> RegistersResult:
    """Zip ``-data-list-register-names`` and ``-values`` output by index.

    A register the value read did not cover (or whose value gdb left empty,
    which happens before the program starts on some targets) keeps its name
    with ``value=None`` -- never a fabricated ``0x0``.
    """
    name_list = (
        [item for item in names if isinstance(item, str)] if isinstance(names, list) else []
    )
    value_map: dict[int, str] = {}
    if isinstance(values, list):
        for entry in values:
            if isinstance(entry, dict):
                number = _mi_int(entry.get("number"))
                text = entry.get("value")
                if number is not None and isinstance(text, str) and text.strip():
                    value_map[number] = text.strip()
    registers = tuple(
        RegisterValue(number=index, name=name, value=value_map.get(index))
        for index, name in enumerate(name_list[:MAX_REGISTERS])
    )
    return RegistersResult(registers=registers, truncated=len(name_list) > MAX_REGISTERS)


def memory_from_payload(
    payload: dict[str, Any], *, requested_address: int, requested_length: int
) -> MemoryResult:
    """Build a :class:`MemoryResult` from ``-data-read-memory-bytes`` output.

    gdb may return fewer bytes than requested (a read running off the end of a
    mapped region comes back shorter); the result records the *actual* byte
    count and flags ``short_read`` rather than padding.
    """
    memory = payload.get("memory")
    blocks = memory if isinstance(memory, list) else []
    contents = ""
    begin: int | None = None
    for block in blocks:
        if isinstance(block, dict) and isinstance(block.get("contents"), str):
            contents = block["contents"].strip()
            begin = _mi_int(block.get("begin")) or begin
    if len(contents) % 2 == 1:
        raise AnalysisError(
            f"malformed MI memory read: odd-length contents ({len(contents)} characters)"
        )
    actual_bytes = len(contents) // 2
    return MemoryResult(
        address=begin if begin is not None else requested_address,
        requested_length=requested_length,
        length=actual_bytes,
        contents_hex=contents,
        short_read=actual_bytes < requested_length,
    )



# --------------------------------------------------------------------------- #
# Typed results (frozen dataclasses with provenance)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class BreakpointInfo:
    """One breakpoint gdb actually created.

    Attributes:
        number: The debugger's breakpoint number (``bkptno`` for later hits).
        address: The resolved address, or ``None`` for a pending breakpoint.
        function: The symbol name gdb resolved, when it did.
        pending: ``True`` when gdb could not resolve the location yet.
    """

    number: int
    address: int | None
    function: str | None = None
    pending: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize (JSON-safe; a ``None`` address stays ``null``)."""
        return {
            "number": self.number,
            "address": None if self.address is None else f"0x{self.address:x}",
            "function": self.function,
            "pending": self.pending,
        }


@dataclass(frozen=True)
class BreakpointResult:
    """Answer to ``break_at``: the breakpoint plus its provenance."""

    breakpoint: BreakpointInfo
    warnings: tuple[str, ...] = ()
    evidence: Evidence = field(
        default_factory=lambda: _mi_evidence(
            "-break-insert", "breakpoint created by -break-insert"
        )
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize for ``--json`` / MCP (JSON-safe values only)."""
        return {
            "breakpoint": self.breakpoint.to_dict(),
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class StopInfo:
    """Why and where the target stopped, straight from ``*stopped``.

    Attributes:
        reason: MI stop reason: ``breakpoint-hit``, ``end-stepping-range``,
            ``exited-normally``, ``exited-signalled`` ... ``unknown`` when gdb
            named none (a plain ``*stopped``).
        breakpoint_number: Which breakpoint hit, when the reason was a hit.
        address: Stop address from the stop frame, when reported.
        function: Symbol under the stop frame, when resolved.
        thread_id: MI thread id the stop belongs to.
    """

    reason: str
    breakpoint_number: int | None = None
    address: int | None = None
    function: str | None = None
    thread_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize (JSON-safe; ``None`` stays ``null``)."""
        return {
            "reason": self.reason,
            "breakpoint_number": self.breakpoint_number,
            "address": None if self.address is None else f"0x{self.address:x}",
            "function": self.function,
            "thread_id": self.thread_id,
        }


@dataclass(frozen=True)
class StopResult:
    """Answer to run / continue / step / next: where the target stopped."""

    stop: StopInfo
    warnings: tuple[str, ...] = ()
    evidence: Evidence = field(
        default_factory=lambda: _mi_evidence(
            "-exec-continue", "target stop reported by -exec-*"
        )
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize for ``--json`` / MCP."""
        return {
            "stop": self.stop.to_dict(),
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }



@dataclass(frozen=True)
class RegisterValue:
    """One register: its MI number, its name and its hex value.

    ``value`` is ``None`` when gdb listed the register but reported no usable
    value for it (for example before the program has started).
    """

    number: int
    name: str
    value: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize (JSON-safe)."""
        return {"number": self.number, "name": self.name, "value": self.value}


@dataclass(frozen=True)
class RegistersResult:
    """Answer to ``read_registers``: the register file snapshot."""

    registers: tuple[RegisterValue, ...]
    truncated: bool = False
    warnings: tuple[str, ...] = ()
    evidence: Evidence = field(
        default_factory=lambda: _mi_evidence(
            "-data-list-register-names/-values", "register file snapshot"
        )
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize for ``--json`` / MCP."""
        return {
            "registers": [register.to_dict() for register in self.registers],
            "count": len(self.registers),
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class MemoryResult:
    """Answer to ``read_memory``: raw bytes read from the live target."""

    address: int
    requested_length: int
    length: int
    contents_hex: str
    short_read: bool
    warnings: tuple[str, ...] = ()
    evidence: Evidence = field(
        default_factory=lambda: _mi_evidence(
            "-data-read-memory-bytes", "memory bytes read from the live process"
        )
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize for ``--json`` / MCP."""
        return {
            "address": f"0x{self.address:x}",
            "requested_length": self.requested_length,
            "length": self.length,
            "contents_hex": self.contents_hex,
            "short_read": self.short_read,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class FrameInfo:
    """One backtrace frame: level, address, symbol and source location."""

    level: int | None
    address: int | None
    function: str | None = None
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize (JSON-safe; ``None`` stays ``null``)."""
        return {
            "level": self.level,
            "address": None if self.address is None else f"0x{self.address:x}",
            "function": self.function,
            "source": self.source,
        }


@dataclass(frozen=True)
class BacktraceResult:
    """Answer to ``backtrace``: the frame walk at the current stop."""

    frames: tuple[FrameInfo, ...]
    truncated: bool = False
    warnings: tuple[str, ...] = ()
    evidence: Evidence = field(
        default_factory=lambda: _mi_evidence("-stack-list-frames", "backtrace frames")
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize for ``--json`` / MCP."""
        return {
            "frames": [frame.to_dict() for frame in self.frames],
            "count": len(self.frames),
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class QuitResult:
    """Answer to ``quit``: whether the gdb process really went away.

    ``clean`` is ``True`` only when gdb exited on its own (``-gdb-exit``
    honoured, exit code ``0``); a process that had to be terminated or killed
    reports ``clean=False`` and says so in ``warnings``.
    """

    clean: bool
    exit_code: int | None
    warnings: tuple[str, ...] = ()
    evidence: Evidence = field(
        default_factory=lambda: _mi_evidence("-gdb-exit", "debugger process shutdown")
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize for ``--json`` / MCP."""
        return {
            "clean": self.clean,
            "exit_code": self.exit_code,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }



# --------------------------------------------------------------------------- #
# Availability probing (the attach/trace precedent)
# --------------------------------------------------------------------------- #


def gdb_available() -> bool:
    """Probe ``PATH`` for the gdb executable. Never runs gdb; cannot fail."""
    return shutil.which("gdb") is not None


def gdb_status() -> dict[str, str]:
    """Return ``{"available": "true"/"false", "reason": ...}`` for rendering.

    The reason names where gdb was found, or how to install it, mirroring the
    ``codevanta attach`` availability line.
    """
    executable = shutil.which("gdb")
    if executable:
        return {
            "available": "true",
            "reason": f"gdb found on PATH ({executable}); live MI sessions can launch",
        }
    return {
        "available": "false",
        "reason": f"gdb is not on PATH; install it with {_GDB_INSTALL_HINT}",
    }


def _require_gdb() -> str:
    """Return the gdb executable path, or raise the typed unavailable error."""
    executable = shutil.which("gdb")
    if executable is None:
        raise AnalysisError(
            "gdb is not on PATH, so no live debug session can be launched; "
            f"install it with {_GDB_INSTALL_HINT} and retry "
            "(gdb_available() reports whether it is)"
        )
    return executable


# --------------------------------------------------------------------------- #
# Transport: the live gdb process
# --------------------------------------------------------------------------- #


class MITransport(Protocol):
    """What a session needs from the pipe to gdb.

    The live :class:`GdbMiProcess` implements it over ``subprocess.Popen``;
    tests drive :class:`DebugSession` with canned doubles honouring the same
    three methods.
    """

    def send(self, command: str) -> None:
        """Write one MI command line (token prefix and newline included)."""
        ...

    def read_until_prompt(self, timeout: float) -> list[str]:
        """Read raw lines until the MI prompt; raise ``AnalysisError`` on timeout."""
        ...

    def shutdown(self, timeout: float) -> tuple[int | None, bool]:
        """Tear the process down; return ``(exit_code, clean)``. Safe to repeat."""
        ...


class GdbMiProcess:
    """Own the gdb child process and speak MI over its stdio pipes.

    Output is read by a daemon thread into a queue, which is what makes
    ``read_until_prompt`` able to *time out* portably -- Windows pipes have no
    selectable timeouts. A command that misses its budget raises
    :class:`AnalysisError`; the process itself is only ever torn down through
    :meth:`shutdown`, which verifies the exit and escalates terminate -> kill
    when gdb ignores the polite path.
    """

    def __init__(
        self, argv: list[str], *, target: str | None = None, exit_grace: float = 5.0
    ) -> None:
        self._exit_grace = exit_grace
        self._queue: queue.Queue[str] = queue.Queue()
        self._closed = False
        command = [*argv, *([target] if target else [])]
        try:
            self._process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            raise AnalysisError(
                f"the gdb executable {command[0]!r} could not be launched: it is missing; "
                "install gdb and make sure it is on PATH "
                "(gdb_available() reports whether it is)"
            ) from exc
        except OSError as exc:
            raise AnalysisError(f"gdb could not be launched: {exc}") from exc
        self._reader = threading.Thread(
            target=self._pump,
            args=(self._process.stdout,),
            daemon=True,
            name="codevanta-gdb-mi-reader",
        )
        self._reader.start()

    @property
    def alive(self) -> bool:
        """Whether the gdb process is still running."""
        return self._process.poll() is None



    def _pump(self, stream: Any) -> None:
        """Push every output line into the queue until gdb closes the pipe."""
        try:
            for line in stream:
                self._queue.put(line)
        except (OSError, ValueError):  # pragma: no cover - torn-down pipes
            pass

    def send(self, command: str) -> None:
        """Write one MI command line; raise when the process is gone."""
        if not self.alive:
            raise AnalysisError(
                f"the gdb process has exited (code {self._process.returncode}); "
                "this debug session is over"
            )
        try:
            if self._process.stdin is not None:
                self._process.stdin.write(command + "\n")
                self._process.stdin.flush()
        except (OSError, ValueError) as exc:
            raise AnalysisError(f"the gdb process stopped accepting commands: {exc}") from exc

    def read_until_prompt(self, timeout: float) -> list[str]:
        """Read lines until the MI prompt, bounded by ``timeout`` seconds.

        Raises:
            AnalysisError: The budget expired before the prompt -- the session
                is left unusable on purpose and callers tear it down -- or the
                process died first.
        """
        lines: list[str] = []
        while True:
            if len(lines) >= MAX_MI_LINES:
                raise AnalysisError(
                    f"gdb printed more than {MAX_MI_LINES} MI lines without a prompt; "
                    "raise the timeout or reduce the session workload"
                )
            try:
                line = self._queue.get(timeout=max(timeout, 0.05))
            except queue.Empty as exc:
                if not self.alive:
                    return lines  # gdb exited; what we have is all there is
                raise AnalysisError(
                    f"the gdb session exceeded its timeout of {timeout:g} seconds waiting "
                    "for the MI prompt; raise the timeout or reduce the session workload"
                ) from exc
            lines.append(line)
            if line.strip() == PROMPT.strip():
                return lines

    def shutdown(self, timeout: float) -> tuple[int | None, bool]:
        """Close stdin, wait ``timeout`` seconds, escalate terminate -> kill.

        Returns ``(exit_code, clean)``: ``clean`` is ``True`` only when gdb
        exited by itself within the budget. Calling this on an already-exited
        process just reports its recorded exit, so a double teardown is safe.
        """
        if self._closed:
            code = self._process.poll()
            return code, code == 0
        self._closed = True
        if self.alive:
            if self._process.stdin is not None:
                try:
                    self._process.stdin.close()
                except OSError:  # pragma: no cover - already broken pipes
                    pass
            try:
                code = self._process.wait(timeout=timeout)
                return code, code == 0
            except subprocess.TimeoutExpired:
                pass
            self._process.terminate()
            try:
                code = self._process.wait(timeout=self._exit_grace)
                return code, False
            except subprocess.TimeoutExpired:  # pragma: no cover - pathological
                self._process.kill()
                return self._process.wait(timeout=self._exit_grace), False
        code = self._process.poll()
        return code, code == 0



# --------------------------------------------------------------------------- #
# The session
# --------------------------------------------------------------------------- #


def _require_timeout(timeout: float) -> float:
    """Validate a wall-clock budget."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise AnalysisError(f"timeout must be a positive number of seconds, got {timeout!r}")
    return float(timeout)


def _require_address(address: int) -> int:
    """Validate one virtual address."""
    if isinstance(address, bool) or not isinstance(address, int) or address <= 0:
        raise AnalysisError(f"address must be a positive int, got {address!r}")
    return address


def _require_length(length: int) -> int:
    """Validate a memory-read length against :data:`MAX_MEMORY_BYTES`."""
    if (
        isinstance(length, bool)
        or not isinstance(length, int)
        or not 1 <= length <= MAX_MEMORY_BYTES
    ):
        raise AnalysisError(f"length must be an int between 1 and {MAX_MEMORY_BYTES}, got {length!r}")
    return length


def _require_frames(max_frames: int) -> int:
    """Validate a backtrace budget against :data:`MAX_BACKTRACE_FRAMES`."""
    if (
        isinstance(max_frames, bool)
        or not isinstance(max_frames, int)
        or not 1 <= max_frames <= MAX_BACKTRACE_FRAMES
    ):
        raise AnalysisError(
            f"max_frames must be an int between 1 and {MAX_BACKTRACE_FRAMES}, got {max_frames!r}"
        )
    return max_frames


def parse_location(location: str) -> tuple[str, str]:
    """Split a ``--break-at`` location into ``("address"|"function", text)``.

    ``0x401000`` and all-digit text are addresses; anything else is a symbol
    name handed to gdb verbatim.

    Raises:
        AnalysisError: An empty location, or one that looks like an address
            but does not parse as one.
    """
    text = location.strip()
    if not text:
        raise AnalysisError(
            "break location must be a function name or an address, not an empty string"
        )
    lowered = text.lower()
    if lowered.startswith("0x") or text.isdigit():
        try:
            value = int(text, 16 if lowered.startswith("0x") else 10)
        except ValueError as exc:
            raise AnalysisError(
                f"break location {location!r} looks like an address but does not parse"
            ) from exc
        _require_address(value)
        return "address", f"*0x{value:x}"
    return "function", text


def _stop_evidence(command: str) -> Evidence:
    """Provenance for one ``-exec-*`` stop report."""
    return _mi_evidence(command, f"target stop reported by {command}")


def _mi_error(record: MIRecord, command: str) -> AnalysisError:
    """Turn one MI ``^error`` record into the typed, caller-correctable error."""
    payload = record.payload if isinstance(record.payload, dict) else {}
    message = payload.get("msg")
    detail = message if isinstance(message, str) else record.raw[:120]
    return AnalysisError(f"gdb rejected {command!r}: {detail}")


class DebugSession:
    """A live gdb MI session this module owns, from launch to verified exit.

    Instantiate through :meth:`launch` (a real ``gdb --interpreter=mi2``
    process) or directly with any :class:`MITransport` (tests, embedding
    hosts). The session is a context manager: leaving it always shuts the
    debugger down, so an exception in the middle of a session cannot leak a
    process.

    Every command returns a frozen, JSON-safe result carrying an
    :class:`~codevanta.evidence.models.Evidence` record that names the MI
    command which produced it. Every MI ``^error`` and every missed deadline
    raises :class:`~codevanta.core.report.AnalysisError` naming what went
    wrong -- the caller-correctable typed-error contract, never a traceback.
    """

    def __init__(
        self,
        transport: MITransport,
        *,
        target: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._transport = transport
        self._target = target
        self._timeout = _require_timeout(timeout)
        self._token = 0
        self._quit_result: QuitResult | None = None



    # -- lifecycle ------------------------------------------------------------ #

    @classmethod
    def launch(
        cls,
        target: str | Path,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        transport: MITransport | None = None,
    ) -> DebugSession:
        """Launch gdb on ``target`` and wait for its first MI prompt.

        Args:
            target: The program to debug; handed to gdb as its last argument.
                Validity is gdb's to report: a file it cannot load answers an
                MI error at the first ``-exec-*``, which surfaces as the same
                typed :class:`AnalysisError` as any other refusal.
            timeout: Per-command wall-clock budget in seconds (handshake
                included).
            transport: Injectable replacement for the live process; ``None``
                (the default) launches a real ``gdb --interpreter=mi2``.

        Raises:
            AnalysisError: gdb is not on PATH, the process could not spawn,
                the target is empty, or the handshake missed its budget.
        """
        checked_timeout = _require_timeout(timeout)
        resolved_target = str(target)
        if not resolved_target.strip():
            raise AnalysisError("debug target must be a non-empty program path")
        if transport is None:
            _require_gdb()
            transport = GdbMiProcess(list(_MI_ARGV_PREFIX), target=resolved_target)
        session = cls(transport, target=resolved_target, timeout=checked_timeout)
        session._execute_raw("")  # handshake: the first prompt ends the banner
        return session

    def __enter__(self) -> DebugSession:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._quit_result is None:
            try:
                self.quit()
            except AnalysisError:
                pass  # the shutdown attempt was made; the original failure wins

    # -- command plumbing ------------------------------------------------------ #

    def _next_token(self) -> int:
        self._token += 1
        return self._token

    def _execute_raw(self, command: str) -> list[MIRecord]:
        """Send ``command`` (token-prefixed) and read its records back."""
        if command:
            self._transport.send(f"{self._next_token()}{command}")
        return parse_mi_transcript(self._transport.read_until_prompt(self._timeout))

    def execute(self, command: str) -> dict[str, Any]:
        """Send one MI command, return its ``^``-record payload.

        Raises:
            AnalysisError: gdb answered ``^error`` (its ``msg`` is passed
                through), the payload was malformed, or the command missed the
                session deadline.
        """
        records = self._execute_raw(command)
        result = next((record for record in records if record.kind == "result"), None)
        if result is None:
            raise AnalysisError(
                f"gdb never answered {command!r} within {self._timeout:g} seconds "
                "(no result record before the prompt)"
            )
        if result.result_class == "error":
            raise _mi_error(result, command)
        return _payload_dict(result)

    def _exec_wait_stop(self, command: str) -> StopResult:
        """Run an ``-exec-*`` command and build its stop result.

        gdb answers ``-exec-run`` with ``^running`` immediately -- followed by
        a prompt -- and only emits ``*stopped`` when the target later stops or
        exits, with a fresh prompt of its own. So one read is rarely enough:
        the session keeps reading prompt-delimited chunks (each still under the
        session deadline) until the stop record shows up or gdb goes away.
        """
        records = self._execute_raw(command)
        while True:
            result = next((record for record in records if record.kind == "result"), None)
            if result is None:
                raise AnalysisError(
                    f"gdb never answered {command!r} within {self._timeout:g} seconds"
                )
            if result.result_class == "error":
                raise _mi_error(result, command)
            if result.result_class != "running":
                # A synchronous answer (^done, ^exit) without a stop: the
                # command was not an exec command, or gdb refused silently.
                raise AnalysisError(
                    f"gdb answered {command!r} with ^{result.result_class} but no "
                    "*stopped record followed; the target may already be gone"
                )
            stopped = next(
                (
                    record
                    for record in records
                    if record.kind == "exec" and record.async_class == "stopped"
                ),
                None,
            )
            if stopped is not None:
                payload = stopped.payload if isinstance(stopped.payload, dict) else {}
                return StopResult(
                    stop=stop_from_payload(payload), evidence=_stop_evidence(command)
                )
            more = parse_mi_transcript(self._transport.read_until_prompt(self._timeout))
            if not more:
                raise AnalysisError(
                    f"gdb answered {command!r} with ^running but stopped for good "
                    "before any *stopped record; the session is over"
                )
            records.extend(more)



    # -- capabilities ----------------------------------------------------------- #

    def break_at(
        self, function: str | None = None, address: int | None = None
    ) -> BreakpointResult:
        """Insert a breakpoint at a function name or a virtual address.

        Exactly one of ``function`` / ``address`` must be given. A pending
        breakpoint (gdb cannot resolve the location yet) is reported honestly
        through :attr:`BreakpointInfo.pending`, never guessed into an address.

        Raises:
            AnalysisError: Both or neither location was given, the address is
                invalid, or gdb answered ``^error`` naming the location.
        """
        if (function is None) == (address is None):
            raise AnalysisError("break_at needs exactly one of function or address")
        if function is not None:
            if not isinstance(function, str) or not function.strip():
                raise AnalysisError(f"function must be a non-empty symbol name, got {function!r}")
            location = function.strip()
            detail = f"breakpoint at function {location!r}"
        else:
            assert address is not None
            checked = _require_address(address)
            location = f"*0x{checked:x}"
            detail = f"breakpoint at address 0x{checked:x}"
        payload = self.execute(f"-break-insert {location}")
        bkpt = payload.get("bkpt")
        info = breakpoint_from_payload(bkpt if isinstance(bkpt, dict) else payload)
        warnings: list[str] = []
        if info.pending:
            warnings.append(
                f"gdb created breakpoint {info.number} as pending: it could not resolve "
                f"{location!r} to an address yet"
            )
        return BreakpointResult(
            breakpoint=info,
            warnings=_cap_warnings(warnings),
            evidence=_mi_evidence("-break-insert", detail),
        )

    def run(self) -> StopResult:
        """Start the target; wait until it stops or exits."""
        return self._exec_wait_stop("-exec-run")

    def continue_execution(self) -> StopResult:
        """Resume the target; wait until it stops or exits."""
        return self._exec_wait_stop("-exec-continue")

    def step_into(self) -> StopResult:
        """One instruction, entering calls; wait for the stop."""
        return self._exec_wait_stop("-exec-step --all 0")

    def step_over(self) -> StopResult:
        """One instruction, skipping calls; wait for the stop."""
        return self._exec_wait_stop("-exec-next --all 0")



    def read_registers(self) -> RegistersResult:
        """Snapshot the register file at the current stop."""
        names = self.execute("-data-list-register-names")
        values = self.execute("-data-list-register-values x")
        result = registers_from_payloads(
            names.get("register-names"), values.get("register-values")
        )
        warnings: list[str] = []
        if result.truncated:
            warnings.append(f"register list truncated to the first {MAX_REGISTERS} names")
        return RegistersResult(
            registers=result.registers,
            truncated=result.truncated,
            warnings=_cap_warnings(warnings),
        )

    def read_memory(self, address: int, length: int) -> MemoryResult:
        """Read ``length`` bytes at ``address`` from the live target.

        Raises:
            AnalysisError: An invalid address/length, or gdb refused the read
                (unmapped memory names the range).
        """
        checked_address = _require_address(address)
        checked_length = _require_length(length)
        payload = self.execute(
            f"-data-read-memory-bytes -o 0 0x{checked_address:x} {checked_length}"
        )
        result = memory_from_payload(
            payload, requested_address=checked_address, requested_length=checked_length
        )
        warnings: list[str] = []
        if result.short_read:
            warnings.append(
                f"gdb returned {result.length} of the requested {checked_length} bytes; "
                "the read may have reached the end of a mapped region"
            )
        return MemoryResult(
            address=result.address,
            requested_length=checked_length,
            length=result.length,
            contents_hex=result.contents_hex,
            short_read=result.short_read,
            warnings=_cap_warnings(warnings),
        )

    def backtrace(self, max_frames: int = MAX_BACKTRACE_FRAMES) -> BacktraceResult:
        """Walk the call stack at the current stop, bounded by ``max_frames``."""
        checked = _require_frames(max_frames)
        payload = self.execute(f"-stack-list-frames 0 {checked - 1}")
        result = backtrace_from_payload(payload, requested=checked)
        warnings: list[str] = []
        if result.truncated:
            warnings.append(f"backtrace truncated to the requested {checked} frames")
        return BacktraceResult(
            frames=result.frames,
            truncated=result.truncated,
            warnings=_cap_warnings(warnings),
        )

    def quit(self) -> QuitResult:
        """Exit gdb and verify the process is really gone.

        The result is cached: a second ``quit`` (the context-manager exit
        after an explicit one) reports the same verified outcome instead of
        poking a dead process. ``clean`` is ``True`` only when gdb exited on
        its own; otherwise the result says what was needed to bring it down.
        """
        if self._quit_result is not None:
            return self._quit_result
        warnings: list[str] = []
        try:
            self._execute_raw("-gdb-exit")
        except AnalysisError as exc:
            warnings.append(f"the -gdb-exit handshake did not complete cleanly: {exc}")
        exit_code, clean = self._transport.shutdown(self._timeout)
        if not clean:
            warnings.append(
                f"the gdb process did not exit on its own (exit code {exit_code}); "
                "it was terminated"
            )
        result = QuitResult(clean=clean, exit_code=exit_code, warnings=_cap_warnings(warnings))
        self._quit_result = result
        return result

# --------------------------------------------------------------------------- #
# One-shot orchestration: launch -> optional break -> one action -> verified quit
# --------------------------------------------------------------------------- #

#: Actions :func:`run_debug` accepts, in the order the CLI advertises them.
DEBUG_ACTIONS: tuple[str, ...] = (
    "registers",
    "memory",
    "backtrace",
    "continue",
    "step",
    "next",
    "quit",
)


def run_debug(
    target: str | Path,
    *,
    action: str = "registers",
    break_at: str | None = None,
    address: int | None = None,
    length: int = 64,
    max_frames: int = 20,
    timeout: float = DEFAULT_TIMEOUT,
    transport: MITransport | None = None,
) -> dict[str, Any]:
    """Run one complete live debug session and return every result as JSON.

    The session this function owns: gdb is launched on ``target``, an optional
    breakpoint is inserted (``break_at`` names a function or an address, and
    the target is run to it), the requested ``action`` is performed at the
    stop, and the debugger is shut down with its exit verified. Every payload
    in the returned mapping is the ``to_dict()`` of a typed result, so the
    provenance of each piece rides along.

    Args:
        target: Program for gdb to load.
        action: One of :data:`DEBUG_ACTIONS`: ``registers`` (default),
            ``memory`` (needs ``address``), ``backtrace``, ``continue``,
            ``step``, ``next``, or ``quit`` (launch, optionally break, exit).
        break_at: Optional location: ``main`` or ``0x401000``. When given, the
            breakpoint is inserted and the target runs to it before the action.
        address: Virtual address for the ``memory`` action (required there,
            rejected elsewhere so a typo cannot silently no-op).
        length: Byte count for the ``memory`` action.
        max_frames: Frame budget for the ``backtrace`` action.
        timeout: Per-command wall-clock budget in seconds.
        transport: Injectable MI transport (tests); ``None`` launches gdb.

    Returns:
        ``target``, ``break`` (the breakpoint result and the stop it produced),
        ``action``, ``result`` (the action's typed payload) and ``quit`` (the
        verified shutdown), all JSON-safe.

    Raises:
        AnalysisError: An unknown action, an action/argument mismatch, an
            out-of-range length or frame budget, a missing gdb executable, or
            any MI-level refusal -- each naming what is wrong.
    """
    if action not in DEBUG_ACTIONS:
        raise AnalysisError(f"action must be one of {', '.join(DEBUG_ACTIONS)}, got {action!r}")
    if action == "memory":
        if address is None:
            raise AnalysisError("action 'memory' needs an address to read")
        _require_address(address)
        _require_length(length)
    elif address is not None:
        raise AnalysisError(
            f"address is only used by action 'memory', not {action!r}; pass it with --action memory"
        )
    if action == "backtrace":
        _require_frames(max_frames)
    payload: dict[str, Any] = {
        "target": str(target),
        "break": None,
        "action": action,
        "result": None,
        "quit": None,
    }
    with DebugSession.launch(target, timeout=timeout, transport=transport) as session:
        if break_at is not None:
            kind, location = parse_location(break_at)
            if kind == "function":
                info = session.break_at(function=location)
            else:
                info = session.break_at(address=int(location[1:], 16))
            stop = session.run()
            payload["break"] = {"location_kind": kind, **info.to_dict(), "run": stop.to_dict()}
        if action == "registers":
            payload["result"] = session.read_registers().to_dict()
        elif action == "memory":
            assert address is not None
            payload["result"] = session.read_memory(address, length).to_dict()
        elif action == "backtrace":
            payload["result"] = session.backtrace(max_frames).to_dict()
        elif action == "continue":
            payload["result"] = session.continue_execution().to_dict()
        elif action == "step":
            payload["result"] = session.step_into().to_dict()
        elif action == "next":
            payload["result"] = session.step_over().to_dict()
        else:  # "quit": the launch (+ optional break) is the whole session
            payload["result"] = None
        payload["quit"] = session.quit().to_dict()
    return payload



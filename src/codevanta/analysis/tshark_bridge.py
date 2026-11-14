"""tshark field-extraction bridge: TSV parser plus one skip-gated runner.

The adb/sigrok pattern applied to packet captures: everything that
*understands* ``tshark -T fields`` output is the pure
:func:`parse_tshark_fields` function, fully tested offline against canned TSV
transcripts, and everything that *runs* tshark is :func:`pcap_fields`, gated
on a single ``shutil.which("tshark")`` probe with a bounded timeout and a
``-c`` packet cap on the command line itself. On a machine without tshark the
parser still runs and the wrapper still imports; it fails with the typed
:class:`~codevanta.core.report.AnalysisError` carrying the install hint and a
pointer at the offline ``codevanta binmeta <file>`` structural pcap fallback --
never a traceback, never a partial decode.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_PACKET_LIMIT",
    "DEFAULT_TIMEOUT",
    "EVIDENCE_SOURCE",
    "MAX_FIELDS",
    "MAX_PACKET_LIMIT",
    "MAX_ROWS",
    "MAX_TIMEOUT",
    "TSHARK_MISSING_MESSAGE",
    "PcapFieldsResult",
    "PcapRow",
    "parse_tshark_fields",
    "pcap_fields",
    "tshark_available",
]

#: Packets requested from one ``pcap_fields`` call by default.
DEFAULT_PACKET_LIMIT = 50

#: Hard ceiling on packets requested per call (the parser's own cap too).
MAX_PACKET_LIMIT = 100

#: Parsed data rows kept from one transcript (bounded work).
MAX_ROWS = 100

#: Field names accepted per call.
MAX_FIELDS = 16

#: Default wall-clock budget for one tshark invocation, in seconds.
DEFAULT_TIMEOUT = 30.0

#: Hard ceiling on the wall-clock budget of one tshark invocation.
MAX_TIMEOUT = 300.0

#: Ceiling on warnings kept per result.
MAX_WARNINGS = 32

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "bridge.tshark"

#: Typed failure for the wrapper when tshark is absent, with install hint and
#: the offline structural fallback named explicitly.
TSHARK_MISSING_MESSAGE = (
    "tshark is not on PATH; install Wireshark/tshark (https://www.wireshark.org) "
    "and make sure it is on PATH; for an offline structural pcap/pcapng summary "
    "without tshark use `codevanta binmeta <file>`"
)

#: ``tcp.srcport`` / ``tcp.payload`` -- one legal tshark ``-e`` field name.
_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_.]{1,64}$")


class RunnerOutcome(Protocol):
    """What a runner must return: ``subprocess.CompletedProcess``-shaped."""

    returncode: int
    stdout: Any
    stderr: Any


class Runner(Protocol):
    """The injectable stand-in for ``subprocess.run`` (offline tests)."""

    def __call__(self, command: tuple[str, ...], **kwargs: Any) -> RunnerOutcome: ...


def _note(warnings: list[str], message: str) -> None:
    """Append ``message`` once, summarising away everything past the cap."""
    if message in warnings:
        return
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)
    elif warnings and not warnings[-1].endswith("..."):
        warnings.append(f"{MAX_WARNINGS}+ warnings; further messages dropped...")


def _tail(text: str, limit: int = 400) -> str:
    """Return the last ``limit`` characters of ``text``, whitespace-flattened."""
    flat = " ".join(text.split())
    return flat[-limit:] if len(flat) > limit else flat


@dataclass(frozen=True)
class PcapRow:
    """One packet's requested fields from a ``tshark -T fields`` transcript.

    Attributes:
        number: 1-based packet number when requested via ``-e frame.number``.
        fields: Requested field name -> decoded string; absent/empty columns
            come back as ``None``.
    """

    number: int | None
    fields: dict[str, str | None]

    def to_dict(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "fields": dict(self.fields),
        }
@dataclass(frozen=True)
class PcapFieldsResult:
    """Bounded, evidence-backed parse of one tshark field extraction."""

    path: str
    fields: tuple[str, ...]
    display_filter: str | None = None
    packet_limit: int = DEFAULT_PACKET_LIMIT
    rows: tuple[PcapRow, ...] = ()
    truncated: bool = False
    transcript_path: str | None = None
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="tshark -T fields",
            confidence=Confidence.HIGH,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "fields": list(self.fields),
            "display_filter": self.display_filter,
            "packet_limit": self.packet_limit,
            "rows": [row.to_dict() for row in self.rows],
            "count": len(self.rows),
            "truncated": self.truncated,
            "transcript_path": self.transcript_path,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def parse_tshark_fields(
    text: Any,
) -> tuple[tuple[str, ...], tuple[PcapRow, ...], bool, list[str]]:
    """Parse canned ``tshark -T fields`` TSV output into typed rows.

    With ``-E header=y`` the first line names the columns; each following
    tab-separated line becomes one :class:`PcapRow`. Rows are bounded at
    :data:`MAX_ROWS`; junk lines become warnings. The parse never raises for
    transcript content; anything that is not ``str`` raises the typed error.

    Returns:
        ``(header_fields, rows, truncated, warnings)``.
    """
    if not isinstance(text, str):
        raise AnalysisError(f"transcript must be a string, got {type(text).__name__}")
    warnings: list[str] = []
    header: tuple[str, ...] = ()
    rows: list[PcapRow] = []
    truncated = False
    for line in text.splitlines():
        stripped = line.rstrip("\r")
        if not stripped:
            continue
        if not header:
            header = tuple(column for column in stripped.split("\t"))
            continue
        columns = stripped.split("\t")
        padded: list[str | None] = list(columns) + [None] * (len(header) - len(columns))
        values: dict[str, str | None] = {}
        for name, column in zip(header, padded, strict=False):
            values[name] = column if column else None
        number: int | None = None
        if "frame.number" in values and values["frame.number"] is not None:
            try:
                number = int(values["frame.number"])
            except ValueError:
                number = None
        rows.append(PcapRow(number=number, fields=values))
        if len(rows) >= MAX_ROWS:
            truncated = True
            _note(warnings, f"row limit {MAX_ROWS} reached; further packets dropped")
            break
    if not header:
        _note(warnings, "no header line in the transcript")
    return header, tuple(rows), truncated, warnings


def _check_fields(fields: Any) -> tuple[str, ...]:
    """Validate the requested ``-e`` field names before they reach argv."""
    if isinstance(fields, str):
        checked = tuple(part.strip() for part in fields.split(","))
    elif isinstance(fields, (list, tuple)):
        checked = tuple(fields)
    else:
        raise AnalysisError(
            f"fields must be a comma-separated string or a sequence, got {type(fields).__name__}"
        )
    if isinstance(fields, str):
        checked = tuple(part for part in checked if part)
    if not checked or all(not str(part).strip() for part in checked):
        raise AnalysisError("fields must name at least one tshark -e field, e.g. frame.number")
    if len(checked) > MAX_FIELDS:
        raise AnalysisError(f"too many fields requested (limit {MAX_FIELDS})")
    for name in checked:
        if not isinstance(name, str) or not _FIELD_NAME_RE.match(name):
            raise AnalysisError(
                f"field {name!r} is not a tshark field name; expected letters, digits "
                "and . _ only (e.g. frame.number)"
            )
    return checked

def _check_timeout(value: Any) -> float:
    """Validate one wall-clock budget; the wrapper shares the bound."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AnalysisError(f"timeout must be a number of seconds, got {value!r}")
    timeout = float(value)
    if not 1.0 <= timeout <= MAX_TIMEOUT:
        raise AnalysisError(
            f"timeout {timeout} is out of range; expected 1 .. {MAX_TIMEOUT} seconds"
        )
    return timeout


def tshark_available() -> bool:
    """Report whether tshark is on ``PATH``; the only gate a caller needs."""
    return shutil.which("tshark") is not None


def pcap_fields(
    input_path: str | Path,
    fields: str | list[str] | tuple[str, ...],
    *,
    display_filter: str | None = None,
    packet_limit: int = DEFAULT_PACKET_LIMIT,
    timeout: float = DEFAULT_TIMEOUT,
    runner: Runner | None = None,
    out_dir: str | Path | None = None,
) -> PcapFieldsResult:
    """Run ``tshark -r <file> -T fields -e ...`` and parse the TSV transcript.

    Skip-gated: without tshark on ``PATH`` (and no injected ``runner``) this
    raises the typed :data:`TSHARK_MISSING_MESSAGE` error -- which names the
    offline ``codevanta binmeta <file>`` structural fallback -- before any
    process is spawned. The ``-c`` flag caps how many packets tshark itself
    decodes; the parser keeps at most :data:`MAX_ROWS` rows either way. With
    ``out_dir`` the raw transcript is preserved as ``tshark-fields.txt``.
    """
    if not isinstance(input_path, (str, Path)):
        raise AnalysisError(
            f"input_path must be a str or Path, got {type(input_path).__name__}"
        )
    target = Path(input_path)
    if not target.is_file():
        raise AnalysisError(f"capture file not found: {target}")
    checked_fields = _check_fields(fields)
    if isinstance(packet_limit, bool) or not isinstance(packet_limit, int):
        raise AnalysisError(f"packet_limit must be an integer, got {packet_limit!r}")
    if not 1 <= packet_limit <= MAX_PACKET_LIMIT:
        raise AnalysisError(
            f"packet_limit {packet_limit} is out of range; expected 1 .. {MAX_PACKET_LIMIT}"
        )
    if display_filter is not None and (
        not isinstance(display_filter, str) or not display_filter.strip()
    ):
        raise AnalysisError("display_filter must be a non-empty string or None")
    checked_timeout = _check_timeout(timeout)
    if runner is None and not tshark_available():
        raise AnalysisError(TSHARK_MISSING_MESSAGE)
    command: list[str] = [
        "tshark",
        "-r",
        str(target),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-c",
        str(packet_limit),
    ]
    if display_filter is not None:
        command.extend(["-Y", display_filter])
    for name in checked_fields:
        command.extend(["-e", name])
    execute = runner if runner is not None else subprocess.run
    try:
        outcome = execute(
            tuple(command), capture_output=True, text=True, timeout=checked_timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise AnalysisError(
            f"tshark exceeded its timeout of {checked_timeout} seconds and was terminated"
        ) from exc
    except FileNotFoundError as exc:
        raise AnalysisError(
            f"{TSHARK_MISSING_MESSAGE}; the runner raised FileNotFoundError, so the "
            "executable vanished between the PATH probe and the call"
        ) from exc
    returncode = getattr(outcome, "returncode", None)
    if not isinstance(returncode, int):
        raise AnalysisError(
            "the runner outcome violates the injection contract: returncode must be an int"
        )
    stdout = getattr(outcome, "stdout", None)
    stderr_text = getattr(outcome, "stderr", "")
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    transcript_text = stdout if isinstance(stdout, str) else ""
    if returncode != 0:
        raise AnalysisError(
            f"tshark exited with code {returncode}: "
            f"{_tail(str(stderr_text)) or 'no stderr output'}"
        )
    header, rows, truncated, warnings = parse_tshark_fields(transcript_text)
    if header != checked_fields:
        _note(warnings, f"header field order {header!r} differs from request {checked_fields!r}")
    transcript_path: str | None = None
    if out_dir is not None:
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        transcript_file = out_path / "tshark-fields.txt"
        transcript_file.write_text(transcript_text, encoding="utf-8")
        transcript_path = str(transcript_file)
    return PcapFieldsResult(
        path=str(target),
        fields=checked_fields,
        display_filter=display_filter,
        packet_limit=packet_limit,
        rows=rows,
        truncated=truncated,
        transcript_path=transcript_path,
        warnings=warnings,
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="tshark -T fields",
            confidence=Confidence.HIGH,
            detail=f"{len(rows)} packet row(s), {len(checked_fields)} field(s)",
        ),
    )


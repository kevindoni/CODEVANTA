"""Firmware extraction bridge: binwalk/unblob parsers plus skip-gated runners.

The adb/sigrok pattern applied to firmware images: everything that
*understands* extraction output is a pure parser (:func:`parse_binwalk_output`
and :func:`parse_unblob_output`), fully tested offline against canned
transcripts, and everything that *runs* an extractor is a thin wrapper
(:func:`firmware_extract`) gated on a single ``shutil.which`` probe with a
bounded timeout. On a machine without either tool the wrapper still imports
and fails with the typed missing-tool error -- which names the offline
``codevanta binmeta <file>`` magic-scan fallback -- never a traceback, never a
partial extraction.

The wrapper also shallow-scans the extraction directory it produced (bounded
64 paths, sorted) so the result carries both what the tool *reported* and
what it actually *wrote*.
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
    "BINWALK_MISSING_MESSAGE",
    "DEFAULT_TIMEOUT",
    "EXTRACT_TOOLS",
    "EVIDENCE_SOURCE",
    "EVIDENCE_UNBLOB",
    "MAX_ENTRIES",
    "MAX_TIMEOUT",
    "MAX_TREE",
    "UNBLOB_MISSING_MESSAGE",
    "ExtractedEntry",
    "FirmwareExtractResult",
    "firmware_extract",
    "parse_binwalk_output",
    "parse_unblob_output",
    "scan_extract_tree",
]

#: Default wall-clock budget for one extraction run, in seconds.
DEFAULT_TIMEOUT = 120.0

#: Hard ceiling on the wall-clock budget of one extraction run.
MAX_TIMEOUT = 600.0

#: Reported extraction entries kept from one transcript (bounded work).
MAX_ENTRIES = 64

#: Extraction-directory paths kept in one result (bounded work).
MAX_TREE = 64

#: Ceiling on warnings kept per result.
MAX_WARNINGS = 32

#: Evidence ``source`` id for the binwalk lane.
EVIDENCE_SOURCE = "bridge.binwalk"

#: Evidence ``source`` id for the unblob lane.
EVIDENCE_UNBLOB = "bridge.unblob"

#: Extraction tools :func:`firmware_extract` accepts.
EXTRACT_TOOLS: tuple[str, ...] = ("binwalk", "unblob")

#: Typed failure when binwalk is absent, with the offline ``codevanta
#: binmeta`` magic-scan fallback named explicitly.
BINWALK_MISSING_MESSAGE = (
    "binwalk is not on PATH; install it with pip install binwalk (or from "
    "https://github.com/ReFirmLabs/binwalk) and make sure it is on PATH; for a "
    "magic-scan fallback without binwalk use `codevanta binmeta <file>`"
)

#: Typed failure when unblob is absent, with the same fallback.
UNBLOB_MISSING_MESSAGE = (
    "unblob is not on PATH; install it with pip install unblob (https://unblob.org) "
    "and make sure it is on PATH; for a magic-scan fallback without unblob use "
    "`codevanta binmeta <file>`"
)

#: ``1884    0x75C    LZMA compressed data, ...`` -- one binwalk table row.
_BINWALK_ROW = re.compile(r"^(?P<offset>\d+)\s+0x[0-9A-Fa-f]+\s+(?P<kind>\S.*)$")

#: ``original size 12345`` / ``size: 3207168`` / ``size 0x400`` -- size hints.
_BINWALK_SIZE = re.compile(
    r"(?:(?:original\s+)?size[:=]?\s*(?P<hex>0x[0-9a-fA-F]+|\d+)|(?P<plain>\d+)\s+bytes)",
    re.IGNORECASE,
)

#: ``Chunk found: gzip 0x0-0x400`` -- one unblob chunk line.
_UNBLOB_CHUNK = re.compile(
    r"Chunk found:\s+(?P<kind>[\w./-]+)\s+0x(?P<offset>[0-9a-fA-F]+)"
    r"(?:\s*-\s*0x(?P<end>[0-9a-fA-F]+))?"
)

#: ``Extracted gzip chunk to 0x0.gz.extract`` -- where a chunk landed.
_UNBLOB_PATH = re.compile(r"[Ee]xtracted\s+.*?to\s+(?P<path>\S+)")


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


def _first_size(kind: str) -> int | None:
    """Extract one reported byte size from a binwalk description."""
    match = _BINWALK_SIZE.search(kind)
    if match is None:
        return None
    if match.group("plain") is not None:
        return int(match.group("plain"))
    literal = match.group("hex")
    return int(literal, 16) if literal.lower().startswith("0x") else int(literal)


@dataclass(frozen=True)
class ExtractedEntry:
    """One reported extraction record from an extractor transcript.

    Attributes:
        offset: File offset the extractor reported, ``None`` when it did not.
        kind: Guessed format/description as the extractor phrased it.
        size: Reported byte size, ``None`` when the transcript omitted one.
        path: Extraction path, ``None`` unless the transcript named one.
    """

    kind: str
    offset: int | None = None
    size: int | None = None
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"kind": self.kind}
        if self.offset is not None:
            data["offset"] = self.offset
        if self.size is not None:
            data["size"] = self.size
        if self.path is not None:
            data["path"] = self.path
        return data


@dataclass(frozen=True)
class ExtractParse:
    """Bounded parse of one extractor transcript (parser half, offline)."""

    entries: tuple[ExtractedEntry, ...] = ()
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FirmwareExtractResult:
    """Bounded, evidence-backed report of one extraction run (wrapper half)."""

    tool: str
    path: str
    out_dir: str
    entries: tuple[ExtractedEntry, ...] = ()
    tree: tuple[str, ...] = ()
    entries_truncated: bool = False
    tree_truncated: bool = False
    transcript_path: str | None = None
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="binwalk -e --directory",
            confidence=Confidence.MEDIUM,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "path": self.path,
            "out_dir": self.out_dir,
            "entries": [entry.to_dict() for entry in self.entries],
            "count": len(self.entries),
            "tree": list(self.tree),
            "tree_count": len(self.tree),
            "entries_truncated": self.entries_truncated,
            "tree_truncated": self.tree_truncated,
            "transcript_path": self.transcript_path,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def parse_binwalk_output(text: Any) -> ExtractParse:
    """Parse a ``binwalk -e`` scan table into bounded typed entries.

    Table rows are ``DECIMAL HEXADECIMAL DESCRIPTION``; every other line
    (banners, the dash separator, progress chatter) becomes a warning. A
    ``size``/``original size``/``N bytes`` hint inside a description becomes
    the entry's ``size``. The parse never raises for transcript content;
    anything that is not ``str`` raises the typed error.
    """
    if not isinstance(text, str):
        raise AnalysisError(f"transcript must be a string, got {type(text).__name__}")
    entries: list[ExtractedEntry] = []
    warnings: list[str] = []
    truncated = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or set(stripped) == {"-"}:
            continue  # banner/separator chatter
        row = _BINWALK_ROW.match(stripped)
        if row is None:
            _note(warnings, f"unrecognised line skipped: {stripped[:64]!r}")
            continue
        kind = row.group("kind")
        entries.append(
            ExtractedEntry(
                kind=kind,
                offset=int(row.group("offset")),
                size=_first_size(kind),
            )
        )
        if len(entries) >= MAX_ENTRIES:
            truncated = True
            _note(warnings, f"entry limit {MAX_ENTRIES} reached; further rows dropped")
            break
    if not entries and not warnings:
        _note(warnings, "no extraction rows in the transcript")
    return ExtractParse(entries=tuple(entries), truncated=truncated, warnings=warnings)


def parse_unblob_output(text: Any) -> ExtractParse:
    """Parse an unblob log into bounded typed entries.

    ``Chunk found: <kind> 0x<offset>[-0x<end>]`` lines become entries (the
    end offset gives a size); ``Extracted ... to <path>`` lines attach their
    path to the most recent entry. Everything else is a warning. The parse
    never raises for transcript content; anything that is not ``str`` raises
    the typed error.
    """
    if not isinstance(text, str):
        raise AnalysisError(f"transcript must be a string, got {type(text).__name__}")
    entries: list[ExtractedEntry] = []
    warnings: list[str] = []
    truncated = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        chunk = _UNBLOB_CHUNK.search(stripped)
        if chunk is not None:
            offset = int(chunk.group("offset"), 16)
            end = chunk.group("end")
            size = int(end, 16) - offset if end is not None else None
            entries.append(ExtractedEntry(kind=chunk.group("kind"), offset=offset, size=size))
            if len(entries) >= MAX_ENTRIES:
                truncated = True
                _note(warnings, f"entry limit {MAX_ENTRIES} reached; further rows dropped")
                break
            continue
        landed = _UNBLOB_PATH.search(stripped)
        if landed is not None and entries:
            last = entries[-1]
            entries[-1] = ExtractedEntry(
                kind=last.kind, offset=last.offset, size=last.size, path=landed.group("path")
            )
            continue
        _note(warnings, f"unrecognised line skipped: {stripped[:64]!r}")
    if not entries and not warnings:
        _note(warnings, "no extraction rows in the transcript")
    return ExtractParse(entries=tuple(entries), truncated=truncated, warnings=warnings)


def scan_extract_tree(
    out_dir: str | Path, *, limit: int = MAX_TREE
) -> tuple[tuple[str, ...], bool]:
    """Shallow-scan an extraction directory into a sorted relative path list.

    Bounded to ``limit`` paths (default 64); the second element reports
    whether anything was dropped. A missing directory yields an empty tree,
    because some extractors legitimately write nothing for a no-match scan.
    """
    root = Path(out_dir)
    if not root.is_dir():
        return (), False
    paths = sorted(str(child.relative_to(root)) for child in root.rglob("*"))
    return tuple(paths[:limit]), len(paths) > limit


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

def firmware_extract(
    input_path: str | Path,
    out_dir: str | Path,
    *,
    tool: str = "binwalk",
    timeout: float = DEFAULT_TIMEOUT,
    runner: Runner | None = None,
) -> FirmwareExtractResult:
    """Run ``binwalk -e --directory`` or ``unblob`` and parse the outcome.

    Skip-gated: without the chosen tool on ``PATH`` (and no injected
    ``runner``) this raises the typed missing-tool error -- which points at
    the offline ``codevanta binmeta <file>`` magic-scan fallback -- before any
    process is spawned. The raw transcript is preserved at
    ``<out_dir>/<tool>-transcript.txt`` next to the parsed result.
    """
    if not isinstance(tool, str) or tool not in EXTRACT_TOOLS:
        raise AnalysisError(f"tool must be one of {', '.join(EXTRACT_TOOLS)}, got {tool!r}")
    if not isinstance(input_path, (str, Path)):
        raise AnalysisError(
            f"input_path must be a str or Path, got {type(input_path).__name__}"
        )
    target = Path(input_path)
    if not target.is_file():
        raise AnalysisError(f"firmware file not found: {target}")
    if not isinstance(out_dir, (str, Path)):
        raise AnalysisError(f"out_dir must be a str or Path, got {type(out_dir).__name__}")
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    checked_timeout = _check_timeout(timeout)
    if tool == "binwalk":
        missing_message = BINWALK_MISSING_MESSAGE
        tool_path = shutil.which("binwalk")
        command: tuple[str, ...] = ("binwalk", "-e", "--directory", str(destination), str(target))
        evidence_source = EVIDENCE_SOURCE
        method = "binwalk -e --directory"
        parser = parse_binwalk_output
    else:
        missing_message = UNBLOB_MISSING_MESSAGE
        tool_path = shutil.which("unblob")
        command = ("unblob", "-e", str(destination), str(target))
        evidence_source = EVIDENCE_UNBLOB
        method = "unblob -e"
        parser = parse_unblob_output
    if runner is None and tool_path is None:
        raise AnalysisError(missing_message)
    execute = runner if runner is not None else subprocess.run
    try:
        outcome = execute(command, capture_output=True, text=True, timeout=checked_timeout)
    except subprocess.TimeoutExpired as exc:
        raise AnalysisError(
            f"{tool} exceeded its timeout of {checked_timeout} seconds and was terminated"
        ) from exc
    except FileNotFoundError as exc:
        raise AnalysisError(
            f"{missing_message}; the runner raised FileNotFoundError, so the "
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
            f"{tool} exited with code {returncode}: "
            f"{_tail(str(stderr_text)) or 'no stderr output'}"
        )
    parsed = parser(transcript_text)
    tree, tree_truncated = scan_extract_tree(destination)
    transcript_file = destination / f"{tool}-transcript.txt"
    transcript_file.write_text(transcript_text, encoding="utf-8")
    return FirmwareExtractResult(
        tool=tool,
        path=str(target),
        out_dir=str(destination),
        entries=parsed.entries,
        entries_truncated=parsed.truncated,
        tree=tree,
        tree_truncated=tree_truncated,
        transcript_path=str(transcript_file),
        warnings=parsed.warnings,
        evidence=Evidence(
            source=evidence_source,
            method=method,
            confidence=Confidence.MEDIUM,
            detail=f"{len(parsed.entries)} reported entr(ies), {len(tree)} extracted path(s)",
        ),
    )


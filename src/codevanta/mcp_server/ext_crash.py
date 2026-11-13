"""MCP tool: ``codevanta_crash`` -- summarise a crash dump, format detected.

One tool covers both crash-dump families the crash lane parses: a Linux ELF
core dump and an Apple ``.ips`` crash report. The format is detected from the
leading magic bytes (``\\x7fELF`` means a core; anything else is handed to the
``.ips`` parser, which raises a typed error for files it cannot place), so the
caller never has to know which family a file belongs to.

The function is a plain ``dict``-returning helper like every other entry in
:mod:`codevanta.mcp_server.tools`; it never launches anything, reads only the
file at ``path``, and every failure surfaces as
:class:`~codevanta.core.report.AnalysisError` rather than a traceback.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis.apple_ips import parse_ips_report
from codevanta.analysis.crash_core import parse_core_dump
from codevanta.core.report import AnalysisError

__all__ = ["codevanta_crash"]

#: Leading bytes that identify an ELF image (core dumps included).
_ELF_MAGIC = b"\x7fELF"

#: Bytes to peek at for format detection.
_DETECT_BYTES = 4


def _validate_crash_path(path: str) -> Path:
    """Return ``path`` as an existing regular file, or raise naming the problem."""
    if not isinstance(path, str):
        raise AnalysisError(f"path must be a string, got {type(path).__name__}")
    text = path.strip()
    if not text:
        raise AnalysisError("path must not be empty")
    candidate = Path(text).expanduser()
    if not candidate.exists():
        raise AnalysisError(f"file not found: {path}")
    if not candidate.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    return candidate


def _detect_and_parse(target: Path) -> tuple[str, dict[str, Any]]:
    """Peek at the magic bytes and hand the file to the matching parser."""
    try:
        with target.open("rb") as handle:
            magic = handle.read(_DETECT_BYTES)
    except OSError as exc:
        raise AnalysisError(f"cannot read crash dump {str(target)!r}: {exc}") from exc
    if magic == _ELF_MAGIC:
        return "elf-core", parse_core_dump(target).to_dict()
    return "apple-ips", parse_ips_report(target).to_dict()


def codevanta_crash(path: str) -> dict[str, Any]:
    """Summarise a crash dump file, auto-detecting ELF core vs Apple ``.ips``.

    Args:
        path: Path to the crash dump (ELF core or ``.ips`` report). Required.

    Returns:
        A JSON-safe payload with ``format`` (``"elf-core"`` or
        ``"apple-ips"``), ``path``, the parsed summary fields, and the
        ``evidence`` record (``crash.elfcore`` / ``crash.ips``) whose
        ``confidence`` states how much of the finding was parse-verified.

    Raises:
        AnalysisError: If ``path`` is missing, empty, unreadable, not a regular
            file, or is neither a parseable core dump nor an ``.ips`` report.
    """
    target = _validate_crash_path(path)
    detected_format, payload = _detect_and_parse(target)
    # The detected format must win over the summary's own "format" field, so
    # the payload spread comes first and the wrapper keys are written last.
    return {**payload, "path": str(target), "format": detected_format}

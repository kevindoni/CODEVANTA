"""Parse Apple ``.ips`` crash reports into a bounded, attributable summary.

Apple ships crash reports in two generations, and this module reads both:

``json`` format (2016-onward, ``bug_type`` 309+)
    The file is a pair of JSON lines: the dump header (``app_name``,
    ``os_version``, ``product``, ``timestamp`` ...) followed by the crash body
    (``exception``, ``faultingThread``, ``threads``, ``images``,
    ``termination``). Some tools write the literal marker line ``JSON dump
    header`` first; when that line is present it is skipped and the JSON that
    follows is parsed the same way.
``plist`` format (legacy)
    A single header line (originally the un-terminated front of a plist, so it
    may or may not parse as JSON) followed by a property list. The plist is
    read with :mod:`plistlib` -- pure Python, no external tools -- and the
    classic keys (``OS Version``, ``Exception Type``, ``Threads``, ``Images``,
    ``Faulting Thread``) are extracted.

Extraction rules
----------------
The faulting thread is the one named by ``faultingThread`` (JSON) or
``Faulting Thread`` (plist); when that is missing or out of range, the first
thread flagged ``triggered`` is taken, and failing that the first thread. Every
frame resolves ``imageIndex`` against the images list, keeping the image name,
the offset into that image, and the ``symbol``/``symbolLocation`` pair when the
report was written with symbols.

Bounds
------
A parse reads at most :data:`MAX_IPS_BYTES` bytes, keeps at most
:data:`MAX_FRAMES` frames and :data:`MAX_IMAGES` images; a cut sets
``truncated`` and a warning instead of growing without limit. The only
exception raised is :class:`~codevanta.core.report.AnalysisError`: a file that
does not look like an ``.ips`` report in either generation is a typed error,
never a traceback.
"""

from __future__ import annotations

import json
import plistlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_METHOD_JSON",
    "EVIDENCE_METHOD_PLIST",
    "EVIDENCE_SOURCE",
    "MAX_FRAMES",
    "MAX_IMAGES",
    "MAX_IPS_BYTES",
    "MAX_WARNINGS",
    "IpsFrame",
    "IpsImage",
    "IpsSummary",
    "parse_ips_report",
]

#: Hard ceiling on the bytes one parse will read.
MAX_IPS_BYTES = 16 * 1024 * 1024

#: Frames kept for the faulting thread, whatever the report carries.
MAX_FRAMES = 64

#: Images kept per report, whatever the report carries.
MAX_IMAGES = 64

#: Warnings kept per report before the rest are summarised away.
MAX_WARNINGS = 32

#: Evidence ``source`` for every finding extracted from an ``.ips`` report.
EVIDENCE_SOURCE = "crash.ips"

#: Evidence ``method`` when the body was a JSON object (modern reports).
EVIDENCE_METHOD_JSON = "ips_json_body"

#: Evidence ``method`` when the body was a property list (legacy reports).
EVIDENCE_METHOD_PLIST = "ips_plist_body"

#: The literal first-line marker some writers emit before the JSON lines.
_JSON_MARKER = "JSON dump header"

#: ``"Exception Type": "EXC_BAD_ACCESS (SIGSEGV)"`` -- the signal is in parens.
_SIGNAL_IN_TYPE = re.compile(r"\((SIG[A-Z0-9]+)\)")

#: Legacy header lines are the front of a plist and often cut mid-object, so
#: the key/value pairs are scraped with a tolerant scanner instead of JSON.
_HEADER_PAIR = re.compile(r'"(?P<key>[^"]+)"\s*:\s*(?:"(?P<text>[^"]*)"|(?P<num>[^,{}]*))')


@dataclass(frozen=True)
class IpsImage:
    """One entry of the report's image list (binary, framework or library)."""

    index: int
    name: str
    path: str | None = None
    uuid: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"index": self.index, "name": self.name}
        if self.path is not None:
            data["path"] = self.path
        if self.uuid is not None:
            data["uuid"] = self.uuid
        return data


@dataclass(frozen=True)
class IpsFrame:
    """One stack frame of the faulting thread."""

    index: int
    image_index: int | None
    image: str | None
    offset: int | None
    symbol: str | None = None
    symbol_location: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"index": self.index}
        if self.image_index is not None:
            data["image_index"] = self.image_index
        data["image"] = self.image
        if self.offset is not None:
            data["offset"] = f"0x{self.offset:x}"
        if self.symbol is not None:
            data["symbol"] = self.symbol
        if self.symbol_location is not None:
            data["symbol_location"] = self.symbol_location
        return data


@dataclass(frozen=True)
class IpsSummary:
    """Bounded, evidence-backed summary of one Apple ``.ips`` crash report."""

    format: str
    product: str | None
    os_version: str | None
    crash_time: str | None
    exception_type: str | None
    exception_signal: str | None
    termination_reason: str | None
    faulting_thread: int | None
    frames: tuple[IpsFrame, ...]
    images: tuple[IpsImage, ...]
    truncated: bool
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method=EVIDENCE_METHOD_JSON,
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view; frame offsets as hex strings."""
        return {
            "format": self.format,
            "product": self.product,
            "os_version": self.os_version,
            "crash_time": self.crash_time,
            "exception_type": self.exception_type,
            "exception_signal": self.exception_signal,
            "termination_reason": self.termination_reason,
            "faulting_thread": self.faulting_thread,
            "frames": [frame.to_dict() for frame in self.frames],
            "images": [image.to_dict() for image in self.images],
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _read_file(path: Path) -> bytes:
    """Read ``path`` whole, refusing files above :data:`MAX_IPS_BYTES`."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise AnalysisError(f"cannot stat {str(path)!r}: {exc}") from exc
    if size > MAX_IPS_BYTES:
        raise AnalysisError(
            f"crash report {str(path)!r} is {size} bytes; the parse budget is "
            f"{MAX_IPS_BYTES} bytes"
        )
    try:
        return path.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"cannot read {str(path)!r}: {exc}") from exc


def _as_int(value: Any) -> int | None:
    """Return ``value`` as an ``int`` when it is one (bools excluded)."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _first_key(mapping: dict[str, Any], *keys: str) -> Any:
    """Return the first present, non-empty value among ``keys``."""
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def _parse_header_line(line: str) -> dict[str, str]:
    """Extract the metadata pairs of the report's first line.

    A modern header is complete JSON and parses exactly; a legacy header is the
    cut-off front of a plist, so the pairs are scraped with a tolerant scanner.
    Whatever fails stays absent rather than raising: the body carries the same
    fields in both generations.
    """
    header: dict[str, str] = {}
    stripped = line.strip()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            for key, value in parsed.items():
                if value is not None:
                    header[str(key)] = str(value)
            return header
    for match in _HEADER_PAIR.finditer(stripped):
        text = match.group("text")
        num = match.group("num")
        header[match.group("key")] = text if text is not None else (num or "").strip()
    return header


def _json_object_at_start(text: str) -> dict[str, Any] | None:
    """Parse ``text`` as one JSON object; ``None`` when it is not one."""
    try:
        parsed = json.loads(text)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _json_object_after_marker(body: str) -> dict[str, Any] | None:
    """Parse the first JSON object line of ``body`` (marker format)."""
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parsed = _json_object_at_start(stripped)
        if parsed is not None:
            return parsed
        return None
    return None


def _looks_like_plist(text: str) -> bool:
    """Return True when ``text`` opens like an XML property list."""
    head = text.lstrip()[:256]
    return head.startswith("<?xml") or "<plist" in head


def _split_report(raw_text: str) -> tuple[dict[str, str], str, str]:
    """Detect the generation and split the report into header/body text.

    Returns ``(header, body_text, body_format)`` where ``body_format`` is
    ``"json"`` or ``"plist"``. A file that matches neither generation raises
    :class:`AnalysisError`: guessing a format would only mislabel the finding.
    """
    first_line = next((line for line in raw_text.splitlines() if line.strip()), "")
    if not first_line:
        raise AnalysisError("not an Apple .ips crash report: the file is empty")
    if first_line.strip() == _JSON_MARKER:
        body = raw_text.split(first_line, 1)[1].strip()
        if _json_object_after_marker(body) is None:
            raise AnalysisError(
                "not an Apple .ips crash report: the JSON dump header marker "
                "is not followed by a JSON body"
            )
        return {}, body, "json"
    header = _parse_header_line(first_line)
    body = raw_text.split(first_line, 1)[1].lstrip() if first_line in raw_text else ""
    if _json_object_at_start(body) is not None:
        return header, body, "json"
    if _looks_like_plist(body) or body.startswith("bplist"):
        return header, body, "plist"
    if header:
        raise AnalysisError(
            "not an Apple .ips crash report: the header line parses, but the "
            "body is neither JSON nor a property list"
        )
    raise AnalysisError(
        "not an Apple .ips crash report: expected a JSON dump header or a "
        "plist header line"
    )


def _extract_termination(payload: Any) -> str | None:
    """Flatten a termination block (dict or string) into one reason string."""
    if isinstance(payload, str):
        return payload or None
    if not isinstance(payload, dict):
        return None
    parts: list[str] = []
    for key in ("indicator", "namespace", "reason", "details", "description"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            parts.append(value)
    return " | ".join(parts) if parts else None


def _images_from_payload(
    raw_images: Any,
    truncated_flag: list[bool],
    warnings: list[str],
) -> tuple[IpsImage, ...]:
    """Build the bounded image list from the raw JSON/plist array."""
    if not isinstance(raw_images, list):
        if raw_images is not None:
            warnings.append("images list is not an array; ignored")
        return ()
    images: list[IpsImage] = []
    for index, entry in enumerate(raw_images):
        if len(images) >= MAX_IMAGES:
            truncated_flag[0] = True
            warnings.append(
                f"image limit {MAX_IMAGES} reached; further images are dropped"
            )
            break
        if not isinstance(entry, dict):
            warnings.append(f"image {index} is not a dictionary; skipped")
            continue
        name = entry.get("name") or entry.get("CFBundleName") or f"image {index}"
        path = entry.get("path") or entry.get("CFBundlePath")
        uuid = entry.get("uuid")
        images.append(
            IpsImage(
                index=index,
                name=str(name),
                path=str(path) if path else None,
                uuid=str(uuid) if uuid else None,
            )
        )
    return tuple(images)


def _frames_from_payload(
    raw_frames: Any,
    images: tuple[IpsImage, ...],
    truncated_flag: list[bool],
    warnings: list[str],
) -> tuple[IpsFrame, ...]:
    """Build the bounded faulting-thread frames from the raw array."""
    if not isinstance(raw_frames, list):
        if raw_frames is not None:
            warnings.append("faulting thread has no frame array; ignored")
        return ()
    frames: list[IpsFrame] = []
    for index, entry in enumerate(raw_frames):
        if len(frames) >= MAX_FRAMES:
            truncated_flag[0] = True
            warnings.append(
                f"frame limit {MAX_FRAMES} reached; further frames are dropped"
            )
            break
        image_index: int | None = None
        offset: int | None = None
        symbol: str | None = None
        symbol_location: int | None = None
        if isinstance(entry, dict):
            image_index = _as_int(entry.get("imageIndex"))
            offset = _as_int(entry.get("imageOffset"))
            raw_symbol = entry.get("symbol")
            symbol = str(raw_symbol) if raw_symbol else None
            symbol_location = _as_int(entry.get("symbolLocation"))
        elif isinstance(entry, list) and entry:
            # Some writers emit [imageIndex, imageOffset] pairs.
            image_index = _as_int(entry[0])
            offset = _as_int(entry[1]) if len(entry) > 1 else None
        else:
            warnings.append(f"frame {index} has an unsupported shape; skipped")
            continue
        image_name: str | None = None
        if image_index is not None and 0 <= image_index < len(images):
            image_name = images[image_index].name
        frames.append(
            IpsFrame(
                index=index,
                image_index=image_index,
                image=image_name,
                offset=offset,
                symbol=symbol,
                symbol_location=symbol_location,
            )
        )
    return tuple(frames)


def _pick_faulting_thread(
    raw_threads: Any,
    declared_index: int | None,
    warnings: list[str],
) -> tuple[int | None, dict[str, Any]]:
    """Return ``(thread_index, thread_dict)`` for the faulting thread.

    ``declared_index`` wins when it points at a real thread; otherwise the
    first thread flagged ``triggered`` is taken; failing that, the first
    thread. A report without usable threads returns ``(None, {})`` and a
    warning, not an error: metadata and images may still be worth reporting.
    """
    if not isinstance(raw_threads, list) or not raw_threads:
        if raw_threads is not None:
            warnings.append("threads list is not an array; ignored")
        return None, {}
    index: int | None = None
    if declared_index is not None and 0 <= declared_index < len(raw_threads):
        index = declared_index
    else:
        if declared_index is not None:
            warnings.append(
                f"faulting thread index {declared_index} is out of range; "
                "falling back to the triggered thread"
            )
        for position, thread in enumerate(raw_threads):
            if isinstance(thread, dict) and thread.get("triggered"):
                index = position
                break
        if index is None:
            index = 0
    thread = raw_threads[index]
    if not isinstance(thread, dict):
        warnings.append(f"thread {index} is not a dictionary; no frames decoded")
        return index, {}
    return index, thread


def _as_plist_dict(payload: Any, warnings: list[str]) -> dict[str, Any]:
    """Coerce a parsed plist body into a dictionary or raise a typed error."""
    if isinstance(payload, dict):
        return payload
    warnings.append("plist body is not a dictionary; ignored")
    return {}


def _evidence_for(
    method: str,
    frames: tuple[IpsFrame, ...],
    exception_type: str | None,
    image_count: int,
) -> Evidence:
    """Build the report-level evidence record from what was actually decoded."""
    if frames and exception_type:
        confidence = Confidence.HIGH
        detail = (
            f"{len(frames)} frame(s) of the faulting thread and the exception "
            f"record parsed; {image_count} image(s) listed"
        )
    elif frames or exception_type:
        confidence = Confidence.MEDIUM
        detail = f"partial crash record parsed; {image_count} image(s) listed"
    else:
        confidence = Confidence.LOW
        detail = f"metadata only; {image_count} image(s) listed"
    return Evidence(
        source=EVIDENCE_SOURCE,
        method=method,
        confidence=confidence,
        detail=detail,
    )


def _summary_from_json(
    header: dict[str, str],
    body: dict[str, Any],
    truncated_flag: list[bool],
    warnings: list[str],
) -> IpsSummary:
    """Extract an :class:`IpsSummary` from a JSON-generation report."""
    images = _images_from_payload(body.get("images"), truncated_flag, warnings)
    declared = _as_int(body.get("faultingThread"))
    thread_index, thread = _pick_faulting_thread(body.get("threads"), declared, warnings)
    frames = _frames_from_payload(thread.get("frames"), images, truncated_flag, warnings)
    raw_exception = body.get("exception")
    exception = raw_exception if isinstance(raw_exception, dict) else {}
    exception_type = exception.get("type") or body.get("exceptionType")
    exception_signal = exception.get("signal")
    if exception_signal is None and isinstance(exception_type, str):
        match = _SIGNAL_IN_TYPE.search(exception_type)
        exception_signal = match.group(1) if match else None
    product = header.get("product") or body.get("product")
    os_version = header.get("os_version") or body.get("os_version")
    crash_time = header.get("timestamp") or body.get("timestamp")
    termination = _extract_termination(body.get("termination"))
    return IpsSummary(
        format="json",
        product=product,
        os_version=os_version,
        crash_time=crash_time,
        exception_type=str(exception_type) if exception_type else None,
        exception_signal=str(exception_signal) if exception_signal else None,
        termination_reason=termination,
        faulting_thread=thread_index,
        frames=frames,
        images=images,
        truncated=truncated_flag[0],
        warnings=warnings,
        evidence=_evidence_for(
            EVIDENCE_METHOD_JSON, frames, str(exception_type) if exception_type else None, len(images)
        ),
    )


def _summary_from_plist(
    header: dict[str, str],
    body: dict[str, Any],
    truncated_flag: list[bool],
    warnings: list[str],
) -> IpsSummary:
    """Extract an :class:`IpsSummary` from a plist-generation report."""
    images = _images_from_payload(body.get("Images"), truncated_flag, warnings)
    declared = _as_int(body.get("Faulting Thread"))
    if declared is None:
        triggered = body.get("Triggered by Thread")
        declared = _as_int(triggered) if triggered is not None else None
    thread_index, thread = _pick_faulting_thread(body.get("Threads"), declared, warnings)
    frames = _frames_from_payload(thread.get("frames"), images, truncated_flag, warnings)
    exception_type = body.get("Exception Type") or header.get("exception")
    exception_signal = body.get("Exception Signal")
    if exception_signal is None and isinstance(exception_type, str):
        match = _SIGNAL_IN_TYPE.search(exception_type)
        exception_signal = match.group(1) if match else None
    product = header.get("product") or body.get("Product") or body.get("product")
    os_version = body.get("OS Version") or header.get("os_version")
    crash_time = body.get("Time Stamp") or header.get("timestamp")
    termination = _extract_termination(body.get("Termination Reason"))
    return IpsSummary(
        format="plist",
        product=product,
        os_version=os_version,
        crash_time=crash_time,
        exception_type=str(exception_type) if exception_type else None,
        exception_signal=str(exception_signal) if exception_signal else None,
        termination_reason=termination,
        faulting_thread=thread_index,
        frames=frames,
        images=images,
        truncated=truncated_flag[0],
        warnings=warnings,
        evidence=_evidence_for(
            EVIDENCE_METHOD_PLIST,
            frames,
            str(exception_type) if exception_type else None,
            len(images),
        ),
    )


def _merge_json_lines(body: str) -> dict[str, Any] | None:
    """Merge every JSON object line of ``body`` into one payload dict.

    The marker generation sometimes writes the dump header and the crash body
    as two separate lines after the marker; merging lets the same extraction
    code serve both. Lines that are not JSON objects are skipped, so a stray
    log line between the JSON lines cannot abort the parse.
    """
    merged: dict[str, Any] = {}
    found = False
    for line in body.splitlines():
        parsed = _json_object_at_start(line.strip())
        if parsed is not None:
            merged.update(parsed)
            found = True
    return merged if found else None


def parse_ips_report(path: str | Path) -> IpsSummary:
    """Parse an Apple ``.ips`` crash report at ``path``.

    Both generations are read: the modern two-JSON-line format (with or
    without a leading ``JSON dump header`` marker) and the legacy
    header-line-plus-XML-plist format. The result carries the product, OS
    version, crash time, exception type/signal, termination reason, the
    faulting thread's frames (images, offsets, symbols when present) and the
    bounded image list.

    Args:
        path: Path to the ``.ips`` crash report.

    Returns:
        The bounded :class:`IpsSummary` with its evidence record; ``truncated``
        plus ``warnings`` describe every cut or skipped entry.

    Raises:
        AnalysisError: If the file is missing, unreadable, larger than
            :data:`MAX_IPS_BYTES`, empty, or neither JSON-body nor plist-body
            in shape.
    """
    target = Path(path)
    warnings: list[str] = []
    truncated_flag = [False]
    raw = _read_file(target)
    text = raw.decode("utf-8", errors="replace")

    header, body, body_format = _split_report(text)
    if body_format == "json":
        payload = _json_object_at_start(body)
        if payload is None:
            payload = _merge_json_lines(body)
        if payload is None:
            raise AnalysisError(
                "not an Apple .ips crash report: the body is not a JSON object"
            )
        return _summary_from_json(header, payload, truncated_flag, warnings)
    try:
        payload = plistlib.loads(body.encode("utf-8", errors="replace"))
    except (ValueError, plistlib.InvalidFileException) as exc:
        raise AnalysisError(f"malformed .ips plist body: {exc}") from exc
    return _summary_from_plist(
        header, _as_plist_dict(payload, warnings), truncated_flag, warnings
    )

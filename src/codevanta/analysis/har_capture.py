"""HAR (HTTP Archive) capture summariser (read-only, offline, pure parsing).

A HAR file is a JSON document with the shape ``{"log": {"entries": [...]}}``
where every entry records one HTTP request/response pair::

    entry["request"]["method"] / ["url"]
    entry["response"]["status"] / ["content"]["mimeType"]
    entry["response"]["content"]["text"]      (optionally base64, see encoding)
    entry["startedDateTime"]                  (ISO-8601 string)
    entry["time"]                             (milliseconds, float)

The summariser walks the entries once and produces a frozen, JSON-safe
:class:`HarCaptureSummary`: bounded per-entry rows (method + url + status),
the started-time span, the summed request time, a content-type histogram,
the unique host set and a gRPC flag per entry. An entry counts as gRPC when
its response content-type contains ``application/grpc`` *or* its body starts
with the 5-byte gRPC frame prefix (1 flag byte in {0, 1} + 4-byte big-endian
frame length equal to the remaining bytes); the frame length is then reported
as the message length.

Guarantees:

* Pure parsing: :func:`summarise_har` works on bytes with no filesystem
  access, so it is always available offline.
* Bounded work: at most :data:`MAX_ENTRIES` entries are walked, at most
  :data:`MAX_ROWS` rows are kept, the histogram keeps at most
  :data:`MAX_CONTENT_TYPES` distinct content types and the host set at most
  :data:`MAX_HOSTS` names; anything beyond sets ``truncated`` and is
  summarised away. Body probes never read more than
  :data:`MAX_BODY_PROBE_BYTES` per entry.
* Nothing here executes, writes, or fetches; input that is not a HAR
  document raises :class:`~codevanta.core.report.AnalysisError` naming the
  defect -- never a raw ``KeyError`` traceback.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_METHOD",
    "EVIDENCE_SOURCE",
    "MAX_BODY_PROBE_BYTES",
    "MAX_ENTRIES",
    "MAX_FILE_BYTES",
    "MAX_HOSTS",
    "MAX_ROWS",
    "MAX_URL_CHARS",
    "HarCaptureSummary",
    "HarEntryRow",
    "load_har",
    "summarise_har",
]

#: Hard ceiling on entries walked by one summary (bounded work; entries past
#: this are not visited at all, so the count stops at the ceiling).
MAX_ENTRIES = 4096

#: Per-entry rows kept before the rest are counted but not listed.
MAX_ROWS = 200

#: Distinct content types kept in the histogram before the rest are dropped.
MAX_CONTENT_TYPES = 16

#: Unique hosts kept before further hosts only set ``truncated``.
MAX_HOSTS = 32

#: Ceiling on the bytes read from one response body for gRPC frame probing.
MAX_BODY_PROBE_BYTES = 4096

#: Ceiling on base64 body text that will be decoded for frame probing.
MAX_BODY_B64_CHARS = 8 * 1024 * 1024

#: Hard ceiling on the bytes one :func:`load_har` call will read.
MAX_FILE_BYTES = 256 * 1024 * 1024

#: Characters of one URL kept in a row before the rest are cut.
MAX_URL_CHARS = 512

#: Evidence source shared by every record in this module.
EVIDENCE_SOURCE = "web.har"

#: Evidence method for capture summaries.
EVIDENCE_METHOD = "har_entry_walk"

_GRPC_CONTENT_TYPE = "application/grpc"


@dataclass(frozen=True)
class HarEntryRow:
    """One HTTP request/response pair, summarised (bounded)."""

    method: str
    url: str
    status: int
    time_ms: float
    content_type: str
    grpc: bool
    grpc_length: int | None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record."""
        return {
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "time_ms": self.time_ms,
            "content_type": self.content_type,
            "grpc": self.grpc,
            "grpc_length": self.grpc_length,
        }


@dataclass(frozen=True)
class HarCaptureSummary:
    """Bounded summary of one HAR capture.

    Attributes:
        entry_count: Entries walked (never above :data:`MAX_ENTRIES`).
        rows: First :data:`MAX_ROWS` walked entries as bounded rows.
        total_time_ms: Sum of walked entries' ``time`` fields, rounded to
            milliseconds.
        started_first: ``startedDateTime`` of the first walked entry (or
            ``""`` when absent).
        started_last: ``startedDateTime`` of the last walked entry (or
            ``""`` when absent).
        content_types: Response content-type histogram, at most
            :data:`MAX_CONTENT_TYPES` distinct keys.
        hosts: Unique request hosts in first-seen order, at most
            :data:`MAX_HOSTS`.
        grpc_count: Walked entries flagged as gRPC.
        truncated: True when any bound (entries, rows, histogram, hosts)
            cut the walk short.
        evidence: Evidence record for the summary.
    """

    entry_count: int
    rows: tuple[HarEntryRow, ...]
    total_time_ms: float
    started_first: str
    started_last: str
    content_types: dict[str, int]
    hosts: tuple[str, ...]
    grpc_count: int
    truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record."""
        return {
            "entry_count": self.entry_count,
            "total_time_ms": self.total_time_ms,
            "started_first": self.started_first,
            "started_last": self.started_last,
            "content_types": dict(self.content_types),
            "hosts": list(self.hosts),
            "grpc_count": self.grpc_count,
            "truncated": self.truncated,
            "rows": [row.to_dict() for row in self.rows],
            "evidence": self.evidence.to_dict(),
        }
def _as_int(value: Any) -> int:
    """Return ``value`` as a plain int, or ``0`` for anything else."""
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


def _as_float(value: Any) -> float:
    """Return ``value`` as a plain float, or ``0.0`` for anything else."""
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, int):
        return float(value)
    if isinstance(value, float):
        return value
    return 0.0


def _as_str(value: Any) -> str:
    """Return ``value`` as a plain str, or ``""`` for anything else."""
    return value if isinstance(value, str) else ""


def _response_headers_content_type(response: dict[str, Any]) -> str:
    """Extract the content-type from response headers, or ``""``."""
    headers = response.get("headers")
    if not isinstance(headers, list):
        return ""
    for header in headers:
        if not isinstance(header, dict):
            continue
        name = _as_str(header.get("name")).lower()
        if name == "content-type":
            return _as_str(header.get("value"))
    return ""


def _content_type(entry: dict[str, Any]) -> str:
    """Normalised response content type (lowercase, parameters dropped)."""
    response = entry.get("response")
    content = response.get("content") if isinstance(response, dict) else None
    mime = ""
    if isinstance(content, dict):
        mime = _as_str(content.get("mimeType"))
    if not mime and isinstance(response, dict):
        mime = _response_headers_content_type(response)
    return mime.split(";", 1)[0].strip().lower()


def looks_like_grpc_frame(body: bytes) -> bool:
    """Return True when ``body`` starts with a valid 5-byte gRPC frame prefix.

    The prefix is one flag byte in ``{0, 1}`` followed by a 4-byte big-endian
    frame length that must equal the number of remaining bytes.
    """
    if len(body) < 5:
        return False
    if body[0] not in (0, 1):
        return False
    return int.from_bytes(body[1:5], "big") == len(body) - 5


def _response_body(entry: dict[str, Any]) -> bytes:
    """Bounded response body bytes (base64 decoded when HAR says so)."""
    response = entry.get("response")
    content = response.get("content") if isinstance(response, dict) else None
    if not isinstance(content, dict):
        return b""
    text = _as_str(content.get("text"))
    if not text:
        return b""
    if content.get("encoding") == "base64":
        if len(text) > MAX_BODY_B64_CHARS:
            return b""
        try:
            return base64.b64decode(text)
        except (ValueError, TypeError):
            return b""
    return text.encode("utf-8", errors="replace")[:MAX_BODY_PROBE_BYTES]


def _grpc_info(entry: dict[str, Any]) -> tuple[bool, int | None]:
    """Return ``(is_grpc, frame_message_length)`` for one entry.

    Either an ``application/grpc`` content type or a body that starts with a
    valid 5-byte gRPC frame prefix flags the entry; the frame length is only
    reported when the prefix is actually present.
    """
    grpc = _GRPC_CONTENT_TYPE in _content_type(entry)
    body = _response_body(entry)[: MAX_BODY_PROBE_BYTES + 5]
    grpc_length: int | None = None
    if looks_like_grpc_frame(body):
        grpc = True
        grpc_length = int.from_bytes(body[1:5], "big")
    return grpc, grpc_length


def summarise_har(data: bytes) -> HarCaptureSummary:
    """Summarise raw HAR JSON bytes (pure; no filesystem access).

    Raises:
        AnalysisError: If ``data`` is not JSON, not a JSON object, or its
            ``log`` is missing or does not carry an ``entries`` list -- in
            short, whenever the input is not a HAR document.
    """
    try:
        document = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise AnalysisError(f"not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise AnalysisError("not a HAR document: top level is not a JSON object")
    log = document.get("log")
    if not isinstance(log, dict):
        raise AnalysisError('not a HAR document: no "log" object')
    entries = log.get("entries")
    if not isinstance(entries, list):
        raise AnalysisError('not a HAR document: "log.entries" is not a list')

    rows: list[HarEntryRow] = []
    total_time = 0.0
    started_first = ""
    started_last = ""
    content_types: dict[str, int] = {}
    hosts: list[str] = []
    grpc_count = 0
    walked = 0
    truncated = False

    for index, entry in enumerate(entries):
        if index >= MAX_ENTRIES:
            truncated = True
            break
        if not isinstance(entry, dict):
            truncated = True
            continue
        request = entry.get("request")
        if not isinstance(request, dict):
            truncated = True
            continue
        response = entry.get("response")
        walked += 1
        method = _as_str(request.get("method"))[:32]
        url = _as_str(request.get("url"))[:MAX_URL_CHARS]
        status = _as_int(response.get("status")) if isinstance(response, dict) else 0
        time_ms = _as_float(entry.get("time"))
        started = _as_str(entry.get("startedDateTime"))
        content_type = _content_type(entry)
        grpc, grpc_length = _grpc_info(entry)

        total_time += time_ms
        if not started_first:
            started_first = started
        started_last = started
        if grpc:
            grpc_count += 1
        if content_type:
            if content_type in content_types:
                content_types[content_type] += 1
            elif len(content_types) < MAX_CONTENT_TYPES:
                content_types[content_type] = 1
            else:
                truncated = True
        host = urlsplit(url).hostname or ""
        if host and host not in hosts:
            if len(hosts) < MAX_HOSTS:
                hosts.append(host)
            else:
                truncated = True
        if len(rows) < MAX_ROWS:
            rows.append(
                HarEntryRow(
                    method=method,
                    url=url,
                    status=status,
                    time_ms=time_ms,
                    content_type=content_type,
                    grpc=grpc,
                    grpc_length=grpc_length,
                )
            )
        else:
            truncated = True

    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method=EVIDENCE_METHOD,
        confidence=Confidence.CERTAIN,
        extra={"entries": walked, "grpc_entries": grpc_count},
    )
    return HarCaptureSummary(
        entry_count=walked,
        rows=tuple(rows),
        total_time_ms=round(total_time, 3),
        started_first=started_first,
        started_last=started_last,
        content_types=content_types,
        hosts=tuple(hosts),
        grpc_count=grpc_count,
        truncated=truncated,
        evidence=evidence,
    )


def load_har(path: Path) -> HarCaptureSummary:
    """Read one HAR file (bounded) and summarise it (read-only)."""
    if not path.exists():
        raise AnalysisError(f"file not found: {path}")
    if not path.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise AnalysisError(f"HAR too large: {size} bytes (limit {MAX_FILE_BYTES})")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"cannot read {str(path)!r}: {exc}") from exc
    return summarise_har(data)

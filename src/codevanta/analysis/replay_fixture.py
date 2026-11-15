"""HAR capture to deterministic replay fixture (offline, stdlib only).

REA (https://rea.tools) frames a recorded application surface as a
reinforcement-learning *environment*: a bounded, deterministic description
of the endpoints, requests and responses an application actually exchanged,
which an agent harness can replay or train against offline. This module
builds the offline half of that idea inside CODEVANTA's static model:
:func:`build_replay_fixture` reads one HTTP Archive (HAR) file and emits a
:class:`ReplayFixtureReport` -- normalised request/response rows plus an
endpoint manifest -- without CODEVANTA ever serving traffic, opening a
socket or executing anything. The honest difference from a real RL
environment: CODEVANTA produces the fixture *document*; replaying it is
another tool's job.

Guarantees:

* Pure parsing, stdlib only: the HAR is read once, bounded by
  :data:`codevanta.analysis.har_capture.MAX_FILE_BYTES` (reused by import;
  the existing :func:`~codevanta.analysis.har_capture.load_har` API returns
  only a summary, so raw entries are re-parsed here under the same bounds),
  and nothing is fetched, written or executed afterwards.
* Deterministic: entries are sorted by ``startedDateTime`` (stable on the
  original order), endpoints and summary maps are emitted in sorted order,
  and :meth:`ReplayFixtureReport.to_fixture_json` serialises with
  ``sort_keys`` -- the same input file yields byte-identical documents.
* Bounded work: entries, query pairs, headers, header values, endpoint
  rows, host rows, warnings and body previews all carry hard caps; every
  cap that fires is reported through a ``truncated`` flag or a warning --
  never silently. Response bodies are never inlined: only their size,
  SHA-256, mime type and (when the body fits ``max_body_bytes``) a base64
  preview of the first :data:`PREVIEW_BYTES` bytes are stored.
* The fixture is *derived data*: methods are upper-cased, long header
  values are cut, path segments collapse to ``{n}`` / ``{hex}`` templates.
  Those normalisation choices are documented here and echoed by the report
  evidence record, which is why its confidence is *medium* rather than
  certain.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from codevanta.analysis.har_capture import MAX_BODY_B64_CHARS, MAX_FILE_BYTES
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_BODY_BYTES",
    "DEFAULT_MAX_ENTRIES",
    "EVIDENCE_METHOD",
    "EVIDENCE_SOURCE",
    "EndpointRecord",
    "FixtureEntry",
    "MAX_BODY_BYTES_LIMIT",
    "MAX_ENDPOINTS",
    "MAX_ENTRIES_LIMIT",
    "MAX_HEADER_COUNT",
    "MAX_HEADER_NAME_CHARS",
    "MAX_HEADER_VALUE_CHARS",
    "MAX_HOSTS",
    "MAX_QUERY_FIELD_CHARS",
    "MAX_QUERY_PAIRS",
    "MAX_WARNINGS",
    "PREVIEW_BYTES",
    "ReplayFixtureReport",
    "ResponseBodyFacts",
    "build_replay_fixture",
]

#: Default ceiling on entries kept in one fixture (the "replay script").
DEFAULT_MAX_ENTRIES = 500

#: Highest ``max_entries`` value accepted from a caller.
MAX_ENTRIES_LIMIT = 4096

#: Default ceiling on a response body eligible for a stored preview.
DEFAULT_MAX_BODY_BYTES = 262_144

#: Highest ``max_body_bytes`` value accepted from a caller.
MAX_BODY_BYTES_LIMIT = 16 * 1024 * 1024

#: Query pairs kept per entry before the rest are dropped with a flag.
MAX_QUERY_PAIRS = 64

#: Characters kept from one query name or value.
MAX_QUERY_FIELD_CHARS = 512

#: Request headers kept per entry before the rest are dropped with a flag.
MAX_HEADER_COUNT = 128

#: Characters kept from one request header name.
MAX_HEADER_NAME_CHARS = 128

#: Characters kept from one request header value.
MAX_HEADER_VALUE_CHARS = 512

#: Distinct endpoints kept in the manifest before further ones are only
#: counted (the honest distinct total is still reported).
MAX_ENDPOINTS = 256

#: Unique host names listed in the summary before further ones are only
#: counted.
MAX_HOSTS = 32

#: Warnings kept in one report.
MAX_WARNINGS = 32

#: Bytes of a response body inlined into the base64 preview.
PREVIEW_BYTES = 128

#: Evidence source shared by every record in this module.
EVIDENCE_SOURCE = "replay.fixture"

#: Evidence method for fixture reports.
EVIDENCE_METHOD = "har_normalization"

_MAX_METHOD_CHARS = 32
_MAX_SCHEME_CHARS = 16
_MAX_HOST_CHARS = 256
_MAX_PATH_CHARS = 2048
_MAX_STATUS_TEXT_CHARS = 64
_MAX_STARTED_CHARS = 64
_MAX_MIME_CHARS = 256

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_MIN_HEX_SEGMENT = 8


@dataclass(frozen=True)
class ResponseBodyFacts:
    """Bounded facts about one response body (the body itself is not kept).

    Attributes:
        size: Decoded body size in bytes (0 when absent or undecodable).
        sha256: SHA-256 hex digest of the decoded body, or ``""`` when there
            is no decodable body.
        preview_b64: Base64 of the first :data:`PREVIEW_BYTES` bytes when
            the body is present, decodable and within ``max_body_bytes``;
            otherwise ``None``.
        mime: ``content.mimeType`` value (safety-capped).
        has_body: True when ``content.text`` was present at all.
        preview_omitted: True when the body exceeded ``max_body_bytes`` and
            was deliberately not previewed.
    """

    size: int
    sha256: str
    preview_b64: str | None
    mime: str
    has_body: bool
    preview_omitted: bool

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record with a stable key set."""
        return {
            "has_body": self.has_body,
            "size": self.size,
            "sha256": self.sha256,
            "mime": self.mime,
            "preview_b64": self.preview_b64,
            "preview_omitted": self.preview_omitted,
        }


@dataclass(frozen=True)
class FixtureEntry:
    """One normalised request/response pair from the capture.

    Attributes:
        index: Position of the entry in the original HAR (0-based), kept so
            replay tools can cite the source row.
        started: ``startedDateTime`` string (safety-capped), the sort key.
        method: Request method, upper-cased.
        scheme: URL scheme, lower-cased.
        host: URL hostname, lower-cased.
        path: URL path.
        query: Ordered ``(name, value)`` pairs, from ``queryString`` when
            present else percent-decoded from the URL, capped.
        request_headers: Ordered ``(name, value)`` pairs, capped.
        status: Response status code (0 when absent/garbage).
        status_text: Response ``statusText``.
        content_type: ``Content-Type`` response header (selected).
        content_length: ``Content-Length`` response header (selected).
        body: Bounded body facts; the body bytes themselves are never kept.
        time_ms: Entry ``time`` as a float, or ``None`` when absent.
        wait_ms: ``timings.wait`` as a float, or ``None`` when absent.
        query_truncated: True when the query had more pairs than the cap.
        headers_truncated: True when the request had more headers than the
            cap.
        header_values_truncated: True when any header name/value was cut.
    """

    index: int
    started: str
    method: str
    scheme: str
    host: str
    path: str
    query: tuple[tuple[str, str], ...]
    request_headers: tuple[tuple[str, str], ...]
    status: int
    status_text: str
    content_type: str
    content_length: str
    body: ResponseBodyFacts
    time_ms: float | None
    wait_ms: float | None
    query_truncated: bool = False
    headers_truncated: bool = False
    header_values_truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record."""
        data: dict[str, Any] = {
            "index": self.index,
            "started": self.started,
            "method": self.method,
            "scheme": self.scheme,
            "host": self.host,
            "path": self.path,
            "query": [[name, value] for name, value in self.query],
            "request_headers": [[name, value] for name, value in self.request_headers],
            "status": self.status,
            "status_text": self.status_text,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "body": self.body.to_dict(),
            "time_ms": self.time_ms,
            "wait_ms": self.wait_ms,
        }
        if self.query_truncated:
            data["query_truncated"] = True
        if self.headers_truncated:
            data["headers_truncated"] = True
        if self.header_values_truncated:
            data["header_values_truncated"] = True
        return data


@dataclass(frozen=True)
class EndpointRecord:
    """One unique ``(method, host, path-template)`` surface point.

    Attributes:
        method: Upper-cased request method.
        host: Request hostname.
        path_template: Path with numeric segments collapsed to ``{n}`` and
            long hex runs collapsed to ``{hex}``.
        count: Entries observed against this endpoint (kept entries only).
        statuses: Hit counts keyed by the literal status code as a string.
    """

    method: str
    host: str
    path_template: str
    count: int
    statuses: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record."""
        return {
            "method": self.method,
            "host": self.host,
            "path_template": self.path_template,
            "count": self.count,
            "statuses": dict(self.statuses),
        }


@dataclass(frozen=True)
class ReplayFixtureReport:
    """The bounded, deterministic replay fixture for one HAR capture.

    Attributes:
        har_path: Path of the source HAR as given.
        har_sha256: SHA-256 hex digest of the HAR file bytes.
        entries: Normalised entries, sorted by ``startedDateTime`` (stable).
        endpoints: Manifest rows, sorted by ``(host, template, method)``.
        endpoint_count: Distinct endpoints found (honest even past the cap).
        total_entries: Entries kept in the fixture (``== len(entries)``).
        har_entry_count: Entries present in the HAR before any cap.
        unique_hosts: Unique hosts, sorted, at most :data:`MAX_HOSTS`.
        host_count: Distinct hosts found (honest even past the cap).
        total_body_bytes: Sum of kept entries' response body sizes.
        method_counts: Hit counts per request method, sorted by method.
        status_classes: Hit counts per status class (``2xx`` ... ``5xx``,
            ``other``), sorted by class.
        truncated: True when any cap fired.
        warnings: Bounded, deterministically ordered cap/loss warnings.
        evidence: Evidence record (medium confidence: derived data).
    """

    har_path: str
    har_sha256: str
    entries: tuple[FixtureEntry, ...]
    endpoints: tuple[EndpointRecord, ...]
    endpoint_count: int
    total_entries: int
    har_entry_count: int
    unique_hosts: tuple[str, ...]
    host_count: int
    total_body_bytes: int
    method_counts: dict[str, int]
    status_classes: dict[str, int]
    truncated: bool
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Return the full JSON-safe record (summary nested under
        ``summary``, entries and manifest both included)."""
        return {
            "har_path": self.har_path,
            "har_sha256": self.har_sha256,
            "summary": {
                "total_entries": self.total_entries,
                "har_entry_count": self.har_entry_count,
                "unique_hosts": list(self.unique_hosts),
                "host_count": self.host_count,
                "total_body_bytes": self.total_body_bytes,
                "method_counts": dict(self.method_counts),
                "status_classes": dict(self.status_classes),
            },
            "entries": [entry.to_dict() for entry in self.entries],
            "endpoints": [endpoint.to_dict() for endpoint in self.endpoints],
            "endpoint_count": self.endpoint_count,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }

    def to_fixture_json(self) -> str:
        """Return the standalone ``{"fixture": ..., "manifest": ...}`` document.

        The fixture side carries provenance, the session summary, the
        normalised entries and the warnings; the manifest side carries the
        endpoint surface. Serialised with sorted keys so the same report
        always produces byte-identical output.
        """
        data = self.to_dict()
        fixture = {
            key: value for key, value in data.items() if key != "endpoints"
        }
        manifest = {
            "endpoints": data["endpoints"],
            "endpoint_count": self.endpoint_count,
            "truncated": self.endpoint_count > len(self.endpoints),
        }
        return json.dumps({"fixture": fixture, "manifest": manifest}, sort_keys=True, indent=2)


def _as_int(value: Any) -> int:
    """Return ``value`` as a plain int, or ``0`` for anything else."""
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


def _as_str(value: Any) -> str:
    """Return ``value`` as a plain str, or ``""`` for anything else."""
    return value if isinstance(value, str) else ""


def _as_float_or_none(value: Any) -> float | None:
    """Return ``value`` as a float when it is a real number, else ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _cut(value: str, limit: int) -> tuple[str, bool]:
    """Return ``(value, cut?)`` after cutting to ``limit`` characters."""
    if len(value) > limit:
        return value[:limit], True
    return value, False


def _warn(warnings: list[str], message: str) -> None:
    """Append one warning unless the cap has been reached."""
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)


def _read_har(path: Path) -> tuple[bytes, dict[str, Any]]:
    """Read one HAR file under the shared size bound and parse it as JSON.

    Raises:
        AnalysisError: The path is missing or not a regular file, the file
            exceeds :data:`codevanta.analysis.har_capture.MAX_FILE_BYTES`,
            it cannot be read, or it is not a JSON object.
    """
    if not path.exists():
        raise AnalysisError(f"file not found: {path}")
    if not path.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise AnalysisError(f"HAR too large: {size} bytes (limit {MAX_FILE_BYTES})")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"cannot read {str(path)!r}: {exc}") from exc
    try:
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise AnalysisError(f"not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise AnalysisError("not a HAR document: top level is not a JSON object")
    return raw, document


def _decode_body(content: dict[str, Any], text: str) -> tuple[bytes, bool]:
    """Return ``(body_bytes, decoded?)`` for one response content object.

    Base64-encoded bodies are decoded under the shared character bound; a
    failed or over-bound decode returns ``(b"", False)`` so the entry still
    lands with ``has_body`` true and an honest warning.
    """
    if not text:
        return b"", True
    if content.get("encoding") == "base64":
        if len(text) > MAX_BODY_B64_CHARS:
            return b"", False
        try:
            return base64.b64decode(text), True
        except (ValueError, TypeError):
            return b"", False
    return text.encode("utf-8", errors="replace"), True


def _url_parts(url: str) -> tuple[str, str, str]:
    """Return ``(scheme, host, path)`` for a request URL, empty on garbage."""
    try:
        parts = urlsplit(url)
        return parts.scheme.lower(), parts.hostname or "", parts.path or "/"
    except ValueError:
        return "", "", "/"


def _query_pairs(request: dict[str, Any], url: str) -> list[tuple[str, str]]:
    """Return the ordered query pairs for one request.

    ``queryString`` wins when it carries at least one well-formed pair;
    otherwise the pairs are percent-decoded from the URL query.
    """
    raw = request.get("queryString")
    pairs: list[tuple[str, str]] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                pairs.append((_as_str(item.get("name")), _as_str(item.get("value"))))
        if pairs:
            return pairs
    try:
        return parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return []


def _request_headers(raw: Any) -> tuple[list[tuple[str, str]], bool, bool]:
    """Return ``(pairs, count_cut?, value_cut?)`` for a request header list."""
    pairs: list[tuple[str, str]] = []
    count_cut = False
    value_cut = False
    if not isinstance(raw, list):
        return pairs, count_cut, value_cut
    for item in raw:
        if not isinstance(item, dict):
            continue
        if len(pairs) >= MAX_HEADER_COUNT:
            count_cut = True
            break
        name = _as_str(item.get("name"))
        value = _as_str(item.get("value"))
        if len(name) > MAX_HEADER_NAME_CHARS:
            name = name[:MAX_HEADER_NAME_CHARS]
            value_cut = True
        if len(value) > MAX_HEADER_VALUE_CHARS:
            value = value[:MAX_HEADER_VALUE_CHARS]
            value_cut = True
        pairs.append((name, value))
    return pairs, count_cut, value_cut


def _response_header(response: dict[str, Any], name: str) -> str:
    """Return one selected response header value, or ``""``."""
    raw = response.get("headers")
    if not isinstance(raw, list):
        return ""
    for item in raw:
        if isinstance(item, dict) and _as_str(item.get("name")).lower() == name:
            return _as_str(item.get("value"))[:MAX_HEADER_VALUE_CHARS]
    return ""


def _path_template(path: str) -> str:
    """Collapse numeric segments to ``{n}`` and long hex runs to ``{hex}``."""
    segments: list[str] = []
    for segment in path.split("/"):
        if segment.isdigit():
            segments.append("{n}")
        elif len(segment) >= _MIN_HEX_SEGMENT and all(ch in _HEX_CHARS for ch in segment):
            segments.append("{hex}")
        else:
            segments.append(segment)
    return "/".join(segments)


def _status_class(status: int) -> str:
    """Return ``2xx``-style class for a status, or ``other``."""
    if 100 <= status < 600:
        return f"{status // 100}xx"
    return "other"


def _norm_entry(
    index: int,
    entry: dict[str, Any],
    max_body_bytes: int,
    counters: dict[str, int],
) -> FixtureEntry:
    """Normalise one validated entry, bumping aggregate cap counters."""
    request = entry["request"]
    response = entry.get("response")
    if not isinstance(response, dict):
        response = {}
    url = _as_str(request.get("url"))
    scheme_raw, host_raw, path_raw = _url_parts(url)

    started, started_cut = _cut(_as_str(entry.get("startedDateTime")), _MAX_STARTED_CHARS)
    method, method_cut = _cut(_as_str(request.get("method")).upper(), _MAX_METHOD_CHARS)
    scheme, scheme_cut = _cut(scheme_raw, _MAX_SCHEME_CHARS)
    host, host_cut = _cut(host_raw, _MAX_HOST_CHARS)
    path, path_cut = _cut(path_raw, _MAX_PATH_CHARS)
    status_text, status_cut = _cut(
        _as_str(response.get("statusText")), _MAX_STATUS_TEXT_CHARS
    )
    if any((started_cut, method_cut, scheme_cut, host_cut, path_cut, status_cut)):
        counters["fields_cut"] = counters.get("fields_cut", 0) + 1

    pairs = _query_pairs(request, url)
    query_truncated = len(pairs) > MAX_QUERY_PAIRS
    if query_truncated:
        counters["query"] = counters.get("query", 0) + 1
        pairs = pairs[:MAX_QUERY_PAIRS]
    query: list[tuple[str, str]] = []
    query_fields_cut = False
    for name, value in pairs:
        cut_name = name[:MAX_QUERY_FIELD_CHARS]
        cut_value = value[:MAX_QUERY_FIELD_CHARS]
        if len(cut_name) != len(name) or len(cut_value) != len(value):
            query_fields_cut = True
        query.append((cut_name, cut_value))
    if query_fields_cut:
        counters["query_fields"] = counters.get("query_fields", 0) + 1

    header_pairs, headers_truncated, values_cut = _request_headers(request.get("headers"))
    if headers_truncated:
        counters["header_count"] = counters.get("header_count", 0) + 1
    if values_cut:
        counters["header_values"] = counters.get("header_values", 0) + 1

    content = response.get("content")
    if not isinstance(content, dict):
        content = {}
    text = _as_str(content.get("text"))
    has_body = bool(text)
    body_bytes, decoded = _decode_body(content, text)
    if has_body and not decoded:
        counters["undecodable"] = counters.get("undecodable", 0) + 1
    size = len(body_bytes) if has_body and decoded else 0
    preview_omitted = has_body and decoded and size > max_body_bytes
    if preview_omitted:
        counters["preview_omitted"] = counters.get("preview_omitted", 0) + 1
    preview = None
    if has_body and decoded and not preview_omitted:
        preview = base64.b64encode(body_bytes[:PREVIEW_BYTES]).decode("ascii")
    body = ResponseBodyFacts(
        size=size,
        sha256=hashlib.sha256(body_bytes).hexdigest() if has_body and decoded else "",
        preview_b64=preview,
        mime=_as_str(content.get("mimeType"))[:_MAX_MIME_CHARS],
        has_body=has_body,
        preview_omitted=preview_omitted,
    )

    timings = entry.get("timings")
    wait_ms = _as_float_or_none(timings.get("wait")) if isinstance(timings, dict) else None

    return FixtureEntry(
        index=index,
        started=started,
        method=method,
        scheme=scheme,
        host=host,
        path=path,
        query=tuple(query),
        request_headers=tuple(header_pairs),
        status=_as_int(response.get("status")),
        status_text=status_text,
        content_type=_response_header(response, "content-type"),
        content_length=_response_header(response, "content-length"),
        body=body,
        time_ms=_as_float_or_none(entry.get("time")),
        wait_ms=wait_ms,
        query_truncated=query_truncated,
        headers_truncated=headers_truncated,
        header_values_truncated=values_cut,
    )


def build_replay_fixture(
    har_path: Path,
    *,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> ReplayFixtureReport:
    """Build the deterministic replay fixture for one HAR capture.

    Args:
        har_path: Path to a recorded HAR file.
        max_entries: Entries kept (1.. :data:`MAX_ENTRIES_LIMIT`); entries
            past the cap are not walked and the truncation is reported.
        max_body_bytes: Bodies at or under this size get a bounded base64
            preview; larger bodies keep only size + SHA-256
            (1.. :data:`MAX_BODY_BYTES_LIMIT`).

    Returns:
        The :class:`ReplayFixtureReport` -- normalised entries sorted by
        ``startedDateTime``, an endpoint manifest of unique
        ``(method, host, path-template)`` rows with counts and status
        distributions, and a session summary.

    Raises:
        AnalysisError: The path is missing or unreadable, the file is not
            JSON, it is not a HAR document (no ``log.entries`` list), the
            capture has no (replayable) entries, or a cap argument is out
            of range.
    """
    if not 1 <= max_entries <= MAX_ENTRIES_LIMIT:
        raise AnalysisError(f"max_entries must be between 1 and {MAX_ENTRIES_LIMIT}")
    if not 1 <= max_body_bytes <= MAX_BODY_BYTES_LIMIT:
        raise AnalysisError(f"max_body_bytes must be between 1 and {MAX_BODY_BYTES_LIMIT}")

    raw, document = _read_har(har_path)
    log = document.get("log")
    if not isinstance(log, dict):
        raise AnalysisError('not a HAR document: no "log" object')
    raw_entries = log.get("entries")
    if not isinstance(raw_entries, list):
        raise AnalysisError('not a HAR document: "log.entries" is not a list')
    if not raw_entries:
        raise AnalysisError("HAR has no entries; nothing to replay")

    har_entry_count = len(raw_entries)
    walked = raw_entries[:max_entries]
    entries_truncated = har_entry_count > max_entries
    counters: dict[str, int] = {}
    kept: list[FixtureEntry] = []
    for index, entry in enumerate(walked):
        request = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(request, dict) or not _as_str(request.get("url")):
            counters["malformed"] = counters.get("malformed", 0) + 1
            continue
        kept.append(_norm_entry(index, entry, max_body_bytes, counters))
    if not kept:
        raise AnalysisError("no replayable entries in HAR: every walked entry lacks a request URL")

    kept.sort(key=lambda item: (item.started, item.index))

    hosts: set[str] = set()
    method_counts: dict[str, int] = {}
    status_classes: dict[str, int] = {}
    total_body_bytes = 0
    endpoints: dict[tuple[str, str, str], dict[str, int]] = {}
    distinct_endpoints: set[tuple[str, str, str]] = set()
    endpoints_truncated = False
    for item in kept:
        hosts.add(item.host)
        method_counts[item.method] = method_counts.get(item.method, 0) + 1
        status_class = _status_class(item.status)
        status_classes[status_class] = status_classes.get(status_class, 0) + 1
        total_body_bytes += item.body.size
        key = (item.method, item.host, _path_template(item.path))
        distinct_endpoints.add(key)
        if key in endpoints:
            statuses = endpoints[key]
            statuses[str(item.status)] = statuses.get(str(item.status), 0) + 1
        elif len(endpoints) < MAX_ENDPOINTS:
            endpoints[key] = {str(item.status): 1}
        else:
            endpoints_truncated = True

    endpoint_records = tuple(
        EndpointRecord(
            method=method,
            host=host_key,
            path_template=template,
            count=sum(statuses.values()),
            statuses=dict(sorted(statuses.items())),
        )
        for (method, host_key, template), statuses in sorted(endpoints.items())
    )

    host_count = len(hosts)
    unique_hosts = tuple(sorted(hosts)[:MAX_HOSTS])
    hosts_truncated = host_count > len(unique_hosts)

    warnings: list[str] = []
    if entries_truncated:
        _warn(warnings, f"entries truncated to {len(walked)} of {har_entry_count}")
    if counters.get("malformed"):
        _warn(warnings, f"skipped {counters['malformed']} entries with no request URL")
    if counters.get("query"):
        _warn(warnings, f"query pairs capped at {MAX_QUERY_PAIRS} on {counters['query']} entries")
    if counters.get("query_fields"):
        _warn(
            warnings,
            f"query names/values cut at {MAX_QUERY_FIELD_CHARS} chars"
            f" on {counters['query_fields']} entries",
        )
    if counters.get("header_count"):
        _warn(
            warnings,
            f"request headers capped at {MAX_HEADER_COUNT} on {counters['header_count']} entries",
        )
    if counters.get("header_values"):
        _warn(
            warnings,
            f"header names/values cut at {MAX_HEADER_VALUE_CHARS} chars"
            f" on {counters['header_values']} entries",
        )
    if counters.get("fields_cut"):
        _warn(
            warnings,
            f"oversized scalar fields (started/method/scheme/host/path/statusText)"
            f" cut on {counters['fields_cut']} entries",
        )
    if counters.get("preview_omitted"):
        _warn(
            warnings,
            f"body preview omitted on {counters['preview_omitted']} entries"
            f" larger than max_body_bytes={max_body_bytes}",
        )
    if counters.get("undecodable"):
        _warn(
            warnings,
            f"response body base64 undecodable on {counters['undecodable']} entries",
        )
    if endpoints_truncated:
        _warn(
            warnings,
            f"endpoint manifest capped at {MAX_ENDPOINTS}"
            f" of {len(distinct_endpoints)} distinct endpoints",
        )
    if hosts_truncated:
        _warn(warnings, f"unique host list capped at {MAX_HOSTS} of {host_count} hosts")

    truncated = (
        entries_truncated
        or endpoints_truncated
        or hosts_truncated
        or bool(counters)
    )
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method=EVIDENCE_METHOD,
        confidence=Confidence.MEDIUM,
        detail=(
            "derived data: normalisation choices (upper-cased methods, {n}/{hex} path"
            " templates, capped header values, size+sha256+preview-only bodies) documented"
        ),
        extra={
            "entries": len(kept),
            "endpoints": len(distinct_endpoints),
            "caps": {
                "max_entries": max_entries,
                "max_body_bytes": max_body_bytes,
                "query_pairs": MAX_QUERY_PAIRS,
                "headers": MAX_HEADER_COUNT,
                "header_value_chars": MAX_HEADER_VALUE_CHARS,
                "endpoints": MAX_ENDPOINTS,
                "preview_bytes": PREVIEW_BYTES,
            },
        },
    )
    return ReplayFixtureReport(
        har_path=str(har_path),
        har_sha256=hashlib.sha256(raw).hexdigest(),
        entries=tuple(kept),
        endpoints=endpoint_records,
        endpoint_count=len(distinct_endpoints),
        total_entries=len(kept),
        har_entry_count=har_entry_count,
        unique_hosts=unique_hosts,
        host_count=host_count,
        total_body_bytes=total_body_bytes,
        method_counts=dict(sorted(method_counts.items())),
        status_classes=dict(sorted(status_classes.items())),
        truncated=truncated,
        warnings=tuple(warnings),
        evidence=evidence,
    )

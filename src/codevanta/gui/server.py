"""Loopback-only HTTP dashboard in front of the CODEVANTA analysis engines.

This module is the server half of the local GUI: :func:`create_server` returns a
:class:`~http.server.ThreadingHTTPServer` bound to a loopback address, and
:func:`serve` runs it until ``Ctrl+C``. Every route is ``GET``, returns
``application/json`` (except ``/``, which returns the dashboard page) and is a
thin adapter over an existing analysis entry point -- no analysis is
reimplemented here:

* ``/`` -- :func:`codevanta.gui.layout.render_dashboard_html`
* ``/api/health`` -- static status payload
* ``/api/info`` -- :func:`codevanta.core.report.build_report`
* ``/api/functions`` -- :func:`codevanta.core.functions.discover_functions`
* ``/api/strings`` -- :class:`codevanta.core.strings.StringExtractor`
* ``/api/xrefs`` -- :func:`codevanta.analysis.xrefs.find_xrefs`
* ``/api/cfg`` -- :func:`codevanta.analysis.cfg.build_cfg` and
  :func:`codevanta.analysis.cfg.build_recursive_cfg`
* ``/api/struct`` -- :func:`codevanta.analysis.type_recovery.suggest_struct`
* ``/api/callgraph`` -- :func:`codevanta.analysis.callgraph.build_call_graph`
* ``/api/diff`` -- :func:`codevanta.analysis.binary_diff.diff_binaries`
* ``/api/decompile`` -- :func:`codevanta.analysis.decompilers.decompile_function`
* ``/api/emulate`` -- :func:`codevanta.analysis.emulate.emulate_function`
* ``/api/symbolic`` -- :func:`codevanta.analysis.symbolic.explore_paths`
* ``/api/session_save`` -- :meth:`codevanta.storage.session.SessionStore.save`
* ``/api/session_list`` -- :meth:`codevanta.storage.session.SessionStore.list`
* ``/bridges`` -- :func:`codevanta.analysis.bridge.bridges_report`
* ``/unknowns`` -- :func:`codevanta.core.unknowns.records_from_payload` over a
  ledger JSON file named by ``?ledger=``
* ``/obligations`` -- :func:`codevanta.core.obligations.list_obligations` over a
  ledger JSON file named by ``?ledger=`` (a typed "not available" payload when
  the module is not part of this build)
* ``/compare`` -- :func:`codevanta.analysis.compare.compare_inventories`,
  :func:`~codevanta.analysis.compare.compare_strings` or
  :func:`~codevanta.analysis.compare.compare_bundles`, selected by ``?what=``
* ``/nav`` -- the :class:`codevanta.analysis.nav.NavStore` read APIs
  (bookmarks, comments, cursor) for one session of one database
* ``/metadata`` -- :func:`codevanta.analysis.binmeta.inspect_metadata`

Contract:

* **Loopback only.** :func:`create_server` refuses any host that is not
  ``localhost``, ``::1`` or inside ``127.0.0.0/8`` with a :class:`ValueError`,
  so the tool can never be exposed on a LAN interface by accident.
* **Bounds are the analysis bounds.** Every numeric query parameter is checked
  against the ceiling of the engine that consumes it (string, xref, call-graph,
  struct and disassembly limits), so a request cannot ask for more work than the
  engines already allow.
* **Read-only analysis.** Bytes are parsed, never executed and never written.
  The dashboard never mutates the analysed file. The one thing a request may
  write is a *session* record -- the optional ``/api/session_save`` route
  appends one row to the session database (see :data:`SESSION_DB_ENV`) and
  touches nothing else; every other route only reads.
* **Origin checked.** Every request must carry a ``Host`` header naming the
  dashboard itself -- ``127.0.0.1``, ``localhost`` or ``[::1]``, with either the
  bound port or no port at all -- otherwise it is answered with ``421`` before
  any route runs, so a DNS-rebinding page cannot drive the API or read local
  binaries. Every response, including error responses, also carries
  ``X-Frame-Options: DENY``, ``X-Content-Type-Options: nosniff`` and a
  restrictive ``Content-Security-Policy``.
* **Bounded responses.** Each payload is capped at :data:`MAX_RESPONSE_BYTES`.
  Top-level lists are halved first, then oversized strings and lists nested
  deeper are replaced with ``"<cut: N chars>"``-style placeholders, and a payload
  that still does not fit is replaced by a minimal ``response too large``
  document. The emitted body therefore never exceeds the cap, whatever the shape
  of the payload, and a truncated payload is flagged with
  ``"response_truncated": true``.

Status codes: ``400`` with ``{"error": ...}`` for bad input, a missing file or a
rejected analysis request, ``404`` for an unknown route, ``405`` for a non-``GET``
method, ``421`` with ``{"error": ...}`` for a foreign ``Host`` header and ``500``
with ``{"error": ...}`` for an unexpected failure.
"""

from __future__ import annotations

import json
import math
import os
import socket
import sys
import webbrowser
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from codevanta.analysis.binary_diff import (
    DEFAULT_SEMANTIC_THRESHOLD,
    MAX_SEMANTIC_THRESHOLD,
    MIN_SEMANTIC_THRESHOLD,
    diff_binaries,
)
from codevanta.analysis.binmeta import inspect_metadata
from codevanta.analysis.bridge import bridges_report
from codevanta.analysis.callgraph import (
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_FUNCTIONS,
    MAX_LIMIT,
    build_call_graph,
)
from codevanta.analysis.cfg import build_cfg, build_recursive_cfg
from codevanta.analysis.compare import (
    COMPARE_WHATS,
    MAX_COMPARE_FUNCTIONS,
    MAX_COMPARE_STRINGS,
    compare_bundles,
    compare_inventories,
    compare_strings,
    load_document,
    load_report_payload,
)
from codevanta.analysis.compare import (
    DEFAULT_MAX_FUNCTIONS as DEFAULT_COMPARE_FUNCTIONS,
)
from codevanta.analysis.compare import (
    DEFAULT_MAX_STRINGS as DEFAULT_COMPARE_STRINGS,
)
from codevanta.analysis.decompile import (
    DEFAULT_MAX_BLOCKS as DEFAULT_DECOMPILE_MAX_BLOCKS,
)
from codevanta.analysis.decompile import (
    DEFAULT_MAX_INSTRUCTIONS as DEFAULT_DECOMPILE_MAX_INSTRUCTIONS,
)
from codevanta.analysis.decompile import MAX_MAX_BLOCKS as MAX_DECOMPILE_MAX_BLOCKS
from codevanta.analysis.decompile import (
    MAX_MAX_INSTRUCTIONS as MAX_DECOMPILE_MAX_INSTRUCTIONS,
)
from codevanta.analysis.decompilers import BackendResult, supported_backends
from codevanta.analysis.decompilers import (
    decompile_function as decompile_with_backend,
)
from codevanta.analysis.emulate import (
    DEFAULT_MAX_INSTRUCTIONS as DEFAULT_EMULATE_MAX_INSTRUCTIONS,
)
from codevanta.analysis.emulate import (
    EMULATOR_AVAILABLE,
    emulate_function,
    emulator_status,
)
from codevanta.analysis.emulate import (
    MAX_MAX_INSTRUCTIONS as MAX_EMULATE_MAX_INSTRUCTIONS,
)
from codevanta.analysis.nav import NavStore
from codevanta.analysis.symbolic import (
    DEFAULT_MAX_PATHS as DEFAULT_SYMBOLIC_MAX_PATHS,
)
from codevanta.analysis.symbolic import (
    DEFAULT_MAX_STEPS as DEFAULT_SYMBOLIC_MAX_STEPS,
)
from codevanta.analysis.symbolic import (
    MAX_MAX_PATHS as MAX_SYMBOLIC_MAX_PATHS,
)
from codevanta.analysis.symbolic import (
    MAX_MAX_STEPS as MAX_SYMBOLIC_MAX_STEPS,
)
from codevanta.analysis.symbolic import (
    explore_paths,
)
from codevanta.analysis.type_recovery import (
    DEFAULT_MAX_FIELDS,
    MAX_MAX_FIELDS,
    MIN_MAX_FIELDS,
    suggest_struct,
)
from codevanta.analysis.xrefs import DEFAULT_MAX_BYTES, find_xrefs
from codevanta.core.functions import discover_functions
from codevanta.core.loader import BinaryInfo, BinaryLoader, BinaryLoadError
from codevanta.core.report import (
    DEFAULT_XREF_LIMIT,
    MAX_DISASSEMBLY_COUNT,
    MAX_STRING_LIMIT,
    MAX_XREF_LIMIT,
    AnalysisError,
    build_report,
)
from codevanta.core.strings import StringExtractor
from codevanta.core.unknowns import MAX_UNKNOWN_RECORDS, records_from_payload

# ``/obligations`` is implemented against the ledger module that lands with the
# phase-9 merge; on branches that predate it the import fails and the route
# answers the typed "not available" payload instead of crashing at import time.
try:
    from codevanta.core import obligations as _obligations_module
except ImportError:  # pragma: no cover - absent before the phase-9 merge
    _obligations_module = None  # type: ignore[assignment]

from codevanta.storage.session import DEFAULT_LIMIT as DEFAULT_SESSION_LIMIT
from codevanta.storage.session import MAX_LIMIT as MAX_SESSION_LIMIT
from codevanta.storage.session import MAX_NOTE_LENGTH as MAX_SESSION_NOTE_LENGTH
from codevanta.storage.session import SessionError, SessionRecord, SessionStore

from .layout import render_dashboard_html

__all__ = [
    "DEFAULT_SESSION_DB",
    "MAX_RESPONSE_BYTES",
    "ROUTES",
    "SECURITY_HEADERS",
    "SESSION_DB_ENV",
    "VERSION",
    "create_handler",
    "create_server",
    "is_allowed_host",
    "normalize_host",
    "serve",
    "session_db_path",
]

#: Version reported by ``/api/health`` when the package metadata is unavailable.
_VERSION_FALLBACK = "0.1.0"

#: Default cap on a rendered JSON response (the analysis limits keep payloads
#: far below it; the cap only guards against pathological input).
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

#: Defaults for the routes whose engine default is tuned for a full report.
DEFAULT_INFO_FUNCTIONS = 50
DEFAULT_FUNCTIONS_LIMIT = 200
DEFAULT_STRINGS_LIMIT = 200
DEFAULT_MIN_STRING_LENGTH = 4
DEFAULT_CFG_INSTRUCTIONS = 2_000
DEFAULT_CFG_BLOCKS = 500

#: Default ``/unknowns`` ``limit``: the engine's own record ceiling, so the
#: route never asks the parser for a window it would refuse anyway.
DEFAULT_UNKNOWN_LIMIT = MAX_UNKNOWN_RECORDS

#: Ceiling of the ``/obligations`` listing. Mirrors the ledger engine's own
#: record bound and stays a literal here, so the route keeps its response bound
#: even on a build where :mod:`codevanta.core.obligations` is absent.
MAX_OBLIGATION_RECORDS = 256

#: Read budget for one ledger JSON file served by ``/unknowns`` or
#: ``/obligations``: a request cannot stream an unbounded file through the
#: parser (the same discipline the response cap applies on the way out).
MAX_LEDGER_BYTES = 4 * 1024 * 1024

#: Backend ``/api/decompile`` uses when the query parameter is absent.
DEFAULT_DECOMPILE_BACKEND = "auto"

#: Backends ``/api/decompile`` accepts: ``auto`` plus every registered provider.
DECOMPILE_BACKENDS: frozenset[str] = frozenset(
    {DEFAULT_DECOMPILE_BACKEND, *supported_backends()}
)

#: Prefix of the block-coverage line the native renderer writes in its header.
_HEADER_BLOCKS_PREFIX = " * blocks: "

#: Environment variable that overrides the session database location. It is the
#: same variable the CLI and the MCP tools read, so a dashboard, a ``codevanta
#: session list`` shell and an agent all share one database.
SESSION_DB_ENV = "CODEVANTA_DB"

#: Session database used when :data:`SESSION_DB_ENV` is unset.
DEFAULT_SESSION_DB = Path.home() / ".codevanta" / "sessions.db"

#: Minimum ``/api/session_list`` limit: ``SessionStore.list`` rejects ``<= 0``.
MIN_SESSION_LIMIT = 1

#: Content types used by the two response kinds.
_JSON_CONTENT_TYPE = "application/json; charset=utf-8"
_HTML_CONTENT_TYPE = "text/html; charset=utf-8"

#: Headers attached to every response, whatever the route or the status code.
#:
#: ``X-Frame-Options`` blocks framing the dashboard from another page,
#: ``X-Content-Type-Options`` stops content sniffing and the policy allows exactly
#: what the page needs -- its own inline script and style, XHR to the same origin
#: -- and nothing else (no images, fonts, frames or remote origins).
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    (
        "Content-Security-Policy",
        "default-src 'none'; script-src 'unsafe-inline'; "
        "style-src 'unsafe-inline'; connect-src 'self'",
    ),
)

#: Host header names the dashboard answers to; the port, when present, must also
#: match the port the server is listening on.
_ALLOWED_HOST_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})

#: Longest string kept inside a payload that has to be cut down to the cap.
_MAX_KEPT_STRING = 256

#: Longest list kept inside a payload that has to be cut down to the cap.
_MAX_KEPT_ITEMS = 32


def _package_version() -> str:
    """Return the installed ``codevanta`` version, or the fallback constant."""
    try:
        from importlib.metadata import version

        return version("codevanta")
    except Exception:  # pragma: no cover - metadata is present once installed
        return _VERSION_FALLBACK


#: Version string exposed by ``/api/health``.
VERSION = _package_version()


def session_db_path() -> Path:
    """Return the session database the two session routes read and write.

    Resolution matches the CLI (``codevanta session ...``) and the MCP tools:
    ``$CODEVANTA_DB`` when it is set to a non-blank value, otherwise
    :data:`DEFAULT_SESSION_DB`. A blank variable counts as unset, so exporting
    ``CODEVANTA_DB=`` never resolves to the current directory.

    There is deliberately **no** ``db`` query parameter: the route table takes
    the location from the server's own environment, so a request can never
    point the dashboard at an arbitrary file to create or overwrite.

    Returns:
        The database path (it need not exist yet; the store creates it).
    """
    configured = os.environ.get(SESSION_DB_ENV)
    if configured and configured.strip():
        return Path(configured.strip()).expanduser()
    return DEFAULT_SESSION_DB


class _RouteError(ValueError):
    """Bad request input; reported as HTTP 400 with the message as ``error``."""


def normalize_host(host: str) -> str:
    """Validate ``host`` as a loopback address and return the bind host.

    Accepted inputs are ``127.0.0.1``, ``localhost``, ``::1`` and any address in
    ``127.0.0.0/8``; ``localhost`` normalizes to ``127.0.0.1``.

    Args:
        host: Requested bind host.

    Returns:
        The address to bind.

    Raises:
        ValueError: If ``host`` is not a string or not a loopback address.
    """
    if not isinstance(host, str):
        raise ValueError(f"host must be a string, got {type(host).__name__}")
    candidate = host.strip().lower()
    if not candidate:
        raise ValueError(
            "host must be a loopback address (127.0.0.1, localhost or ::1); "
            "an empty host would listen on every interface"
        )
    if candidate == "localhost":
        return "127.0.0.1"
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if candidate == "::1":
        return "::1"
    octets = candidate.split(".")
    if len(octets) == 4 and all(octet.isdigit() for octet in octets):
        values = [int(octet) for octet in octets]
        if all(0 <= value <= 255 for value in values) and values[0] == 127:
            return candidate
    raise ValueError(
        f"refusing to bind {host!r}: the dashboard is loopback-only "
        "(127.0.0.1, localhost, ::1 or 127.x.y.z)"
    )


def _split_host_header(value: str) -> tuple[str, str | None] | None:
    """Split a ``Host`` header into ``(name, port-or-None)``, or ``None``.

    Both the bracketed IPv6 form (``[::1]``, ``[::1]:8765``) and the plain
    ``name:port`` form are understood; anything structurally ambiguous (an
    unterminated bracket, a trailing colon-suffix, an unbracketed IPv6 literal
    other than a bare loopback) is reported as malformed.
    """
    text = value.strip().lower()
    if not text:
        return None
    if text.startswith("["):
        closing = text.find("]")
        if closing < 0:
            return None
        rest = text[closing + 1:]
        if rest and not rest.startswith(":"):
            return None
        return text[1:closing], (rest[1:] or None)
    if text.count(":") > 1:
        # An unbracketed IPv6 literal cannot carry a port; only the bare
        # loopback address is meaningful here.
        return (text, None) if text in _ALLOWED_HOST_NAMES else None
    if ":" in text:
        name, _, raw_port = text.partition(":")
        return name, (raw_port or None)
    return text, None


def is_allowed_host(value: str | None, port: int) -> bool:
    """Return whether ``value`` is an acceptable ``Host`` header for ``port``.

    The dashboard is only ever reached through its own loopback URL, so the rule
    is deliberately narrow: the name must be ``127.0.0.1``, ``localhost`` or
    ``[::1]`` and, when the header carries a port, that port must be the port this
    server is listening on. A missing header, a foreign name (the DNS-rebinding
    case) or a mismatched port is rejected.

    Args:
        value: The raw ``Host`` header, or ``None`` when it was not sent.
        port: The TCP port the server accepted the request on.

    Returns:
        ``True`` when the request may be served, ``False`` when it must get a
        ``421`` instead.
    """
    if not isinstance(value, str):
        return False
    split = _split_host_header(value)
    if split is None:
        return False
    name, raw_port = split
    if name not in _ALLOWED_HOST_NAMES:
        return False
    if raw_port is None:
        return True
    if not raw_port.isdigit():
        return False
    return int(raw_port) == port


def _first(params: dict[str, str], name: str) -> str | None:
    """Return the stripped first value of ``name``, or ``None`` when absent."""
    value = params.get(name)
    if value is None:
        return None
    text = value.strip()
    return text or None


def _query_int(
    params: dict[str, str],
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    """Parse an integer query parameter and enforce ``minimum..maximum``."""
    raw = _first(params, name)
    if raw is None:
        return default
    try:
        value = int(raw, 10)
    except ValueError:
        raise _RouteError(f"{name} must be an integer, got {raw!r}") from None
    if value < minimum or value > maximum:
        raise _RouteError(f"{name} must be within {minimum}..{maximum}, got {value}")
    return value


def _reject_unknown(params: dict[str, str], allowed: frozenset[str]) -> None:
    """Reject every query parameter outside ``allowed``.

    The analysis routes tolerate extra parameters (each one reads only the names
    it understands, so an older page keeps working against a newer server). The
    session routes are different: they *write*, so a typo such as ``notse=`` must
    be reported instead of silently saving a session with no note. Unknown names
    are listed in the error, because the caller needs to see which one was wrong.
    """
    unknown = sorted(set(params) - allowed)
    if unknown:
        shown = ", ".join(repr(name) for name in unknown)
        raise _RouteError(
            f"unknown query parameter(s) {shown}; this route accepts "
            f"{', '.join(sorted(allowed)) or 'no parameters'}"
        )


def _query_notes(params: dict[str, str], name: str) -> str | None:
    """Parse the optional free-text ``notes`` parameter.

    Notes are stored verbatim (newlines and non-ASCII characters included) but
    are bounded: the store itself only checks the type, so the route reuses the
    per-note ceiling the storage layer already declares, keeping one request
    from parking an unbounded blob in the database. A blank value means "no
    note" rather than an empty one, so the listing does not have to tell the two
    spellings apart.
    """
    raw = _first(params, name)
    if raw is None:
        return None
    if len(raw) > MAX_SESSION_NOTE_LENGTH:
        raise _RouteError(
            f"{name} must be at most {MAX_SESSION_NOTE_LENGTH} characters, "
            f"got {len(raw)}"
        )
    return raw


def _query_float(
    params: dict[str, str],
    name: str,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    """Parse a finite float query parameter and enforce ``minimum..maximum``."""
    raw = _first(params, name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise _RouteError(f"{name} must be a number, got {raw!r}") from None
    if not math.isfinite(value):
        raise _RouteError(f"{name} must be a finite number, got {raw!r}")
    if value < minimum or value > maximum:
        raise _RouteError(f"{name} must be within {minimum}..{maximum}, got {value}")
    return value


def _query_flag(params: dict[str, str], name: str, default: bool) -> bool:
    """Parse a ``0|1`` (or ``false|true``) query parameter as a boolean."""
    raw = _first(params, name)
    if raw is None:
        return default
    lowered = raw.lower()
    if lowered in {"0", "false", "no", "off"}:
        return False
    if lowered in {"1", "true", "yes", "on"}:
        return True
    raise _RouteError(f"{name} must be 0 or 1, got {raw!r}")


def _query_address(params: dict[str, str], name: str) -> int | None:
    """Parse a hex (``0x...``) or decimal address query parameter."""
    raw = _first(params, name)
    if raw is None:
        return None
    try:
        value = int(raw, 16) if raw.lower().startswith("0x") else int(raw, 10)
    except ValueError:
        raise _RouteError(
            f"{name} must be a hexadecimal (0x...) or decimal address, got {raw!r}"
        ) from None
    if value < 0:
        raise _RouteError(f"{name} must be a non-negative address, got {raw}")
    return value


def _query_path(params: dict[str, str], name: str, allow_paths: bool) -> Path:
    """Return the file path named by ``name`` as a :class:`~pathlib.Path`."""
    raw = _first(params, name)
    if raw is None:
        raise _RouteError(f"{name} is required")
    if not allow_paths:
        raise _RouteError(
            f"{name} is not accepted by this server (path parameters are disabled)"
        )
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        # Pasted paths regularly arrive with the shell or Explorer quotes attached.
        raw = raw[1:-1].strip()
        if not raw:
            raise _RouteError(f"{name} is required")
    try:
        return Path(raw)
    except (ValueError, OSError) as exc:
        raise _RouteError(f"{name} is not a usable path: {exc}") from None


def _load(path: Path) -> BinaryInfo:
    """Load ``path`` through the production loader (failures become HTTP 400)."""
    return BinaryLoader().load(path)


def _require_file(path: Path, name: str) -> None:
    """Reject a ``400`` unless ``path`` names an existing regular file.

    The engine loaders have their own error mapping, but the routes that take
    several path parameters (``/compare``, ``/nav``) validate every one of them
    up front so the error always names the parameter that was wrong.
    """
    if not path.is_file():
        raise _RouteError(f"{name} does not exist or is not a file: {path}")


def _read_json_document(path: Path, *, limit_bytes: int) -> dict[str, Any]:
    """Read one bounded JSON object document from ``path``.

    Read failures, invalid JSON and non-object documents become the typed
    ``AnalysisError`` the engines already raise, so ``_dispatch`` maps them onto
    HTTP ``400`` without any route-specific handling. The ``limit_bytes`` budget
    is checked before the file is opened: a huge ledger is refused, not parsed.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:  # pragma: no cover - _require_file just checked it
        raise AnalysisError(f"cannot read {path}: {exc}") from None
    if size > limit_bytes:
        raise _RouteError(f"{path} exceeds the {limit_bytes} byte read budget ({size})")
    try:
        with path.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except UnicodeDecodeError as exc:
        raise AnalysisError(f"{path} is not UTF-8 text: {exc}") from None
    except OSError as exc:  # pragma: no cover - _require_file just checked it
        raise AnalysisError(f"cannot read {path}: {exc}") from None
    except json.JSONDecodeError as exc:
        raise AnalysisError(f"{path} is not valid JSON: {exc}") from None
    if not isinstance(document, dict):
        raise AnalysisError(f"{path} is not a JSON object")
    return document


def _api_health(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return a static liveness payload."""
    return {
        "status": "ok",
        "version": VERSION,
        "routes": sorted(ROUTES),
        "paths_allowed": allow_paths,
    }


def _api_info(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Report binary metadata, provenance and the bounded function list."""
    path = _query_path(params, "path", allow_paths)
    max_functions = _query_int(params, "max_functions", DEFAULT_INFO_FUNCTIONS, 0, MAX_LIMIT)
    report = build_report(path, string_limit=0, xref_limit=0)
    functions = report["functions"]
    kept = functions[:max_functions]
    return {
        "binary": report["binary"],
        "provenance": report["provenance"],
        "function_count": len(functions),
        "functions_returned": len(kept),
        "functions_truncated": len(kept) < len(functions),
        "functions": kept,
        "string_count": report["strings"]["count"],
    }


def _api_functions(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return the function candidates reported by structural discovery."""
    path = _query_path(params, "path", allow_paths)
    limit = _query_int(params, "limit", DEFAULT_FUNCTIONS_LIMIT, 0, MAX_LIMIT)
    info = _load(path)
    candidates = discover_functions(info)
    kept = candidates[:limit]
    return {
        "path": str(info.path),
        "format": info.format,
        "count": len(candidates),
        "returned": len(kept),
        "truncated": len(kept) < len(candidates),
        "functions": [candidate.to_dict() for candidate in kept],
    }


def _api_strings(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return ASCII/UTF-16 strings found by the production string scanner."""
    path = _query_path(params, "path", allow_paths)
    min_length = _query_int(
        params, "min_length", DEFAULT_MIN_STRING_LENGTH, 1, MAX_STRING_LIMIT
    )
    limit = _query_int(params, "limit", DEFAULT_STRINGS_LIMIT, 0, MAX_STRING_LIMIT)
    info = _load(path)
    extractor = StringExtractor(min_length=min_length)
    # ``limit=0`` means "none"; a limit of N is probed with N+1 so truncation is
    # known without scanning the file twice.
    found = extractor.extract(path, info=info, limit=limit + 1) if limit else []
    kept = found[:limit]
    return {
        "path": str(info.path),
        "format": info.format,
        "min_length": min_length,
        "limit": limit,
        "returned": len(kept),
        "truncated": len(found) > limit,
        "strings": [item.to_dict() for item in kept],
    }


def _api_xrefs(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return cross references from the bounded executable-byte scan."""
    path = _query_path(params, "path", allow_paths)
    limit = _query_int(params, "limit", DEFAULT_XREF_LIMIT, 0, MAX_XREF_LIMIT)
    info = _load(path)
    scan = find_xrefs(path, info, max_bytes=DEFAULT_MAX_BYTES)
    kept = scan.xrefs[:limit]
    payload = scan.to_dict()
    payload["path"] = str(info.path)
    payload["format"] = info.format
    payload["limit"] = limit
    payload["returned"] = len(kept)
    payload["scan_truncated"] = scan.truncated
    payload["truncated"] = len(kept) < len(scan.xrefs)
    payload["xrefs"] = [xref.to_dict() for xref in kept]
    return payload


def _api_cfg(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return a control-flow graph, linear or recursively traversed."""
    path = _query_path(params, "path", allow_paths)
    address = _query_address(params, "address")
    traversal = (_first(params, "traversal") or "linear").lower()
    if traversal not in {"linear", "recursive"}:
        raise _RouteError(f"traversal must be 'linear' or 'recursive', got {traversal!r}")
    max_instructions = _query_int(
        params, "max_instructions", DEFAULT_CFG_INSTRUCTIONS, 1, MAX_DISASSEMBLY_COUNT
    )
    max_blocks = _query_int(params, "max_blocks", DEFAULT_CFG_BLOCKS, 1, MAX_DISASSEMBLY_COUNT)
    info = _load(path)
    start = address if address is not None else info.entry_point
    if start is None:
        raise _RouteError("address is required: the binary has no entry point")
    builder = build_recursive_cfg if traversal == "recursive" else build_cfg
    graph = builder(
        path,
        info,
        start,
        max_instructions=max_instructions,
        max_blocks=max_blocks,
    )
    payload = graph.to_dict()
    payload["traversal"] = traversal
    payload["path"] = str(info.path)
    return payload


def _api_struct(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return the struct-layout suggestion for one code window."""
    path = _query_path(params, "path", allow_paths)
    address = _query_address(params, "address")
    include_stack = _query_flag(params, "include_stack", False)
    max_fields = _query_int(
        params, "max_fields", DEFAULT_MAX_FIELDS, MIN_MAX_FIELDS, MAX_MAX_FIELDS
    )
    info = _load(path)
    start = address if address is not None else info.entry_point
    if start is None:
        raise _RouteError("address is required: the binary has no entry point")
    suggestion = suggest_struct(
        path,
        info,
        start,
        max_fields=max_fields,
        include_stack=include_stack,
    )
    payload = suggestion.to_dict()
    payload["path"] = str(info.path)
    payload["include_stack"] = include_stack
    return payload


def _api_callgraph(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return the direct-call graph with both engine limits honoured."""
    path = _query_path(params, "path", allow_paths)
    max_functions = _query_int(
        params, "limit_functions", DEFAULT_MAX_FUNCTIONS, 1, MAX_LIMIT
    )
    max_edges = _query_int(params, "limit_edges", DEFAULT_MAX_EDGES, 1, MAX_LIMIT)
    info = _load(path)
    graph = build_call_graph(
        path,
        info,
        max_functions=max_functions,
        max_edges=max_edges,
    )
    payload = graph.to_dict()
    payload["path"] = str(info.path)
    payload["limit_functions"] = max_functions
    payload["limit_edges"] = max_edges
    return payload


def _api_diff(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return the structural (or semantic) difference between two binaries."""
    left = _query_path(params, "left", allow_paths)
    right = _query_path(params, "right", allow_paths)
    semantic = _query_flag(params, "semantic", False)
    threshold = _query_float(
        params,
        "threshold",
        DEFAULT_SEMANTIC_THRESHOLD,
        MIN_SEMANTIC_THRESHOLD,
        MAX_SEMANTIC_THRESHOLD,
    )
    result = diff_binaries(left, right, semantic=semantic, threshold=threshold)
    payload = result.to_dict()
    payload["semantic"] = semantic
    payload["threshold"] = threshold
    return payload


def _decompiled_block_count(result: BackendResult) -> int | None:
    """Return how many basic blocks the rendering covered, when it says so.

    Mirrors :func:`codevanta.mcp_server.tools.decompile`'s helper so the API and
    the MCP tool publish the same JSON: the external backends record their block
    count in ``evidence.extra``, while the native renderer publishes it in the
    pseudo-C header comment (`` * blocks: N  instructions: M``). ``None`` means
    the backend reported no coverage.
    """
    recorded = result.evidence.extra.get("block_count")
    if isinstance(recorded, int) and not isinstance(recorded, bool):
        return recorded
    for line in result.text.splitlines():
        if line == " */":
            break
        if not line.startswith(_HEADER_BLOCKS_PREFIX):
            continue
        field = line[len(_HEADER_BLOCKS_PREFIX) :].split(" ", 1)[0]
        if field.isdigit():
            return int(field)
    return None


def _api_decompile(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return one function rendered as C-like text by the chosen backend.

    ``backend=auto`` (the default) prefers an installed external decompiler and
    falls back to the built-in renderer, listing every skipped backend in
    ``warnings``; ``angr`` and ``ghidra`` are strict and answer ``400`` with a
    message naming the backend when it is unavailable, so a missing optional
    dependency never becomes a ``500`` or an ``ImportError``.
    """
    path = _query_path(params, "path", allow_paths)
    address = _query_address(params, "address")
    backend = (_first(params, "backend") or DEFAULT_DECOMPILE_BACKEND).lower()
    if backend not in DECOMPILE_BACKENDS:
        supported = ", ".join(sorted(DECOMPILE_BACKENDS))
        raise _RouteError(f"backend must be one of {supported}, got {backend!r}")
    max_instructions = _query_int(
        params,
        "max_instructions",
        DEFAULT_DECOMPILE_MAX_INSTRUCTIONS,
        1,
        MAX_DECOMPILE_MAX_INSTRUCTIONS,
    )
    max_blocks = _query_int(
        params,
        "max_blocks",
        DEFAULT_DECOMPILE_MAX_BLOCKS,
        1,
        MAX_DECOMPILE_MAX_BLOCKS,
    )
    info = _load(path)
    start = address if address is not None else info.entry_point
    if start is None:
        raise _RouteError("address is required: the binary has no entry point")
    result = decompile_with_backend(
        path,
        info,
        start,
        backend=backend,
        max_instructions=max_instructions,
        max_blocks=max_blocks,
    )
    payload = result.to_dict()
    payload["path"] = str(info.path)
    payload["address"] = f"0x{start:x}"
    payload["blocks"] = _decompiled_block_count(result)
    return payload


def _query_registers(params: dict[str, str], name: str) -> dict[str, int] | None:
    """Parse repeatable ``set=REG=VAL`` pairs into an initial-register map.

    ``set`` may be repeated (``set=eax=1&set=ebx=2``) -- :func:`_parse_query`
    hands repeated occurrences over joined with a comma -- or carry
    comma-separated pairs in one value. Values are decimal or ``0x``-hex
    integers; register names and widths are validated by the engine itself, so
    an unknown name surfaces as the engine's error, not a parser guess.
    """
    raw = _first(params, name)
    if raw is None:
        return None
    seeds: dict[str, int] = {}
    for pair in raw.split(","):
        text = pair.strip()
        reg, sep, value = text.partition("=")
        reg = reg.strip().lower()
        value = value.strip()
        if not sep or not reg or not value:
            raise _RouteError(
                f"{name} must be REG=VAL pairs (e.g. set=eax=0x2a), got {text!r}"
            )
        try:
            seeds[reg] = int(value, 16) if value.lower().startswith("0x") else int(value, 10)
        except ValueError:
            raise _RouteError(
                f"{name} value must be a hexadecimal (0x...) or decimal integer, "
                f"got {value!r}"
            ) from None
    return seeds


def _api_emulate(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Emulate one function on the sandboxed CPU and return the run trace."""
    if not EMULATOR_AVAILABLE:
        raise _RouteError(emulator_status())
    path = _query_path(params, "path", allow_paths)
    address = _query_address(params, "address")
    max_instructions = _query_int(
        params,
        "max_instructions",
        DEFAULT_EMULATE_MAX_INSTRUCTIONS,
        1,
        MAX_EMULATE_MAX_INSTRUCTIONS,
    )
    seeds = _query_registers(params, "set")
    info = _load(path)
    start = address if address is not None else info.entry_point
    if start is None:
        raise _RouteError("address is required: the binary has no entry point")
    result = emulate_function(
        path,
        info,
        start,
        initial_registers=seeds,
        max_instructions=max_instructions,
    )
    payload = result.to_dict()
    payload["path"] = str(info.path)
    payload["address"] = f"0x{start:x}"
    return payload


def _api_symbolic(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Explore the execution paths through one function, both limits honoured."""
    path = _query_path(params, "path", allow_paths)
    address = _query_address(params, "address")
    max_paths = _query_int(
        params, "max_paths", DEFAULT_SYMBOLIC_MAX_PATHS, 1, MAX_SYMBOLIC_MAX_PATHS
    )
    max_steps = _query_int(
        params, "max_steps", DEFAULT_SYMBOLIC_MAX_STEPS, 1, MAX_SYMBOLIC_MAX_STEPS
    )
    info = _load(path)
    start = address if address is not None else info.entry_point
    if start is None:
        raise _RouteError("address is required: the binary has no entry point")
    exploration = explore_paths(path, info, start, max_paths=max_paths, max_steps=max_steps)
    payload = exploration.to_dict()
    payload["path"] = str(info.path)
    payload["address"] = f"0x{start:x}"
    return payload


def _session_item(record: SessionRecord) -> dict[str, Any]:
    """Project a stored session onto the fields the listing exposes.

    The full record also carries the SHA-256, bitness, entry point and the two
    counts; the dashboard panel shows one row per session and needs the
    path/format/architecture identity plus the note, so only those are returned.
    """
    return {
        "session_id": record.session_id,
        "path": record.binary_path,
        "format": record.format,
        "architecture": record.architecture,
        "created_at": record.created_at,
        "notes": record.notes,
    }


def _api_session_save(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Analyze a binary and persist the run as a session row.

    This is the only route with an effect: it appends one row to the database
    named by :func:`session_db_path` and returns the identifiers of that row so
    the page can show it without a second request. Re-saving the same binary is
    legal and appends another row -- the store keeps an audit trail of repeated
    analyses rather than overwriting.
    """
    _reject_unknown(params, frozenset({"path", "notes"}))
    path = _query_path(params, "path", allow_paths)
    notes = _query_notes(params, "notes")
    info = _load(path)
    # The counts are the two numbers the store persists next to the fingerprint;
    # they are computed by the same engines ``/api/functions`` and ``/api/strings``
    # serve, so the saved row can never disagree with what the page displayed.
    functions_count = len(discover_functions(info))
    strings_count = len(StringExtractor().extract(path, info=info))
    with SessionStore(session_db_path()) as store:
        record = store.save(
            info,
            functions_count,
            strings_count,
            notes=notes,
        )
    return {"session_id": record.session_id, "created_at": record.created_at}


def _api_session_list(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return the stored sessions, newest first, bounded by ``limit``.

    ``limit`` is validated against the storage bounds -- ``1`` up to
    :data:`~codevanta.storage.session.MAX_LIMIT` -- and defaults to the store's
    own :data:`~codevanta.storage.session.DEFAULT_LIMIT`, so the route never
    asks the store for a window it would reject or silently shrink.
    """
    _reject_unknown(params, frozenset({"limit"}))
    limit = _query_int(
        params,
        "limit",
        DEFAULT_SESSION_LIMIT,
        MIN_SESSION_LIMIT,
        MAX_SESSION_LIMIT,
    )
    with SessionStore(session_db_path()) as store:
        records = store.list(limit=limit)
    return {
        "limit": limit,
        "count": len(records),
        "sessions": [_session_item(record) for record in records],
    }


def _api_bridges(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return the bridge capability report for this machine.

    The engine probes every known external tool in ``KNOWN_BRIDGES`` order with
    its own bounded ``--version`` budget; unavailability is a record with
    ``available=False`` and an install hint, never an error, so the route
    always answers ``200`` with the honest list.
    """
    capabilities = bridges_report()
    tools = [capability.to_dict() for capability in capabilities]
    return {
        "count": len(tools),
        "available": sum(1 for tool in tools if tool["available"]),
        "tools": tools,
    }


def _api_unknowns(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return the unknown records of one ledger JSON file, bounded.

    The ledger named by ``?ledger=`` is parsed by the same engine the CLI and
    the MCP tools use (:func:`~codevanta.core.unknowns.records_from_payload`),
    so its validation rules (deterministic ids, known severities and statuses,
    bounded text) apply unchanged and its ``AnalysisError`` becomes HTTP ``400``.
    ``limit`` bounds the returned window the way ``/api/functions`` does; the
    full count and the truncation flag are always reported.
    """
    ledger = _query_path(params, "ledger", allow_paths)
    limit = _query_int(params, "limit", DEFAULT_UNKNOWN_LIMIT, 0, MAX_UNKNOWN_RECORDS)
    _require_file(ledger, "ledger")
    payload = _read_json_document(ledger, limit_bytes=MAX_LEDGER_BYTES)
    records = records_from_payload(payload)
    kept = records[:limit] if limit else ()
    return {
        "path": str(ledger),
        "count": len(records),
        "limit": limit,
        "returned": len(kept),
        "truncated": len(kept) < len(records),
        "items": [record.to_dict() for record in kept],
    }


def _api_obligations(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return the obligation records of one ledger JSON file, bounded.

    Implemented against :mod:`codevanta.core.obligations` when that module is
    part of this build; otherwise the route answers the typed "not available"
    payload (HTTP ``400``, the same convention ``/api/emulate`` uses for a
    missing optional dependency) instead of failing at import time. An optional
    ``status`` filter is validated by the engine itself, so a typo such as
    ``status=opne`` is reported rather than silently read as an empty ledger.
    """
    if _obligations_module is None:
        raise _RouteError(
            "obligations are not available: codevanta.core.obligations "
            "is not part of this build"
        )
    ledger = _query_path(params, "ledger", allow_paths)
    limit = _query_int(params, "limit", MAX_OBLIGATION_RECORDS, 0, MAX_OBLIGATION_RECORDS)
    status = _first(params, "status")
    _require_file(ledger, "ledger")
    payload = _read_json_document(ledger, limit_bytes=MAX_LEDGER_BYTES)
    records = _obligations_module.list_obligations(payload, status=status)
    kept = records[:limit] if limit else ()
    return {
        "path": str(ledger),
        "count": len(records),
        "limit": limit,
        "returned": len(kept),
        "truncated": len(kept) < len(records),
        "items": [record.to_dict() for record in kept],
    }


def _api_compare(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return the comparator result for two JSON artifacts.

    ``what`` selects the engine the CLI already dispatches to: ``functions``
    and ``strings`` compare analyze-report payloads (evidence bundles are
    unwrapped to their report entry), ``bundles`` diffs two evidence-bundle
    documents by record kind and digest membership. Both paths are validated
    to exist before any engine runs, and the bounded ``max_functions`` /
    ``max_strings`` windows keep the comparison as cheap as the CLI's flags.
    """
    left = _query_path(params, "left", allow_paths)
    right = _query_path(params, "right", allow_paths)
    what = (_first(params, "what") or "functions").lower()
    if what not in COMPARE_WHATS:
        raise _RouteError(f"what must be one of {', '.join(COMPARE_WHATS)}, got {what!r}")
    _require_file(left, "left")
    _require_file(right, "right")
    if what == "functions":
        max_functions = _query_int(
            params, "max_functions", DEFAULT_COMPARE_FUNCTIONS, 1, MAX_COMPARE_FUNCTIONS
        )
        result: Any = compare_inventories(
            load_report_payload(left),
            load_report_payload(right),
            max_functions=max_functions,
        )
        payload = result.to_dict()
        payload["max_functions"] = max_functions
    elif what == "strings":
        max_strings = _query_int(
            params, "max_strings", DEFAULT_COMPARE_STRINGS, 1, MAX_COMPARE_STRINGS
        )
        result = compare_strings(
            load_report_payload(left),
            load_report_payload(right),
            max_strings=max_strings,
        )
        payload = result.to_dict()
        payload["max_strings"] = max_strings
    else:
        result = compare_bundles(load_document(left), load_document(right))
        payload = result.to_dict()
    payload["what"] = what
    return payload


def _api_nav(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return bookmarks, comments and the cursor for one session.

    All three read APIs of :class:`~codevanta.analysis.nav.NavStore` are served
    in one request so the navigation panel needs no follow-ups. The database
    named by ``?db=`` must exist already -- a dashboard request can read a
    session database but never create one -- and the engine's own validation
    (usable session id, session row present) applies unchanged, so an unknown
    session is the engine's typed ``AnalysisError`` (HTTP ``400``) including
    its "save a session first" hint.
    """
    db = _query_path(params, "db", allow_paths)
    session_id = _first(params, "session")
    if session_id is None:
        raise _RouteError("session is required")
    _require_file(db, "db")
    with NavStore(db) as store:
        bookmarks = store.bookmarks(session_id)
        comments = store.comments(session_id)
        cursor = store.cursor(session_id)
    return {
        "db": str(db),
        "session_id": session_id,
        "bookmarks": [bookmark.to_dict() for bookmark in bookmarks],
        "comments": [comment.to_dict() for comment in comments],
        "cursor": cursor.to_dict() if cursor is not None else None,
    }


def _api_metadata(params: dict[str, str], allow_paths: bool) -> dict[str, Any]:
    """Return the auto-detected format metadata for one path.

    :func:`~codevanta.analysis.binmeta.inspect_metadata` classifies files
    through every typed detector (pyc, APK signing, Go build info, cargo
    audit, Electron fuses, kernel modules, ELF notes) and directories as
    desktop-app layouts; unknown or malformed inputs are the engine's typed
    ``AnalysisError`` (HTTP ``400``), never a guess.
    """
    target = _query_path(params, "path", allow_paths)
    report = inspect_metadata(target)
    return report.to_dict()


#: Route table: request path -> payload builder. Builders take the query
#: parameters and the handler's ``paths_allowed`` flag.
ROUTES: dict[str, Callable[[dict[str, str], bool], dict[str, Any]]] = {
    "/api/health": _api_health,
    "/api/info": _api_info,
    "/api/functions": _api_functions,
    "/api/strings": _api_strings,
    "/api/xrefs": _api_xrefs,
    "/api/cfg": _api_cfg,
    "/api/struct": _api_struct,
    "/api/callgraph": _api_callgraph,
    "/api/diff": _api_diff,
    "/api/decompile": _api_decompile,
    "/api/emulate": _api_emulate,
    "/api/symbolic": _api_symbolic,
    "/api/session_save": _api_session_save,
    "/api/session_list": _api_session_list,
    "/bridges": _api_bridges,
    "/unknowns": _api_unknowns,
    "/obligations": _api_obligations,
    "/compare": _api_compare,
    "/nav": _api_nav,
    "/metadata": _api_metadata,
}

def _json_default(value: Any) -> Any:
    """Last-resort encoder for values the analysis payloads should not contain."""
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bytes>"
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=str)
    return str(value)


def _dump(payload: Any) -> bytes:
    """Serialize ``payload`` to UTF-8 JSON using the payload encoder rules."""
    return json.dumps(payload, ensure_ascii=False, default=_json_default).encode("utf-8")


def _cut_value(value: Any) -> Any:
    """Replace oversized values with bounded placeholders, recursively.

    Strings longer than :data:`_MAX_KEPT_STRING` become ``"<cut: N chars>"`` and
    lists longer than :data:`_MAX_KEPT_ITEMS` keep their head plus a
    ``"<cut: N items>"`` marker, so a payload whose size comes from one huge
    scalar -- or from one long list nested below the top level -- shrinks to
    something that fits, instead of staying oversized.
    """
    if isinstance(value, str):
        if len(value) > _MAX_KEPT_STRING:
            return f"<cut: {len(value)} chars>"
        return value
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bytes>"
    if isinstance(value, dict):
        return {key: _cut_value(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        return _cut_value(sorted(value, key=str))
    if isinstance(value, (list, tuple)):
        items = [_cut_value(item) for item in value]
        if len(items) > _MAX_KEPT_ITEMS:
            dropped = len(items) - _MAX_KEPT_ITEMS
            items = [*items[:_MAX_KEPT_ITEMS], f"<cut: {dropped} items>"]
        return items
    return value


def _encode_payload(payload: dict[str, Any]) -> bytes:
    """Render ``payload`` as JSON bytes, always within :data:`MAX_RESPONSE_BYTES`.

    The shrink is staged, cheapest loss first: top-level lists are halved, then
    every oversized string and nested list is replaced by a placeholder, and only
    if the payload still does not fit is it replaced by a minimal error document.
    The returned body is therefore never larger than the cap, whatever the shape
    of the payload, and every truncated form is self-describing
    (``"response_truncated": true``).
    """
    body = _dump(payload)
    if len(body) <= MAX_RESPONSE_BYTES:
        return body
    capped = dict(payload)
    capped["response_truncated"] = True
    for _ in range(16):
        body = _dump(capped)
        if len(body) <= MAX_RESPONSE_BYTES:
            return body
        shrunk = False
        for key, value in capped.items():
            if isinstance(value, list) and len(value) > 1:
                capped[key] = value[: max(1, len(value) // 2)]
                shrunk = True
        if not shrunk:
            break
    body = _dump(_cut_value(capped))
    if len(body) <= MAX_RESPONSE_BYTES:
        return body
    return _dump(
        {
            "error": "response too large",
            "response_truncated": True,
            "limit": MAX_RESPONSE_BYTES,
        }
    )



def _parse_query(query: str) -> dict[str, str]:
    """Flatten a query string into ``{name: value}``.

    A repeated parameter (``set=eax=1&set=ebx=2``) arrives as one comma-joined
    value, so the repeatable ``set=REG=VAL`` form of ``/api/emulate`` survives
    the flattening. Routes that accept a parameter only once reject the joined
    value as malformed input instead of silently picking the first occurrence.
    """
    parsed = parse_qs(query, keep_blank_values=True)
    return {key: ",".join(values) if values else "" for key, values in parsed.items()}


class _GuiRequestHandler(BaseHTTPRequestHandler):
    """Request handler implementing the dashboard route table.

    :func:`create_handler` subclasses this to bind the ``paths_allowed`` policy;
    the class itself defaults to accepting path parameters.
    """

    server_version = f"CODEVANTA-gui/{VERSION}"
    protocol_version = "HTTP/1.1"
    allow_paths = True

    def log_message(self, format: str, *args: Any) -> None:
        """Silence per-request logging; the CLI prints the URL only."""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming
        self._method_not_allowed()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming
        self._method_not_allowed()

    def _method_not_allowed(self) -> None:
        if not self._accepts_request_host():
            return
        self._send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "only GET is supported"})

    def end_headers(self) -> None:
        """Close the header block, adding the headers every reply must carry.

        This is the single choke point all responses share -- route bodies,
        ``421``/``404``/``405`` rejections and the errors
        :class:`~http.server.BaseHTTPRequestHandler` raises itself -- so the
        security headers cannot be forgotten on one path.
        """
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        super().end_headers()

    def _bound_port(self) -> int:
        """Return the TCP port the server accepted this request on."""
        # ``self.server`` is typed as a plain ``BaseServer``, which does not
        # declare ``server_address``; every server we build is a ``TCPServer``.
        address = getattr(self.server, "server_address", None)
        if not isinstance(address, tuple) or len(address) < 2:  # pragma: no cover
            return 0
        return int(address[1])

    def _accepts_request_host(self) -> bool:
        """Check the ``Host`` header against the loopback allowlist.

        Returns:
            ``True`` when the request may proceed, ``False`` when a ``421``
            response has already been written.
        """
        host = self.headers.get("Host")
        port = self._bound_port()
        if is_allowed_host(host, port):
            return True
        shown = (host or "").strip() or "<missing>"
        self._send_json(
            HTTPStatus.MISDIRECTED_REQUEST,
            {
                "error": (
                    f"refusing Host {shown!r}: only 127.0.0.1, localhost and [::1] "
                    f"on port {port} may drive the dashboard"
                )
            },
        )
        return False

    def _dispatch(self) -> None:
        """Route one GET request, mapping failures onto the documented codes."""
        if not self._accepts_request_host():
            return
        try:
            split = urlsplit(self.path)
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"malformed URL: {exc}"})
            return
        route = split.path or "/"
        if len(route) > 1:
            route = route.rstrip("/") or "/"
        if route == "/":
            self._send_body(
                HTTPStatus.OK,
                render_dashboard_html().encode("utf-8"),
                _HTML_CONTENT_TYPE,
            )
            return
        builder = ROUTES.get(route)
        if builder is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"unknown route {route!r}"})
            return
        params = _parse_query(split.query)
        try:
            payload = builder(params, self.allow_paths)
        except (ValueError, AnalysisError, BinaryLoadError, SessionError) as exc:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": str(exc) or type(exc).__name__},
            )
            return
        except Exception as exc:  # noqa: BLE001 - last-resort mapping to HTTP 500
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": f"{type(exc).__name__}: {exc}"},
            )
            return
        self._send_json(HTTPStatus.OK, payload)

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        self._send_body(status, _encode_payload(payload), _JSON_CONTENT_TYPE)

    def _send_body(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            # A HEAD response carries no body, so it must not advertise one:
            # a non-zero length would desynchronize a keep-alive connection.
            self.send_header("Content-Length", "0" if self.command == "HEAD" else str(len(body)))
            self.send_header("Cache-Control", "no-store")
            # The security headers are added by ``end_headers`` so that the paths
            # which never reach here (421/404/405 handle it, but also the errors
            # BaseHTTPRequestHandler raises itself) carry them too.
            self.end_headers()
            if self.command != "HEAD" and body:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):  # pragma: no cover - client gone
            self.close_connection = True


def create_handler(paths_allowed: bool = True) -> type[BaseHTTPRequestHandler]:
    """Build the request-handler class for one dashboard server.

    Args:
        paths_allowed: When false, the routes that take a file parameter reject
            it with HTTP 400, so a handler can be created for a context where
            filesystem access must not be reachable at all.

    Returns:
        A :class:`~http.server.BaseHTTPRequestHandler` subclass ready to be
        passed to a server.

    Raises:
        TypeError: If ``paths_allowed`` is not a :class:`bool`.
    """
    if not isinstance(paths_allowed, bool):
        raise TypeError(
            f"paths_allowed must be a bool, got {type(paths_allowed).__name__}"
        )

    class GuiRequestHandler(_GuiRequestHandler):
        """Request handler bound to one ``paths_allowed`` policy."""

    GuiRequestHandler.allow_paths = paths_allowed
    return GuiRequestHandler


class _GuiHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server with daemon threads and a selectable family.

    ``ThreadingHTTPServer`` already sets ``daemon_threads``; it is spelled out
    here together with ``allow_reuse_address`` so a restarted dashboard can
    rebind ``127.0.0.1:8765`` immediately.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        address_family: socket.AddressFamily = socket.AF_INET,
    ) -> None:
        # BaseServer.__init__ creates the listening socket, so the family has to
        # be in place before the superclass runs.
        self.address_family = address_family
        super().__init__(server_address, handler_class)


def create_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    """Create (but do not start) a loopback-bound dashboard server.

    Args:
        host: Bind host; must be loopback (see :func:`normalize_host`).
        port: TCP port, ``0`` asks the OS for a free ephemeral port.

    Returns:
        A :class:`~http.server.ThreadingHTTPServer` ready for
        :meth:`~http.server.BaseServer.serve_forever`.

    Raises:
        ValueError: If ``host`` is not loopback or ``port`` is out of range.
    """
    bind_host = normalize_host(host)
    if isinstance(port, bool) or not isinstance(port, int):
        raise ValueError(f"port must be an integer, got {type(port).__name__}")
    if not 0 <= port <= 65535:
        raise ValueError(f"port must be within 0..65535, got {port}")
    family = socket.AF_INET6 if bind_host == "::1" else socket.AF_INET
    return _GuiHTTPServer((bind_host, port), create_handler(), address_family=family)


def _url_for(server: ThreadingHTTPServer) -> str:
    """Return the browser URL of a bound server."""
    host, port = server.server_address[0], server.server_address[1]
    text = str(host)
    if ":" in text:
        return f"http://[{text}]:{port}/"
    return f"http://{text}:{port}/"


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    """Print the dashboard URL and serve until ``Ctrl+C``.

    Args:
        host: Bind host; must be loopback.
        port: TCP port, ``0`` asks the OS for a free ephemeral port.
        open_browser: When true, hand the URL to :mod:`webbrowser` before
            serving. A failure to launch a browser is ignored, because the URL
            is always printed.

    Raises:
        ValueError: If ``host`` is not loopback or ``port`` is out of range.
        OSError: If the address cannot be bound (e.g. the port is taken).

    Note:
        This function blocks inside
        :meth:`~http.server.BaseServer.serve_forever`; tests exercise
        :func:`create_server` plus a background thread instead.
    """
    server = create_server(host, port)
    url = _url_for(server)
    print(f"CODEVANTA dashboard: {url}")
    print("Loopback only, read-only analysis. Press Ctrl+C to stop.")
    sys.stdout.flush()
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # pragma: no cover - headless session without a browser
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCODEVANTA dashboard stopped.")
    finally:
        server.server_close()






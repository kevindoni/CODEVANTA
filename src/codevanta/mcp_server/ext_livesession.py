"""MCP tools for persistent gdb debug sessions (no MCP imports).

Four tools: ``codevanta_debug_start`` (one bounded gdb run, registered under a
deterministic id such as ``dbg-001``), ``codevanta_debug_status`` (lifecycle
state plus bounded stored trace info), ``codevanta_debug_close`` (cleanup +
``closed`` marker) and ``codevanta_debug_sessions`` (all sessions, bounded).
The session is honest by construction: it wraps *one* gdb invocation through
the :func:`codevanta.analysis.debugger.run_breakpoints` injection contract --
there is no interactive MI plumbing, and ``status`` reports exactly the stored
result of that invocation. All state lives in a module-level registry capped at
:data:`MAX_SESSIONS` records; the raw gdb capture is persisted next to the
session script and removed again on ``close``. The registration imports live in
:mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrappers live inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codevanta.analysis.debugger import DEFAULT_TIMEOUT, Runner, gdb_available, run_breakpoints
from codevanta.analysis.dynamic import DEFAULT_MAX_HITS
from codevanta.core.loader import BinaryInfo, BinaryLoader, BinaryLoadError
from codevanta.core.report import AnalysisError

#: Maximum number of session records the registry holds (open or closed).
MAX_SESSIONS = 8

#: Deterministic session ids look like ``dbg-001``.
SESSION_ID_TEMPLATE = "dbg-{:03d}"

#: Hits kept in the bounded per-session preview.
RECENT_HITS = 8

#: Distinct hit addresses / coverage functions kept in the stored summary.
MAX_SUMMARY_ENTRIES = 64

#: Session lifecycle states: the synchronous run has completed, or the record
#: has been closed (and its artifacts removed).
STATE_COMPLETED = "completed"
STATE_CLOSED = "closed"

DEFAULT_DEBUG_MAX_HITS = DEFAULT_MAX_HITS
DEFAULT_DEBUG_TIMEOUT = DEFAULT_TIMEOUT

TOOL_DESCRIPTION_START = (
    "Start a gdb debug session against a local binary and run it to "
    "completion: breakpoint addresses (file virtual-address space) are "
    "validated, a gdb batch script is generated (hit ceiling max_hits, "
    "wall-clock budget timeout), executed once through gdb -batch, and the "
    "captured trace is parsed into a summary (hits, backtrace-attributed "
    "function coverage, warnings). The session is one gdb invocation -- there "
    "is no interactive session -- registered under a deterministic id "
    "(dbg-001, dbg-002, ...) with the raw capture persisted for status/close. "
    "At most 8 session records are kept; close one before starting more. "
    "Requires gdb on PATH; its absence is a typed error."
)
TOOL_DESCRIPTION_STATUS = (
    "Report the lifecycle state and bounded stored trace info of a gdb debug "
    "session started with codevanta_debug_start: its state (completed or "
    "closed), target path, breakpoint addresses, exit code, hit counts, "
    "function coverage, a bounded recent-hits preview and the run warnings. "
    "Read-only: nothing is re-run. An unknown session id is a typed error "
    "naming the id."
)
TOOL_DESCRIPTION_CLOSE = (
    "Close a gdb debug session: remove its session artifacts (script file, "
    "raw gdb capture, session directory) and mark the record closed. The "
    "stored trace summary stays queryable through codevanta_debug_sessions. "
    "An unknown or already-closed session id is a typed error naming the id."
)
TOOL_DESCRIPTION_SESSIONS = (
    "List every registered gdb debug session (at most 8, oldest first) with "
    "its id, state (completed or closed), target path and hit count, plus the "
    "registry bound. Bounded summary only -- use codevanta_debug_status for "
    "the stored trace of one session."
)


class _CaptureRunner:
    """Runner wrapper that tees gdb stdout into the session capture file.

    ``inner`` is the injectable runner supplied by the caller (``None`` means
    ``subprocess.run``, mirroring ``codevanta.analysis.debugger``'s own
    default). The outcome object is returned unchanged; only its stdout text
    is persisted, after the run, so a failing runner writes nothing.
    """

    def __init__(self, inner: Runner | None, capture_path: Path) -> None:
        self._inner = inner
        self._capture_path = capture_path
        self.captured = False

    def __call__(self, command: Sequence[str], **kwargs: Any) -> Any:
        if self._inner is not None:
            outcome = self._inner(command, **kwargs)
        else:
            outcome = subprocess.run(command, **kwargs)
        stdout = getattr(outcome, "stdout", None)
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        self._capture_path.write_text(str(stdout or ""), encoding="utf-8", newline="\n")
        self.captured = True
        return outcome


@dataclass
class DebugSession:
    """One registered gdb session: its inputs, state and stored trace summary.

    Attributes:
        session_id: Deterministic id (``dbg-001``, ``dbg-002``, ...).
        path: Target binary the single gdb invocation ran against.
        addresses: Breakpoint addresses that were requested.
        max_hits: Hit ceiling the script enforced.
        timeout: Wall-clock budget of the invocation, in seconds.
        state: ``completed`` after the run, ``closed`` after cleanup.
        work_dir: Session directory holding the (removed) script and the raw
            capture; removed itself on close and on eviction.
        script_path: Path of the executed gdb script. The file is removed by
            the run itself, so this is a record, not a handle.
        capture_path: Path of the persisted raw gdb stdout; removed on close.
        exit_code: Exit code gdb returned (0 on success).
        warnings: Run-level warnings (non-zero exit, cleanup issues).
        total_hits: Parsed hit count.
        hit_addresses: Distinct hit addresses, bounded.
        function_coverage: Hit count per ``0x``-spelled function address.
        truncated: Whether the parser flagged a truncated trace.
        parse_warnings: Parser warnings, bounded.
        command: The exact ``argv`` of the gdb invocation.
        hits: Bounded recent-hits preview (serialized hit records).
    """

    session_id: str
    path: str
    addresses: tuple[int, ...]
    max_hits: int
    timeout: float
    state: str
    work_dir: Path
    script_path: str
    capture_path: str
    exit_code: int
    warnings: tuple[str, ...]
    total_hits: int
    hit_addresses: tuple[int, ...]
    function_coverage: dict[str, int]
    truncated: bool
    parse_warnings: tuple[str, ...]
    command: tuple[str, ...]
    hits: list[dict[str, Any]] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        """Return the bounded stored trace summary shared by all tools."""
        return {
            "total_hits": self.total_hits,
            "unique_hit_count": len(self.hit_addresses),
            "hit_addresses": list(self.hit_addresses),
            "truncated": self.truncated,
            "function_coverage": dict(
                list(self.function_coverage.items())[:MAX_SUMMARY_ENTRIES]
            ),
            "recent_hits": self.hits[:RECENT_HITS],
            "parse_warnings": list(self.parse_warnings[:RECENT_HITS]),
            "exit_code": self.exit_code,
            "warnings": list(self.warnings),
            "command": list(self.command),
        }

    def record(self) -> dict[str, Any]:
        """Return the bounded listing entry used by ``sessions``."""
        return {
            "session_id": self.session_id,
            "state": self.state,
            "path": self.path,
            "total_hits": self.total_hits,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return the full bounded payload (start/status)."""
        return {
            "session_id": self.session_id,
            "state": self.state,
            "path": self.path,
            "addresses": list(self.addresses),
            "max_hits": self.max_hits,
            "timeout": self.timeout,
            "gdb_available": gdb_available(),
            "script_path": self.script_path,
            "capture_path": self.capture_path,
            "script_removed": not Path(self.script_path).exists(),
            "capture_present": Path(self.capture_path).exists(),
            **self.summary(),
        }


@dataclass
class _Registry:
    """Module-level session registry (bounded, deterministic ids)."""

    sessions: dict[str, DebugSession] = field(default_factory=dict)
    next_number: int = 1
    lock: threading.Lock = field(default_factory=threading.Lock)


_REGISTRY = _Registry()


def _load_info(path: str) -> BinaryInfo:
    """Load the target's metadata, converting loader errors to AnalysisError."""
    target = Path(path).expanduser()
    if not target.is_file():
        raise AnalysisError(f"file not found: {target}")
    try:
        return BinaryLoader().load(target)
    except BinaryLoadError as exc:
        raise AnalysisError(f"could not load {target}: {exc}") from exc


def _reserve_slot() -> str:
    """Reserve a registry slot and return the next deterministic session id.

    Raises:
        AnalysisError: The registry holds ``MAX_SESSIONS`` records and none of
            them is closed (close one with ``codevanta_debug_close`` first).
    """
    with _REGISTRY.lock:
        if len(_REGISTRY.sessions) >= MAX_SESSIONS:
            for session_id, session in list(_REGISTRY.sessions.items()):
                if session.state != STATE_CLOSED or len(_REGISTRY.sessions) < MAX_SESSIONS:
                    break
                shutil.rmtree(session.work_dir, ignore_errors=True)
                del _REGISTRY.sessions[session_id]
            if len(_REGISTRY.sessions) >= MAX_SESSIONS:
                raise AnalysisError(
                    f"session registry is full ({MAX_SESSIONS} sessions); close one with "
                    "codevanta_debug_close before starting another"
                )
        session_id = SESSION_ID_TEMPLATE.format(_REGISTRY.next_number)
        _REGISTRY.next_number += 1
        return session_id



def codevanta_debug_start(
    path: str,
    addresses: Sequence[int],
    max_hits: int = DEFAULT_DEBUG_MAX_HITS,
    timeout: float = DEFAULT_DEBUG_TIMEOUT,
    *,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Run one bounded gdb session on ``path`` and register it as ``dbg-NNN``.

    The address list, ``max_hits`` and ``timeout`` are validated by the script
    builder; the invocation goes through
    :func:`codevanta.analysis.debugger.run_breakpoints` with a per-session
    runner that persists the raw gdb capture. On success the session record
    (state ``completed``) and its payload are returned; on failure nothing is
    registered and every artifact is removed.
    """
    if isinstance(addresses, (str, bytes)) or not isinstance(addresses, Sequence):
        raise AnalysisError(
            f"addresses must be a list of ints, got {type(addresses).__name__}"
        )
    requested = tuple(addresses)
    info = _load_info(path)
    session_id = _reserve_slot()
    work_dir = Path(tempfile.mkdtemp(prefix="codevanta-debug-session-"))
    capture_path = work_dir / "gdb-capture.log"
    try:
        capture_runner = _CaptureRunner(runner, capture_path)
        result = run_breakpoints(
            Path(path).expanduser(),
            info,
            requested,
            max_hits=max_hits,
            timeout=timeout,
            runner=capture_runner,
            script_dir=work_dir,
        )
    except Exception:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise
    report = result.report
    coverage = {
        f"0x{address:x}": count
        for address, count in list(report.function_coverage.items())[:MAX_SUMMARY_ENTRIES]
    }
    session = DebugSession(
        session_id=session_id,
        path=str(Path(path).expanduser()),
        addresses=requested,
        max_hits=max_hits,
        timeout=timeout,
        state=STATE_COMPLETED,
        work_dir=work_dir,
        script_path=result.script_path,
        capture_path=str(capture_path),
        exit_code=result.exit_code,
        warnings=result.warnings,
        total_hits=report.total_hits,
        hit_addresses=tuple(report.unique_addresses[:MAX_SUMMARY_ENTRIES]),
        function_coverage=coverage,
        truncated=report.truncated,
        parse_warnings=tuple(report.warnings[:RECENT_HITS]),
        command=result.command,
        hits=[hit.to_dict() for hit in report.hits[:RECENT_HITS]],
    )
    with _REGISTRY.lock:
        _REGISTRY.sessions[session_id] = session
    return session.to_dict()


def _lookup(session_id: str) -> DebugSession:
    """Return the session record for ``session_id`` or raise naming the id."""
    if not isinstance(session_id, str) or not session_id.strip():
        raise AnalysisError(f"session_id must be a non-empty string, got {session_id!r}")
    session = _REGISTRY.sessions.get(session_id)
    if session is None:
        known = ", ".join(_REGISTRY.sessions) or "none"
        raise AnalysisError(
            f"unknown session id: {session_id!r} (registered sessions: {known})"
        )
    return session


def codevanta_debug_status(session_id: str) -> dict[str, Any]:
    """Return the lifecycle state and bounded stored info of one session.

    Read-only: the stored result of the session's single gdb invocation, never
    a re-run. An unknown session id raises an error naming the id.
    """
    return _lookup(session_id).to_dict()


def codevanta_debug_close(session_id: str) -> dict[str, Any]:
    """Close a session: remove its artifacts and mark the record ``closed``.

    The script file (already removed by the run itself), the raw capture file
    and the session directory are deleted; the summary stays queryable through
    :func:`codevanta_debug_sessions`. An unknown or already-closed session id
    raises an error naming the id.
    """
    session = _lookup(session_id)
    if session.state == STATE_CLOSED:
        raise AnalysisError(
            f"session {session_id} is already closed and its artifacts are gone"
        )
    removed: list[str] = []
    for artifact in (session.script_path, session.capture_path):
        artifact_path = Path(artifact)
        if artifact_path.exists():
            try:
                artifact_path.unlink()
                removed.append(artifact)
            except OSError as exc:
                session.warnings = (*session.warnings, f"could not remove {artifact}: {exc}")
    shutil.rmtree(session.work_dir, ignore_errors=True)
    session.state = STATE_CLOSED
    return {
        "session_id": session.session_id,
        "state": session.state,
        "removed": removed,
        "work_dir_removed": not session.work_dir.exists(),
        "total_hits": session.total_hits,
    }


def codevanta_debug_sessions() -> dict[str, Any]:
    """List every registered session with its state, bounded by the registry."""
    with _REGISTRY.lock:
        records = [session.record() for session in _REGISTRY.sessions.values()]
    return {
        "count": len(records),
        "max_sessions": MAX_SESSIONS,
        "sessions": records,
    }


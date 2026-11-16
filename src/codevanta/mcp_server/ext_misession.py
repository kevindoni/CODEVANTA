"""MCP tools for persistent interactive gdb MI sessions (no MCP imports).

Five tools: ``codevanta_mi_start`` (launch one interactive
``gdb --interpreter=mi2`` and register it under a deterministic id such as
``mi-001``), ``codevanta_mi_console`` (send one raw MI command and return the
transcript), ``codevanta_mi_status`` (lifecycle state plus the bounded recent
command history), ``codevanta_mi_close`` (verified shutdown) and
``codevanta_mi_sessions`` (all sessions, bounded).

The lifecycle contract, in the shape the interactive debugging lane of
closed-source tooling made familiar:

- a session is a *live process* the server owns, identified by id;
- ``close`` quits gdb and **verifies** the debugger process went away
  (``-gdb-exit`` honoured, exit code 0 -> ``clean: true``), reporting the
  escalation path otherwise -- and it never kills an attached inferior as
  part of cleanup;
- what close *cannot* verify, it says: the inferior's disposition after gdb
  exits is only observable through Linux ``/proc``; on every other platform
  the payload reports ``inferior_disposition: "unknown"`` with the reason
  instead of guessing.

The registry holds at most :data:`MAX_SESSIONS` records; eviction closes a
live session first. All state lives in this process -- restart the server and
the sessions are gone, which ``status`` states in every payload.
"""

from __future__ import annotations

import contextlib
import platform
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from codevanta.analysis.debug_session import (
    DEFAULT_TIMEOUT,
    DebugSession,
    MITransport,
    gdb_available,
)
from codevanta.core.report import AnalysisError

#: Maximum number of session records the registry holds (live or closed).
MAX_SESSIONS = 8

#: Deterministic session ids look like ``mi-001``.
SESSION_ID_TEMPLATE = "mi-{:03d}"

#: Commands kept in the bounded per-session history.
RECENT_COMMANDS = 16

#: Session lifecycle states.
STATE_READY = "ready"
STATE_CLOSED = "closed"

TOOL_DESCRIPTION_MI_START = (
    "Start one persistent interactive gdb MI session and register it under a "
    "deterministic id (mi-001, mi-002, ...). Optionally pass a target program "
    "to pre-load; without one the session starts bare and you load a file "
    "through the console lane (-file-exec-file). Requires gdb on PATH; its "
    "absence is a typed error. The session lives in this server process: a "
    "restart drops it. At most 8 records are kept; close one before starting "
    "more."
)
TOOL_DESCRIPTION_MI_CONSOLE = (
    "Send one raw gdb/MI command to a live session (single line, no newline) "
    "and return its transcript: result class, parsed payload and every MI "
    "record around it. An MI ^error is returned as data, not raised -- the "
    "console reports what gdb said. Only -gdb-exit is refused here; use "
    "codevanta_mi_close, which verifies the shutdown."
)
TOOL_DESCRIPTION_MI_STATUS = (
    "Report the lifecycle state of one MI session: ready or closed, its "
    "target, per-command timeout, gdb availability and the bounded recent "
    "command history (command, result class, error text when gdb refused). "
    "Read-only; an unknown session id is a typed error naming the id."
)
TOOL_DESCRIPTION_MI_CLOSE = (
    "Close one MI session with a verified shutdown: send -gdb-exit, wait for "
    "the debugger process to go away on its own (clean: true, exit code 0), "
    "and report the escalation path when it did not. Close never kills an "
    "attached inferior; the inferior's disposition after gdb exits is only "
    "verifiable through Linux /proc, so the payload says 'unknown' with the "
    "reason everywhere else. An unknown or already-closed id is a typed error."
)
TOOL_DESCRIPTION_MI_SESSIONS = (
    "List every registered MI session (at most 8, oldest first): id, state "
    "(ready or closed), target and command count, plus the registry bound."
)


@dataclass
class _LiveSession:
    """One registered interactive session: the live object plus bookkeeping."""

    session_id: str
    session: DebugSession | None  # None once closed
    target: str | None
    timeout: float
    state: str = STATE_READY
    history: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=RECENT_COMMANDS))


@dataclass
class _Registry:
    """Module-level session registry (bounded, deterministic ids)."""

    sessions: dict[str, _LiveSession] = field(default_factory=dict)
    next_number: int = 1
    lock: threading.Lock = field(default_factory=threading.Lock)


_REGISTRY = _Registry()


def _platform_facts() -> dict[str, Any]:
    """What this platform can and cannot verify about an inferior's fate."""
    system = platform.system() or "unknown"
    verifiable = system == "Linux"
    if verifiable:
        note = (
            "inferior disposition after gdb exits is verifiable through /proc in "
            "principle; close still reports it because it does not perform the check"
        )
    else:
        note = (
            f"on {system} the inferior's disposition after gdb exits cannot be "
            "verified (no /proc equivalent is consulted); close quits and verifies "
            "the gdb process only and never kills an attached inferior"
        )
    return {
        "system": system,
        "inferior_disposition": "unknown",
        "disposition_reason": note,
    }


def _reserve_slot() -> str:
    """Reserve a registry slot, evicting closed records when full.

    When every record is live, the oldest session gets a *verified* shutdown
    (``quit()``, never an abandon) before its record is dropped; the
    deterministic id counter never rewinds, so an id is never handed out
    twice.
    """
    with _REGISTRY.lock:
        if len(_REGISTRY.sessions) >= MAX_SESSIONS:
            for session_id, record in list(_REGISTRY.sessions.items()):
                if record.state == STATE_CLOSED:
                    del _REGISTRY.sessions[session_id]
                    if len(_REGISTRY.sessions) < MAX_SESSIONS:
                        break
        if len(_REGISTRY.sessions) >= MAX_SESSIONS:
            oldest_id, oldest = next(iter(_REGISTRY.sessions.items()))
            del _REGISTRY.sessions[oldest_id]
            if oldest.session is not None:
                with contextlib.suppress(Exception):
                    oldest.session.quit()
        reserved = SESSION_ID_TEMPLATE.format(_REGISTRY.next_number)
        _REGISTRY.next_number += 1
        return reserved


def codevanta_mi_start(
    target: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    *,
    transport: MITransport | None = None,
) -> dict[str, Any]:
    """Launch one interactive gdb MI session and register it as ``mi-NNN``.

    Args:
        target: Optional program to pre-load into gdb.
        timeout: Per-command wall-clock budget for the session, in seconds.
        transport: Injectable MI transport (tests and embedding hosts);
            ``None`` launches a real ``gdb --interpreter=mi2`` process.

    Returns:
        The registered session's payload.

    Raises:
        AnalysisError: gdb is not on PATH, the launch or handshake failed, or
            the registry is full of live sessions.
    """
    if target is not None and not isinstance(target, str):
        raise AnalysisError(f"target must be a string or null, got {type(target).__name__}")
    session_id = _reserve_slot()
    session = DebugSession.launch(
        target if target and target.strip() else None,
        timeout=timeout,
        transport=transport,
    )
    record = _LiveSession(
        session_id=session_id,
        session=session,
        target=target if target and target.strip() else None,
        timeout=timeout,
    )
    with _REGISTRY.lock:
        _REGISTRY.sessions[session_id] = record
    return {
        "session_id": session_id,
        "state": record.state,
        "target": record.target,
        "timeout": timeout,
        "gdb_available": gdb_available(),
        **_platform_facts(),
    }


def _lookup(session_id: str) -> _LiveSession:
    """Return the session record for ``session_id`` or raise naming the id."""
    if not isinstance(session_id, str) or not session_id.strip():
        raise AnalysisError(f"session_id must be a non-empty string, got {session_id!r}")
    record = _REGISTRY.sessions.get(session_id)
    if record is None:
        known = ", ".join(_REGISTRY.sessions) or "none"
        raise AnalysisError(
            f"unknown session id: {session_id!r} (registered sessions: {known})"
        )
    return record


def codevanta_mi_console(session_id: str, command: str) -> dict[str, Any]:
    """Send one raw MI command to a live session and return the transcript.

    ``-gdb-exit`` is refused with a typed error pointing at
    :func:`codevanta_mi_close`, because an unverified exit is exactly what the
    close lane exists to prevent. Every other command goes through; an MI
    ``^error`` comes back as ``result_class: "error"`` data.
    """
    record = _lookup(session_id)
    if record.state != STATE_READY or record.session is None:
        raise AnalysisError(
            f"session {session_id} is closed; start a new one with codevanta_mi_start"
        )
    if not isinstance(command, str) or not command.strip():
        raise AnalysisError("command must be a non-empty single-line MI command")
    stripped = command.strip()
    if stripped.startswith("-gdb-exit") or stripped == "kill":
        raise AnalysisError(
            "refused: shutting the debugger down belongs to codevanta_mi_close, "
            "which verifies the exit; the console lane never ends a session"
        )
    entry: dict[str, Any] = {"command": stripped}
    try:
        payload = record.session.console(stripped)
    except AnalysisError as exc:
        entry.update({"ok": False, "error": str(exc)})
        record.history.append(entry)
        raise
    entry.update({"ok": True, "result_class": payload["result_class"]})
    record.history.append(entry)
    return {"session_id": session_id, **payload}


def codevanta_mi_status(session_id: str) -> dict[str, Any]:
    """Return the lifecycle state and bounded history of one session."""
    record = _lookup(session_id)
    return {
        "session_id": record.session_id,
        "state": record.state,
        "target": record.target,
        "timeout": record.timeout,
        "gdb_available": gdb_available(),
        "recent_commands": list(record.history),
        **_platform_facts(),
    }


def codevanta_mi_close(session_id: str) -> dict[str, Any]:
    """Close a session with a verified gdb shutdown.

    The quit result drives the payload: ``clean`` is true only when gdb
    exited on its own with code 0, and the warnings name any escalation.
    """
    record = _lookup(session_id)
    if record.state == STATE_CLOSED or record.session is None:
        raise AnalysisError(
            f"session {session_id} is already closed and its process is gone"
        )
    quit_result = record.session.quit()
    record.session = None
    record.state = STATE_CLOSED
    return {
        "session_id": record.session_id,
        "state": record.state,
        "clean": quit_result.clean,
        "exit_code": quit_result.exit_code,
        "warnings": list(quit_result.warnings),
        **_platform_facts(),
    }


def codevanta_mi_sessions() -> dict[str, Any]:
    """List every registered MI session, bounded by the registry."""
    with _REGISTRY.lock:
        records = [
            {
                "session_id": record.session_id,
                "state": record.state,
                "target": record.target,
                "commands": len(record.history),
            }
            for record in _REGISTRY.sessions.values()
        ]
    return {"count": len(records), "max_sessions": MAX_SESSIONS, "sessions": records}

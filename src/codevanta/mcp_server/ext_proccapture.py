"""MCP tools for owned process captures (no MCP imports).

Four tools: ``codevanta_proc_run`` (execute the caller-selected command
locally as one bounded owned subprocess and register the capture under a
deterministic id such as ``proc-001``), ``codevanta_proc_status`` (the stored
bounded capture), ``codevanta_proc_compare`` (deterministic comparison of two
stored captures) and ``codevanta_proc_sessions`` (all sessions, bounded).

The lane is honest by construction: ``run`` is *dynamic analysis* -- it
executes the command you pass it on this machine -- and every description says
so. The capture itself follows the
:func:`codevanta.analysis.proc_capture.capture_process` contract: argv form
(no shell), output via pipes (no terminal emulation), 1 MiB per stream kept
with sha256 over the full raw bytes, a wall-clock budget of at most 120
seconds, and a timeout reported as an honest ``timed_out`` state rather than
an error. ``status`` and ``compare`` re-run nothing: they report exactly the
stored records. All state lives in a module-level registry capped at
:data:`MAX_PROC_SESSIONS` records; proc records have no ``close`` step in this
lane, so a full registry refuses further runs until the server process is
restarted (the id counter stays monotonic either way). The registration
imports live in :mod:`codevanta.mcp_server.tools`; the ``@server.tool``
wrappers live inside :func:`codevanta.mcp_server.server.build_server` --
imports alone do not register anything.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from codevanta.analysis.proc_capture import (
    DEFAULT_TIMEOUT,
    MAX_OUTPUT_BYTES,
    ProcCapture,
    ProcRunner,
    capture_process,
    compare_captures,
)
from codevanta.core.report import AnalysisError

#: Maximum number of session records the registry holds.
MAX_PROC_SESSIONS = 8

#: Deterministic session ids look like ``proc-001``.
SESSION_ID_TEMPLATE = "proc-{:03d}"

#: The only lifecycle state in this lane: the bounded run has been captured.
STATE_CAPTURED = "captured"

#: Wrapper defaults re-exported for the server layer.
DEFAULT_PROC_TIMEOUT = DEFAULT_TIMEOUT
PROC_MAX_OUTPUT_BYTES = MAX_OUTPUT_BYTES

TOOL_DESCRIPTION_PROC_RUN = (
    "Run the caller-selected command LOCALLY on this machine as an owned, "
    "bounded child process and register the capture under a deterministic id "
    "(proc-001, proc-002, ...). SECURITY: this tool EXECUTES the command you "
    "pass -- it is dynamic analysis, not static inspection -- so pass only "
    "commands you intend to run. The child is spawned in argv form (no shell) "
    "with output captured via pipes (no terminal emulation, no PTY): stdout "
    "and stderr are kept up to max_output_bytes (1 MiB) per stream with the "
    "sha256 of the full raw bytes recorded either way, the wall-clock budget "
    "is at most 120 seconds (a timeout is reported honestly as timed_out with "
    "the partial output and exit_code null), at most 32 arguments and 16 extra "
    "env variables (merged over the inherited environment) are accepted. At "
    "most 8 captures are kept; a full registry is a typed error."
)
TOOL_DESCRIPTION_PROC_STATUS = (
    "Report the stored bounded capture of a registered proc session: the exact "
    "argv, exit code, duration, stdout/stderr (with truncation flags and the "
    "sha256 of each full raw stream), timed_out state, started/finished "
    "timestamps and warnings. Read-only: nothing is re-run. An unknown session "
    "id is a typed error naming the id."
)
TOOL_DESCRIPTION_PROC_COMPARE = (
    "Compare two registered proc captures deterministically on their stored "
    "bytes: exit-code match, duration delta in milliseconds, per-stream sha256 "
    "digest match, and a bounded difflib unified diff (200 lines per stream) "
    "for mismatched output, with a verdict of identical, exit-mismatch, "
    "output-mismatch, or divergent. SECURITY note: this tool never executes "
    "anything -- it reads the two stored records only. Unknown session ids are "
    "typed errors naming the id."
)
TOOL_DESCRIPTION_PROC_SESSIONS = (
    "List every registered proc capture with its state, bounded by the "
    "8-record registry. Read-only: nothing is re-run."
)


@dataclass
class ProcSession:
    """One registered capture: its deterministic id, state and stored record.

    Attributes:
        session_id: Deterministic id (``proc-001``, ``proc-002``, ...).
        state: ``captured`` -- the single bounded run has finished and its
            result is stored. There is no ``closed`` state in this lane.
        registered_at: UTC timestamp (ISO 8601) of the registration.
        capture: The stored :class:`ProcCapture`.
    """

    session_id: str
    state: str
    registered_at: str
    capture: ProcCapture

    def summary(self) -> dict[str, Any]:
        """Return the bounded stored capture shared by all tools."""
        return self.capture.to_dict()

    def record(self) -> dict[str, Any]:
        """Return the bounded listing entry used by ``sessions``."""
        return {
            "session_id": self.session_id,
            "state": self.state,
            "registered_at": self.registered_at,
            "command": list(self.capture.command),
            "exit_code": self.capture.exit_code,
            "timed_out": self.capture.timed_out,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return the full stored payload: id, state and the capture itself."""
        return {
            "session_id": self.session_id,
            "state": self.state,
            "registered_at": self.registered_at,
            "capture": self.capture.to_dict(),
        }


@dataclass
class _Registry:
    """Module-level session registry (bounded, deterministic ids)."""

    sessions: dict[str, ProcSession] = field(default_factory=dict)
    next_number: int = 1
    lock: threading.Lock = field(default_factory=threading.Lock)


_REGISTRY = _Registry()


def _reserve_slot() -> str:
    """Reserve a registry slot and return the next deterministic session id.

    Raises:
        AnalysisError: The registry holds ``MAX_PROC_SESSIONS`` records. Proc
            records have no close step in this lane, so nothing is evicted
            automatically; the caller must restart the server session to
            clear the registry.
    """
    with _REGISTRY.lock:
        if len(_REGISTRY.sessions) >= MAX_PROC_SESSIONS:
            raise AnalysisError(
                f"session registry is full ({MAX_PROC_SESSIONS} captures); this "
                "lane keeps every capture, so restart the server session to clear it"
            )
        session_id = SESSION_ID_TEMPLATE.format(_REGISTRY.next_number)
        _REGISTRY.next_number += 1
        return session_id


def _lookup(session_id: str) -> ProcSession:
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
def codevanta_proc_run(
    command: str,
    arguments: Sequence[str] | None = None,
    working_directory: str | None = None,
    timeout: float = DEFAULT_PROC_TIMEOUT,
    env: Mapping[str, str] | None = None,
    max_output_bytes: int = PROC_MAX_OUTPUT_BYTES,
    *,
    runner: ProcRunner | None = None,
) -> dict[str, Any]:
    """Execute the caller-selected command locally and register the capture.

    SECURITY: the command runs on this machine as an owned child process.
    The run goes through :func:`codevanta.analysis.proc_capture.capture_process`
    (bounded: argv form, pipes, byte and wall-clock ceilings); on success the
    record is registered as ``proc-NNN`` with state ``captured`` and returned.
    On failure nothing is registered. A full registry is a typed error.

    The ``runner`` parameter is the test seam: an injected stand-in replaces
    ``subprocess.run`` entirely, so no offline test ever spawns a process.
    """
    # Validate and run first (like the livesession lane validates its target
    # before reserving a slot): a rejected run consumes no session id.
    capture = capture_process(
        command,
        arguments if arguments is not None else (),
        working_directory,
        timeout=timeout,
        env=env,
        max_output_bytes=max_output_bytes,
        runner=runner,
    )
    session_id = _reserve_slot()
    session = ProcSession(
        session_id=session_id,
        state=STATE_CAPTURED,
        registered_at=capture.finished_at,
        capture=capture,
    )
    with _REGISTRY.lock:
        _REGISTRY.sessions[session_id] = session
    return session.to_dict()


def codevanta_proc_status(session_id: str) -> dict[str, Any]:
    """Return the stored bounded capture of one session.

    Read-only: the stored result of the session's single bounded run, never a
    re-run. An unknown session id raises an error naming the id.
    """
    return _lookup(session_id).to_dict()


def codevanta_proc_compare(left_session_id: str, right_session_id: str) -> dict[str, Any]:
    """Compare two registered captures on their stored bytes.

    Nothing is re-run: both records are looked up and handed to
    :func:`codevanta.analysis.proc_capture.compare_captures`. Unknown session
    ids raise errors naming the id.
    """
    left = _lookup(left_session_id)
    right = _lookup(right_session_id)
    payload = compare_captures(left.capture, right.capture).to_dict()
    return {
        "left_session_id": left.session_id,
        "right_session_id": right.session_id,
        **payload,
    }


def codevanta_proc_sessions() -> dict[str, Any]:
    """List every registered session with its state, bounded by the registry."""
    with _REGISTRY.lock:
        records = [session.record() for session in _REGISTRY.sessions.values()]
    return {
        "count": len(records),
        "max_sessions": MAX_PROC_SESSIONS,
        "sessions": records,
    }


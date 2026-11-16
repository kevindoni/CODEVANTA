"""MCP tools for persistent Frida instrumentation sessions (no MCP imports).

Five tools: ``codevanta_frida_start`` (attach/spawn plus one bounded
observation run, registered under a deterministic id such as ``frida-001``),
``codevanta_frida_load`` (one more script plus a bounded slice on a live
session), ``codevanta_frida_status`` (lifecycle state plus bounded stored
capture), ``codevanta_frida_close`` (detach/unload, cleanup, ``closed``
marker) and ``codevanta_frida_sessions`` (all sessions, bounded).

The session is honest by construction: it wraps the
:func:`codevanta.analysis.frida_bridge.start_session` contract -- a session
is *one bounded observation run* (attach/spawn, optional initial script,
then a wall-clock ``run_for`` slice), not interactive plumbing. With the
``frida`` Python module the bridge handle stays live so
``codevanta_frida_load`` can attach further scripts (each followed by
another bounded slice); without the module the bridge degrades to one
bounded ``frida -l <script>`` CLI run and the record is a one-shot whose
``load`` raises the typed "not supported for this session kind" error.
``status`` reports exactly the stored result of the run(s) that happened.
Every tool that needs frida probes availability first
(``importlib.util.find_spec`` + ``shutil.which``, never an import) and fails
with one honest typed error naming what is missing. All state lives in a
module-level registry capped at :data:`MAX_FRIDA_SESSIONS` records; the raw
message capture is persisted next to the session script and removed again
on ``close``. The registration imports live in
:mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrappers live inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codevanta.analysis.frida_bridge import (
    DEFAULT_DURATION,
    MAX_SCRIPT_BYTES,
    MAX_TIMEOUT,
    MODE_ATTACH,
    MODE_SPAWN,
    MODES,
    Runner,
    start_session,
)
from codevanta.core.report import AnalysisError

#: Maximum number of session records the registry holds (open or closed).
MAX_FRIDA_SESSIONS = 8

#: Deterministic session ids look like ``frida-001``.
SESSION_ID_TEMPLATE = "frida-{:03d}"

#: Messages kept in the bounded per-session preview.
RECENT_MESSAGES = 8

#: Install hint shared by every honest unavailability message.
FRIDA_INSTALL_HINT = "'pip install frida-tools frida'"

#: Session lifecycle states: the bounded run has completed, or the record
#: has been closed (and its artifacts removed).
STATE_COMPLETED = "completed"
STATE_CLOSED = "closed"

DEFAULT_FRIDA_DURATION = DEFAULT_DURATION

TOOL_DESCRIPTION_FRIDA_START = (
    "Start a Frida instrumentation session against a local process: attach "
    "to a pid or a program name, or spawn a program (resumed after the "
    "initial script is loaded). One initial script may be given inline "
    "(script) or by file (script_path, at most 64 KiB); the session then "
    "collects messages for one bounded observation slice (duration, 1 .. 60 "
    "seconds). Honesty: the session is one bounded observation run through "
    "the frida bridge -- there is no interactive plumbing. With the frida "
    "Python module installed the handle stays live for codevanta_frida_load "
    "until codevanta_frida_close; without the module the bridge degrades to "
    "one bounded `frida -l <script>` CLI run and the session is a one-shot "
    "(script required, further loads refused). Registered under a "
    "deterministic id (frida-001, frida-002, ...) with the raw message "
    "capture persisted for status/close; at most 8 session records are "
    "kept. Requires the frida CLI and/or the frida python bindings; their "
    "absence is a typed error naming exactly what is missing."
)
TOOL_DESCRIPTION_FRIDA_LOAD = (
    "Load one additional script into a live Frida session started with "
    "codevanta_frida_start and collect another bounded message slice "
    "(duration, 1 .. 60 seconds). The script is given inline (source) or by "
    "file (path, at most 64 KiB) and only module-backed sessions accept it: "
    "a one-shot session (started through the frida CLI fallback) refuses "
    "with a typed 'not supported for this session kind' error, and an "
    "unknown or already-closed session id is a typed error naming the id."
)
TOOL_DESCRIPTION_FRIDA_STATUS = (
    "Report the lifecycle state and bounded stored capture of a Frida "
    "session started with codevanta_frida_start: its state (completed or "
    "closed), mode, target, whether it is a live module-backed session or a "
    "one-shot CLI run, message counts, a bounded recent-messages preview, "
    "run warnings and the availability probe snapshot taken at start. "
    "Read-only: nothing is re-run. An unknown session id is a typed error "
    "naming the id."
)
TOOL_DESCRIPTION_FRIDA_CLOSE = (
    "Close a Frida session: detach/unload through the frida bridge handle "
    "(best-effort, safe for one-shot records), remove its session artifacts "
    "(script files, raw message capture, session directory) and mark the "
    "record closed. The bounded summary stays queryable through "
    "codevanta_frida_sessions. An unknown or already-closed session id is a "
    "typed error naming the id."
)
TOOL_DESCRIPTION_FRIDA_SESSIONS = (
    "List every registered Frida session (at most 8, oldest first) with its "
    "id, state (completed or closed), mode, target and message count, plus "
    "the registry bound. Bounded summary only -- use codevanta_frida_status "
    "for the stored capture of one session."
)


@dataclass(frozen=True)
class FridaAvailability:
    """Snapshot of the dual frida gate (module spec + CLI on ``PATH``).

    Mirrors ``codevanta.analysis.dynamic._probe_frida``'s honesty: the
    module is located via ``importlib.util.find_spec`` and never imported,
    the CLI via ``shutil.which`` and never run.
    """

    module_available: bool
    cli_available: bool

    @property
    def available(self) -> bool:
        """Dual gate: the CLI or the Python module; the caller needs only this."""
        return self.module_available or self.cli_available

    @property
    def reason(self) -> str:
        """Human-readable explanation, non-empty in both directions."""
        if self.module_available and self.cli_available:
            return (
                "the frida python bindings are importable and the frida CLI is on "
                "PATH; the version is not probed, because probing would load frida"
            )
        missing: list[str] = []
        if not self.cli_available:
            missing.append("the frida CLI")
        if not self.module_available:
            missing.append("the frida python bindings")
        return (
            f"frida is not installed: missing {' and '.join(missing)}; "
            f"install with {FRIDA_INSTALL_HINT}. Script generation works "
            "without it, only the live session does not"
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the probe for the JSON payload."""
        return {
            "available": self.available,
            "module": self.module_available,
            "cli": self.cli_available,
            "reason": self.reason,
        }


def _module_spec() -> object | None:
    """Return the ``frida`` module spec without importing the module."""
    try:
        return importlib.util.find_spec("frida")
    except (ImportError, ValueError):  # pragma: no cover - defensive only
        return None


def _probe_frida() -> FridaAvailability:
    """Probe both gate halves without importing or running anything."""
    return FridaAvailability(
        module_available=_module_spec() is not None,
        cli_available=shutil.which("frida") is not None
        or shutil.which("frida-ps") is not None,
    )


@dataclass
class FridaSessionRecord:
    """One registered Frida session: its inputs, state and stored summary.

    Attributes:
        session_id: Deterministic id (``frida-001``, ``frida-002``, ...).
        mode: ``attach`` or ``spawn``.
        target: The target as text (a pid renders as its decimal digits).
        pid: The pid for attach-by-pid or a spawned program, else ``None``.
        device_id: Frida device id, or ``None`` for the local device.
        script_path: Path of the initial session script (a record, removed
            on close; empty when no initial script was given).
        duration: Wall-clock budget of one bounded observation slice.
        state: ``completed`` after the run, ``closed`` after cleanup.
        one_shot: True when the bridge ran the one-shot ``frida -l`` CLI
            fallback instead of a live module session.
        work_dir: Session directory holding scripts and the raw capture;
            removed on close and on eviction.
        capture_path: Path of the persisted raw message capture; removed on
            close.
        probe: The availability snapshot taken when the session started.
        warnings: Run-level warnings (CLI transcript warnings, cleanup).
        message_count: Messages captured so far (bounded by the bridge).
        dropped_messages: Messages summarised away by the bridge's cap.
        truncated: Whether any capture was cut short by a bound.
        timeout_reached: Whether the one-shot CLI run ended on its budget.
        resumed: Whether a spawned target was resumed.
        messages: Bounded recent-messages preview (serialized records).
        loads: Scripts attached through ``codevanta_frida_load`` (the
            initial script is not counted).
        handle: The live bridge handle, or ``None`` once closed.
    """

    session_id: str
    mode: str
    target: str
    pid: int | None
    device_id: str | None
    script_path: str
    duration: float
    state: str
    one_shot: bool
    work_dir: Path
    capture_path: str
    probe: FridaAvailability
    warnings: tuple[str, ...]
    message_count: int
    dropped_messages: int
    truncated: bool
    timeout_reached: bool
    resumed: bool
    messages: list[dict[str, str]] = field(default_factory=list)
    loads: int = 0
    handle: Any | None = field(default=None, repr=False, compare=False)

    def summary(self) -> dict[str, Any]:
        """Return the bounded stored capture summary shared by all tools."""
        return {
            "message_count": self.message_count,
            "dropped_messages": self.dropped_messages,
            "truncated": self.truncated,
            "timeout_reached": self.timeout_reached,
            "recent_messages": self.messages[:RECENT_MESSAGES],
            "warnings": list(self.warnings),
        }

    def record(self) -> dict[str, Any]:
        """Return the bounded listing entry used by ``sessions``."""
        return {
            "session_id": self.session_id,
            "state": self.state,
            "mode": self.mode,
            "target": self.target,
            "message_count": self.message_count,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return the full bounded payload (start/status/load)."""
        live = (
            self.state == STATE_COMPLETED
            and not self.one_shot
            and self.handle is not None
        )
        return {
            "session_id": self.session_id,
            "state": self.state,
            "mode": self.mode,
            "target": self.target,
            "pid": self.pid,
            "device_id": self.device_id,
            "session_kind": "one-shot-cli" if self.one_shot else "module",
            "live": live,
            "duration": self.duration,
            "script_path": self.script_path,
            "capture_path": self.capture_path,
            "capture_present": Path(self.capture_path).exists(),
            "scripts_loaded": self.loads,
            "resumed": self.resumed,
            "frida_available": self.probe.available,
            "probe": self.probe.to_dict(),
            **self.summary(),
        }


@dataclass
class _Registry:
    """Module-level session registry (bounded, deterministic ids)."""

    sessions: dict[str, FridaSessionRecord] = field(default_factory=dict)
    next_number: int = 1
    lock: threading.Lock = field(default_factory=threading.Lock)


_REGISTRY = _Registry()


def _discard_artifacts(session: FridaSessionRecord) -> None:
    """Close the bridge handle (best-effort) and remove the session dir."""
    if session.handle is not None:
        session.handle.close()
        session.handle = None
    shutil.rmtree(session.work_dir, ignore_errors=True)


def _reserve_slot() -> str:
    """Reserve a registry slot and return the next deterministic session id.

    Raises:
        AnalysisError: The registry holds ``MAX_FRIDA_SESSIONS`` records and
            none of them is closed (close one with ``codevanta_frida_close``
            first).
    """
    with _REGISTRY.lock:
        if len(_REGISTRY.sessions) >= MAX_FRIDA_SESSIONS:
            for session_id, session in list(_REGISTRY.sessions.items()):
                if session.state != STATE_CLOSED or len(_REGISTRY.sessions) < MAX_FRIDA_SESSIONS:
                    break
                _discard_artifacts(session)
                del _REGISTRY.sessions[session_id]
            if len(_REGISTRY.sessions) >= MAX_FRIDA_SESSIONS:
                raise AnalysisError(
                    f"session registry is full ({MAX_FRIDA_SESSIONS} sessions); close "
                    "one with codevanta_frida_close before starting another"
                )
        session_id = SESSION_ID_TEMPLATE.format(_REGISTRY.next_number)
        _REGISTRY.next_number += 1
        return session_id


def _lookup(session_id: str) -> FridaSessionRecord:
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


def _check_duration(duration: Any) -> float:
    """Validate one bounded observation slice against :data:`MAX_TIMEOUT`."""
    if isinstance(duration, bool) or not isinstance(duration, (int, float)):
        raise AnalysisError(
            f"duration must be a positive number of seconds, got {duration!r}"
        )
    if duration <= 0 or not 1.0 <= float(duration) <= MAX_TIMEOUT:
        raise AnalysisError(
            f"duration {duration} is out of range; expected 1 .. {MAX_TIMEOUT} seconds"
        )
    return float(duration)


def _check_mode(mode: Any) -> str:
    """Validate the session mode: ``attach`` or ``spawn``."""
    if not isinstance(mode, str) or mode.strip().lower() not in MODES:
        raise AnalysisError(f"mode must be one of {', '.join(MODES)}, got {mode!r}")
    return mode.strip().lower()


def _check_target(mode: str, target: Any, pid: Any) -> int | str:
    """Validate the ``target``/``pid`` pair into one bridge target."""
    if pid is not None:
        if isinstance(pid, bool) or not isinstance(pid, int):
            raise AnalysisError(f"pid must be an int or None, got {type(pid).__name__}")
        if pid <= 0:
            raise AnalysisError(f"target pid must be positive, got {pid}")
        if isinstance(target, str) and target.strip():
            raise AnalysisError("pass either pid or target, not both")
        if mode == MODE_SPAWN:
            raise AnalysisError(
                "spawn mode needs a program name (target); attach mode accepts "
                "pid or target"
            )
        return pid
    if not isinstance(target, str) or not target.strip():
        raise AnalysisError(
            "target must be a non-empty program name (or pass a pid to attach to)"
        )
    return target.strip()


def _check_inline_script(script: Any) -> str:
    """Validate one inline gadget script, bounded to ``MAX_SCRIPT_BYTES``."""
    if not isinstance(script, str) or not script.strip():
        raise AnalysisError(
            f"script must be a non-empty string, got {type(script).__name__}"
        )
    size = len(script.encode("utf-8"))
    if size > MAX_SCRIPT_BYTES:
        raise AnalysisError(
            f"script is {size} bytes; expected at most {MAX_SCRIPT_BYTES} (64 KiB)"
        )
    return script


def _check_script_file(path: Any) -> str:
    """Validate one script file, bounded to ``MAX_SCRIPT_BYTES``."""
    if not isinstance(path, (str, Path)):
        raise AnalysisError(f"script_path must be a str or Path, got {type(path).__name__}")
    file_path = Path(path)
    if not file_path.is_file():
        raise AnalysisError(f"script file not found: {file_path}")
    size = file_path.stat().st_size
    if size > MAX_SCRIPT_BYTES:
        raise AnalysisError(
            f"script is {size} bytes; expected at most {MAX_SCRIPT_BYTES} "
            f"(64 KiB): {file_path}"
        )
    return str(file_path)


def _write_capture(capture_path: Path, messages: Sequence[Any]) -> None:
    """Persist the raw message capture (already bounded by the bridge)."""
    lines = [json.dumps(message.to_dict(), ensure_ascii=True) for message in messages]
    text = "\n".join(lines) + ("\n" if lines else "")
    capture_path.write_text(text, encoding="utf-8", newline="\n")


def codevanta_frida_start(
    mode: str = MODE_ATTACH,
    target: str = "",
    pid: int | None = None,
    script: str | None = None,
    script_path: str | None = None,
    device_id: str | None = None,
    duration: float = DEFAULT_FRIDA_DURATION,
    *,
    module: Any | None = None,
    runner: Runner | None = None,
    probe: FridaAvailability | None = None,
) -> dict[str, Any]:
    """Start a Frida session on ``pid``/``target`` and register it as ``frida-NNN``.

    The availability probe runs first (``find_spec`` + ``which``, never an
    import) and its absence is one honest typed error. The run itself goes
    through :func:`codevanta.analysis.frida_bridge.start_session`: attach or
    spawn, one optional initial script (inline ``script`` or ``script_path``,
    at most one), then a bounded ``run_for(duration)`` observation slice --
    a spawned target is resumed after the script is loaded. With the frida
    Python module the handle stays live for ``codevanta_frida_load``;
    without it the bridge runs one bounded ``frida -l`` CLI invocation and
    the record is a one-shot. On success the session record (state
    ``completed``) and its bounded payload are returned; on failure nothing
    is registered and every artifact is removed.
    """
    availability = probe if probe is not None else _probe_frida()
    if not availability.available:
        raise AnalysisError(availability.reason)
    checked_duration = _check_duration(duration)
    checked_mode = _check_mode(mode)
    bridge_target = _check_target(checked_mode, target, pid)
    if script is not None and script_path is not None:
        raise AnalysisError("pass either script (inline source) or script_path, not both")
    inline = _check_inline_script(script) if script is not None else None
    on_disk = _check_script_file(script_path) if script_path is not None else None
    session_id = _reserve_slot()
    work_dir = Path(tempfile.mkdtemp(prefix="codevanta-frida-session-"))
    local_script: Path | None = None
    if inline is not None:
        local_script = work_dir / "session-script.js"
        local_script.write_text(inline, encoding="utf-8", newline="\n")
    for_bridge = str(local_script) if local_script is not None else on_disk
    try:
        handle = start_session(
            bridge_target,
            checked_mode,
            device_id=device_id,
            script_path=for_bridge,
            duration=checked_duration,
            module=module,
            runner=runner,
        )
        result = getattr(handle, "result", None)
        timeout_reached = False
        run_warnings: tuple[str, ...] = ()
        if handle.one_shot:
            # The CLI fallback already executed the script to its duration
            # budget inside start_session; there is nothing left to observe.
            timeout_reached = bool(getattr(result, "timeout_reached", False))
            run_warnings = tuple(getattr(result, "warnings", ()))
        else:
            if local_script is not None:
                handle.load_script(local_script)
            if checked_mode == MODE_SPAWN:
                handle.resume()
            handle.run_for(checked_duration)
    except Exception:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise
    messages = handle.messages
    dropped = handle.dropped_messages
    truncated = dropped > 0
    if handle.one_shot and result is not None:
        truncated = truncated or bool(result.truncated)
    capture_path = work_dir / "frida-capture.log"
    _write_capture(capture_path, messages)
    record_pid: int | None = None
    if isinstance(bridge_target, int):
        record_pid = bridge_target
    else:
        # A spawned target reports the pid the bridge picked at spawn time.
        spawned_pid = getattr(handle, "_spawned_pid", None)
        if isinstance(spawned_pid, int):
            record_pid = spawned_pid
    record = FridaSessionRecord(
        session_id=session_id,
        mode=checked_mode,
        target=str(bridge_target),
        pid=record_pid,
        device_id=device_id,
        script_path=str(local_script) if local_script is not None else (on_disk or ""),
        duration=checked_duration,
        state=STATE_COMPLETED,
        one_shot=handle.one_shot,
        work_dir=work_dir,
        capture_path=str(capture_path),
        probe=availability,
        warnings=run_warnings,
        message_count=len(messages),
        dropped_messages=dropped,
        truncated=truncated,
        timeout_reached=timeout_reached,
        resumed=bool(handle.resumed),
        messages=[message.to_dict() for message in messages[:RECENT_MESSAGES]],
        handle=handle,
    )
    with _REGISTRY.lock:
        _REGISTRY.sessions[session_id] = record
    return record.to_dict()


def codevanta_frida_load(
    session_id: str,
    source: str | None = None,
    path: str | None = None,
    duration: float = DEFAULT_FRIDA_DURATION,
) -> dict[str, Any]:
    """Load one more script into a live session and collect a bounded slice.

    Only module-backed sessions accept scripts: a one-shot session (the
    ``frida`` CLI fallback already ran its script to the duration budget and
    reaped the process) refuses with the typed "not supported for this
    session kind" error. An unknown or already-closed session id is a typed
    error naming the id.
    """
    session = _lookup(session_id)
    if session.state == STATE_CLOSED:
        raise AnalysisError(
            f"session {session_id} is already closed; start a new one to load another script"
        )
    if session.one_shot or session.handle is None:
        raise AnalysisError(
            f"loading a script is not supported for this session kind: session "
            f"{session_id} is a one-shot `frida` CLI run whose script already "
            "executed to its duration budget; start a module-backed session "
            "(install the frida Python module) to load more scripts"
        )
    checked_duration = _check_duration(duration)
    if source is not None and path is not None:
        raise AnalysisError("pass either source (inline) or path (file), not both")
    script_file: Path
    if source is not None:
        inline = _check_inline_script(source)
        session.loads += 1
        script_file = session.work_dir / f"load-{session.loads:03d}.js"
        script_file.write_text(inline, encoding="utf-8", newline="\n")
    elif path is not None:
        script_file = Path(_check_script_file(path))
    else:
        raise AnalysisError("load needs a script: pass source (inline) or path (file)")
    try:
        session.handle.load_script(script_file)
        session.handle.run_for(checked_duration)
    except Exception:
        if source is not None and script_file.exists():
            script_file.unlink()
            session.loads -= 1
        raise
    messages = session.handle.messages
    session.message_count = len(messages)
    session.dropped_messages = session.handle.dropped_messages
    session.truncated = session.dropped_messages > 0
    session.messages = [message.to_dict() for message in messages[:RECENT_MESSAGES]]
    return session.to_dict()


def codevanta_frida_status(session_id: str) -> dict[str, Any]:
    """Return the lifecycle state and bounded stored info of one session.

    Read-only: the stored result of the session's bounded observation run,
    never a re-run. An unknown session id raises an error naming the id.
    """
    return _lookup(session_id).to_dict()


def codevanta_frida_close(session_id: str) -> dict[str, Any]:
    """Close a session: detach/unload, remove artifacts, mark ``closed``.

    The bridge handle is closed best-effort (safe for one-shot records), the
    session scripts, the raw capture file and the session directory are
    deleted; the bounded summary stays queryable through
    :func:`codevanta_frida_sessions`. An unknown or already-closed session
    id raises an error naming the id.
    """
    session = _lookup(session_id)
    if session.state == STATE_CLOSED:
        raise AnalysisError(
            f"session {session_id} is already closed and its artifacts are gone"
        )
    close_report: dict[str, Any] | None = None
    if session.handle is not None:
        close_report = session.handle.close()
        session.handle = None
    removed: list[str] = []
    for artifact in (session.script_path, session.capture_path):
        if not artifact:
            continue
        artifact_path = Path(artifact)
        if artifact_path.exists():
            try:
                artifact_path.unlink()
                removed.append(artifact)
            except OSError as exc:
                session.warnings = (*session.warnings, f"could not remove {artifact}: {exc}")
    shutil.rmtree(session.work_dir, ignore_errors=True)
    session.state = STATE_CLOSED
    payload = {
        "session_id": session.session_id,
        "state": session.state,
        "removed": removed,
        "work_dir_removed": not session.work_dir.exists(),
        "message_count": session.message_count,
    }
    if close_report is not None:
        # The verified lifecycle half of close: what happened to the script,
        # the attachment, and a still-paused spawned target -- reported, not
        # swallowed. An attached target is never resumed by close.
        payload["close"] = {
            "unloaded": close_report.get("unloaded"),
            "detached": close_report.get("detached"),
            "resumed_spawn": close_report.get("resumed_spawn"),
            **({"note": close_report["note"]} if close_report.get("note") else {}),
            "warnings": list(close_report.get("warnings", ())),
        }
    return payload


def codevanta_frida_sessions() -> dict[str, Any]:
    """List every registered session with its state, bounded by the registry."""
    with _REGISTRY.lock:
        records = [session.record() for session in _REGISTRY.sessions.values()]
    return {
        "count": len(records),
        "max_sessions": MAX_FRIDA_SESSIONS,
        "sessions": records,
    }


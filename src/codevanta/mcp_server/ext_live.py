"""MCP tools exposing the live instrumentation bridges (no MCP imports).

Three tools: ``codevanta_frida`` (devices | ps | script, skip-gated on the
frida CLI tools and/or the frida Python module), ``codevanta_lldb_run``
(batch ``lldb -b`` run, skip-gated on lldb) and ``codevanta_rizin_functions``
(batch ``rizin -q -c 'aaa; afl'``, skip-gated on rizin). The registration
import lives in :mod:`codevanta.mcp_server.tools`; the ``@server.tool``
wrappers live inside :func:`codevanta.mcp_server.server.build_server` --
imports alone do not register anything. The keyword-only ``runner`` on every
function mirrors the bridges' injection seams for offline hosts and tests.
"""

from __future__ import annotations

from typing import Any

from codevanta.analysis import frida_bridge, lldb_bridge, rizin_bridge
from codevanta.core.report import AnalysisError

#: Actions accepted by :func:`codevanta_frida`.
FRIDA_ACTIONS = ("devices", "ps", "script")


def codevanta_frida(
    action: str,
    device_id: str | None = None,
    pid: int | None = None,
    script_path: str | None = None,
    duration: float = frida_bridge.DEFAULT_DURATION,
    *,
    runner: Any | None = None,
) -> dict[str, Any]:
    """Probe Frida devices/processes or run one bounded script session.

    ``action='devices'`` lists Frida devices; ``action='ps'`` lists processes
    on the local or a named device; ``action='script'`` attaches to ``pid``
    and runs ``script_path`` for ``duration`` seconds (1 .. 60), returning the
    bounded captured-message record. Every variant is skip-gated: without the
    frida CLI tools or the frida module the typed unavailable error fires.
    """
    if not isinstance(action, str) or action.strip().lower() not in FRIDA_ACTIONS:
        raise AnalysisError(f"action must be one of {', '.join(FRIDA_ACTIONS)}, got {action!r}")
    norm = action.strip().lower()
    if norm == "devices":
        return frida_bridge.list_devices(runner=runner).to_dict()
    if norm == "ps":
        return frida_bridge.list_processes(device_id=device_id, runner=runner).to_dict()
    if pid is None:
        raise AnalysisError("codevanta_frida action 'script' requires pid (a positive int)")
    if script_path is None:
        raise AnalysisError("codevanta_frida action 'script' requires script_path")
    session = frida_bridge.start_session(
        pid,
        frida_bridge.MODE_ATTACH,
        script_path=script_path,
        duration=duration,
        runner=runner,
    )
    return session.to_dict()


def codevanta_lldb_run(
    target: str,
    break_at: str | None = None,
    timeout_s: float = lldb_bridge.DEFAULT_TIMEOUT,
    *,
    runner: Any | None = None,
) -> dict[str, Any]:
    """Run one batch ``lldb -b`` session on ``target`` and parse the result.

    Optional ``break_at`` (function name or ``0x`` address), wall-clock budget
    ``timeout_s`` (1 .. 120, default 30). Requires lldb on PATH; its absence is
    a typed error with the install hint.
    """
    return (
        lldb_bridge.run_under_lldb(target, break_at=break_at, timeout_s=timeout_s, runner=runner)
        .to_dict()
    )


def codevanta_rizin_functions(
    path: str,
    *,
    runner: Any | None = None,
) -> dict[str, Any]:
    """List functions with batch ``rizin -q -c 'aaa; afl'`` (bounded 256).

    Requires rizin on PATH; its absence is a typed error with the install
    hint and the offline ``codevanta functions`` fallback pointer.
    """
    return rizin_bridge.functions_of(path, runner=runner).to_dict()

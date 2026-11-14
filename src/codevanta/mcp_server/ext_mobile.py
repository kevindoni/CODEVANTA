"""MCP tool: ``codevanta_adb`` -- Android device queries over adb.

One tool covers the read-only side of the mobile lane: ``action="devices"``
lists attached devices/emulators, and ``action="props"`` / ``"packages"`` /
``"processes"`` inspect the device named by ``device``. The format-2 lane
extends the same tool with the bounded ops half: ``logcat`` (``-d -t``
transcript, capped at 200 rows, optional ``pid``/``count``), ``pull`` /
``push`` (one file, 512 MiB budget, host-side sha256), ``start`` / ``stop``
(the ``am start -W`` / ``am force-stop`` lifecycle) and ``setting`` (one
``settings get`` value). The heavyweight mutating half of the lane
(``install``, ``screencap``, ``bugreport``) is deliberately not exposed over
MCP -- installs change a device and require the CLI's explicit ``--yes``
confirmation.

Like every entry in :mod:`codevanta.mcp_server.tools` this is a plain
``dict``-returning function; it never launches anything (no ``adb
start-server``), and adb's absence surfaces as the typed
:class:`~codevanta.core.report.AnalysisError` from
:func:`codevanta.analysis.adb.list_devices` and friends rather than a
traceback.
"""

from __future__ import annotations

from typing import Any

from codevanta.analysis.adb import (
    inspect_device,
    list_devices,
    list_packages,
    list_processes,
    pull_file,
    push_file,
    read_logcat,
    read_setting,
    start_app,
    stop_app,
)
from codevanta.core.report import AnalysisError

__all__ = ["codevanta_adb"]

#: Actions ``codevanta_adb`` accepts; ``props``/``packages``/``processes`` need ``device``.
ADB_ACTIONS: tuple[str, ...] = (
    "devices",
    "props",
    "packages",
    "processes",
    "logcat",
    "pull",
    "push",
    "start",
    "stop",
    "setting",
)


def codevanta_adb(
    action: str,
    device: str | None = None,
    *,
    pid: int | None = None,
    count: int = 50,
    local_path: str | None = None,
    remote_path: str | None = None,
    package: str | None = None,
    namespace: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    """Query an Android device over adb.

    Args:
        action: One of ``devices``, ``props``, ``packages``, ``processes``,
            ``logcat``, ``pull``, ``push``, ``start``, ``stop``, ``setting``.
        device: Device serial; required for every action except ``devices``.
        pid: For ``logcat``: only rows from this PID.
        count: For ``logcat``: how many recent rows to ask adb for.
        local_path: For ``pull``/``push``: the host-side file path.
        remote_path: For ``pull``/``push``: the device-side file path.
        package: For ``start``/``stop``: the package to launch or kill.
        namespace: For ``setting``: one of ``system``/``secure``/``global``.
        key: For ``setting``: the setting key.

    Returns:
        A JSON-safe payload with ``action``, the parsed rows and the
        ``evidence`` record whose ``source`` is the ``adb.<command>`` id and
        whose ``confidence`` states how directly the transcript supports it.

    Raises:
        AnalysisError: On an unknown action, a missing ``device`` for an
            action that needs one, a missing action-specific argument, or
            when adb is not on ``PATH`` (with the platform-tools install
            hint).
    """
    if action not in ADB_ACTIONS:
        raise AnalysisError(
            f"unknown action {action!r}; expected one of {', '.join(ADB_ACTIONS)}"
        )
    if action == "devices":
        result = list_devices()
        return {
            "action": action,
            **result.to_dict(),
        }
    if not device or not device.strip():
        raise AnalysisError(f"action {action!r} requires a device serial")
    if action == "props":
        return {"action": action, **inspect_device(device).to_dict()}
    if action == "packages":
        return {"action": action, **list_packages(device).to_dict()}
    if action == "processes":
        return {"action": action, **list_processes(device).to_dict()}
    if action == "logcat":
        return {"action": action, **read_logcat(device, pid=pid, count=count).to_dict()}
    if action in ("pull", "push"):
        if not local_path or not local_path.strip():
            raise AnalysisError(f"action {action!r} requires local_path")
        if not remote_path or not remote_path.strip():
            raise AnalysisError(f"action {action!r} requires remote_path")
        transfer = (
            pull_file(device, remote_path, local_path)
            if action == "pull"
            else push_file(device, local_path, remote_path)
        )
        return {"action": action, **transfer.to_dict()}
    if action in ("start", "stop"):
        if not package or not package.strip():
            raise AnalysisError(f"action {action!r} requires package")
        lifecycle = (
            start_app(device, package) if action == "start" else stop_app(device, package)
        )
        return {"action": action, **lifecycle.to_dict()}
    if not namespace or not namespace.strip():
        raise AnalysisError(f"action {action!r} requires namespace")
    if not key or not key.strip():
        raise AnalysisError(f"action {action!r} requires key")
    return {
        "action": action,
        **read_setting(device, namespace, key).to_dict(),
    }

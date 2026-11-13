"""MCP tool: ``codevanta_adb`` -- Android device queries over adb.

One tool covers the read-only side of the mobile lane: ``action="devices"``
lists attached devices/emulators, and ``action="props"`` / ``"packages"`` /
``"processes"`` inspect the device named by ``device``. The mutating half of
the lane (``install``, ``screencap``, ``bugreport``) is deliberately not
exposed over MCP -- installs change a device and require the CLI's explicit
``--yes`` confirmation.

Like every entry in :mod:`codevanta.mcp_server.tools` this is a plain
``dict``-returning function; it never launches anything (no ``adb
start-server``), and adb's absence surfaces as the typed
:class:`~codevanta.core.report.AnalysisError` from
:func:`codevanta.analysis.adb.list_devices` and friends rather than a
traceback.
"""

from __future__ import annotations

from typing import Any

from codevanta.analysis.adb import inspect_device, list_devices, list_packages, list_processes
from codevanta.core.report import AnalysisError

__all__ = ["codevanta_adb"]

#: Actions ``codevanta_adb`` accepts; ``props``/``packages``/``processes`` need ``device``.
ADB_ACTIONS: tuple[str, ...] = ("devices", "props", "packages", "processes")


def codevanta_adb(action: str, device: str | None = None) -> dict[str, Any]:
    """Query an Android device over adb.

    Args:
        action: One of ``devices``, ``props``, ``packages``, ``processes``.
        device: Device serial; required for ``props``, ``packages`` and
            ``processes``, ignored for ``devices``.

    Returns:
        A JSON-safe payload with ``action``, the parsed rows and the
        ``evidence`` record whose ``source`` is the ``adb.<command>`` id and
        whose ``confidence`` states how directly the transcript supports it.

    Raises:
        AnalysisError: On an unknown action, a missing ``device`` for an
            action that needs one, or when adb is not on ``PATH`` (with the
            platform-tools install hint).
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
    return {"action": action, **list_processes(device).to_dict()}

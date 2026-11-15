"""MCP tools for lane-wingui: live Windows GUI observation (no MCP imports).

Three tools: ``codevanta_win_windows`` (bounded top-level window list with
optional pid filter), ``codevanta_win_tree`` (the accessibility-lite child
window hierarchy under one hwnd) and ``codevanta_win_shot`` (one window
captured to a verified PNG artifact). The registration imports live in
:mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrappers live
inside :func:`codevanta.mcp_server.server.build_server` -- imports alone do
not register anything.

Availability is data, not a crash: when no Win32 provider exists (non
Windows platform) every tool returns ``{"available": false, "reason": ...}``
instead of raising. Unknown hwnds and empty captures remain typed
:class:`~codevanta.core.report.AnalysisError`s, which the server wrappers
turn into ``ToolError``.

Scope note for callers: these tools observe *native Win32 controls*
(Button/Edit/Static/ComboBox, ...) best. Applications that draw their own
widgets -- Electron, Qt, WPF, and modern WinUI surfaces -- expose less (or
nothing) through the Win32 window hierarchy; the tree may then show a few
host windows with no meaningful children.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis import win_gui

TOOL_DESCRIPTION_WIN_WINDOWS = (
    "List the top-level windows of the running Windows session, bounded to "
    "256 entries, optionally filtered by owning process id. Each entry "
    "carries hwnd, pid, title (256-char cap), window class name and "
    "visible/enabled flags. Works best on native Win32 applications; "
    "Electron/Qt/WPF apps expose less through the Win32 window hierarchy. "
    "On non-Windows hosts this returns available=false with a reason "
    "instead of failing -- availability is data. Pure stdlib ctypes "
    "(user32); nothing is executed in the observed process."
)

TOOL_DESCRIPTION_WIN_TREE = (
    "Observe the live window hierarchy under one hwnd (the accessibility-"
    "lite widget tree): hwnd, class name (Button/Edit/Static/ComboBox, ...), "
    "title, control id, rect and visible/enabled per node, with children "
    "bounded to 512 per node and depth bounded to 8 levels -- every bound "
    "hit is reported as a flag, never hidden. This reads native Win32 "
    "controls; Electron/Qt/WPF applications draw their own widgets and "
    "expose much less via Win32. On non-Windows hosts this returns "
    "available=false with a reason; an unknown hwnd is a typed "
    "AnalysisError. Pure stdlib ctypes (user32); nothing is executed."
)

TOOL_DESCRIPTION_WIN_SHOT = (
    "Capture one window's current appearance as a PNG artifact written to "
    "<output_directory>/window_<hwnd>x<width>x<height>.png, verified by "
    "round-trip decoding before the file is written; the result carries "
    "path, sha256, dimensions and byte count. Captures work best on native "
    "Win32 controls (Button/Edit/Static/ComboBox, ...); Electron/Qt/WPF "
    "windows still capture pixel-wise but expose fewer widgets to the tree "
    "tools. On non-Windows hosts this returns available=false with a "
    "reason; an unknown hwnd is a typed AnalysisError. Pure stdlib ctypes "
    "(user32/gdi32), deterministic PNG encoder; nothing is executed."
)


def _unavailable() -> dict[str, Any]:
    """Honest availability result when the platform has no Win32 provider."""
    return {"available": False, "reason": win_gui.UNAVAILABLE_REASON}


def codevanta_win_windows(pid: int | None = None) -> dict[str, Any]:
    """List bounded top-level windows, optionally filtered by pid."""
    provider = win_gui.get_provider()
    if provider is None:
        return _unavailable()
    return win_gui.list_windows(provider, pid=pid).to_dict()


def codevanta_win_tree(hwnd: int) -> dict[str, Any]:
    """Observe the bounded window hierarchy under one hwnd."""
    provider = win_gui.get_provider()
    if provider is None:
        return _unavailable()
    return win_gui.observe_tree(provider, hwnd)


def codevanta_win_shot(hwnd: int, output_directory: str) -> dict[str, Any]:
    """Capture one window as a verified PNG artifact on disk."""
    provider = win_gui.get_provider()
    if provider is None:
        return _unavailable()
    return win_gui.capture_window(provider, hwnd, Path(output_directory))

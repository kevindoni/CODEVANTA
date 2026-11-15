"""MCP tools for lane-wininput: real GUI input + visual regression loop.

Four tools: ``codevanta_win_click`` (one click at window-relative
coordinates), ``codevanta_win_type`` (foreground + unicode typing),
``codevanta_win_key`` (foreground + named key press) and
``codevanta_win_visual_regression`` (the loop: drive scripted steps,
capture the window, pixel-diff it against a reference PNG). The
registration imports live in :mod:`codevanta.mcp_server.tools`; the
``@server.tool`` wrappers live inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.

Safety statement, honest up front: these tools send REAL input to the
target window -- the mouse moves, keys are injected through Win32
``SendInput`` and the target application receives them exactly as if a
user had acted. Nothing is simulated. On non-Windows hosts every tool
returns ``{"available": false, "reason": ...}`` instead of raising --
availability is data. Unknown hwnds, unsupported key names and missing
reference files remain typed :class:`~codevanta.core.report.AnalysisError`s,
which the server wrappers turn into ``ToolError``.
"""

from __future__ import annotations

from typing import Any

from codevanta.analysis import win_gui, win_input

TOOL_DESCRIPTION_WIN_CLICK = (
    "Send ONE REAL mouse click to a live Windows window: the click "
    "coordinates are window-relative (x, y added to the window's top-left "
    "on screen) and are injected as MOUSEEVENTF_LEFTDOWN/LEFTUP through "
    "user32 SendInput after moving the cursor -- this is real input the "
    "target application receives, not a simulation. The window is brought "
    "to the foreground best-effort first (OS focus rules may refuse; that "
    "is reported as a warning, never a crash). On non-Windows hosts this "
    "returns available=false with a reason; an unknown hwnd is a typed "
    "AnalysisError. Pure stdlib ctypes (user32)."
)

TOOL_DESCRIPTION_WIN_TYPE = (
    "Bring a live Windows window to the foreground (best-effort, per OS "
    "focus rules; refusal becomes a warning) and type real text into it: "
    "every character is injected as a KEYEVENTF_UNICODE down/up pair "
    "through user32 SendInput -- astral characters travel as their UTF-16 "
    "surrogate pair. This is REAL input the target application receives, "
    "not a simulation; text is capped at 256 characters per call. On "
    "non-Windows hosts this returns available=false with a reason; an "
    "unknown hwnd is a typed AnalysisError. Pure stdlib ctypes (user32)."
)

TOOL_DESCRIPTION_WIN_KEY = (
    "Bring a live Windows window to the foreground (best-effort) and "
    "press one named key by injecting its virtual-key code down/up through "
    "user32 SendInput -- REAL input the target application receives, not a "
    "simulation. Supported key names: enter, tab, esc, space, backspace, "
    "delete, insert, home, end, pageup, pagedown, left, up, right, down "
    "and f1..f12; an unknown name is a typed AnalysisError listing them. "
    "On non-Windows hosts this returns available=false with a reason; an "
    "unknown hwnd is a typed AnalysisError. Pure stdlib ctypes (user32)."
)

TOOL_DESCRIPTION_WIN_VISUAL_REGRESSION = (
    "The automated visual regression loop for UI verification: drive a "
    "live Windows window through a validated step script (click at "
    "window-relative coordinates, type text, press named keys, bounded "
    "waits -- all REAL input injected through user32 SendInput, not a "
    "simulation), settle for repaint, capture the window as a verified "
    "PNG artifact written into output_directory, and pixel-diff it against "
    "reference_png (identical/minor/major verdict plus changed_ratio). "
    "Missing reference file is a typed error raised before any input is "
    "sent; the step script is validated whole before the first event, so "
    "a refused script never touches the target. Steps cap: 64, text cap: "
    "256 chars, wait cap: 5000 ms. On non-Windows hosts this returns "
    "available=false with a reason. Pure stdlib ctypes (user32/gdi32) "
    "plus a deterministic PNG encoder and pixel differ."
)


def _unavailable() -> dict[str, Any]:
    """Honest availability result when the platform has no input provider."""
    return {"available": False, "reason": win_input.UNAVAILABLE_REASON}


def codevanta_win_click(hwnd: int, x: int, y: int) -> dict[str, Any]:
    """One real click at window-relative (x, y) inside ``hwnd``."""
    input_provider = win_input.get_input_provider()
    gui_provider = win_gui.get_provider()
    if input_provider is None or gui_provider is None:
        return _unavailable()
    return win_input.drive_window(
        gui_provider,
        input_provider,
        hwnd,
        [{"action": "click", "x": x, "y": y}],
        settle_ms=0,
    ).to_dict()


def codevanta_win_type(hwnd: int, text: str) -> dict[str, Any]:
    """Foreground ``hwnd`` and type real unicode text into it."""
    input_provider = win_input.get_input_provider()
    gui_provider = win_gui.get_provider()
    if input_provider is None or gui_provider is None:
        return _unavailable()
    return win_input.drive_window(
        gui_provider,
        input_provider,
        hwnd,
        [{"action": "type", "text": text}],
        settle_ms=0,
    ).to_dict()


def codevanta_win_key(hwnd: int, key: str) -> dict[str, Any]:
    """Foreground ``hwnd`` and press one named key (VK code) for real."""
    input_provider = win_input.get_input_provider()
    gui_provider = win_gui.get_provider()
    if input_provider is None or gui_provider is None:
        return _unavailable()
    return win_input.drive_window(
        gui_provider,
        input_provider,
        hwnd,
        [{"action": "key", "key": key}],
        settle_ms=0,
    ).to_dict()


def codevanta_win_visual_regression(
    hwnd: int,
    steps: list[dict[str, Any]],
    reference_png: str,
    output_directory: str,
    settle_ms: int = 250,
) -> dict[str, Any]:
    """Drive ``steps``, capture ``hwnd``, pixel-diff against the reference."""
    input_provider = win_input.get_input_provider()
    gui_provider = win_gui.get_provider()
    if input_provider is None or gui_provider is None:
        return _unavailable()
    return win_input.visual_regression(
        gui_provider,
        input_provider,
        hwnd,
        steps,
        reference_png,
        output_directory,
        settle_ms=settle_ms,
    )


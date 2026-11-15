"""Real Windows GUI input (lane-wininput): drive a window, then verify it.

CODEVANTA's static lanes decode *files*; this lane *drives* a live Windows
window -- clicks, typed text and named key presses injected through the
Win32 ``SendInput`` surface -- and composes with
:mod:`codevanta.analysis.win_gui` (capture) and
:mod:`codevanta.analysis.png_diff` (pixel diff) into the automated visual
regression loop: run scripted UI steps, capture the window, compare it
against a reference PNG.

Everything input-related flows through an injectable provider seam
(:class:`WinInputProvider`), so tests record every injected event with a
fake and CI on Linux never touches a cursor:

* :func:`get_input_provider` returns the real ctypes provider on ``win32``
  and an honest ``None`` elsewhere -- availability is data, never a crash.
* :func:`drive_window` validates the *whole* step script up front (bounds
  included), then dispatches it: window-relative clicks resolved through
  the GUI provider's ``window_rect``, unicode typing, named keys and
  bounded waits. Nothing is sent when validation refuses.
* :func:`visual_regression` is the loop: drive -> settle -> capture ->
  pixel-diff against a reference PNG, with the verdict returned as data.

Bounds
------

A drive stops at :data:`MAX_STEPS` steps, types at most
:data:`MAX_TEXT_CHARS` characters per ``type`` step and waits at most
:data:`MAX_WAIT_MS` per ``wait`` step (and for the final settle). Every
bound that fires is a typed :class:`~codevanta.core.report.AnalysisError`
raised *before any input is sent*, never a half-executed script.

Evidence discipline
--------------------

Every drive result carries an
:class:`~codevanta.evidence.models.Evidence` record with source
``"win.input"`` and method ``"sendinput-drive"``: the input really went to
the target window. Foreground failures (the OS refuses focus transfers per
its focus rules) are recorded as warnings, never crashes.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from codevanta.analysis import win_gui
from codevanta.analysis.png_diff import pixel_diff
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "MAX_STEPS",
    "MAX_TEXT_CHARS",
    "MAX_WAIT_MS",
    "UNAVAILABLE_REASON",
    "VK_CODES",
    "DriveResult",
    "WinInputProvider",
    "drive_window",
    "get_input_provider",
    "visual_regression",
]

#: Hard ceiling on steps per drive; a longer script is refused whole.
MAX_STEPS = 64

#: Maximum characters typed per ``type`` step.
MAX_TEXT_CHARS = 256

#: Maximum single ``wait`` step (and final settle), in milliseconds.
MAX_WAIT_MS = 5000

#: Evidence source shared by every record this module emits.
_EVIDENCE_SOURCE = "win.input"

#: Honest availability reason reused by every API when no provider exists.
UNAVAILABLE_REASON = (
    "Windows GUI input requires native Win32 (ctypes user32 SendInput); "
    "this platform does not provide it, so no real input can be sent."
)

#: Named keys -> virtual-key codes (Win32 VK_*). Unknown names are a typed
#: error that lists exactly these supported names.
VK_CODES: dict[str, int] = {
    "enter": 0x0D,
    "tab": 0x09,
    "esc": 0x1B,
    "space": 0x20,
    "backspace": 0x08,
    "delete": 0x2E,
    "insert": 0x2D,
    "home": 0x24,
    "end": 0x23,
    "pageup": 0x21,
    "pagedown": 0x22,
    "left": 0x25,
    "up": 0x26,
    "right": 0x27,
    "down": 0x28,
    **{f"f{n}": 0x70 + n - 1 for n in range(1, 13)},
}

#: The four actions a step script may contain.
_ACTIONS = ("click", "type", "key", "wait")


class WinInputProvider(Protocol):
    """The testing contract every input API reads through.

    Implementations inject real OS input. The real provider
    (:class:`CtypesWinInputProvider`) answers via user32 ``SendInput``;
    tests answer with a recording fake, so nothing in this module or its
    tests depends on an actual desktop or moves a real cursor.
    """

    def set_cursor(self, x: int, y: int) -> None:
        """Move the cursor to absolute screen coordinates or raise."""
        ...

    def click_left(self, x: int, y: int) -> None:
        """Left-click (down then up) at absolute screen coordinates."""
        ...

    def type_unicode(self, text: str) -> None:
        """Type ``text`` as per-character KEYEVENTF_UNICODE events."""
        ...

    def press_key(self, vk: int) -> None:
        """Press and release the virtual-key code ``vk``."""
        ...

    def set_foreground(self, hwnd: int) -> bool:
        """Best-effort focus transfer; ``False`` when the OS refuses."""
        ...


@dataclass(frozen=True)
class DriveResult:
    """Outcome of :func:`drive_window`; frozen and JSON-safe.

    ``steps`` holds one bounded entry per executed step (``index``,
    ``action``, ``ok``, ``detail``). ``ok`` is the overall flag: every
    step succeeded. ``warnings`` carries the foreground-failure note and
    any per-step provider failures. ``available`` is ``False`` (with
    ``reason`` set) when no provider exists -- honest data, not a crash.
    """

    available: bool
    hwnd: int = 0
    ok: bool = False
    steps: tuple[dict[str, Any], ...] = ()
    settle_ms: int = 0
    warnings: tuple[str, ...] = ()
    reason: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection with the per-step rows."""
        return {
            "available": self.available,
            "hwnd": self.hwnd,
            "ok": self.ok,
            "step_count": len(self.steps),
            "steps": [dict(step) for step in self.steps],
            "settle_ms": self.settle_ms,
            "warnings": list(self.warnings),
            "reason": self.reason,
            "evidence": dict(self.evidence),
        }


def _is_int(value: Any) -> bool:
    """Strict ``int`` check: ``bool`` is rejected (it subclasses ``int``)."""
    return isinstance(value, int) and not isinstance(value, bool)




def _validate_steps(steps: Any) -> list[dict[str, Any]]:
    """Validate the whole script up-front; return it unchanged on success.

    Every refusal here is a typed :class:`AnalysisError` raised before a
    single input event reaches the provider.
    """
    if not isinstance(steps, list):
        raise AnalysisError(
            f"win_input: steps must be a list of step dicts, got {type(steps).__name__}"
        )
    if len(steps) > MAX_STEPS:
        raise AnalysisError(
            f"win_input: {len(steps)} steps exceed the {MAX_STEPS}-step bound"
        )
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise AnalysisError(
                f"win_input: step {index} must be a dict, got {type(step).__name__}"
            )
        action = step.get("action")
        if action not in _ACTIONS:
            raise AnalysisError(
                f"win_input: step {index} has unknown action {action!r}; "
                f"supported actions: {', '.join(_ACTIONS)}"
            )
        if action == "click":
            for axis in ("x", "y"):
                if not _is_int(step.get(axis)):
                    raise AnalysisError(
                        f"win_input: step {index} click needs integer {axis!r} "
                        f"(window-relative), got {step.get(axis)!r}"
                    )
        elif action == "type":
            text = step.get("text")
            if not isinstance(text, str):
                raise AnalysisError(
                    f"win_input: step {index} type needs a string 'text', "
                    f"got {type(text).__name__}"
                )
            if len(text) > MAX_TEXT_CHARS:
                raise AnalysisError(
                    f"win_input: step {index} text of {len(text)} characters "
                    f"exceeds the {MAX_TEXT_CHARS}-character bound"
                )
        elif action == "key":
            key = step.get("key")
            if not isinstance(key, str):
                raise AnalysisError(
                    f"win_input: step {index} key needs a string key name, "
                    f"got {type(key).__name__}"
                )
            if key.strip().lower() not in VK_CODES:
                raise AnalysisError(
                    f"win_input: step {index} key {key!r} is not supported; "
                    f"supported keys: {', '.join(sorted(VK_CODES))}"
                )
        else:  # wait
            ms = step.get("ms")
            if not isinstance(ms, int) or isinstance(ms, bool):
                raise AnalysisError(
                    f"win_input: step {index} wait needs integer 'ms', got {ms!r}"
                )
            if not 0 <= ms <= MAX_WAIT_MS:
                raise AnalysisError(
                    f"win_input: step {index} wait of {ms} ms exceeds the "
                    f"{MAX_WAIT_MS}-ms bound"
                )
    return steps


def _validate_settle(settle_ms: Any) -> int:
    """Bound the final settle the same way as a ``wait`` step."""
    if not _is_int(settle_ms):
        raise AnalysisError(f"win_input: settle_ms must be an integer, got {settle_ms!r}")
    if not 0 <= settle_ms <= MAX_WAIT_MS:
        raise AnalysisError(
            f"win_input: settle_ms of {settle_ms} exceeds the {MAX_WAIT_MS}-ms bound"
        )
    return settle_ms


def drive_window(
    gui_provider: win_gui.Win32Provider | None,
    input_provider: WinInputProvider | None,
    hwnd: int,
    steps: list[dict[str, Any]],
    settle_ms: int = 250,
) -> DriveResult:
    """Drive ``hwnd`` with a validated step script via real injected input.

    Steps are ``{"action": "click", "x": rel_x, "y": rel_y}`` (window-
    relative coordinates resolved through ``gui_provider.window_rect``),
    ``{"action": "type", "text": ...}``, ``{"action": "key", "key": ...}``
    (a :data:`VK_CODES` name) and ``{"action": "wait", "ms": ...}``. The
    whole script is validated before any input is sent, so a refused
    script leaves the target untouched. Focus is requested best-effort
    first; an OS focus-rules refusal becomes a warning, never a crash.
    After the last step the driver settles for ``settle_ms`` so the UI can
    repaint before a caller captures it.

    An unknown hwnd (the GUI provider raises) is a typed
    :class:`AnalysisError` naming it; a missing provider yields the honest
    unavailable :class:`DriveResult` instead.
    """
    if input_provider is None:
        return DriveResult(
            available=False, hwnd=hwnd if _is_int(hwnd) else 0, reason=UNAVAILABLE_REASON
        )
    if gui_provider is None:
        return DriveResult(
            available=False,
            hwnd=hwnd if _is_int(hwnd) else 0,
            reason=win_gui.UNAVAILABLE_REASON,
        )
    if not _is_int(hwnd):
        raise AnalysisError(f"win_input: hwnd must be an integer, got {hwnd!r}")
    validated = _validate_steps(steps)
    settle = _validate_settle(settle_ms)
    try:
        left, top, _right, _bottom = gui_provider.window_rect(hwnd)
    except (KeyError, OSError, AnalysisError) as exc:
        raise AnalysisError(f"win_input: unknown hwnd {hwnd}: {exc!r}") from exc

    warnings: list[str] = []
    if not input_provider.set_foreground(hwnd):
        warnings.append(
            f"could not set hwnd {hwnd} to the foreground (OS focus rules); "
            "input goes to whatever currently has focus"
        )

    executed: list[dict[str, Any]] = []
    ok = True
    for index, step in enumerate(validated):
        action = step["action"]
        step_ok = True
        try:
            if action == "click":
                abs_x, abs_y = left + step["x"], top + step["y"]
                input_provider.click_left(abs_x, abs_y)
                detail = (
                    f"clicked window-relative ({step['x']}, {step['y']}) "
                    f"at absolute ({abs_x}, {abs_y})"
                )
            elif action == "type":
                text = step["text"]
                input_provider.type_unicode(text)
                detail = f"typed {len(text)} character(s)"
            elif action == "key":
                key = step["key"]
                vk = VK_CODES[key.strip().lower()]
                input_provider.press_key(vk)
                detail = f"pressed {key.strip().lower()} (VK 0x{vk:02X})"
            else:  # wait
                time.sleep(step["ms"] / 1000.0)
                detail = f"waited {step['ms']} ms"
        except (OSError, AnalysisError) as exc:
            step_ok = False
            ok = False
            detail = f"step failed: {exc!r}"
            warnings.append(f"step {index} ({action}) failed: {exc!r}")
        executed.append(
            {"index": index, "action": action, "ok": step_ok, "detail": detail}
        )
    if settle:
        time.sleep(settle / 1000.0)
    evidence = Evidence(
        source=_EVIDENCE_SOURCE,
        method="sendinput-drive",
        confidence=Confidence.HIGH,
        detail=(
            f"{len(executed)} step(s) driven against hwnd {hwnd} "
            f"(settle {settle} ms); real input injected via user32 SendInput"
        ),
    ).to_dict()
    return DriveResult(
        available=True,
        hwnd=hwnd,
        ok=ok,
        steps=tuple(executed),
        settle_ms=settle,
        warnings=tuple(warnings),
        evidence=evidence,
    )



def visual_regression(
    gui_provider: win_gui.Win32Provider | None,
    input_provider: WinInputProvider | None,
    hwnd: int,
    steps: list[dict[str, Any]],
    reference_png: str | Path,
    output_directory: str | Path,
    settle_ms: int = 250,
) -> dict[str, Any]:
    """The automated visual regression loop: drive, capture, pixel-diff.

    Drives ``hwnd`` through :func:`drive_window`, captures the settled
    window through :func:`codevanta.analysis.win_gui.capture_window` and
    compares the capture against ``reference_png`` with
    :func:`codevanta.analysis.png_diff.pixel_diff`. The capture is written
    into ``output_directory`` as a verified artifact. The result carries
    the drive result, the screenshot path and the pixel-diff verdict
    (``identical``/``minor``/``major`` with ``changed_ratio``).

    A missing reference file is a typed ``file not found`` error raised
    *before* any input is sent; a missing provider yields the honest
    unavailable dict.
    """
    if input_provider is None:
        return {"available": False, "reason": UNAVAILABLE_REASON}
    if gui_provider is None:
        return {"available": False, "reason": win_gui.UNAVAILABLE_REASON}
    reference = Path(reference_png)
    if not reference.is_file():
        raise AnalysisError(f"win_input: reference file not found: {reference}")
    drive = drive_window(gui_provider, input_provider, hwnd, steps, settle_ms=settle_ms)
    if not drive.available:  # defence in depth; unreachable after the checks above
        return {"available": False, "reason": drive.reason}
    capture = win_gui.capture_window(gui_provider, hwnd, Path(output_directory))
    diff = pixel_diff(capture["path"], reference)
    drive_dict = drive.to_dict()
    evidence = Evidence(
        source=_EVIDENCE_SOURCE,
        method="sendinput-visual-regression",
        confidence=Confidence.HIGH,
        detail=(
            f"drove hwnd {hwnd} through {drive_dict['step_count']} step(s), "
            f"captured {diff.left_width}x{diff.left_height} and pixel-diffed "
            f"against {reference.name}: {diff.verdict} ({diff.changed_ratio})"
        ),
    ).to_dict()
    return {
        "available": True,
        "hwnd": hwnd,
        "ok": drive.ok,
        "drive": drive_dict,
        "screenshot_path": capture["path"],
        "screenshot": capture,
        "diff": diff.to_dict(),
        "evidence": evidence,
    }



def get_input_provider() -> WinInputProvider | None:
    """Build the real ctypes input provider on Windows; ``None`` elsewhere.

    Availability is honest data: callers must handle ``None`` (every API
    in this module does, without raising). The class is only defined when
    ``sys.platform == "win32"``, so importing this module on Linux never
    touches ``ctypes.windll`` or ``wintypes``.
    """
    if sys.platform != "win32" or _INPUT_PROVIDER_CLS is None:
        return None
    return _INPUT_PROVIDER_CLS()


def _utf16_units(text: str) -> list[int]:
    """UTF-16 code units of ``text`` -- what KEYEVENTF_UNICODE consumes.

    BMP characters map one-to-one; astral characters (e.g. emoji) are
    sent as their surrogate pair, exactly how Windows expects them.
    """
    units: list[int] = []
    for char in text:
        code = ord(char)
        if code < 0x10000:
            units.append(code)
        else:
            offset = code - 0x10000
            units.append(0xD800 | (offset >> 10))
            units.append(0xDC00 | (offset & 0x3FF))
    return units


if sys.platform == "win32":  # pragma: win32-cover -- real provider, live only

    class CtypesWinInputProvider:
        """Real :class:`WinInputProvider` over user32 SendInput via ctypes.

        Every event is injected with ``SendInput`` (never the deprecated
        ``mouse_event``/``keybd_event``), so the target receives input
        indistinguishable from a user's. ``SendInput`` returning fewer
        accepted events than sent means the system blocked the injection
        (UIPI or focus policy) -- a typed error, never a silent no-op.
        """

        _INPUT_MOUSE = 0
        _INPUT_KEYBOARD = 1
        _MOUSEEVENTF_LEFTDOWN = 0x0002
        _MOUSEEVENTF_LEFTUP = 0x0004
        _KEYEVENTF_KEYUP = 0x0002
        _KEYEVENTF_UNICODE = 0x0004

        def __init__(self) -> None:
            import ctypes
            from ctypes import wintypes

            self._ct = ctypes
            self._wt = wintypes
            self._user32 = ctypes.windll.user32

            class MOUSEINPUT(ctypes.Structure):
                _fields_ = [
                    ("dx", wintypes.LONG),
                    ("dy", wintypes.LONG),
                    ("mouseData", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD),
                    ("time", wintypes.DWORD),
                    ("dwExtraInfo", ctypes.c_size_t),
                ]

            class KEYBDINPUT(ctypes.Structure):
                _fields_ = [
                    ("wVk", wintypes.WORD),
                    ("wScan", wintypes.WORD),
                    ("dwFlags", wintypes.DWORD),
                    ("time", wintypes.DWORD),
                    ("dwExtraInfo", ctypes.c_size_t),
                ]

            class INPUTUNION(ctypes.Union):
                _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT)]

            class INPUT(ctypes.Structure):
                _anonymous_ = ("union",)
                _fields_ = [("type", wintypes.DWORD), ("union", INPUTUNION)]

            self._mouseinput_cls = MOUSEINPUT
            self._keybdinput_cls = KEYBDINPUT
            self._input_cls = INPUT
            self._input_size = ctypes.sizeof(INPUT)
            self._bind_signatures()

        def _bind_signatures(self) -> None:
            """Pin exact signatures; defaults would truncate 64-bit handles."""
            ct, wt = self._ct, self._wt
            self._user32.SetCursorPos.argtypes = [ct.c_int, ct.c_int]
            self._user32.SetCursorPos.restype = wt.BOOL
            self._user32.SendInput.argtypes = [
                wt.UINT, ct.POINTER(self._input_cls), ct.c_int,
            ]
            self._user32.SendInput.restype = wt.UINT
            self._user32.SetForegroundWindow.argtypes = [wt.HWND]
            self._user32.SetForegroundWindow.restype = wt.BOOL

        def _send(self, events: list[Any], what: str) -> None:
            """Send a batch; fewer accepted events than sent is a typed error."""
            array = (self._input_cls * len(events))(*events)
            sent = self._user32.SendInput(len(events), array, self._input_size)
            if sent != len(events):
                raise AnalysisError(
                    f"win_input: SendInput blocked ({sent} of {len(events)} "
                    f"events) while {what} (UIPI or focus policy)"
                )

        def set_cursor(self, x: int, y: int) -> None:
            if not self._user32.SetCursorPos(int(x), int(y)):
                raise AnalysisError(f"win_input: SetCursorPos failed at ({x}, {y})")

        def click_left(self, x: int, y: int) -> None:
            self.set_cursor(x, y)
            down = self._input_cls(type=self._INPUT_MOUSE)
            down.mi = self._mouseinput_cls(dwFlags=self._MOUSEEVENTF_LEFTDOWN)
            up = self._input_cls(type=self._INPUT_MOUSE)
            up.mi = self._mouseinput_cls(dwFlags=self._MOUSEEVENTF_LEFTUP)
            self._send([down, up], f"left click at ({x}, {y})")

        def type_unicode(self, text: str) -> None:
            for unit in _utf16_units(text):
                down = self._input_cls(type=self._INPUT_KEYBOARD)
                down.ki = self._keybdinput_cls(wScan=unit, dwFlags=self._KEYEVENTF_UNICODE)
                up = self._input_cls(type=self._INPUT_KEYBOARD)
                up.ki = self._keybdinput_cls(
                    wScan=unit, dwFlags=self._KEYEVENTF_UNICODE | self._KEYEVENTF_KEYUP
                )
                self._send([down, up], f"typing U+{unit:04X}")

        def press_key(self, vk: int) -> None:
            code = int(vk) & 0xFFFF
            down = self._input_cls(type=self._INPUT_KEYBOARD)
            down.ki = self._keybdinput_cls(wVk=code)
            up = self._input_cls(type=self._INPUT_KEYBOARD)
            up.ki = self._keybdinput_cls(wVk=code, dwFlags=self._KEYEVENTF_KEYUP)
            self._send([down, up], f"pressing VK 0x{code:02X}")

        def set_foreground(self, hwnd: int) -> bool:
            """Best-effort per OS focus rules; ``False`` when refused."""
            return bool(self._user32.SetForegroundWindow(int(hwnd)))

    _INPUT_PROVIDER_CLS: type[CtypesWinInputProvider] | None = CtypesWinInputProvider

else:
    _INPUT_PROVIDER_CLS = None



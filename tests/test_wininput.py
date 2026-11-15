"""Windows GUI input tests (lane-wininput).

Every fixture is a fake :class:`~codevanta.analysis.win_input.WinInputProvider`
that *records* every injected event -- no real SendInput/SetCursorPos call
happens, so the suite runs unchanged on Linux CI and never moves a cursor.
The fake GUI provider answers ``window_rect`` from a fixed table and
``capture_window_png`` from the win_gui encoder over synthetic pixels
(same pattern as tests/test_wingui.py), so the visual regression loop is
exercised end to end without a desktop.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codevanta.analysis import win_gui, win_input
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools

CAPTURE_WIDTH = 12
CAPTURE_HEIGHT = 8

#: Fixed fake window: a 256x256 window whose top-left sits at (100, 200).
FAKE_RECT = (100, 200, 356, 456)


def gradient_pixels(width: int, height: int) -> list[list[tuple[int, int, int, int]]]:
    """Deterministic synthetic RGBA rows (same discipline as test_wingui)."""
    return [
        [
            (
                (x * 13 + y * 7) % 256,
                (x * 5 + y * 29) % 256,
                (x * 3 + y * 11) % 256,
                255,
            )
            for x in range(width)
        ]
        for y in range(height)
    ]


def shifted_pixels(width: int, height: int) -> list[list[tuple[int, int, int, int]]]:
    """A *different* deterministic frame: every channel of every pixel moves."""
    return [
        [
            (
                (x * 13 + y * 7 + 100) % 256,
                (x * 5 + y * 29 + 90) % 256,
                (x * 3 + y * 11 + 80) % 256,
                255,
            )
            for x in range(width)
        ]
        for y in range(height)
    ]


class FakeInputProvider:
    """Recording WinInputProvider: records events, never touches the OS."""

    def __init__(self, *, foreground_succeeds: bool = True) -> None:
        self.calls: list[tuple] = []
        self.foreground_succeeds = foreground_succeeds

    def set_cursor(self, x: int, y: int) -> None:
        self.calls.append(("set_cursor", x, y))

    def click_left(self, x: int, y: int) -> None:
        self.calls.append(("click_left", x, y))

    def type_unicode(self, text: str) -> None:
        for char in text:  # mirror the real provider's per-char injection
            self.calls.append(("unicode", char))

    def press_key(self, vk: int) -> None:
        self.calls.append(("vk", vk))

    def set_foreground(self, hwnd: int) -> bool:
        self.calls.append(("foreground", hwnd))
        return self.foreground_succeeds


class FakeGuiProvider:
    """Fixed-rect Win32Provider whose captures are synthetic-pixel PNGs."""

    def window_rect(self, hwnd: int) -> tuple[int, int, int, int]:
        if hwnd != 101:
            raise KeyError(f"no such window {hwnd}")
        return FAKE_RECT

    def capture_window_png(self, hwnd: int) -> bytes:
        if hwnd != 101:
            raise KeyError(f"no such window {hwnd}")
        return win_gui.encode_png(CAPTURE_WIDTH, CAPTURE_HEIGHT, gradient_pixels(
            CAPTURE_WIDTH, CAPTURE_HEIGHT
        ))


@pytest.fixture()
def input_provider() -> FakeInputProvider:
    return FakeInputProvider()


@pytest.fixture()
def gui_provider() -> FakeGuiProvider:
    return FakeGuiProvider()


# ---- coordinate resolution + provider calls ----------------------------------------


def test_click_resolves_window_relative_to_absolute(
    gui_provider: FakeGuiProvider, input_provider: FakeInputProvider
) -> None:
    result = win_input.drive_window(
        gui_provider,
        input_provider,
        101,
        [{"action": "click", "x": 10, "y": 20}],
        settle_ms=0,
    )
    assert result.available is True
    assert result.ok is True
    assert input_provider.calls == [
        ("foreground", 101),
        ("click_left", 110, 220),  # FAKE_RECT top-left (100, 200) + (10, 20)
    ]
    assert result.steps == (
        {
            "index": 0,
            "action": "click",
            "ok": True,
            "detail": "clicked window-relative (10, 20) at absolute (110, 220)",
        },
    )


def test_type_records_per_character_sequence(
    gui_provider: FakeGuiProvider, input_provider: FakeInputProvider
) -> None:
    win_input.drive_window(
        gui_provider,
        input_provider,
        101,
        [{"action": "type", "text": "hi!"}],
        settle_ms=0,
    )
    assert input_provider.calls == [
        ("foreground", 101),
        ("unicode", "h"),
        ("unicode", "i"),
        ("unicode", "!"),
    ]


def test_press_key_maps_names_to_vk_codes(
    gui_provider: FakeGuiProvider, input_provider: FakeInputProvider
) -> None:
    result = win_input.drive_window(
        gui_provider,
        input_provider,
        101,
        [{"action": "key", "key": "enter"}],
        settle_ms=0,
    )
    assert input_provider.calls == [("foreground", 101), ("vk", 0x0D)]
    assert result.steps[0]["detail"] == "pressed enter (VK 0x0D)"
    assert win_input.VK_CODES["enter"] == 0x0D
    assert win_input.VK_CODES["tab"] == 0x09
    assert win_input.VK_CODES["esc"] == 0x1B
    assert win_input.VK_CODES["f1"] == 0x70
    assert win_input.VK_CODES["f12"] == 0x7B


def test_unknown_key_is_typed_error_before_any_input(
    gui_provider: FakeGuiProvider, input_provider: FakeInputProvider
) -> None:
    with pytest.raises(AnalysisError, match="not supported"):
        win_input.drive_window(
            gui_provider,
            input_provider,
            101,
            [{"action": "key", "key": "meta"}],
            settle_ms=0,
        )
    assert input_provider.calls == []  # refused whole, nothing sent


# ---- drive_window happy path + bounds ----------------------------------------------


def test_drive_window_happy_path_three_mixed_steps(
    gui_provider: FakeGuiProvider, input_provider: FakeInputProvider
) -> None:
    result = win_input.drive_window(
        gui_provider,
        input_provider,
        101,
        [
            {"action": "click", "x": 3, "y": 4},
            {"action": "type", "text": "ab"},
            {"action": "key", "key": "tab"},
        ],
        settle_ms=0,
    )
    assert result.available is True
    assert result.ok is True
    assert [step["index"] for step in result.steps] == [0, 1, 2]
    assert [step["action"] for step in result.steps] == ["click", "type", "key"]
    assert all(step["ok"] for step in result.steps)
    assert input_provider.calls == [
        ("foreground", 101),
        ("click_left", 103, 204),
        ("unicode", "a"),
        ("unicode", "b"),
        ("vk", 0x09),
    ]
    assert result.evidence["source"] == "win.input"
    assert result.evidence["method"] == "sendinput-drive"


def test_step_cap_is_rejected_before_any_input(
    gui_provider: FakeGuiProvider, input_provider: FakeInputProvider
) -> None:
    steps = [{"action": "wait", "ms": 0} for _ in range(win_input.MAX_STEPS + 1)]
    with pytest.raises(AnalysisError, match="64-step bound"):
        win_input.drive_window(gui_provider, input_provider, 101, steps, settle_ms=0)
    assert input_provider.calls == []


def test_wait_is_bounded_and_executed(
    gui_provider: FakeGuiProvider, input_provider: FakeInputProvider
) -> None:
    with pytest.raises(AnalysisError, match="5000-ms bound"):
        win_input.drive_window(
            gui_provider,
            input_provider,
            101,
            [{"action": "wait", "ms": win_input.MAX_WAIT_MS + 1}],
            settle_ms=0,
        )
    assert input_provider.calls == []
    result = win_input.drive_window(
        gui_provider,
        input_provider,
        101,
        [{"action": "wait", "ms": 0}],
        settle_ms=0,
    )
    assert result.ok is True
    assert result.steps[0]["detail"] == "waited 0 ms"


def test_negative_settle_is_a_typed_error(
    gui_provider: FakeGuiProvider, input_provider: FakeInputProvider
) -> None:
    with pytest.raises(AnalysisError, match="settle_ms"):
        win_input.drive_window(
            gui_provider, input_provider, 101, [{"action": "wait", "ms": 0}], settle_ms=-1
        )
    assert input_provider.calls == []


# ---- validation refuses before ANY recorded input -----------------------------------


def test_steps_not_a_list_is_typed_error_before_any_input(
    gui_provider: FakeGuiProvider, input_provider: FakeInputProvider
) -> None:
    with pytest.raises(AnalysisError, match="must be a list"):
        win_input.drive_window(
            gui_provider, input_provider, 101, "click the button", settle_ms=0
        )
    assert input_provider.calls == []


def test_unknown_action_is_typed_error_before_any_input(
    gui_provider: FakeGuiProvider, input_provider: FakeInputProvider
) -> None:
    with pytest.raises(AnalysisError, match="unknown action"):
        win_input.drive_window(
            gui_provider,
            input_provider,
            101,
            [{"action": "click", "x": 1, "y": 1}, {"action": "scroll", "ticks": 3}],
            settle_ms=0,
        )
    assert input_provider.calls == []  # the valid first step was NOT executed


def test_malformed_steps_are_typed_errors_before_any_input(
    gui_provider: FakeGuiProvider, input_provider: FakeInputProvider
) -> None:
    with pytest.raises(AnalysisError, match="must be a dict"):
        win_input.drive_window(gui_provider, input_provider, 101, ["click"], settle_ms=0)
    with pytest.raises(AnalysisError, match="integer 'x'"):
        win_input.drive_window(
            gui_provider,
            input_provider,
            101,
            [{"action": "click", "x": "5", "y": 0}],
            settle_ms=0,
        )
    with pytest.raises(AnalysisError, match="string 'text'"):
        win_input.drive_window(
            gui_provider, input_provider, 101, [{"action": "type", "text": 7}], settle_ms=0
        )
    with pytest.raises(AnalysisError, match="256-character bound"):
        win_input.drive_window(
            gui_provider,
            input_provider,
            101,
            [{"action": "type", "text": "x" * (win_input.MAX_TEXT_CHARS + 1)}],
            settle_ms=0,
        )
    assert input_provider.calls == []


def test_unknown_hwnd_is_typed_error_naming_it(
    gui_provider: FakeGuiProvider, input_provider: FakeInputProvider
) -> None:
    with pytest.raises(AnalysisError, match=r"hwnd 999"):
        win_input.drive_window(
            gui_provider, input_provider, 999, [{"action": "wait", "ms": 0}], settle_ms=0
        )
    assert input_provider.calls == []


def test_foreground_failure_is_warning_not_crash(
    gui_provider: FakeGuiProvider, input_provider: FakeInputProvider
) -> None:
    input_provider.foreground_succeeds = False
    result = win_input.drive_window(
        gui_provider,
        input_provider,
        101,
        [{"action": "key", "key": "esc"}],
        settle_ms=0,
    )
    assert result.ok is True  # input still drove; focus is best-effort
    assert result.warnings
    assert "foreground" in result.warnings[0]
    assert input_provider.calls == [("foreground", 101), ("vk", 0x1B)]



# ---- visual regression loop ----------------------------------------------------------


def _write_reference(directory: Path, pixels: list) -> Path:
    """A reference PNG built from the win_gui encoder over synthetic pixels."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "reference.png"
    path.write_bytes(win_gui.encode_png(CAPTURE_WIDTH, CAPTURE_HEIGHT, pixels))
    return path


def test_visual_regression_identical_reference(
    gui_provider: FakeGuiProvider,
    input_provider: FakeInputProvider,
    tmp_path: Path,
) -> None:
    reference = _write_reference(tmp_path / "ref", gradient_pixels(
        CAPTURE_WIDTH, CAPTURE_HEIGHT
    ))
    result = win_input.visual_regression(
        gui_provider,
        input_provider,
        101,
        [{"action": "click", "x": 1, "y": 1}],
        reference,
        tmp_path / "out",
        settle_ms=0,
    )
    assert result["available"] is True
    assert result["ok"] is True
    assert result["drive"]["ok"] is True
    screenshot = Path(result["screenshot_path"])
    assert screenshot.is_file()
    assert screenshot.parent == tmp_path / "out"
    assert result["diff"]["verdict"] == "identical"
    assert result["diff"]["changed_ratio"] == 0.0
    assert result["diff"]["identical"] is True
    assert input_provider.calls == [("foreground", 101), ("click_left", 101, 201)]


def test_visual_regression_detects_changed_pixels(
    gui_provider: FakeGuiProvider,
    input_provider: FakeInputProvider,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = _write_reference(tmp_path, shifted_pixels(CAPTURE_WIDTH, CAPTURE_HEIGHT))
    # Only the *reference* differs; the capture keeps the gradient pixels.
    monkeypatch.setattr(
        gui_provider,
        "capture_window_png",
        lambda hwnd: win_gui.encode_png(
            CAPTURE_WIDTH, CAPTURE_HEIGHT, gradient_pixels(CAPTURE_WIDTH, CAPTURE_HEIGHT)
        ),
    )
    result = win_input.visual_regression(
        gui_provider,
        input_provider,
        101,
        [],
        reference,
        tmp_path / "out",
        settle_ms=0,
    )
    assert result["diff"]["verdict"] != "identical"
    assert result["diff"]["identical"] is False
    assert result["diff"]["changed_ratio"] > 0.0
    assert result["ok"] is True  # the drive succeeded; only the pixels differ


def test_visual_regression_missing_reference_is_typed_before_input(
    gui_provider: FakeGuiProvider, input_provider: FakeInputProvider, tmp_path: Path
) -> None:
    missing = tmp_path / "no_such_reference.png"
    with pytest.raises(AnalysisError, match="file not found"):
        win_input.visual_regression(
            gui_provider,
            input_provider,
            101,
            [{"action": "type", "text": "should never be typed"}],
            missing,
            tmp_path / "out",
            settle_ms=0,
        )
    assert input_provider.calls == []



# ---- honest availability + MCP tool surface ------------------------------------------


def test_provider_none_results_are_honest(tmp_path: Path) -> None:
    drive = win_input.drive_window(None, None, 101, [], settle_ms=0)
    assert drive.available is False
    assert "SendInput" in drive.reason
    assert drive.to_dict()["available"] is False
    loop = win_input.visual_regression(None, None, 101, [], "ref.png", tmp_path)
    assert loop == {"available": False, "reason": win_input.UNAVAILABLE_REASON}


def test_mcp_tools_without_input_provider_are_honest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(win_input, "get_input_provider", lambda: None)
    monkeypatch.setattr(win_gui, "get_provider", lambda: None)
    for payload in (
        tools.codevanta_win_click(101, 1, 1),
        tools.codevanta_win_type(101, "hi"),
        tools.codevanta_win_key(101, "enter"),
        tools.codevanta_win_visual_regression(
            101, [], str(tmp_path / "ref.png"), str(tmp_path)
        ),
    ):
        assert payload["available"] is False
        assert payload["reason"]


def test_mcp_tools_plumb_through_the_provider_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gui = FakeGuiProvider()
    inp = FakeInputProvider()
    monkeypatch.setattr(win_input, "get_input_provider", lambda: inp)
    monkeypatch.setattr(win_gui, "get_provider", lambda: gui)
    click = tools.codevanta_win_click(101, 5, 5)
    assert click["available"] is True
    assert click["ok"] is True
    assert inp.calls[-1] == ("click_left", 105, 205)
    typed = tools.codevanta_win_type(101, "ok")
    assert typed["ok"] is True
    pressed = tools.codevanta_win_key(101, "enter")
    assert pressed["ok"] is True
    reference = _write_reference(tmp_path, gradient_pixels(CAPTURE_WIDTH, CAPTURE_HEIGHT))
    loop = tools.codevanta_win_visual_regression(
        101, [], str(reference), str(tmp_path / "out"), 0
    )
    assert loop["available"] is True
    assert loop["diff"]["verdict"] == "identical"
    assert Path(loop["screenshot_path"]).is_file()
    with pytest.raises(AnalysisError, match=r"hwnd 999"):
        tools.codevanta_win_click(999, 0, 0)
    with pytest.raises(AnalysisError, match="not supported"):
        tools.codevanta_win_key(101, "windows")


# ---- JSON safety ----------------------------------------------------------------------


def test_all_results_are_json_safe(
    gui_provider: FakeGuiProvider,
    input_provider: FakeInputProvider,
    tmp_path: Path,
) -> None:
    reference = _write_reference(tmp_path, gradient_pixels(CAPTURE_WIDTH, CAPTURE_HEIGHT))
    results = [
        win_input.drive_window(
            gui_provider,
            input_provider,
            101,
            [
                {"action": "click", "x": 1, "y": 2},
                {"action": "type", "text": "hey"},
                {"action": "key", "key": "f12"},
                {"action": "wait", "ms": 0},
            ],
            settle_ms=0,
        ).to_dict(),
        win_input.drive_window(None, None, 101, [], settle_ms=0).to_dict(),
        win_input.visual_regression(
            gui_provider,
            input_provider,
            101,
            [],
            reference,
            tmp_path / "out",
            settle_ms=0,
        ),
    ]
    for result in results:
        assert json.loads(json.dumps(result, sort_keys=True)) == result


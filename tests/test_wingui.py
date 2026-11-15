"""Windows GUI observation tests (lane-wingui).

Every fixture is a fake :class:`~codevanta.analysis.win_gui.Win32Provider`
answering from a synthetic window tree -- no real windows are created, so
the suite runs unchanged on Linux CI. The fake's ``capture_window_png``
returns a *real* PNG built with the module's own encoder, and captures are
verified by decoding them with :func:`codevanta.analysis.png_diff.decode_png`.
One optional smoke test touches the live desktop and is skipped everywhere
else.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from codevanta.analysis import win_gui
from codevanta.analysis.png_diff import decode_png
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools

CAPTURE_WIDTH = 12
CAPTURE_HEIGHT = 8

CLASSES = ("Button", "Edit", "Static", "ComboBox")


def gradient_pixels(width: int, height: int) -> list[list[tuple[int, int, int, int]]]:
    """Deterministic synthetic RGBA rows (no two captures share a pattern)."""
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


class FakeProvider:
    """Synthetic Win32Provider over a fixed tree with optional stress knobs.

    Contract mirrors the real provider: unknown hwnds yield empty child
    lists from ``child_windows`` and a ``KeyError`` from ``window_rect`` /
    ``capture_window_png`` -- exactly the behaviour the API layer must
    translate into typed errors.
    """

    def __init__(self) -> None:
        self._top: list[win_gui.WindowInfo] = []
        self._children: dict[int, list[win_gui.WindowInfo]] = {}
        self._rects: dict[int, tuple[int, int, int, int]] = {}
        self._build_fixed_tree()

    # -- construction ------------------------------------------------------

    def _add(
        self,
        hwnd: int,
        pid: int,
        title: str,
        class_name: str,
        *,
        parent: int | None = None,
        visible: bool = True,
        enabled: bool = True,
        control_id: int | None = None,
        rect: tuple[int, int, int, int] = (0, 0, 100, 100),
    ) -> win_gui.WindowInfo:
        info = win_gui.WindowInfo(
            hwnd=hwnd,
            pid=pid,
            title=title,
            class_name=class_name,
            visible=visible,
            enabled=enabled,
            control_id=control_id,
        )
        if parent is None:
            self._top.append(info)
        else:
            self._children.setdefault(parent, []).append(info)
        self._rects[hwnd] = rect
        return info

    def _build_fixed_tree(self) -> None:
        self._add(101, 100, "Main Window", "NotepadFrame", rect=(0, 0, 640, 480))
        for index, class_name in enumerate(CLASSES):
            hwnd = 111 + index
            self._add(
                hwnd,
                100,
                f"control {index}",
                class_name,
                parent=101,
                control_id=1001 + index,
                rect=(10, 10 + 30 * index, 200, 30 * index + 28),
            )
        self._add(  # depth chain tail under the Button control
            1111, 100, "deep label", "Static", parent=111, control_id=1101,
            rect=(12, 12, 60, 28),
        )
        self._add(  # an invisible tool palette with no children
            202, 200, "", "ToolWindow", visible=False, rect=(8, 8, 96, 64),
        )

    def add_bounded_windows(self, count: int, *, pid: int = 900) -> None:
        for index in range(count):
            self._add(
                5000 + index, pid, f"bulk {index}", "BulkWindow",
                rect=(0, 0, 10, 10),
            )

    def add_depth_chain(self, depth: int, *, root: int = 301, pid: int = 300) -> None:
        hwnd = root
        parent = None
        for level in range(depth):
            self._add(
                hwnd, pid, f"level {level}", "ChainWindow",
                parent=parent, rect=(0, level, 10, level + 1),
            )
            parent, hwnd = hwnd, hwnd + 1

    def add_fanout(self, parent: int, count: int, *, pid: int = 400) -> None:
        self._add(parent, pid, "fan", "FanWindow", rect=(0, 0, 20, 20))
        for index in range(count):
            self._add(
                4100 + index, pid, f"leaf {index}", "LeafButton",
                parent=parent, control_id=index + 1, rect=(0, index, 5, index + 1),
            )

    # -- Win32Provider seam -------------------------------------------------

    def top_level_windows(self) -> list[win_gui.WindowInfo]:
        return list(self._top)

    def child_windows(self, hwnd: int) -> list[win_gui.WindowInfo]:
        return list(self._children.get(hwnd, []))

    def window_rect(self, hwnd: int) -> tuple[int, int, int, int]:
        try:
            return self._rects[hwnd]
        except KeyError as exc:
            raise KeyError(f"no such window {hwnd}") from exc

    def capture_window_png(self, hwnd: int) -> bytes:
        if hwnd not in self._rects:
            raise KeyError(f"no such window {hwnd}")
        width = CAPTURE_WIDTH + hwnd % 5
        height = CAPTURE_HEIGHT + hwnd % 3
        return win_gui.encode_png(width, height, gradient_pixels(width, height))


@pytest.fixture()
def provider() -> FakeProvider:
    return FakeProvider()


# ---- list_windows ----------------------------------------------------------------


def test_list_windows_returns_fixed_tree(provider: FakeProvider) -> None:
    summary = win_gui.list_windows(provider, pid=None)
    assert summary.available is True
    assert summary.enumerated == 2
    assert summary.filtered_out == 0
    assert summary.truncated is False
    assert summary.at_cap is False
    assert [w.hwnd for w in summary.windows] == [101, 202]
    main = summary.windows[0]
    assert (main.pid, main.title, main.class_name, main.visible) == (
        100, "Main Window", "NotepadFrame", True,
    )
    assert main.control_id is None  # top-level windows carry no control id


def test_list_windows_pid_filter_counts(provider: FakeProvider) -> None:
    summary = win_gui.list_windows(provider, pid=100)
    assert summary.available is True
    assert summary.enumerated == 2
    assert [w.hwnd for w in summary.windows] == [101]
    assert summary.filtered_out == 1
    assert summary.requested_pid == 100


def test_list_windows_bounded_at_max_windows(provider: FakeProvider) -> None:
    provider.add_bounded_windows(300)
    summary = win_gui.list_windows(provider, pid=None)
    assert summary.enumerated == 302
    assert len(summary.windows) == win_gui.MAX_WINDOWS
    assert summary.truncated is True
    assert summary.filtered_out == 0


def test_list_windows_at_cap_is_flagged_not_truncated(provider: FakeProvider) -> None:
    provider.add_bounded_windows(win_gui.MAX_WINDOWS - 2)  # exactly MAX_WINDOWS total
    summary = win_gui.list_windows(provider, pid=None)
    assert summary.enumerated == win_gui.MAX_WINDOWS
    assert summary.truncated is False
    assert summary.at_cap is True


# ---- observe_tree ----------------------------------------------------------------


def test_observe_tree_shape_and_control_ids(provider: FakeProvider) -> None:
    result = win_gui.observe_tree(provider, 101)
    assert result["available"] is True
    root = result["root"]
    assert root["hwnd"] == 101
    assert root["class"] == "NotepadFrame"
    assert root["rect"] == [0, 0, 640, 480]
    assert len(root["children"]) == 4
    button = root["children"][0]
    assert button["class"] == "Button"
    assert button["control_id"] == 1001
    assert button["rect"] == [10, 10, 200, 28]
    assert button["children"][0]["control_id"] == 1101
    assert result["node_count"] == 6
    assert result["depth_truncated"] is False
    assert result["children_truncated"] is False
    assert result["warnings"] == []


def test_observe_tree_depth_cap_flagged(provider: FakeProvider) -> None:
    provider.add_depth_chain(12)
    result = win_gui.observe_tree(provider, 301)
    assert result["node_count"] == win_gui.MAX_DEPTH  # 8 levels, no deeper
    assert result["depth_truncated"] is True
    deepest = result["root"]
    for _ in range(win_gui.MAX_DEPTH - 1):
        assert len(deepest["children"]) == 1
        deepest = deepest["children"][0]
    assert deepest["depth_truncated"] is True  # child 309 exists but is cut
    assert deepest["children"] == []


def test_observe_tree_children_cap_flagged(provider: FakeProvider) -> None:
    provider.add_fanout(401, 600)
    result = win_gui.observe_tree(provider, 401)
    root = result["root"]
    assert len(root["children"]) == win_gui.MAX_CHILDREN_PER_NODE
    assert root["children_truncated"] is True
    assert result["children_truncated"] is True
    assert result["node_count"] == 1 + win_gui.MAX_CHILDREN_PER_NODE


def test_observe_tree_child_hwnd_subtree_root(provider: FakeProvider) -> None:
    result = win_gui.observe_tree(provider, 111)
    root = result["root"]
    assert root["class"] == "Button"
    assert root["control_id"] == 1001
    assert any("child window" in warning for warning in result["warnings"])


# ---- capture_window ----------------------------------------------------------------


def test_capture_window_writes_verified_png(
    provider: FakeProvider, tmp_path: Path
) -> None:
    result = win_gui.capture_window(provider, 101, tmp_path)
    assert result["available"] is True
    path = Path(result["path"])
    assert path.name == f"window_101x{result['width']}x{result['height']}.png"
    assert path.is_file()
    assert result["bytes"] == path.stat().st_size
    import hashlib

    assert result["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    image = decode_png(path.read_bytes())  # reader verifies the writer
    assert (image.width, image.height) == (result["width"], result["height"])
    assert image.color_type == 6
    assert len(image.pixels) == image.height
    assert len(image.pixels[0]) == image.width


def test_capture_and_encoder_are_deterministic(
    provider: FakeProvider, tmp_path: Path
) -> None:
    pixels = gradient_pixels(CAPTURE_WIDTH, CAPTURE_HEIGHT)
    first = win_gui.encode_png(CAPTURE_WIDTH, CAPTURE_HEIGHT, pixels)
    second = win_gui.encode_png(CAPTURE_WIDTH, CAPTURE_HEIGHT, pixels)
    assert first == second  # identical pixels -> byte-identical PNG
    one = win_gui.capture_window(provider, 101, tmp_path)
    two = win_gui.capture_window(provider, 101, tmp_path / "again")
    assert Path(one["path"]).read_bytes() == Path(two["path"]).read_bytes()


def test_encoder_rejects_bad_input_typed() -> None:
    pixel = (1, 2, 3, 4)
    with pytest.raises(AnalysisError, match="unsupported color type"):
        win_gui.encode_png(1, 1, [[(1, 2)]], color_type=1)
    with pytest.raises(AnalysisError, match="invalid dimensions"):
        win_gui.encode_png(0, 1, [[]])
    with pytest.raises(AnalysisError, match="pixel rows"):
        win_gui.encode_png(1, 2, [[pixel]])
    with pytest.raises(AnalysisError, match="pixels in a row"):
        win_gui.encode_png(2, 1, [[pixel]])
    with pytest.raises(AnalysisError, match="channels"):
        win_gui.encode_png(1, 1, [[(1, 2)]])
    with pytest.raises(AnalysisError, match="pixel values not bytes"):
        win_gui.encode_png(1, 1, [[(300, 0, 0, 0)]])


# ---- honest availability + typed refusals -----------------------------------------


def test_provider_none_results_are_honest_data(tmp_path: Path) -> None:
    summary = win_gui.list_windows(None, pid=1)
    assert summary.available is False
    assert "not Windows" in summary.reason or "Win32" in summary.reason
    assert summary.windows == ()
    payload = summary.to_dict()
    assert payload["available"] is False
    tree = win_gui.observe_tree(None, 1)
    assert tree == {
        "available": False,
        "reason": win_gui.UNAVAILABLE_REASON,
        "root": None,
    }
    shot = win_gui.capture_window(None, 1, tmp_path)
    assert shot["available"] is False
    assert shot["path"] is None
    assert win_gui.UNAVAILABLE_REASON in shot["reason"]


def test_unknown_hwnd_raises_typed_error_naming_it(provider: FakeProvider) -> None:
    with pytest.raises(AnalysisError, match=r"hwnd 999"):
        win_gui.observe_tree(provider, 999)
    with pytest.raises(AnalysisError, match=r"hwnd 999"):
        win_gui.capture_window(provider, 999, Path("."))


# ---- MCP tool surface ---------------------------------------------------------------


def test_mcp_tools_without_provider_are_honest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(win_gui, "get_provider", lambda: None)
    payload = tools.codevanta_win_windows(pid=None)
    assert payload["available"] is False
    assert payload["reason"]
    payload = tools.codevanta_win_tree(12345)
    assert payload["available"] is False
    assert payload["reason"]
    payload = tools.codevanta_win_shot(12345, str(tmp_path))
    assert payload["available"] is False
    assert payload["reason"]


def test_mcp_tools_plumb_through_the_provider_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = FakeProvider()
    monkeypatch.setattr(win_gui, "get_provider", lambda: provider)
    payload = tools.codevanta_win_windows(pid=100)
    assert payload["available"] is True
    assert payload["returned"] == 1
    tree = tools.codevanta_win_tree(101)
    assert tree["available"] is True
    assert tree["node_count"] == 6
    shot = tools.codevanta_win_shot(101, str(tmp_path))
    assert Path(shot["path"]).is_file()
    with pytest.raises(AnalysisError, match=r"hwnd 999"):
        tools.codevanta_win_shot(999, str(tmp_path))


@pytest.mark.skipif(sys.platform != "win32", reason="live desktop smoke only")
def test_real_provider_smoke_lists_desktop() -> None:
    provider = win_gui.get_provider()
    summary = win_gui.list_windows(provider, pid=None)
    if provider is None:  # tolerate exotic Windows images without user32
        assert summary.available is False
        return
    assert summary.available is True
    assert len(summary.windows) <= win_gui.MAX_WINDOWS
    assert all(window.hwnd != 0 for window in summary.windows)


# ---- JSON safety ---------------------------------------------------------------------


def test_all_results_are_json_safe(
    provider: FakeProvider, tmp_path: Path
) -> None:
    results = [
        win_gui.list_windows(provider, pid=100).to_dict(),
        win_gui.list_windows(provider, pid=None).to_dict(),
        win_gui.observe_tree(provider, 101),
        win_gui.capture_window(provider, 101, tmp_path),
    ]
    for result in results:
        assert json.loads(json.dumps(result, sort_keys=True)) == result



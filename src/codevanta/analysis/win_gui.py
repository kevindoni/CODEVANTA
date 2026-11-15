"""Pure-stdlib Windows GUI observation: window tree + screenshot (lane-wingui).

CODEVANTA's static lanes decode *files*; this lane observes a *live* Windows
process through the Win32 accessibility-lite surface: the window hierarchy
that user32 exposes for native controls (Button/Edit/Static/ComboBox, ...).
Electron/Qt/WPF applications render their own controls and therefore expose
much less through Win32 -- the tools say so up front and never pretend.

Everything reads through an injectable provider seam
(:class:`Win32Provider`), so tests drive a fake tree and CI on Linux never
touches a window manager:

* :func:`get_provider` returns the real ctypes provider on ``win32`` and an
  honest ``None`` elsewhere -- availability is data, never a crash.
* :func:`list_windows` enumerates bounded top-level windows with an optional
  pid filter.
* :func:`observe_tree` walks the child-window hierarchy depth- and
  breadth-bounded, reporting every bound it hits as a flag.
* :func:`capture_window` captures one window as PNG bytes and writes a
  verified artifact to disk (path + sha256 + dimensions).

The PNG writer (:func:`encode_png`) is the counterpart of the reader in
:mod:`codevanta.analysis.png_diff`: signature, IHDR (8-bit RGB or RGBA),
one filtered scanline stream (filter byte ``0`` per row) compressed with a
fixed zlib level into a single IDAT, then IEND, each chunk CRC'd with
``zlib.crc32``. Identical pixels therefore produce byte-identical files.

Bounds
------

Enumeration stops at :data:`MAX_WINDOWS` windows; the tree walk stops at
:data:`MAX_DEPTH` levels and :data:`MAX_CHILDREN_PER_NODE` children per
node; titles are truncated to :data:`MAX_TITLE_CHARS` characters. The
capture refuses images above :data:`MAX_PNG_PIXELS` pixels before any GDI
allocation. Every bound that fires is reported in the result, not hidden.

Evidence discipline
-------------------

Every public result carries an :class:`~codevanta.evidence.models.Evidence`
record with source ``"win_gui"`` describing exactly what was enumerated,
walked or captured. Unknown hwnds and failed captures raise the typed
:class:`~codevanta.core.report.AnalysisError`; a missing provider never
does.
"""

from __future__ import annotations

import hashlib
import struct
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from codevanta.analysis.png_diff import MAX_PNG_PIXELS, decode_png
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "MAX_CHILDREN_PER_NODE",
    "MAX_DEPTH",
    "MAX_PNG_PIXELS",
    "MAX_TITLE_CHARS",
    "MAX_WINDOWS",
    "WindowInfo",
    "WinGuiSummary",
    "Win32Provider",
    "UNAVAILABLE_REASON",
    "capture_window",
    "encode_png",
    "get_provider",
    "list_windows",
    "observe_tree",
]

#: Hard ceiling on enumerated top-level windows per call.
MAX_WINDOWS = 256

#: Maximum tree depth (root = level 1); deeper children are not descended.
MAX_DEPTH = 8

#: Maximum children expanded per node; the rest are reported as truncated.
MAX_CHILDREN_PER_NODE = 512

#: Titles longer than this are truncated before they enter a result.
MAX_TITLE_CHARS = 256

#: PNG magic signature (PNG spec 5.2), shared discipline with png_diff.
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

#: Fixed zlib level so identical pixels always compress to identical bytes.
_PNG_COMPRESSION_LEVEL = 6

#: Supported PNG color types -> channel count (mirrors the reader).
_CHANNELS_BY_COLOR_TYPE: dict[int, int] = {2: 3, 6: 4}

#: Evidence source shared by every record this module emits.
_EVIDENCE_SOURCE = "win_gui"

#: Honest availability reason reused by every API when no provider exists.
#: Honest availability reason reused by every API when no provider exists.
UNAVAILABLE_REASON = (
    "Windows GUI observation requires native Win32 (ctypes user32/gdi32); "
    "this platform does not provide it, so no live windows can be observed."
)

@dataclass(frozen=True)
class WindowInfo:
    """One observed window: identity, owner process and bounding metadata.

    ``control_id`` is the ``GetWindowLongW(GWL_ID)`` child identifier and is
    ``None`` where the platform does not expose one (top-level windows and
    providers without the call).
    """

    hwnd: int
    pid: int
    title: str
    class_name: str
    visible: bool
    enabled: bool = True
    control_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection."""
        return {
            "hwnd": self.hwnd,
            "pid": self.pid,
            "title": self.title,
            "class_name": self.class_name,
            "visible": self.visible,
            "enabled": self.enabled,
            "control_id": self.control_id,
        }


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    """Length-prefixed chunk with the CRC32 of type + payload (PNG spec 5.4)."""
    crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", crc)


def encode_png(
    width: int,
    height: int,
    pixels: Any,
    *,
    color_type: int = 6,
) -> bytes:
    """Encode ``pixels`` as a minimal deterministic 8-bit PNG.

    ``pixels`` is a sequence of ``height`` rows, each a sequence of ``width``
    ``(r, g, b)`` or ``(r, g, b, a)`` integer tuples in ``0..255`` matching
    ``color_type`` (2 RGB, 6 RGBA). Every scanline is emitted with filter
    byte ``0`` (None) and compressed in one IDAT at the fixed zlib level
    :data:`_PNG_COMPRESSION_LEVEL`, so identical pixels give byte-identical
    output.

    Raises:
        AnalysisError: On unsupported color type, out-of-bound dimensions
            (see :data:`MAX_PNG_PIXELS`), or row/pixel shape and value
            mismatches.
    """
    channels = _CHANNELS_BY_COLOR_TYPE.get(color_type)
    if channels is None:
        raise AnalysisError(f"png: unsupported color type {color_type} (use 2 RGB or 6 RGBA)")
    if width <= 0 or height <= 0:
        raise AnalysisError(f"png: invalid dimensions {width}x{height}")
    if width * height > MAX_PNG_PIXELS:
        raise AnalysisError(f"png: {width}x{height} exceeds the {MAX_PNG_PIXELS}-pixel bound")
    if len(pixels) != height:
        raise AnalysisError(f"png: expected {height} pixel rows, got {len(pixels)}")
    raw = bytearray()
    for row in pixels:
        if len(row) != width:
            raise AnalysisError(f"png: expected {width} pixels in a row, got {len(row)}")
        raw.append(0)  # filter type None for this scanline
        for pixel in row:
            if len(pixel) != channels:
                raise AnalysisError(f"png: pixel has {len(pixel)} channels, expected {channels}")
            try:
                raw.extend(bytes(pixel))
            except (TypeError, ValueError) as exc:
                raise AnalysisError(f"png: pixel values not bytes: {exc}") from exc
    ihdr = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    idat = zlib.compress(bytes(raw), _PNG_COMPRESSION_LEVEL)
    return (
        _PNG_SIGNATURE
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", idat)
        + _png_chunk(b"IEND", b"")
    )


class Win32Provider(Protocol):
    """The testing contract every live-observation API reads through.

    Implementations answer four questions about a running Windows session.
    The real provider (:class:`CtypesWin32Provider`) answers via user32 and
    gdi32; tests answer from a synthetic tree, so nothing in this module or
    its tests depends on an actual desktop being present.
    """

    def top_level_windows(self) -> list[WindowInfo]:
        """Bounded list of top-level windows (most-recently-z first)."""
        ...

    def child_windows(self, hwnd: int) -> list[WindowInfo]:
        """Bounded direct children of ``hwnd`` (control_id where available)."""
        ...

    def window_rect(self, hwnd: int) -> tuple[int, int, int, int]:
        """``(left, top, right, bottom)`` or raise for an unknown hwnd."""
        ...

    def capture_window_png(self, hwnd: int) -> bytes:
        """PNG bytes of the window's current appearance or raise."""
        ...


@dataclass(frozen=True)
class WinGuiSummary:
    """Outcome of :func:`list_windows`; frozen and JSON-safe.

    ``windows`` is the bounded, pid-filtered result. ``enumerated`` counts
    what the provider returned before filtering; ``filtered_out`` counts
    windows removed by the pid filter; ``truncated`` is provable over-cap
    enumeration; ``at_cap`` flags the ambiguous exactly-at-``MAX_WINDOWS``
    case (the provider may have stopped early itself).
    """

    available: bool
    windows: tuple[WindowInfo, ...] = ()
    requested_pid: int | None = None
    enumerated: int = 0
    filtered_out: int = 0
    truncated: bool = False
    at_cap: bool = False
    reason: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection with per-window rows."""
        return {
            "available": self.available,
            "windows": [window.to_dict() for window in self.windows],
            "requested_pid": self.requested_pid,
            "enumerated": self.enumerated,
            "filtered_out": self.filtered_out,
            "truncated": self.truncated,
            "at_cap": self.at_cap,
            "returned": len(self.windows),
            "reason": self.reason,
            "evidence": dict(self.evidence),
        }


def list_windows(provider: Win32Provider | None, pid: int | None = None) -> WinGuiSummary:
    """Enumerate bounded top-level windows, optionally filtered by ``pid``.

    A ``None`` provider yields the honest unavailable summary (this is
    data, not a crash -- callers on Linux get it verbatim). Enumeration
    results are re-bounded to :data:`MAX_WINDOWS` here as defence in depth
    even though the real provider caps its own callbacks.
    """
    if provider is None:
        return WinGuiSummary(available=False, requested_pid=pid, reason=UNAVAILABLE_REASON)
    windows = list(provider.top_level_windows())
    enumerated = len(windows)
    if pid is None:
        matched = windows
    else:
        matched = [window for window in windows if window.pid == pid]
    bounded = matched[:MAX_WINDOWS]
    evidence = Evidence(
        source=_EVIDENCE_SOURCE,
        method="enum_windows",
        confidence=Confidence.HIGH,
        detail=(
            f"{enumerated} top-level windows enumerated"
            + (f", pid filter {pid} kept {len(matched)}" if pid is not None else "")
            + f", returned {len(bounded)} after the {MAX_WINDOWS}-window bound"
        ),
    ).to_dict()
    return WinGuiSummary(
        available=True,
        windows=tuple(bounded),
        requested_pid=pid,
        enumerated=enumerated,
        filtered_out=enumerated - len(matched),
        truncated=enumerated > MAX_WINDOWS,
        at_cap=enumerated == MAX_WINDOWS,
        evidence=evidence,
    )


@dataclass
class _TreeStats:
    """Mutable walk counters shared across the recursive node builder."""

    node_count: int = 0
    depth_truncated: bool = False
    children_truncated: bool = False
    warnings: list[str] = field(default_factory=list)


def _safe_rect(
    provider: Win32Provider, hwnd: int, depth: int, stats: _TreeStats
) -> list[int] | None:
    """Rect for ``hwnd`` or ``None``; the root refusal is a typed error."""
    try:
        return list(provider.window_rect(hwnd))
    except (KeyError, OSError, AnalysisError) as exc:
        if depth == 1:
            raise AnalysisError(f"win_gui: unknown hwnd {hwnd}: {exc!r}") from exc
        stats.warnings.append(f"rect unavailable for hwnd {hwnd}: {exc!r}")
        return None


def _build_node(
    provider: Win32Provider, hwnd: int, depth: int, stats: _TreeStats
) -> dict[str, Any]:
    """One tree node plus bounded children; every bound hit becomes a flag."""
    stats.node_count += 1
    children = provider.child_windows(hwnd)
    children_truncated = len(children) > MAX_CHILDREN_PER_NODE
    if children_truncated:
        stats.children_truncated = True
    bounded_children = children[:MAX_CHILDREN_PER_NODE]
    rect = _safe_rect(provider, hwnd, depth, stats)
    node: dict[str, Any] = {
        "hwnd": int(hwnd),
        "pid": 0,
        "class": "",
        "title": "",
        "control_id": None,
        "rect": rect,
        "visible": False,
        "enabled": False,
        "children": [],
        "children_truncated": children_truncated,
        "depth_truncated": False,
    }
    if depth < MAX_DEPTH:
        for child in bounded_children:
            child_node = _build_node(provider, child.hwnd, depth + 1, stats)
            # Children carry their own metadata straight from the provider.
            child_node["pid"] = child.pid
            child_node["class"] = child.class_name
            child_node["title"] = child.title[:MAX_TITLE_CHARS]
            child_node["control_id"] = child.control_id
            child_node["visible"] = child.visible
            child_node["enabled"] = child.enabled
            node["children"].append(child_node)
    elif bounded_children:
        node["depth_truncated"] = True
        stats.depth_truncated = True
    return node


def _root_metadata(
    provider: Win32Provider, hwnd: int, stats: _TreeStats
) -> dict[str, Any]:
    """Metadata for the root hwnd, searched top-level first, then one level."""
    for window in provider.top_level_windows()[:MAX_WINDOWS]:
        if window.hwnd == hwnd:
            return _node_base(window)
    for window in provider.top_level_windows()[:MAX_WINDOWS]:
        for child in provider.child_windows(window.hwnd)[:MAX_CHILDREN_PER_NODE]:
            if child.hwnd == hwnd:
                stats.warnings.append(
                    f"root hwnd {hwnd} is a child window; observed as a subtree root"
                )
                return _node_base(child)
    stats.warnings.append(
        f"provider exposes no metadata for root hwnd {hwnd}; fields are degraded"
    )
    return {"pid": 0, "class": "", "title": "", "control_id": None, "visible": False, "enabled": False}


def _node_base(window: WindowInfo) -> dict[str, Any]:
    """Common node metadata pulled from a :class:`WindowInfo`."""
    return {
        "pid": window.pid,
        "class": window.class_name,
        "title": window.title[:MAX_TITLE_CHARS],
        "control_id": window.control_id,
        "visible": window.visible,
        "enabled": window.enabled,
    }


def observe_tree(provider: Win32Provider | None, hwnd: int) -> dict[str, Any]:
    """Walk the window hierarchy rooted at ``hwnd`` into a bounded node dict.

    Nodes carry hwnd, class, title, control_id, rect, visible/enabled and
    their bounded children; depth and per-node children caps are reported
    as flags on the offending nodes and summarised on the result. An
    unknown hwnd raises a typed :class:`AnalysisError` naming it; a ``None``
    provider yields the honest unavailable dict instead.
    """
    if provider is None:
        return {"available": False, "reason": UNAVAILABLE_REASON, "root": None}
    try:
        provider.window_rect(hwnd)
    except (KeyError, OSError, AnalysisError) as exc:
        raise AnalysisError(f"win_gui: unknown hwnd {hwnd}: {exc!r}") from exc
    stats = _TreeStats()
    root = _build_node(provider, hwnd, depth=1, stats=stats)
    root.update(_root_metadata(provider, hwnd, stats))
    evidence = Evidence(
        source=_EVIDENCE_SOURCE,
        method="observe_tree",
        confidence=Confidence.HIGH,
        detail=(
            f"{stats.node_count} nodes under hwnd {hwnd} "
            f"(depth cap {MAX_DEPTH}, children cap {MAX_CHILDREN_PER_NODE})"
        ),
    ).to_dict()
    return {
        "available": True,
        "root": root,
        "node_count": stats.node_count,
        "depth_cap": MAX_DEPTH,
        "children_cap": MAX_CHILDREN_PER_NODE,
        "depth_truncated": stats.depth_truncated,
        "children_truncated": stats.children_truncated,
        "warnings": stats.warnings,
        "evidence": evidence,
    }


def capture_window(
    provider: Win32Provider | None, hwnd: int, output_directory: Path
) -> dict[str, Any]:
    """Capture ``hwnd`` to ``<output>/window_<hwnd>x<width>x<height>.png``.

    The PNG bytes are round-trip decoded with
    :func:`codevanta.analysis.png_diff.decode_png` *before* anything is
    written, so the artifact on disk is verified evidence: the result
    carries its sha256 and dimensions. An unknown hwnd raises a typed
    :class:`AnalysisError` naming it; a ``None`` provider yields the
    honest unavailable dict instead.
    """
    if provider is None:
        return {"available": False, "reason": UNAVAILABLE_REASON, "path": None}
    try:
        png_bytes = provider.capture_window_png(hwnd)
    except (KeyError, OSError) as exc:
        raise AnalysisError(f"win_gui: cannot capture hwnd {hwnd}: {exc!r}") from exc
    if not png_bytes:
        raise AnalysisError(f"win_gui: provider returned no PNG for hwnd {hwnd}")
    image = decode_png(png_bytes)
    out_dir = Path(output_directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"window_{hwnd}x{image.width}x{image.height}.png"
    path.write_bytes(png_bytes)
    digest = hashlib.sha256(png_bytes).hexdigest()
    evidence = Evidence(
        source=_EVIDENCE_SOURCE,
        method="capture_window_png",
        confidence=Confidence.HIGH,
        detail=(
            f"captured hwnd {hwnd} as {image.width}x{image.height} PNG "
            f"({len(png_bytes)} bytes), round-trip decoded before writing"
        ),
    ).to_dict()
    return {
        "available": True,
        "hwnd": hwnd,
        "path": str(path),
        "sha256": digest,
        "width": image.width,
        "height": image.height,
        "bytes": len(png_bytes),
        "evidence": evidence,
    }


def get_provider() -> Win32Provider | None:
    """Build the real ctypes provider on Windows; ``None`` elsewhere.

    Availability is honest data: callers must handle ``None`` (every API in
    this module does, without raising). The class is only defined when
    ``sys.platform == "win32"``, so importing this module on Linux never
    touches ``ctypes.windll``, ``wintypes`` or ``WINFUNCTYPE``.
    """
    if sys.platform != "win32" or _WIN32_PROVIDER_CLS is None:
        return None
    return _WIN32_PROVIDER_CLS()


if sys.platform == "win32":  # pragma: win32-cover -- real provider, live only

    class CtypesWin32Provider:
        """Real :class:`Win32Provider` over user32/gdi32 via ctypes.

        Enumeration runs through ``WNDENUMPROC`` callbacks that stop early
        at :data:`MAX_WINDOWS`, so a busy desktop costs a bounded number of
        callback invocations. Titles are truncated to
        :data:`MAX_TITLE_CHARS` before they leave the provider. Handles are
        declared with pointer-sized restypes (``HDC``/``HBITMAP``) so 64-bit
        GDI handles are never truncated through a default ``c_int``.
        """

        _GWL_ID = -12
        _SRC_COPY = 0x00CC0020
        _PW_RENDERFULLCONTENT = 0x2
        _DIB_RGB_COLORS = 0x0
        _BI_RGB = 0x0

        def __init__(self) -> None:
            import ctypes
            from ctypes import wintypes

            self._ct = ctypes
            self._wt = wintypes
            self._user32 = ctypes.windll.user32
            self._gdi32 = ctypes.windll.gdi32
            self._enumproc = ctypes.WINFUNCTYPE(
                wintypes.BOOL, wintypes.HWND, wintypes.LPARAM
            )
            self._bind_signatures()

        def _bind_signatures(self) -> None:
            """Pin pointer-sized signatures; defaults truncate 64-bit handles."""
            ct, wt = self._ct, self._wt
            self._user32.EnumWindows.argtypes = [self._enumproc, wt.LPARAM]
            self._user32.EnumWindows.restype = wt.BOOL
            self._user32.EnumChildWindows.argtypes = [wt.HWND, self._enumproc, wt.LPARAM]
            self._user32.EnumChildWindows.restype = wt.BOOL
            self._user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ct.POINTER(wt.DWORD)]
            self._user32.GetWindowThreadProcessId.restype = wt.DWORD
            self._user32.GetWindowTextLengthW.argtypes = [wt.HWND]
            self._user32.GetWindowTextLengthW.restype = ct.c_int
            self._user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ct.c_int]
            self._user32.GetWindowTextW.restype = ct.c_int
            self._user32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ct.c_int]
            self._user32.GetClassNameW.restype = ct.c_int
            self._user32.IsWindowVisible.argtypes = [wt.HWND]
            self._user32.IsWindowVisible.restype = wt.BOOL
            self._user32.IsWindowEnabled.argtypes = [wt.HWND]
            self._user32.IsWindowEnabled.restype = wt.BOOL
            self._user32.GetWindowLongW.argtypes = [wt.HWND, ct.c_int]
            self._user32.GetWindowLongW.restype = wt.LONG
            self._user32.GetWindowRect.argtypes = [wt.HWND, ct.POINTER(wt.RECT)]
            self._user32.GetWindowRect.restype = wt.BOOL
            self._user32.GetWindowDC.argtypes = [wt.HWND]
            self._user32.GetWindowDC.restype = wt.HDC
            self._user32.ReleaseDC.argtypes = [wt.HWND, wt.HDC]
            self._user32.ReleaseDC.restype = ct.c_int

            self._user32.PrintWindow.argtypes = [wt.HWND, wt.HDC, wt.UINT]
            self._user32.PrintWindow.restype = wt.BOOL
            self._gdi32.BitBlt.argtypes = [
                wt.HDC, ct.c_int, ct.c_int, ct.c_int, ct.c_int,
                wt.HDC, ct.c_int, ct.c_int, wt.DWORD,
            ]
            self._gdi32.BitBlt.restype = wt.BOOL
            self._gdi32.CreateCompatibleDC.argtypes = [wt.HDC]
            self._gdi32.CreateCompatibleDC.restype = wt.HDC
            self._gdi32.CreateCompatibleBitmap.argtypes = [wt.HDC, ct.c_int, ct.c_int]
            self._gdi32.CreateCompatibleBitmap.restype = wt.HBITMAP
            self._gdi32.SelectObject.argtypes = [wt.HDC, wt.HGDIOBJ]
            self._gdi32.SelectObject.restype = wt.HGDIOBJ
            self._gdi32.DeleteObject.argtypes = [wt.HGDIOBJ]
            self._gdi32.DeleteObject.restype = wt.BOOL
            self._gdi32.DeleteDC.argtypes = [wt.HDC]
            self._gdi32.DeleteDC.restype = wt.BOOL
            self._gdi32.GetDIBits.argtypes = [
                wt.HDC, wt.HBITMAP, wt.UINT, wt.UINT, ct.c_void_p, ct.c_void_p, wt.UINT,
            ]
            self._gdi32.GetDIBits.restype = ct.c_int

        def _describe(self, hwnd: int, with_control_id: bool) -> WindowInfo:
            """Snapshot one window: pid, bounded title, class, visibility."""
            wt = self._wt
            pid = wt.DWORD(0)
            self._user32.GetWindowThreadProcessId(hwnd, self._ct.byref(pid))
            length = max(0, int(self._user32.GetWindowTextLengthW(hwnd)))
            title_buf = self._ct.create_unicode_buffer(min(length, MAX_TITLE_CHARS) + 1)
            self._user32.GetWindowTextW(hwnd, title_buf, len(title_buf))
            class_buf = self._ct.create_unicode_buffer(256)
            self._user32.GetClassNameW(hwnd, class_buf, len(class_buf))
            control_id: int | None = None
            if with_control_id:
                control_id = int(self._user32.GetWindowLongW(hwnd, self._GWL_ID))
            return WindowInfo(
                hwnd=int(hwnd),
                pid=int(pid.value),
                title=title_buf.value[:MAX_TITLE_CHARS],
                class_name=class_buf.value,
                visible=bool(self._user32.IsWindowVisible(hwnd)),
                enabled=bool(self._user32.IsWindowEnabled(hwnd)),
                control_id=control_id,
            )

        def _enumerate(self, run: Any, with_control_id: bool) -> list[WindowInfo]:
            """Drive one ``WNDENUMPROC`` walk, stopping at MAX_WINDOWS."""
            found: list[WindowInfo] = []

            def on_window(hwnd: int, _lparam: int) -> int:
                if len(found) >= MAX_WINDOWS:
                    return 0  # stop the walk; the cap is honest and bounded
                found.append(self._describe(hwnd, with_control_id))
                return 1

            callback = self._enumproc(on_window)
            run(callback)
            return found

        def top_level_windows(self) -> list[WindowInfo]:
            run = lambda callback: self._user32.EnumWindows(callback, 0)  # noqa: E731
            return self._enumerate(run, with_control_id=False)

        def child_windows(self, hwnd: int) -> list[WindowInfo]:
            wt = self._wt

            def run(callback: Any) -> Any:
                return self._user32.EnumChildWindows(wt.HWND(hwnd), callback, 0)

            return self._enumerate(run, with_control_id=True)

        def window_rect(self, hwnd: int) -> tuple[int, int, int, int]:
            rect = self._wt.RECT()
            if not self._user32.GetWindowRect(hwnd, self._ct.byref(rect)):
                raise AnalysisError(
                    f"win_gui: GetWindowRect failed for hwnd {hwnd} (gone or no access)"
                )
            return (int(rect.left), int(rect.top), int(rect.right), int(rect.bottom))

        def capture_window_png(self, hwnd: int) -> bytes:
            """BitBlt/PrintWindow the window into a 32-bpp DIB, encode as PNG."""
            left, top, right, bottom = self.window_rect(hwnd)
            width, height = right - left, bottom - top
            if width <= 0 or height <= 0:
                raise AnalysisError(f"win_gui: hwnd {hwnd} has empty rect {width}x{height}")
            if width * height > MAX_PNG_PIXELS:
                raise AnalysisError(
                    f"win_gui: hwnd {hwnd} capture {width}x{height} exceeds "
                    f"the {MAX_PNG_PIXELS}-pixel bound"
                )
            window_dc = self._user32.GetWindowDC(hwnd)
            if not window_dc:
                raise AnalysisError(f"win_gui: GetWindowDC failed for hwnd {hwnd}")
            mem_dc = None
            bitmap = None
            try:
                mem_dc = self._gdi32.CreateCompatibleDC(window_dc)
                if not mem_dc:
                    raise AnalysisError(f"win_gui: CreateCompatibleDC failed for hwnd {hwnd}")
                bitmap = self._gdi32.CreateCompatibleBitmap(window_dc, width, height)
                if not bitmap:
                    raise AnalysisError(
                        f"win_gui: CreateCompatibleBitmap failed for hwnd {hwnd}"
                    )
                self._gdi32.SelectObject(mem_dc, bitmap)
                if not self._user32.PrintWindow(hwnd, mem_dc, self._PW_RENDERFULLCONTENT):
                    self._gdi32.BitBlt(
                        mem_dc, 0, 0, width, height, window_dc, 0, 0, self._SRC_COPY
                    )
                return self._read_pixels(mem_dc, bitmap, width, height, hwnd)
            finally:
                if bitmap:
                    self._gdi32.DeleteObject(bitmap)
                if mem_dc:
                    self._gdi32.DeleteDC(mem_dc)
                self._user32.ReleaseDC(hwnd, window_dc)

        def _read_pixels(
            self, mem_dc: Any, bitmap: Any, width: int, height: int, hwnd: int
        ) -> bytes:
            """Pull top-down BGRA rows out of the DIB and PNG-encode RGBA."""
            ct = self._ct
            wt = self._wt

            class BITMAPINFOHEADER(ct.Structure):
                _fields_ = [
                    ("biSize", wt.DWORD),
                    ("biWidth", wt.LONG),
                    ("biHeight", wt.LONG),
                    ("biPlanes", wt.WORD),
                    ("biBitCount", wt.WORD),
                    ("biCompression", wt.DWORD),
                    ("biSizeImage", wt.DWORD),
                    ("biXPelsPerMeter", wt.LONG),
                    ("biYPelsPerMeter", wt.LONG),
                    ("biClrUsed", wt.DWORD),
                    ("biClrImportant", wt.DWORD),
                ]

            header = BITMAPINFOHEADER()
            header.biSize = ct.sizeof(BITMAPINFOHEADER)
            header.biWidth = width
            header.biHeight = -height  # negative: top-down rows
            header.biPlanes = 1
            header.biBitCount = 32
            header.biCompression = self._BI_RGB
            buffer = ct.create_string_buffer(width * height * 4)
            got = self._gdi32.GetDIBits(
                mem_dc, bitmap, 0, height, buffer, ct.byref(header),
                self._DIB_RGB_COLORS,
            )
            if got != height:
                raise AnalysisError(f"win_gui: GetDIBits failed for hwnd {hwnd}")
            stride = width * 4
            raw = buffer.raw
            rows = [
                [
                    (row[offset + 2], row[offset + 1], row[offset], row[offset + 3])
                    for offset in range(0, stride, 4)
                ]  # BGRA in memory -> RGBA pixels
                for row in (raw[y * stride:(y + 1) * stride] for y in range(height))
            ]
            return encode_png(width, height, rows, color_type=6)





    _WIN32_PROVIDER_CLS: type[CtypesWin32Provider] | None = CtypesWin32Provider

else:
    _WIN32_PROVIDER_CLS = None






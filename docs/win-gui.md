# Windows GUI observation (windows, tree, screenshot)

Three MCP tools, `codevanta_win_windows`, `codevanta_win_tree` and
`codevanta_win_shot`, observe the live Win32 GUI: list top-level
windows, walk the child-window hierarchy under one hwnd, and capture a
window as a PNG artifact. Read-only observers — nothing is executed in
the observed process, and no input is sent (that is the
[win-input lane](win-input.md)).

Availability is data, not a crash: on a non-Windows host every tool
returns `{"available": false, "reason": …}` instead of raising. An
unknown hwnd stays a typed `AnalysisError`.

## What it reports

* `codevanta_win_windows(pid=None)` — the session's top-level windows,
  bounded to 256 entries, optionally filtered by owning process id.
  Each entry carries `hwnd`, `pid`, `title` (256-char cap), the window
  class name and `visible`/`enabled` flags.
* `codevanta_win_tree(hwnd)` — the accessibility-lite widget tree under
  one hwnd: per node, `hwnd`, class name (`Button`, `Edit`, `Static`,
  `ComboBox`, …), `title`, control id, `rect` and `visible`/`enabled`.
  Children are bounded to 512 per node and depth to 8 levels — every
  bound hit is reported as a flag, never hidden.
* `codevanta_win_shot(hwnd, output_directory)` — one window's current
  appearance as `<output_directory>/window_<hwnd>x<width>x<height>.png`,
  verified by round-trip decoding before the file is written; the
  result carries `path`, `sha256`, `dimensions` and byte count.

All three are pure stdlib ctypes (`user32`/`gdi32`) with a
deterministic PNG encoder; capture and tree evidence is `high`
confidence — the rows are read from the window's own structures.

## Scope note

These tools observe **native Win32 controls** best. Applications that
draw their own widgets — Electron, Qt, WPF, and modern WinUI surfaces —
expose less (or nothing) through the Win32 window hierarchy; the tree
may then show a few host windows with no meaningful children, while
`codevanta_win_shot` still captures the pixels of any window. For
automated verification on such surfaces use the
[visual regression loop](win-input.md).

## Usage

```json
{"pid": 4242}
{"hwnd": 197128}
{"hwnd": 197128, "output_directory": "C:\\sandbox"}
```

Python surface:

```python
from codevanta.analysis.win_gui import get_provider, list_windows, observe_tree, capture_window

provider = get_provider()          # None off Windows
if provider is not None:
    for window in list_windows(provider).windows:
        print(window.hwnd, window.title)
```

## Bounds and confidence

| Bound | Default | Effect |
|-------|---------|--------|
| Top-level window rows | 256 | `truncated: true` when hit |
| Title length | 256 chars | clipped |
| Tree children per node | 512 | flagged, never hidden |
| Tree depth | 8 levels | flagged, never hidden |

| Finding | Confidence | Why |
|---------|------------|-----|
| Window / tree rows | `high` | read from `EnumWindows`/`GetClassName`-family calls against the live session |
| The PNG artifact | `high` | round-trip decoded before the write; the record carries its sha256 |

## Limitations

* Off-Windows there is nothing to observe — the honest
  `available=false` object is the whole answer.
* Custom-drawn UIs (Electron/Qt/WPF/WinUI) expose few or no Win32
  child controls; use [win-shot](win-gui.md) pixels and the
  [visual regression loop](win-input.md) for those.
* The observation is a moment in time: windows come and go, and a
  stale hwnd from a previous call is the typed unknown-hwnd error.

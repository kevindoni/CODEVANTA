# Windows input automation (real input + visual regression)

Four MCP tools, `codevanta_win_click`, `codevanta_win_type`,
`codevanta_win_key` and `codevanta_win_visual_regression`, drive a
live Windows window with **real input** and verify the result by
pixel-diffing a capture against a reference PNG.

The safety statement, honest up front: these tools send REAL input to
the target window — the mouse moves, keys are injected through Win32
`SendInput`, and the target application receives them exactly as if a
user had acted. Nothing is simulated.

## What it reports

* `codevanta_win_click(hwnd, x, y)` — one real click at
  **window-relative** coordinates (x, y are added to the window's
  top-left on screen), injected as `MOUSEEVENTF_LEFTDOWN`/`LEFTUP`
  after moving the cursor.
* `codevanta_win_type(hwnd, text)` — foreground the window
  (best-effort) and type real text: every character is a
  `KEYEVENTF_UNICODE` down/up pair; astral characters travel as their
  UTF-16 surrogate pair.
* `codevanta_win_key(hwnd, key)` — foreground and press one named key
  by its virtual-key code. Supported names: `enter`, `tab`, `esc`,
  `space`, `backspace`, `delete`, `insert`, `home`, `end`, `pageup`,
  `pagedown`, `left`, `up`, `right`, `down` and `f1`..`f12`; an
  unknown name is a typed error listing them.
* `codevanta_win_visual_regression(hwnd, steps, reference_png,
  output_directory, settle_ms=250)` — the loop: validate the whole
  step script (`click` / `type` / `key` / `wait` actions), inject the
  events, settle for repaint, capture the window as a verified PNG
  artifact in `output_directory`, and pixel-diff it against
  `reference_png` — an `identical`/`minor`/`major` verdict plus
  `changed_ratio`.

A refused-to-foreground window is a warning, never a crash (OS focus
rules decide); an unknown hwnd is a typed `AnalysisError`. On
non-Windows hosts every tool returns `{"available": false, "reason":
…}` instead of raising — availability is data.

## Usage

```json
{"hwnd": 197128, "x": 120, "y": 40}
{"hwnd": 197128, "text": "hello"}
{"hwnd": 197128, "key": "enter"}
{"hwnd": 197128, "steps": [{"action": "click", "x": 120, "y": 40}, {"action": "type", "text": "hi"}, {"action": "wait", "ms": 400}],
 "reference_png": "C:\\ref\\dialog.png", "output_directory": "C:\\sandbox"}
```

Python surface: `codevanta.analysis.win_input.drive_window` and
`codevanta.analysis.win_input.visual_regression`, both provider-based
(the same `SendInput` provider the tools use), so the loop is
scriptable headlessly on a Windows host.

The script is validated **whole before the first event**, and a
missing `reference_png` is a typed error raised **before any input is
sent** — a refused script never touches the target.

## Bounds and confidence

| Bound | Default | Effect |
|-------|---------|--------|
| Text per call | 256 chars | longer text is a typed error |
| Steps per script | 64 | more are a typed error |
| Wait per step | 5000 ms | more is a typed error |
| Settle before capture | 250 ms (`settle_ms`) | caller-tunable |

| Finding | Confidence | Why |
|---------|------------|-----|
| An injected-input record | `high` | the SendInput calls are the event; the record reports what was injected |
| A visual-regression verdict | `high` | computed from the captured PNG's pixels against the reference, deterministically |

## Limitations

* Input goes to the **window with foreground focus** at injection
  time; a lost race for focus is reported as a warning, but the keys
  went somewhere — schedule runs on an idle desktop.
* `SendInput` is global by nature: the injection is not confined to
  the target hwnd; the window-relative coordinates are, the input
  queue is not.
* UAC prompts, secure desktops and elevated windows do not receive
  synthetic input from a non-elevated caller.
* The pixel differ is exact and deterministic; it does not blur,
  scale or anti-alias — a theme change is a `major` verdict, by
  design.

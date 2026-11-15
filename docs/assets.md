# PE visual assets (icons, cursors, bitmaps)

`codevanta_pe_assets` extracts the real visual assets of a PE — icons,
cursors and bitmaps stored as Windows resources — decoding their
device-independent bitmaps (DIBs) into deterministic PNG artifacts on
disk, with a manifest behind every claim. Fully offline, pure Python;
nothing is executed.

## What it reports

One PNG file per decoded asset, named
`<group>_<id>_<w>x<h>.png` in `output_directory`, plus a manifest
row per asset carrying:

* `group` name and `resource kind` — `RT_GROUP_ICON`/`RT_ICON`,
  `RT_GROUP_CURSOR`/`RT_CURSOR` or `RT_BITMAP`;
* `resource id`, `width`, `height`, `bit depth`;
* `hotspot` coordinates for cursors (the click anchor);
* the written file's byte count and `sha256`.

A PE without image resources is a valid **empty result** — not an
error. Unsupported DIB variants (exotic compressions, odd depths) are
skipped with warnings that name the resource; the rest of the manifest
stands. Evidence is `high` confidence: every row is decoded from the
resource's own bytes.

## Usage

```json
{"path": "sample.exe", "output_directory": "C:\\sandbox\\assets"}
```

Python surface:

```python
from codevanta.analysis.winres_assets import extract_visual_assets

report = extract_visual_assets("sample.exe", "out/assets")
for asset in report.assets:
    print(asset.group, asset.resource_id, asset.width, asset.height, asset.sha256)
payload = report.to_dict()   # JSON-safe, warnings included
```

Missing files and non-PE inputs are typed `AnalysisError`s; an
unwritable output directory likewise.

## Bounds and confidence

| Bound | Default | Effect |
|-------|---------|--------|
| Assets extracted | 128 | counting continues; `truncated: true` |
| Entries per group | 32 | overflow stays in the honest counts |
| Unsupported DIB variants | — | skipped with a warning naming the resource |

| Finding | Confidence | Why |
|---------|------------|-----|
| A manifest row + PNG | `high` | decoded deterministically from the resource's DIB bytes |

## Limitations

* Only the three image-bearing resource kinds above; string tables,
  version infos and dialog templates belong to the UI-resources lane
  (`codevanta_dialog_decode` / `codevanta_ui_preview`).
* Icons are decoded per image entry, so one multi-resolution `RT_ICON`
  group yields several rows — the `<w>x<h>` suffix keeps them apart.
* DIB variants the decoder does not support are skipped honestly, not
  guessed into grey rectangles.

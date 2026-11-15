# JavaScript source maps (v3 decode + position trace)

`codevanta_sourcemap` decodes a JavaScript source map (v3) fully
offline: the base64-VLQ `mappings` string becomes a bounded segment
table, and — with a generated position — that table is walked backwards
to the original source location. It is the read path for the
web-frontend lane: minified bundles ship their truth in the `.map`
file, and this tool turns one minified coordinate back into a file,
line and symbol name. Pure Python standard library; nothing is
executed.

## What it reports

**Decode mode** (no `line`/`column`) returns the map's structure:

* the decoded mapping **segments** (generated line/column ↔ original
  source index/line/column, plus optional name index), bounded;
* the **sources** list (joined with `sourceRoot` when present), the
  **names** list, and truncation flags for each;
* an evidence record (`source: sourcemap`, `method:
  base64_vlq_decode`) at `high` confidence.

**Trace mode** (`line` and `column`, both 0-based generated
coordinates, always passed together) finds the nearest mapping **at or
before that column on that line** and returns the original file path,
line, column and symbol name when a name exists. A position with no
preceding mapping is an honest `hit=false` result — never an error.
Trace evidence is `method: vlq_trace`, `high` confidence.

Malformed maps — bad JSON, `version != 3`, an invalid VLQ digit run,
an index outside the sources/names tables — are typed
`AnalysisError`s, never guessed around.

## Usage

```json
{"path": "bundle.js.map"}
{"path": "bundle.js.map", "line": 128, "column": 40117}
```

Python surface:

```python
from codevanta.analysis.sourcemap import decode_source_map, trace_position

report = decode_source_map(data)
print(report.sources, report.segment_count, report.truncated)
hit = trace_position(data, 128, 40117)
if hit["hit"]:
    print(hit["source"], hit["line"], hit["column"], hit.get("name"))
```

## Bounds and confidence

Every bound that fires is reported through `truncated` flags or
warnings — never silently.

| Bound | Default | Effect |
|-------|---------|--------|
| Mapping segments kept | 20 000 | decoding continues past the cap is stopped; `truncated: true` |
| Sources kept | 512 | further sources dropped; flag |
| Names kept | 512 | further names dropped; flag |
| Name/source length | 128 chars | longer entries clipped |
| Map size | 64 MiB | larger maps are a typed error ("source map too large") |
| File read | 256 MiB | the shared read cap; larger files refused before decoding |

| Finding | Confidence | Why |
|---------|------------|-----|
| A decoded segment row | `high` | deterministic base64-VLQ arithmetic over the map's own bytes |
| A `hit=true` trace | `high` | the mapping at-or-before the position, read from the decoded table |
| A `hit=false` trace | not a finding | honest absence — no mapping precedes that column |

## Limitations

* Trace mode resolves to the **nearest preceding** mapping on the
  line, which is what the v3 format guarantees — not an exact-column
  match; the returned original column is the mapping's own.
* Index-map (`sections`) composition and inline `sourceMappingURL`
  lookup are out of scope: pass the `.map` file itself.
* `sourcesContent` is summarised, not echoed — the tool points at
  sources, it does not re-embed them.
* The segment cap means gigantic bundles trace correctly only within
  the decoded prefix; the `truncated` flag states when the cap fired,
  and a trace beyond it reports `hit=false` rather than a wrong name.

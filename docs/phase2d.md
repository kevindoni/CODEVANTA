# Phase 2d — Offline HTML/SVG Graph Viewer

Phase 2d adds a fourth rendering of the call graph. `to_html` turns the same
`{nodes, edges}` model that `to_dot` and `to_graphml` already serialize into a
single self-contained HTML5 document with an inline SVG view. The file references
no CDN, web font, external stylesheet, image or script file and contains no
JavaScript logic, so it opens offline — from disk, a USB stick, or an air-gapped
host.

| Module | What changed |
|--------|--------------|
| `src/codevanta/analysis/graph_export.py` | `validate_graph` is now public: the DOT/GraphML checks return a normalized, sorted copy so other renderers reuse one contract |
| `src/codevanta/analysis/html_view.py` | New `to_html` — HTML5 document, inline CSS, three-column inline SVG, collapsible edge table, JSON payload |
| `src/codevanta/cli/main.py` | `codevanta callgraph --format html` (with `--output`/`-o`) |
| `tests/test_html_view.py` | Document structure, offline guarantees, escaping, layout, determinism, caps |

Nothing is executed and no memory is read: the viewer only draws a graph the
analysis already produced. The library returns a string; the CLI writes it only
when `--output` is given.

**Status:** in progress. The viewer is a static layout — no pan/zoom, no search,
no filtering, no per-node expansion, no debugger — see [Limitations](#limitations).

## Usage

```powershell
codevanta callgraph C:\Windows\System32\notepad.exe --format html -o callgraph.html
Invoke-Item callgraph.html
```

`--format` defaults to `json`; `html` joins `dot` and `graphml` as a *rendering of
the graph model*, while `json` serializes the analysis payload
(`CallGraph.to_dict()`). The same bounded analysis options apply to every format:

| Option | Default | Effect |
|--------|---------|--------|
| `--limit-functions` | 2000 | Maximum function candidates kept as nodes |
| `--limit-edges` | 20000 | Maximum call edges reported |
| `--format` | `json` | `json`, `dot`, `graphml` or `html` |
| `--output` / `-o` | stdout | Destination file for the rendered document |

With `-o` the CLI writes the document and prints the summary plus any analysis
warnings:

```text
graph written: callgraph.html
nodes: 635 · edges: 60 · truncated: yes · format: html
warning: edge limit reached (max_edges=60); later edges were dropped
warning: caller attribution failed for 60 call site(s); the call address itself
is used as the edge source for those edges
```

Use `-o` rather than shell redirection: the document and the trailing summary
line are both printed to the terminal when `--output` is omitted, so `>` would
append the summary to the captured file.

The same renderer is available as a function, for any producer that can describe
its graph as `{nodes, edges}`:

```python
from pathlib import Path

from codevanta.analysis.html_view import to_html

document = to_html({"nodes": [...], "edges": [...]}, title="callgraph notepad.exe")
Path("graph.html").write_text(document, encoding="utf-8")
```

`to_html` validates, normalizes, and renders — it returns the document string and
never writes a file itself.

## Document anatomy

The output is newline-separated and newline-terminated, in this order:

1. `<!DOCTYPE html>`, `<html lang="en">`, `<head>` with `<meta charset="utf-8">`,
   a viewport meta, the escaped title in `<title>` and the inline `<style>`.
2. `<header>` with the escaped title in `<h1>` and the counts
   `<span class="nodes">695 nodes</span> <span class="edges">60 edges</span>`
   (naively pluralized: `1 node`, `0 edges`).
3. `<svg class="graph" viewBox="0 0 980 H" role="img" aria-label="Graph of nodes and edges">`
   (width is fixed at 980 user units, height `H` follows the tallest column)
   containing `<defs>` with the single arrow marker, the three column headings,
   one `<g class="edges">` group, then one `<g class="nodes">` group.
4. `<details class="edges">` with `<summary>Edges (N)</summary>` and a
   `# | source | target | label` table listing every edge.
5. `<script type="application/json" id="codevanta-graph">` holding the normalized
   graph.
6. `</body>`, `</html>`.

Rendering details:

- **Node box** — a 220×40 rounded rectangle (`rx="6"`), the label centred in the
  upper half, the `kind` as a 10 px caption beneath it, and a `<title>` carrying
  the raw node id. A blank label falls back to the id; a blank `kind` emits no
  caption.
- **Edge** — a straight `<line class="edge">` from one box border to another,
  ending in the shared arrow marker (`marker-end="url(#arrow)"`), with a
  `<title>` tooltip reading `source -> target (label)`.
- **Column colours** — left column blue, middle teal, right violet; the palette
  is dark (`color-scheme: dark`) and fully inline.
- **Payload** — compact, `sort_keys=True`, `ensure_ascii=True` JSON of
  `{title, nodes, edges}`. `</` is written as `<\/` so no label can terminate the
  script element. Nothing reads this payload: it exists so the raw data travels
  with the picture.

## Three kind-based columns

Nodes are placed by `kind` (trimmed, case-insensitive); the column is the outer
sort key, so the graph reads left to right as *code → call sites → everything
else*:

| Column | Heading | `kind` values |
|--------|---------|---------------|
| Left | `function / entry_point` | `function`, `entry_point` |
| Middle | `call_site` | `call_site` |
| Right | `import / external / other` | `import`, `external`, and any other or missing `kind` |

Inside a column, nodes are ordered by a fixed kind rank (`entry_point` 0,
`function` 1, `call_site` 2, `import` 3, `external` 4, unknown 9) and then by
`id`, stacked downwards at a 40 px box plus a 24 px gap. Edges are ordered by
`(source, target, label)` and drawn beneath the boxes. The result is
deterministic: identical content always produces byte-identical HTML regardless of
input order, so repeated runs are diffable and safe to commit.

**Placeholder nodes appear in the middle column.** `CallGraph.to_graph_model`
inserts a `call_site` node for every edge source that is a raw call address — a
call site whose caller could not be attributed. Those nodes are drawn like any
other, which is why the header node count can be larger than the `nodes:` figure
in the CLI summary while the edge counts match:

```text
$ codevanta callgraph app.exe --format html --output graph.html --limit-edges 60

# CLI summary (analysis counts)
nodes: 635 · edges: 60 · truncated: yes · format: html

# viewer header (rendered model)
695 nodes  60 edges
```

The 60 extra nodes are the 60 unattributed call sites named in the warning.

## Caps and sizing

- **One contract.** `to_html` validates through `validate_graph` first, so the
  accepted shape and every error message are identical to the DOT and GraphML
  exporters (`graph must be a dict`, `duplicate node id`, `not a known node id`,
  `max_nodes is N`, `>= 1`). A partially valid graph is never rendered.
- **Overflow is an error, not a truncation.** `to_html(graph, max_nodes, max_edges)`
  takes limits ≥ 1 (defaults `DEFAULT_MAX_NODES` 5000 and `DEFAULT_MAX_EDGES`
  20000) and raises `GraphExportError` when the graph is larger. The viewer never
  silently drops nodes or edges.
- **Size-derived caps in the CLI.** Each serializer is called with
  `max(DEFAULT_MAX_NODES, len(model["nodes"]))` and
  `max(DEFAULT_MAX_EDGES, len(model["edges"]))`, so a graph the analysis already
  accepted is never rejected downstream by an exporter default.
- **The real bound is the analysis budget.** `--limit-functions` (2000),
  `--limit-edges` (20000), and the xref scan's `max_bytes` budget cut the graph
  before rendering; a capped graph reports `truncated: yes` and its warnings on
  the CLI, but the HTML header shows only the counts it received.
- **Size follows the data.** Canvas width is fixed at 980 user units
  (2×40 margin + 3×220 box + 2×120 gap); canvas height grows with the tallest
  column. Output size is linear in nodes and edges — there is no pagination,
  clustering, or summarisation.

## Offline guarantees

The document is one file that depends on nothing else:

- No `http://` or `https://` substring anywhere — no CDN, no schema location, no
  web font, no analytics.
- No `<link>`, no `@import`, no `src=` and no `href=` (so no external image,
  stylesheet, or `<script src>`).
- The only `<script>` element is `type="application/json"` — data, not code. The
  viewer runs no JavaScript at all.
- The `<svg>` deliberately omits `xmlns` (itself an `http` reference). That is
  correct for an SVG inlined in HTML5, and it means the fragment is **not** a
  standalone `.svg` file.
- Fonts come from the system stack (`ui-sans-serif`, `system-ui`, `"Segoe UI"`,
  `Roboto`, `Arial`, `sans-serif`); no image, cookie, or storage is used.

Every graph-supplied string — node ids, labels, kinds, edge endpoints and labels,
the page title, and the edge-table cells — is escaped with
`html.escape(..., quote=True)`, and the JSON payload defuses `</`. A label
containing `<script>` or `&` is therefore shown as text, never interpreted.

## Empty and edge cases

- **Empty graph** — still a complete document: `0 nodes`, `0 edges`, a
  "no nodes to display" caption in the SVG, a `no edges` row in the table, and no
  edge lines.
- **Long labels** — display is truncated at 34 characters with an ellipsis; the
  JSON payload keeps the full text.
- **Blank title** — falls back to `CODEVANTA graph`; a non-`str` title raises
  `GraphExportError`. The CLI always passes `callgraph <file name>`.

## CLI examples

```powershell
# whole graph as one offline HTML viewer
codevanta callgraph C:\Windows\System32\notepad.exe --format html -o callgraph.html

# smaller, readable viewer for a large target
codevanta callgraph C:\Windows\System32\notepad.exe --format html `
  --limit-functions 40 --limit-edges 60 -o callgraph-small.html

# the same graph in the other renderings
codevanta callgraph samples\elf64_text.bin --format dot -o callgraph.dot
codevanta callgraph samples\elf64_text.bin --format graphml -o callgraph.graphml
codevanta callgraph samples\elf64_text.bin --format json -o callgraph.json

# open the offline viewer
Invoke-Item callgraph.html
```

A target that produces a single callable and no resolved calls still yields a
usable document (one node, `0 edges`), which is the honest result for a minimal
sample such as `samples\elf64_text.bin`.

## Payload shape

The embedded JSON is the normalized graph plus the title:

```json
{"edges":[],"nodes":[{"id":"0x401000","kind":"entry_point","label":"sub_401000"}],"title":"callgraph elf64_text.bin"}
```

Keys are sorted, the encoding is compact, and non-ASCII text is written as
`\uXXXX` escapes, so the payload parses identically on any machine and can be
extracted again from an archived HTML file without re-running the analysis.

## Limitations

- **Static layout.** Three columns of fixed 220×40 boxes, one node per row, no
  force-directed placement, no crossing minimisation, and no edge bundling.
- **Not interactive.** There is no JavaScript: no pan, no zoom, no search, no
  filtering by `kind` or confidence, no collapse/expand of nodes, and no hover
  highlighting beyond the browser's own tooltips (`<title>` elements). The only
  control is the `<details>` edge table, which is native HTML — it opens all
  edges at once, not per node.
- **No web server and no debugger.** The viewer is a file opened from disk; it
  does not load the target, resolve addresses, fetch anything, or expose a UI the
  analysis can answer queries from. Static analysis only — the binary is never
  executed and no memory is inspected.
- **Dense graphs overlap.** Edges are straight lines between box borders, so
  edges between two nodes of the same column run along the outer border and cross
  other boxes, and many edges can leave one box at the same point. A crowded
  column makes the canvas taller rather than wrapping into a grid.
- **Large graphs stay linear but become unreadable.** Output is proportional to
  node and edge count, yet thousands of boxes are not a picture; the
  `--limit-functions` / `--limit-edges` budgets, not the layout, are the real
  safeguard.
- **Display truncation and raw control characters.** Labels longer than 34
  characters are cut for display only (the payload keeps them whole), and control
  characters or lone surrogates in graph text are not stripped — unlike the
  GraphML exporter, which must satisfy XML 1.0. Browsers render them harmlessly.
- **Inline-only SVG.** Without `xmlns`, the `<svg>` fragment cannot be saved as a
  standalone `.svg` file.
- **Call-graph semantics are unchanged.** Everything in
  [docs/phase2c.md](phase2c.md) still applies: a `call_import` / `call_indirect`
  target is the pointer slot, not the callee; `call_import` naming is an address
  equality inference; caller attribution is the nearest candidate at or below the
  call site, and unattributable sites become `call_site` placeholders. The viewer
  draws what the analysis proved — it adds no resolution of its own.

## Next steps

1. Node aggregation for dense columns (fold repeated `external` nodes into one
   summed box) so a large graph stays legible without changing the analysis.
2. Optional `.svg` export with a namespace declaration, for embedding the same
   picture in reports and tickets.
3. Per-node evidence in the payload — address, confidence, and source — so a
   viewer file carries the same provenance the JSON report does.
4. Deep links from a node box into the report, a session annotation, or an
   address lookup, keeping the document a static file.
5. Pan/zoom, search, and kind filters. These are the first features that would
   need JavaScript; today the payload travels with the file but nothing reads it,
   so an interactive viewer remains deliberate later-phase work.
6. A debugger remains out of scope: nothing here executes or attaches to the
   target.

## Verification

```powershell
python -m pytest
ruff check src tests
```

Phase 2d behavior is covered by `tests/test_html_view.py`: HTML5 document
structure and inline style/SVG, the absence of any external reference
(`http://`, `https://`, `//cdn`, `@import`, `<link>`, `src=`, `href=`, `xmlns`),
escaping of ids/labels/titles, the header counts and their pluralization, the
empty-graph document, three-column routing and ordering, column headings,
label/kind rendering and truncation, the arrow marker, the `<details>` edge table,
byte-identical determinism across reordered input, the JSON payload round-trip and
its `</` defanging, `max_nodes`/`max_edges` overflow, every shared validation
error, and the single-name public surface (`__all__ == ["to_html"]`).
`tests/test_cli_phase2d.py` covers the CLI path: `--format html` to stdout starts
with the doctype, contains an inline `<svg>` and no `http(s)` reference, and
`-o FILE` writes the document while printing only the `graph written` summary.


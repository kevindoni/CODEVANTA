# Phase 2b — Call Graphs, Graph Export, and Session Annotations

Phase 2b turns the phase 2 building blocks (cross-references, linear-sweep CFG,
SQLite sessions) into analyst-facing capabilities:

| Module | What it does |
|--------|--------------|
| `src/codevanta/analysis/callgraph.py` | Aggregates direct `call` cross-references into a node/edge call graph |
| `src/codevanta/analysis/graph_export.py` | Renders the generic graph model as Graphviz DOT or GraphML |
| `src/codevanta/storage/session.py` | Adds per-address annotations to stored sessions |
| `src/codevanta/mcp_server/tools.py`, `server.py` | Exposes xrefs, CFG, and session save/list over MCP (nine tools at the end of phase 2b; phase 2c adds `codevanta_callgraph` for ten) |
| `src/codevanta/cli/main.py` | Adds `callgraph` and `session annotate|notes` |

Everything here remains read-only with respect to the analysed target: bytes are
read from disk and decoded, nothing is loaded into a process or executed.

**Status:** in progress. There is no web viewer, no graph UI, and no debugger
yet, and the call graph contains direct calls only — see
[Limitations](#limitations).

## Delivered scope

### Call graph (`analysis/callgraph.py`)

`build_call_graph(path, info, functions=None, max_functions=2_000, max_edges=20_000)`
filters, attributes, and deduplicates what the phase 2 xref scan already proved.
It does not disassemble anything itself.

**Nodes**

- One node per function candidate (from `discover_functions`, or the injected
  `functions` list). Duplicate candidates at the same address collapse to one
  node; the highest-confidence candidate wins.
- `kind` is `entry_point` when the candidate address equals `info.entry_point`,
  otherwise `function`.
- `label` is the candidate name, or the synthesized `sub_<hex>` when the
  candidate has no name.
- `confidence` is the candidate's own confidence (`high`, `medium`, `low`,
  `unknown`) as a plain string — the call graph does not upgrade it.
- A direct call target that is **not** a known candidate becomes an `external`
  node with label `external_<hex>` and confidence `unknown`. External nodes are
  how out-of-scope targets (thunks, imports, code the discovery heuristics
  missed) stay visible without pretending they are analysed functions.

**Edges**

- Only cross references whose `kind` is `"call"` become edges. `jump` and
  `branch` references are not call graph edges.
- Each edge records `source` (the attributed caller), `target` (the callee
  address read from the operand), `from_address` (the virtual address of the
  calling instruction), and `label` (`"call"` for every edge produced here).
- Edges are deduplicated by `(source, target, from_address)` and sorted by
  `(source, from_address)`. Two different call sites between the same pair of
  nodes therefore remain two edges — the graph is per call site, not a
  collapsed multi-edge count.

**Caller attribution is a heuristic**

The xref layer records the address of the calling *instruction*, not the
enclosing function. No function boundary data is trusted, so a call site is
attributed to the **nearest function candidate whose address is at or below the
call address inside the same section** — the candidate that most plausibly owns
that address. Consequences:

- Attribution never crosses a section boundary.
- A call site below the first candidate of its section has no owner. The call
  address itself is then used as the edge source and a single aggregated
  warning reports how many call sites could not be attributed.
- Candidates nested inside another function (or data labelled as a function)
  can steal attribution from the real caller.

**Limits**

- `max_functions` and `max_edges` accept `1 .. 200_000`; anything else raises
  `AnalysisError`.
- When more candidates exist than `max_functions`, the lowest-address
  candidates are kept, the graph is marked `truncated`, and calls to a dropped
  candidate degrade to `external` nodes.
- Edges are deduplicated and sorted *before* the `max_edges` cut, so the kept
  edges are the first ones in `(source, from_address)` order.
- A truncated underlying xref scan also marks the graph `truncated`.

**Serialization**

`CallGraph.to_dict()` returns the analysis payload: `node_count`, `edge_count`,
`nodes`, `edges`, `truncated`, `warnings`, and the graph-level `evidence`.
Addresses are rendered as `0x...` strings.

`CallGraph.to_graph_model()` returns the generic, renderer-neutral model used by
the exporters:

```python
{
    "nodes": [{"id": "0x401000", "address": "0x401000", "label": "main",
               "kind": "entry_point", "confidence": "high"}],
    "edges": [{"source": "0x401000", "target": "external:0x401100",
               "from_address": "0x401010", "label": "call"}],
    "truncated": False,
}
```

Node ids are `0x<addr>` for candidate nodes and `external:0x<addr>` for external
nodes. An edge endpoint without a node falls back to `0x<addr>`, or
`unresolved` when the address is unknown, so an unattributed call site can
reference an id that has no node.

### DOT and GraphML export (`analysis/graph_export.py`)

`to_dot(graph, title="CODEVANTA graph", max_nodes=5_000, max_edges=20_000)` and
`to_graphml(...)` render the generic graph model with the standard library only.
The module imports no CODEVANTA code, so the call graph, the CFG, and future
viewers share one renderer.

- **Input contract:** every node needs a non-blank unique string `id` and a
  string `label`; `kind` is optional. Every edge needs `source` and `target`
  referencing existing node ids; `label` is optional and defaults to `"call"`.
- **Fail closed:** any contract violation raises `GraphExportError`, including
  duplicate ids and graphs larger than `max_nodes` / `max_edges`. A partially
  valid graph is never rendered, and oversized graphs are an error rather than
  a silent truncation.
- **Deterministic:** nodes are emitted sorted by `id` and edges by
  `(source, target, label)`, so identical content produces byte-identical
  output regardless of insertion order.
- **DOT:** a `digraph "<title>" { ... }` with a graph label; node ids and labels
  are double-quoted and escaped (`"`, `\`, newline, carriage return, tab).
  Nodes whose `kind` is `function` or `entry_point` are drawn as `box`,
  everything else as `ellipse`. Every edge carries a quoted label.
- **GraphML:** a valid XML 1.0 document with the GraphML namespace and schema
  location, `key` declarations for the node `label` (`d0`), node `kind` (`d1`),
  and edge `label` (`d2`), a directed `graph` (`id="G"`), one `node`/`edge`
  element per item, and a `desc` element holding the title.
- **Unrepresentable characters:** characters that cannot appear in the output
  format (C0 controls other than tab/newline, lone surrogates, `U+FFFE`/`U+FFFF`)
  are replaced with `U+FFFD` instead of corrupting the document.

Both functions only *return* a string; nothing is written to disk. The CLI
decides whether to print the payload or save it with `--output`.

### Session annotations (`storage/session.py`)

Annotations are free-text notes attached to one address inside a stored session,
kept in an `annotations` table keyed by `(session_id, address)`.

- `annotate(session_id, address, note)` upserts one note per address. Saving
  again for the same address **replaces** the note and refreshes `created_at`
  instead of appending a second row.
- Validation: `address` must be a non-negative integer (booleans are rejected),
  `note` must be a non-blank string of at most 4,000 characters, and the session
  must already exist — otherwise `SessionError`.
- `annotations(session_id)` returns every note for the session ordered by
  address ascending, and raises `SessionError` for an unknown session.
- `remove_annotation(session_id, address)` returns `True` when a note was
  deleted and `False` otherwise, so unknown sessions and addresses are
  idempotent rather than errors.
- `Annotation.to_dict()` renders the address as `0x...` hex alongside
  `session_id`, `note`, and `created_at` (UTC ISO-8601).

Annotations hang off a stored session id, not off a file path, so they stay
attached to the snapshot they were written for. There is no annotation MCP tool
and no `remove` CLI command yet; re-annotating the same address is how you edit
a note from the CLI.

### MCP server: nine tools

The stdio server now registers nine tools. Phase 1 tools are unchanged
(`codevanta_info`, `codevanta_functions`, `codevanta_strings`,
`codevanta_disasm`, `codevanta_analyze`); phase 2b adds four:

| Tool | Arguments | Returns |
|------|-----------|---------|
| `codevanta_xrefs` | `path`, `limit=200`, `max_bytes=4_000_000` | `count`, `returned`, `truncated`, `items`, `scanned_bytes`, `warnings` |
| `codevanta_cfg` | `path`, `address=None`, `function=None`, `max_instructions=2_000`, `max_blocks=500` | `start`, `blocks`, `instruction_count`, `truncated`, `warnings` |
| `codevanta_session_save` | `path`, `db=None`, `notes=None` | `session`, `db` |
| `codevanta_session_list` | `db=None`, `limit=20` | `count`, `items`, `db` |

- `codevanta_xrefs` caps `limit` at 200,000 and `max_bytes` at 64,000,000; a
  truncated scan sets `truncated`.
- `codevanta_cfg` resolves `address`/`function` the same way the CLI does and
  falls back to the entry point; `max_instructions` and `max_blocks` are capped
  at 100,000. Block boundaries remain heuristic.
- `codevanta_session_save` loads the binary, counts function candidates and
  strings (`min_length=4`), and persists one additive record.
- `codevanta_session_list` returns newest-first records, capped at `limit`
  `1 .. 10_000`.
- Session database resolution is shared: an explicit `db` wins, then
  `$CODEVANTA_DB`, then `~/.codevanta/sessions.db`.
- No MCP tool exposes the call graph, DOT/GraphML export, or annotations yet.

## CLI examples

```powershell
# Call graph as the analysis payload (default --format json)
codevanta callgraph C:\Windows\System32\notepad.exe

# Render Graphviz DOT or GraphML for an external renderer
codevanta callgraph C:\Windows\System32\notepad.exe --format dot > callgraph.dot
codevanta callgraph C:\Windows\System32\notepad.exe --format graphml -o callgraph.graphml

# Tighten the budgets on a large binary
codevanta callgraph C:\Windows\System32\kernel32.dll --limit-functions 500 --limit-edges 2000 --format json
```

`callgraph` prints the payload (or writes it with `--output` / `-o`) followed by
a dim summary line — nodes, edges, truncation state, and format — and prints
each graph warning. `--format dot` and `--format graphml` render
`to_graph_model()`; `--format json` emits `to_dict()`. Export and analysis
failures exit with code 2.

```powershell
# Persist a snapshot, then annotate addresses inside it
codevanta session save samples\sample.exe --notes "baseline triage"
codevanta session list
codevanta session show 4f9c1a7b2d3e

# Annotations: address accepts decimal or 0x-prefixed hex
codevanta session annotate 4f9c1a7b2d3e 0x401000 "decrypts config with XOR 0x5a"
codevanta session annotate 4f9c1a7b2d3e 4198400 "same site, decimal form"
codevanta session notes 4f9c1a7b2d3e

# Point every session command at a specific database
codevanta session notes 4f9c1a7b2d3e --db .\triage.db
```

`session notes` prints an `Address` / `Note` / `Created` table ordered by
address, or a friendly message when the session has no notes. Every `session`
subcommand accepts `--db`, and an invalid address or unknown session exits with
code 2.

## Evidence and confidence semantics

Evidence answers "how was this produced", confidence answers "how much should I
trust it". The call graph is deliberately `medium`: every edge is a decoded
direct call, but the *edge owner* is inferred.

| Finding | `source` | `method` | Confidence | Why |
|---------|----------|----------|------------|-----|
| Whole call graph | `callgraph.direct_calls` | `xref_aggregation` | `medium` | Calls are read directly from operands, but caller attribution is a nearest-preceding-candidate heuristic |
| Call graph node | inherited from the candidate (`export`, `symbol`, `entry_point`) | — | candidate's own (`high` / `medium` / `low`) | Node confidence is the function candidate's confidence, not a graph-level verdict |
| External node | — | — | `unknown` | The address is a call target only; no function was detected there |
| Call graph edge | — | — | — | Edges carry no separate evidence; they inherit the graph-level record plus `from_address` |
| DOT / GraphML output | — | — | — | Rendering only; formatting cannot add or remove certainty |
| Annotation | — | — | — | Analyst-supplied text stored verbatim; no analysis claim is made |

Practical reading: an edge at `0x401000 -> 0x401040` means "some direct call
instruction at `from_address` targets `0x401040`, and the nearest candidate at or
below it in that section is `0x401000`". It does **not** mean the caller's
function body has been proven to start there. Treat nodes as candidates (as
everywhere else in CODEVANTA), not as verified function boundaries, and check
the warnings before trusting attribution on an unfamiliar binary.

## Limitations

- **Direct calls only.** `call rax`, `call qword ptr [...]`, jump tables, and
  import thunks are not resolved, so they never become edges. Tail calls written
  as `jmp` are not call edges either.
- **Caller attribution is heuristic.** Edges are attached to the nearest
  function candidate at or below the call site in the same section. With
  overlapping or misdetected candidates, a call can be attributed to the wrong
  owner; call sites below the first candidate are attributed to the call address
  itself and reported as warnings. There is no proven function-boundary model.
- **No recursive traversal.** The graph is not built by walking callees, and
  CFGs are still single-region linear sweeps — no per-function graph joins, no
  code/data disambiguation.
- **No indirect-call resolution.** Dynamic dispatch, vtables, and
  register-indirect calls are invisible, so dynamic behaviour is
  under-represented by design rather than guessed at.
- **Everything is bounded.** `max_functions`, `max_edges`, `max_bytes`,
  `max_instructions`, `max_blocks`, and `limit` cut work short on large inputs.
  Check `truncated` and `warnings` before treating a result as complete.
- **Export is strict, not forgiving.** Graphs larger than `max_nodes` /
  `max_edges` raise `GraphExportError` instead of being truncated, and malformed
  input raises rather than rendering a partial graph.
- **No layout in exports.** DOT and GraphML contain no coordinates; an external
  renderer (`dot`, Gephi, yEd, …) supplies layout. GraphML stores node ids in XML
  attributes, and attribute-value normalization turns tabs/newlines inside an id
  into spaces, so such ids do not round-trip byte-exactly (labels still do).
- **No web viewer and no graph UI.** Output is CLI tables, JSON, DOT, and
  GraphML only.
- **No debugger.** Phase 2b is static analysis; the target is never executed.
- **Annotations are CLI/API only.** There is no annotation MCP tool, no
  annotation export into the JSON report, and no bulk edit; notes are edited by
  re-annotating the same address. Deleting a note is only available through the
  Python API (`SessionStore.remove_annotation`).
- **Sessions and annotations are local and shallow.** One local SQLite file,
  SQLite-default locking, no concurrency model, and no schema migration yet.
- **MCP coverage is partial.** Xrefs, CFG, and session save/list are exposed;
  the call graph, graph export, and annotations are not.

## Next steps

1. Indirect-target resolution: import thunks, `call qword ptr [...]`, and jump
   tables, so dynamic-call edges stop disappearing.
2. Recursive descent with function-boundary detection, so caller attribution can
   be replaced by real function extents instead of a nearest-preceding-candidate
   heuristic.
3. Per-function CFG aggregation onto the call graph, so a node can expand into
   its own block graph.
4. MCP tools for the call graph and DOT/GraphML export, and for annotations, so
   coding agents see the same surface as the CLI.
5. Annotation ergonomics: `session notes remove`, annotation export alongside
   the JSON report, and schema versioning/migrations for the session database.
6. A graph-oriented viewer and a debugger backend — both are later-phase work,
   not part of what is delivered here.

## Verification

```powershell
python -m pytest
ruff check src tests
```

Phase 2b modules are covered by `tests/test_callgraph.py`,
`tests/test_graph_export.py`, `tests/test_session.py` (annotations),
`tests/test_mcp_tools.py` (nine tools), and `tests/test_cli_phase2b.py`.


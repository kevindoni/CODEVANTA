# Phase 2c — Import and Indirect Call Resolution, Embedded Call Graphs, MCP Call Graph

Phase 2c widens the call-graph view without weakening the evidence rules. Before
2c, only direct `call`/`jmp`/`branch` operands were resolved and only direct calls
became graph edges, so any call through a pointer slot disappeared. This phase
resolves the pointer slot when its address is statically encoded in the operand,
labels calls through import slots with the imported name, and exposes the graph
over MCP.

| Module | What changed |
|--------|--------------|
| `src/codevanta/analysis/xrefs.py` | Resolves `call [rip+disp]` and `call [abs]` slots into `call_import` / `call_indirect` xrefs; counts skipped indirect calls |
| `src/codevanta/analysis/callgraph.py` | Edges now come from `call`, `call_import` and `call_indirect`; import slots become `import` nodes labelled from the import table |
| `src/codevanta/core/report.py` | `include_callgraph` embeds a bounded graph (1000 functions / 5000 edges) in the JSON report |
| `src/codevanta/cli/main.py` | `codevanta analyze --callgraph` |
| `src/codevanta/mcp_server/tools.py`, `server.py` | `codevanta_callgraph`, for ten MCP tools total |

Everything here remains read-only with respect to the analysed target: bytes are
read from disk and decoded, nothing is loaded into a process or executed, and no
memory contents are dereferenced.

**Status:** in progress. Register-targeted and indexed-indirect calls are still
unresolved, there is no recursive traversal, and there is no web viewer or
debugger — see [Limitations](#limitations).

## Delivered scope

### 1. Memory-operand call resolution (`analysis/xrefs.py`)

`find_xrefs` still reports every direct transfer first; for a `call` it then tries
to resolve a pointer slot. Three operand shapes can produce a reference:

| Operand shape | Example | `kind` | `to_address` | Evidence source | Confidence |
|---------------|---------|--------|--------------|-----------------|------------|
| Direct literal | `call 0x401010` | `call` | the callee | `capstone.direct_call` | `certain` |
| Absolute slot | `call qword ptr [0x402000]` | `call_import` / `call_indirect` | the slot | `capstone.import_call` / `capstone.indirect_call` | `certain` / `high` |
| RIP-relative slot | `call qword ptr [rip + 0xa]` | `call_import` / `call_indirect` | the slot | `capstone.import_call` / `capstone.indirect_call` | `certain` / `high` |

**The reported target is always the pointer slot, never the callee.** The pointer
is loaded from memory at run time, so the callee is unknowable from the file
bytes alone. For `call_indirect` the slot address is proven by the decoded
operand, which is why the confidence stays `high` while the callee remains
unknown.

RIP-relative resolution uses the standard x86/x64 rule: the effective address is
the address of the *next* instruction (`instruction.address + instruction.size`)
plus or minus the encoded displacement, so `dword ptr [rip - 0xa]` resolves
backwards correctly.

Import naming is a single address-equality test: the resolved slot is looked up
in `info.imports`, and a match produces `kind="call_import"` with
`target_name` set to the import name and confidence `certain`. Imports whose
entry has no address or no name are ignored (they can never match). No match
produces `kind="call_indirect"` with no `target_name`. A direct literal operand
always wins: import matching is only attempted when the operand is not already a
literal address.

Everything else stays unresolved rather than guessed:

- `call rax`, `call qword ptr [rax + 8]`, `call qword ptr [rax + rcx*8]` — the
  slot address is not statically known, and the operand text does not match the
  sized-pointer pattern.
- An unsized memory operand (no `byte|word|dword|qword ptr` prefix) — the shape,
  not the address, is what fails to match.

Those skipped **calls** are counted in `indirect_skipped` so callers can see how
much of the call graph was left unresolved. Indirect `jmp` and conditional
branches that cannot be resolved are *not* counted: the counter exists to size
call-graph incompleteness, and a skipped jump is not a missing call edge.

`XrefResult.to_dict()` exposes `indirect_skipped` alongside `xref_count`,
`xrefs`, `scanned_sections`, `scanned_bytes`, `truncated`, `warnings`, and
`evidence`; each xref carries `target_name` only when the call went through a
known import. The scan stays bounded by `max_bytes` (`DEFAULT_MAX_BYTES` is
4,000,000; the MCP tool caps it at 64,000,000).

### 2. Call graph over call, import, and indirect edges (`analysis/callgraph.py`)

`build_call_graph` still only filters, attributes, and deduplicates what the xref
scan already proved — it does not disassemble anything itself. Three xref kinds
now become edges:

| Xref kind | Node kind for the target | Node label | Node confidence |
|-----------|--------------------------|------------|-----------------|
| `call` (known candidate) | `function` / `entry_point` | candidate name or `sub_<hex>` | the candidate's own confidence |
| `call` (unknown address) | `external` | `external_<hex>` | `unknown` |
| `call_import` | `import` | the import name (or the slot hex when the name is missing) | `high` |
| `call_indirect` | `external` | `external_<hex>` | `unknown` |

Import nodes are keyed by the slot address and labelled from the import table
(`xref.target_name`), so a call through the IAT of a known import reads as
`import` rather than as an opaque external address. A `call_indirect` node stays
`external` with `unknown` confidence: the slot is certain, the callee is not.
`jump` and `branch` references, and indirect calls whose slot is not statically
known, still produce no edge.

Edges keep the phase 2b contract: `source` is the attributed caller, `target` is
the callee or slot, `from_address` is the calling instruction's virtual address,
and `label` is always `"call"` (import naming lives on the target node, not on the
edge). Edges are deduplicated by `(source, target, from_address)` and sorted by
`(source, from_address)`, so two distinct call sites between the same nodes stay
two edges.

**Caller attribution is still a heuristic.** The xref layer records the calling
instruction, not the enclosing function, so a call site is attributed to the
nearest function candidate whose address is at or below the call site inside the
same section. Attribution never crosses a section boundary, and a call site
below the first candidate of its section has no owner: the call address itself
becomes the edge source and one aggregated warning reports how many sites could
not be attributed. The graph's evidence detail restates all of this, together
with the node/edge counts and the import/indirect edge split, and the graph keeps
reporting `medium` confidence (source `callgraph.direct_calls`, method
`xref_aggregation`) for backward compatibility.

Bounds are unchanged in kind but matter more now that more calls resolve:
`max_functions` defaults to 2,000, `max_edges` to 20,000, and both accept
`1 .. 200_000`. Too many candidates keeps the lowest-address ones and drops the
rest (calls to dropped candidates degrade to `external` nodes); too many edges
sorts, then cuts. A truncated xref scan also marks the graph `truncated`. In the
generic graph model, import nodes are namespaced as `import:0x<addr>` and
external nodes as `external:0x<addr>` so a slot address can never collide with a
candidate id.

### 3. `codevanta analyze --callgraph`

`codevanta analyze` accepts a `--callgraph` flag:

- Without the flag the report matches the phase 2b payload — the `callgraph` key
  is absent, not empty.
- With the flag, `report["callgraph"]` holds `CallGraph.to_dict()`
  (`node_count`, `edge_count`, `nodes`, `edges`, `truncated`, `warnings`,
  `evidence`).
- The embedded graph is deliberately bounded to
  `REPORT_MAX_CALLGRAPH_FUNCTIONS` = **1000** nodes and
  `REPORT_MAX_CALLGRAPH_EDGES` = **5000** edges — well below the call-graph
  defaults — so a report stays a bounded payload. When either cap cuts the
  result, `report["callgraph"]["truncated"]` is `true`.
- Pre-computed function candidates are reused instead of rediscovering them, so a
  report never scans the binary twice for candidates.
- With `--output` a dim one-line summary is printed after the file is written:
  `callgraph: N nodes · M edges · truncated: yes|no`. Without `--output` the full
  JSON (including the graph) is printed to stdout.
- The analysis layer is imported lazily inside `build_report`, so
  `codevanta.core.report` still has no import-time dependency on
  `codevanta.analysis`.

The MCP `codevanta_analyze` tool does **not** take a call-graph flag: it returns
the phase 1 report. Agents use `codevanta_callgraph` instead (below).

### 4. MCP: ten tools, including `codevanta_callgraph`

The stdio server (`codevanta mcp serve`) now registers ten tools:

| Tool | Purpose |
|------|---------|
| `codevanta_info` | Format, architecture, sections, imports, exports, symbols |
| `codevanta_functions` | Function candidates with source and confidence |
| `codevanta_strings` | ASCII and UTF-16LE strings with offset and VA |
| `codevanta_disasm` | Disassemble the entry point, an address, or a function |
| `codevanta_analyze` | Full phase 1 JSON report with provenance |
| `codevanta_xrefs` | Cross references from executable sections |
| `codevanta_cfg` | Linear-sweep control-flow graph for one region |
| `codevanta_callgraph` | **New:** inter-function call graph |
| `codevanta_session_save` | Persist fingerprint and counts as a session |
| `codevanta_session_list` | List stored sessions, newest first |

`codevanta_callgraph(path, limit_functions=1000, limit_edges=5000)` returns
`CallGraph.to_dict()`. Both limits must be integers in `1 .. 200_000` (booleans
are rejected); a missing file or an out-of-range limit raises `AnalysisError`
with the offending argument named. The tool description states, in the payload
the agent reads, that edges come from direct calls plus resolved pointer-slot
calls, that caller attribution is heuristic, and that `truncated`/`warnings`
must be checked before treating the graph as complete.

Known gap: `codevanta_xrefs` returns `count`, `returned`, `truncated`, `items`,
`scanned_bytes`, and `warnings` — it does **not** surface `indirect_skipped`, and
the `codevanta xrefs` table shows kinds only. The counter is available in
`codevanta xrefs --json` and through `XrefResult.indirect_skipped` in Python.

## CLI examples

```powershell
# Resolve import and indirect call slots, and see what could not be resolved
codevanta xrefs C:\Windows\System32\notepad.exe --limit 40
codevanta xrefs C:\Windows\System32\notepad.exe --json | Select-String indirect_skipped

# Call graph with import nodes labelled from the import table
codevanta callgraph C:\Windows\System32\notepad.exe
codevanta callgraph C:\Windows\System32\notepad.exe --format dot -o callgraph.dot
codevanta callgraph C:\Windows\System32\notepad.exe --limit-functions 500 --limit-edges 2000

# One JSON report that already contains the bounded graph
codevanta analyze C:\Windows\System32\notepad.exe --callgraph -o report.json
```

## Payload shapes

A resolved import call inside an xref listing:

```json
{
  "from_address": "0x14000101a",
  "to_address": "0x14002d000",
  "kind": "call_import",
  "instruction": "call qword ptr [rip + 0x2fdfe5]",
  "source": "capstone.import_call",
  "target_name": "GetProcAddress",
  "evidence": { "source": "capstone.import_call", "method": "linear_disassembly", "confidence": "certain" }
}
```

The same call site as a call-graph edge, with the slot as an `import` node:

```json
{
  "nodes": [{ "address": "0x14002d000", "label": "GetProcAddress", "kind": "import", "confidence": "high" }],
  "edges": [{ "source": "0x140001000", "target": "0x14002d000", "from_address": "0x14000101a", "label": "call" }],
  "truncated": false
}
```

## Confidence and evidence

| Result | Source label | Confidence | Why |
|--------|--------------|------------|-----|
| xref scan as a whole | `capstone.xref_scan` | `certain` | every emitted reference is a read of decoded operands |
| `call_import` | `capstone.import_call` | `certain` | slot decoded from the operand, name corroborated by the import table |
| `call_indirect` | `capstone.indirect_call` | `high` | slot is proven, the callee behind it is not |
| call graph | `callgraph.direct_calls` | `medium` | calls are decoded, but caller attribution is a nearest-candidate heuristic |

Coverage is reported, never assumed: `truncated`, `warnings`, and
`indirect_skipped` are the fields to read before treating a result as complete.

## Limitations

- **No register-target resolution.** `call rax`, `call r8`, and virtual dispatch
  through registers are unresolved; they are counted in `indirect_skipped` and
  produce no edge.
- **No indexed or computed memory targets.** `call qword ptr [rax + 8]`,
  `[rbx + rcx*8]`, vtable walks, and jump tables do not match the sized-pointer
  pattern and stay unresolved. Only an absolute slot (`[0x...]`) or a
  RIP-relative slot (`[rip +/- 0x...]`) with an explicit `byte`/`word`/`dword`/
  `qword` size prefix resolves.
- **The slot is not dereferenced.** For `call_import` and `call_indirect` the
  reported target is the pointer slot, not the code behind it; the analyzer never
  reads the pointer's value, so "target" does not mean "callee".
- **`call_import` is an address-equality inference.** A slot that happens to
  share an address with an import entry is labelled with that import name. The
  import table is the only corroboration, and imports without an address or name
  can never match.
- **Caller attribution is heuristic.** Edges attach to the nearest candidate at
  or below the call site in the same section. Overlapping or misdetected
  candidates can attribute a call to the wrong owner; unattributable sites use
  the call address and raise one aggregated warning.
- **No recursive traversal.** The graph is not built by walking callees, and
  CFGs remain single-region linear sweeps — no per-function graph joins and no
  code/data disambiguation.
- **Tail calls are not call edges.** A `jmp` to another function stays a `jump`
  reference (or an unresolved indirect jump) and never becomes an edge.
- **Everything is bounded.** `max_bytes`, `max_functions`, `max_edges`, and the
  report's 1000/5000 caps cut work short on large inputs; a capped graph is
  marked `truncated`.
- **No web viewer and no debugger.** Output is CLI tables, JSON, DOT, and
  GraphML only; the target is never executed and no memory is inspected at run
  time.

## Next steps

1. Dereference resolved pointer slots where the slot holds a mapped, readable
   address, so a `call_import`/`call_indirect` can name the real callee instead of
   only the slot.
2. Resolve register and indexed-indirect targets through lightweight per-function
   value tracking, so `call qword ptr [rax + 8]` and simple vtables stop
   disappearing.
3. Recursive descent with function-boundary detection, replacing the
   nearest-preceding-candidate heuristic with real function extents.
4. Per-function CFG aggregation onto the call graph, so a node can expand into
   its own block graph.
5. Surface `indirect_skipped` in `codevanta_xrefs` and the xrefs table, and add a
   call-graph flag to `codevanta_analyze` so MCP clients can request the embedded
   graph directly.
6. A graph-oriented viewer and a debugger backend — later-phase work, not part of
   what is delivered here.

## Verification

```powershell
python -m pytest
ruff check src tests
```

Phase 2c behavior is covered by `tests/test_xrefs.py` (RIP-relative and absolute
import slots, negative displacements, unmapped slots, skipped-call counting,
`target_name` presence/absence), `tests/test_callgraph.py` (import and external
nodes, mixed edge ordering), `tests/test_report_callgraph.py` (the 1000/5000 caps,
lazy import, `analyze --callgraph` output and summary),
`tests/test_mcp_tools.py` (ten tools, `codevanta_callgraph`, rejected bounds), and
`tests/test_cli_phase2b.py`.


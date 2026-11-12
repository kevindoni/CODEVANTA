# Changelog

All notable changes to CODEVANTA are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Cross-reference scanner (`codevanta.analysis.xrefs`): `call`, `jump`, and
  `branch` references recovered from direct branch operands in executable
  sections. Targets that are only reachable through registers or memory are
  skipped rather than guessed. Every reference carries evidence
  (`capstone.direct_call` / `direct_jump` / `conditional_branch`, confidence
  `certain`), and the scan reports section coverage, scanned bytes, and whether
  it was truncated by the `max_bytes` budget.
- Control-flow graph builder (`codevanta.analysis.cfg`): linear sweep of one
  region into `BasicBlock`s with sorted, deduplicated successor edges derived
  from leader and terminator rules. Indirect branches stay unresolved; the
  sweep is bounded by `max_instructions` and `max_blocks` and is labelled
  `medium` confidence because block boundaries are heuristic.
- SQLite session storage (`codevanta.storage.session`): additive analysis
  records (fingerprint, format, architecture, bitness, entry point, function and
  string counts, notes) with `save`, `get`, `list`, and `delete`. Standard
  library only, parameterized SQL, bounded queries.
- CLI: `codevanta xrefs` (with `--limit`, `--max-bytes`, `--json`),
  `codevanta cfg` (with `--address`/`--function`, `--max-instructions`,
  `--max-blocks`, `--json`), and `codevanta session save|list|show` (with
  `--db`, defaulting to `$CODEVANTA_DB` or `~/.codevanta/sessions.db`).
- Direct-call call graph (`codevanta.analysis.callgraph`): `build_call_graph`
  aggregates the `call` cross references into `CallGraphNode` /
  `CallGraphEdge` records plus a generic `{nodes, edges}` model. Every call
  target that is not a known candidate becomes an `external` node, edges are
  deduplicated by `(source, target, from_address)` and bounded by
  `max_functions` / `max_edges`. Caller attribution is heuristic — the nearest
  function candidate at or below the call site inside the same section — so the
  graph reports `medium` confidence, uses the call address as the source for
  unattributable sites, and says so in `warnings`.
- Graph export (`codevanta.analysis.graph_export`): dependency-free `to_dot` and
  `to_graphml` render the shared graph model with deterministic ordering, strict
  contract validation (`GraphExportError`), escaped/quoted DOT strings, and a
  GraphML document with `label`/`kind`/edge-label keys. Output only — nothing is
  written to disk.
- Session annotations (`codevanta.storage.session`): `Annotation` records plus
  `annotate` (one upsertable note per `(session_id, address)`), `annotations`
  (ordered by address), and `remove_annotation`. Notes are bounded to 4,000
  characters, blank notes and unknown sessions raise `SessionError`.
- MCP tools: `codevanta_xrefs`, `codevanta_cfg`, `codevanta_session_save`, and
  `codevanta_session_list` join the five phase 1 tools, for nine tools total.
  Bounded arguments, shared database resolution (explicit `db`, then
  `$CODEVANTA_DB`, then `~/.codevanta/sessions.db`), and the same evidence
  semantics as the CLI.
- CLI: `codevanta callgraph` (with `--limit-functions`, `--limit-edges`,
  `--format json|dot|graphml`, `--output`/`-o`) and
  `codevanta session annotate SESSION_ID ADDRESS NOTE` /
  `codevanta session notes SESSION_ID` (decimal or `0x` hex addresses, `--db`).
- Import and indirect call resolution (`codevanta.analysis.xrefs`): `call`
  instructions through an absolute or RIP-relative pointer slot
  (`call qword ptr [0x402000]`, `call qword ptr [rip + 0xa]`) now resolve to the
  slot address — RIP-relative operands are biased by the instruction length, so
  negative displacements work. A slot that matches an `info.imports` address
  becomes `call_import` with `target_name` set to the import name and confidence
  `certain`; any other resolved slot becomes `call_indirect` with confidence
  `high` (the slot is proven, the callee is not). The reported `to_address` is
  always the slot, never the code behind it. Register and indexed operands
  (`call rax`, `call qword ptr [rax + 8]`) are skipped and counted in the new
  `XrefResult.indirect_skipped` field, which `to_dict()` exposes; indirect jumps
  and conditional branches are not counted. Direct literal operands still take
  precedence, and the scan stays bounded by `max_bytes`.
- Call graph coverage (`codevanta.analysis.callgraph`): edges now come from
  `call`, `call_import`, and `call_indirect` cross references. A resolved import
  slot becomes an `import` node labelled from the import table (`high`
  confidence, namespaced `import:0x<addr>` in the generic graph model), a
  `call_indirect` slot stays an `external` node (`unknown` confidence), and
  `jump`/`branch` references plus unresolved indirect calls still produce no
  edges. Edge deduplication, ordering, limits, and the heuristic caller
  attribution (nearest candidate at or below the call site in the same section,
  with one aggregated warning for unattributable sites) are unchanged.
- `codevanta analyze --callgraph`: embeds `report["callgraph"]` when the flag is
  passed and omits the key entirely when it is not. The embedded graph is bounded
  to 1000 functions and 5000 edges
  (`REPORT_MAX_CALLGRAPH_FUNCTIONS` / `REPORT_MAX_CALLGRAPH_EDGES`), reuses the
  pre-computed candidates, sets `truncated` when a cap cuts it short, and prints
  a one-line node/edge/truncation summary alongside `--output`. The analysis
  layer is imported lazily, so `codevanta.core.report` gains no import-time
  dependency on `codevanta.analysis`.
- MCP tool `codevanta_callgraph` (`limit_functions`, `limit_edges`, defaulting to
  1000 and 5000, accepted range 1..200000) joins the server, bringing it to ten
  tools. It returns `CallGraph.to_dict()` with nodes, edges, `truncated`,
  `warnings`, and evidence, and rejects non-integer or out-of-range limits with
  `AnalysisError`.
- Documentation: `docs/phase2c.md` covers import/indirect resolution, import
  nodes, the embedded report graph, the ten MCP tools, CLI examples, remaining
  limits, and next steps; the README now links `CONTRIBUTORS.md` from its
  Community section.
- `validate_graph` (`codevanta.analysis.graph_export`) is now public: the DOT and
  GraphML checks return a normalized, deterministically ordered copy, so other
  renderers reuse one contract instead of duplicating it.
- Offline HTML/SVG graph viewer (`codevanta.analysis.html_view`): `to_html`
  renders the shared graph model as one self-contained HTML5 document — inline
  stylesheet, inline SVG in three `kind`-based columns
  (`function`/`entry_point`, `call_site`, everything else), header node/edge
  counts, arrowed straight-line edges, a collapsible `<details>` table listing
  every edge, and an `application/json` payload of the normalized graph. It
  references no `http(s)` URL, CDN, web font or external file and shipped without
  JavaScript logic in its phase 2d form (phase 2f adds one inline script; see
  below), so it opens offline; the `<svg>` omits `xmlns` and is
  inline-only. Output is byte-identical for identical content.
- CLI: `codevanta callgraph --format html` (with `--output`/`-o`) joins
  `json|dot|graphml`. Every serializer now receives size-derived caps
  (`max(default, len(...))`), so a graph the analysis already accepted is never
  rejected downstream by an exporter default.
- Documentation: `docs/phase2d.md` covers the viewer, the three columns, document
  anatomy, caps and sizing, offline guarantees, limits, and next steps.
- Recursive CFG traversal (`codevanta.analysis.cfg`): new
  `build_recursive_cfg(path, info, start, max_instructions=2000, max_blocks=500)`
  returns the same `FunctionCFG` as `build_cfg`, but follows control flow from
  `start` with a worklist of block starts and a visited set instead of decoding a
  fixed window. Successors follow the block-terminating instruction: a
  conditional jump yields fallthrough plus its direct target, an unconditional
  `jmp` yields the target only, `ret`/`iret` yield none, and every other
  instruction (including `call`) yields fallthrough only. Call targets are not
  followed and indirect jumps are not resolved; direct targets outside executable
  sections are dropped and reported in `warnings`. Blocks and successors are
  sorted, the graph is bounded by `max_instructions` / `max_blocks` (with the
  existing `truncated` flag), and evidence uses `cfg.recursive_traversal` at
  `medium` confidence because indirect targets remain unresolved. Unreachable
  padding after a `ret` or `jmp` is no longer decoded.
- CLI: `codevanta cfg --traversal linear|recursive`. The default stays `linear`,
  so existing invocations, tables, and JSON output are unchanged; `recursive`
  selects `build_recursive_cfg` and reports the same payload with the
  `cfg.recursive_traversal` evidence source.
- Documentation: `docs/phase2e.md` covers the new traversal, its successor rules,
  how it differs from the linear sweep, the CLI flag, evidence and confidence,
  bounds, limitations, and next steps.
- Jump-table resolver (`codevanta.analysis.jump_tables`): `resolve_jump_table`
  decodes a bounded array of absolute pointers starting at a caller-supplied
  address — 8-byte slots on a 64-bit binary, 4-byte on a 32-bit one, decoded with
  the binary's endianness. The scan stops at the first slot that cannot be a
  target (zero terminator, target outside `min_target`/`max_target`, target no
  section maps, or — with the default `executable_only` — a target in a
  non-executable section) and records why in `warnings`. Work is bounded by
  `max_entries` (default 256, hard ceiling 4096) plus one pointer-sized peek that
  decides `truncated`. Slot and summary evidence use
  `jump_table.pointer_array` / `absolute_pointers` at `medium` confidence: a
  pointer array found by shape is evidence of a dispatch table, not proof that a
  dispatcher indexes it.
- Opt-in indirect resolution in the recursive CFG
  (`codevanta.analysis.cfg.build_recursive_cfg`): `resolve_indirect=False`
  (default) keeps phase 2e behaviour byte-for-byte; when enabled, a
  block-terminating `jmp qword ptr [rip + disp]` / `jmp qword ptr [abs]` (and
  the `dword` 32-bit forms) is turned into a table address and decoded with the
  jump-table resolver, and its executable, file-backed targets become sorted,
  deduplicated successors that the traversal follows. Bounded by
  `max_jump_tables` (default 8) and `max_table_entries` (default 256, ceiling
  4096); register/indexed operands, unreadable tables, and tables past the budget
  leave the edge out and are reported in `FunctionCFG.warnings`, prefixed with
  the block start. Evidence stays `cfg.recursive_traversal` at `medium` and its
  detail names how many tables and slots were resolved when the option is on.
- CLI: `codevanta jump-table PATH --address ADDR [--entries N]
  [--executable-only/--no-executable-only] [--json]` prints an index/target
  table with a pointer-size, entry-count, and truncated footer plus one warning
  per stop reason, and exits `2` on an invalid address, a rejected budget, or a
  table that cannot be read.
- CLI: `codevanta cfg --resolve-indirect`, accepted only with
  `--traversal recursive` (the linear sweep exits `2` instead of silently
  ignoring it). The other cfg output and options are unchanged, and the
  jump-table budgets stay at their library defaults on the command line.
- Interactive offline viewer (`codevanta.analysis.html_view`): the HTML export
  now carries one inline, dependency-free script adding drag-to-pan (via
  `viewBox`), wheel zoom anchored at the pointer and clamped to 0.2x–8x, a label
  search that highlights hits and dims the rest (Esc clears it), and per-kind
  filter checkboxes (function/entry_point, call_site, import/external). Still no
  CDN, no web font, and no `http(s)` reference anywhere; the static view renders
  in full with scripting disabled, and output remains deterministic and escaped.
- Structural binary diff (`codevanta.analysis.binary_diff`): `diff_infos` /
  `diff_binaries` compare two binaries as metadata only — functions matched by
  address (with `name`/`size` compared) then by name (so a relocated function is
  one `changed` entry, not a removal plus an addition), sections and exports by
  name, imports by `(library, name)`. `max_functions` defaults to 5000, is
  clamped to 1..20000, keeps the lowest addresses when it truncates, and records
  the clamp. Evidence uses `binary_diff.structural` / `metadata_compare` at
  `medium` confidence with the explicit caveat that no instruction bytes were
  read, compared, or executed, so `identical` means "no structural delta was
  observed", never "the code is equivalent".
- CLI: `codevanta diff LEFT RIGHT [--max-functions N] [--json]` prints an
  `Identical` header, per-kind delta counts, the named section/import/export
  deltas, and a function-delta table sorted by address. A difference exits `0`;
  only load or input errors exit `2`.
- Documentation: `docs/phase2f.md` covers the jump-table resolver and its stop
  rules, CFG opt-in resolution and its warnings, the interactive viewer, the
  structural diff and its matching rules, the CLI surface, confidence, limits,
  and next steps.

### Notes

- Phase 2 is in progress: the CFG uses a linear sweep by default and an optional
  bounded recursive traversal (`--traversal recursive`), with direct branch
  targets plus absolute and RIP-relative pointer slots only; jump tables are
  absolute 4/8-byte pointer arrays reached from a `jmp` memory operand, so
  register and indexed dispatch stay unresolved; no call following, no
  cross-function analysis, no slot dereferencing, and no debugger yet. The HTML
  export is interactive but still a single offline file, and the binary diff is
  structural (metadata) only, with no byte-level or semantic comparison. See
  `docs/phase2.md`, `docs/phase2b.md`, `docs/phase2c.md`, `docs/phase2d.md`,
  `docs/phase2e.md`, and `docs/phase2f.md`.
- Node boundaries and caller attribution are heuristics, not proven function
  extents. Sessions and annotations live in one local SQLite file with no schema
  migrations yet.

## [0.1.0] - 2026-12-11

### Added

- PE and ELF loaders (format, architecture, bitness, endianness, entry point,
  image base, sections, imports, exports, symbols) backed by LIEF.
- Capstone-backed x86/x64 disassembly of executable sections and the entry point.
- Function discovery from exports, function symbols, and the entry point, each
  with a detection source and confidence level.
- ASCII and UTF-16LE string extraction with file offset and mapped virtual address.
- Evidence layer: every finding records source, method, and confidence.
- IR layer: backend-neutral `IRInstruction` plus an adapter registry for future
  VEX/P-Code lifting.
- CLI: `info`, `functions`, `strings`, `disasm`, `analyze` with JSON export.
- MCP server (`codevanta mcp serve`, stdio) exposing five tools to coding agents.
- Guided setup for Claude Code, Cursor, Cline, and VS Code with plan preview,
  unified diffs, `*.codevanta.bak` backups, idempotent writes, verification, and
  `codevanta uninstall`.
- One-line bootstrap installers for Windows (PowerShell) and macOS/Linux (bash).
- 55 unit and integration tests; Ruff linting in CI.

### Notes

- Static analysis only: target binaries are never executed.
- PyVEX/angr, Z3, and Unicorn are intentionally deferred to a later phase.

[Unreleased]: https://github.com/kevindoni/CODEVANTA/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kevindoni/CODEVANTA/releases/tag/v0.1.0

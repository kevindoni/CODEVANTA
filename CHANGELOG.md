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

### Notes

- Phase 2 is in progress: linear sweep only, direct branch targets only, call
  graph edges from direct calls only, no recursive traversal, no indirect-call
  resolution, no graph viewer, and no debugger yet. See `docs/phase2.md` and
  `docs/phase2b.md`.
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

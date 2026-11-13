# CODEVANTA — Project Specification

**ADVANCED CODE INTELLIGENCE** · Decode. Analyze. Understand.

## Vision

A local-first, vendor-agnostic reverse engineering platform that reads,
disassembles, and explains PE, ELF, and Mach-O binaries accurately. Every claim
is backed by evidence, so the engine (and, later, an AI layer) can be audited.

## Architecture principles

- **Local-first** — analysis runs on the user's machine; no forced cloud calls.
- **Vendor-agnostic** — LIEF + Capstone core; Ghidra/IDA/Hopper are optional.
- **Stable base first** — parser, disassembler, and xrefs must be correct before
  symbolic execution, taint analysis, or unpacking.
- **Evidence traceability** — every finding records source, method, and confidence.
- **AI as a layer** — the AI layer explains and orchestrates; it never replaces
  the disassembler, parser, or analysis engine.

## Stack (MVP phases 1–3)

| Component | Technology | Role |
|-----------|------------|------|
| Language | Python 3.10+ | orchestration, CLI, API, scripting |
| Binary parser | LIEF | PE, ELF, and Mach-O metadata |
| Disassembler | Capstone | multi-architecture decoding |
| CLI | Typer + Rich | command line interface |
| IR abstraction | internal adapters (`src/ir`) | VEX/P-Code ready |
| Evidence | internal models (`src/evidence`) | provenance + confidence |

Deferred to later phases: PyVEX/angr, Z3, Unicorn, symbolic execution, advanced
taint analysis, automatic unpacking, reverse debugging, advanced type recovery,
multi-user collaboration, AI binary modification.

## Phase 1 scope (delivered)

- PE, ELF, and Mach-O loaders with format/arch/bitness/endianness/entry/image
  base.
- Sections/segments, imports, exports, symbol extraction.
- x86/x64 disassembly of executable sections and the entry point.
- Function discovery from exports, function symbols, and the entry point —
  never claiming heuristic boundaries it cannot prove. Mach-O symbol entries
  do not encode kind, so `is_function` there is derived from executable-section
  membership and reported at medium confidence.
- ASCII and UTF-16 string extraction with file offset and mapped VA; the UTF-16
  byte order follows the binary's endianness (little-endian targets UTF-16LE,
  big-endian targets UTF-16BE, no metadata means no byte-swap guessing).
- CLI: `info`, `functions`, `strings`, `disasm`, `analyze` (+ JSON export).

## Phase 1.5 scope (delivered)

- MCP server (`codevanta mcp serve`, stdio) exposing fifteen tools:
  `codevanta_info`, `codevanta_functions`, `codevanta_strings`,
  `codevanta_disasm`, `codevanta_analyze`, `codevanta_xrefs`,
  `codevanta_cfg`, `codevanta_callgraph`, `codevanta_diff`,
  `codevanta_jump_table`, `codevanta_function_hash`,
  `codevanta_similarity`, `codevanta_struct`, `codevanta_session_save`,
  `codevanta_session_list`.
- Guided setup (`codevanta setup`) for Claude Code, Cursor, Cline, and VS Code:
  plan preview with unified diff, explicit approval, `*.codevanta.bak` backups,
  idempotent writes, post-apply verification, and `codevanta uninstall`.
- Shared analysis helpers (`src/core/report.py`) so the CLI and MCP tools cannot
  drift apart.

## Phase 2 scope (delivered)

- Cross-references: `call`/`jump`/`branch` recovered from direct branch
  operands in executable sections (register/memory targets skipped rather than
  guessed), with callee naming and scan budgets.
- Control-flow graphs: linear sweep and recursive traversal
  (`cfg --traversal linear|recursive`) with leader/terminator block rules;
  recursive walks follow statically known direct transfers and flag discovered
  function boundaries at medium confidence. Indirect jumps can be resolved
  through jump tables (`--resolve-indirect`).
- Call graphs over direct calls, exportable to DOT, GraphML, and an interactive
  standalone HTML view (pan/zoom/search/filter, no server required).
- Jump-table resolution in absolute and relative (`--base`) modes.
- Struct/field recovery (`codevanta struct`) from access patterns, with
  alignment and array-candidate hints.
- Function fingerprints, shape similarity, and binary diff
  (structural / `--deep` normalized-shape / `--semantic` pairing).
- SQLite session storage (`session save|list|show|annotate|notes`) for triage
  snapshots and analyst notes; parameterized SQL, bounded queries.
- `analyze` JSON report integration: xrefs, CFG, and callgraph sections with
  provenance steps, degrading to warning-carrying empty results when a binary
  has nothing to decode.

## Phase 1 acceptance criteria

1. Reads PE, ELF, Mach-O, and DEX files.
2. Reports binary metadata correctly.
3. Exposes section information.
4. Shows imports and exports.
5. Extracts strings with their locations.
6. Disassembles with correct addresses and bytes.
7. Function candidates include detection source and confidence.
8. Produces a consistent JSON report.
9. CLI runs on Windows.
10. Unit and integration tests pass.

## Quality requirements

- Static analysis only — the target is never executed.
- Malformed input fails safely with a clear error.
- Consistent error handling and input validation.
- Bounded resource use on large inputs.
- No fabricated function boundaries or metadata.
- Every finding carries an evidence source.

## Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| 1 | Foundation (loader, disassembler, strings, functions, CLI, JSON) | **delivered** — `core/loader.py` (PE, ELF, Mach-O incl. fat slices, DEX), `core/disassembler.py`, `core/strings.py`, `core/functions.py`, `core/report.py`, `cli/main.py` |
| 1.5 | MCP server + guided agent setup | **delivered** — 17 tools in `mcp_server/server.py`, `setup/` adapters |
| 2 | Cross-references, CFG (linear + recursive), call graphs, jump tables, sessions | **delivered** — `analysis/xrefs.py`, `analysis/cfg.py`, `analysis/callgraph.py`, `analysis/jump_tables.py`, `storage/session.py`. Remaining open: **live debugger attach**, the graph-oriented **viewer application**, **GUI session persistence** |
| 3 | Type recovery, binary diff, Python scripting | **delivered** except embedded Python scripting — struct recovery (`analysis/type_recovery.py`), diff (`analysis/binary_diff.py`), fingerprints (`analysis/function_hash.py`), similarity, decompilation via `native` / `angr` / `ghidra` (`analysis/decompilers/`). Remaining open: **embedded Python scripting**, **evidence bundle** export |
| 4 | Unicorn emulation, IR lifting, symbolic execution (optional) | **emulation delivered** (unchanged: `analysis/emulate.py`, bounded and offline, never executes on the host). Remaining open: **IR lifting / typed SSA** (`ir/adapters/` is an empty registry — no concrete adapter), **symbolic execution** (no symbolic path or Z3 in `src/`) |
| 5 | Plugin system, full AI layer, multi-user, CI/CD | **CI/CD delivered** — `ci.yml` (test on 3.11/3.13/3.14, type-check via mypy, package/wheel smoke test, decompile-parity, ghidra-parity) plus `release.yml` (build → publish-pypi → github-release), with an 85% coverage gate. Remaining open: **plugin SDK** (`plugins/__init__.py` is a stub), **full AI layer**, **multi-user** |

Cross-cutting work that no phase delivers yet: **.NET / WebAssembly / JVM
`.class` formats**, **fuzz and benchmark gates** (`scripts/bench.py` exists but
no CI job enforces it), **Windows and macOS CI** (every job is
`runs-on: ubuntu-latest`), and an actual **PyPI release** (the publishing job is
wired, but no `v*` tag has been cut).

## Responsible use

Authorized analysis only: software you own, systems you have written permission
to inspect, security research, interoperability, and education.

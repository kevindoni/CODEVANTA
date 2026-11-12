# CODEVANTA — Project Specification

**ADVANCED CODE INTELLIGENCE** · Decode. Analyze. Understand.

## Vision

A local-first, vendor-agnostic reverse engineering platform that reads,
disassembles, and explains PE and ELF binaries accurately. Every claim is
backed by evidence, so the engine (and, later, an AI layer) can be audited.

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
| Binary parser | LIEF | PE and ELF metadata |
| Disassembler | Capstone | multi-architecture decoding |
| CLI | Typer + Rich | command line interface |
| IR abstraction | internal adapters (`src/ir`) | VEX/P-Code ready |
| Evidence | internal models (`src/evidence`) | provenance + confidence |

Deferred to later phases: PyVEX/angr, Z3, Unicorn, symbolic execution, advanced
taint analysis, automatic unpacking, reverse debugging, advanced type recovery,
multi-user collaboration, AI binary modification.

## Phase 1 scope (current)

- PE and ELF loaders with format/arch/bitness/endianness/entry/image base.
- Sections/segments, imports, exports, symbol extraction.
- x86/x64 disassembly of executable sections and the entry point.
- Function discovery from exports, function symbols, and the entry point —
  never claiming heuristic boundaries it cannot prove.
- ASCII and UTF-16LE string extraction with file offset and mapped VA.
- CLI: `info`, `functions`, `strings`, `disasm`, `analyze` (+ JSON export).

## Phase 1.5 scope (delivered)

- MCP server (`codevanta mcp serve`, stdio) exposing five tools:
  `codevanta_info`, `codevanta_functions`, `codevanta_strings`,
  `codevanta_disasm`, `codevanta_analyze`.
- Guided setup (`codevanta setup`) for Claude Code, Cursor, Cline, and VS Code:
  plan preview with unified diff, explicit approval, `*.codevanta.bak` backups,
  idempotent writes, post-apply verification, and `codevanta uninstall`.
- Shared analysis helpers (`src/core/report.py`) so the CLI and MCP tools cannot
  drift apart.

## Phase 1 acceptance criteria

1. Reads PE and ELF files.
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

| Phase | Focus | Estimate |
|-------|-------|----------|
| 1 | Foundation (loader, disassembler, strings, functions, CLI, JSON) | current |
| 2 | CFG/DFG visualization, session save/load, basic debugger | 5–7 weeks |
| 3 | Basic type recovery, binary diff, Python scripting | 6–8 weeks |
| 4 | Unicorn emulation, IR lifting, symbolic execution (optional) | 8–10 weeks |
| 5 | Plugin system, full AI layer, multi-user, CI/CD | 10–12 weeks |

## Responsible use

Authorized analysis only: software you own, systems you have written permission
to inspect, security research, interoperability, and education.

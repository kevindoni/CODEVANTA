# CODEVANTA

> **Advanced Code Intelligence** — Decode. Analyze. Understand.

CODEVANTA is an AI-powered code intelligence, reverse engineering, and binary
analysis platform. It helps engineers, security researchers, and analysts
understand software faster — from source code to executables with missing
symbols or incomplete documentation.

## Vision

Build a unified workspace for unpacking software complexity by bringing
disassembly, decompilation, static analysis, binary inspection, and AI-assisted
reasoning into one clear, auditable, and extensible experience.

## Core focus

- **Binary analysis** — inspect executables, libraries, metadata, sections, symbols, and binary formats.
- **Reverse engineering** — navigate functions, call graphs, data flow, cross-references, and program behavior.
- **AI code intelligence** — explain functions, summarize modules, detect patterns, and ask context-aware questions.
- **Static analysis** — identify suspicious behavior, dependencies, API usage, and risk indicators.
- **Analyst workflow** — manage workspaces, annotations, findings, evidence, and shareable reports.

## Target workflow

```text
Import target → Index & normalize → Disassemble/decompile → Analyze → Ask AI → Review evidence → Export report
```

CODEVANTA prioritizes insights that can be traced back to technical evidence.
AI acts as a copilot to accelerate analysis, not as a replacement for analyst
verification.

## Project status

🚧 **Phase 1 (foundation) implemented** — binary loading, disassembly, string
extraction, function discovery, and JSON export are working and tested.

Delivered in phase 1:

- PE and ELF loaders (format, architecture, bitness, endianness, entry point, image base).
- Sections, imports, exports, and symbol extraction — every finding carries evidence.
- x86/x64 disassembly of executable sections and the entry point.
- Function candidates from exports, function symbols, and the entry point, each with source and confidence.
- ASCII and UTF-16LE string extraction with file offset and mapped virtual address.
- CLI: `info`, `functions`, `strings`, `disasm`, `analyze` (+ JSON report).
- **MCP server** (`codevanta mcp serve`) exposing the phase 1 tools to coding agents.
- **Guided setup** (`codevanta setup`) for Claude Code, Cursor, Cline, and VS Code, with plan preview, backups, and verification.

### Phase 2 (in progress)

Phase 2 adds the first reverse-engineering views on top of the phase 1 engine:

- **Cross-references** (`analysis/xrefs.py`) — `call`/`jump`/`branch` references
  recovered from direct branch operands in executable sections, each with
  evidence and an optional callee name. Calls through an absolute or RIP-relative
  pointer slot (`call qword ptr [0x402000]`, `call qword ptr [rip + 0xa]`) now
  resolve to the slot: known imports become `call_import` with a `target_name`,
  other slots become `call_indirect`, and register/indexed calls that cannot be
  resolved are skipped and counted (`indirect_skipped`).
- **Control-flow graphs** (`analysis/cfg.py`) — basic blocks and successor edges
  for one region. The default is a linear sweep with leader/terminator rules;
  `build_recursive_cfg` (and `codevanta cfg --traversal recursive`) instead walks
  control flow from the start address with a worklist and a visited set, so
  blocks come from real branch targets and unreachable padding after a `ret` or
  `jmp` is excluded. Indirect targets stay unresolved by default;
  `resolve_indirect=True` (and `codevanta cfg --traversal recursive
  --resolve-indirect`) decodes the pointer table behind a `jmp qword ptr [rip +
  disp]` / `jmp qword ptr [abs]` and follows its executable targets, bounded per
  traversal by `max_jump_tables` and `max_table_entries`.
- **Jump tables** (`analysis/jump_tables.py`) — `resolve_jump_table` decodes a
  bounded array of absolute pointers (4 or 8 bytes, binary endianness) into
  `JumpTableEntry` records with evidence. The scan stops at the first zero
  pointer, out-of-window target, unmapped target, or non-executable target and
  reports why; results are `medium` confidence because a pointer array found by
  shape is evidence of a dispatch table, not proof of one.
- **Structural binary diff** (`analysis/binary_diff.py`) — `diff_binaries`
  compares two binaries as metadata only: functions matched by address then name,
  sections/exports by name, imports by `(library, name)`. Deltas are `added`,
  `removed`, or `changed`, and the whole comparison is `medium` confidence
  because no bytes and no semantics are compared.
- **Call graph** (`analysis/callgraph.py`) — `call`, `call_import`, and
  `call_indirect` cross-references aggregated into nodes and edges. Import slots
  become `import` nodes labelled from the import table; unresolved callees stay
  `external`. Caller attribution is heuristic (nearest function candidate at or
  below the call site in the same section), so the graph reports `medium`
  confidence and warns when a call site cannot be attributed.
- **Graph export** (`analysis/graph_export.py`) — the call graph rendered as
  Graphviz DOT or GraphML by one dependency-free, deterministic exporter.
- **Offline graph viewer** (`analysis/html_view.py`) — `codevanta callgraph
  --format html` writes one self-contained HTML5 document with an inline SVG
  view: three kind-based columns, header counts, and a collapsible edge table.
  One inline script adds drag-to-pan, mouse-wheel zoom (0.2x–8x), label search
  with hit/dim highlighting, and per-kind filters. No CDN, no web font, no
  library and no server, so it opens offline from disk — and with scripting
  disabled the static view still renders in full.
- **Session storage** (`storage/session.py`) — additive SQLite records of each
  analysis run (fingerprint, format, arch, entry point, function/string counts)
  plus per-address analyst annotations (`annotate`, `annotations`,
  `remove_annotation`; one replaceable note per address).
- **MCP tools** — `codevanta_xrefs`, `codevanta_cfg`, `codevanta_callgraph`,
  `codevanta_session_save`, `codevanta_session_list`, alongside the five phase 1
  tools (ten in total).
- **CLI:** `codevanta xrefs`, `codevanta cfg` (with
  `--traversal linear|recursive`, default `linear`, and `--resolve-indirect` for
  recursive traversals), `codevanta jump-table`, `codevanta diff`,
  `codevanta callgraph`, `codevanta analyze --callgraph`, plus the
  `session save|list|show|annotate|notes` subcommands.

Phase 2 is deliberately narrow: linear sweep by default with an additional
bounded recursive traversal for CFGs, direct branch targets plus
absolute/RIP-relative pointer slots only, jump tables only as absolute 4/8-byte
pointer arrays reached from a `jmp` memory operand (no register/indexed
dispatch), call graph edges from `call` / `call_import` / `call_indirect` only,
no following calls into callees, no cross-function analysis, a structural
(metadata-only) binary diff with no byte-level comparison, and no debugger yet.
See [docs/phase2.md](docs/phase2.md), [docs/phase2b.md](docs/phase2b.md),
[docs/phase2c.md](docs/phase2c.md), [docs/phase2d.md](docs/phase2d.md),
[docs/phase2e.md](docs/phase2e.md), and [docs/phase2f.md](docs/phase2f.md) for
scope, confidence semantics, and limitations.

## Installation

```powershell
cd D:\PALIKASIKU\CODEVANTA
python -m pip install -e ".[dev]"
```

One-line install (installs, then prints a setup plan):

```powershell
irm https://raw.githubusercontent.com/kevindoni/CODEVANTA/main/scripts/install.ps1 | iex
```

See [docs/install.md](docs/install.md) for the macOS/Linux one-liner, manual
installs, and the full setup/uninstall reference.

## Usage

```powershell
codevanta info      C:\Windows\System32\notepad.exe
codevanta functions C:\Windows\System32\kernel32.dll --limit 8
codevanta strings   C:\Windows\System32\notepad.exe --min-length 8
codevanta disasm    C:\Windows\System32\notepad.exe --count 40
codevanta analyze   samples\elf64_text.bin --output samples\report.json

# Phase 2
codevanta xrefs     C:\Windows\System32\notepad.exe --limit 40
codevanta cfg       C:\Windows\System32\notepad.exe --address 0x140001000
codevanta cfg       C:\Windows\System32\notepad.exe --address 0x140001000 --traversal recursive
codevanta cfg       C:\Windows\System32\notepad.exe --address 0x140001000 --traversal recursive --resolve-indirect
codevanta jump-table C:\Windows\System32\notepad.exe --address 0x140003000
codevanta jump-table C:\Windows\System32\notepad.exe --address 0x140003000 --entries 64 --json
codevanta diff      samples\v1.bin samples\v2.bin
codevanta diff      samples\v1.bin samples\v2.bin --max-functions 20000 --json
codevanta callgraph C:\Windows\System32\notepad.exe --format dot -o callgraph.dot
codevanta callgraph C:\Windows\System32\notepad.exe --format graphml -o callgraph.graphml
codevanta callgraph C:\Windows\System32\notepad.exe --format html -o callgraph.html
Invoke-Item callgraph.html   # drag to pan, wheel to zoom, search labels, filter by kind
codevanta analyze   C:\Windows\System32\notepad.exe --callgraph -o report.json
codevanta session save C:\Windows\System32\notepad.exe --notes "baseline triage"
codevanta session list --limit 10
codevanta session show 4f9c1a7b2d3e
codevanta session annotate 4f9c1a7b2d3e 0x401000 "decrypts config with XOR 0x5a"
codevanta session notes 4f9c1a7b2d3e
```

All addresses in reports are absolute virtual addresses (VA). Function
candidates always state their detection source (`export`, `symbol`,
`entry_point`) and confidence (`high`, `medium`, `low`, `unknown`).

Phase 2 results carry their own evidence: xrefs are `certain` (the target is
read directly from the decoded operand), CFG blocks are `medium` (block
boundaries come from mnemonic heuristics), jump-table entries are `medium` (a
pointer array found by shape is not proof a dispatcher indexes it), the
structural diff is `medium` (metadata only, never bytes or behavior), and the
call graph is `medium` (calls are decoded, but caller attribution is a
nearest-candidate heuristic). `codevanta callgraph` defaults to `--format json`
and can emit `dot`, `graphml`, or `html` (one self-contained file with an inline
SVG view that pans, zooms, searches, and filters by kind without any CDN, opened
straight from disk); `codevanta cfg` defaults to the entry point and to
`--traversal linear`, `--traversal recursive` reports the same shape with
evidence source `cfg.recursive_traversal`, and `--resolve-indirect` (recursive
only) adds jump-table successors; `codevanta jump-table` takes a decimal or `0x`
hex `--address` and a `--entries` slot budget; `codevanta diff` exits `0`
whether or not the binaries differ, and `2` on load or input errors. Sessions default
to `$env:CODEVANTA_DB` or `~/.codevanta/sessions.db`, and `session annotate`
accepts decimal or `0x` hex addresses.

Calls through a pointer slot report the **slot** address, not the callee: the
pointer is read at run time, so the code behind it is unknown here. A slot that
matches the import table becomes `call_import` with a `target_name`; any other
absolute or RIP-relative slot becomes `call_indirect` (`high` confidence — the
slot is proven, the callee is not); register and indexed operands are skipped and
counted in `indirect_skipped`, which `codevanta xrefs --json` prints.
`codevanta analyze --callgraph` embeds the graph in the report, bounded to 1000
functions and 5000 edges, and marks it `truncated` when a cap cuts it short.

## Coding agent setup (MCP)

CODEVANTA exposes the same analysis as MCP tools, so coding agents can call it
directly:

```powershell
codevanta setup --list                          # status per client and scope
codevanta setup --dry-run --client cursor        # show the plan, write nothing
codevanta setup --client cursor --yes --verify   # apply and verify
codevanta setup --client claude --scope user
codevanta setup --client vscode --scope project --project .
codevanta uninstall --client cursor
```

Supported clients: `claude` (Claude Code), `cursor`, `cline` (VS Code
extension), `vscode` (Copilot, project scope).

Safety model: every run prints the exact file changes and a diff first; nothing
is written without `--yes` (or an interactive confirmation); existing configs
are backed up as `*.codevanta.bak`; re-running the same command is a no-op.

MCP tools (ten): `codevanta_info`, `codevanta_functions`,
`codevanta_strings`, `codevanta_disasm`, `codevanta_analyze`,
`codevanta_xrefs`, `codevanta_cfg`, `codevanta_callgraph`,
`codevanta_session_save`, `codevanta_session_list`.

`codevanta_callgraph` takes the same bounded limits as the CLI
(`limit_functions`, `limit_edges`, defaulting to 1000 and 5000) and returns nodes,
edges, `truncated`, `warnings`, and evidence. Import targets arrive as `import`
nodes labelled from the import table; unresolved callees stay `external`.
`codevanta_analyze` remains the phase 1 report and has no call-graph flag.

Prompt you can paste into a coding agent:

> Install CODEVANTA and connect it to this coding agent. Show me the setup plan
> first, then verify the installation.

## Project layout

```text
src/codevanta/
├── core/        # loader (LIEF), disassembler (Capstone), strings, functions, shared report
├── evidence/    # evidence records, provenance, confidence scoring
├── ir/          # backend-neutral instruction model + adapter registry
├── mcp_server/  # MCP tools and stdio server for coding agents
├── setup/       # client config planning, apply, verify (claude/cursor/cline/vscode)
├── analysis/    # cross-references, call graph, CFG (linear sweep + recursive traversal), jump tables, structural diff, graph/HTML export (phase 2)
├── api/         # HTTP API (phase 2+)
├── cli/         # Typer command line surface
├── storage/     # SQLite session storage and annotations (phase 2)
└── plugins/     # plugin system (phase 5)
tests/           # unit and integration tests
docs/            # architecture and install notes
scripts/         # one-line bootstrap installers
```

## Testing

```powershell
python -m pytest
ruff check src tests
```

## Documentation

- [Project specification](PROJECT_SPEC.md)
- [Architecture](docs/architecture.md)
- [Phase 2 — cross-references, CFGs, sessions](docs/phase2.md)
- [Phase 2b — call graphs, graph export, session annotations](docs/phase2b.md)
- [Phase 2c — import/indirect calls, embedded call graphs, MCP call graph](docs/phase2c.md)
- [Phase 2d — offline HTML/SVG graph viewer](docs/phase2d.md)
- [Phase 2e — recursive CFG traversal](docs/phase2e.md)
- [Phase 2f — jump tables, CFG indirect resolution, interactive viewer, structural diff](docs/phase2f.md)

## Roadmap

- [x] Phase 1 — core engine foundation: PE/ELF loading, disassembly, strings, functions, CLI, JSON evidence reports
- [ ] Phase 2 — cross-references, CFG views, session storage, basic debugger
- [ ] Phase 3 — basic type recovery, binary diff, Python scripting
- [ ] Phase 4 — emulation (Unicorn), IR lifting, symbolic execution (optional)
- [ ] Phase 5 — plugin system, full AI layer, multi-user, CI/CD

## Product principles

1. **Evidence first** — important insights should be traceable to an artifact or code location.
2. **Analyst in control** — AI provides assistance and context; users remain the decision makers.
3. **Composable by design** — engines and analyzers should be extensible through separate components.
4. **Secure by default** — analyzed targets are treated as untrusted input.
5. **Clarity over magic** — outputs should explain limitations, confidence, and assumptions.

## Use cases

- Understand legacy executables without complete source code
- Map dependencies and behavior in internal libraries
- Triage malware artifacts in an isolated environment
- Explain native or low-level functions to engineering teams
- Generate technical documentation for poorly documented software
- Support binary-focused code review and security research

> **Security note:** never open untrusted binaries or samples in a production
> environment. Use an appropriate sandbox, VM, or isolated analysis environment.

## Contributing

Contributions, design discussions, and bug reports are welcome. Before opening a
pull request, describe the change context, compatibility risks, and validation
steps.

## Community

- [Contributing](CONTRIBUTING.md) — development setup, checks, and conventions
- [Contributors](CONTRIBUTORS.md) — maintainer, agent workstreams, and how to be listed
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Security policy](SECURITY.md) — report vulnerabilities privately
- [Repository settings checklist](docs/repository-settings.md) — maintainers
- [Changelog](CHANGELOG.md)

## License

MIT — see [LICENSE](LICENSE). Third-party components keep their own licenses.

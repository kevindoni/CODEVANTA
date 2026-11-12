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
  for one region, built by linear sweep with leader/terminator rules.
- **Call graph** (`analysis/callgraph.py`) — `call`, `call_import`, and
  `call_indirect` cross-references aggregated into nodes and edges. Import slots
  become `import` nodes labelled from the import table; unresolved callees stay
  `external`. Caller attribution is heuristic (nearest function candidate at or
  below the call site in the same section), so the graph reports `medium`
  confidence and warns when a call site cannot be attributed.
- **Graph export** (`analysis/graph_export.py`) — the call graph rendered as
  Graphviz DOT or GraphML by one dependency-free, deterministic exporter.
- **Session storage** (`storage/session.py`) — additive SQLite records of each
  analysis run (fingerprint, format, arch, entry point, function/string counts)
  plus per-address analyst annotations (`annotate`, `annotations`,
  `remove_annotation`; one replaceable note per address).
- **MCP tools** — `codevanta_xrefs`, `codevanta_cfg`, `codevanta_callgraph`,
  `codevanta_session_save`, `codevanta_session_list`, alongside the five phase 1
  tools (ten in total).
- **CLI:** `codevanta xrefs`, `codevanta cfg`, `codevanta callgraph`,
  `codevanta analyze --callgraph`, plus the
  `session save|list|show|annotate|notes` subcommands.

Phase 2 is deliberately narrow: linear sweep only, direct branch targets plus
absolute/RIP-relative pointer slots only, call graph edges from `call` /
`call_import` / `call_indirect` only, no register-target resolution, no recursive
traversal, no graph viewer, and no debugger yet. See
[docs/phase2.md](docs/phase2.md), [docs/phase2b.md](docs/phase2b.md), and
[docs/phase2c.md](docs/phase2c.md) for scope, confidence semantics, and
limitations.

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
codevanta callgraph C:\Windows\System32\notepad.exe --format dot -o callgraph.dot
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
boundaries come from mnemonic heuristics), and the call graph is `medium`
(calls are decoded, but caller attribution is a nearest-candidate heuristic).
`codevanta callgraph` defaults to `--format json` and can emit `dot` or
`graphml`; `codevanta cfg` defaults to the entry point; sessions default to
`$env:CODEVANTA_DB` or `~/.codevanta/sessions.db`, and `session annotate` accepts
decimal or `0x` hex addresses.

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
├── analysis/    # cross-references, call graph, linear-sweep CFG, DOT/GraphML export (phase 2)
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

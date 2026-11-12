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
- **MCP server** (`codevanta mcp serve`) exposing the same five tools to coding agents.
- **Guided setup** (`codevanta setup`) for Claude Code, Cursor, Cline, and VS Code, with plan preview, backups, and verification.

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
```

All addresses in reports are absolute virtual addresses (VA). Function
candidates always state their detection source (`export`, `symbol`,
`entry_point`) and confidence (`high`, `medium`, `low`, `unknown`).

## Coding agent setup (MCP)

CODEVANTA exposes the same analysis as MCP tools, so coding agents can call it
directly:

```powershell
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

MCP tools: `codevanta_info`, `codevanta_functions`, `codevanta_strings`,
`codevanta_disasm`, `codevanta_analyze`.

Prompt you can paste into a coding agent:

> Install CODEVANTA and connect it to this coding agent. Show me the setup plan
> first, then verify the installation.

## Project layout

```text
src/
├── core/        # loader (LIEF), disassembler (Capstone), strings, functions, shared report
├── evidence/    # evidence records, provenance, confidence scoring
├── ir/          # backend-neutral instruction model + adapter registry
├── mcp_server/  # MCP tools and stdio server for coding agents
├── setup/       # client config planning, apply, verify (claude/cursor/cline/vscode)
├── analysis/    # cross-references and CFG (phase 2+)
├── api/         # HTTP API (phase 2+)
├── cli/         # Typer command line surface
├── storage/     # session storage (phase 2+)
└── plugins/     # plugin system (phase 5)
tests/           # unit and integration tests
docs/            # architecture notes
```

## Testing

```powershell
python -m pytest
ruff check src tests
```

## Documentation

- [Project specification](PROJECT_SPEC.md)
- [Architecture](docs/architecture.md)

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

## License

MIT — see [LICENSE](LICENSE). Third-party components keep their own licenses.

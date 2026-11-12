# Changelog

All notable changes to CODEVANTA are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/kevindoni/CODEVANTA/releases/tag/v0.1.0

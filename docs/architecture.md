# CODEVANTA Architecture

## Layering

```
User (CLI / future Web UI / future Python SDK)
        │
        ▼
┌─────────────────────┐
│  API / CLI layer    │  Typer + Rich
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Analysis core      │
│  ├─ loader (LIEF)   │
│  ├─ disassembler    │  Capstone
│  ├─ strings         │
│  └─ functions       │
└─────────┬───────────┘
          │
    ┌─────┴─────┐
    ▼           ▼
IR layer     Evidence layer
(adapter)    (source/method/confidence)
    │           │
    └─────┬─────┘
          ▼
     JSON / future formats
```

## Core modules

| Module | Responsibility |
|--------|----------------|
| `src/codevanta/core/loader.py` | Parse PE/ELF via LIEF; normalize metadata into `BinaryInfo` |
| `src/codevanta/core/disassembler.py` | Decode machine code with Capstone into `IRInstruction` |
| `src/codevanta/core/strings.py` | Extract ASCII/UTF-16LE strings with offset → VA mapping |
| `src/codevanta/core/functions.py` | Discover function candidates with provenance |
| `src/codevanta/core/report.py` | Shared report/disassembly helpers for CLI and MCP |
| `src/codevanta/mcp_server/tools.py` | MCP tool functions (plain, testable) |
| `src/codevanta/mcp_server/server.py` | MCP stdio server (`MCPServer`, five tools) |
| `src/codevanta/setup/clients.py` | Per-client config adapters (claude/cursor/cline/vscode) |
| `src/codevanta/setup/plan.py` | Setup plans, unified diffs, create/update/noop classification |
| `src/codevanta/setup/apply.py` | Idempotent writes with `*.codevanta.bak` backups |
| `src/codevanta/setup/verify.py` | Entry verification and tool-layer smoke test |
| `src/codevanta/ir/` | Adapter contract; VEX/P-Code adapters arrive in phase 4 |
| `src/codevanta/evidence/` | Evidence records, provenance, confidence scoring |
| `src/codevanta/cli/main.py` | Command line surface |

## Address model

All addresses exposed by `BinaryInfo` are absolute virtual addresses (VA):

- PE: `image_base + RVA` for sections, entry point, exports, and imports.
- ELF: section `virtual_address`, `entrypoint`, symbol `value`.

`BinaryInfo.va_to_offset()` and `offset_to_va()` map between VA and file offsets
using section metadata, which is required for static disassembly.

## Function discovery policy

Phase 1 only reports candidates from structural evidence:

1. **Exports** (`export` source, high confidence).
2. **Function symbols** (`symbol` source, high confidence).
3. **Entry point** (`entry_point` source, medium confidence — a code entry, not
   a proven function boundary).

Speculative heuristics (prologue scanning, call-target mining, recursive
descent) are deliberately out of scope until phase 2, and will always be
labelled with their own source and confidence.

## Evidence model

```python
Evidence(source="pe.export_table", method="export_directory",
         confidence=Confidence.HIGH, address=0x140001000)
```

Reports embed each finding's evidence so the AI layer can cite machine results
instead of guessing.

## JSON report shape

```json
{
  "provenance": {"tool": "codevanta", "tool_version": "0.1.0", "steps": [...]},
  "binary": {"format": "PE", "architecture": "x86_64", "sections": [...], "imports": [...], "exports": [...]},
  "functions": [{"address": "0x...", "source": "export", "confidence": "high", "evidence": {...}}],
  "strings": {"count": 123, "items": [...]}
}
```

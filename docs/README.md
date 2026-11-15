# Documentation index

User-facing documentation for CODEVANTA.

| Document | What it covers |
|----------|----------------|
| [Install](install.md) | Installing from PyPI or from source |
| [API](api.md) | The 25 dashboard routes and the 60 MCP tools (as of v0.3.x) |
| [Architecture](architecture.md) | How the engine, CLI, GUI and MCP layers fit together |
| [Samples](samples.md) | The committed analysis fixtures and how to reproduce them |
| [JavaScript/Electron](javascript.md) | Static app inventory: modules, imports, IPC boundaries |
| [Electron audit](electron-audit.md) | Security anti-pattern rules for Electron apps |
| [SBOM](sbom.md) | CycloneDX 1.6 export from CODEVANTA inventories |
| [Capabilities](capabilities.md) | File-scope capability rules (capa-style subset) |
| [Stackstrings](stackstrings.md) | Stack-built string recovery via bounded emulation |
| [Triage hashes](triage-hash.md) | imphash (Mandiant convention) + ssdeep-shaped fuzzy hash |
| [Go symbols](go-symbols.md) | pclntab function-name recovery from stripped Go binaries |
| [Demangling](demangle.md) | Itanium / MSVC / Rust / Swift symbol decoding, offline |
| [FS snapshot & diff](fs-diff.md) | Deterministic directory manifests and before/after diffing |
| [Source maps](sourcemap.md) | JS source map v3 decode and generated→original position trace |
| [Unpack](unpack.md) | Bounded in-memory archive manifests with bomb guards |
| [Net capture](net-capture.md) | tshark interfaces and capture around a target command |
| [Win input](win-input.md) | Real SendInput automation and the visual regression loop |
| [Win GUI](win-gui.md) | Live window list, widget tree and PNG capture |
| [Assets](assets.md) | PE icon/cursor/bitmap resources as PNG artifacts |
| [SSA IR](ssa.md) | Versioned SSA view of one function (decompiler v2 increment 1) |
| [Codegen](codegen.md) | Deterministic starter code from a studied rebuild project |
| [Sessions](sessions.md) | gdb / Frida / process session families (start, status, close) |
| [YARA subset](yara-subset.md) | Bounded YARA rule parsing and matching |
| [Replay fixture](replay-fixture.md) | HAR recordings as deterministic replay fixtures |
| [PDB info](pdb-info.md) | MSF v7 structure and PE CodeView references, offline |
| [Assets](assets/) | Screenshots used by the README |
| [Release checklist](release-checklist.md) | What the release workflow verifies |
| [Repository settings](repository-settings.md) | Branch protection and CI gates |
| [Attribution](attribution.md) | Credits for bundled tooling and inspiration |

Engineering phase diaries (`phase*.md`) are development logs kept for
transparency; the current feature surface is always described in the
[README](../README.md) and the changelog.

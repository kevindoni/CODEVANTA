# Contributors

CODEVANTA is built and maintained in the open. This file records who is
responsible for the project and how its work was produced.

## Project lead and maintainer

**Kevin Doni** ([@kevindoni](https://github.com/kevindoni)) — creator, project
direction, and review. The maintainer owns every change merged into this
repository, including all AI-assisted work described below.

## AI-assisted engineering

CODEVANTA is developed with AI agents orchestrated through **Cline** and reviewed
by the maintainer. The workstreams below are **agent workstreams, not individual
human contributors** — they are listed to document how this repository was
built, not to credit people:

| Workstream | Delivered in this repository |
|------------|------------------------------|
| Architecture and phase planning | Phase scoping, module boundaries, `PROJECT_SPEC.md`, roadmap |
| Core loader and disassembler | PE/ELF loading (LIEF), x86/x64 disassembly (Capstone), strings, function discovery |
| Evidence and IR layers | Evidence records (source, method, confidence), backend-neutral IR and adapter registry |
| CLI | `info`, `functions`, `strings`, `disasm`, `analyze`, plus the phase 2 commands |
| MCP server and coding-agent setup | Ten MCP tools, stdio server, guided setup for Claude Code, Cursor, Cline, VS Code |
| Cross-reference scanner | `call`, `jump`, and `branch` xrefs from direct branch operands |
| Linear-sweep CFG | Basic blocks and successor edges for one executable region |
| Call graph and graph export | Call graph from direct, import, and resolvable indirect calls, plus deterministic DOT and GraphML export |
| SQLite sessions and annotations | Analysis records and per-address analyst notes |
| Documentation | README, phase docs, install notes, changelog, community and repository files |
| Independent audits | Separate review passes over delivered code, tests, and documentation |

Each workstream above was reviewed, corrected, and accepted by the maintainer
before merge. The maintainer is accountable for its correctness.

## Individual contributors

This section lists human contributors who are not maintainers. It is currently
empty: CODEVANTA has one maintainer and the AI-agent workstreams above.

## How to be listed

1. Open a pull request that adds your name under **Individual contributors**,
   alphabetically, in the form `- Name ([@handle](https://github.com/handle)) — area`.
2. Read [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, required
   checks, and conventions.
3. Participation is covered by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Code, tests, documentation, bug reports, and design review all count. Do not add
other people to this file without their consent.

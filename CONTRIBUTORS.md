# Contributors

CODEVANTA is built and maintained in the open. This file records who is
responsible for the project and how its work was produced.

## Project lead and maintainer

**Kevin Doni** ([@kevindoni](https://github.com/kevindoni)) — creator, project
direction, and review. The maintainer owns every change merged into this
repository, including all AI-assisted work described below.

## AI-assisted engineering

CODEVANTA is developed with AI agents orchestrated through **Cline** and reviewed
and accepted by the maintainer. This section credits those agents explicitly,
because the GitHub contributor graph only counts linked accounts and therefore
under-reports the work: squash merges also record the merge actor as the commit
author, so agent-authored work arrives as a maintainer commit.

### Agents

| Agent | Role in this repository | Notes |
|-------|-------------------------|-------|
| **Cline** (AI coding agent, [cline.bot](https://cline.bot)) | Orchestrator and pair programmer: phase planning, implementation waves, independent audits, review follow-up, releases and repository maintenance | Runs with a multi-agent pattern (specialist agents in parallel, then a read-only auditor), each wave gated by `ruff`, `mypy`, `pytest` and CI before merge |
| **Cline specialist agents** | Focused workstreams inside a wave — loader, disassembly, xrefs/CFG, call graph, diff, type recovery, MCP surface, CLI, documentation, tooling, and audit | File ownership is disjoint per agent; every claim in this file comes from work those agents delivered and the maintainer reviewed |
| **Zai GLM-5.3** (AI coding agent) | Per-section entropy triage, GraphML fixture hardening, `PROJECT_SPEC.md` refresh | Author identity recorded directly in the history as `Zai GLM-5.3 <zai-glm-5.3@users.noreply.github.com>` |

### Workstreams delivered

| Workstream | Delivered in this repository |
|------------|------------------------------|
| Architecture and phase planning | Phase scoping, module boundaries, `PROJECT_SPEC.md`, roadmap |
| Core loader and disassembler | PE/ELF loading (LIEF), x86/x64 disassembly (Capstone), strings (ASCII, UTF-16LE/BE), function discovery |
| Evidence and IR layers | Evidence records (source, method, confidence), backend-neutral IR and adapter registry |
| Mach-O support | Thin 32/64 loading plus universal ("fat") containers with deterministic slice selection |
| Entropy triage | Per-section Shannon entropy with a packing hint and explicit "no file bytes" handling |
| CLI | `info`, `functions`, `strings`, `disasm`, `analyze`, `xrefs`, `cfg`, `diff`, `jump-table`, `struct`, `callgraph`, `entropy`, `session`, `setup`, `uninstall`, `mcp`, `gui` |
| Local web dashboard | `codevanta gui`: loopback-only dashboard with nine read-only JSON routes, Host validation and a hard response cap |
| MCP server and coding-agent setup | Fifteen MCP tools, stdio plus `sse`/`streamable-http` transports, guided setup for Claude Code, Cursor, Cline and VS Code |
| Analysis engines | Xref scanner, linear and recursive CFG, call graph, jump tables, function fingerprints, shape similarity, binary diff (structural, deep, semantic), struct/field recovery with alignment, array and signedness hints |
| Graph export | Deterministic JSON, DOT, GraphML and self-contained interactive HTML |
| Persistence | SQLite sessions with per-address analyst annotations |
| Samples and benchmarks | Deterministic PE/Mach-O/ELF samples with a regeneration script, plus a micro-benchmark harness |
| Quality gates | `pytest` (885+ cases), branch coverage floor, `ruff`, `mypy`, three Python versions, wheel smoke test, and a release workflow with a dry-run path |
| Documentation | README, `docs/api.md`, `docs/samples.md`, phase docs 2 → 2k, install notes, changelog, community and repository files |
| Independent audits | Separate review passes over delivered code, tests and documentation (twelve audit rounds so far) |

Each workstream above was reviewed, corrected, and accepted by the maintainer
before merge. The maintainer is accountable for its correctness; the agents are
not legal persons and hold no copyright in this repository.

### How agent authorship is recorded

* Commits may carry `Co-authored-by: Cline (AI coding agent) <noreply@cline.bot>`
  when an agent produced the change and the maintainer reviewed it.
* Squash merges through the protected `main` branch attribute the commit to the
  merge actor, so agent work reaches `main` as a maintainer commit even when the
  pull request carried a co-author trailer.
* This file, not the contributor graph, is the authoritative record of which
  agents worked on what.

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

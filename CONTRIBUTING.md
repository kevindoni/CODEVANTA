# Contributing to CODEVANTA

Thanks for helping improve CODEVANTA. This document covers the development
workflow, checks, and conventions.

## Development setup

```powershell
git clone https://github.com/kevindoni/CODEVANTA.git
cd CODEVANTA
python -m pip install -e ".[dev]"
```

Python 3.10+ is required; CI runs on 3.11 and 3.13.

## Checks before opening a pull request

```powershell
ruff check src tests
python -m pytest
```

Both must pass. CI also builds the wheel, installs it in a clean virtual
environment, and asserts that the wheel contains only the `codevanta` package.

## Project layout

```text
src/codevanta/
├── core/       loader (LIEF), disassembler (Capstone), strings, functions, report
├── evidence/   evidence records, provenance, confidence
├── ir/         backend-neutral instruction model and adapter registry
├── mcp_server/ MCP tools and stdio server
├── setup/      client adapters, plans, apply, verify
├── cli/        Typer command line
└── ...
tests/          unit and integration tests
```

## Conventions

- **Evidence first.** Any new finding must carry an `Evidence` record with
  `source`, `method`, and `confidence`. Never present a guess as a fact.
- **No fake boundaries.** Function candidates must state where they came from
  (`export`, `symbol`, `entry_point`, …). Heuristics belong to a later phase and
  must use their own source labels.
- **Static only.** Never execute an analyzed target.
- **Fail safely.** Malformed input must raise a clear, typed error, not crash.
- **Bound resources.** Validate and cap counts/limits before reading or decoding.
- **Type hints** on public functions; docstrings on modules and non-obvious logic.
- **No duplication.** Shared logic belongs in `core/report.py`, not copied into
  the CLI and MCP layers.

## Adding an MCP tool

1. Add a plain function to `src/codevanta/mcp_server/tools.py` returning a
   JSON-serializable dict; validate inputs and raise `AnalysisError`.
2. Register it in `src/codevanta/mcp_server/server.py` with a descriptive
   docstring/description.
3. Add tests in `tests/test_mcp_tools.py` (plain call, error path, and one
   in-process `call_tool` assertion if the tool is central).

## Adding a coding-agent client

1. Add a `ClientAdapter` subclass in `src/codevanta/setup/clients.py`
   implementing `container_key`, `config_path`, and `build_entry`.
2. Register it in `CLIENTS` (and `ALIASES` if it has alternate names).
3. Add plan tests in `tests/test_setup_plan.py`: create, idempotent noop,
   preserve other servers, invalid JSON refusal, and uninstall.

## Commit messages

Use a short imperative subject, optionally with a conventional prefix
(`feat:`, `fix:`, `docs:`, `build:`, `test:`, `refactor:`). Explain the *why* in
the body and mention user-visible changes.

### Attribution trailer

When an AI agent produced a change, add the trailer so the authorship stays
visible in the history:

```text
Co-authored-by: Cline (AI coding agent) <noreply@cline.bot>
```

Squash merges rewrite the commit and record the merge actor as the author, so the
trailer is what survives; [CONTRIBUTORS.md](CONTRIBUTORS.md) remains the
authoritative per-agent record. `.mailmap` keeps the maintainer's identities
collapsed in `git shortlog`, which is why local counts and the GitHub contributor
graph disagree.

## Pull requests

`main` is protected: a pull request is required and the CI checks
(`test (py3.11)`, `test (py3.13)`, `build and smoke-test wheel`) must pass before
a squash merge. Direct pushes to `main` are rejected, including for maintainers.

Work on a branch, push it, and open a pull request:

```powershell
git checkout -b feat/my-change
git push -u origin feat/my-change
gh pr create --fill --base main
```

Describe the problem, the approach, compatibility risks, and the validation you
ran. Link related issues. Keep changes focused; large refactors should be
discussed in an issue first.

## Code of conduct

Participation is covered by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

import pathlib
pp = pathlib.Path("pyproject.toml")
t = pp.read_text(encoding="utf-8")
assert 'version = "0.1.0"' in t
t = t.replace('version = "0.1.0"', 'version = "0.1.1"', 1)
pp.write_text(t, encoding="utf-8", newline="\n")
cl = pathlib.Path("CHANGELOG.md")
c = cl.read_text(encoding="utf-8")
entry = """## [0.1.1] - 2026-11-13

### Added

- **Live gdb debug sessions** (`codevanta.analysis.debug_session` + `codevanta debug`
  + MCP tool `codevanta_debug`): the layer now owns a real `gdb --interpreter=mi2`
  process - launch, break-at (symbol or address), continue, step/next, register
  reads, bounded memory reads, backtrace frames, verified quit - each result typed,
  JSON-safe and evidence-backed (`gdb.mi2`, HIGH, one-run provenance). A missing gdb
  is a typed `AnalysisError` with an install hint, never a traceback.
- MCP tool count is now 23; the MCP `INSTRUCTIONS` document `debug` as the one
  explicit execution exception.

### Changed

- README is fully de-hardcoded: real screenshots of the CLI, the loopback dashboard
  and a 97-node call graph export; installation starts from PyPI; volatile counts
  and Windows-only example paths removed; docs describe the actual CI gates.
"""
c = c.replace("## [Unreleased]", entry + "\n## [Unreleased]", 1)
cl.write_text(c, encoding="utf-8", newline="\n")
print("version + changelog bumped")

# Changelog

All notable changes to CODEVANTA are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-11-13

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

## [Unreleased]

### Added

- Vtable discovery and thunk resolution (`codevanta.analysis.vtables` +
  `codevanta vtable` + MCP tool `codevanta_vtable`): indirect cross-references
  the xref scanner cannot see. Candidates are runs of consecutive code
  pointers in non-executable data sections (`vtable.candidate` /
  `vtable.slot_ref`, medium confidence — a run of code pointers is a
  heuristic, not proof); PIE builds work because pointer slots that are zero
  on disk are filled through a dynamic-relocation overlay. Slot targets that
  are one-instruction tail-call thunks resolve to the final callee
  (`resolved_target` + `vtable.thunk_chain`). Address mode decodes one
  candidate at an exact address, skipping up to two leading Itanium-header
  slots (offset-to-top, RTTI); `--scan` sweeps every data section.
  `samples/shapes-vtable` (8.4 KB aarch64 ELF, two C++ classes built with the
  NDK's clang++) backs the tests.
- DWARF debug-info extraction (`codevanta.analysis.debuginfo` + `codevanta
  dwarf` + MCP tool `codevanta_dwarf`): when a build kept its debug info, the
  strongest symbol evidence available is now first-class — producer-grade
  function names with byte-exact extents (`dwarf.debug_info` /
  `DIE_subprogram`, high confidence) and named type layouts (structs, unions,
  enums, classes) with byte sizes. ELF only via the optional pyelftools extra
  (`pip install -e ".[dwarf]"`, included in `dev`); missing extra and
  non-ELF inputs fail with typed messages naming the limitation. PDB (PE)
  stays open: the LIEF OSS build gates its PDB parser behind the Extended
  distribution, so there is no OSS backend to wrap yet.
  `samples/hello-dwarf` (7.7 KB aarch64 ELF built with the NDK's clang `-g`)
  backs the test suite.
- DEX loader (`codevanta.core.loader`): Android DEX containers (magic
  `dex\n`) now load through LIEF's dedicated DEX parser with format, version
  endianness, and Dalvik method extraction. Defined methods become
  `high`-confidence function symbols from `dex.method_ids` with
  smali-style names (`LMain;->add`); referenced-but-undefined methods become
  imports carrying the defining class as `library`. DEX has no virtual
  address space, so symbol addresses are **file offsets** — stated in a
  loader warning and in every finding's evidence. Disassembly stays
  unsupported (`dalvik` is not a Capstone target) and fails with the usual
  typed error. A real 952-byte `samples/hello.dex` (built with the Android
  SDK's `d8`) backs the test suite.

- Phase 7 wiring (`feat/phase7-wiring`): the phase 6 engines are reachable
  from every surface. New CLI commands `codevanta symbolic` (branch-decision
  path exploration with `--set REG=VALUE` seeds and `--max-paths`/`--max-steps`
  budgets), `codevanta dataflow` (def-use and provable constants of one
  function), `codevanta evidence-bundle` (hash a binary plus `--entry
  NAME=FILE` payloads into a tamper-evident bundle; refuses to overwrite the
  subject) and `codevanta plugins list/run` (the live registry, and one plugin
  run under the harness budget). MCP gains `codevanta_symbolic` and
  `codevanta_dataflow` (the server now registers 22 tools) and the dashboard
  gains `/api/symbolic` with its panel (14 routes; `build_server().list_tools()`
  and `ROUTES` both verified). `scripts/report_bundle.py` ties a report and an
  optional saved trace into one verified bundle; `bench/baseline.json` became
  per-platform (`bench/baseline.windows.json`, `bench/baseline.linux.json`) so
  the gate never compares timings across operating systems; saved traces
  (`samples/gdb_trace.log`, `samples/frida_trace.jsonl`) let `codevanta trace`
  be exercised offline, and `tests/test_cli_phase7.py`,
  `test_trace_samples.py`, `test_symbolic_parity.py`, `test_report_bundle.py`
  pin all of it.
- CI hardening: a `fuzz-smoke` job runs the parser fuzzer (30 seeded iterations
  over the committed samples) plus `tests/test_fuzz_parsers.py` on every PR; an
  informational `benchmark` job reports drift against the committed baseline
  with a wide tolerance and `continue-on-error` (timings are machine-dependent,
  so it reports, it does not gate); a non-blocking `test-platform` job runs the
  suite on windows-latest and macos-latest (py3.13) as platform signal while
  parity stays proven by the Linux job.
- Path exploration (`codevanta.analysis.symbolic` + `codevanta symbolic` + MCP
  tool `codevanta_symbolic`): breadth-first replay of the branch decisions of
  one function on a private unicorn CPU. The observed side of every branch is
  the real emulation result; the other side is enqueued with its guarding flags
  or loop counter rewritten (`seeded` — an assumption, never a solved
  constraint, and each such branch says so with a per-path warning and drops
  the summary to low confidence). No symbolic variables, no path predicate, no
  SMT anywhere. Paths report decisions, taken targets, end registers, the
  `rax`/`eax` value at a leaving `ret` (`None` otherwise), a stop reason
  (`return`/`budget`/`blocked`/`unmapped`) and executed steps; `complete` is
  true only when nothing was left unexplored and every reported path returned.
  Optional angr bridge (`explore_with_angr`) reports the same shape when angr
  is installed; x86/x86-64 only; missing unicorn, bad addresses and bad seeds
  fail with typed errors before anything runs.
- Dataflow (`codevanta.analysis.dataflow` + `codevanta dataflow` + MCP tool
  `codevanta_dataflow`): one forward pass over the recursive CFG recovers
  register definitions, uses, provable constants (`mov` immediates, copies,
  `add`/`sub`/`xor` of known values, rip-relative loads) and reaching
  definitions, with alias normalisation and call-clobber handling. Honest
  limits stated in the result: the pass is a linearization (joins take the
  highest-addressed predecessor), undefined reads become warnings, and nothing
  is guessed.
- Evidence bundles (`codevanta.analysis.evidence_bundle`): hash a subject
  binary (streamed SHA-256) and any number of canonical-JSON payloads into one
  frozen document; `verify_bundle` recomputes every digest and reports each
  mismatch by name, catching edited payloads, edited digests, and
  added/removed/renamed entries. Bounded (256 entries, 16 MiB per payload),
  deterministic byte-for-byte across builds, with `build`/`verify`/`read`/
  `write`/`dumps` helpers and the digest recipe documented for non-Python
  verifiers.
- Plugin SDK (`codevanta.plugins`): a structural protocol (name, version,
  description, `analyze(context) -> mapping`) so an outside analyser never
  needs to import CODEVANTA; entry-point discovery (`codevanta.analyzers`,
  kinds analyzer/exporter/provider) that reads metadata without importing; a
  process-local registry with `register`/`unregister`/`builtin_plugins`;
  `build_context` (loaded binary, discovered candidates, entry-point focus,
  read-only budget) and `run_plugin` under a wall-clock and canonical-JSON byte
  budget. The built-in `MetricsAnalyzer` proves the path end to end, and
  `codevanta plugins list/run` drive it from the CLI.
- Trace and attach CLI (`codevanta trace`, `codevanta attach`): replay a saved
  gdb/Frida session capture and map its hits onto function candidates
  (`--provider auto` detects the format and states its choice; an unplaceable
  capture exits 2 instead of guessing), and generate the provider script plus
  the exact argv that runs it — without ever launching anything. MCP parity via
  `codevanta_trace`, whose errors carry the real reason instead of a generic
  tool failure.
- GUI session persistence: `/api/session_save` (the dashboard's one writing
  route — one row in the same SQLite store `codevanta session save` uses) and
  `/api/session_list`, plus a Sessions panel; the counts a save records come
  from the same engines the page displays.
- Parser fuzz harness (`scripts/fuzz_parsers.py` +
  `tests/test_fuzz_parsers.py`): seeded, replayable mutations (byteflip,
  truncate, length-field, section-table, huge-counts, zero-sizes, splice) of
  the committed samples and in-memory-packed ELFs, treating any undocumented
  exception from the public API as a finding that names seed, iteration, file,
  edit and mutant digest.
- Benchmark regression gate (`scripts/bench_gate.py` +
  `tests/test_bench_gate.py`): imports `scripts/bench.py`'s measurement helpers
  and compares every `best_ms` against a committed best-of-15 baseline (50%
  default tolerance, missing rows fail, `--repeat` can raise precision but
  never drop below the baseline's, one confirming re-measure keeps the better
  pass, `--update-baseline` accepts new numbers, `--platform` picks the
  baseline).

### Changed

- Dashboard usability pass (`codevanta gui`): the workflow is now guided
  instead of expert-first. Step 1 is a single path field with one primary
  **Analyze** button (Enter works too); its result renders as a plain-language
  overview — format/arch chips, section/import/export/symbol/function/string
  counts, entry point, human-readable file size, SHA-256 — instead of a raw
  JSON table. Step 2 presents the six deeper views as cards with
  plain-English titles and one-line questions they answer ("Who calls whom",
  "Code flow", "Data layouts", ...), each carrying only its own contextual
  options. Diff moved into a collapsed "Advanced" disclosure, the empty state
  explains what to do first, and JSON stays available under "Raw JSON (for
  scripts and agents)". Element ids stayed stable where tests pin them; all
  rendering remains `textContent`-only with zero external references.
- Dashboard redesign (`codevanta gui`): the layout was rewritten around a
  sticky top bar with trust badges (read-only, local), a hero path input with
  Enter-to-run, a labeled options panel, a full-width seven-action toolbar,
  and a result card with a sticky-header table, colored confidence badges
  (certain/high green, medium amber, low red), a "HTTP 200 · N of M rows"
  status chip, auto-scroll to results, and raw JSON tucked into a collapsible
  disclosure. Typography now pairs a system sans for UI with monospace
  reserved for data; surfaces are layered (page, card, inset inputs) with a
  single teal accent. Still a fully self-contained page: no CDN, no fonts, no
  external URL, and results remain `textContent`-only.

### Fixed

- Trace attribution (`codevanta.analysis.trace`): a hit above the last known
  function was attributed to it because an unknown candidate size was treated
  as unbounded. Candidate extents now come from the symbol size or, failing
  that, the enclosing executable section, and an address outside every
  candidate is reported unattributed instead of guessed onto the nearest
  symbol.

### Added

- Dynamic session layer (`codevanta.analysis.dynamic`): gdb and Frida providers
  with availability detection that never imports the tool, deterministic
  non-interactive script builders (`build_gdb_script`, `build_frida_script`) that
  bound hits, validate addresses against executable sections and record a header
  with the target and image base, plus `attach_command` for the exact argv a user
  should run. Nothing is launched: the scripts are generated for the user to run.
- Trace analysis (`codevanta.analysis.trace`): `parse_gdb_trace` and
  `parse_frida_trace` turn a finished session into a `TraceReport` — hits mapped to
  function candidates, hits per function, unique addresses, truncation and
  evidence — so dynamic results feed the same evidence pipeline as static ones.
- Ghidra provider in CI (`ghidra-parity`, best effort): a pinned Ghidra release and
  JDK are downloaded, `GHIDRA_INSTALL_DIR` is exported and the parity tests run
  against the real Ghidra decompiler; when the download cannot happen the job
  prints a notice instead of pretending it ran. `pyghidra` joined the
  `decompilers` extra.
- Type propagation for the pseudo-C decompiler (`codevanta.analysis.type_propagation`):
  per-argument inference from how each register is used (pointer dereference,
  sub-width load, arithmetic, comparison against zero, unused), a return type from
  the last write before `ret`, and every verdict carrying the observation that
  produced it at a stated confidence. The decompiler signature and
  `evidence.extra` now say `uint64_t * a0` / `int32_t a1` / `uint32_t` instead of
  `undefined64` for everything.
- Decompiler parity job (`decompile-parity` in CI): installs the new
  `decompilers` extra, prints `scripts/check_decompiler_backends.py`, and runs
  `tests/test_decompiler_parity.py`, which decompiles a fixture through a real
  angr backend and asserts the provider layer picked it instead of the native
  fallback. `scripts/check_decompiler_backends.py` gives the same availability
  report locally, with `--json` for tooling.
- MCP: `codevanta_entropy` exposes the entropy triage over MCP (same bounded
  `threshold` / `max_sample_bytes` validation as the CLI), and
  `codevanta_analyze` gains `include_xrefs` / `include_cfg` /
  `include_callgraph` flags mirroring the CLI so a single call can carry the
  phase 2 sections; defaults keep the phase 1 payload unchanged.
- Entropy triage (`codevanta.core.entropy` + `codevanta entropy`): per-section
  Shannon entropy sampled from file bytes (capped per section, sample size
  reported) with a packing heuristic — sections at or above the threshold
  (default 7.2 bits/byte, `--threshold`) get a `packed_hint` labelled medium
  confidence in evidence. Sections without file bytes (e.g. `S_ZEROFILL`,
  `NOBITS`) carry `entropy: null` with a warning instead of a fabricated
  value, and samples below the minimum floor suppress the packing judgment.
  `--max-sample-bytes` bounds the read; `--json` emits the full report.
- Local web dashboard (`codevanta.gui`, `codevanta gui`): a standard-library-only
  `ThreadingHTTPServer` bound to a loopback address serves one self-contained
  dashboard page and nine read-only `GET` JSON routes (`/api/health`,
  `/api/info`, `/api/functions`, `/api/strings`, `/api/xrefs`, `/api/cfg`,
  `/api/struct`, `/api/callgraph`, `/api/diff`). Every route is a thin adapter
  over the engine of the same name — no analysis is reimplemented — so each
  payload keeps that engine's evidence record and limits. A host outside
  `localhost`, `::1` or `127.0.0.0/8` is refused with `ValueError`, every numeric
  query parameter is validated against the consuming engine's ceiling, and a
  payload over `MAX_RESPONSE_BYTES` (4 MiB) has its top-level lists halved and is
  flagged `response_truncated`. `create_server(port=0)` returns a bound,
  unstarted server for tests and `create_handler(paths_allowed=False)` rejects
  the file-taking routes outright.
- Fat (universal) Mach-O loading (`codevanta.core.loader`): the four container
  magics (`FAT_MAGIC`, `FAT_CIGAM`, `FAT_MAGIC_64`, `FAT_CIGAM_64`, 32- and
  64-bit `fat_arch` tables) are parsed before LIEF runs, and exactly one slice is
  then parsed. Selection is deterministic and stated in the evidence: a 64-bit
  slice wins over a 32-bit one (`prefer_64bit`), otherwise the lowest file offset
  wins (`first_by_offset`); every other slice is reported, never parsed. Section
  offsets are rebased by the slice offset, so `va_to_offset()` maps into the
  outer container, and `BinaryInfo.evidence` carries `source="macho.fat_header"`
  with the structured `extra` keys (`fat`, `fat_magic`, `fat_magic_name`,
  `fat_arch_64`, `slice_index`, `slice_count`, `slice_arch`, `slice_cputype`,
  `slice_offset`, `slice_size`, `selection_rule`, `selection_reason`,
  `available_arches`, `available_slices`) at `certain` confidence. Malformed
  containers raise `BinaryLoadError` naming the defect — zero `nfat_arch`, a
  truncated `fat_arch` table, a zero slice size, or an offset/size past the end
  of the file.
- Committed PE and Mach-O samples (`samples/pe64_text.bin`,
  `samples/macho64_text.bin`): a PE32+ image with one executable `.text` and a
  one-entry export table, and a thin `MH_EXECUTE` Mach-O exporting
  `_codevanta_sample_main`, sharing one hand-assembled x86_64 code body and ASCII
  payload so cross-format behaviour can be compared directly.
  `scripts/make_samples.py` (standard library only) regenerates them byte for
  byte from zeroed timestamps and fixed padding, `--check` exits non-zero when a
  committed sample is stale, `--output-dir` writes elsewhere, and
  `tests/test_samples.py` enforces that in CI.
- MCP HTTP transports (`codevanta.mcp_server.server.run`, `codevanta mcp serve`):
  `transport` accepts `stdio` (default, unchanged: JSON-RPC over stdin/stdout),
  `sse` and `streamable-http`, which bind `host:port` instead
  (`port=0` picks a free port). Because these tools read arbitrary local files, a
  non-loopback host is refused unless `allow_remote=True`, and an unknown
  transport raises `AnalysisError` naming the supported set. The CLI forwards
  every option verbatim (`--transport`, `--host`, `--port`, `--allow-remote`) and
  exits `2` on a rejected transport or bind, so existing stdio configurations
  keep their meaning.
- CI coverage and type checks (`.github/workflows/ci.yml`): the test job runs
  `pytest --cov=codevanta --cov-report=term-missing`, and a separate `type-check`
  job runs `mypy src/codevanta` on Python 3.13.
- Benchmark script (`scripts/bench.py`): times the public analysis entry points
  (`load`, `discover_functions`, `extract_strings`, disassembly, `find_xrefs`,
  `build_cfg`, `build_call_graph`, `function_fingerprint`, `suggest_struct`, and
  `diff_binaries` when two inputs are given) with `time.perf_counter` only, so a
  performance regression shows up as a number. It defaults to the committed
  `samples/`, takes `--repeat`, `--max-instructions` and `--limit-functions`
  bounds, reports the shortest run per benchmark as `best_ms`, prints a sorted
  table or `--json`, and writes nothing — inputs are read, never mapped or
  executed. A benchmark the analysis layer refuses shows `iterations 0` with the
  reason on stderr instead of a fabricated time.
- API reference and sample documentation (`docs/api.md`, `docs/samples.md`):
  every public entry point with the signature and defaults read from the source,
  the evidence/confidence contract, the dashboard routes, the fifteen MCP tools,
  and six runnable recipes whose printed output is the real output; plus a page
  per sample binary with its SHA-256 and one working command each.

- Big-endian UTF-16 string extraction (`codevanta.core.strings`): the UTF-16
  scan now follows the binary's endianness — big-endian targets (e.g. MIPS,
  s390x, PowerPC) yield `utf-16be` strings, little-endian targets keep
  `utf-16le`. Without binary metadata the scan stays UTF-16LE rather than
  guessing a byte swap, so shifted cross-byte-order matches are never
  fabricated. Evidence labels follow the existing scheme
  (`string_scanner` / `utf-16be_scan`).
- Mach-O loader support (`codevanta.core.loader`): Mach-O 32/64 binaries now
  load with format, architecture (x86_64, aarch64, x86, arm, ppc), bitness,
  endianness, image base, entry point, sections, imports (undefined symbols),
  exports (dyld export information), and symbol-table entries — every finding
  carrying evidence. Mach-O symbol entries do not encode kind, so
  `is_function` is derived from executable-section membership, stated in the
  evidence detail, and function candidates from the Mach-O symbol table are
  reported at `medium` confidence. Sections without file bytes (e.g.
  `S_ZEROFILL`) map to no file offset, keeping VA/offset translation honest.
- Cross-reference scanner (`codevanta.analysis.xrefs`): `call`, `jump`, and
  `branch` references recovered from direct branch operands in executable
  sections. Targets that are only reachable through registers or memory are
  skipped rather than guessed. Every reference carries evidence
  (`capstone.direct_call` / `direct_jump` / `conditional_branch`, confidence
  `certain`), and the scan reports section coverage, scanned bytes, and whether
  it was truncated by the `max_bytes` budget.
- Control-flow graph builder (`codevanta.analysis.cfg`): linear sweep of one
  region into `BasicBlock`s with sorted, deduplicated successor edges derived
  from leader and terminator rules. Indirect branches stay unresolved; the
  sweep is bounded by `max_instructions` and `max_blocks` and is labelled
  `medium` confidence because block boundaries are heuristic.
- SQLite session storage (`codevanta.storage.session`): additive analysis
  records (fingerprint, format, architecture, bitness, entry point, function and
  string counts, notes) with `save`, `get`, `list`, and `delete`. Standard
  library only, parameterized SQL, bounded queries.
- CLI: `codevanta xrefs` (with `--limit`, `--max-bytes`, `--json`),
  `codevanta cfg` (with `--address`/`--function`, `--max-instructions`,
  `--max-blocks`, `--json`), and `codevanta session save|list|show` (with
  `--db`, defaulting to `$CODEVANTA_DB` or `~/.codevanta/sessions.db`).
- Direct-call call graph (`codevanta.analysis.callgraph`): `build_call_graph`
  aggregates the `call` cross references into `CallGraphNode` /
  `CallGraphEdge` records plus a generic `{nodes, edges}` model. Every call
  target that is not a known candidate becomes an `external` node, edges are
  deduplicated by `(source, target, from_address)` and bounded by
  `max_functions` / `max_edges`. Caller attribution is heuristic — the nearest
  function candidate at or below the call site inside the same section — so the
  graph reports `medium` confidence, uses the call address as the source for
  unattributable sites, and says so in `warnings`.
- Graph export (`codevanta.analysis.graph_export`): dependency-free `to_dot` and
  `to_graphml` render the shared graph model with deterministic ordering, strict
  contract validation (`GraphExportError`), escaped/quoted DOT strings, and a
  GraphML document with `label`/`kind`/edge-label keys. Output only — nothing is
  written to disk.
- Session annotations (`codevanta.storage.session`): `Annotation` records plus
  `annotate` (one upsertable note per `(session_id, address)`), `annotations`
  (ordered by address), and `remove_annotation`. Notes are bounded to 4,000
  characters, blank notes and unknown sessions raise `SessionError`.
- MCP tools: `codevanta_xrefs`, `codevanta_cfg`, `codevanta_session_save`, and
  `codevanta_session_list` join the five phase 1 tools, for nine tools total.
  Bounded arguments, shared database resolution (explicit `db`, then
  `$CODEVANTA_DB`, then `~/.codevanta/sessions.db`), and the same evidence
  semantics as the CLI.
- CLI: `codevanta callgraph` (with `--limit-functions`, `--limit-edges`,
  `--format json|dot|graphml`, `--output`/`-o`) and
  `codevanta session annotate SESSION_ID ADDRESS NOTE` /
  `codevanta session notes SESSION_ID` (decimal or `0x` hex addresses, `--db`).
- Import and indirect call resolution (`codevanta.analysis.xrefs`): `call`
  instructions through an absolute or RIP-relative pointer slot
  (`call qword ptr [0x402000]`, `call qword ptr [rip + 0xa]`) now resolve to the
  slot address — RIP-relative operands are biased by the instruction length, so
  negative displacements work. A slot that matches an `info.imports` address
  becomes `call_import` with `target_name` set to the import name and confidence
  `certain`; any other resolved slot becomes `call_indirect` with confidence
  `high` (the slot is proven, the callee is not). The reported `to_address` is
  always the slot, never the code behind it. Register and indexed operands
  (`call rax`, `call qword ptr [rax + 8]`) are skipped and counted in the new
  `XrefResult.indirect_skipped` field, which `to_dict()` exposes; indirect jumps
  and conditional branches are not counted. Direct literal operands still take
  precedence, and the scan stays bounded by `max_bytes`.
- Call graph coverage (`codevanta.analysis.callgraph`): edges now come from
  `call`, `call_import`, and `call_indirect` cross references. A resolved import
  slot becomes an `import` node labelled from the import table (`high`
  confidence, namespaced `import:0x<addr>` in the generic graph model), a
  `call_indirect` slot stays an `external` node (`unknown` confidence), and
  `jump`/`branch` references plus unresolved indirect calls still produce no
  edges. Edge deduplication, ordering, limits, and the heuristic caller
  attribution (nearest candidate at or below the call site in the same section,
  with one aggregated warning for unattributable sites) are unchanged.
- `codevanta analyze --callgraph`: embeds `report["callgraph"]` when the flag is
  passed and omits the key entirely when it is not. The embedded graph is bounded
  to 1000 functions and 5000 edges
  (`REPORT_MAX_CALLGRAPH_FUNCTIONS` / `REPORT_MAX_CALLGRAPH_EDGES`), reuses the
  pre-computed candidates, sets `truncated` when a cap cuts it short, and prints
  a one-line node/edge/truncation summary alongside `--output`. The analysis
  layer is imported lazily, so `codevanta.core.report` gains no import-time
  dependency on `codevanta.analysis`.
- MCP tool `codevanta_callgraph` (`limit_functions`, `limit_edges`, defaulting to
  1000 and 5000, accepted range 1..200000) joins the server, bringing it to ten
  tools. It returns `CallGraph.to_dict()` with nodes, edges, `truncated`,
  `warnings`, and evidence, and rejects non-integer or out-of-range limits with
  `AnalysisError`.
- Documentation: `docs/phase2c.md` covers import/indirect resolution, import
  nodes, the embedded report graph, the ten MCP tools, CLI examples, remaining
  limits, and next steps; the README now links `CONTRIBUTORS.md` from its
  Community section.
- `validate_graph` (`codevanta.analysis.graph_export`) is now public: the DOT and
  GraphML checks return a normalized, deterministically ordered copy, so other
  renderers reuse one contract instead of duplicating it.
- Offline HTML/SVG graph viewer (`codevanta.analysis.html_view`): `to_html`
  renders the shared graph model as one self-contained HTML5 document — inline
  stylesheet, inline SVG in three `kind`-based columns
  (`function`/`entry_point`, `call_site`, everything else), header node/edge
  counts, arrowed straight-line edges, a collapsible `<details>` table listing
  every edge, and an `application/json` payload of the normalized graph. It
  references no `http(s)` URL, CDN, web font or external file and shipped without
  JavaScript logic in its phase 2d form (phase 2f adds one inline script; see
  below), so it opens offline; the `<svg>` omits `xmlns` and is
  inline-only. Output is byte-identical for identical content.
- CLI: `codevanta callgraph --format html` (with `--output`/`-o`) joins
  `json|dot|graphml`. Every serializer now receives size-derived caps
  (`max(default, len(...))`), so a graph the analysis already accepted is never
  rejected downstream by an exporter default.
- Documentation: `docs/phase2d.md` covers the viewer, the three columns, document
  anatomy, caps and sizing, offline guarantees, limits, and next steps.
- Recursive CFG traversal (`codevanta.analysis.cfg`): new
  `build_recursive_cfg(path, info, start, max_instructions=2000, max_blocks=500)`
  returns the same `FunctionCFG` as `build_cfg`, but follows control flow from
  `start` with a worklist of block starts and a visited set instead of decoding a
  fixed window. Successors follow the block-terminating instruction: a
  conditional jump yields fallthrough plus its direct target, an unconditional
  `jmp` yields the target only, `ret`/`iret` yield none, and every other
  instruction (including `call`) yields fallthrough only. Call targets are not
  followed and indirect jumps are not resolved; direct targets outside executable
  sections are dropped and reported in `warnings`. Blocks and successors are
  sorted, the graph is bounded by `max_instructions` / `max_blocks` (with the
  existing `truncated` flag), and evidence uses `cfg.recursive_traversal` at
  `medium` confidence because indirect targets remain unresolved. Unreachable
  padding after a `ret` or `jmp` is no longer decoded.
- CLI: `codevanta cfg --traversal linear|recursive`. The default stays `linear`,
  so existing invocations, tables, and JSON output are unchanged; `recursive`
  selects `build_recursive_cfg` and reports the same payload with the
  `cfg.recursive_traversal` evidence source.
- Documentation: `docs/phase2e.md` covers the new traversal, its successor rules,
  how it differs from the linear sweep, the CLI flag, evidence and confidence,
  bounds, limitations, and next steps.
- Jump-table resolver (`codevanta.analysis.jump_tables`): `resolve_jump_table`
  decodes a bounded array of absolute pointers starting at a caller-supplied
  address — 8-byte slots on a 64-bit binary, 4-byte on a 32-bit one, decoded with
  the binary's endianness. The scan stops at the first slot that cannot be a
  target (zero terminator, target outside `min_target`/`max_target`, target no
  section maps, or — with the default `executable_only` — a target in a
  non-executable section) and records why in `warnings`. Work is bounded by
  `max_entries` (default 256, hard ceiling 4096) plus one pointer-sized peek that
  decides `truncated`. Slot and summary evidence use
  `jump_table.pointer_array` / `absolute_pointers` at `medium` confidence: a
  pointer array found by shape is evidence of a dispatch table, not proof that a
  dispatcher indexes it.
- Opt-in indirect resolution in the recursive CFG
  (`codevanta.analysis.cfg.build_recursive_cfg`): `resolve_indirect=False`
  (default) keeps phase 2e behaviour byte-for-byte; when enabled, a
  block-terminating `jmp qword ptr [rip + disp]` / `jmp qword ptr [abs]` (and
  the `dword` 32-bit forms) is turned into a table address and decoded with the
  jump-table resolver, and its executable, file-backed targets become sorted,
  deduplicated successors that the traversal follows. Bounded by
  `max_jump_tables` (default 8) and `max_table_entries` (default 256, ceiling
  4096); register/indexed operands, unreadable tables, and tables past the budget
  leave the edge out and are reported in `FunctionCFG.warnings`, prefixed with
  the block start. Evidence stays `cfg.recursive_traversal` at `medium` and its
  detail names how many tables and slots were resolved when the option is on.
- CLI: `codevanta jump-table PATH --address ADDR [--entries N]
  [--executable-only/--no-executable-only] [--json]` prints an index/target
  table with a pointer-size, entry-count, and truncated footer plus one warning
  per stop reason, and exits `2` on an invalid address, a rejected budget, or a
  table that cannot be read.
- CLI: `codevanta cfg --resolve-indirect`, accepted only with
  `--traversal recursive` (the linear sweep exits `2` instead of silently
  ignoring it). The other cfg output and options are unchanged, and the
  jump-table budgets stay at their library defaults on the command line.
- Interactive offline viewer (`codevanta.analysis.html_view`): the HTML export
  now carries one inline, dependency-free script adding drag-to-pan (via
  `viewBox`), wheel zoom anchored at the pointer and clamped to 0.2x–8x, a label
  search that highlights hits and dims the rest (Esc clears it), and per-kind
  filter checkboxes (function/entry_point, call_site, import/external). Still no
  CDN, no web font, and no `http(s)` reference anywhere; the static view renders
  in full with scripting disabled, and output remains deterministic and escaped.
- Structural binary diff (`codevanta.analysis.binary_diff`): `diff_infos` /
  `diff_binaries` compare two binaries as metadata only — functions matched by
  address (with `name`/`size` compared) then by name (so a relocated function is
  one `changed` entry, not a removal plus an addition), sections and exports by
  name, imports by `(library, name)`. `max_functions` defaults to 5000, is
  clamped to 1..20000, keeps the lowest addresses when it truncates, and records
  the clamp. Evidence uses `binary_diff.structural` / `metadata_compare` at
  `medium` confidence with the explicit caveat that no instruction bytes were
  read, compared, or executed, so `identical` means "no structural delta was
  observed", never "the code is equivalent".
- CLI: `codevanta diff LEFT RIGHT [--max-functions N] [--json]` prints an
  `Identical` header, per-kind delta counts, the named section/import/export
  deltas, and a function-delta table sorted by address. A difference exits `0`;
  only load or input errors exit `2`.
- Documentation: `docs/phase2f.md` covers the jump-table resolver and its stop
  rules, CFG opt-in resolution and its warnings, the interactive viewer, the
  structural diff and its matching rules, the CLI surface, confidence, limits,
  and next steps.
- Relative jump tables (`codevanta.analysis.jump_tables`): `resolve_jump_table`
  gained `mode="absolute"|"relative"` (case-insensitive, `MODE_RELATIVE`) plus
  `base_address`. Relative mode reads each 4-byte slot as a *signed* 32-bit
  offset and resolves `target = base_address + offset`, so position-independent
  switch tables work; an explicit `pointer_size` other than 4 is rejected, and a
  missing base raises `AnalysisError` instead of guessing one. A zero offset is a
  real entry pointing at the base and no longer terminates anything — only the
  shared stop rules (target outside `min_target`/`max_target`, unmapped target,
  or a non-executable target under `executable_only`) end the scan, and each is
  reported in `warnings` exactly as in absolute mode. `truncated` still requires
  the entry ceiling plus a further usable slot. Evidence uses
  `jump_table.relative_offsets` / `signed_offsets` at `medium` confidence and
  records the base on every record; absolute mode keeps
  `jump_table.pointer_array` / `absolute_pointers` and byte-identical output.
- Function fingerprints (`codevanta.analysis.function_hash`, new):
  `normalize_instruction` renders one instruction as `"<mnemonic> <operands>"`
  with a lower-cased mnemonic and every numeric literal masked to `#` (hex before
  bare decimals, digit-bearing register/operand names preserved, consecutive
  masks collapsed, whitespace normalized). `function_fingerprint` disassembles a
  bounded linear sweep from an address and returns a `FunctionFingerprint` whose
  `digest` is the SHA-256 of the newline-joined normalized stream. The budget is
  `max_instructions` (default 2000, accepted 1..100000) and the read window is
  `max_instructions * 16` bytes clipped to the section, so `truncated` reports a
  prefix-only digest. Evidence uses `function_hash.normalized` /
  `normalized_linear_disassembly` at `medium` confidence and states the caveat:
  this is a shape fingerprint, so equal digests are not byte equality and
  different digests are not a semantic difference.
- Deep diff (`codevanta.analysis.binary_diff`): `deep=False` is now an explicit
  argument on `diff_infos` and `diff_binaries`. When true, every
  address-matched function pair is fingerprinted on both sides
  (`DEEP_MAX_INSTRUCTIONS` = 2000, equal to the standalone default); a differing
  digest makes the entry `changed` with a content note and both digests, a
  metadata-only change whose digests match says so, and `FunctionDelta` gained
  `left_digest` / `right_digest` (always both set or both `None`, serialized by
  `to_dict()` when present). Matching rules, structural-only output, and the
  `added`/`removed`/`changed` semantics are unchanged; relocated (name-matched)
  and one-sided functions are not fingerprinted. Deep mode is bounded by
  `MAX_DEEP_FINGERPRINTS=1000` address-matched pairs per side (lowest addresses)
  and reports truncated, capped, and failed fingerprints through `warnings`
  instead of raising; its top-level evidence switches to the content caveat and
  records `deep`, `deep_instructions`, and `max_deep_fingerprints`.
- CLI: `codevanta jump-table --mode absolute|relative --base ADDR`.
  `--mode` is optional, case-insensitive, and validated before the file loads
  (an unknown layout exits `2`); omitting it keeps the phase 2f absolute
  behaviour and the unchanged footer. `--base` uses the same decimal/`0x` parser
  as `--address` and rejects unparsable or negative values with `invalid base`.
  `--mode relative` without `--base` exits `2` instead of inventing an origin,
  and the footer gains `mode: <layout>` only when `--mode` was given plus
  `base: 0x…` only for relative tables. `--json` output is the resolver's
  `to_dict()` unchanged.
- CLI: `codevanta diff --deep` passes `deep=True` to `diff_binaries`. The
  function-delta table gains a `Digest (left -> right)` column only when a delta
  carries digests, showing the first 12 hex characters of each side's SHA-256
  joined by ` -> ` and `-` for `added`/`removed` or over-ceiling pairs; a dim
  footer states that equal digests are not byte equality. `--json` keeps the
  existing document shape with `left_digest`/`right_digest` inside
  `functions_changed` and `evidence.extra.deep`, and exit codes are unchanged.
- Documentation: `docs/phase2g.md` covers the relative table layout and its
  zero-offset rule, the shared stop rules, fingerprint normalization, digests,
  bounds and caveats, deep-diff behaviour and bounds, the `--mode`/`--base` and
  `--deep` CLI reference, confidence, limits, and next steps.
- Struct-field suggestions (`codevanta.analysis.type_recovery`):
  `suggest_struct(path, info, start, max_instructions=2000, max_fields=64,
  include_stack=False)` disassembles a bounded window and reads the memory
  operands of every decoded instruction. Only `[reg]`, `[reg + 0xNN]` and
  `[reg - 0xNN]` are understood — a decimal displacement is accepted like a hex
  one — while an index register, a scale or a segment prefix is skipped rather
  than guessed, and `lea`, `nop` and `prefetch*` are skipped because they do not
  access memory. Widths come from the `byte`/`word`/`dword`/`qword` keyword
  (1/2/4/8), falling back to the pointer width of the binary. Direction is a
  write when the memory operand is first and a read otherwise, except
  `cmp`/`cmps`/`cmpsb`/`cmpsw`/`cmpsd`/`cmpsq`/`test`, which are always reads.
  Accesses aggregate per offset into `SuggestedField` records (dominant width,
  ties to the wider access; read/write totals across widths; ascending offsets),
  stack registers (`sp`/`esp`/`rsp`/`bp`/`ebp`/`rbp`) are dropped unless
  `include_stack=True`, and `max_fields` sets `truncated` with lower offsets
  winning. Every record is `medium` confidence
  (`type_recovery.memory_operand`/`operand_scan`,
  `type_recovery.suggestion`/`operand_aggregation`) and states that fields are
  heuristic from operand shapes, not verified types.
- MCP tools: `codevanta_diff` (structural binary diff with optional `deep`
  fingerprinting, `max_functions` default 5000), `codevanta_jump_table`
  (absolute by default, `mode="relative"` requires `base`, `entries` default 256
  and values above 4096 are rejected), and `codevanta_function_hash` (normalized-shape SHA-256
  with `max_instructions` default 2000) bring the server to thirteen tools.
  Arguments are validated the same way as the CLI (limits `1 .. 20000`,
  non-negative addresses, booleans rejected for flags) and analysis failures
  raise `AnalysisError`; struct suggestions were not exposed over MCP until
  `codevanta_struct` in phase 2i.
- CLI: `codevanta struct PATH` with `--address`/`-a`, `--function`/`-f`,
  `--max-instructions`, `--max-fields`, `--include-stack`, and `--json`. The
  start address resolves as address, then function name, then entry point. The
  table lists `Offset`, `Width`, `Reads`, and `Writes` per suggested field with a
  footer for the base registers the sweep saw, the field and instruction counts,
  the applied field cap, and the truncation flag, followed by one `warning:` line
  when the cap was reached or no field was decoded (the latter also points at
  `--include-stack`). Base registers come from a second bounded pass over the
  same window, so they are the registers in use, not a per-field attribution.
  `--json` prints the suggestion's `to_dict()`, and load or input errors (missing
  file, invalid address or limits, unknown function, non-executable address)
  exit `2`.
- CI: the test matrix in `.github/workflows/ci.yml` is now `"3.11"`, `"3.13"`,
  and `"3.14"` (`fail-fast: false`), with the wheel build and clean-venv smoke
  test still on 3.13. Python 3.14 was previously held back because it needed
  published `lief` wheels; `lief` now ships `cp314` wheels (`lief 1.0.0`), so the
  `lief>=0.14` requirement resolves to a 3.14-capable release.
  `requires-python` stays `>=3.10`, so 3.10 and 3.12 remain supported without
  being exercised by CI, and `docs/repository-settings.md` was updated to match.
- Documentation: `docs/phase2h.md` covers the operand shapes that are and are not
  recovered, the stack-register rule, width and direction rules, per-offset
  aggregation (including that offsets from different base registers share one
  bucket), the `medium` evidence labels, bounds and determinism, the thirteen
  MCP tools, the `codevanta struct` CLI reference, the new CI matrix, confidence,
  limitations, and next steps.
- Struct layout hints (`codevanta.analysis.type_recovery`): `StructSuggestion`
  gains `alignment` and `array_groups`, both derived from the fields the
  suggestion actually reports, so the `max_fields` cap can change them.
  `alignment` is the greatest common divisor of the absolute non-zero offsets —
  offset `0` is ignored because it is a multiple of every candidate — and is
  `None` when fewer than two distinct non-zero offsets were seen. `array_groups`
  holds `ArrayGroup(offset, stride, count, width, evidence)` records for maximal
  runs of at least three consecutive fields (in ascending offset order) that
  share one width and one stride; a run stops at the first width or stride
  change, the scan then restarts at the next field so no field belongs to two
  groups, and `span` is `stride * (count - 1) + width`. Every group is `medium`
  confidence (`type_recovery.array_run` / `stride_run_detection`) and its detail
  states that the heuristic cannot tell an array from repeated struct members.
- Function similarity (`codevanta.analysis.function_hash`):
  `normalized_tokens(path, info, address, max_instructions=2000)` returns the
  tokens the fingerprint hashes — one shared sweep, so the digest and the tokens
  cannot disagree — and `function_similarity(...)` compares two regions as
  multisets of those tokens (`shared = sum(min)`, `union = sum(max)`,
  `score = shared / union`, in `0.0 .. 1.0`), returning
  `SimilarityResult(score, shared, left_total, right_total, evidence, warnings)`
  with the score rounded to four decimals in `to_dict()`. Evidence is
  `function_hash.similarity` / `token_multiset` at `medium` confidence with a
  shape-not-semantics caveat; a truncated side adds a warning, and a side with no
  tokens raises `AnalysisError` instead of scoring `0.0`. Work is bounded to
  `2 * max_instructions` instructions and `2 * max_instructions * 16` bytes.
- MCP: `codevanta_struct` exposes `suggest_struct` with `address`/`function`/
  `max_instructions`/`max_fields`/`include_stack` and returns the suggestion's
  `to_dict()` unchanged, including `alignment` and `array_groups` — fourteen
  tools total. Bounded arguments, `AnalysisError` on bad input, and the same
  evidence semantics as the CLI. Function similarity is not exposed over MCP.
- CLI: `codevanta struct` prints `alignment: <n>` (or `alignment: unknown` when
  none could be derived) plus one
  `array at 0x10: 3 x 8-byte, stride 8` line per array candidate — or
  `arrays: none` when no run was found — between the counts line and the
  warning lines. `--json` output carries `alignment` and `array_groups`
  unchanged.
- Documentation: `docs/phase2i.md` covers the gcd alignment rule and its `None`
  cases, the maximal-run array heuristic and its evidence, the Ruzicka multiset
  similarity and its normalization, the fourteen MCP tools including
  `codevanta_struct`, the `codevanta struct` footer, the `medium` labels, bounds
  and determinism, limitations, and next steps.
- Semantic diff pairing (`codevanta.analysis.binary_diff`): `diff_infos` and
  `diff_binaries` gain `semantic=False` and
  `threshold=DEFAULT_SEMANTIC_THRESHOLD` (0.9). With `semantic=True` the
  candidates that address and name matching left unpaired are scored with
  `function_similarity`, sorted by descending score (ties broken by left then
  right address) and taken greedily while the score is at least `threshold` and
  neither side has been used. Each accepted pair becomes one `changed` delta at
  the right-hand address with `FunctionDelta.similarity` rounded to four decimals
  and an evidence detail naming the score, the threshold, both addresses, and the
  fact that a shape overlap is not proof of equal code; structurally matched
  deltas keep `similarity=None` and omit the key from `to_dict()`. A pairing can
  only replace a remove-plus-add pair, never an address or name match, so
  structural mode and the `identical` flag semantics are unchanged. The pass is
  bounded by `MAX_SEMANTIC_PAIRS` (4096): above that leftover cross product the
  whole pass is skipped with a warning and every leftover keeps its
  `added`/`removed` verdict, and each score decodes at most
  `SEMANTIC_MAX_INSTRUCTIONS` (2000) instructions per side. A pair that cannot be
  scored is skipped and summarised in a warning, `threshold` is validated in every
  mode (finite number in `0.0 .. 1.0`, else `AnalysisError`), and the comparison
  evidence gains `semantic`, `semantic_threshold`, `semantic_instructions`, and
  `max_semantic_pairs`.
- Signedness hints (`codevanta.analysis.type_recovery`): `SuggestedField` gains
  `signed: bool | None`, read from the mnemonic of each access —
  `movsx`/`movsxd`/`sar`/`idiv`/`imul` mark signed,
  `movzx`/`shr`/`div`/`mul` mark unsigned, every other mnemonic carries no hint.
  Hints are aggregated per offset: one kind gives `True`/`False`, no hint gives
  `None`, and a contradiction gives `None` plus one
  `SignednessConflictWarning` (a `UserWarning`) naming the offset. `signed` is
  omitted from `SuggestedField.to_dict()` when it is `None`, so an unclassified
  field's JSON is unchanged, while the field evidence detail now names the hint
  (`signedness signed|unsigned|unknown`) and `evidence.extra["signed"]` carries
  the same value. `None` means "no evidence", never "safe".
- MCP: `codevanta_similarity` takes `path_a`, `address_a`, `path_b`, `address_b`,
  and `max_instructions=2000`, exposes `function_similarity`, and returns its
  `to_dict()` (`score`, `shared`, `left_total`, `right_total`, `union`,
  `warnings`, evidence at `function_hash.similarity` / `token_multiset`,
  `medium`). Addresses must be non-negative integers and are validated per side,
  `max_instructions` stays in `1 .. 20000`, and bad input raises
  `AnalysisError` — fifteen tools total. `codevanta_diff` keeps only
  `max_functions` and `deep`, so the semantic pass has no MCP argument yet.
- CLI: `codevanta diff --semantic` / `--threshold`. The threshold defaults to
  `DEFAULT_SEMANTIC_THRESHOLD` (0.9), is validated before either binary is loaded
  (a value outside `0.0 .. 1.0`, `nan`, or `inf` exits 2 with
  `invalid threshold ...`), and is checked even without `--semantic`.
  `--semantic` passes `semantic=True` / `threshold` to `diff_binaries`, so a
  relocated function becomes one `changed` row instead of a removal plus an
  addition, and each scored pair prints one dim
  `semantic pair 0x401000 -> 0x401010 (<name>): similarity 1.0000` line after the
  otherwise unchanged function table (no `Similarity` column), followed by a dim
  caveat that a pairing is not proof of equal code. `AnalysisError` from the
  analysis layer now also maps to exit 2, and `--json` carries `similarity` plus
  the `semantic` evidence keys.
- CLI: `codevanta struct` closes its footer with a `signed:` line listing
  `<offset> signed|unsigned` for every field whose mnemonics carried a hint, in
  table order — for example `signed: 0x10 signed, 0x18 unsigned` — or
  `signed: none` when nothing hinted (`none` means "no evidence", never "safe").
  The four `Offset`/`Width`/`Reads`/`Writes` columns and the phase 2h/2i footer
  lines are unchanged, and contradictory offsets stay absent from the line because
  the analysis layer already collapsed them to `signed=None`.
- Documentation: `docs/phase2j.md` covers the semantic pairing rule, its two
  bounds and warnings, threshold validation, the semantic caveat and evidence
  keys, the fifteen MCP tools including `codevanta_similarity`, the mnemonic
  signedness sets and their `None`/conflict semantics, the `diff --semantic` /
  `--threshold` switches and the `struct` `signed:` footer, limitations, and next
  steps.
- MCP `codevanta_diff` (`codevanta.mcp_server.tools` / `server`): gains
  `deep=False`, `semantic=False`, and `threshold=DEFAULT_SEMANTIC_THRESHOLD`
  (0.9) next to `max_functions`, so the phase 2j pairing pass is reachable from an
  agent in one call instead of a `codevanta_similarity` call per address pair.
  `threshold` is a finite number in `0.0 .. 1.0` and is validated in every mode —
  a boolean, a non-numeric value, `NaN`, `inf`, or an out-of-range value raises
  `AnalysisError` even with `semantic=False`, and only the two paths are checked
  first, so a bad value never costs a binary load. `deep`/`semantic` must be real
  booleans. The returned payload is unchanged except that semantic mode adds
  `semantic`, `semantic_threshold`, `semantic_instructions`, and
  `max_semantic_pairs` to the comparison evidence `extra` and `similarity` to each
  paired `changed` entry. No tool was added or removed: the server stays at
  fifteen tools.
- Cross-architecture guard (`codevanta.analysis.binary_diff`): the semantic pass
  now requires both sides to describe the same instruction set. `_semantic_pairs`
  compares `BinaryInfo.architecture` through the new `_comparable_architecture`
  helper, which **trims surrounding whitespace and lower-cases the token only** and
  maps the loader's literal `"unknown"` placeholder (`_UNKNOWN_ARCHITECTURE`) to an
  empty token, so "not determined" is never treated as "a different target". There
  is no alias table: a hand-built `"AMD64"` becomes `"amd64"` and a hand-built
  `"x86-64"` stays `"x86-64"`, so both count as *different* from `"x86_64"` and
  skip the pass. The token itself comes from the loader's per-format substring
  helper, which does not cover every machine value: PE `MIPS`/`R4000` and ELF
  `IA_64`/RISC-V/PowerPC/s390 headers all fall through to `"unknown"` (the PE
  helper has no MIPS branch, the ELF helper no IA-64 branch), and since `unknown`
  means "no claim", two `unknown` sides bypass the guard and are scored as if they
  shared an instruction set. Two different identified tokens skip the pass
  entirely with one warning naming both sides
  (`semantic matching skipped: the two sides target different architectures (left
  x86, right x86_64), ... every leftover keeps its added/removed verdict`); nothing
  is decoded or scored, address and name matching plus every structural delta and
  `deep=True` are untouched, and the gate runs before the `MAX_SEMANTIC_PAIRS`
  ceiling so one explanation is reported instead of two. It runs *after* the
  "nothing left to pair" early return, so a cross-architecture diff with an empty
  leftover on one side emits no warning at all.
- Merged struct windows (`codevanta.analysis.type_recovery`): `suggest_structs`
  folds several windows of one binary into one `StructSuggestion`. Each address is
  decoded once with the shared `max_instructions` budget and `include_stack`
  policy, and the per-window fields are merged into one field per offset — read
  and write counters summed, `first_access` the earliest any window recorded,
  width the **widest** per-window width with a `WidthConflictWarning` naming the
  offset and every width seen when the windows disagree, and signedness folded
  with the single-window rule — except that a contradiction seen *inside* one
  window is not lost to a window that only hinted one way: each per-window field
  records `signed_conflict` in its evidence, the merge checks it, and such an
  offset keeps `signed=None` with a `SignednessConflictWarning` raised by the merge
  too (whenever at least one window left a hint to compare against).
  `alignment`, `array_groups`, and `truncated` are recomputed from the merged
  fields, so a stride or alignment that only becomes visible across windows is
  still reported; `truncated` is the **OR** of the merge cap and every window's own
  `DEFAULT_MAX_FIELDS` cap, because a window that hit its own cap could not
  contribute the offsets it dropped, and `window_truncated` lists the addresses of
  the windows that hit theirs. Work is bounded by `max_windows`
  (`MIN_MERGED_WINDOWS` 1 .. `MAX_MERGED_WINDOWS` 16, default 16), one decode per
  window, `DEFAULT_MAX_FIELDS` per window, and `DEFAULT_MAX_FIELDS` merged offsets
  — at most `max_windows * max_instructions` decoded instructions. Addresses must
  be a non-empty collection of non-negative integers; duplicates
  (`window address 0x... appears more than once`), empty lists, non-integer
  entries, negative values, and over-limit counts raise `AnalysisError` before
  anything is decoded. A *partial* overlap is allowed instead of rejected — looking
  further into the same function is a legitimate second window — and announced with
  `WindowOverlapWarning`, which notes that the shared instructions are then counted
  by both windows, so the summed per-offset counters and `memory_access_count` are
  upper bounds rather than totals. Addresses are sorted, so the result and the
  warning order are identical for any permutation, `address` is the lowest merged
  address, `instruction_count` is the sum over windows, `max_fields` is always
  `DEFAULT_MAX_FIELDS`, and the merge is identifiable from
  `type_recovery.merged_suggestion` / `type_recovery.merged_field` evidence
  (`window_merge` method) carrying `window_count`, `windows`, `max_windows`,
  `max_instructions`, `memory_access_count`, `window_truncated`, and per-field
  `widths`/`signed_conflict`.
- CLI: `codevanta struct --address` / `-a` is repeatable. One address keeps the
  phase 2i/2j single-window output, zero addresses keep the entry-point /
  `--function` behaviour, and two or more addresses are merged through
  `suggest_structs` — bounded by `STRUCT_MAX_WINDOWS` (`MAX_MERGED_WINDOWS`, 16),
  sorted before decoding, so the output is identical for any order of the same
  address set. A merged run prints the usual table plus one
  `windows: N (0x.., 0x..)` footer line between the `instructions`/`max fields`/
  `truncated` line and `alignment:`. Its `base registers:` value is **not** a
  second sweep: the merge does not decode a window twice, the CLI reads the
  registers out of the evidence the merge already produced
  (`_struct_evidence_base_registers`), and because the phase 2k analysis layer
  records no `base_registers` key there the footer prints
  `base registers: not recorded by the merge` instead of a list (a single window
  still re-sweeps itself through `_struct_base_registers` and does name them). A
  truncated merge is told to split the windows — `field cap reached: the merged
  sweep keeps at most 64 offsets, so split the windows into separate runs to see
  the remaining offsets` — because the same command exits 2 on a non-default
  `--max-fields` next to a merge, so its hint must not send the user to a rejected
  flag. Because `--function` and `--max-fields` describe one window, more than one
  `--address` together with either a `--function` or a non-default `--max-fields`
  exits 2 with an explicit message instead of ignoring the option; duplicated
  addresses, more than 16 addresses, and addresses outside an executable section
  also exit 2 through the analysis layer's `AnalysisError`. `--json` stays
  `StructSuggestion.to_dict()`, with `window_count`/`windows` in the evidence
  `extra`.
- Documentation: `docs/phase2k.md` covers the new `codevanta_diff` arguments and
  their validation, the architecture guard's token rules and warning, the
  `suggest_structs` merge rules, address validation, bounds and evidence keys, the
  repeatable `struct --address` switch with its `windows:` footer and exit-2
  combinations, limitations, and next steps.
- `codevanta analyze` can now embed the phase 2 results in its JSON report under
  two additive top-level keys, opt-in per section exactly like `--callgraph`:
  `xrefs` (count, returned, truncated, items with per-item evidence, scanned
  sections/bytes, scan-level truncation, skipped indirect calls, warnings) and
  `cfg` (entry-point linear-sweep CFG with blocks, successors, and warnings).
  Both degrade to warning-carrying empty results on binaries with no executable
  content, and the provenance step chain gains `find_xrefs` and `build_cfg`.
  New options: `--xrefs`, `--cfg`, `--xref-limit` (default 2000, capped at
  200000) and `--json` (echo the payload when `--output` is used). Without the
  new flags the report is exactly the phase 1 payload, so existing JSON
  consumers are unaffected.
- Pseudo-C decompilation (`codevanta.analysis.decompile`, `codevanta decompile`):
  `decompile_function(path, info, address, max_instructions=2000,
  max_blocks=500)` renders one function as readable C from the recursive CFG's
  blocks, so nothing is decoded twice and nothing is executed. Argument count
  comes from the ABI argument registers read before the first `call` (capped at
  six, `mov rax, rdi` reads `rdi` while `mov rdi, rax` does not); argument
  registers become `a0`..`a5`, frame slots become `local_0x8`/`arg_0x8`, other
  memory operands become `*(u64*)(...)` with the binary's pointer width. Only
  mnemonic-justified statements are emitted (`mov`/`lea`, compound and unary
  assignments) so nothing is invented, and every emitted line keeps its raw
  instruction text as a trailing comment. Control flow is structured into
  `if`/`else`, `while (1)` with `continue;`/`break`, and `goto LABEL_<addr>;`
  for whatever cannot be nested; conditions come from `cmp`/`test` plus the
  branch mnemonic, with `(unsigned)` forms for `jb`..`ja`. Every rendering is
  `Confidence.LOW` with `source="decompile.pseudo_c"` /
  `method="mnemonic_heuristic"`, repeated in a header comment block inside the
  text. Budgets are `2000`/`500` by default and capped at
  `MAX_MAX_INSTRUCTIONS`/`MAX_MAX_BLOCKS` (`100000`); a cut-short rendering sets
  `truncated` and warns instead of failing, while a non-executable address, an
  out-of-range budget and a region that decodes to nothing raise `AnalysisError`
  (exit `2`).
- Pluggable decompiler backends (`codevanta.analysis.decompilers`): `ghidra`
  (pyghidra + `GHIDRA_INSTALL_DIR`), `angr` and the always-available `native`
  renderer sit behind one `decompile_function(...) -> BackendResult` entry point.
  `BackendAvailability` reports `available`, a non-empty `reason` and the
  `requires` tuple per provider and never raises or installs anything, so a
  missing package is a probe result, never an `ImportError`. `backend="auto"`
  (the default) prefers `ghidra` then `angr` and falls back to `native` with one
  warning per skipped backend, while `backend="angr"`/`"ghidra"` are strict and
  fail with the probe's reason and install hint. Budgets are validated once,
  before any backend runs. `codevanta decompile --backend` and `--output` wrap
  it, and neither Ghidra nor angr is a CODEVANTA dependency.
- Bounded offline emulation (`codevanta.analysis.emulate`, `codevanta emulate`):
  `emulate_function` copies the file's bytes into a *private* unicorn CPU and
  runs them there, so nothing is ever executed on the host and no host syscall,
  process or library is invoked. Only ABI entry state is seeded (`rip` at the
  address, `rsp`/`rbp` in a stack region at `STACK_BASE_64`/`STACK_BASE_32`);
  inputs arrive through `initial_registers`/`initial_memory` (`--set`, `--mem`),
  never by guessing. Every run ends with a stated `stopped_reason` — `return`,
  `budget`, `unmapped`, `unsupported`, `error` — plus a warning, and a value
  left in `rax` after a budget stop is reported as a register rather than a
  return value. Work is bounded by `max_instructions` (2000, ceiling 100000),
  `stack_size` (64 KiB, ceiling 16 MiB), `MAX_SECTION_BYTES`,
  `MAX_TOTAL_MAPPED` (64 MiB), `MAX_INITIAL_BLOCKS`/`MAX_INITIAL_BLOCK_BYTES`
  and `MAX_MEMORY_WRITES` (256, overflow counted and warned).
  `resolve_indirect_target` stops at the first indirect jump/call and returns
  its target, with `None` meaning "not resolved" rather than "no target";
  `xor_bytes` and `decrypt_string_loop` (xor/add/sub, optional per-byte
  `key_step`, C-style terminators) apply a recovered key without executing
  anything. Emulation needs the optional `unicorn` engine and exits `2` with the
  reason when it is missing; only x86 and x86-64 are emulated, other
  architectures report `unsupported` instead of a guess.
- Phase 3 surfaces: the sixteenth MCP tool `codevanta_decompile` (same payload
  as `BackendResult.to_dict()` plus the resolved `path`/`address` and the block
  count, with an unavailable strict backend surfacing as a tool error carrying
  the probe's reason), and the dashboard's tenth route `/api/decompile` with its
  form on the page — `backend=auto` by default, `address` defaulting to the
  entry point, and `400` naming the backend when a strict one is unavailable.
- Documentation: `docs/phase3.md` covers the rendering rules, the ABI argument
  inference, the confidence/evidence contract and exact bounds of the native
  renderer, every emulation stop reason and limit, the provider layer's
  selection policy and the availability matrix observed in this environment,
  how to install `angr`/`pyghidra`+Ghidra to unlock real C output, `docs/api.md`
  gains the three new modules' reference sections, and the README usage block
  and docs index list the two new commands and the phase 3 document.

### Notes

- Phase 2 is in progress: the CFG uses a linear sweep by default and an optional
  bounded recursive traversal (`--traversal recursive`), with direct branch
  targets plus absolute and RIP-relative pointer slots only; jump tables are
  absolute 4/8-byte pointer arrays, or signed 32-bit offset tables once a base is
  supplied through the API (CFG indirect resolution still uses the absolute
  layout), so register and indexed dispatch stay unresolved; no call following,
  no cross-function analysis, no slot dereferencing, and no debugger yet. The HTML
  export is interactive but still a single offline file, and the binary diff is
  structural (metadata) by default with an opt-in normalized-shape fingerprint
  comparison for address-matched functions — still no byte-level or semantic
  equivalence claim. The phase 2g switches are `jump-table --mode
  absolute|relative --base ADDR`, the new `function_fingerprint` API, and
  `diff --deep`; the CFG's indirect resolution still uses the absolute layout.
  Phase 2h adds heuristic struct-field suggestions (`suggest_struct` and
  `codevanta struct`), which report an offset, an access width, and read/write
  counts only: there is no type name, and offsets
  reached through different base registers share one bucket (cross-window merging
  arrives in phase 2k as `suggest_structs`, and even then stays inside one
  binary). Phase 2i adds
  `alignment` (the gcd of the reported non-zero offsets, `None` when fewer than
  two exist) and `array_groups` (maximal runs of at least three equally wide,
  equally spaced fields) to those suggestions — both are `medium` heuristics over
  one bounded window, so they cannot prove padding, a struct size or a declared
  array — plus `function_similarity`, a multiset overlap of normalized tokens, and
  the `codevanta_struct` MCP tool. Phase 2j adds the opt-in semantic pairing pass
  on the binary diff (`semantic=True`, `threshold` defaulting to `0.9`, greedy,
  capped at 4096 leftover pairs), the `codevanta_similarity` MCP tool (fifteen
  tools), and the `signed` mnemonic hint on struct fields, reachable as
  `diff --semantic --threshold` and as the `codevanta struct` footer `signed:`
  line. Phase 2k adds `deep`/`semantic`/`threshold` to the `codevanta_diff` MCP
  tool (still fifteen tools), the semantic pass's cross-architecture guard, and
  the `suggest_structs` merged-window API over up to `MAX_MERGED_WINDOWS` (16)
  addresses of one binary — one field per offset, widest width winning with a
  `WidthConflictWarning`, layout hints recomputed, reachable from the CLI by
  repeating `--address` — while `codevanta_struct` still takes a single address.
  See `docs/phase2.md`, `docs/phase2b.md`, `docs/phase2c.md`,
  `docs/phase2d.md`, `docs/phase2e.md`, `docs/phase2f.md`, `docs/phase2g.md`,
  `docs/phase2h.md`, `docs/phase2i.md`, `docs/phase2j.md`, and
  `docs/phase2k.md`.
- Node boundaries and caller attribution are heuristics, not proven function
  extents. Sessions and annotations live in one local SQLite file with no schema
  migrations yet.

## [0.1.0] - 2026-11-12

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

[Unreleased]: https://github.com/kevindoni/CODEVANTA/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kevindoni/CODEVANTA/releases/tag/v0.1.0

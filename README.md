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

- PE, ELF, Mach-O, and DEX loaders (format, architecture, bitness, endianness, entry point, image base).
- Sections, imports, exports, and symbol extraction — every finding carries evidence.
- x86/x64 disassembly of executable sections and the entry point.
- Function candidates from exports, function symbols, and the entry point, each with source and confidence.
- ASCII and UTF-16 string extraction (byte order follows the binary) with file offset and mapped virtual address.
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
  for one region. The default is a linear sweep with leader/terminator rules;
  `build_recursive_cfg` (and `codevanta cfg --traversal recursive`) instead walks
  control flow from the start address with a worklist and a visited set, so
  blocks come from real branch targets and unreachable padding after a `ret` or
  `jmp` is excluded. Indirect targets stay unresolved by default;
  `resolve_indirect=True` (and `codevanta cfg --traversal recursive
  --resolve-indirect`) decodes the pointer table behind a `jmp qword ptr [rip +
  disp]` / `jmp qword ptr [abs]` and follows its executable targets, bounded per
  traversal by `max_jump_tables` and `max_table_entries`.
- **Jump tables** (`analysis/jump_tables.py`) — `resolve_jump_table` decodes a
  bounded array of absolute pointers (4 or 8 bytes, binary endianness) into
  `JumpTableEntry` records with evidence. `mode="relative"` with an explicit
  `base_address` instead reads signed 32-bit offsets and resolves
  `target = base + offset`, which is the shape of position-independent switch
  tables; a zero offset is a valid entry pointing at the base, not a terminator.
  Both modes stop at the first out-of-window target, unmapped target, or
  (with `executable_only`) non-executable target and report why, and both are
  `medium` confidence because a slot array found by shape is evidence of a
  dispatch table, not proof of one.
- **Function fingerprints** (`analysis/function_hash.py`) —
  `function_fingerprint` takes one bounded linear sweep from an address and
  returns a SHA-256 digest over the *normalized* instruction stream: mnemonics
  are kept, every numeric literal is masked to `#`, and whitespace is collapsed.
  It is `medium` confidence and explicitly not semantic equivalence — equal
  digests are not byte equality, and masked branch targets make different
  callees look alike.
- **Function similarity** (`analysis/function_hash.py`) — `normalized_tokens`
  exposes the token stream the digest hashes, and `function_similarity` scores
  two regions as multisets of those tokens: `sum(min) / sum(max)` of their
  counts (the Ruzicka / weighted-Jaccard overlap) in `0.0 .. 1.0`, with the
  shared count, both side totals, and a warning per truncated side. It is
  `medium` confidence and a *shape* measure only: literals are masked and the
  comparison is order-insensitive, so `1.0` is not equality and `0.0` is not
  proof of different behaviour. Exposed as the `codevanta_similarity` MCP tool.
- **Structural binary diff** (`analysis/binary_diff.py`) — `diff_binaries`
  compares two binaries as metadata only: functions matched by address then name,
  sections/exports by name, imports by `(library, name)`. Deltas are `added`,
  `removed`, or `changed`, and the whole comparison is `medium` confidence
  because no bytes and no semantics are compared. `deep=True` adds a content
  signal for address-matched functions only: when their fingerprints differ the
  entry becomes `changed` with both digests, while every structural rule, and
  structural-only mode, stays unchanged. `semantic=True` adds a *pairing* pass
  instead of a new rule: the functions that address and name matching left
  unpaired are scored with `function_similarity` and the highest scores at or
  above `threshold` (default `0.9`) become one `changed` entry each, carrying a
  `similarity` rounded to four decimals. Pairing is greedy — highest score first,
  ties broken by address, one use per candidate — and it never overrides an
  address or name match, so a leftover below the threshold keeps its
  `added`/`removed` verdict. It is bounded twice: at most 4096 leftover pairs are
  scored (the whole pass is skipped, with a warning, above that) and one score
  reads at most 2000 instructions per side.
- **Call graph** (`analysis/callgraph.py`) — `call`, `call_import`, and
  `call_indirect` cross-references aggregated into nodes and edges. Import slots
  become `import` nodes labelled from the import table; unresolved callees stay
  `external`. Caller attribution is heuristic (nearest function candidate at or
  below the call site in the same section), so the graph reports `medium`
  confidence and warns when a call site cannot be attributed.
- **Graph export** (`analysis/graph_export.py`) — the call graph rendered as
  Graphviz DOT or GraphML by one dependency-free, deterministic exporter.
- **Offline graph viewer** (`analysis/html_view.py`) — `codevanta callgraph
  --format html` writes one self-contained HTML5 document with an inline SVG
  view: three kind-based columns, header counts, and a collapsible edge table.
  One inline script adds drag-to-pan, mouse-wheel zoom (0.2x–8x), label search
  with hit/dim highlighting, and per-kind filters. No CDN, no web font, no
  library and no server, so it opens offline from disk — and with scripting
  disabled the static view still renders in full.
- **Session storage** (`storage/session.py`) — additive SQLite records of each
  analysis run (fingerprint, format, arch, entry point, function/string counts)
  plus per-address analyst annotations (`annotate`, `annotations`,
  `remove_annotation`; one replaceable note per address).
- **Struct-field suggestions** (`analysis/type_recovery.py`) — `suggest_struct`
  reads the memory operands of a bounded window and reports one
  `SuggestedField` per displacement. Only `[reg]`, `[reg + 0xNN]` and
  `[reg - 0xNN]` are understood (index/scale and segment forms are skipped),
  width comes from the `byte`/`word`/`dword`/`qword` keyword or else the
  pointer width, direction comes from operand position with `cmp`/`test` always
  reads, stack registers are skipped unless `include_stack=True`, and each
  offset keeps its dominant width plus total read/write counts. Each suggestion
  also carries two layout *hints* computed from the fields it reports:
  `alignment`, the greatest common divisor of the absolute non-zero offsets
  (`None` when fewer than two distinct ones were seen), and `array_groups`,
  maximal runs of at least three consecutive fields that share one width and one
  stride. Every record is `medium` confidence and explicitly heuristic: no type
  names, no padding or struct-size inference, and offsets are bucketed per
  displacement so different base registers share one bucket. Each field also
  carries a `signed` hint read from the *mnemonics* that touched its offset:
  `movsx`/`movsxd`/`sar`/`idiv`/`imul` say signed,
  `movzx`/`shr`/`div`/`mul` say unsigned, and every other mnemonic says nothing.
  Only one kind of hint at an offset gives `True`/`False`; no hint gives `None`,
  and a contradiction gives `None` plus a `SignednessConflictWarning` naming the
  offset. `None` means *no evidence*, never "safe", and the key is omitted from
  the JSON rather than emitted as `null`. `suggest_structs` merges up to
  `MAX_MERGED_WINDOWS` (16) windows of the same binary into one suggestion: one
  field per offset, counters summed, the widest per-window width kept with a
  `WidthConflictWarning` when the windows disagree, signedness folded with the
  single-window rule except that a contradiction seen *inside* one window survives
  to the merge (`None` plus a `SignednessConflictWarning`), and
  `alignment`/`array_groups` recomputed from the merged fields. Addresses must be
  unique; a *partial* overlap is allowed but announced with
  `WindowOverlapWarning`, because the shared instructions are then counted by both
  windows and the summed counters are upper bounds. `truncated` is the OR of the
  merge cap and every window's own 64-offset cap, and `window_truncated` names the
  windows that hit theirs. Duplicate, empty, non-integer, negative, or over-limit
  addresses are rejected with `AnalysisError`, and the merge is bounded by
  `max_windows * max_instructions` decoded instructions. The CLI reaches it by
  repeating `--address`.
- **MCP tools** — `codevanta_similarity` joins `codevanta_struct`,
  `codevanta_diff`, `codevanta_jump_table`, `codevanta_function_hash`,
  `codevanta_xrefs`, `codevanta_cfg`, `codevanta_callgraph`,
  `codevanta_session_save`, and `codevanta_session_list`, alongside the five
  phase 1 tools (fifteen in total). `codevanta_diff` takes `max_functions`,
  `deep`, `semantic`, and `threshold`, so the phase 2j pairing pass is reachable
  from an agent without a separate `codevanta_similarity` call.
- **`analyze` integration** (`core/report.py`) — the `codevanta analyze` JSON
  report can embed the phase 2 output under additive `xrefs` and `cfg` keys,
  each with its own evidence and warnings, behind `--xrefs` and `--cfg`
  (opt-in, like `--callgraph`). `xrefs` is bounded by `--xref-limit` (default
  2000) on top of the scanner's 4 MB decode budget; the entry-point CFG is
  bounded by 2000 instructions and 500 blocks. Binaries with no executable
  content still produce a report with degraded, warning-carrying sections.
- **CLI:** `codevanta struct` (with a repeatable `--address`/`-a` — more than one
  value merges the windows and adds a `windows:` footer line — plus `--function`,
  `--max-instructions`, `--max-fields`, `--include-stack`, `--json`, and a footer
  reporting `alignment:` plus one line per array candidate or `arrays: none`,
  closing with a `signed:` line),
  `codevanta xrefs`, `codevanta cfg` (with
  `--traversal linear|recursive`, default `linear`, and `--resolve-indirect` for
  recursive traversals), `codevanta jump-table` (with
  `--mode absolute|relative` and `--base ADDR` for signed-offset tables),
  `codevanta diff` (with `--deep` for the normalized-shape comparison, and
  `--semantic` / `--threshold` for the shape-similarity pairing),
  `codevanta entropy` (per-section Shannon entropy with a `packed_hint`
  heuristic, `--threshold`, `--max-sample-bytes`, `--json`),
  `codevanta callgraph`, `codevanta analyze` (with `--callgraph` for the call
  graph and `--xrefs` / `--cfg` / `--xref-limit` / `--json` for the phase 2
  sections), plus the `session save|list|show|annotate|notes` subcommands.

Phase 2 is deliberately narrow: linear sweep by default with an additional
bounded recursive traversal for CFGs, direct branch targets plus
absolute/RIP-relative pointer slots only, jump tables as absolute 4/8-byte
pointer arrays or signed 32-bit offset tables with an analyst-supplied base
(`--mode relative --base`) — never register/indexed dispatch, call graph edges
from `call` / `call_import` / `call_indirect` only, no following calls into
callees, no cross-function analysis, a structural (metadata-only) binary diff
plus an opt-in shape-fingerprint comparison of address-matched functions, an
opt-in shape-similarity pairing of the leftovers, struct fields as per-offset
hypotheses from `[reg]`/`[reg ± disp]` operands only, struct evidence merged
across at most 16 windows of one binary through the `suggest_structs` API, and no
debugger yet. The
phase 2g switches are `jump-table --mode absolute|relative
--base ADDR` (plus the same `mode`/`base_address` arguments on
`resolve_jump_table`), the new `function_fingerprint` API, and `diff --deep`
(`deep=True`); the CFG's indirect resolution still uses the absolute layout.
Phase 2h adds `codevanta struct` (and the `suggest_struct` API) plus the
`codevanta_diff`, `codevanta_jump_table`, and `codevanta_function_hash` MCP
tools. Phase 2i adds the `alignment`/`array_groups` layout hints on a struct
suggestion, the `function_similarity`/`normalized_tokens` API, and the
`codevanta_struct` MCP tool. Phase 2j adds the opt-in semantic pairing pass on the
binary diff (`semantic=True`, `threshold` defaulting to `0.9`), the
`codevanta_similarity` MCP tool (fifteen tools), and the `signed` mnemonic hint on
struct fields, reachable as `diff --semantic --threshold` and as the
`codevanta struct` footer `signed:` line. Phase 2k adds the `deep` / `semantic` /
`threshold` arguments to the `codevanta_diff` MCP tool (fifteen tools, no new
registration), the semantic pass's cross-architecture guard — the pass is skipped
with a warning naming both `BinaryInfo.architecture` tokens, which are compared
after trimming whitespace and lower-casing only, so a hand-built `AMD64` does not
match `x86_64`, headers the loader cannot map (PE `MIPS`, ELF IA-64/RISC-V/PowerPC/
s390) come out `unknown`, two `unknown` sides bypass the guard, and a diff with no
leftover on one side emits no warning at all — and the `suggest_structs`
merged-window API over up to `MAX_MERGED_WINDOWS` (16) addresses of one binary,
reachable as `codevanta struct -a A -a B` — one field per offset, widest width
winning, with a `windows:` footer line.
See [docs/phase2.md](docs/phase2.md), [docs/phase2b.md](docs/phase2b.md),
[docs/phase2c.md](docs/phase2c.md), [docs/phase2d.md](docs/phase2d.md),
[docs/phase2e.md](docs/phase2e.md), [docs/phase2f.md](docs/phase2f.md),
[docs/phase2g.md](docs/phase2g.md), [docs/phase2h.md](docs/phase2h.md),
[docs/phase2i.md](docs/phase2i.md), [docs/phase2j.md](docs/phase2j.md), and
[docs/phase2k.md](docs/phase2k.md) for
scope, confidence semantics, and limitations.

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
codevanta analyze   C:\Windows\System32\notepad.exe --xrefs --cfg       # report + xrefs + cfg
codevanta analyze   C:\Windows\System32\notepad.exe                     # phase 1 only
codevanta analyze   C:\Windows\System32\notepad.exe --xref-limit 200 --xrefs -o report.json
codevanta xrefs     C:\Windows\System32\notepad.exe --limit 40
codevanta cfg       C:\Windows\System32\notepad.exe --address 0x140001000
codevanta cfg       C:\Windows\System32\notepad.exe --address 0x140001000 --traversal recursive
codevanta cfg       C:\Windows\System32\notepad.exe --address 0x140001000 --traversal recursive --resolve-indirect
codevanta jump-table C:\Windows\System32\notepad.exe --address 0x140003000
codevanta jump-table C:\Windows\System32\notepad.exe --address 0x140003000 --entries 64 --json
codevanta diff      samples\v1.bin samples\v2.bin
codevanta diff      samples\v1.bin samples\v2.bin --max-functions 20000 --json
codevanta diff      samples\v1.bin samples\v2.bin --semantic
codevanta diff      samples\v1.bin samples\v2.bin --semantic --threshold 0.75 --json
codevanta callgraph C:\Windows\System32\notepad.exe --format dot -o callgraph.dot
codevanta callgraph C:\Windows\System32\notepad.exe --format graphml -o callgraph.graphml
codevanta callgraph C:\Windows\System32\notepad.exe --format html -o callgraph.html
Invoke-Item callgraph.html   # drag to pan, wheel to zoom, search labels, filter by kind
codevanta analyze   C:\Windows\System32\notepad.exe --callgraph -o report.json
codevanta session save C:\Windows\System32\notepad.exe --notes "baseline triage"
codevanta session list --limit 10
codevanta session show 4f9c1a7b2d3e
codevanta session annotate 4f9c1a7b2d3e 0x401000 "decrypts config with XOR 0x5a"
codevanta session notes 4f9c1a7b2d3e
codevanta struct    C:\Windows\System32\notepad.exe --address 0x140001000
codevanta struct    samples\handle.bin --function process --include-stack --json

# Phase 3
codevanta decompile C:\Windows\System32\notepad.exe 0x1400019c0 --backend native
codevanta decompile samples\pe64_text.bin --json
codevanta decompile samples\pe64_text.bin --max-instructions 20 --output rendering.c
codevanta emulate   samples\pe64_text.bin                              # returns 42
codevanta emulate   samples\pe64_text.bin --set rdi=2 --mem 0x600000=48454c4c4f
codevanta emulate   C:\Windows\System32\notepad.exe --resolve-target   # jmp/call [rip+..]
```

`diff --semantic` prints one dim
`semantic pair 0x401000 -> 0x401010 (<name>): similarity 1.0000` line per pair
after the unchanged function table (`--threshold` defaults to `0.9` and is
validated before either file is loaded), and `codevanta struct` closes its footer
with `signed: 0x10 signed, 0x18 unsigned`, or `signed: none` when no mnemonic
hinted anything. The same data comes back from Python and JSON:

```python
from codevanta.analysis.binary_diff import diff_binaries

# Leftovers paired by normalized instruction-shape similarity (default 0.9)
diff = diff_binaries("samples/v1.bin", "samples/v2.bin", semantic=True, threshold=0.9)
for delta in diff.functions_changed:
    print(hex(delta.address), delta.similarity)  # None unless the pair was scored
```

All addresses in reports are absolute virtual addresses (VA). Function
candidates always state their detection source (`export`, `symbol`,
`entry_point`) and confidence (`high`, `medium`, `low`, `unknown`).

The `codevanta analyze` JSON report can include the phase 2 results: `--xrefs`
adds an `xrefs` section (bounded by `--xref-limit`, default 2000) and `--cfg`
adds the entry-point `cfg` (at most 2000 instructions and 500 blocks), both with
evidence and warnings. Binaries with no executable content still produce a
report with degraded, warning-carrying sections, and without the flags the
report is the phase 1 payload.

Phase 2 results carry their own evidence: xrefs are `certain` (the target is
read directly from the decoded operand), CFG blocks are `medium` (block
boundaries come from mnemonic heuristics), jump-table entries are `medium` (a
pointer array found by shape is not proof a dispatcher indexes it), the
structural diff is `medium` (metadata only, never bytes or behavior), the call
graph is `medium` (calls are decoded, but caller attribution is a
nearest-candidate heuristic), struct fields are `medium` (an operand proves
an access, not a type or a layout — `alignment` is only the gcd of the observed
offsets and an `array_groups` entry is only a repeated width and stride, and a
`signed` hint is only the mnemonics that happened to touch that offset), a
function fingerprint is `medium` (normalized shape, not bytes), and a similarity
score is `medium` (multiset overlap of normalized tokens, not semantics).
`codevanta callgraph` defaults to
`--format json`
and can emit `dot`, `graphml`, or `html` (one self-contained file with an inline
SVG view that pans, zooms, searches, and filters by kind without any CDN, opened
straight from disk); `codevanta cfg` defaults to the entry point and to
`--traversal linear`, `--traversal recursive` reports the same shape with
evidence source `cfg.recursive_traversal`, and `--resolve-indirect` (recursive
only) adds jump-table successors; `codevanta jump-table` takes a decimal or `0x`
hex `--address` and a `--entries` slot budget; `codevanta diff` exits `0`
whether or not the binaries differ, and `2` on load or input errors;
`codevanta struct` defaults to the entry point, starts at `--address` or
`--function` when given, reports each field's offset, width, read and write
counts, and adds a footer naming the base registers the sweep saw — a single
window re-sweeps itself to find them, while a merged run does not decode anything
twice and therefore prints `base registers: not recorded by the merge` — the
inferred `alignment:` (`unknown` when none could be derived), one
`array at 0x..: N x W-byte, stride S` line per array candidate (or
`arrays: none`), plus one `warning:` line per limitation (`--json` for the full
document, including `alignment` and `array_groups`). Sessions
default to `$env:CODEVANTA_DB` or `~/.codevanta/sessions.db`, and
`session annotate` accepts decimal or `0x` hex addresses.

Calls through a pointer slot report the **slot** address, not the callee: the
pointer is read at run time, so the code behind it is unknown here. A slot that
matches the import table becomes `call_import` with a `target_name`; any other
absolute or RIP-relative slot becomes `call_indirect` (`high` confidence — the
slot is proven, the callee is not); register and indexed operands are skipped and
counted in `indirect_skipped`, which `codevanta xrefs --json` prints.
`codevanta analyze --callgraph` embeds the graph in the report, bounded to 1000
functions and 5000 edges, and marks it `truncated` when a cap cuts it short.
The `xrefs` and `cfg` sections use the same opt-in shape (`--xrefs`, `--cfg`).

`codevanta dwarf` reads DWARF debug info that a build kept: producer-grade
function names with byte-exact extents plus named type layouts (structs,
unions, enums, classes) with byte sizes — the strongest symbol evidence a
binary can carry (`dwarf.debug_info`, high confidence). ELF only; needs the
optional `pyelftools` extra (`pip install -e ".[dwarf]"`, already in `dev`),
and fails with a typed message naming the extra when it is missing.
PDB (PE) stays open: the LIEF OSS build gates its PDB parser behind the
Extended distribution.

`codevanta vtable` recovers indirect cross-references the xref scanner cannot
see: C++ vtable candidates — runs of consecutive code pointers in data
sections (PIE slots are filled via dynamic-relocation overlay, so virtualized
builds work) — and thunk chains, where a slot target is a one-instruction
tail-call that forwards to the real override (`resolved_target`). Every
candidate and slot carries `vtable.candidate` / `vtable.slot_ref` /
`vtable.thunk_chain` evidence at **medium** confidence: a run of code pointers
is a heuristic, not proof.

Phase 3 adds the two commands that read a function instead of a file:
`codevanta decompile` renders one function as pseudo-C and `codevanta emulate`
computes what it returns. Decompilation is `low` confidence by design — control
flow, argument count and types come from mnemonics only — and every result says
so in its evidence record and in a header comment inside the text.
`--backend auto` (the default) prefers an installed Ghidra/pyghidra or angr and
falls back to the built-in renderer, printing one `warning:` per skipped backend
so a fallback is never silent; `--backend ghidra|angr` is strict and exits `2`
with the probe's reason instead of substituting a provider. Emulation runs the
file's bytes on a private unicorn CPU — nothing executes on the host — and always
ends with a stated reason (`return`, `budget`, `unmapped`, `unsupported`,
`error`); a value left in `rax` after a budget stop is reported as a register,
never as a return value. `codevanta emulate` needs the optional `unicorn` engine
and exits `2` with the reason when it is missing. See
[docs/phase3.md](docs/phase3.md).
### Try it in the browser

```powershell
codevanta gui                  # http://127.0.0.1:8765/  (opens a browser)
codevanta gui --port 9000      # pick a port
codevanta gui --no-browser     # print the URL and wait
```

`codevanta gui` serves one self-contained dashboard page over a loopback-only,
read-only HTTP server — no extra dependencies, no network access, and the
analysed file is never executed or written. The page drives ten JSON routes
(`/api/health`, `/api/info`, `/api/functions`, `/api/strings`, `/api/xrefs`,
`/api/cfg`, `/api/struct`, `/api/callgraph`, `/api/diff`, `/api/decompile`), each
a thin adapter over the engine of the same name, so the browser shows the same
evidence payload the CLI prints. Try it on the committed samples:

```powershell
codevanta info    samples\pe64_text.bin        # PE32+ with one export
codevanta disasm  samples\macho64_text.bin --count 10
codevanta disasm  samples\elf64_text.bin       # 5-byte .text, easiest to read
```

See [docs/samples.md](docs/samples.md) for every sample file and
[docs/api.md](docs/api.md#codevantagui-local-web-dashboard) for the route
parameters, status codes, and the `create_server` / `serve` Python API.

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

MCP tools (twenty): `codevanta_info`, `codevanta_functions`,
`codevanta_strings`, `codevanta_disasm`, `codevanta_analyze`,
`codevanta_xrefs`, `codevanta_cfg`, `codevanta_callgraph`, `codevanta_diff`,
`codevanta_jump_table`, `codevanta_function_hash`, `codevanta_similarity`,
`codevanta_struct`, `codevanta_entropy`, `codevanta_decompile`,
`codevanta_dwarf`, `codevanta_vtable`, `codevanta_trace`,
`codevanta_session_save`, `codevanta_session_list`.
`codevanta_analyze` mirrors
the CLI flags (`include_xrefs` / `include_cfg` / `include_callgraph`, default off)
so a single call can carry the phase 2 sections when an agent prefers one payload.

`codevanta_decompile` takes `path`, `address`, `backend` (`auto` by default) and
the same `max_instructions`/`max_blocks` budgets as the CLI, and returns the
rendering with the provider that produced it, its `language`, `warnings`,
`evidence` and the number of basic blocks it covers.

`codevanta_callgraph` takes the same bounded limits as the CLI
(`limit_functions`, `limit_edges`, defaulting to 1000 and 5000) and returns nodes,
edges, `truncated`, `warnings`, and evidence. Import targets arrive as `import`
nodes labelled from the import table; unresolved callees stay `external`.
`codevanta_analyze` keeps its phase 1 payload and has no call-graph or phase 2
flag; ask for the sections from Python with `build_report(path,
include_xrefs=True)` or use `codevanta_xrefs` / `codevanta_cfg`.

`codevanta_diff` compares two binaries structurally (`max_functions` default
5000, `deep=False`) and reports `warnings` when a cap truncated the comparison.
The semantic pairing pass is not exposed here yet — call `codevanta_similarity`
on the addresses that matter instead.
`codevanta_jump_table` defaults to `mode="absolute"` and requires `base` when
`mode="relative"`; `entries` defaults to 256 and values above 4096 are rejected.
`codevanta_function_hash` returns a SHA-256 over the normalized instruction
shape (numeric literals masked) with a `truncated` flag — equal digests are not
byte equality, and different digests are not a semantic difference.
`codevanta_struct` takes the same `address`/`function`/`max_instructions`/
`max_fields`/`include_stack` arguments as the CLI and returns the suggestion
document unchanged, including `alignment` (a number or `null`), `array_groups`,
and each field's `signed` hint when it is known; fields are `medium` heuristics
from operand shapes, never verified types.
`codevanta_similarity` compares two regions as multisets of normalized
instruction tokens and returns `score` (`shared / union`, four decimals),
`shared`, `left_total`, `right_total`, `union`, `warnings`, and evidence — a
shape measure, so `1.0` is not equality.

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
├── gui/         # loopback-only web dashboard (stdlib HTTP server + JSON routes)
├── analysis/    # cross-references, call graph, CFG (linear sweep + recursive traversal), jump tables (absolute + relative), function fingerprints and similarity, structural/deep diff, struct-field suggestions with alignment/array hints, graph/HTML export (phase 2)
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

CI runs the same lint and test job on Python 3.11, 3.13, and 3.14, and builds
plus smoke-tests the wheel on 3.13.

## Documentation

- [Project specification](PROJECT_SPEC.md)
- [Architecture](docs/architecture.md)
- [API reference](docs/api.md) — every public Python entry point, the evidence
  contract, the ten dashboard routes, and the sixteen MCP tools
- [Sample binaries](docs/samples.md) — the committed PE/Mach-O/ELF fixtures and
  how to regenerate them
- [Contributor attribution](docs/attribution.md) — how agent commits are credited,
  and how to make an agent appear in GitHub's contributor graph
- [Phase 2 — cross-references, CFGs, sessions](docs/phase2.md)
- [Phase 2b — call graphs, graph export, session annotations](docs/phase2b.md)
- [Phase 2c — import/indirect calls, embedded call graphs, MCP call graph](docs/phase2c.md)
- [Phase 2d — offline HTML/SVG graph viewer](docs/phase2d.md)
- [Phase 2e — recursive CFG traversal](docs/phase2e.md)
- [Phase 2f — jump tables, CFG indirect resolution, interactive viewer, structural diff](docs/phase2f.md)
- [Phase 2g — relative jump tables, function fingerprints, deep diff](docs/phase2g.md)
- [Phase 2h — struct-field suggestions, MCP parity, Python 3.14 CI](docs/phase2h.md)
- [Phase 2i — alignment/array hints, function similarity, struct over MCP](docs/phase2i.md)
- [Phase 2j — semantic diff pairing, similarity over MCP, signedness hints](docs/phase2j.md)
- [Phase 2k — diff options over MCP, cross-architecture guard, merged struct windows](docs/phase2k.md)
- [Phase 3 — pseudo-C decompilation, bounded emulation, decompiler backends](docs/phase3.md)

## Roadmap

Verified against this repository, not against intent. Every ✅ names the file
that implements it, so each claim is one file lookup away; every ⬜ is absent
from `src/`. A phase can be **delivered with named gaps** — those gaps are the
*Open* column, not a follow-up phase.

| Phase | Delivered | Open |
|-------|-----------|------|
| **1 · Foundation** | ✅ PE / ELF / Mach-O (fat slices too) / DEX loaders — `core/loader.py:363-379` (`dex\n` magic → `_load_dex`)<br>✅ Disassembly, ASCII + UTF-16 strings, function discovery, JSON evidence report — `core/disassembler.py`, `core/strings.py`, `core/functions.py`, `core/report.py`<br>✅ Per-section entropy and packing triage — `core/entropy.py` (`shannon_entropy`, `analyze_entropy`), `codevanta entropy`<br>✅ CLI: 20 commands (19 `@app.command()` + `mcp serve`) plus the `session` sub-app with 5 subcommands — `cli/main.py`<br>✅ MCP server exposing 17 tools — `mcp_server/server.py` (`build_server().list_tools()` returns 17)<br>✅ Guided agent setup for Claude Code, Cursor, Cline and VS Code — `setup/` (`clients.py`, `plan.py`, `apply.py`, `verify.py`) | ⬜ **.NET (CLR), WebAssembly and JVM `.class`/JAR formats** — `loader.py` recognises PE, ELF, Mach-O and DEX only |
| **2 · RE views** | ✅ Cross-references, incl. `call_import` / `call_indirect` slot resolution — `analysis/xrefs.py`<br>✅ Linear **and** recursive CFG — `analysis/cfg.py` (`build_cfg`, `build_recursive_cfg`), `codevanta cfg --traversal recursive`<br>✅ Call graphs with DOT / GraphML / HTML export — `analysis/callgraph.py`, `analysis/graph_export.py`, `analysis/html_view.py`<br>✅ Absolute and relative jump tables — `analysis/jump_tables.py` (`MODE_ABSOLUTE`, `MODE_RELATIVE`)<br>✅ SQLite sessions with address annotations — `storage/session.py`, `codevanta session save/list/show/annotate/notes`<br>✅ Structural binary diff, function fingerprints, function similarity — `analysis/binary_diff.py`, `analysis/function_hash.py`<br>✅ Struct-field recovery — `analysis/type_recovery.py`, `codevanta struct`<br>✅ Read-only loopback dashboard, 10 endpoints — `gui/server.py` (`ROUTES`) | ⬜ **Live debugger attach** — `codevanta attach` states outright that "the provider is never launched: this command writes a file and prints a command line"; nothing runs gdb/Frida against a target<br>⬜ **GUI session persistence** — `gui/server.py:ROUTES` has 10 endpoints and none is session-related<br>⬜ **Graph-oriented viewer application** — the shipped viewer is the static HTML/SVG export (`analysis/html_view.py`), not an interactive app |
| **3 · Decompilation** | ✅ Pseudo-C through three providers — `analysis/decompile.py`, `analysis/decompilers/` (`native`, `angr`, `ghidra` reported by `available_backends()`)<br>✅ Type propagation over decompiled output — `analysis/type_propagation.py`<br>✅ Decompiler parity enforced in CI instead of assumed — `.github/workflows/ci.yml` jobs `decompile-parity` and `ghidra-parity` | ⬜ **Embedded Python scripting** — no script command and no sandboxed interpreter; `session` stores annotations only |
| **4 · Emulation** | ✅ Bounded, offline emulation that never executes on the host, with explicit `return` / `budget` / `unmapped` / `unsupported` stop reasons — `analysis/emulate.py` (Unicorn), `codevanta emulate`<br>✅ 29 emulation tests — `tests/test_emulate.py` | ⬜ **Typed / SSA IR lifting** — `ir/base.py` and `ir/adapters/` are a contract plus an empty registry ("Concrete adapters arrive in phase 4")<br>⬜ **Symbolic execution** — no `Simulator`/`SimulationManager`/Z3 usage anywhere in `src/` |
| **5 · Platform** | ✅ CI/CD with real gates — `ci.yml` runs 7 job runs (3 Python versions × `test`, plus `type-check` (mypy), `package` (wheel smoke test), `decompile-parity`, `ghidra-parity`) and `pyproject.toml` sets `fail_under = 85` coverage<br>✅ Release pipeline — `release.yml`: `build` → `publish-pypi` (trusted publishing) → `github-release`<br>✅ Dynamic provider probing, script generation and trace replay reachable from the CLI — `analysis/dynamic.py`, `analysis/trace.py` (`parse_gdb_trace`, `parse_frida_trace`), `codevanta attach`, `codevanta trace` | ⬜ **Plugin SDK** — `plugins/__init__.py` is a single docstring line, "Plugin system — phase 5"<br>⬜ **Full AI layer** and **multi-user** — no auth, user or tenant model exists in `src/`<br>⬜ **Evidence bundle** export — `evidence/` has `models`, `provenance` and `confidence`, but no bundle writer; only the `analyze` JSON report is emitted<br>⬜ **Fuzz and benchmark gates** — `scripts/bench.py` and `tests/test_bench.py` exist, yet no CI job enforces either and there is no fuzzer<br>⬜ **Windows / macOS CI** — every job in both workflows is `runs-on: ubuntu-latest`<br>⬜ **PyPI release** — publishing is wired but has never run: `git tag -l` is empty, so no `v*` tag has been cut |

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

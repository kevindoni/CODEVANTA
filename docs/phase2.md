# Phase 2 — Cross-References, CFGs, and Sessions

Phase 2 builds on the phase 1 foundation (loader, disassembler, functions,
strings, evidence, JSON report) with three analysis building blocks:

| Module | What it does |
|--------|--------------|
| `src/codevanta/analysis/xrefs.py` | Collects cross-references from direct branch, call, and jump instructions |
| `src/codevanta/analysis/cfg.py` | Splits one decoded region into basic blocks and ordered successor edges (linear sweep) |
| `src/codevanta/storage/session.py` | Persists analysis snapshots in a local SQLite database |

All three are read-only with respect to the analysed target: bytes are read
from disk and decoded, nothing is loaded into a process or executed.

**Status:** in progress. There is no web viewer and no debugger yet — see
[Limitations](#limitations).

## Delivered scope

### Cross-reference scanner (`analysis/xrefs.py`)

`find_xrefs(path, info, functions=None, max_bytes=4_000_000)` walks every
section that is executable and has file-backed bytes, decodes it with Capstone,
and emits an `Xref` for each transfer instruction whose target is statically
known.

- **Kinds:** `call` (`call`), `jump` (`jmp`), `branch` (the conditional x86
  family: `je`/`jne`/`jz`/`jnz`/`jb`/`jbe`/`ja`/`jae`/`jl`/`jle`/`jg`/`jge`/
  `js`/`jns`/`jo`/`jno`/`jp`/`jnp`/`jcxz`/`jecxz`/`jrcxz`).
- **Direct targets only:** the entire operand text must be a hexadecimal
  literal (`^0x[0-9a-fA-F]+$`). `call rax` and `jmp qword ptr [rax]` are
  skipped rather than guessed, because their target is not statically known at
  this layer.
- **Naming:** if a discovered function candidate starts at the target address,
  the xref carries that `function` name.
- **Budget:** one scan decodes at most `max_bytes` (default 4,000,000) bytes;
  `XrefResult.truncated` and `XrefResult.warnings` report incomplete coverage.
- **Output:** references sorted by `from_address`; every xref carries its own
  `Evidence`, and the result carries scan-level evidence plus
  `scanned_sections` / `scanned_bytes`.

### Linear-sweep CFG (`analysis/cfg.py`)

`build_cfg(path, info, start, max_instructions=2000, max_blocks=500)` decodes
one contiguous region beginning at `start` (which must be inside an executable
section) and derives blocks with local rules only:

- **Leaders:** the start address; the instruction after any terminator; and the
  direct target of a branch when that target is itself a decoded address.
- **Blocks:** consecutive instructions between two leaders; `end` is exclusive
  (the address just past the last instruction).
- **Successors:** `ret`-like instructions and unconditional jumps do not fall
  through; conditional jumps and ordinary instructions fall through to the next
  instruction; jumps and conditional jumps also gain their direct target.
  Successors are deduplicated, sorted, and must reference a decoded block start
  — targets outside the sweep are dropped and listed in a warning.
- **Limits:** `max_instructions` and `max_blocks` bound the work;
  `FunctionCFG.truncated` says whether the graph may be incomplete.

Indirect branches (`jmp rax`, `jmp qword ptr [...]`, jump tables) are not
resolved, so those blocks simply end with an unresolved terminator.

### Recursive-descent CFG (`analysis/recursive_cfg.py`)

`build_recursive_cfg(path, info, start, max_instructions=2000, max_blocks=500,
max_functions=32, max_bytes=1_000_000)` walks code by following statically
known direct transfers from one seed address:

- **Jump targets** become intra-function block edges; conditional jumps also
  fall through, so both arms are decoded.
- **Direct call targets** become function-boundary candidates
  (`cfg.recursive_descent` / `direct_call_target`, medium confidence — the
  boundary is a candidate, not proven) and the next walk seeds.
- **Indirect transfers** (`call rax`, `jmp qword ptr [...]`) stay explicitly
  unresolved with their reason; no edge, boundary, or function is invented.
- **Budgets:** instruction, block, function, and byte budgets all bound the
  walk; `RecursiveCFG.truncated` and the warnings say exactly which budget cut
  what. Overlapping blocks (a branch into the middle of decoded code) count
  their instructions twice, and `visited_instructions` says so.
- Per-function graphs reuse the `FunctionCFG` shape of the linear sweep, so
  consumers handle both with one parser.

### Session store (`storage/session.py`)

`SessionStore(db_path)` keeps analysis snapshots in SQLite (standard library
only, parameterized SQL). The database file and any missing parent directories
are created on construction, and the store works as a context manager.

- `save(info, functions_count, strings_count, notes=None, session_id=None)`
  appends a row and returns a `SessionRecord`: 12-hex-character id (generated
  from `uuid4` unless supplied), UTC ISO-8601 timestamp, binary path, SHA-256,
  format, architecture, bitness, entry point, function and string counts, notes.
- `get(id)`, `list(limit=50)` (newest first, capped at 10,000), `delete(id)`,
  `close()`.
- Sessions are **additive**: saving the same binary twice produces two rows, so
  repeated analyses stay auditable.
- Stored content is a fingerprint plus counts — not disassembly, xrefs, or CFG
  blocks.

## CLI examples

```powershell
# Cross-references for one binary (table, or --json for the raw result)
codevanta xrefs C:\Windows\System32\notepad.exe --limit 40
codevanta xrefs samples\elf64_text.bin --max-bytes 200000 --json

# Control-flow graph for a region: address, function name, or entry point
codevanta cfg C:\Windows\System32\notepad.exe --address 0x140001000
codevanta cfg C:\Windows\System32\kernel32.dll --function CreateFileW --max-blocks 100

# Sessions: save a snapshot, then inspect the database
codevanta session save C:\Windows\System32\notepad.exe --notes "baseline triage"
codevanta session list --limit 10
codevanta session show 4f9c1a7b2d3e
```

Option notes:

- `xrefs`: `--limit` (rows shown, default 100), `--max-bytes` (decode budget,
  default 4,000,000), `--json`.
- `cfg`: `--address`/`-a`, `--function`/`-f`, `--max-instructions` (default
  2000), `--max-blocks` (default 500), `--json`. When neither address nor
  function is given, the entry point is used.
- `session save|list|show`: `--db` selects the database file. The default is
  `$env:CODEVANTA_DB` when set, otherwise `~/.codevanta/sessions.db`.
  `session save` re-runs function discovery and string extraction (minimum
  length 4) to fill the counts; `session list` shows 20 rows by default.

## Evidence and confidence semantics

`Confidence` is not a quality score for the binary — it states how directly the
finding is supported by decoded data.

| Finding | `source` | `method` | Confidence | Why |
|---------|----------|----------|------------|-----|
| One xref | `capstone.direct_call` / `capstone.direct_jump` / `capstone.conditional_branch` | `linear_disassembly` | `certain` | The target is read straight from the decoded operand; nothing is inferred |
| Whole xref scan | `capstone.xref_scan` | `linear_disassembly` | `certain` | Every emitted reference is a direct read; incomplete coverage is reported through `truncated` and `warnings`, not by lowering confidence |
| CFG graph | `cfg.linear_sweep` | `linear_sweep` | `medium` | The instruction stream is decoded, but leaders, terminators, and successor sets are mnemonic heuristics |
| CFG block | `cfg.linear_sweep` | `basic_block` | `medium` | Block boundaries depend on the same heuristic rules |
| Session record | — | — | — | Sessions store file metadata and counts; no analysis evidence is attached |

Practical reading: a `certain` xref means "this instruction really does encode
this target", not "this is a reasonable-looking edge". A `medium` CFG means
"this is what a linear sweep suggests the control flow looks like" — verify
before acting on it, especially around indirect branches, jump tables, and data
embedded in code sections.

## Limitations

- **Direct branch targets only.** Register- and memory-indirect transfers are
  ignored (xrefs) or left unresolved (CFG). Jump tables are not interpreted.
- **No call-graph recursion.** A CFG covers one region starting at the address
  you ask for; callees are not followed and per-function graphs are not joined.
- **Everything is bounded.** `max_bytes`, `max_instructions`, and `max_blocks`
  cut work short on large inputs; check `truncated` and `warnings` before
  treating a result as complete.
- **No CFG rendering.** Results are tables and JSON. There is no graph viewer
  and no web UI.
- **No debugger.** Phase 2 is static analysis only; the target is never
  executed.
- **Sessions are shallow.** They store a fingerprint plus function/string
  counts. Xrefs, CFG output, and annotations are not persisted, and there is no
  schema migration yet.
- **Single-user, local.** The SQLite file is a local artifact with no locking
  strategy beyond SQLite defaults and no concurrency model.
- **Phase 2 tools are not exposed over MCP yet.** The MCP server still offers
  the five phase 1 tools.

## Next steps

1. Recursive descent with function-boundary detection, so CFGs stop depending on
   a caller-supplied start address.
2. Indirect-target resolution: jump tables, `call qword ptr [...]` thunks, and
   import-stub targets.
3. A call-graph layer built from the xref output, with per-function CFG
   aggregation.
4. Persist xrefs and CFG blocks into sessions, and store analyst annotations
   next to them.
5. Schema versioning and migrations for the session database.
6. MCP tools for xrefs, CFGs, and sessions, so coding agents see the same
   surface as the CLI.
7. Debugger backend and a graph-oriented viewer — both are later-phase work,
   not part of what is delivered here.

## Verification

```powershell
python -m pytest
ruff check src tests
```

Phase 2 modules are covered by `tests/test_xrefs.py`, `tests/test_cfg.py`,
`tests/test_session.py`, and `tests/test_cli_phase2.py`.

# Phase 2h — Struct-Field Suggestions, MCP Parity, Python 3.14 CI

Phase 2h closes the phase 2 loop in three places:

1. **Struct-field type recovery** (`analysis/type_recovery.py`, new):
   `suggest_struct` reads the memory operands of a bounded instruction window
   and suggests the fields a function touches through one base register.
2. **MCP parity** (`mcp_server/tools.py`, `mcp_server/server.py`):
   `codevanta_diff`, `codevanta_jump_table`, and `codevanta_function_hash`
   expose the phase 2f/2g analysis, bringing the server to thirteen tools.
3. **Python 3.14 on CI** (`.github/workflows/ci.yml`): the test matrix is now
   3.11, 3.13, and 3.14.

| Path | What changed |
|------|--------------|
| `src/codevanta/analysis/type_recovery.py` | New: `parse_memory_operands(...)`, `suggest_struct(...)`, `FieldAccess`, `SuggestedField`, `StructSuggestion`, `STACK_REGISTERS`, limit constants |
| `src/codevanta/mcp_server/tools.py` | New `diff(...)`, `jump_table(...)`, `function_hash(...)` plus shared `_check_bounded_int` / `_check_bool` / `_check_address` validation |
| `src/codevanta/mcp_server/server.py` | `codevanta_diff`, `codevanta_jump_table`, `codevanta_function_hash` registered — thirteen tools |
| `src/codevanta/cli/main.py` | `struct` command |
| `.github/workflows/ci.yml` | test matrix `"3.11"`, `"3.13"`, `"3.14"` |
| `docs/repository-settings.md` | 3.14 note updated |

Everything here stays static: binaries are read through
`codevanta.core.report.read_code` (bounded by the containing section's file
bytes), never mapped and never executed.

**Status:** in progress. A suggested field is a *hypothesis* derived from
operand shapes, not a recovered type. See [Limitations](#limitations).

## Usage

```powershell
# Fields touched by the entry point
codevanta struct samples\handle.bin

# Fields touched by a named function, or by an explicit address
codevanta struct samples\handle.bin --function process
codevanta struct samples\handle.bin --address 0x401000 --json

# Keep frame-relative operands and widen the budget
codevanta struct samples\handle.bin --function process --include-stack --max-instructions 4000 --max-fields 128
```

The same analysis is available from Python.

```python
from codevanta.analysis.type_recovery import suggest_struct
from codevanta.core.loader import BinaryLoader

path = "samples/handle.bin"
info = BinaryLoader().load(path)

suggestion = suggest_struct(path, info, 0x401000)
for field in suggestion.fields:
    print(hex(field.offset), field.width, field.read_count, field.write_count)
print(suggestion.to_dict()["truncated"])
```

Struct suggestions are not exposed over MCP yet; the three tools this phase
adds are `codevanta_diff`, `codevanta_jump_table`, and
`codevanta_function_hash` (see [MCP surface](#mcp-surface-thirteen-tools)).

## Struct-field suggestions

`parse_memory_operands` reads one decoded instruction; `suggest_struct` runs it
over a bounded linear sweep and aggregates the result.

### Which operands count

Only three addressing shapes are understood — a single base register with an
optional signed displacement:

| Operand | Result |
|---------|--------|
| `[rdi]` | offset `0x0` |
| `[rdi + 0x18]` | offset `0x18` |
| `[rdi - 8]` | offset `-0x8` (a decimal displacement is accepted like hex) |
| `[rdi + rcx*4]` | skipped — index register |
| `fs:[rax]` | skipped — segment prefix |

An operand with an index register, a scale or a segment prefix is skipped
rather than guessed, so it never becomes a bogus field. `lea` and `nop` are
skipped because their bracket expression is not a memory access, and any
mnemonic starting with `prefetch` is skipped too.

### Stack registers

`STACK_REGISTERS` is `sp`, `esp`, `rsp`, `bp`, `ebp`, `rbp`. Operands based on
them describe a stack slot or a spilled local, not a struct field, so they are
dropped by default; `include_stack=True` (`--include-stack`) keeps them as
ordinary offsets. Nothing resolves the frame, so an included `[rbp - 8]` simply
appears as offset `-0x8` with no claim that it is a local variable.

### Instruction-pointer registers

Operands based on `ip`, `eip`, or `rip` address a global (or the import/thunk
table), not a field of the pointer argument, so they are always skipped. Without
that rule, `[rip + disp]` in a PIE build would show up as a huge fake offset.

### Widths

| Operand keyword | Width |
|-----------------|-------|
| `byte ptr` | 1 |
| `word ptr` | 2 |
| `dword ptr` | 4 |
| `qword ptr` | 8 |
| none | pointer width — 2 bytes (16-bit), 4 (32-bit), 8 (64-bit); unknown bitness falls back to 8 |

The width is an **access** width. It is not a claim about a declared type: a
`dword ptr` read could be half of an 8-byte value or one element of an array.

### Direction

- memory operand as the **first** operand → `write`
- memory operand anywhere else → `read`
- `cmp`, `cmps`, `cmpsb`, `cmpsw`, `cmpsd`, `cmpsq`, `test` → always `read`,
  even when the memory operand comes first
- `call`, `jmp` (for example vtable dispatch through `[rax + 0x18]`) and `push`
  → always `read`, because the memory operand is dereferenced, not assigned

Read-modify-write instructions (`add qword ptr [rdi + 8], 1`, `cmpxchg`) count
as a write only; the read half of the pair is not counted.

### Aggregation by offset

Accesses are reduced to one `SuggestedField` per displacement:

- the **dominant width** is the width seen most often at that offset; a tie
  goes to the wider access, which is the safer assumption;
- `read_count` / `write_count` are totals for the offset across *all* widths;
- `first_access` is the address of the first instruction that touched the
  offset;
- fields are sorted by ascending offset, so a given input always produces the
  same suggestion;
- the base register is recorded on each `FieldAccess` but is **not** part of the
  aggregation key, so `[rdi + 0x10]` and `[rsi + 0x10]` collapse into a single
  offset `0x10` field.

That last point is the biggest structural caveat of this phase: one suggestion
is an offset histogram for one swept window, not a per-object layout. When a
function receives two structs in two registers, their fields merge whenever the
displacements collide. The `codevanta struct` footer recovers the set of base
registers separately (see [CLI reference](#codevanta-struct)), but that list is
not a per-field attribution.

### Evidence and confidence

| Record | `source` / `method` | Confidence |
|--------|---------------------|------------|
| `FieldAccess` | `type_recovery.memory_operand` / `operand_scan` | `MEDIUM` |
| `SuggestedField` | `type_recovery.memory_operand` / `operand_scan` | `MEDIUM` |
| `StructSuggestion` | `type_recovery.suggestion` / `operand_aggregation` | `MEDIUM` |

Every record is capped at `MEDIUM` and never higher: the operand proves that
memory was accessed, not what the memory holds. The suggestion's detail string
states that the fields are heuristic from operand shapes and not verified
types, and its `extra` map carries `max_instructions`, `max_fields`,
`instruction_count`, `memory_access_count`, `field_count`, `truncated`, and
`include_stack`.

### Bounds and determinism

| Option | Range | Default |
|--------|-------|---------|
| `max_instructions` | 1 .. 100000 (`MAX_DISASSEMBLY_COUNT`) | 2000 |
| `max_fields` | 1 .. 512 | 64 |

- at most `max_instructions * 16` file bytes are read, further bounded by the
  file-backed bytes of the containing section;
- `truncated` reports offsets dropped by the **field** cap (lower offsets win);
  exhausting the instruction budget is *not* reported there, so compare
  `instruction_count` with `max_instructions` yourself;
- `AnalysisError` is raised for an invalid `start` or limit, a start outside an
  executable section, an address with no file bytes, an architecture that
  cannot be disassembled, or a window that decodes no instruction;
- two calls with the same arguments always produce the same suggestion: the
  sweep is linear and fields, widths and counters are ordered deterministically.

## MCP surface (thirteen tools)

This phase completes the MCP parity work begun in phase 2c: `codevanta_diff`,
`codevanta_jump_table`, and `codevanta_function_hash` expose the phase 2f/2g
analysis, so the server now registers thirteen tools.

| Tool | Purpose |
|------|---------|
| `codevanta_info` | format, architecture, bitness, sections, imports, exports, evidence |
| `codevanta_functions` | function candidates with detection source and confidence |
| `codevanta_strings` | ASCII/UTF-16LE strings with file offset and virtual address |
| `codevanta_disasm` | bounded disassembly of one region |
| `codevanta_analyze` | phase 1 report (sections, strings, functions) |
| `codevanta_xrefs` | call/jump/branch references, import and indirect slots |
| `codevanta_cfg` | linear or recursive basic blocks and edges |
| `codevanta_callgraph` | call-graph nodes, edges, warnings |
| `codevanta_diff` | structural binary diff, optional deep fingerprints |
| `codevanta_jump_table` | absolute or relative jump-table decode |
| `codevanta_function_hash` | normalized-shape SHA-256 of one function |
| `codevanta_session_save` | persist an analysis record |
| `codevanta_session_list` | list stored sessions |

### `codevanta_diff(left, right, max_functions=5000, deep=False)`

Functions are matched by virtual address first and, for the leftovers, by name
after moving; sections and exports by name, imports by `(library, name)`.
`identical` means no function, section, import or export delta was observed —
equal file hashes are neither required nor implied. `deep=True` additionally
fingerprints the normalized instruction shape of address-matched functions and
marks a pair `changed` with both digests when they differ; every structural rule
stays unchanged. `max_functions` is validated `1 .. 20000` per side and any
truncation is reported in `warnings`.

### `codevanta_jump_table(path, address, mode="absolute", base=None, entries=256, executable_only=True)`

`mode="absolute"` (the default) reads consecutive pointer-sized virtual
addresses; `mode="relative"` reads signed 32-bit offsets and resolves
`target = base + offset`, with `base` **required** in that mode. `entries` is
validated `1 .. 20000`; anything above the resolver's `MAX_ENTRIES` (4096) is
rejected rather than clamped. `executable_only=True` ends the scan with a warning when a target falls
in a non-executable section. The payload carries `table_address`, `entry_count`,
`entries`, `pointer_size`, `truncated`, `warnings`, and `evidence`.

### `codevanta_function_hash(path, address, max_instructions=2000)`

Decodes a bounded linear sweep from `address`, renders each instruction as
`"<mnemonic> <operands>"`, masks every numeric literal to `#`, and hashes the
newline-joined stream with SHA-256 (`algorithm: "sha256"`). Equal digests mean
equal mnemonic/operand shape — not byte equality — and different digests are not
a semantic difference. `truncated` marks a digest that covers only a prefix of
the region. `max_instructions` is validated `1 .. 20000`, and at most
`max_instructions * 16` file bytes are read.

Shared argument handling: paths pass through `_validate_path`, limits through
`_check_bounded_int` (`1 .. 20000`, booleans rejected even though `bool` is an
`int`), flags through `_check_bool`, and addresses through `_check_address`
(non-negative, non-boolean). Failures raise `AnalysisError` naming the argument.

The MCP tools are thin adapters over the analysis functions, so they add no
confidence of their own: the diff, jump tables, and fingerprints all report
`medium`. Struct suggestions are **not** exposed over MCP yet — the CLI and the
Python API are the only entry points in this phase.

## CLI reference

### `codevanta struct`

```text
codevanta struct PATH [--address INT] [--function NAME] [--max-instructions INT]
                      [--max-fields INT] [--include-stack] [--json]
```

| Option | Meaning |
|--------|---------|
| `PATH` | PE or ELF file; read, never executed |
| `--address`, `-a` | start address (decimal or `0x` hex) |
| `--function`, `-f` | start at a discovered function name |
| `--max-instructions` | instruction budget (default `2000`, max `100000`) |
| `--max-fields` | field cap (default `64`, max `512`) |
| `--include-stack` | keep `[rsp]`/`[rbp]`-relative operands |
| `--json` | print the full suggestion document |

The start address resolves like the other region commands: `--address` when
given, else the named function, else the binary's entry point. The table is
titled `Struct at 0x…` and shows `Offset`, `Width`, `Reads`, and `Writes` per
suggested field, sorted by ascending offset; a negative offset is rendered
`-0x8`.

Under the table a dim footer reports `base registers`, `fields`, `instructions`,
`max fields`, and `truncated: yes|no`. The base-register list is produced by a
second bounded pass over the same window through `parse_memory_operands` (sorted
and de-duplicated), because `suggest_struct` aggregates per offset and drops the
register: it names the registers the sweep used as struct pointers, not which
register owns which field, and it shows `-` when that pass fails. One `warning:`
line follows per limitation — the field cap being reached (with a hint to raise
`--max-fields`), and an empty result, which also points at `--include-stack`
when stack operands are being excluded.

`--json` prints `StructSuggestion.to_dict()` unchanged: `address`,
`instruction_count`, `field_count`, `max_fields`, `truncated`, `include_stack`,
`fields` (each with `offset`, `width`, `read_count`, `write_count`,
`access_count`, `first_access`, and its own `evidence`), and the
suggestion-level `evidence`.

```powershell
codevanta struct samples\handle.bin --address 0x401000
codevanta struct samples\handle.bin --function process --json > struct.json
```

The command exits `0` on success and `2` on load or input errors (missing file,
invalid address or limits, unknown function name, address outside an executable
section), matching the `xrefs`, `cfg`, `jump-table`, `diff`, and `callgraph`
conventions. The phase 2f/2g commands are unchanged.

## CI matrix

`.github/workflows/ci.yml` now runs its lint and test job on **3.11, 3.13, and
3.14** (`fail-fast: false`), plus the wheel build and smoke test on 3.13:

| Job | Interpreter | Checks |
|-----|-------------|--------|
| `test` | 3.11, 3.13, 3.14 | `ruff check src tests`, `python -m pytest` |
| `package` | 3.13 | build the wheel, install it into a clean venv, run `codevanta --help` and `codevanta mcp --help`, assert the wheel layout |

3.14 was previously held out of the matrix because it needed published `lief`
wheels. `lief` now ships `cp314` wheels (`lief 1.0.0`), so the `lief>=0.14`
requirement resolves to a 3.14-capable release. `requires-python` stays
`>=3.10`, so 3.10 and 3.12 remain supported but are not exercised by CI;
`docs/repository-settings.md` was updated to match.

## Confidence summary

| Output | Confidence | Why |
|--------|------------|-----|
| `FieldAccess` | `medium` | the operand shape is proven, the meaning of the access is not |
| `SuggestedField` / `StructSuggestion` | `medium` | aggregation over a linear window; no layout, alignment or identity proof |
| `codevanta_diff` / `codevanta_jump_table` / `codevanta_function_hash` | the underlying value | MCP adapters forward the analysis evidence unchanged |

Nothing in this phase is promoted above `medium`, and no output claims byte or
semantic equivalence.

## Limitations

- **No type names.** Fields are an offset and a width: no `int32_t`, no
  struct name, no pointer-versus-integer distinction, no signedness.
- **No alignment or padding inference.** Offsets are reported exactly as encoded
  in the operands; nothing inserts gaps, infers `alignas`, or computes a total
  struct size.
- **No cross-function inference.** One call analyses one bounded window. The same
  struct touched by a caller and its callee is never merged, and no field is
  corroborated against another function.
- **Aggregation ignores the base register.** Displacements from different
  registers merge into one list, so two objects with colliding offsets become a
  single field set (see [Aggregation by offset](#aggregation-by-offset)).
- **Linear sweep only.** Control flow is not followed, so data bytes inside the
  window can decode as instructions and produce spurious fields; padding and jump
  tables in the region are not excluded.
- **Read-modify-write counts as a write.** `add [rdi + 8], 1` and `cmpxchg`
  contribute no read to `read_count`.
- **Intel syntax only.** ARM/MIPS-shaped operands (`[x0, #0x10]`) never match, so
  a non-Intel binary yields no fields instead of wrong ones.
- **`truncated` is field-cap only.** Instruction-budget exhaustion is invisible in
  the suggestion.
- **Not over MCP.** Thirteen tools are registered and none of them returns a
  struct suggestion.
- **Phase 2 scope otherwise unchanged.** No slot dereferencing, no call
  following, no debugger, and the diff remains structural with an opt-in shape
  comparison for address-matched functions only.

## Next steps

- Expose struct suggestions over MCP (`codevanta_struct`) so agents get the same
  view as the CLI.
- Key aggregation by base register (and by call site) to separate objects that
  share displacements inside one window.
- Drive the sweep from the recursive CFG traversal so only reachable code is
  scanned, and exclude padding and jump tables.
- Infer alignment, padding, arrays, and embedded pointers; separate signed from
  unsigned accesses.
- Cross-check offsets against symbols, DWARF/PDB, and repeated use across
  functions before considering a confidence above `medium`.
- Decide whether 3.12 replaces one of the tested interpreters or stays untested.

## Verification

```powershell
python -m pytest tests\test_type_recovery.py tests\test_mcp_tools.py
python -m pytest
ruff check src tests
```

- `tests/test_type_recovery.py` — three-field recovery from
  `48 8b 47 10` / `48 89 5f 18` / `8b 4f 20` / `c3` with the right offsets,
  widths and directions; `medium` evidence that names the heuristic;
  stack operands excluded by default and kept with `include_stack`; a zero
  offset; `max_fields` truncation; invalid start and out-of-range budgets;
  compare/test direction; indexed and `lea` operands skipped; negative
  displacement and pointer-width fallback; dominant-width tie-break and
  frequency; determinism and JSON serializability.
- `tests/test_mcp_tools.py` — the thirteen-tool list, plus one test per new tool:
  `codevanta_diff` (moved entry point), `codevanta_jump_table` (absolute and
  relative tables), and `codevanta_function_hash` (shape, not bytes).
- `tests/test_cli_phase2h.py` — the entry-point run reporting three fields, the
  footer naming base registers and truncation, `--address` in hex and decimal,
  `--max-fields` truncation plus its warning, stack slots excluded by default and
  kept with `--include-stack`, both `--json` payloads, exit `2` for an invalid
  address, an unknown function, a missing file and an out-of-range budget, and
  `--help` documenting every option.

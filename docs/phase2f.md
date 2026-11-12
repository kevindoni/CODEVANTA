# Phase 2f — Jump Tables, CFG Indirect Resolution, Interactive Viewer, Structural Diff

Phase 2f closes two gaps from phase 2e, makes the offline viewer interactive,
and adds a structural comparison view:

1. A **jump-table resolver** (`analysis/jump_tables.py`) that decodes a bounded
   array of absolute pointers into candidate dispatch targets, with evidence.
2. **Opt-in indirect resolution in the recursive CFG traversal**
   (`build_recursive_cfg(..., resolve_indirect=True)`), so a
   `jmp qword ptr [rip + disp]` dispatch block can gain successors instead of
   silently terminating the traversal.
3. An **interactive offline viewer**: the HTML export from `analysis/html_view.py`
   now pans, zooms, searches, and filters by node kind — still one
   self-contained file with no CDN and no JavaScript library.
4. **Structural binary diff** (`analysis/binary_diff.py`): metadata-level
   comparison of two binaries (functions, sections, imports, exports), labelled
   `medium` confidence because no bytes and no semantics are compared.

| Module | What changed |
|--------|--------------|
| `src/codevanta/analysis/jump_tables.py` | New: `resolve_jump_table(...)` returning `JumpTableResult` / `JumpTableEntry` |
| `src/codevanta/analysis/cfg.py` | `build_recursive_cfg` gained `resolve_indirect=False`, `max_jump_tables=8`, `max_table_entries=256` |
| `src/codevanta/analysis/html_view.py` | Inline `<script>` adds pan, wheel zoom, label search, kind filters |
| `src/codevanta/analysis/binary_diff.py` | New: `diff_infos(...)` / `diff_binaries(...)` returning `BinaryDiff` |
| `src/codevanta/cli/main.py` | `codevanta diff`, `codevanta jump-table`, `codevanta cfg --resolve-indirect` |

Everything here is static: target files are parsed and read, never mapped or
executed, and no run-time memory is inspected.

**Status:** in progress. Jump tables are recognised by *shape*, not by proving a
dispatcher indexes them; indirect resolution covers pointer-reached memory
operands only; the diff is structural only. See [Limitations](#limitations).

## Usage

```powershell
# Decode a pointer table (the address must be inside a section and file-backed)
codevanta jump-table samples\dispatch.bin --address 0x402000

# Same, with an explicit slot budget and JSON output
codevanta jump-table samples\dispatch.bin --address 0x402000 --entries 64 --json

# Disable the executable-only filter (pointers into data sections no longer stop the scan)
codevanta jump-table samples\dispatch.bin --address 0x402000 --no-executable-only

# Recursive CFG that follows jump tables out of indirect jumps
codevanta cfg samples\dispatch.bin --address 0x401000 --traversal recursive --resolve-indirect

# Structural metadata diff, human-readable or JSON
codevanta diff samples\v1.bin samples\v2.bin
codevanta diff samples\v1.bin samples\v2.bin --max-functions 20000 --json

# Interactive offline viewer (unchanged command, new interactions)
codevanta callgraph samples\app.exe --format html -o graph.html
```

## Jump-table resolver

`resolve_jump_table` decodes one array of absolute virtual addresses. The whole
window is `max_entries * pointer_size` bytes, validated against the binary map
before a byte is read, and read through `codevanta.core.report.read_code`, which
never returns more bytes than the containing section maps.

```python
from pathlib import Path

from codevanta.analysis.jump_tables import resolve_jump_table
from codevanta.core.loader import BinaryLoader

path = Path("samples/dispatch.bin")
info = BinaryLoader().load(path)

result = resolve_jump_table(path, info, 0x402000, max_entries=256)
print(result.pointer_size)                  # 8 on a 64-bit binary, 4 on 32-bit
print(len(result.entries), result.truncated)
for entry in result.entries:
    print(f"#{entry.index} target=0x{entry.target:x}")
for warning in result.warnings:
    print("warning:", warning)
```

| Argument | Default | Meaning |
|----------|---------|---------|
| `table_address` | — | Absolute VA of the first pointer slot; must be inside a section *and* backed by file bytes |
| `max_entries` | `256` (`DEFAULT_MAX_ENTRIES`) | Slots to decode, `1 .. 4096` (`MAX_ENTRIES`) |
| `pointer_size` | from bitness | `8` for a 64-bit binary, `4` for a 32-bit one; any other explicit value is rejected |
| `executable_only` | `True` | A target outside an executable section ends the scan |
| `min_target` / `max_target` | `None` | Optional inclusive window for accepted targets (library API only) |

### What is decoded

- Each slot is read as an unsigned integer of `pointer_size` bytes, decoded with
  the binary's endianness: an `endianness` string starting with `big`, `msb`, or
  `be` is big-endian, everything else little-endian.
- Pointer width is inferred from `bitness` (64 → 8, 32 → 4). A binary with any
  other bitness must be given an explicit `pointer_size`.
- The scan is sequential from `table_address`. There is no search for a table
  and no heuristic start: the caller supplies the address.

### Stop rules

The scan stops at the **first** slot that is not a usable target — including
index 0. Every stop is appended to `result.warnings`, so a short table can be
told apart from one that ran into something unexpected:

| Slot content | Recorded warning |
|--------------|------------------|
| `0` | `zero pointer at index N ... terminates the table` (the conventional terminator) |
| Below `min_target` | `index N: target ... is below min_target ...` |
| Above `max_target` | `index N: target ... is above max_target ...` |
| Not mapped by any section | `index N: target ... is not mapped by any section ...` |
| In a non-executable section (with `executable_only`) | `index N: target ... is inside non-executable section '...'` |

Stopping — rather than skipping and continuing — is deliberate: a table is a
contiguous run of pointers, so the first non-pointer slot is evidence the array
ended or the address was wrong. Skipping could splice two unrelated arrays
together.

`truncated` is `True` only when the scan reached `max_entries` without stopping
*and* the next slot still holds a readable, non-zero pointer. A table that ended
exactly at the ceiling is not reported as truncated.

### Evidence and confidence

| Result | `evidence.source` | `evidence.method` | Confidence |
|--------|-------------------|-------------------|------------|
| Each decoded slot | `jump_table.pointer_array` | `absolute_pointers` | `medium` |
| Resolution as a whole | `jump_table.pointer_array` | `absolute_pointers` | `medium` |

Slot evidence is pinned to the slot address and carries the decoded index and
target; result evidence is pinned to `table_address` and records entry count,
pointer size, and the `truncated` flag.

`medium` is the ceiling here because the module only shows that a run of values
*looks like* a pointer array. It never shows that a dispatcher bounds-checks an
index and reads the slot, so "pointer array by shape" is not proof of a
`switch` statement.

`JumpTableResult.to_dict()` yields `table_address`, `entry_count`, `entries`
(`index`, `target`, `evidence`), `pointer_size`, `truncated`, `warnings`, and
`evidence`.

## CFG opt-in indirect resolution

`build_recursive_cfg` keeps its phase 2e behaviour unless you ask for more:

```python
from pathlib import Path

from codevanta.analysis.cfg import build_recursive_cfg
from codevanta.core.loader import BinaryLoader

path = Path("samples/dispatch.bin")
info = BinaryLoader().load(path)

graph = build_recursive_cfg(
    path,
    info,
    0x401000,
    resolve_indirect=True,   # default False
    max_jump_tables=8,       # default 8
    max_table_entries=256,   # default 256
)
```

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `resolve_indirect` | `False` | Resolve `jmp` through a pointer table into successors |
| `max_jump_tables` | `8` | Tables resolved per traversal, `1 .. MAX_DISASSEMBLY_COUNT` |
| `max_table_entries` | `256` | Slots decoded per table, `1 .. 4096` (`jump_tables.MAX_ENTRIES`) |

The two jump-table limits are validated even when `resolve_indirect` is `False`,
so an invalid budget fails the same way regardless of the flag. With
`resolve_indirect=False` the traversal output, warnings, and evidence text are
exactly what phase 2e produced.

### What gets resolved

Only a block-terminating `jmp` with a pointer-sized **memory** operand:

- `jmp qword ptr [rip + disp]` on a 64-bit binary (or `dword ptr` on a 32-bit
  one), where the displacement is resolved against the address of the *next*
  instruction, exactly as the CPU would,
- `jmp qword ptr [0x402000]` — the absolute form.

Everything else yields no table address: `jmp rax`, indexed operands such as
`jmp qword ptr [rax*8 + 0x402000]`, symbol expressions, and narrower or wider
reads. Those may still be dispatchers, but no table address can be justified for
them.

Once a table address is known, `resolve_jump_table` decodes up to
`max_table_entries` slots (with `executable_only=True`), and only targets that
are executable, file-backed addresses become successors. Successors are
deduplicated and sorted, then queued as leaders like any other branch target, so
the blocks behind them are traversed normally.

On the command line, `--resolve-indirect` is the only knob: the jump-table
budgets stay at their library defaults (`max_jump_tables=8`,
`max_table_entries=256`), so a CLI traversal never spends more than eight
tables' worth of reads. Raising them means calling `build_recursive_cfg`
directly.

### Warnings

Every jump-table limitation is reported in `FunctionCFG.warnings`, prefixed with
the block start, so a caveat can be traced to the block that caused it:

- `jump-table limit reached (max_jump_tables=...)` — the per-traversal budget is
  spent; further indirect jumps stay unresolved (reported once per traversal).
- `jump table at 0x... was truncated at max_table_entries=...` — the slot
  ceiling cut that table short.
- `jump table at 0x...: <module warning>` — the resolver's own stop reasons are
  surfaced verbatim, including the zero terminator.
- `jump-table target(s) ... are not executable file bytes` — decoded targets
  that cannot become blocks (at most eight addresses are named per warning).
- `jump table at 0x... could not be read (...)` — the table address was not
  readable; that edge is omitted and the table is not counted as resolved.

A resolved table that yields no usable target is *not* counted as an unresolved
indirect branch; only operands that never produced a table address are. The
aggregate count appears in the usual
`N indirect branch target(s) were not resolved ...` warning.

When `resolve_indirect=True`, the graph's evidence detail is extended with
`N jump table(s) resolved from indirect jumps (M pointer slot(s) decoded,
bounded by max_jump_tables=... and max_table_entries=...)`; with the default
`False` the evidence text is unchanged. Evidence source and confidence stay
`cfg.recursive_traversal` / `medium`, because resolved tables still describe only
what the decoded pointers claim.

## Interactive offline viewer

`codevanta callgraph --format html` (and `to_html`) still writes one
self-contained HTML5 document with an inline SVG view. It now also carries a
single inline `<script>` — no `src`, no library, no web font, no `http(s)`
reference anywhere in the document — adding:

| Interaction | Behaviour |
|-------------|-----------|
| Pan | Drag the SVG; the `viewBox` is rewritten as you move |
| Zoom | Mouse wheel, anchored at the pointer, clamped to `0.2x`–`8x` |
| Search | The `cv-search` input highlights matching nodes (`cv-hit`) and dims the rest (`cv-dim`); `Esc` clears it |
| Kind filters | Checkboxes for `function / entry_point`, `call_site`, and `import / external`; unchecked groups are hidden |

Search is case-insensitive and matches the **rendered** label plus the node id
(the box `<title>`), so a query that only hits the truncated tail of a long label
does not match. Filters and search compose: a node hidden by a filter stays
hidden regardless of the query.

With scripting disabled the document still renders in full — every node is
visible and no class is applied by default. Output stays deterministic: identical
graph content produces byte-identical HTML, because nodes are sorted by
`(column, kind rank, id)`, edges by `(source, target, label)`, and the script
never interpolates graph text (it drives itself from `data-kind`, the label text,
and the `application/json` payload).

Viewer limitations are unchanged in kind: the layout is a fixed three-column
stack (zoom moves it, it does not re-flow), filters hide nodes but not their
edges, the edge table always lists every edge, panning is unbounded, and
reloading the page is the only way to reset the view.

## Structural binary diff

`diff_binaries` loads both files with LIEF and compares the metadata the loader
already extracted plus the candidates from `discover_functions`. No instruction
bytes are compared and nothing is executed.

```python
from codevanta.analysis.binary_diff import diff_binaries

diff = diff_binaries("samples/v1.bin", "samples/v2.bin", max_functions=5000)
print(diff.identical)
for delta in diff.functions_changed:
    print(f"0x{delta.address:x}", delta.name, delta.change)
```

### Matching rules, in order

1. **By address.** Candidates sharing a virtual address are the same function;
   if their metadata differs the entry is `changed`. Only `name` and `size` are
   compared — `source`, `confidence`, and `evidence` describe how a candidate
   was *found*, not the binary itself, and may legitimately differ between two
   loads.
2. **By name.** Candidates left over on both sides are matched by name, so a
   relocated function is reported as one `changed` entry carrying both addresses
   instead of one removal plus one addition.
3. **Everything left over** is `removed` (left side only) or `added` (right side
   only).

Sections are compared by **name**, imports by `(library, name)` (rendered as
`lib!name` when a library is known, otherwise `name`), and exports by **name**.
Consequently a section that changed size or flags under the same name, or an
export that kept its name but moved, is **not** a delta. `identical` therefore
means "no structural delta was observed" — it neither requires nor implies equal
file hashes.

`BinaryDiff.to_dict()` reports both paths, `identical`, the three function-delta
lists, the added/removed section, import, and export lists, `evidence`, and
`warnings`.

### Bounds and confidence

`max_functions` defaults to `5000` and is clamped into `1 .. 20000`; a clamped
value is recorded in `warnings`. When a side has more candidates than the
ceiling, the lowest addresses are kept and a truncation warning says so, so the
same inputs always produce the same output.

| Result | `evidence.source` | `evidence.method` | Confidence |
|--------|-------------------|-------------------|------------|
| Diff as a whole | `binary_diff.structural` | `metadata_compare` | `medium` |

Every delta's evidence repeats the caveat: structural metadata only, no
instruction bytes read, compared, or executed, so it is not a semantic
equivalence claim. A `changed` entry means "the observed metadata differs", never
"the machine code differs" — and `identical` does not mean the two files behave
the same, only that the compared metadata matched.

## CLI reference

### `codevanta jump-table`

```text
codevanta jump-table PATH --address ADDR [--entries N] [--executable-only|--no-executable-only] [--json]
```

| Option | Default | Effect |
|--------|---------|--------|
| `--address` / `-a` | required | First pointer slot, decimal or `0x` hex |
| `--entries` | `256` | Maximum slots decoded (`1 .. 4096`) |
| `--executable-only` / `--no-executable-only` | enabled | Stop the scan at a pointer into a non-executable section |
| `--json` | off | Emit `JumpTableResult.to_dict()` instead of the table |

The table prints `Index` and `Target` columns, a footer with pointer size, entry
count, and the `truncated` flag, then one `warning:` line per stop reason. An
invalid address, budget, or unreadable table exits `2`.

### `codevanta cfg --resolve-indirect`

```text
codevanta cfg PATH [--address ADDR | --function NAME] --traversal recursive --resolve-indirect [--max-instructions N] [--max-blocks N] [--json]
```

`--resolve-indirect` is rejected with exit code `2` unless
`--traversal recursive` is also given: the linear sweep has no notion of a
dispatch edge, and silently ignoring the flag would look like "nothing was
found". With `recursive` the output is the same table and the same `--json`
payload as phase 2e, plus jump-table successors in `successors` and jump-table
caveats in `warnings`.

### `codevanta diff`

```text
codevanta diff LEFT RIGHT [--max-functions N] [--json]
```

| Option | Default | Effect |
|--------|---------|--------|
| `--max-functions` | `5000` | Per-side ceiling on compared function candidates, clamped to `1 .. 20000` |
| `--json` | off | Emit `BinaryDiff.to_dict()` instead of the tables |

The human-readable output is a header (left path, right path, `Identical`
yes/no), a `Deltas` table with added/removed/changed counts per kind, a
section/import/export delta table when any exist, and a function-delta table
sorted by address. A difference is the **successful** outcome: the command exits
`0` whether or not the binaries differ, and `2` only on load or input errors.

## Confidence summary

| Result | Source | Confidence | Ceiling because |
|--------|--------|------------|-----------------|
| Jump-table slot and resolution | `jump_table.pointer_array` | `medium` | A pointer array found by shape is evidence of a dispatch table, not proof one is indexed |
| Recursive CFG with resolved tables | `cfg.recursive_traversal` | `medium` | Resolved targets come from those same candidate pointers; unresolved operands still omit edges |
| Structural binary diff | `binary_diff.structural` | `medium` | Metadata comparison only — no bytes, no semantics |

## Limitations

- **Tables are found by shape, not by use.** Nothing proves a dispatcher
  bounds-checks an index and reads the slot you pointed at. The resolver decodes
  what is at the address you gave it; if that address is wrong, the "table" is
  whatever data happens to look like pointers.
- **The stop rule is a hard stop.** The first zero pointer, out-of-window target,
  unmapped target, or non-executable target ends the scan. A table with a data
  pointer in the middle is therefore reported short, with a warning rather than a
  guessed continuation.
- **No relative or counted tables.** Only absolute pointers of exactly 4 or 8
  bytes are decoded. 32-bit relative deltas, hybrid layouts, and tables with a
  count/size prelude are not modelled.
- **Indirect resolution is narrow.** Only `jmp qword ptr [rip + disp]` /
  `jmp qword ptr [abs]` (and their `dword` 32-bit forms) yield a table address.
  `jmp rax`, indexed operands (`jmp qword ptr [rax*8 + ...]`), symbol
  expressions, and indirect *conditional* branches stay unresolved and are
  counted in `warnings`.
- **Resolution budgets are per traversal, not per function.** One graph may spend
  all eight tables on its first branches, after which later dispatch blocks are
  reported as unresolved.
- **The viewer is interactive, not editable.** Pan/zoom move a fixed three-column
  layout; filters hide nodes but not their edges; the edge table is never
  filtered; there is no zoom reset (reload instead), no node dragging, and no
  persistence.
- **The diff is structural.** Sections by name, imports by `(library, name)`,
  exports by name, functions by address then name. A size/flag change under an
  unchanged section name is invisible; a same-name export that moved is
  invisible; instruction bytes, relocations, and behavior are never compared. A
  truncation warning means part of a side was not compared at all.
- **Not exposed over MCP.** There is no `codevanta_jump_table`, no
  `codevanta_diff`, and `codevanta_cfg` takes no `resolve_indirect` argument;
  both new views are library and CLI only.
- **No debugger.** Static analysis only: files are read, never executed, and no
  run-time memory is inspected.

## Next steps

1. Resolve register and indexed dispatch (`jmp rax`, `jmp [rax*8 + table]`) by
   tracking the index register, which needs a small dataflow pass.
2. Support relative and offset-switched tables plus counted layouts, so compiler
   families other than absolute-pointer arrays are covered.
3. Corroborate a table by requiring the dispatcher to load from it, and use that
   to raise corroborated tables above `medium`.
4. Expose `max_jump_tables` / `max_table_entries` on `codevanta cfg` and thread
   `--resolve-indirect` through `codevanta_cfg` for MCP clients.
5. Grow the diff with byte- and function-level comparison (per-function hashes,
   then instruction-level deltas), so `changed` can mean "code changed" instead
   of "metadata changed".
6. Add node dragging, layout persistence, and a zoom-reset control to the viewer
   once the layout stops being a fixed three-column stack.

## Verification

```powershell
python -m pytest
ruff check src tests
```

Jump tables are covered by `tests/test_jump_tables.py` (terminated tables,
`max_entries` truncation, invalid addresses, non-executable targets), indirect
resolution by `tests/test_cfg_recursive.py` (resolved successors, table budgets,
register-operand warnings), the viewer by `tests/test_html_view.py` (inline
script, no `http(s)`, search and filter controls, determinism, escaping), the
diff by `tests/test_binary_diff.py`, and the CLI surface by
`tests/test_cli_phase2f.py`.


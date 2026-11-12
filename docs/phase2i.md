# Phase 2i — Alignment and Array Hints, Function Similarity, Struct over MCP

Phase 2i turns the phase 2h struct-field list into a small layout hint and adds a
second way to compare two regions:

1. **Layout hints** (`analysis/type_recovery.py`): `StructSuggestion` gains
   `alignment` (the greatest common divisor of the reported offsets) and
   `array_groups` (maximal runs of equally wide, equally spaced fields), both
   derived from the fields that are actually reported.
2. **Function similarity** (`analysis/function_hash.py`): `normalized_tokens`
   exposes the token stream the digest hashes, and `function_similarity` scores
   two regions as multisets of those tokens, in `0.0 .. 1.0`.
3. **Struct suggestions everywhere** (`mcp_server/tools.py`,
   `mcp_server/server.py`, `cli/main.py`): `codevanta_struct` joins the MCP
   surface (fourteen tools) and `codevanta struct` prints the alignment and the
   array candidates in its footer.

| Path | What changed |
|------|--------------|
| `src/codevanta/analysis/type_recovery.py` | `ArrayGroup`, `StructSuggestion.alignment`, `StructSuggestion.array_groups`, `_alignment`, `_array_groups`, `_MIN_ARRAY_ELEMENTS` |
| `src/codevanta/analysis/function_hash.py` | `normalized_tokens`, `SimilarityResult`, `function_similarity` |
| `src/codevanta/mcp_server/tools.py` | New `struct(...)` |
| `src/codevanta/mcp_server/server.py` | `codevanta_struct` registered — fourteen tools |
| `src/codevanta/cli/main.py` | `struct` footer gains `alignment:` and one line per array candidate |

Everything here stays static: binaries are read through
`codevanta.core.report.read_code` (bounded by the containing section's file
bytes), never mapped and never executed.

**Status:** in progress. An alignment, an array run and a similarity score are
*hypotheses* about shape, not recovered types and not proven semantic
equivalence. See [Limitations](#limitations).

## Usage

```powershell
# The footer now reports the inferred alignment and any array candidates
codevanta struct samples\elf64_text.bin

# Same analysis with the derived fields in JSON
codevanta struct samples\elf64_text.bin --address 0x401000 --json
```

The same hints come back from Python.

```python
from codevanta.analysis.type_recovery import suggest_struct
from codevanta.core.loader import BinaryLoader

path = "samples/elf64_text.bin"
info = BinaryLoader().load(path)

suggestion = suggest_struct(path, info, 0x401000)
print(suggestion.alignment)  # 8, or None when too few non-zero offsets
for group in suggestion.array_groups:
    print(hex(group.offset), group.count, group.width, group.stride, group.span)
```

Similarity is a library API in this phase — there is no CLI command and no MCP
tool for it.

```python
from codevanta.analysis.function_hash import function_similarity
from codevanta.core.loader import BinaryLoader

loader = BinaryLoader()
left, right = loader.load("samples/elf64_text.bin"), loader.load("samples/elf64_text.bin")

result = function_similarity("samples/elf64_text.bin", left, 0x401000,
                             "samples/elf64_text.bin", right, 0x401000)
print(result.score)      # 0.0 .. 1.0
print(result.shared, result.union)
print(result.warnings)   # a truncated side, if any
```

The same suggestion is available to coding agents through
`codevanta_struct` (see [MCP surface](#mcp-surface-fourteen-tools)).

## Alignment inference

`StructSuggestion.alignment` is the **greatest common divisor of the absolute
values of the reported field offsets**, skipping offset `0`:

| Reported offsets | `alignment` | Why |
|------------------|-------------|-----|
| `0x10`, `0x18`, `0x20` | `8` | `gcd(16, 24, 32) = 8` |
| `0x10`, `0x14` | `4` | `gcd(16, 20) = 4` |
| `0x0`, `0x10`, `0x18` | `8` | offset `0` is ignored |
| `0x10`, `0x11` | `1` | odd offsets collapse the gcd to `1` |
| `-0x8`, `0x10` | `8` | magnitudes are used, so the sign does not matter |
| `0x10` only | `None` | one offset cannot distinguish an alignment from itself |
| no fields | `None` | nothing was observed |

The rule comes from `_alignment`: distinct absolute non-zero offsets are
collected, and `None` is returned whenever fewer than **two** of them exist.
Offset `0` is dropped first because it is a multiple of every candidate
alignment and would therefore contribute nothing.

The result is a divisor of the observed displacements, nothing more. A
power-of-two gcd is what naturally aligned members produce, but a gcd of `8`
does not prove `alignas(8)`, does not prove the struct starts at a multiple of
`8`, and never adds padding or a total size. `1` is the honest answer for an
irregular layout, and `None` is the honest answer for a single offset.

Because the hint is derived from the fields that are **reported**, the
`max_fields` cap can change it: dropping an offset can turn `8` into `4`, or a
value into `None`. `truncated` says whether offsets were dropped, so a capped
suggestion should be re-run with a larger `--max-fields` before its alignment is
trusted.

The suggestion's evidence `extra` map carries the value under `alignment`, and
the detail string appends `, alignment <n>` only when an alignment was derived.

## Array and stride heuristic

`StructSuggestion.array_groups` lists `ArrayGroup` records built by
`_array_groups` over the reported fields, which are already sorted by ascending
offset.

A group is a **maximal run of at least three consecutive fields** (in ascending
offset order) that

- share one **width**, and
- share one **stride** — the distance between each field and the next.

The scan is linear: a run stops at the first width change or at the first stride
change, and is emitted only when it holds at least `_MIN_ARRAY_ELEMENTS = 3`
fields. Two equally spaced fields are treated as a coincidence, because two
points always define a step. When a run is too short the scan restarts at the
next field, so a later run can still begin in the middle of a broken sequence;
a field belongs to at most one group, and no group overlaps another. The result
is deterministic for a given field list.

| Reported fields | Groups |
|-----------------|--------|
| `0x10`/`0x18`/`0x20`, all width `8` | one: offset `0x10`, stride `8`, count `3`, width `8` |
| `0x10`/`0x18`, both width `8` | none — only two fields |
| `0x10`/`0x18`/`0x20` (`qword`,`qword`,`dword`) | none — the run breaks at the width change and the remaining run is too short |
| `0x8`/`0x10`/`0x18`/`0x24` | one: offset `0x8`, stride `8`, count `3` — the last step breaks the run |

Each group serializes as:

```json
{
  "offset": "0x10",
  "stride": 8,
  "count": 3,
  "width": 8,
  "span": 24,
  "evidence": { "...": "..." }
}
```

`offset` is the offset of the first field of the run, `width` is the shared
dominant width in bytes, and the `span` property is
`stride * (count - 1) + width` — the byte range the run covers, not a declared
array size.

Every group carries its own evidence record at `Confidence.MEDIUM`:

| Field | Value |
|-------|-------|
| `source` / `method` | `type_recovery.array_run` / `stride_run_detection` |
| `address` | first access of the run's first field |
| `detail` | names the offset, count, width and stride and states that the run heuristic cannot tell an array from repeated struct members |

The `extra` map carries `offset`, `stride`, `count`, and `width`.

Like alignment, the groups are computed after the `max_fields` cap, so a group
never points at a field that was dropped.

## Function similarity

The phase 2g fingerprint hashes a normalized instruction stream. Phase 2i
exposes that stream and compares two of them.

### Normalized tokens

`normalized_tokens(path, info, address, max_instructions=2000)` returns the
tokens `function_fingerprint` hashes, so
`sha256("\n".join(normalized_tokens(...)))` reproduces the digest. All three
entry points share one private `_sweep`, which is the only place a region is
decoded, so the digest and the tokens can never disagree about which
instructions a region contains or which bounds were applied.

`normalize_instruction` renders one instruction:

1. the mnemonic is lower-cased and kept verbatim — it is the identity;
2. hex literals (`0x401030`, `-0x10`) and bare decimals (`42`, `#-1`) in the
   operands are masked to `#`, so `mov eax, 0x2a` and `mov eax, 0x63` both
   become `mov eax, #`;
3. consecutive masks collapse and whitespace is collapsed, so the result does
   not depend on the disassembler's spacing or on ARM's `#0x1` form.

Registers and names that merely contain digits (`x29`, `dword`, `q3`) are left
intact by the masking patterns. The tokens are never empty: a region with no
decodable instruction raises `AnalysisError` instead of returning `()`.

### The score

`function_similarity(path_a, info_a, address_a, path_b, info_b, address_b,
max_instructions=2000)` counts both token streams with `collections.Counter` and
returns a `SimilarityResult`:

```text
shared = sum((left_counts & right_counts).values())   # sum(min)
union  = sum((left_counts | right_counts).values())   # sum(max)
score  = shared / union
```

That is the Ruzicka (weighted Jaccard) similarity of the two multisets, so:

| Left tokens | Right tokens | `score` |
|-------------|--------------|---------|
| identical multiset | identical multiset | `1.0` |
| `mov eax, #` / `ret` | same two tokens | `1.0` — even when the immediates differed in the binary |
| `nop` | `ret` | `0.0` — nothing shared |
| `nop` / `ret` | `nop` | `0.5` — one of two union occurrences shared |
| `nop` × 2 | `nop` × 1 | `0.5` — multiplicity matters |

`1.0` means both sides hold every token with the same multiplicity. `0.0` means
they share no token. Because the comparison is a multiset overlap, instruction
**order is irrelevant**: a reordered function still scores high, and a function
with the right instructions in the wrong order can score `1.0`.

### Evidence, warnings and serialization

| Item | Value |
|------|-------|
| `source` / `method` | `function_hash.similarity` / `token_multiset` |
| confidence | `MEDIUM`, never higher |
| `address` | the **left** region's start |
| detail | `shared` of `union` occurrences, both side totals, the score to four decimals, and the shape-not-semantics caveat |
| `extra` | `left_address`, `right_address`, `shared`, `left_total`, `right_total`, `union`, `max_instructions`, `left_truncated`, `right_truncated` |

`SimilarityResult.to_dict()` emits `score` **rounded to four decimals**, plus
`shared`, `left_total`, `right_total`, `union` (the property
`left_total + right_total - shared`), `warnings`, and `evidence`.

`warnings` carries one entry per truncated side, for example
`left region 0x401000 was truncated to 2000 instruction(s); the score compares
prefixes`. A truncated comparison is still a comparison of what was decoded, not
of the whole functions.

Neither side may be empty: an empty multiset would produce a meaningless `0.0`
rather than an error, so `function_similarity` raises `AnalysisError` when a side
yields no tokens. Invalid addresses and budgets raise the same error as the
fingerprint.

Work is bounded on both sides: at most `2 * max_instructions` instructions are
decoded and at most `2 * max_instructions * 16` file bytes are read.

Like the digest, the score is a **shape** measure. Numeric literals are masked
before the comparison, so equal scores are not byte equality and different
scores are not a semantic difference. Nothing is executed.

## MCP surface (fourteen tools)

`codevanta_struct` brings the MCP server to fourteen tools. The other thirteen
are unchanged.

| # | Tool |
|---|------|
| 1 | `codevanta_info` |
| 2 | `codevanta_functions` |
| 3 | `codevanta_strings` |
| 4 | `codevanta_disasm` |
| 5 | `codevanta_analyze` |
| 6 | `codevanta_xrefs` |
| 7 | `codevanta_cfg` |
| 8 | `codevanta_callgraph` |
| 9 | `codevanta_diff` |
| 10 | `codevanta_jump_table` |
| 11 | `codevanta_function_hash` |
| 12 | `codevanta_struct` |
| 13 | `codevanta_session_save` |
| 14 | `codevanta_session_list` |

### `codevanta_struct(path, address=None, function=None, max_instructions=2000, max_fields=64, include_stack=False)`

The MCP adapter for `suggest_struct`, and a thin one: it validates the
arguments, loads the binary, resolves the start address, and returns
`StructSuggestion.to_dict()` unchanged.

- **Start address:** `address` wins; otherwise `function`; otherwise the entry
  point (`resolve_target`).
- **Returns:** `address`, `instruction_count`, `field_count`, `max_fields`,
  `truncated`, `include_stack`, `fields`, `alignment`, `array_groups`, and
  `evidence` — the same document `codevanta struct --json` prints.
- **Limits:** `max_instructions` is `1 .. 100000` (the disassembly ceiling),
  `max_fields` is `1 .. 512`; booleans are rejected for every numeric argument,
  and `include_stack` must be a real boolean.
- **Errors:** `AnalysisError` for a missing or non-regular file, a negative or
  non-integer address, an out-of-range limit, a non-boolean flag, an unknown
  function name, or a resolved start outside an executable section.
- **Confidence:** `medium` throughout, inherited from the analysis. The tool
  description states that fields are heuristics from operand shapes, not
  verified types, and that alignment is a gcd of the non-zero offsets while
  `array_groups` lists runs of at least three equally spaced fields.

Similarity is **not** exposed over MCP in this phase: there is no
`codevanta_similarity` tool. `codevanta_function_hash` still returns only the
one-region digest.

## CLI reference

### `codevanta struct`

The options and the field table are unchanged from phase 2h
(`--address`/`-a`, `--function`/`-f`, `--max-instructions`, `--max-fields`,
`--include-stack`, `--json`). The footer gains two layout lines between the
counts and the warnings:

```text
base registers: rdi · fields: 3
instructions: 4 · max fields: 64 · truncated: no
alignment: 8
array at 0x10: 3 x 8-byte, stride 8
```

- `alignment: <n>` prints the derived gcd; when none could be derived it prints
  `alignment: unknown`, which is the `None` case (fewer than two distinct
  non-zero offsets).
- One `array at <offset>: <count> x <width>-byte, stride <stride>` line per
  `ArrayGroup`, in the analysis order (ascending start offset). Offsets use the
  same hex rendering as the table, so a negative offset appears as `-0x8`.
- When no run was found, `arrays: none` replaces the group lines, so the footer
  always says whether an array candidate exists.
- The warning lines are unchanged: the field cap was reached, or no field-shaped
  operand was decoded (the latter also points at `--include-stack`).
- `--json` prints `StructSuggestion.to_dict()`, which now includes `alignment`
  (a number or `null`) and `array_groups` (a list, empty when there is none).
- Load and input errors still exit `2`.

## Confidence summary

| Output | Confidence | Why |
|--------|------------|-----|
| `StructSuggestion` / `SuggestedField` | `medium` | unchanged from phase 2h |
| `ArrayGroup` | `medium` | a repeated width and stride is a run, not a declared array |
| `StructSuggestion.alignment` | `medium` (part of the suggestion) | the gcd of observed offsets is a divisor of the evidence, not a declared alignment; a `None` result is reported as `unknown`/`null` |
| `FunctionFingerprint` / `SimilarityResult` | `medium` | shape, not semantics: literals are masked and nothing is executed |
| `codevanta_struct` | `medium` | the MCP adapter forwards the analysis evidence unchanged |

Nothing in this phase is promoted above `medium`, and no output claims byte or
semantic equivalence.

## Limitations

- **Alignment is a gcd, not a declaration.** It is the greatest common divisor
  of the *reported* absolute non-zero offsets. It cannot distinguish
  `alignas(8)` from a layout that merely happens to be 8-aligned, cannot see
  the alignments of offsets that were never accessed, and cannot recover
  padding, member order or total struct size. `1` and `None` are ordinary,
  honest answers.
- **A field cap changes the hint.** `alignment` and `array_groups` are computed
  after `max_fields`, so raising the cap can add offsets and change both. Read
  `truncated` before trusting either.
- **The array heuristic needs three fields.** Two equally spaced fields are
  never reported. A run also stops at the first width or stride change, so a
  real array that is only partially accessed, or whose elements are touched with
  mixed widths, produces no group. Nothing here recovers element types, an
  element count, or a real length.
- **An array run is not proof of an array.** Three equally wide, equally spaced
  members of a struct look identical to a three-element array; the evidence
  detail says so. Groups also only span fields from the swept window, so a
  longer array appears as a shorter run.
- **Aggregation still ignores the base register.** Offsets from different
  registers share one bucket, so the alignment, the runs and the fields all
  describe the window, not one object.
- **Similarity ignores operand values by construction.** Literals are masked to
  `#`, so two functions that differ only in constants — including security-
  relevant constants — score `1.0`. Different digests and different scores are
  not a semantic difference, and equal ones are not byte equality.
- **Similarity is order-insensitive.** A pure multiset overlap says nothing
  about instruction order, so reordered or duplicated code can score high.
- **Similarity compares bounded prefixes.** Each side is decoded linearly under
  `max_instructions` and the section's file bytes; when a side is cut short — the
  budget ran out, the bytes ended, or trailing bytes would not decode — the score
  covers prefixes only and a warning says so. Linear sweeps also pull in
  neighbouring functions when the start is not a real entry point.
- **Similarity is library-only.** There is no `codevanta similarity` command and
  no MCP tool for it in this phase.
- **Intel syntax only.** A non-Intel binary yields no fields, so it also yields
  no alignment and no array groups.
- **Phase 2 scope otherwise unchanged.** No slot dereferencing, no call
  following, no debugger, and the binary diff remains structural with an opt-in
  shape comparison for address-matched functions only.

## Next steps

- Expose similarity as `codevanta similarity A B --address-a .. --address-b ..`
  and as an MCP tool, reusing `function_similarity` so the caveat travels with
  the score.
- Make the comparison order-sensitive or n-gram based (token shingles, or CFG
  shape) so reordered code no longer scores like identical code.
- Key struct aggregation by base register (and call site) so alignment and runs
  describe one object instead of one window.
- Use the runs to infer element sizes and counts, then padding and a total
  struct size — still at `medium` until corroborated.
- Drive the sweep from the recursive CFG traversal so padding and jump tables no
  longer produce spurious fields, runs or offsets.
- Combine the shape score with the structural diff so `diff --deep` can report a
  similarity per function pair rather than a digest match.
- Corroborate offsets and array runs across functions and against DWARF/PDB
  before considering any confidence above `medium`.

## Verification

```powershell
python -m pytest tests\test_type_recovery.py tests\test_function_hash.py tests\test_mcp_tools.py tests\test_cli_phase2i.py
python -m pytest
ruff check src tests
```

- `tests/test_type_recovery.py` — three evenly spaced qwords yield
  `alignment == 8` and one `ArrayGroup(offset=0x10, stride=8, count=3, width=8)`;
  two fields yield an alignment but no group; a single offset yields
  `alignment is None`; offset `0` is ignored; runs are maximal and split on a
  width change; `to_dict()` carries both keys; both hints are deterministic.
- `tests/test_function_hash.py` — `normalized_tokens` are the hashed strings and
  the digest is unchanged by the refactor; identical regions score `1.0`;
  masked immediates still score `1.0`; disjoint regions score `0.0`; one shared
  token of two scores `0.5`; multiplicity is respected; the evidence is
  shape-based at `medium`; `to_dict()` is JSON-serializable with a rounded
  score; truncation produces a warning; invalid addresses, invalid budgets and
  an empty token multiset raise.
- `tests/test_mcp_tools.py` — the fourteen-tool list plus `codevanta_struct`
  recovering fields from register operands and validating arguments.
- `tests/test_cli_phase2i.py` — the `struct` footer reporting the alignment and
  the array line, `arrays: none` for an irregular layout, and `--json` carrying
  `alignment` and `array_groups`.





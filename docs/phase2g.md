# Phase 2g — Relative Jump Tables, Function Fingerprints, Deep Diff

Phase 2g extends the phase 2f analysis layer in three places:

1. **Relative jump tables** (`analysis/jump_tables.py`): `resolve_jump_table`
   gained `mode="relative"` plus `base_address`, so the same resolver now reads
   position-independent switch tables whose slots are signed 32-bit offsets
   instead of absolute pointers.
2. **Function fingerprints** (`analysis/function_hash.py`, new): a bounded
   SHA-256 digest over a function's *normalized* instruction stream — mnemonics
   and operand shape, with every numeric literal masked.
3. **Deep diff** (`analysis/binary_diff.py`): `deep=True` on `diff_infos` /
   `diff_binaries` compares those fingerprints for address-matched functions and
   reports a content change with both digests. The structural rules themselves
   are untouched.

| Module | What changed |
|--------|--------------|
| `src/codevanta/analysis/jump_tables.py` | `mode="absolute"\|"relative"`, `base_address`, `MODE_RELATIVE`, `RELATIVE_OFFSET_SIZE`, relative evidence labels |
| `src/codevanta/analysis/function_hash.py` | New: `normalize_instruction(...)`, `function_fingerprint(...)`, `FunctionFingerprint` |
| `src/codevanta/analysis/binary_diff.py` | `diff_infos(..., deep=False)`, `diff_binaries(..., deep=False)`, `DEEP_MAX_INSTRUCTIONS`, `MAX_DEEP_FINGERPRINTS`, `FunctionDelta.left_digest` / `right_digest` |
| `src/codevanta/cli/main.py` | `jump-table --mode/--base`, `diff --deep`, digest column, mode/base footer |

Everything here stays static: target files are read through
`codevanta.core.report.read_code` (bounded by the containing section's file
bytes), never mapped and never executed.

**Status:** in progress. Relative tables need an analyst-supplied base, a
fingerprint is a *shape* hash and not semantic equivalence, and deep diff only
adds a content signal for address-matched pairs. See
[Limitations](#limitations).

## Usage

```powershell
# Relative table: 4-byte signed offsets resolved against an explicit base
codevanta jump-table samples\dispatch.bin --address 0x402000 --mode relative --base 0x401000

# Absolute table (default), with an explicit mode in the footer
codevanta jump-table samples\dispatch.bin --address 0x402000 --mode absolute --entries 64 --json

# Deep diff: also compare normalized instruction shapes of address-matched functions
codevanta diff samples\v1.bin samples\v2.bin --deep
codevanta diff samples\v1.bin samples\v2.bin --deep --json
```

The same switches are available in the Python API.

```python
from codevanta.analysis.jump_tables import resolve_jump_table
from codevanta.core.loader import BinaryLoader

path = "samples/dispatch.bin"
info = BinaryLoader().load(path)

# Absolute pointer array (phase 2f behaviour, still the default)
absolute = resolve_jump_table(path, info, 0x402000)

# Signed 32-bit offsets resolved against a base address
relative = resolve_jump_table(
    path,
    info,
    0x402000,
    mode="relative",
    base_address=0x401000,
)
for entry in relative.entries:
    print(hex(entry.target))
```

```python
from codevanta.analysis.function_hash import function_fingerprint

fingerprint = function_fingerprint(path, info, 0x401000)
print(fingerprint.digest, fingerprint.instruction_count, fingerprint.truncated)
```

```python
from codevanta.analysis.binary_diff import diff_binaries

structural = diff_binaries("samples/v1.bin", "samples/v2.bin")
deep = diff_binaries("samples/v1.bin", "samples/v2.bin", deep=True)
for delta in deep.functions_changed:
    print(delta.address, delta.left_digest, delta.right_digest)
```

## Relative jump tables

### Layout

`mode` selects the slot layout and is case-insensitive; `MODES` is
`("absolute", "relative")` and any other value raises `AnalysisError`.

| Mode | Slot width | Decode | Target |
|------|-----------|--------|--------|
| `"absolute"` (default) | `pointer_size` = 4 or 8, `None` picks 8 for a 64-bit binary and 4 for a 32-bit one | unsigned | the stored value |
| `"relative"` | 4 (`RELATIVE_OFFSET_SIZE`), the only accepted width | **signed** 32-bit | `base_address + offset` |

Values are decoded with `info.endianness` in both modes. In relative mode an
explicit `pointer_size` other than 4 raises `AnalysisError`, and `base_address`
is mandatory — omitting it raises `AnalysisError` rather than defaulting to the
table, section or image address. `base_address` must be a non-negative integer;
in absolute mode it is accepted and ignored.

Signed decoding is what makes a table below its base work: with
`base_address=0x401030` the slots `-0x20` and `-0x10` resolve to `0x401010` and
`0x401020`.

### A zero offset is a valid entry

In absolute mode a zero slot is the conventional terminator: the scan stops and
records `zero pointer at index i (0x…) terminates the table`.

In relative mode a zero offset is **not** a terminator and produces no warning.
It is a legitimate delta that resolves to `base_address` itself, so a table whose
first case jumps to the base (or whose case list happens to contain a zero
delta) keeps decoding. Only the shared stop rules below can end a relative
table.

### Stop rules (identical in both modes)

The scan stops at the first slot whose resolved target cannot extend the table:

1. below `min_target`, when supplied;
2. above `max_target`, when supplied (`min_target > max_target` is rejected);
3. a target no section maps;
4. a target inside a non-executable section while `executable_only=True`
   (the default).

`min_target` / `max_target` are always absolute virtual addresses, in both
modes — a relative table is not filtered in offset space. Each stop is recorded
in `JumpTableResult.warnings` with the failing index, the target and the reason,
so a short table is distinguishable from one that hit something unexpected.

These checks are metadata lookups only: resolving a relative table never reads,
maps or executes the code its targets point at.

### Truncation and bounds

- `max_entries` defaults to 256 (`DEFAULT_MAX_ENTRIES`) and is capped at 4096
  (`MAX_ENTRIES`); values outside `1 .. MAX_ENTRIES` raise `AnalysisError`.
- At most `max_entries * pointer_size` bytes are read for the table itself, plus
  one slot-sized peek. The table address must be file-backed by a section before
  anything is read.
- `truncated` is `True` only when the entry ceiling was reached *and* a further
  readable slot is still usable. In absolute mode that means the next slot is a
  non-zero pointer; in relative mode, where no terminator exists, it means
  `base_address + signed(next slot)` passes the same stop rules.
- If the section ends before the requested window, a warning says the scan
  reached the end of the section and the table may be cut off.

### Evidence

Relative records use their own labels so a reader can never mistake a delta for
an address:

| Level | Source | Method |
|-------|--------|--------|
| each entry | `jump_table.relative_offsets` | `signed_offsets` |
| whole table | `jump_table.relative_offsets` | `signed_offsets` |

Entry evidence is pinned to the slot address with detail
`offset #i at 0x… against base 0x… -> 0x…` and `extra` holding `index`,
`target` and `base`. The table-level record reports
`resolved N signed 32-bit offset(s) against base 0x… from 0x…` with `entries`,
`pointer_size: 4`, `truncated` and `base`. `JumpTableResult.pointer_size` is 4
for a relative table.

Absolute mode keeps its phase 2f labels (`jump_table.pointer_array` /
`absolute_pointers`) and byte-identical output — `mode="absolute"` produces the
same `to_dict()` as omitting `mode`, and passing `base_address` in absolute mode
changes nothing. Everything is `Confidence.MEDIUM`: a run of same-width slots
found by shape is evidence of a dispatch table, not proof that a dispatcher
indexes it.

## Function fingerprints

`function_fingerprint(path, info, address, max_instructions=2000)` disassembles
a function with a bounded **linear sweep** starting at `address` and reduces the
result to one SHA-256 digest over its normalized shape.

### Normalization

Each decoded instruction is rendered as `"<mnemonic> <operands>"`:

1. the mnemonic is lower-cased and kept verbatim — it is the instruction's
   identity;
2. every hex literal (`0x401030`, `-0x10`, `+0X1F`) becomes `#`;
3. every bare decimal (`42`, ARM's `#-1`) becomes `#`, with lookarounds so
   register and operand names that merely contain digits (`x29`, `dword`, `q3`)
   survive intact;
4. consecutive masks collapse, so ARM's `#0x1` (`##`) and x86's `0x1` (`#`)
   agree;
5. internal whitespace is collapsed.

Operands only are masked, so `mov eax, 0x2a` and `mov eax, 0x63` both normalize
to `mov eax, #`, and `mov eax, [rbp - 0x10]` and `mov eax, [rbp - 0x8]` render
identically. The masked instructions are joined with `"\n"` and hashed with
SHA-256 (`DIGEST_ALGORITHM = "sha256"`); the digest is lower-case hexadecimal.

### Bounds

- `max_instructions` defaults to 2000 (`DEFAULT_MAX_INSTRUCTIONS`) and is
  accepted in `1 .. 100000` (`MAX_MAX_INSTRUCTIONS`, the shared
  `MAX_DISASSEMBLY_COUNT`); outside that range raises `AnalysisError`.
- The read window is `max_instructions * 16` bytes, further clipped to the
  section's file-backed bytes.
- `truncated` is `True` when the disassembler stopped early, when the
  instruction count reached the budget, or when trailing bytes were left
  undecoded. The digest then covers only a prefix of the function.
- A non-executable address, an address without file bytes, an undecodable
  architecture and a region where no instruction decodes all raise
  `AnalysisError`. An empty stream is deliberately an error instead of an empty
  digest, so undecodable regions cannot all "match" each other.

The sweep is linear and does not follow branches, so bytes belonging to a
neighbouring function are included when `address` is not a real function entry.

### Evidence and what a digest does not mean

`FunctionFingerprint` exposes `address`, `digest`, `instruction_count`,
`truncated`, an `algorithm` property, and evidence with source
`function_hash.normalized`, method `normalized_linear_disassembly` and
`Confidence.MEDIUM`. `extra` records `algorithm`, `max_instructions`,
`instruction_count`, `consumed_bytes` and `truncated`.

A digest is a **shape** fingerprint, so:

- equal digests are **not** byte equality;
- different digests are **not** a semantic difference;
- because immediates and branch targets are masked, calls to two *different*
  callees normalize identically;
- a truncated digest compares prefixes only, so two functions of different
  length can share a digest;
- nothing is executed, and no semantic equivalence is claimed anywhere.

Every evidence record carries that caveat in its `detail` string.

## Deep diff

`diff_infos(..., deep=False)` and `diff_binaries(..., deep=False)` keep the
phase 2f matching rules exactly as they were:

1. same address → same function; `name`/`size` differences make it `changed`
   (discovery `source`/`confidence` are not compared);
2. leftover candidates matched by name, so a relocated function is one
   `changed` entry instead of a removal plus an addition;
3. whatever is left is `removed` on the left and `added` on the right.

`deep=True` adds a content signal on top and changes no structural rule. For
every function that matches **by address**, both sides are fingerprinted with
`function_fingerprint(..., max_instructions=DEEP_MAX_INSTRUCTIONS)` — 2000
instructions, equal to `DEFAULT_MAX_INSTRUCTIONS` so a fingerprint taken during
a diff matches one taken on its own:

- **digests differ** → the entry is `changed`, with the note
  `content changed at 0x…: normalized fingerprints differ (left <digest>, right
  <digest>)` and both digests on the delta;
- **metadata changed, digests equal** → the note says
  `normalized fingerprints match, so this is a metadata-only change`;
- **nothing differs** → no entry, as before.

`FunctionDelta.left_digest` / `right_digest` are always both set or both `None`,
and `to_dict()` exposes them as `left_digest` / `right_digest` only when
present. A content-only change therefore makes `functions_changed` non-empty and
`identical` `False`, which is the one new way a diff can stop being identical.
Functions matched by name after moving, and one-sided functions, are **not**
fingerprinted and keep their structural verdict.

Deep mode is bounded three ways, and every bound that cuts work short is
reported in `warnings`:

| Bound | Value | Effect when exceeded |
|-------|-------|----------------------|
| `max_functions` per side | 5000 default, clamped to `1 .. 20000` | lowest addresses compared, warning issued |
| `MAX_DEEP_FINGERPRINTS` pairs per side | 1000 | only the 1000 lowest addresses fingerprinted, remainder compared structurally |
| `DEEP_MAX_INSTRUCTIONS` per fingerprint | 2000 | digest covers a prefix, counted in a truncation warning |

`diff_infos` never raises for a fingerprint failure: unreadable or undecodable
functions are counted (`N function(s) could not be fingerprinted and were
compared structurally only (first error: …)`) and keep their structural verdict.

In deep mode the top-level evidence `detail` switches to the content caveat
(normalized shapes, masked literals, equal digests are not byte equality), and
`extra` records `deep: true`, `deep_instructions` and `max_deep_fingerprints`.
Per-delta evidence stays `Confidence.MEDIUM`. The whole comparison still only
reads file bytes and executes nothing.

## CLI reference

### `codevanta jump-table`

```text
codevanta jump-table PATH --address ADDR
    [--entries N] [--executable-only/--no-executable-only]
    [--mode absolute|relative] [--base ADDR] [--json]
```

- `--mode` is optional and case-insensitive (`--mode Relative` works). When
  omitted, the command behaves exactly as in phase 2f: absolute layout, and the
  historical footer stays unchanged (no `mode:`/`base:` text).
- `--base` takes a decimal or `0x`-prefixed hex address with the same parser as
  `--address`; an unparsable or negative value exits `2` with
  `invalid base ...`. `--mode relative` without `--base` exits `2`
  (`--mode relative requires --base (e.g. --base 0x401000)`) instead of
  inventing an origin, because every target would otherwise be wrong.
- An unknown `--mode` exits `2` before the file is loaded and lists the accepted
  layouts.
- The index/target table is unchanged. The footer gains `mode: <layout>` when
  `--mode` was given explicitly, and `base: 0x…` in relative mode; the base is
  never printed for an absolute table, and `--base` in absolute mode is parsed
  but ignored by the resolver.
- `--json` emits the resolver's `to_dict()` unchanged, so relative records carry
  `pointer_size: 4` and `jump_table.relative_offsets` / `signed_offsets`
  evidence with the base in the detail and `extra`.

```powershell
codevanta jump-table samples\dispatch.bin --address 0x402000 --mode relative --base 0x401000
codevanta jump-table samples\dispatch.bin --address 0x402000 --mode relative --base 0x401000 --json
codevanta jump-table samples\dispatch.bin --address 0x402000 --no-executable-only
```

### `codevanta diff --deep`

```text
codevanta diff LEFT RIGHT [--max-functions N] [--deep] [--json]
```

- `--deep` passes `deep=True` to `diff_binaries`; without it the command is
  structural-only, exactly as in phase 2f.
- The function-delta table gains a `Digest (left -> right)` column **only when a
  delta actually carries digests**. Cells show the first 12 hex characters of
  each side's SHA-256 joined by ` -> `, and `-` for `added`/`removed` deltas and
  for matched pairs beyond the deep-mode ceiling, which are not fingerprinted.
- A dim footer explains that the digests are the first 12 hex characters of the
  normalized shape SHA-256 and that equal digests are not byte equality.
- `--json` keeps the existing document shape: `left_digest`/`right_digest` appear
  inside `functions_changed` entries, and `evidence.extra.deep` records that the
  mode ran. No new top-level keys are invented.
- Exit codes are unchanged: `0` whether or not the binaries differ, `2` for load
  or input errors.

```powershell
codevanta diff samples\v1.bin samples\v2.bin
codevanta diff samples\v1.bin samples\v2.bin --deep
codevanta diff samples\v1.bin samples\v2.bin --deep --max-functions 20000 --json
```

The fingerprint API (`function_fingerprint`) has no command of its own, and no
MCP tool was added for these features — the MCP surface is unchanged.

## Confidence summary

| Result | Confidence | Why |
|--------|-----------|-----|
| Absolute jump-table entries | `medium` | slot array found by shape; no dispatcher proven |
| Relative jump-table entries | `medium` | same, plus a caller-supplied base that is not verified |
| Function fingerprint | `medium` | normalized shape only; no semantics, truncation possible |
| Structural diff deltas | `medium` | metadata only |
| Deep diff deltas | `medium` | metadata plus masked instruction shapes; still not equivalence |

## Limitations

- **No base inference, in the CLI or the API.** Relative tables need an explicit
  `--base` / `base_address`; nothing derives it from the dispatcher's RIP, the
  table address or the image base, and a wrong base silently yields wrong
  targets that still pass the stop rules. The CFG's opt-in indirect resolution
  also still calls the resolver in absolute mode only, so a relative table
  behind a `jmp [mem]` is not followed by `build_recursive_cfg`.
- **Shape, not proof.** Both table layouts recognise a run of plausible slots;
  neither shows that any code indexes the array, and holes, padding or unrelated
  data that happen to look like targets are indistinguishable from real cases.
- **No target reading during resolution.** Targets are validated against section
  metadata only; a mapped, executable target may still not be a case body.
- **Fingerprints are coarse.** All immediates and branch targets are masked, so
  two functions calling different callees with the same call shape hash equally;
  register allocation differences, instruction reordering and compiler version
  changes all alter the digest even when behaviour is identical.
- **Linear sweep.** Code is decoded from `address` without following control
  flow, so a non-entry address pulls in neighbour bytes and a function longer
  than the budget is fingerprinted from its prefix only.
- **Truncated comparisons.** Two functions can share a digest because only their
  common prefix was decoded; the `truncated` flag is not surfaced per compared
  pair, only counted in `warnings`.
- **Deep diff scope.** Only address-matched pairs are fingerprinted: relocated
  functions (matched by name) and one-sided functions get no content comparison,
  and there is no similarity score, no relocation-aware normalisation and no
  patching.
- **Endianness from the header.** Slot decoding uses `info.endianness`; a table
  stored in the opposite byte order is decoded as garbage, not detected.

## Next steps

- Let `build_recursive_cfg` pass `mode`/`base_address` so recursive traversal can
  follow relative dispatch tables.
- Add base-inference heuristics (dispatcher RIP-relative slot, table address,
  image base) as *candidates with evidence*, never as silent defaults.
- Expose standalone fingerprints on the CLI and add MCP tools for relative
  tables and deep diff — today neither the CLI fingerprint command nor the MCP
  surface covers these features.
- Move fingerprinting from a raw linear sweep to block-level normalization
  (CFG-aware), so padding and neighbouring functions stop contaminating digests.
- Expose per-pair `truncated` in deep-diff output and add an optional similarity
  ratio over normalized instruction streams.
- Compare relocated (name-matched) functions by content once relocation-aware
  normalization exists.
- Cache digests per `(path, address, max_instructions)` and consider MCP tools
  once the CLI surface is stable.

## Verification

```powershell
python -m pytest tests\test_jump_tables.py tests\test_function_hash.py tests\test_binary_diff.py tests\test_cli_phase2g.py
python -m pytest
ruff check src tests
```

- `tests/test_jump_tables.py` — relative layout, zero-offset validity, negative
  offsets, shared stop rules, truncation, evidence labels, absolute-mode output
  unchanged.
- `tests/test_function_hash.py` — normalization and masking, deterministic
  digests, bounds, truncation, error cases, evidence caveat.
- `tests/test_binary_diff.py` — structural rules unchanged, deep-mode digest
  comparison, `left_digest`/`right_digest` exposure, deep bounds and warnings.
- `tests/test_cli_phase2g.py` — `--mode`/`--base` targets, footer and JSON,
  exit code `2` for a missing/`invalid base` and an unknown mode, the unchanged
  default footer, `--deep` digest column and full JSON digests, and the
  structural verdict without `--deep`.






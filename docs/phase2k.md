# Phase 2k — Diff Options over MCP, Cross-Architecture Guard, Merged Struct Windows

Phase 2k closes four gaps left open by phase 2j — the MCP diff could not ask for
the pairing it already supported, a cross-architecture pairing was not refused,
struct evidence from several functions could not be combined, and the CLI could
only look at one window:

1. **Diff options over MCP** (`mcp_server/tools.py`, `mcp_server/server.py`):
   `codevanta_diff` gains `deep`, `semantic`, and `threshold`, so the semantic
   pass is reachable from an agent without a second tool call. The server stays
   at **fifteen** tools — no tool was added or removed.
2. **Cross-architecture guard** (`analysis/binary_diff.py`): semantic pairing is
   skipped, with one warning naming both sides, when the two binaries report
   different identified `BinaryInfo.architecture` tokens (compared after trimming
   whitespace and lower-casing only — see
   [Cross-architecture guard](#cross-architecture-guard)).
3. **Merged struct windows** (`analysis/type_recovery.py`): `suggest_structs`
   folds up to `MAX_MERGED_WINDOWS` (16) windows of one binary into a single
   `StructSuggestion` with one field per offset.
4. **Repeated `--address`** (`cli/main.py`): `codevanta struct --address` is a
   repeatable option, and more than one value routes to `suggest_structs` instead
   of the single-window sweep.

| Path | What changed |
|------|--------------|
| `src/codevanta/mcp_server/tools.py` | `diff(..., deep, semantic, threshold)`, `_check_threshold` |
| `src/codevanta/mcp_server/server.py` | `codevanta_diff` arguments and description — still fifteen tools |
| `src/codevanta/analysis/binary_diff.py` | `_comparable_architecture`, architecture gate in `_semantic_pairs`, `_UNKNOWN_ARCHITECTURE` |
| `src/codevanta/analysis/type_recovery.py` | `suggest_structs`, `MAX_MERGED_WINDOWS`, `MIN_MERGED_WINDOWS`, `WidthConflictWarning`, `WindowOverlapWarning`, `_merge_field`, `_merged_width`, `_merge_window_fields`, `_validate_window_addresses`, `_warn_on_overlapping_windows`, the `window_truncated` evidence key |
| `src/codevanta/cli/main.py` | repeatable `struct --address`, `_struct_evidence_base_registers` (merge footer, evidence-only), `_struct_base_registers` (single window), `_struct_window_text`, the merge wording of `_struct_warnings`, the `windows:` footer line, exit 2 for `--function` / `--max-fields` next to a merge |

Everything here stays static: both diff sides and every merged window are read
through the existing bounded sweeps. Nothing is mapped and nothing is executed.

**Status:** in progress. An MCP diff option, a skip warning and a merged field
set are all *hints about shape and operand use*, not recovered types, not an
equivalence claim, and not a proof that several windows touch one struct. See
[Limitations](#limitations).

## `codevanta_diff` options

`codevanta_diff` now forwards the whole diff contract of
`codevanta.analysis.binary_diff`:

| Argument | Type | Default | Meaning |
|----------|------|---------|---------|
| `left` | `str` | — | Left-hand (baseline) binary; read, never executed |
| `right` | `str` | — | Right-hand (candidate) binary; read, never executed |
| `max_functions` | `int` | `5000` | Per-side ceiling on compared candidates (`1 .. 20000`) |
| `deep` | `bool` | `False` | Also fingerprint address-matched functions |
| `semantic` | `bool` | `False` | Also pair the leftovers by instruction-shape similarity |
| `threshold` | `float` | `0.9` | Smallest similarity score that may pair two leftovers |

`threshold` defaults to `DEFAULT_SEMANTIC_THRESHOLD` (`0.9`) and must be a finite
number in `0.0 .. 1.0` (`MIN_SEMANTIC_THRESHOLD` / `MAX_SEMANTIC_THRESHOLD`). It
is validated in **every** mode: a boolean, a non-numeric value, `NaN`, `inf`, or
an out-of-range value raises `AnalysisError` even when `semantic=False`, so
switching semantic mode on later never changes what the argument means. Only the
two paths are checked before that, so a bad value never costs a binary load.

`deep` and `semantic` must be real booleans. They compose with the phase 2g/2j
rules rather than replacing them: deep mode fingerprints address-matched pairs,
the semantic pass only sees what address and name matching left unpaired, and a
pairing can only turn a remove-plus-add pair into one `changed` entry.

The payload is `BinaryDiff.to_dict()`, unchanged in shape by this phase. With
`semantic=True` the comparison evidence `extra` also carries `semantic`,
`semantic_threshold`, `semantic_instructions`, and `max_semantic_pairs`, and each
paired `changed` entry carries `similarity`.

```python
from codevanta.mcp_server import tools

comparison = tools.diff(
    "samples/v1.bin",
    "samples/v2.bin",
    deep=False,
    semantic=True,
    threshold=0.85,
)
print(comparison["identical"], comparison["warnings"])
```

The server registers the same three arguments:

```text
codevanta_diff(left, right, max_functions=5000, deep=False, semantic=False, threshold=0.9)
```

The tool count is unchanged at **fifteen**: `codevanta_info`, `codevanta_functions`,
`codevanta_strings`, `codevanta_disasm`, `codevanta_analyze`, `codevanta_xrefs`,
`codevanta_cfg`, `codevanta_callgraph`, `codevanta_diff`, `codevanta_jump_table`,
`codevanta_function_hash`, `codevanta_similarity`, `codevanta_struct`,
`codevanta_session_save`, `codevanta_session_list`. `codevanta_similarity` is
still the right tool when an agent wants one score for one address pair;
`codevanta_diff` with `semantic=True` is the tool when the whole comparison
should be paired in one call.

## Cross-architecture guard

A similarity score decodes **both** regions with one instruction set, so a score
is only meaningful when both sides describe the same instruction set. The semantic
pass therefore compares the two sides' `BinaryInfo.architecture` before it
decodes anything.

**What the guard normalises, and what it does not.**
`_comparable_architecture` trims surrounding whitespace, lower-cases the token,
and maps the loader's literal `"unknown"` placeholder to an empty string. That is
the whole contract: there is **no alias table**, so a token is never rewritten to
a canonical spelling. `"X86_64"` and `" x86_64 "` match `"x86_64"`, but a
hand-built `"AMD64"` becomes `"amd64"` and a hand-built `"x86-64"` stays
`"x86-64"`; neither equals `"x86_64"`, so the guard reads them as a *different*
instruction set and skips the whole pass. Only tokens the loader itself produced
compare reliably.

**Which header values become which token.** `BinaryInfo.architecture` is filled
by the loader's per-format helper, which upper-cases the raw header text and
matches substrings. It is not an exhaustive mapping of ELF `e_machine` / PE
`Machine`, and it is not symmetric between the two formats:

| Format | Header text matched | Token |
|--------|---------------------|-------|
| PE | `AMD64`, `X86_64` | `x86_64` |
| PE | `I386`, `I686` | `x86` |
| PE | `AARCH64`, `ARM64` | `aarch64` |
| PE | `ARM` | `arm` |
| PE | `IA64` | `ia64` |
| ELF | `X86_64`, `AMD64` | `x86_64` |
| ELF | `I386`, any text ending in `386` | `x86` |
| ELF | `AARCH64`, `ARM64` | `aarch64` |
| ELF | `ARM` | `arm` |
| ELF | `MIPS` | `mips` |
| both | anything else | `unknown` |

Everything else falls through to `unknown` — and the tables do not cover the same
ground: a PE `MIPS`/`R4000` image and an ELF `IA_64` image both land on `unknown`
because the PE helper has no MIPS branch and the ELF helper has no IA-64 branch.
RISC-V, PowerPC and s390 headers are `unknown` in both formats. Because `unknown`
means "no claim", **two `unknown` sides bypass the guard** and are scored as if
they shared an instruction set.

| Left | Right | Semantic pairing |
|------|-------|------------------|
| `x86_64` | `x86_64` | Runs normally |
| ` X86_64 ` | `x86_64` | Runs — case and surrounding whitespace are folded |
| `x86` | `x86_64` | **Skipped**, one warning names both |
| `arm` | `aarch64` | **Skipped**, one warning names both |
| `AMD64` (hand-built) | `x86_64` | **Skipped** — no alias folding, `amd64` ≠ `x86_64` |
| `x86-64` (hand-built) | `x86_64` | **Skipped** — `x86-64` ≠ `x86_64` |
| `unknown` | anything | Runs — "not determined" is not "a different target" |
| `unknown` | `unknown` | Runs — neither side makes a claim |
| `""` (empty) | anything | Runs — no architecture claim |

An unidentified architecture is normalised to an empty token, so the loader's
`"unknown"` placeholder can never be the reason a pass is refused. When the guard
fires, nothing is decoded and nothing is scored; one warning explains the skip:

```text
semantic matching skipped: the two sides target different architectures
(left x86, right x86_64), so their instruction shapes are not comparable;
every leftover keeps its added/removed verdict
```

The gate runs **before** the `MAX_SEMANTIC_PAIRS` ceiling, so a cross-architecture
comparison produces that one warning instead of stacking a pair-cap notice on top
of it. It runs **after** the "is there anything to pair" early return, though:
`_semantic_pairs` returns immediately when either side has no leftover, so a
cross-architecture diff in which one side has nothing unpaired emits **no warning
at all** — the skip is silent, and only the ordinary structural deltas show that
nothing was paired. The warning is therefore a report about a skipped pairing
attempt, not a guarantee that every cross-architecture library pair is announced.

The guard affects only the semantic pass:

* address and name matching are unchanged, so structural deltas, `identical`, and
  every section/import/export delta are exactly what they were;
* `deep=True` is unaffected — fingerprints are taken per side and never compared
  across instruction sets;
* every leftover keeps its `added` or `removed` verdict, so the guard narrows the
  report rather than inventing one.

## Merged struct windows

`suggest_structs(path, info, addresses, max_instructions=2000,
include_stack=False, max_windows=MAX_MERGED_WINDOWS)` decodes each address once
with the same budget and stack policy as `suggest_struct`, then folds the
per-window fields into **one field per offset**.

```python
from codevanta.analysis.type_recovery import suggest_structs

suggestion = suggest_structs(
    "samples/app.exe",
    loaded_info,
    [0x401000, 0x401120, 0x401540],
    max_instructions=500,
)
for field in suggestion.fields:
    print(hex(field.offset), field.width, field.read_count, field.write_count)
```

### Bounds

| Argument / limit | Range | Notes |
|------------------|-------|-------|
| `addresses` | non-empty collection of `int` | Each must be inside an executable section of `path` |
| `max_windows` | `MIN_MERGED_WINDOWS` (1) .. `MAX_MERGED_WINDOWS` (16) | Defaults to `MAX_MERGED_WINDOWS` |
| `max_instructions` | `MIN_MAX_INSTRUCTIONS` (1) .. `MAX_MAX_INSTRUCTIONS` | Per window, never raised |
| `include_stack` | `bool` | Window-wide, not per address |
| Reported offsets | `DEFAULT_MAX_FIELDS` (64) | The merge cap; there is no `max_fields` argument |

The work is bounded four ways: at most `max_windows` windows, one decode of at
most `max_instructions` instructions per window, at most `DEFAULT_MAX_FIELDS`
reported offsets per window, and therefore at most
`max_windows * max_instructions` decoded instructions in total.

The two caps interact, but they are not the same cap. Every window keeps its own
**lowest** 64 offsets, and the merge keeps its own lowest 64, so an offset a
window dropped can never be one the merge reports: dropping it means the window
reported 64 lower offsets, which fill the merged cap before the dropped one is
reached. That is exactly why a window's own truncation is surfaced separately
instead of being assumed away — the merged suggestion's `truncated` flag is the
**OR** of the merge cap and every window cap (a window that hit its own field cap
makes the merged `truncated` `True` even when the merge itself dropped nothing),
and `evidence.extra.window_truncated` lists the addresses of the windows that hit
theirs.

### Address validation

The address list is validated before anything is decoded, so a bad call costs no
reads:

| Input | Result |
|-------|--------|
| Not a collection, or a `str`/`bytes` | `AnalysisError: addresses must be a collection of integers` |
| Empty | `AnalysisError: addresses must contain at least one window address` |
| A non-`int` entry (including `"0x401000"`) | `AnalysisError: address must be an integer` |
| A negative entry | `AnalysisError: address must be non-negative` |
| A repeated address | `AnalysisError: window address 0x... appears more than once` |
| More than the limit (or `max_windows` lowered) | `AnalysisError: too many window addresses (limit N)` |
| `max_windows = 0` / `max_windows > 16` | `AnalysisError: max_windows must be >= 1` / `max_windows too large` |

A duplicate is rejected rather than deduplicated because a second decode of the
same address would only double-count its evidence. Addresses are then sorted, so
the result — including the order of the warnings raised during the merge — is
identical for any permutation of the same address set.

### Merge rules

| Property | Rule |
|----------|------|
| Field identity | One merged field per offset; offsets visited in ascending order |
| `read_count` / `write_count` | Sum over the windows that saw the offset |
| `first_access` | Earliest access any window recorded (`None` when no window had one) |
| `width` | **Widest** per-window width; `WidthConflictWarning` when the windows disagree |
| `signed` | Folded like one window, but an intra-window contradiction survives the merge: consistent hints → `True`/`False`, no surviving hint → `None`, contradiction → `None` + `SignednessConflictWarning` |
| `alignment` | Recomputed from the **merged** fields (gcd of the absolute non-zero offsets, `None` below two distinct ones) |
| `array_groups` | Recomputed from the merged fields, so a stride that only spans two windows is still reported |
| `truncated` | **OR** of the merge cap and every window cap: `True` when the merge dropped offsets above `DEFAULT_MAX_FIELDS` **or** any window hit its own 64-offset cap |
| `window_truncated` | Evidence key: addresses of the windows that hit their own field cap |
| `address` | The **lowest** merged address |
| `instruction_count` | Sum over all windows |
| `max_fields` | Always `DEFAULT_MAX_FIELDS` (64) |

A wider access is stronger evidence than a narrower one — seeing a `qword` proves
at least eight bytes, seeing a `dword` elsewhere proves nothing against it — so
the widest width wins and the disagreement is reported instead of resolved
silently:

```text
offset 0x10 is accessed with different widths (4-byte, 8-byte); keeping the
widest, 8 byte(s)
```

`WidthConflictWarning` is raised once per conflicting offset, not once per window
pair. Signedness follows the single-window rule on the *surviving* per-window
hints (`signed is not None`), with one deliberate exception: a contradiction that
already happened **inside** one window is not dropped just because another window
only hinted one way. Each per-window field records `signed_conflict` in its
evidence, and `_merge_field` checks it — so when any window that saw the offset
contradicted itself, the merged `signed` stays `None` and the merge raises its own
`SignednessConflictWarning` for that offset (provided at least one window left a
hint to compare against; a purely hint-free offset stays `None` silently). Two
windows disagreeing *with each other* warn the same way, so an offset is reported
as `signed: None` with `signed_conflict: True` in the merged field evidence in
both cases.

### Overlapping windows

Duplicate addresses are rejected, but a **partial** overlap is allowed: decoding
further into the same function is a legitimate second window. When a window's
start lies inside its predecessor's decode, `WindowOverlapWarning` names both, and
the shared instructions are counted by **both** windows. The merged
`read_count`/`write_count` are therefore per-window sums that can exceed the number
of distinct accesses in the binary, and `memory_access_count` over-counts the same
way. The merge is not additive over overlapping windows — only a set of
non-overlapping windows is.

The check is pairwise and adjacent: in sorted order each window is compared with
the one before it (`start < previous_start + decoded_bytes`), so overlapping
neighbours are always announced, while a window nested inside an *earlier*, wider
window stays silent when the window in between ended before it. `WindowOverlapWarning`
is a `UserWarning`, not an error: nothing is refused, re-decoded or de-duplicated.

### Result and evidence

The result is an ordinary `StructSuggestion`, so `to_dict()` and the CLI printer
already understand it. The merge is identifiable from its evidence rather than
from a new key:

| Record | `source` / `method` | `extra` |
|--------|---------------------|---------|
| Suggestion | `type_recovery.merged_suggestion` / `window_merge` | `window_count`, `windows`, `max_windows`, `max_instructions`, `max_fields`, `instruction_count`, `memory_access_count`, `field_count`, `truncated`, `window_truncated`, `include_stack`, `alignment`, `array_group_count` |
| Field | `type_recovery.merged_field` / `window_merge` | `offset`, `width`, `widths`, `read_count`, `write_count`, `signed`, `signed_conflict`, `window_count` |

Both stay at `Confidence.MEDIUM`, and both details carry the heuristic caveat.
`suggest_structs` with a single address reproduces the `suggest_struct` fields,
alignment and array groups for that window, and a merge of **non-overlapping**
windows is a strict union of what each window reported. It is not "lossless" in a
stronger sense:

* overlapping windows double-count their shared instructions, so the counters are
  upper bounds (see [Overlapping windows](#overlapping-windows));
* `truncated` is a single boolean, so it says that *something* was capped, not
  which offsets were dropped or by whom — `window_truncated` names the windows but
  not the offsets;
* `width` keeps the widest per-window value, and `signed = None` erases which
  mnemonics produced the contradiction.

The base registers are **not** carried into the merged evidence at all, as the CLI
section notes.

## CLI: repeated `--address`

`codevanta struct` now takes `--address` / `-a` **repeatedly**:

```text
codevanta struct PATH [-a ADDR]... [--function NAME] [--max-instructions N]
                       [--max-fields N] [--include-stack] [--json]
```

| Addresses given | Path taken |
|-----------------|------------|
| none | `resolve_target` picks the entry point (or `--function`) and one `suggest_struct` window is swept |
| one | the single-window `suggest_struct` sweep, output exactly as in phase 2i/2j |
| two or more | `suggest_structs` merges the windows; the whole `--address` list is validated first |

Every value is parsed with the CLI's existing address parser, so decimal and
`0x`-prefixed hex both work and a negative or unparsable value exits 2 before any
file is loaded. The window count is bounded by `STRUCT_MAX_WINDOWS`
(`MAX_MERGED_WINDOWS`, 16), and the address set is sorted before decoding, so the
output is identical for any order of the same addresses.

```powershell
codevanta struct samples/app.exe -a 0x401000 -a 0x401120 -a 0x401540
```

The merged run prints the same `Offset`/`Width`/`Reads`/`Writes` table as a single
window, one extra footer line naming the windows, and then the usual layout,
`signed:` and `warning:` lines:

```text
windows: 3 (0x401000, 0x401120, 0x401540)
alignment: 8
arrays: none
signed: 0x10 signed
```

Two options describe one window, so a merge rejects them instead of ignoring
them — both exit 2:

| Combination | Message |
|-------------|---------|
| more than one `--address` **and** `--function` | `--function names one start; give either --function or the --address windows, not both` |
| more than one `--address` **and** a non-default `--max-fields` | `--max-fields applies to a single --address; the merged sweep keeps at most 64 fields` |

The default `--max-fields` value (64, `STRUCT_MAX_FIELDS`) is accepted next to a
merge because it equals the merge cap the analysis layer applies anyway. A
duplicated address, more than 16 addresses, or an address outside an executable
section also exits 2, with the `AnalysisError` text from the analysis layer.

`--json` is unchanged in shape: it prints `StructSuggestion.to_dict()`, and a
merged run is recognisable from `evidence.source` (`type_recovery.merged_suggestion`,
against `type_recovery.struct_suggestion` for a single window) and
`evidence.extra.window_count` / `evidence.extra.windows`.

Three consequences worth knowing before relying on a merged result:

* The `base registers:` footer of a merge is **not** derived from the windows: a
  merge does not decode anything a second time. The CLI reads the registers out of
  the evidence the merge already produced (`_struct_evidence_base_registers`), and
  the phase 2k analysis layer records no `base_registers` key there, so the footer
  prints `base registers: not recorded by the merge` instead of a register list
  and instead of a phantom `-`. Compare the single-window path, which re-sweeps its
  one window (`_struct_base_registers`) and really does name the registers.
* A truncated merge is told to **split the windows**, not to raise `--max-fields`:
  the merged run prints `field cap reached: the merged sweep keeps at most 64
  offsets, so split the windows into separate runs to see the remaining offsets`.
  Only the single-window path keeps the `raise --max-fields` hint, because only
  that path honours the flag.
* `codevanta_struct` (MCP) still takes a single `address`/`function`, so an agent
  cannot ask for a merge — it must call `suggest_structs` in its own Python code.
  The `codevanta_struct` MCP description also still says fields carry no
  signedness, as noted in phase 2j; the payload it returns does.

## Limitations

* The guard compares one token, and only fires when **both** sides are identified.
  An `unknown`/empty architecture on either side silently permits a
  cross-architecture score — that is a deliberate "no claim" reading, not a
  verified match.
* Only case and surrounding whitespace are normalised. `AMD64`, `x86-64`,
  `amd64` and `X86_64` are four different tokens as far as the guard is concerned,
  and only the last one matches a loader-produced `x86_64`. Hand-built
  `BinaryInfo.architecture` values therefore have to use the loader's own spelling.
* Several realistic headers never reach a token: PE `MIPS`/`R4000` and ELF
  `IA_64`/`RISCV`/`PPC64`/`s390` all become `unknown`, and two `unknown` sides
  bypass the guard entirely.
* The guard sits after the "nothing left to pair" early return, so a
  cross-architecture diff with an empty leftover on either side produces **no**
  skip warning at all — the pass was already a no-op for a different reason.
* A skip is all-or-nothing for the whole comparison: when the guard fires, no
  leftover on either side is paired, so a mixed-architecture comparison gets no
  pairings at all instead of partial ones.
* `codevanta_diff` forwards the pairing but explains nothing beyond the existing
  evidence keys. A similarity is still not proof that two functions are the same
  code, and masked literals mean an unrelated function with the same instruction
  mix can score `1.0`.
* Merged fields come from **one binary** and one offset bucket per displacement.
  Different base registers share a bucket (phase 2h), and merging windows
  amplifies that: two unrelated structs reached through `rdi` in two functions
  land in the same merged field.
* Overlapping windows are announced, not refused: `WindowOverlapWarning` names the
  two starts, but the shared instructions are still counted twice, so merged
  counters and `memory_access_count` are upper bounds rather than totals.
* The widest width is a lower bound on the bytes touched, never the true field
  size; the warning says that widths disagreed, not which one is correct.
* The merge cap is fixed at `DEFAULT_MAX_FIELDS`. A caller cannot raise it — the
  CLI refuses a non-default `--max-fields` next to a merge rather than lowering it
  silently — and `truncated` only says something was capped, not which offsets.
  `window_truncated` names the windows that hit their own cap, still without
  naming the dropped offsets, and the merged run's hint points at splitting the
  windows rather than at `--max-fields`.
* `WidthConflictWarning`, `SignednessConflictWarning` and `WindowOverlapWarning`
  are process-level `UserWarning`s, the first two raised per offset and the third
  per overlapping window start, so a caller that does not filter them sees them on
  stderr, and a caller that does must catch them to learn which offsets or windows
  were involved.
* One bad window fails the whole merge: every address must be inside an executable
  section and decodable, because the merge refuses to report a partial picture
  silently.
* Still no type names, no padding or struct-size inference, no cross-binary type
  merging (merged windows stay inside one binary), no byte-level or semantic
  equivalence claim, and no debugger.

## Next steps

* Add an `addresses` argument to `codevanta_struct` (MCP) under the same
  `MAX_MERGED_WINDOWS` bound, so an agent reaches the merge the CLI and the API
  already have.
* Let `--max-fields` tune a merge instead of refusing it, and name the dropped
  offsets when `truncated` is set.
* Expose per-window contributions per offset (which window proved the widest
  width), so a merged field can be audited without re-running each window.
* Consider a tolerant mode that pairs across `x86`/`x86_64` explicitly, naming the
  two tokens in the deltas, instead of refusing the whole pass.

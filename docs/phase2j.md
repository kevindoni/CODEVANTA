# Phase 2j — Semantic Diff Pairing, `codevanta_similarity`, Signedness Hints

Phase 2j connects the phase 2i pieces so leftovers stop being reported as a
remove-plus-add pair, and so a field offset can carry one extra label:

1. **Semantic diff** (`analysis/binary_diff.py`): `diff_infos` / `diff_binaries`
   gain `semantic=False` and `threshold=DEFAULT_SEMANTIC_THRESHOLD` (0.9). The
   functions that address and name matching left unpaired are scored with
   `function_similarity` and the best pairs become `changed` entries carrying
   that `similarity`.
2. **Function similarity over MCP** (`mcp_server/tools.py`,
   `mcp_server/server.py`): `codevanta_similarity` exposes
   `function_similarity` to coding agents, bringing the server to fifteen tools.
3. **Signedness hints** (`analysis/type_recovery.py`): `SuggestedField` gains
   `signed`, derived from the mnemonics of the accesses recorded at one offset.
4. **CLI parity** (`cli/main.py`): `codevanta diff` takes `--semantic` and
   `--threshold`, and `codevanta struct` prints a `signed:` footer line.

| Path | What changed |
|------|--------------|
| `src/codevanta/analysis/binary_diff.py` | `diff_infos`/`diff_binaries` `semantic` + `threshold`, `_semantic_pairs`, `_SemanticRequest`, `FunctionDelta.similarity`, `DEFAULT_SEMANTIC_THRESHOLD`, `MIN_SEMANTIC_THRESHOLD`, `MAX_SEMANTIC_THRESHOLD`, `MAX_SEMANTIC_PAIRS`, `SEMANTIC_MAX_INSTRUCTIONS` |
| `src/codevanta/analysis/type_recovery.py` | `SuggestedField.signed`, `_signedness`, `_resolve_signedness`, `SignednessConflictWarning`, `_SIGNED_MNEMONICS`, `_UNSIGNED_MNEMONICS` |
| `src/codevanta/mcp_server/tools.py` | New `similarity(...)`, `_check_side_address` |
| `src/codevanta/mcp_server/server.py` | `codevanta_similarity` registered — fifteen tools |
| `src/codevanta/cli/main.py` | `diff --semantic` / `--threshold` with a `semantic pair` detail line, `struct` footer `signed:` line |

Everything here stays static: both files are read through the bounded sweep in
`codevanta.analysis.function_hash`, never mapped and never executed.

**Status:** in progress. A pairing and a `signed` value are *hints about shape*,
not recovered types and not an equivalence claim. See
[Limitations](#limitations).

## Semantic diff

`semantic=True` adds one more matching pass; it does not change any existing
rule. Matching still runs in this order:

1. **By address** — same virtual address means same function, and a metadata
   difference makes the entry `changed`.
2. **By name** — a function that moved is one `changed` entry with both
   addresses.
3. **By similarity** (`semantic=True` only) — the candidates both earlier passes
   left unpaired are scored with `function_similarity` (the multiset overlap of
   normalized instruction shapes, `shared / union` in `0.0 .. 1.0`).
4. **Everything still left over** is `removed` on the left and `added` on the
   right.

A similarity match can therefore only turn a remove-plus-add pair into one
`changed` entry: it never overrides an address or name match, and it never hides
a one-sided function.

```python
from codevanta.analysis.binary_diff import diff_binaries

structural = diff_binaries("samples/v1.bin", "samples/v2.bin")
semantic = diff_binaries("samples/v1.bin", "samples/v2.bin", semantic=True)

for delta in semantic.functions_changed:
    print(hex(delta.address), delta.change, delta.similarity)
```

### Pairing rule

* Every leftover cross pair is scored: `len(left_leftovers) * len(right_leftovers)`
  calls to `function_similarity`, each bounded by `SEMANTIC_MAX_INSTRUCTIONS`
  instructions per side (equal to `DEFAULT_MAX_INSTRUCTIONS`, 2000, so a score
  taken during a diff matches one taken on its own).
* The pairs are sorted by descending score, with ties broken by the left address
  then the right address.
* They are taken greedily, highest score first, while the score is at least
  `threshold` and neither candidate has been used yet. One candidate never
  appears in two deltas, and the same inputs always produce the same pairing.
* The threshold comparison and the ordering use the **unrounded** score; only
  the reported value is rounded to four decimals.
* Each accepted pair becomes one `changed` delta reported at the **right-hand**
  address, with `similarity` set, both metadata snapshots attached, and a detail
  naming the score, the threshold, both addresses, and the fact that a score is
  not proof that the two functions are the same code.

`FunctionDelta.similarity` stays `None` — and is omitted from `to_dict()` — on
every structurally matched delta, including a name-matched relocation, because
those were never scored.

### Bounds and warnings

| Bound | Value | When it cuts work short |
|-------|-------|-------------------------|
| `MAX_SEMANTIC_PAIRS` | 4096 | The leftover cross product is larger, so **nothing** is scored: one warning names the pair count, and every leftover keeps its `added`/`removed` verdict |
| `SEMANTIC_MAX_INSTRUCTIONS` | 2000 per side | A pair is scored on the decoded prefix only; the number of such pairs is summarised in one warning |
| `max_functions` | 5000 per side (1..20000) | Candidates above the ceiling are dropped before any mode runs, with the phase 2f truncation warning |

A pair that cannot be scored at all — unreadable file, address outside an
executable section, undecodable architecture, or a side that yields no tokens —
is **skipped rather than raised**, so one bad candidate never loses the whole
comparison; the failed count and the first error are reported in one warning.

### Threshold validation

`threshold` is validated in **every** mode, not only with `semantic=True`, so a
caller never gets a silently ignored value that would behave differently the
moment semantic matching is switched on. It must be a finite number in
`0.0 .. 1.0` (`MIN_SEMANTIC_THRESHOLD` / `MAX_SEMANTIC_THRESHOLD`); a boolean, a
string, `NaN`, or an out-of-range value raises `AnalysisError`.

### Evidence

The comparison keeps one evidence record. In semantic mode its caveat changes
from the structural one to a statement that the result is structural metadata
plus normalized instruction-shape similarity, that numeric literals were masked
to `'#'`, that a pairing is a shape overlap and not proof that two functions are
the same code, and that nothing was executed. `extra` gains `semantic: True`,
`semantic_threshold`, `semantic_instructions`, and `max_semantic_pairs`.
Structural mode is unchanged: no semantic key appears in its evidence and every
phase 2f/2g rule still applies.

`deep=True` and `semantic=True` can be combined. Deep mode fingerprints
address-matched functions; the semantic pass handles what address and name
matching left over, so the two signals never describe the same delta.

## `codevanta_similarity` and the fifteen MCP tools

`codevanta_similarity` takes `path_a`, `address_a`, `path_b`, `address_b`, and
`max_instructions=2000`. It reads both regions with the same bounded linear sweep
as `codevanta_function_hash`, masks numeric literals to `#`, and returns
`SimilarityResult.to_dict()`:

| Key | Meaning |
|-----|---------|
| `score` | `shared / union`, rounded to four decimals, in `0.0 .. 1.0` |
| `shared` | Shared token occurrences (`sum(min)` of the two multisets) |
| `left_total`, `right_total` | Token occurrences per side |
| `union` | Union size (`sum(max)`) |
| `warnings` | One note per truncated side — only prefixes were compared |
| `evidence` | `function_hash.similarity` / `token_multiset` at `medium` confidence |

Addresses must be non-negative plain integers (the error names the offending
side — `address_a` or `address_b`), `max_instructions` must be within
`1 .. 20000`, and both files must exist; anything else raises `AnalysisError`.
The score is shape evidence: `1.0` means the two sides share every token with
the same multiplicity — which a relocated or recompiled copy usually does, and
structurally similar but unrelated code can too — and `0.0` is not proof of
different behaviour.

The server exposes **fifteen** tools:

| # | Tool | Backing API |
|---|------|-------------|
| 1 | `codevanta_info` | `codevanta.core.loader` |
| 2 | `codevanta_functions` | `discover_functions` |
| 3 | `codevanta_strings` | string extraction |
| 4 | `codevanta_disasm` | Capstone disassembly |
| 5 | `codevanta_analyze` | `codevanta.core.report` |
| 6 | `codevanta_xrefs` | `find_xrefs` |
| 7 | `codevanta_cfg` | `build_cfg` / `build_recursive_cfg` |
| 8 | `codevanta_callgraph` | `build_call_graph` |
| 9 | `codevanta_diff` | `diff_binaries` |
| 10 | `codevanta_jump_table` | `resolve_jump_table` |
| 11 | `codevanta_function_hash` | `function_fingerprint` |
| 12 | `codevanta_similarity` | `function_similarity` |
| 13 | `codevanta_struct` | `suggest_struct` |
| 14 | `codevanta_session_save` | session storage |
| 15 | `codevanta_session_list` | session storage |

`codevanta_diff` still exposes only `max_functions` and `deep`: the semantic pass
has no MCP argument yet, so an agent that wants a pairing must call
`codevanta_similarity` on the addresses it cares about.

## Signedness hints

`SuggestedField.signed` is a reading of the **mnemonics** that touched an offset
in the decoded window. It is not a declared type.

### Mnemonic sets

| Hint | Mnemonics | Reason |
|------|-----------|--------|
| `signed=True` | `movsx`, `movsxd`, `sar`, `idiv`, `imul` | The result is sign-extended from the operand, or signed arithmetic is done on it |
| `signed=False` | `movzx`, `shr`, `div`, `mul` | The result is zero-extended from the operand, or unsigned arithmetic is done on it |
| no hint (`None`) | everything else (`mov`, `add`, `cmp`, ...) | The mnemonic says nothing about signedness |

A hint only applies to the memory accesses the instruction actually makes. The
implicit-operand sign-extension mnemonics (`cbw`, `cwd`, `cdq`, `cqo`) take no
operand at all, so they cannot label a field and belong to neither set.

### Aggregation per offset

Hints are collapsed exactly like widths are, over all accesses recorded at one
offset:

| Hints recorded | `signed` |
|----------------|----------|
| Every hint `True` | `True` |
| Every hint `False` | `False` |
| No hint at all | `None` — no evidence |
| Both kinds | `None` **plus** one `SignednessConflictWarning` naming the offset |

A contradiction and an unclassified offset both end up as `None`, but they are
not the same thing: the contradictory offset is announced once through
`SignednessConflictWarning` (a `UserWarning`, so callers that do not care about
signedness can ignore it and callers that do can filter on it).

```python
from codevanta.analysis.type_recovery import SignednessConflictWarning, suggest_struct

fields = suggest_struct(path, info, 0x401000).fields
for field in fields:
    print(hex(field.offset), field.width, field.signed)  # True / False / None
```

### `None` semantics

`None` means **"no signedness evidence"**, never "safe", never "unknown integer
type", and never "unsigned". A sign-extending *read* does not prove the field
stores a signed integer — it proves only that this instruction widened the value
with sign extension. The same holds on the write side: `movzx` into a field says
nothing about how that field is later interpreted.

### Where it shows up

* `SuggestedField.signed` and `SuggestedField.to_dict()` — the key `signed` is
  **omitted entirely** when the hint is `None`, so the JSON of an unclassified
  field stays byte-identical to the phase 2i output (an unknown hint is an absent
  key, not `"signed": null`).
* The field's evidence detail names the hint (`signedness signed`,
  `signedness unsigned`, or `signedness unknown`) next to the offset, width and
  access counts, and `evidence.extra["signed"]` holds the same value — including
  `None` there, where JSON renders `null`.

## CLI

`codevanta diff` gained `--semantic` and `--threshold`, and `codevanta struct`
closes its footer with a `signed:` line. Neither change touches the tables: no
`Similarity` column and no `Signed` column are added.

```powershell
codevanta diff   samples\v1.bin samples\v2.bin --semantic
codevanta diff   samples\v1.bin samples\v2.bin --semantic --threshold 0.75 --json
codevanta struct samples\elf64_text.bin --address 0x401000
```

### `diff --semantic` / `--threshold`

* `--semantic` turns the pairing pass on for this run; without it the command
  stays structural, so a relocated function is still one `removed` plus one
  `added` row.
* `--threshold` defaults to `0.9` and is validated **before either binary is
  loaded**: a value outside `0.0 .. 1.0`, `nan`, or `inf` prints
  `error: invalid threshold ...; expected a number within 0.0 .. 1.0` and exits
  `2`. It is checked even when `--semantic` is off, because a silently ignored
  value would change behaviour the moment semantic matching is switched on.
* The function delta table keeps its columns (`Address`, `Name`, `Change`, plus
  `Digest` only when `--deep` produced digests). Each pair is reported as one
  dim detail line printed after the table:

  ```text
  semantic pair 0x401000 -> 0x401010 (<unknown>): similarity 1.0000
  pairs are decoded instruction-shape overlaps, not proof the functions are the same code
  ```

  The score keeps four decimals, matching `FunctionDelta.similarity` and the JSON
  report, so the text and the payload cannot disagree.
* The exit code is `0` whether or not the binaries differ, and `2` on load or
  input errors — now including an `AnalysisError` raised by the analysis layer.
* `--json` is unchanged except that `functions_changed` entries carry
  `similarity` and `evidence.extra` carries `semantic`, `semantic_threshold`,
  `semantic_instructions`, and `max_semantic_pairs`.

### `struct` signed footer

`codevanta struct` accepts `--address`, `--function`, `--max-instructions`,
`--max-fields`, `--include-stack`, and `--json`. It still prints four columns
(`Offset`, `Width`, `Reads`, `Writes`) and then, in this order, the base registers
and field count, the instruction count with `max fields` and `truncated`,
`alignment:` (or `alignment: unknown`), one `array at 0x..: N x W-byte, stride S`
line per array candidate (or `arrays: none`), the new `signed:` line, and finally
one `warning:` line per limitation.

```text
alignment: 8
arrays: none
signed: 0x10 signed, 0x18 unsigned
```

Only offsets that carry a hint are listed, in table order, as
`<offset> signed` or `<offset> unsigned`; a suggestion whose mnemonics never
hinted anything prints `signed: none`, which means *no signedness evidence* —
never "safe". Contradictory offsets are already collapsed to `signed=None` by the
analysis layer, so they are absent from the line and announced through their
warning instead. `--json` carries the same values as the per-field `signed` key.

## Limitations

* A similarity pairing is a **shape overlap**, not proof that two functions are
  the same code. Masked literals and an order-insensitive multiset mean a
  recompiled copy usually scores `1.0`, and an unrelated function with the same
  instruction mix can too.
* Pairing is greedy, so a globally better assignment can be missed: once the
  highest-scoring pair is taken, its two candidates are unavailable.
* The `MAX_SEMANTIC_PAIRS` ceiling is all-or-nothing. Above it the pass is
  skipped for the whole comparison rather than sampled, so a large diff gets no
  pairings at all.
* Scores only cover the decoded prefix of each side (`SEMANTIC_MAX_INSTRUCTIONS`
  per side), and the pass only sees candidates inside the `max_functions`
  windows.
* A pairing moves a delta from `removed`/`added` to `changed`; it never flips
  `identical` to `True`, because a `changed` entry is still a delta.
* `codevanta_diff` has no `semantic` / `threshold` argument yet, so an MCP client
  gets pairing only by calling `codevanta_similarity` per address pair.
* `signed` is a mnemonic hint from one bounded window. Different base registers
  share one offset bucket, so two unrelated structs can contribute contradicting
  hints, and a lost hint (`None`) looks like a contradiction in the payload — only
  the warning tells them apart.
* `SignednessConflictWarning` is a process-level Python warning raised once per
  contradicting offset, so a caller that does not filter it sees it on stderr.
* The `codevanta_struct` MCP description still says fields carry no signedness;
  the payload it returns does (`signed`, when known).
* Still no type names, no padding or struct-size inference, no cross-function
  merging, no byte-level or semantic equivalence claim, and no debugger.

## Next steps

* Add `semantic` / `threshold` arguments to `codevanta_diff`, so an MCP client
  reaches the same pairing the CLI and the API do.
* Sample the `MAX_SEMANTIC_PAIRS` budget (for example by address proximity)
  instead of skipping the whole pass.
* Replace the greedy pass with an order-preserving assignment that keeps the
  current deterministic tie-breaking, and report how many pairs fell below the
  threshold.
* Add the same `signed:` summary to the `codevanta_struct` MCP description so the
  tool text matches the payload it already returns.


# Symbol demangling (Itanium / MSVC / Rust / Swift)

`codevanta_demangle` decodes mangled symbol names offline: the mangling
scheme is detected by prefix and the name is decoded by a bounded
pure-Python parser. It is the naming half of symbol recovery — where
[Go symbols](go-symbols.md) walks a runtime table, this lane parses the
linker-mangled strings themselves. Nothing is executed and no input file
is needed: the input is a list of symbol strings, typically copied out of
an import table, a symbol listing or another tool's output.

## What it reports

Each symbol in the batch comes back as a result in input order, with:

* `scheme` — one of `itanium`, `msvc`, `rust-legacy`, `rust-v0`, `swift`
  or `unknown`, detected by prefix:

  | Scheme | Prefix | Grammar |
  |--------|--------|---------|
  | `itanium` | `_Z…` | Itanium C++ ABI (GCC/Clang on ELF/Mach-O) |
  | `msvc` | `?…@@` | MSVC decorated names (PE) |
  | `rust-legacy` | `_ZN…17h<hash>E` | pre-v0 Rust mangling |
  | `rust-v0` | `_R…` | Rust v0, RFC 2603 |
  | `swift` | `_$s…` / `__T…` | Swift mangling |
  | `unknown` | anything else | no decode attempted |

* `demangled` — the decoded name, or `None` when the scheme is unknown.
* `complete` — **True only when the whole input was consumed by the
  grammar**. A partial decode is `complete=false` with a note naming
  exactly what was not decoded (an unsupported template construct, an
  operator that fell outside the table, …).
* `notes` — every degradation, bounded, never silent.
* `evidence` — one record per result (`source: demangle.symbol`,
  `method: pure_python_parser`), plus one batch-level record on the
  summary with `counts` per scheme and `complete_count`.

The honesty model is deliberate: an undecodable or exotic symbol is
**never an error**. It returns `scheme="unknown"` with `demangled=None`
plus an explanatory note, or a partial result with `complete=false`.
Caller mistakes — non-string entries, empty symbols, an empty list — are
the only typed errors.

## Usage

The MCP tool takes one argument:

```json
{"symbols": ["?fn@ns@@YAHXZ", "_ZN3foo3barEi", "_RNPvE"]}
```

Python surface (the same engine the tool wraps):

```python
from codevanta.analysis.demangle import demangle_symbols

summary = demangle_symbols(["_ZN3foo3barEi"])
print(summary.counts)            # {"rust-legacy": 1}
for result in summary.results:
    print(result.scheme, result.complete, result.demangled)
payload = summary.to_dict()      # JSON-safe, evidence included
```

A batch longer than the 64-symbol default budget is truncated with a
warning, never an error — but individual symbols must be valid bounded
strings.

## Bounds and confidence

Every bound that fires is reported through `notes`, `warnings` or the
`truncated` flag — never silently.

| Bound | Default | Effect |
|-------|---------|--------|
| Symbols processed | 64 (1…256) | counting the rest is skipped; `truncated` + warning |
| Input symbol length | 256 chars | longer input is a typed error, before any parse |
| Output length | 256 chars | clipped; `complete=false` + note |
| Parse depth | 32 nested constructs | deeper nesting degrades with a note |
| Argument list | 64 per function | further arguments degrade with a note |
| Template arguments | 32 per template | further arguments degrade with a note |

| Finding | Confidence | Why |
|---------|------------|-----|
| A `complete=true` result | `high` | the bounded grammar decoded the whole input deterministically |
| A partial result (`complete=false`) | `low` | something in the grammar was not decoded, and the note says what |
| Batch with all results complete | `high` | every symbol decoded soundly |
| Batch with some incomplete | `medium` | mixed batch |
| Batch with no complete result | `low` | nothing decoded soundly |

## Limitations

* Scheme detection is a cheap prefix test, not a parse: a symbol may
  report a scheme it later fails to decode (`complete=false` with the
  reason in `notes`).
* Exotic grammar corners (unusual substitutions, vendor extensions,
  deeply nested templates) surface as honest partial decodes, not
  invented names.
* No demanglers for formats outside the five supported schemes — C
  symbols are not mangled and come back as `unknown`.
* The 256-character input cap is enforced per symbol; longer symbols
  must be pre-split by the caller.

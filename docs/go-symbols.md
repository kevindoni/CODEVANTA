# Go pclntab symbol recovery

`codevanta.analysis.gosymbols` recovers function names from **stripped Go
binaries** by walking the embedded `pclntab` — pure Python, pure stdlib,
nothing executed. It is the next layer after `codevanta.analysis.binmeta`'s
`detect_go_buildinfo` (which identifies the Go toolchain); this engine turns
the runtime's own metadata back into a symbol list.

## Why stripping does not remove Go symbols

The pclntab ("PC/line table") is what `runtime.FuncForPC` and stack traces
use at run time: one entry per function with its package-qualified name,
entry address, and file/line mappings. It lives in `.gopclntab` (ELF) /
`__gopclntab` (Mach-O) or plain `.rdata` (PE) as *required runtime data*, not
debug info — so `strip`, Go's `-ldflags "-s -w"`, and commercial packers that
keep the binary runnable all leave it behind. Walking it recovers every
function name the linker emitted, exactly like Mandiant's GoReSym and
riven-labs' unstrip do.

## Supported layouts

| Magic (LE bytes) | Go version | Layout |
|------------------|------------|--------|
| `0xfffffffb` (`fb ff ff ff`) | 1.2 – 1.15 | No pcHeader fields: 8 fixed bytes, then an `nfunctab` word, then `(pc, funcoff)` uintptr pairs (absolute pc; funcoff and nameoff relative to the whole blob) plus one lone sentinel pc. Best-effort, **low** confidence. |
| `0xfffffffa` (`fa ff ff ff`) | 1.16 – 1.17 | pcHeader without `textStart`; functab pairs of uintptr `(entry, funcoff)` relative to `pclnOffset`; `nameOff` at `+ptrSize`; `funcoff == 0xFFFF…F` marks linker holes (skipped). |
| `0xfffffff0` (`f0 ff ff ff`) | 1.18 – 1.19 | pcHeader adds `textStart`; functab pairs of u32 `(entryoff, funcoff)` — offsets relative to `textStart` / `pclnOffset`; `nameOff` (int32) at `+4`. |
| `0xfffffff1` (`f1 ff ff ff`) | 1.20+ | **Same structure as 1.18.** |

**1.18 vs 1.20 decision:** Go 1.20 bumped the magic because the *trailing
funcdata* encoding changed, but `runtime.pcHeader` is byte-identical in field
layout and the functab/name walk is unchanged — verified against Go 1.18's
`runtime/symtab.go` and GoReSym's `debug/gosym` fork, which parses both with
one code path (and notes Go 1.21+ shares the 1.20 layout). This engine
therefore treats them as one structure and differs only in the reported
version guess.

Per-function **file and line** (the values in effect at the entry PC) are
recovered for the 1.16+ layouts via pcfile/pcln varint tables → cutab →
filetab, with bounded lookups; any failure degrades that function's fields
to `None`. The 1.2-family walk ships names + addresses only — its separate
filetab plumbing is a documented gap.

## Locate strategy

1. **Named sections first**: `.gopclntab` / `__gopclntab` (Mach-O fullnames
   like `__TEXT,__gopclntab` included), searched for a header magic.
2. **Bounded magic scan fallback**: all four magics, both byte orders, over
   non-executable sections only, capped at 64 MiB total.
3. Every candidate must pass a **structural sanity check** before it is
   believed: pad bytes zero, `minLC ∈ {1,2,4}`, `ptrSize ∈ {4,8}`, `1 ≤ nfunc
   ≤ 1 000 000`, all table offsets and the whole functab (nfunc pairs plus
   the sentinel pc) inside the section, and first entry pc < sentinel pc.

A **renamed or packed table (e.g. UPX) is out of scope** — the same
"unpacked only" stance as GoReSym — and reports as *not found* rather than
as a guess.

## Confidence semantics

| Finding | Confidence | Why |
|---------|------------|-----|
| A recovered name/address row | within report evidence: `medium` | the table bytes are real runtime data, decoded deterministically |
| Version/layout guess (1.16+) | `medium` | the magic proves the layout family, but the exact Go release is a range |
| Version/layout guess (1.2 family) | `low` | one magic spans Go 1.2–1.15 and predates the pcHeader |

Names are literal strings from the funcnametab (garble-obfuscated binaries
will yield obfuscated names — still honestly reported); addresses are
link-time VAs, consistent with every other static lane.

## Bounds

Every bound that fires is reported through `truncated`, counters or
`warnings` — never silently.

| Bound | Default | Effect |
|-------|---------|--------|
| Function rows kept (`max_functions`) | 65 536 (1…1 000 000) | counting continues; `truncated: true` |
| Name length | 1024 bytes | longer unterminated names are skipped and counted |
| Funcnametab read | 16 MiB | warning when capped |
| Magic scan / table blob read | 64 MiB | warning / stops the scan |
| Warnings kept | 32 | further warnings dropped |

## Errors

`AnalysisError` (typed, as everywhere in CODEVANTA) when the path is not a
readable supported binary, `max_functions` is out of range, no pclntab was
found (the message names what was searched), or a table was located but its
walk produced no valid entries (malformed, not guessed).

## Python usage

```python
from pathlib import Path

from codevanta.analysis.gosymbols import recover_go_symbols

report = recover_go_symbols(Path("malware/go_sample"), max_functions=65536)
print(report.go_version_guess)      # "1.20"
for function in report.functions:   # sorted by address
    print(hex(function.address), function.name, function.file, function.line)
payload = report.to_dict()          # JSON-safe, hex addresses
```

Lower level: `find_pclntab(info, data_provider)` returns a `PclntabLocation`
(VA, file offset, section, `found_by` = `section` | `magic-scan`, magic) or
`None`, and `decode_pclntab_header(data)` decodes the fixed header bytes of
any supported layout.

## Out of scope

- UPX-compressed or otherwise packed tables (not found by design).
- garble-obfuscated names (recovered as stored — obfuscated).
- Pre-Go-1.2 binaries (magic `0xffffff92` era).

## References

- Mandiant GoReSym — `debug/gosym/pclntab.go` (the 1.2/1.16/1.18/1.20 walk
  this engine mirrors) and its version map.
- riven-labs/unstrip — pclntab-based symbol restoration for Go 1.18+.
- `golang.org/s/go12symtab` — the original go1.2 format note.
- Go `runtime/symtab.go` (go1.16 and go1.18 tags) — `pcHeader`, `functab`,
  `_func` structures and the file/line tables.

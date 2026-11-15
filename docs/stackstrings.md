# Stack-string extraction (FLOSS-style, emulated)

`codevanta.analysis.stackstrings` recovers strings that a binary never stores
in the file because it builds them at runtime: a function moves immediate
characters onto its stack frame (`mov dword ptr [rsp+0x20], 'Hell'`), decodes
or appends to them, then uses the buffer. A static string scan cannot see
those bytes — they only exist once the function has run. This engine makes
them visible by **emulating** each function on the existing bounded emulator
and scanning the emulated stack afterwards, the approach pioneered by Mandiant
FLARE's `floss/stackstrings.py` (see
[flare-floss](https://github.com/mandiant/flare-floss), the direct
inspiration for this module).

It is a Python library engine: read-only, offline, bounded, with an evidence
record behind every recovered string. There is no `codevanta stackstrings`
CLI command (yet) — the surface is `extract_stack_strings`.

## What it recovers

For every scanned function, any run of at least **4 characters** of:

* printable **ASCII** (`0x20`–`0x7E`), and
* **UTF-16LE** (printable char, zero byte, repeated),

that provably appeared in the stack region the emulated function wrote —
whatever stopped the run: a clean `return`, the instruction `budget`, an
`unmapped` access, or any other emulator stop reason. Identical strings are
deduplicated per function; each record says which function built it, at what
stack offset, in which encoding, and under which stop reason.

## The algorithm

1. **Load** the binary with the production loader
   (`BinaryLoader`); a file it cannot parse raises `BinaryLoadError`.
2. **Choose targets**: the caller's explicit `addresses` when given
   (validated exactly like `emulate_function` validates its own — an address
   outside an executable section is a caller mistake and raises
   `AnalysisError`), otherwise the executable-section candidates from
   `discover_functions`, sorted by address for determinism.
3. **Emulate** each function from its start on a private unicorn CPU. The
   engine does not build a second emulator: it reuses
   [`codevanta.analysis.emulate`](api.md#codevantaanalysisemulate-bounded-offline-emulation)
   end to end — same image/stack mapping, same ABI register seeding, same
   instruction budget, same stop-reason classification, same Windows
   `faulthandler` handling. The single specialisation: the memory-write hook
   tracks the *span* of the stack the function wrote, and the final stack
   bytes are read back out of the emulator once the run stops. Nothing is
   ever executed on the host.
4. **Scan** the written stack span for printable ASCII and UTF-16LE runs of
   at least 4 characters (the two encodings are scanned independently, the
   way FLOSS does it — a UTF-16 run is not an ASCII run).
5. **Dedupe and cap**: identical strings per function collapse onto their
   first occurrence; at most `max_strings_per_function` distinct strings are
   kept while `string_count` keeps reporting the honest distinct total, and
   the per-function `truncated` flag says when the cap fired.

## Confidence semantics

| Finding | Confidence | Why |
|---------|------------|-----|
| A recovered string | `medium` | the bytes provably appeared in emulated stack memory — but emulation is an approximation: one entry state, one path, a bounded instruction count, no imports |
| The whole report (any strings recovered) | `medium` | same basis: every string came out of an emulated run |
| An empty "nothing ran" report (non-x86 binary) | `unknown` | no emulation happened; a warning states why |

Medium, not high, because the emulated run is *a* run, not *the* run: with
different registers or a different path the function might build a different
string — or never reach the building code at all.

## Bounds

Every bound that fires is reported through `truncated` flags, `skipped`
counters or `warnings` — never silently.

| Bound | Default | Ceiling | Effect |
|-------|---------|---------|--------|
| Functions scanned | 16 | 64 | the rest are not scanned; `truncated: true` + warning |
| Instructions per function | 2000 | 10 000 | out-of-range values raise `AnalysisError` naming the argument |
| Strings kept per function | 32 | 128 | counting continues; `truncated: true` on the function |
| Characters per string value | 256 (cut) | — | `value_truncated: true` in the record's evidence, honest `length` |
| Minimum run length | 4 chars | — | shorter runs are not findings |
| Stack bytes read back per function | 64 KiB | — | the read is cut with a warning (defensive; the default stack is exactly 64 KiB) |
| Warnings kept | 32 | — | further warnings are dropped |

Skipped functions are counted, never hidden: `skipped.no_stack_writes`
(ran but never wrote the stack), `skipped.setup` (the emulator could not be
prepared), `skipped.not_executable` (discovered candidates outside an
executable section).

## The optional unicorn dependency

The engine runs the file's bytes on a **private unicorn CPU** — nothing
executes on the host, no host process, syscall or library is invoked. That
needs the optional `unicorn` engine; when it is missing,
`extract_stack_strings` raises `AnalysisError` with the emulator's own status
and install hint before anything runs:

```text
stack-string extraction needs the optional unicorn engine: unicorn is not
importable: ...; install it with 'pip install codevanta[emulation]'
```

Install the extra with:

```powershell
pip install "codevanta[emulation]"
```

Only x86 and x86-64 are emulated (the register and stack vocabulary of the
runner is x86-specific, exactly like `emulate.py`); any other architecture
returns an empty report with a warning instead of a guess.

## Python API

```python
from pathlib import Path

from codevanta.analysis.stackstrings import extract_stack_strings

# Scan the first 16 discovered functions (default budgets).
report = extract_stack_strings(Path("sample.bin"))

for record in report.strings:
    print(f"{record.function_address:#x} +{record.stack_offset:#04x} "
          f"[{record.encoding}] {record.value!r}")

# Or point at specific functions and skip discovery entirely.
report = extract_stack_strings(
    Path("sample.bin"),
    addresses=[0x401000, 0x401A30],
    max_functions=8,
    max_instructions=4000,
    max_strings_per_function=64,
)

payload = report.to_dict()  # JSON-safe: addresses as "0x..." strings
```

The result object is `StackStringReport` (`path`, `architecture`, `bitness`,
`functions_scanned`, `functions_emulated`, per-function `FunctionScan` rows
with their `stop_reason`, `instructions`, `stack_writes`, `string_count` and
`truncated` flag, the flat `strings` tuple of `StackString` records, the
`skipped` counters, `warnings`, `truncated` and the shared `evidence`).

Out-of-range budgets, non-int or non-positive explicit addresses, and
explicit addresses outside an executable section raise the typed
`AnalysisError` naming the offending argument, before anything runs.

## Inspiration

The technique and the module's shape follow Mandiant FLARE's
[flare-floss](https://github.com/mandiant/flare-floss) `floss/stackstrings.py`
(emulate the function, then scan the frame for constructed strings), rebuilt
on CODEVANTA's bounded, evidence-carrying emulator with explicit budgets and
honest truncation everywhere.

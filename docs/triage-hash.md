# Triage hashing: imphash + ssdeep fuzzy hashing

`codevanta.analysis.triage_hash` produces the two first-pass hashes a triage
analyst reaches for, pure standard library, offline, bounded, and with an
evidence record behind every claim: the Mandiant-convention **imphash** for PE
import tables and an **ssdeep-style fuzzy hash** with a 0-100 similarity
score for arbitrary bytes.

## imphash (Mandiant convention)

imphash answers "do these two malware families share a build?" — it is the
MD5 over the **lowercase `dll.function` list of a PE import table, in
import-table order**, exactly as described in Mandiant's
[Tracking Malware with Import Hashing](https://www.mandiant.com/resources/blog/tracking-malware-import-hashing)
(the same digest JPCERT's impfuzzy and VirusTotal's imphash field use, so a
digest computed here can be pivoted on VirusTotal directly).

Engine rules, stated honestly:

* The library and function names are digested **exactly as the import table
  stores them**, lowercased, comma-joined: `KERNEL32.dll` + `CreateFileW`
  contributes `kernel32.dll.createfilew`.
* Ordinal imports (no name in the table) are **skipped and counted** in
  `skipped_unnamed` — the loader renames them `ordinal_N`, but a synthesised
  name is not evidence, so it never enters the digest.
* **PE only.** This loader exposes ELF/Mach-O imports as symbols without a
  reliable library pairing, and non-PE "imphash" variants would not match
  anything on VirusTotal. They are refused with a typed `AnalysisError`
  instead of guessed.
* A PE with no named imports (empty or ordinal-only table) is a typed error
  naming what is missing; nothing is hashed over invented input.

## Fuzzy hash (ssdeep piecewise hashing)

Context-triggered piecewise hashing in the
[ssdeep](https://github.com/ssdeep-project/ssdeep) family: a rolling hash
(7-byte window: Adler-style h1/h2 plus a shift/xor h3) splits the input into
content-defined blocks; each block is reduced by a 32-bit FNV-1 step
(prime 16777619, offset basis 2166136261) to one base64 character. The
signature is `block_size:part1:part2` where part2 is computed at double the
block size, so a comparison can survive a factor-of-two block-size mismatch.

* **Block-size rule:** start at 32768 and double while
  `block_size * 64 < length` (so 1 MiB hashes at 32768 — not 16384), capped
  at 1048576 (six sizes). If the first half comes out shorter than 32
  characters the engine halves the block size and re-runs, the classic
  ssdeep adjustment.
* **Comparison:** `fuzzy_compare` ports ssdeep's `fuzzy_compare` — identical
  signature strings score 100; block sizes must be equal or a factor of two
  apart (otherwise the score is 0, not an error); both halves are scored
  (best wins) through the edit-distance formula with the common-7-character
  substring gate, run-of-3 elimination, length scaling and the
  small-blocksize clamp.

### Interop notes (what deviates from the ssdeep 2.14 binary)

This engine replicates the classic ssdeep `fuzzy.c` streaming structure —
rolling hash, dual part1/part2 accumulators, the `j < 32` halving loop, tail
character handling, the 64/32-character half caps and the compare-time
elimination — with two lane-mandated constants:

| Constant | This engine | ssdeep 2.14 binary | Effect |
|----------|-------------|--------------------|--------|
| Minimum block size | 32768 (`32768<<i` ladder) | 3 (`3<<k` ladder) | same file may pick a different block size, so strings differ from ssdeep-binary output |
| Block hash seed | 2166136261 (FNV-1 offset basis) | 0x28021967 (low 6 bits 0x27) | emitted characters differ from ssdeep-binary output at the same block size |

Signatures from this engine are ssdeep-*shaped* (`blocksize:b64:b64`,
parseable by ssdeep tooling) and fully interoperable **with each other**;
they are not byte-identical to signatures produced by the ssdeep binary.
For VirusTotal pivoting use the imphash (exact interop) and sha256; use the
fuzzy hash to cluster samples hashed by this engine.

## Confidence semantics

| Finding | Confidence | Why |
|---------|------------|-----|
| imphash digest | `certain` | MD5 over names literally read from the import table |
| Fuzzy signature | `certain` | derived from bytes read from the file |
| Similarity score | `medium` | edit-distance heuristic, a judgement not an identification |
| `same_file` | identical signatures only | a score of 100 alone can be rounding, not proof |

## Bounds

Every bound that fires is reported through `truncated` flags or `warnings` —
never silently.

| Bound | Default | Effect |
|-------|---------|--------|
| Imports entering the imphash digest | 4096 | `truncated: true`, digest covers the first 4096 named imports |
| Bytes read per fuzzy hash (`max_bytes`) | 64 MiB | file still hashed over its first `max_bytes` bytes, `truncated: true` + warning |
| `max_bytes` ceiling | 512 MiB | out-of-range values raise the typed error |
| Block-size ladder | 32768 .. 1048576 | files beyond 64 MiB keep the 1048576 cap |
| Warnings kept per report | 32 | further warnings are dropped |

## Python usage

```python
from pathlib import Path

from codevanta.analysis.triage_hash import (
    fuzzy_compare,
    fuzzy_hash_file,
    import_hash,
    triage_hashes,
)

sample = Path("sample.exe")

# imphash (PE only; typed AnalysisError otherwise)
imphash = import_hash(sample)
print(imphash.imphash, imphash.digest_input)

# ssdeep-style fuzzy hash with a byte budget
fuzzy = fuzzy_hash_file(sample, max_bytes=32 * 1024 * 1024)
print(fuzzy.signature, fuzzy.truncated, fuzzy.warnings)

# 0-100 similarity between two signatures
comparison = fuzzy_compare(fuzzy.signature, fuzzy_hash_file(Path("other.bin")).signature)
print(comparison.score, comparison.same_file)

# everything at once: sha256, format/arch, imphash, fuzzy hash (JSON-safe)
report = triage_hashes(sample)
print(report.to_dict())
```

Typed `AnalysisError`s (naming what is missing): empty or missing files,
directories, `max_bytes` out of range, non-PE or import-less imphash targets,
and malformed signature strings (the error names which argument).

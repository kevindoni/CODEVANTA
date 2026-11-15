# Archive unpacking manifest (bounded, in memory)

`codevanta_unpack` builds a recursive manifest of an archive file —
completely in memory: **nothing is extracted to disk**. It answers
"what is inside this container, and what is inside the containers
inside it" for the common installer/payload formats, with hard guards
against the two classic failure modes of unpackers: recursive bombs and
compression bombs. Pure Python standard library parsing; nothing is
executed or extracted.

## What it reports

A bounded tree of entries, each carrying its `path`, `kind`, `size`
and — for small leaves when `hashes` is on (the default) — a `sha256`:

* **zip** archives (via `zipfile`) and **tar** archives (via `tarfile`),
  including gz-, bz2- and xz-compressed tars;
* **single-stream gzip, bzip2 and xz** payloads;
* **cpio newc** archives (headers only — names, sizes, kinds);
* **nested archives**, followed recursively up to the depth bound, the
  way an installer ships a zip inside a tar inside a gzip.

The top-level evidence record is `method: stdlib_zipfile_tarfile_headers`
at `high` confidence.

## The guards

| Guard | Value | Effect |
|-------|-------|--------|
| Nesting depth | 4 | deeper archives are recorded as leaves, with a warning |
| Entries per archive | 512 | counting continues; the archive row is flagged truncated |
| Total byte budget | 64 MiB | once spent, remaining streams are named, not read |
| Compression-bomb ratio | declared : compressed > 1000 : 1 | the entry is **listed but never read** |
| Oversized streams | budget-exceeding | truncated honestly, never slurped whole |

The bomb guard matters: a 42-PB-declared `zip bomb` is described by its
header and refused as input, not decoded into memory.

## Usage

```json
{"path": "payload.bin", "hashes": true}
```

`hashes=false` skips leaf hashing for a faster header-only walk.
Python surface:

```python
from codevanta.analysis.unpack import build_unpack_manifest

manifest = build_unpack_manifest(data, hashes=True)
for entry in manifest.entries:
    print(entry.kind, entry.path, entry.size)
payload = manifest.to_dict()   # JSON-safe, evidence included
```

Missing files, directories-as-files and inputs above the shared
256 MiB read cap are typed `AnalysisError`s. An input that is not an
archive at all is also a typed error — the tool names the formats it
probed.

## Bounds and confidence

| Finding | Confidence | Why |
|---------|------------|-----|
| An entry row (path, kind, size) | `high` | read from the container's own headers by the standard library |
| A leaf sha256 | `high` | computed over the decoded bytes actually read |
| A bomb-suspect row | not a decode | listed from declared sizes only, and marked as unread by policy |

## Limitations

* cpio entries are **headers only** — contents are not walked or
  hashed in this increment.
* Formats outside zip/tar/gzip/bzip2/xz/cpio (7z, RAR, CAB, MSI
  containers) are not supported; the typed error names what was tried.
* The manifest reflects the archive's *declared* metadata; a lying
  header yields a lying row, and the byte budget keeps that harmless.
* Nothing is written to disk by design — to unpack for real, use a
  real extractor against the artifact the archive came from.

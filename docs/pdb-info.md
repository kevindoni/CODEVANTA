# PDB information parsing (MSF container)

`codevanta.analysis.pdb_info` opens a local `.pdb` file the way the binary
lanes open a PE or ELF: read-only, offline, bounded, and with an evidence
record behind every claim. It is pure Python standard library — no LIEF
Extended, no DIA, no WinDbg, nothing executed, and **no symbol download,
no symbol servers, no network of any kind**.

It exists because the LIEF OSS build gates its PDB parser behind the
Extended distribution; this lane reads the container structure directly
instead.

```python
from pathlib import Path
from codevanta.analysis.pdb_info import parse_pdb, codeview_reference

report = parse_pdb(Path("app.pdb"))          # MSF structure + info + DBI modules
payload = report.to_dict()                   # JSON-safe
import json; print(json.dumps(payload, indent=2))

reference = codeview_reference(Path("app.exe"))  # PE debug-directory CodeView record
if reference is not None:
    print(reference.pdb_path, reference.guid, reference.age, reference.debug_type)
```

## What it covers

* **MSF v7.00 container** ("Big" format) — the superblock (magic, block
  size validated as a power of two between 512 and 16384, block count,
  directory size, block map address), the stream directory reached through
  the block map, per-stream size entries (with the `0xFFFFFFFF` absent
  sentinel) and block-number tables, plus bounded on-demand stream
  reassembly.
* **PDB info stream (stream 1)** — version, signature, age and the unique
  GUID, exactly as the format stores them, plus the inline named-stream
  string blob (`/names`, `/LinkInfo`, `/src/headerblock`, …), bounded by
  count.
* **Named-stream binding** — the stream carrying the string table is
  located by its own `0xeffeeffe` magic and reported by name (`/names`) in
  the stream rows.
* **DBI stream (stream 3) module list** — each module's name and object
  file name, walked record by record over the 64-byte fixed prefix plus two
  NUL strings. If the walk cannot find the next record inside the
  substream it stops with a warning naming the module index — it never
  guesses.
* **PE CodeView reference** — the debug directory's CodeView record from
  the binary itself: PDB path, GUID + age (`RSDS`) or time-date stamp + age
  (`NB10` records carry no GUID), plus the PE section carrying the record.
  `RSDS` + GUID + age is exactly the tuple a symbol server would key on;
  this module extracts it and stops there.

## What it deliberately does NOT do

* No symbol records — no publics, no globals, no per-module symbol streams.
* No type information — TPI and IPI streams are listed in the directory
  and nothing more.
* No section contributions, section maps, source-server blocks, or the
  optional debug header stream.
* No name→stream-index hash-table decode for the named-stream map: only
  the `/names` string blob is parsed, and only `/names` itself is bound to
  a stream index. This gap is stated here on purpose.
* No symbol download, no symbol server queries, no URL construction, no
  network I/O — ever.

The MSF walk, the info-stream layout, the `/names` magic binding and the
64-byte DBI module prefix (module index at +20) were validated against
real MSVC-produced PDB files; the committed test suite uses only synthetic
fixtures assembled byte by byte.

## Confidence semantics

| Finding | Confidence | Why |
|---------|------------|-----|
| MSF structure (block size, stream count, sizes, block tables) | `certain` | read straight from the file |
| Info stream version / signature / age / GUID | `certain` | fixed-offset fields in stream 1 |
| `/names` strings | `certain` | literal NUL-terminated bytes in the blob |
| DBI module names / object names | `certain` | read from the substream, never inferred |
| PE CodeView path / GUID / age | `certain` | fixed-layout record in the debug directory |

There are no heuristic fallbacks in this module: anything that cannot be
read is reported as a warning or a `None`, never invented.

## Bounds

Every bound that fires is reported through `truncated` flags, honest
counts (`stream_count`, `module_count`) or warnings — never silently.

| Bound | Default | Effect |
|-------|---------|--------|
| Stream rows kept | 256 (`max_streams`) | counting continues; `truncated: true` |
| Module rows kept | 4096 (`max_modules`) | walk stops; `truncated: true` |
| Names kept | 4096 | further names dropped with a warning |
| Block-map entries | 1024 | larger directories raise the typed error |
| Single stream read | 16 MiB | larger streams are skipped and named |
| CodeView PDB path | 1024 bytes | decoded prefix is bounded |
| Debug entries walked | 64 | further entries dropped |
| Warnings kept | 32 | further warnings are dropped |
| Whole file | 512 MiB | larger files raise the typed error |

Malformed container structure — wrong MSF magic, a block size that is not
a power of two between 512 and 16384, a block map or stream directory
pointing outside the file, a directory too small for its stream count —
raises the typed `AnalysisError`. Damage inside one optional stream (info,
DBI, `/names`) degrades to a warning; the rest of the report still stands.
For `codeview_reference`, a non-PE input raises `AnalysisError`; a PE
without a debug directory or without a CodeView entry returns `None`.

## Surfaces

Python only, by design — this lane is not wired into the CLI, MCP server,
or GUI yet:

* `codevanta.analysis.pdb_info.parse_pdb(path, *, max_streams=256, max_modules=4096)`
* `codevanta.analysis.pdb_info.codeview_reference(path)`
* `codevanta.analysis.pdb_info.decode_codeview_record(data)` — the pure
  RSDS/NB10 record decoder, usable on any byte blob

## References

* microsoft/microsoft-pdb — MSF superblock, stream directory, DBI `MODI`
  record layout and the `/names` string table as shipped by the PDB
  toolchain sources.
* LLVM `DebugInfo/PDB/Native` (llvm-pdbutil) — implementation notes for
  the info stream header, the DBI header/substream layout and the
  `0xeffeeffe` names-stream signature.

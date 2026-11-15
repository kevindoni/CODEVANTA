# SBOM export (CycloneDX 1.6)

`codevanta.analysis.sbom.build_sbom` turns inventories CODEVANTA has already
proved into a [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/) Software
Bill of Materials. It is inspired by [anchore/syft](https://github.com/anchore/syft)
and implemented with the Python standard library only — `json`, `hashlib`,
`uuid`, `pathlib`. Nothing new is executed, installed, or fetched.

An SBOM answers one question: *what is inside this thing?* This engine answers
it only from evidence the other lanes already collected — it inventories, it
never guesses.

```python
from pathlib import Path

from codevanta.analysis.sbom import build_sbom

report = build_sbom([Path("path/to/app"), Path("samples/pe64_text.bin")])
print(report.to_json())        # the full CycloneDX 1.6 document
print(report.component_count)  # kept + cut
print(report.truncated, report.warnings)
```

Mix inputs freely. Each path is a PE / ELF / Mach-O / DEX binary (loaded by
the same `BinaryLoader` behind `codevanta info`), or a JavaScript application
directory / `.asar` archive (the bounded scanner behind `codevanta js
analyze`).

## What feeds the document today

| Source | Component | purl |
|--------|-----------|------|
| JS bare imports (`external_packages`) | one `library` per external package | `pkg:npm/<name>`, plus `@<version>` when exact in `package.json` |
| root `package.json` | one `application` for the app itself | `pkg:npm/<name>` when the name is declared |
| PE / Mach-O import tables | one `library` per imported dynamic library | — (not derivable) |
| the binary file itself | one `application` per binary (name = file stem) | — |
| file bytes | `SHA-256` hash on every binary application component | — |

Every component carries two properties: `codevanta:evidence` — a one-line
`source/method/confidence` justification lifted from the lane that produced
the row — and `codevanta:sources`, the input paths that produced it.

## What it deliberately does not claim

* **No guessed versions.** A dependency range (`^1.2.3`, `~2`, `>=3`, `*`,
  `latest`) is a demand, not a fact; only exact versions from `package.json`
  become `@<version>` suffixes. Binary components never carry a version —
  the import table does not know one, so the field is omitted.
* **No purl without an identity.** Binaries and apps named after their
  directory get no purl: a file stem is not a package identity.
* **Go build info and cargo-auditable metadata are a documented gap.** The
  detectors exist (`codevanta.analysis.binmeta`: `meta.gobuildinfo`, the
  cargo-auditable payload), but their module and crate rows are not lifted
  into components yet.
* **No dependency resolution.** `node_modules` is never walked and no
  registry is contacted — the document claims what the source proves (bare
  imports) and what the manifest declares (exact versions), nothing more.
* **No licenses, CPEs, suppliers, or timestamps.**

## Determinism

The same input set produces a byte-identical document:

* `serialNumber` is `urn:uuid:<uuid5>` over the sorted, deduplicated
  `(path, sha256)` pairs of the input set — a JS directory is represented by
  the digest of its root `package.json` (or the empty digest when absent),
  files by the digest of their bytes.
* Components are sorted by `(type, name, purl)`; duplicates — same
  `(type, name, version, purl)` — are merged with their sources unioned.
* No timestamp is emitted.

## Bounds

| Bound | Default | Effect |
|-------|---------|--------|
| `max_components` | 2000 (1..20000) | first N sorted components kept; `truncated: true`, honest `component_count` (kept + cut) and a warning — never silent |
| Warnings kept | 32 | further warnings are dropped (house style) |

Errors are the typed `AnalysisError` naming the offending path: an empty
path sequence, a path that cannot be stat'ed, or an input that is neither a
directory, an `.asar` archive, nor a loadable binary.

The report-level evidence is `sbom.export/inventory_aggregation/medium`:
every per-lane inventory underneath is individually certain, but purl and
version gaps make the aggregated document medium.

## Surfaces

Python only for now — `build_sbom` is not yet wired into the CLI, MCP or GUI
lanes.

## Reference

* [CycloneDX 1.6 JSON schema](https://cyclonedx.org/docs/1.6/json/)
* [package URL specification](https://github.com/package-url/purl-spec)
* [anchore/syft](https://github.com/anchore/syft) — the inspiration for this
  engine

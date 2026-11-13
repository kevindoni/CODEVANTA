# CODEVANTA API reference

Every public Python entry point, with the arguments and defaults read from the
source at the time of writing (`v0.1.0`; the phase 3 sections were read on branch
`feat/phase3-power`, the phase 6 sections on branch `feat/phase7-wiring`).

CODEVANTA does static analysis only: it parses file bytes and never executes a
target on the host. (The phase-3 emulator in
[`codevanta.analysis.emulate`](#codevantaanalysisemulate-bounded-offline-emulation)
runs those same bytes on a private unicorn CPU, with no host process, syscall or
library involved.) Each result object carries an [evidence
record](#the-evidence-contract) so you can tell a proven fact from a heuristic
before you rely on it.

## Contents

- [Conventions](#conventions)
- [The evidence contract](#the-evidence-contract)
- [`codevanta.core.loader`: loading binaries](#codevantacoreloader-loading-binaries)
- [`codevanta.core.report`: the JSON report](#codevantacorereport-the-json-report)
- [`codevanta.core.functions`: function candidates](#codevantacorefunctions-function-candidates)
- [`codevanta.core.strings`: string extraction](#codevantacorestrings-string-extraction)
- [`codevanta.core.disassembler`: disassembly](#codevantacoredisassembler-disassembly)
- [`codevanta.analysis.xrefs`: cross references](#codevantaanalysisxrefs-cross-references)
- [`codevanta.analysis.cfg`: control-flow graphs](#codevantaanalysiscfg-control-flow-graphs)
- [`codevanta.analysis.callgraph`: call graphs](#codevantaanalysiscallgraph-call-graphs)
- [Graph export formats](#graph-export-formats)
- [`codevanta.analysis.binary_diff`: binary diff](#codevantaanalysisbinary_diff-binary-diff)
- [`codevanta.analysis.function_hash`: fingerprints and similarity](#codevantaanalysisfunction_hash-fingerprints-and-similarity)
- [`codevanta.analysis.type_recovery`: struct suggestions](#codevantaanalysistype_recovery-struct-suggestions)
- [`codevanta.analysis.decompile`: pseudo-C rendering](#codevantaanalysisdecompile-pseudo-c-rendering)
- [`codevanta.analysis.decompilers`: decompiler providers](#codevantaanalysisdecompilers-decompiler-providers)
- [`codevanta.analysis.emulate`: bounded offline emulation](#codevantaanalysisemulate-bounded-offline-emulation)
- [`codevanta.analysis.symbolic`: branch-decision path exploration](#codevantaanalysissymbolic-branch-decision-path-exploration)
- [`codevanta.analysis.dataflow`: def-use and constant folding](#codevantaanalysisdataflow-def-use-and-constant-folding)
- [`codevanta.analysis.evidence_bundle`: tamper-evident bundles](#codevantaanalysisevidence_bundle-tamper-evident-bundles)
- [`codevanta.analysis.trace`: trace replay and attribution](#codevantaanalysistrace-trace-replay-and-attribution)
- [`codevanta.analysis.dynamic`: provider probes and session scripts](#codevantaanalysisdynamic-provider-probes-and-session-scripts)
- [`codevanta.plugins`: the plugin SDK](#codevantaplugins-the-plugin-sdk)
- [`codevanta.storage.session`: persisted sessions](#codevantastoragesession-persisted-sessions)
- [`codevanta.gui`: local web dashboard](#codevantagui-local-web-dashboard)
- [`codevanta.mcp_server`: MCP server](#codevantamcp_server-mcp-server)
- [Quick recipes](#quick-recipes)

## Conventions

| Convention | Meaning |
| --- | --- |
| Addresses | Always absolute virtual addresses (VA). PE RVAs are rebased with the image base, and a fat Mach-O slice's section offsets are shifted into the outer container. |
| `X \| None` | `None` means "the format does not record this", never `0`. Callers must check. |
| `to_dict()` | Every result dataclass has one. Dictionaries are JSON-serializable; addresses become `"0x..."` strings, sizes stay integers. |
| Errors | `BinaryLoadError` (load), `AnalysisError` (request cannot be satisfied), `DisassemblyError` (Capstone cannot decode), `SessionError` (storage), `GraphExportError` (export). |
| Execution | Nothing here runs the target binary on the host, writes to it, or needs the network. The phase-3 emulator runs the file's bytes on a private unicorn CPU. |

## The evidence contract

Every finding exposes an `Evidence` record
(`codevanta.evidence.models.Evidence`):

```python
Evidence(source: str, method: str, confidence: Confidence = Confidence.UNKNOWN,
         address: int | None = None, detail: str | None = None,
         extra: dict[str, Any] = {})
```

| Field | Question it answers |
| --- | --- |
| `source` | Which structural input produced this? (e.g. `pe.export_table`, `macho.section_table`, `capstone.direct_call`) |
| `method` | Which technique read it? (e.g. `exported_function`, `linear_disassembly`) |
| `confidence` | How strong is the support? See below. |
| `address` | The VA the claim is about, when there is one. |
| `detail` | Human-readable statement of *why*, including the caveat. |
| `extra` | Structured extras (the fat Mach-O slice metadata lives here). |

`codevanta.evidence.confidence.Confidence` (`str` enum, `.score` gives a
`float` in `0.0 .. 1.0` for ordering):

| Value | Meaning |
| --- | --- |
| `certain` | Direct, unambiguous data from the file format. |
| `high` | Strong structural evidence — an export table, a function symbol. |
| `medium` | Indirect evidence — an entry point, a heuristically attributed caller. |
| `low` | Weak or inferred evidence. |
| `unknown` | No confidence can be established. |

The rule the whole codebase follows: **a heuristic reports `medium` and says so
in `detail`; it is never upgraded to `certain` because it looked right.**
`Provenance` (`codevanta.evidence.provenance`) records the ordered list of
pipeline steps that produced a report, so a report can be audited end to end.


## `codevanta.core.loader`: loading binaries

```python
from codevanta.core.loader import BinaryLoader, BinaryInfo, BinaryLoadError
```

### `BinaryLoader.load`

```python
BinaryLoader().load(path: str | Path) -> BinaryInfo
```

Loads a PE, ELF or Mach-O file. Raises `BinaryLoadError` when the path is
missing, is not a regular file, is empty, exceeds `BinaryLoader.MAX_FILE_SIZE`
(512 MiB), or when neither LIEF nor the fat-header parser can interpret it.

### `BinaryInfo`

Normalized metadata for one loaded binary.

```python
BinaryInfo(
    path: Path, format: str, architecture: str, bitness: int,
    endianness: str, entry_point: int | None, image_base: int,
    sha256: str, file_size: int,
    sections: list[SectionInfo] = [], imports: list[ImportInfo] = [],
    exports: list[ExportInfo] = [], symbols: list[SymbolInfo] = [],
    is_stripped: bool = False, warnings: list[str] = [],
    evidence: Evidence | None = None,
)
```

| Field | Notes |
| --- | --- |
| `format` | `"PE"`, `"ELF"` or `"MachO"`. |
| `architecture` | `x86`, `x86_64`, `arm`, `aarch64`, `ppc`, `ppc64`, or `unknown`. |
| `bitness` | `32`, `64`, or `0` when undetermined. |
| `endianness` | `"little"` or `"big"`; also selects the UTF-16 string scan order. |
| `entry_point` | VA, or `None`. A **medium**-confidence code candidate, not a proven function start. |
| `image_base` | VA the image is mapped at. |
| `sha256`, `file_size` | Always cover the whole file — the outer container for a fat Mach-O. |
| `is_stripped` | `True` when no usable symbol/export information was found. |
| `warnings` | Degraded-coverage notes (no sections, no symbols, unreadable region...). |
| `evidence` | Container-level provenance. Only set for fat Mach-O today. |

Methods:

```python
info.section_for_va(va: int) -> SectionInfo | None
info.va_to_offset(va: int) -> int | None
info.offset_to_va(offset: int) -> int | None
info.to_dict() -> dict[str, Any]
```

`va_to_offset` / `offset_to_va` return `None` for a VA or offset with no file
bytes (an ELF `.bss`, a Mach-O `S_ZEROFILL` section), so a mapping is never
invented. `to_dict()` emits `entry_point` and `image_base` as `"0x..."` and only
adds the `evidence` key when it is not `None`.

The nested records:

```python
SectionInfo(name: str, virtual_address: int, size: int, offset: int,
            raw_size: int = 0, entropy: float | None = None,
            is_executable: bool = False, is_writable: bool = False,
            evidence: Evidence | None = None)

ImportInfo(name: str, library: str | None = None, address: int | None = None,
           evidence: Evidence | None = None)

ExportInfo(name: str, address: int | None, ordinal: int | None = None,
           forwarded_to: str | None = None, evidence: Evidence | None = None)

SymbolInfo(name: str, address: int, size: int = 0, kind: str = "unknown",
           is_function: bool = False, evidence: Evidence | None = None)
```

### Fat (universal) Mach-O

A fat container wraps several thin Mach-O images behind one magic. The loader
unwraps it, selects one slice deterministically, and parses **only** that slice.

```python
FAT_MAGIC = 0xCAFEBABE       FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF    FAT_CIGAM_64 = 0xBFBAFECA

FatArch(index: int, cputype: int, cpusubtype: int, offset: int, size: int, align: int)
FatContainer(magic: int, wide_entries: bool, arches: tuple[FatArch, ...],
             slice: FatArch, rule: str, reason: str)
```

| `FatArch` member | Meaning |
| --- | --- |
| `.is_64bit` | `bool(cputype & 0x01000000)` |
| `.arch_name` | `x86_64`, `aarch64`, `arm`, `x86`, `ppc`, `ppc64`, `aarch64_32`, or `cputype_<hex>` |
| `.to_dict()` | `index`, `arch`, `cputype`, `cpusubtype`, `offset`, `size`, `align`, `is_64bit` |

| `FatContainer` member | Meaning |
| --- | --- |
| `.magic_name` | `FAT_MAGIC`, `FAT_CIGAM`, `FAT_MAGIC_64` or `FAT_CIGAM_64` |
| `.slice_count` | `len(self.arches)` |
| `.evidence_extra()` | the structured dict described below |

Selection rules (`codevanta.core.loader.RULE_PREFER_64BIT` /
`RULE_FIRST_BY_OFFSET`): a 64-bit slice is preferred over any 32-bit slice; ties
(and the all-32-bit case) are broken by lowest file offset. The other slices are
reported, never parsed.

Malformed containers are rejected before any slice is parsed, with
`BinaryLoadError` naming the offending field: a truncated header,
`nfat_arch == 0`, an `nfat_arch` above `MAX_FAT_SLICES` (`32`), a truncated
`fat_arch` table, `size == 0`, an `align` above `MAX_FAT_ALIGN` (`20`), an
`offset` that is not a multiple of `1 << align`, an `offset` pointing inside the
header/table, or an `offset`/`size` that runs past the end of the file.

The selected slice must then *be* a thin Mach-O image, and the container must
agree with it:

- a slice LIEF cannot parse raises `Fat Mach-O <path>: slice N … is not a valid
  thin Mach-O image`;
- a slice that parses as another format raises `Fat Mach-O <path>: fat slice is
  not a Mach-O image: ELF` (or `PE`);
- a `fat_arch[i].cputype` that differs from the parsed thin header's `cputype`
  raises `fat_arch[i].cputype … does not match …`, naming both values.

`MAX_FAT_SLICES` and `MAX_FAT_ALIGN` are importable from
`codevanta.core.loader`, so callers can assert the same bounds.

#### Fat evidence keys

For a fat container, `BinaryInfo.evidence` is a `certain`-confidence record with
`source="macho.fat_header"`, `method="fat_arch_table"`, a `detail` naming the
chosen slice, and this `extra` payload:

| Key | Type | Meaning |
| --- | --- | --- |
| `fat` | `bool` | Always `True`; presence of `extra["fat"]` is the "this was universal" test. |
| `fat_magic` | `str` | `"0xcafebabe"` — the raw magic, zero-padded to 8 digits. |
| `fat_magic_name` | `str` | Symbolic name of the magic. |
| `fat_arch_64` | `bool` | `True` when the table used 64-bit `fat_arch_64` entries. |
| `slice_index` | `int` | Index of the selected slice in the architecture table. |
| `slice_count` | `int` | Number of slices in the container. |
| `slice_arch` | `str` | Architecture name of the selected slice. |
| `slice_cputype` | `str` | `"0x1000007"` — `cputype` of the selected slice. |
| `slice_offset` | `int` | File offset of the selected slice (decimal). |
| `slice_size` | `int` | Byte size of the selected slice (decimal). |
| `selection_rule` | `str` | `prefer_64bit` or `first_by_offset`. |
| `selection_reason` | `str` | Prose for the same rule. |
| `available_arches` | `list[str]` | Arch name of every slice, in table order. |
| `available_slices` | `list[dict]` | `FatArch.to_dict()` for every slice. |

Because section offsets are shifted by the slice offset, `va_to_offset()` inside
a fat Mach-O maps into the outer container and stays valid.


## `codevanta.core.report`: the JSON report

```python
from codevanta.core.report import build_report, AnalysisError
```

### `build_report`

```python
build_report(
    path: str | Path,
    string_limit: int = 5000,
    xref_limit: int = 2000,
    include_callgraph: bool = False,
    include_xrefs: bool = False,
    include_cfg: bool = False,
) -> dict[str, Any]
```

Returns a JSON-serializable report. Nothing more than the file bytes is read and
nothing is executed.

| Flag | Default | Effect | Bound |
| --- | --- | --- | --- |
| `string_limit` | `5000` | Strings kept under `report["strings"]["items"]` | `0 .. MAX_STRING_LIMIT` (`200000`) |
| `xref_limit` | `2000` | Xref items kept under `report["xrefs"]["items"]` | `0 .. MAX_XREF_LIMIT` (`200000`) |
| `include_callgraph` | `False` | Adds `report["callgraph"]` | ≤ `1000` nodes, ≤ `5000` edges |
| `include_xrefs` | `False` | Adds `report["xrefs"]` | ≤ `DEFAULT_MAX_BYTES` (`4_000_000`) decoded bytes |
| `include_cfg` | `False` | Adds `report["cfg"]` | ≤ `2000` instructions, ≤ `500` blocks |

`string_limit` and `xref_limit` are always validated; `xref_limit` is checked
even when `include_xrefs` is `False`. Out-of-range values raise `AnalysisError`.

Sections emitted:

| Key | Always present? | Content |
| --- | --- | --- |
| `provenance` | yes | `{tool, tool_version, created_at, steps}`; `steps` is an ordered list of step names |
| `binary` | yes | `BinaryInfo.to_dict()` |
| `functions` | yes | list of `FunctionCandidate.to_dict()` |
| `strings` | yes | `{count, returned, truncated, items}` |
| `disassembly` | yes | `DisassemblyResult.to_dict()` at the entry point (32 instructions), or `None` |
| `callgraph` | only with `include_callgraph` | `CallGraph.to_dict()` |
| `xrefs` | only with `include_xrefs` | `{count, returned, truncated, items, scanned_sections, scanned_bytes, scan_truncated, indirect_skipped, warnings, evidence}` |
| `cfg` | only with `include_cfg` | `FunctionCFG.to_dict()` |

Without the three flags the payload is exactly the phase-1 report, so no
existing consumer sees a new key. A requested section whose engine has nothing
to decode still appears, carrying an explanatory `warnings` entry: **the phase-2
sections never fail the report.** Only a bad limit (or a call-graph build
failure) raises `AnalysisError`.

Related constants: `MAX_DISASSEMBLY_COUNT = 100_000`,
`MAX_STRING_LIMIT = 200_000`, `MAX_XREF_LIMIT = 200_000`,
`DEFAULT_XREF_LIMIT = 2_000`, `REPORT_MAX_CALLGRAPH_FUNCTIONS = 1000`,
`REPORT_MAX_CALLGRAPH_EDGES = 5000`, `REPORT_MAX_CFG_INSTRUCTIONS = 2000`,
`REPORT_MAX_CFG_BLOCKS = 500`.

> **Layering note.** `codevanta.core.report` must not import
> `codevanta.analysis` at module import time (the analysis package imports
> `AnalysisError` from here). The three phase-2 engines are imported lazily
> inside `build_report`, so a caller that does not ask for a section pays
> nothing for it.

### Report helpers

```python
load_binary(path: str | Path) -> BinaryInfo
read_code(path: str | Path, info: BinaryInfo, address: int, want_bytes: int) -> bytes
resolve_target(info: BinaryInfo, address: int | None, function: str | None) -> int
disassemble_region(path: str | Path, info: BinaryInfo, start: int, count: int = 50) -> DisassemblyResult
```

- `read_code` raises `AnalysisError` when `address` has no file bytes.
- `resolve_target` prefers `address`, then a `function` name matched against
  `discover_functions(info)`, then `info.entry_point`; it raises `AnalysisError`
  when none applies.
- `disassemble_region` requires `1 <= count <= 100_000` and an executable
  section at `start`.

## `codevanta.core.functions`: function candidates

```python
from codevanta.core.functions import discover_functions, FunctionCandidate

discover_functions(info: BinaryInfo) -> list[FunctionCandidate]
```

Structural discovery only — no recursive descent, no heuristics beyond the
format's own tables. The sources are the export table, the function symbols and
the entry point.

```python
FunctionCandidate(
    address: int, name: str | None, size: int | None, source: str,
    confidence: Confidence, evidence: Evidence,
    aliases: tuple[str, ...] = (),
)
```

| Field | Notes |
| --- | --- |
| `address` | VA of the candidate. |
| `name` | Symbol/export name, or `None` for an anonymous candidate. |
| `size` | `None` when the format does not record an extent — never guessed. |
| `source` | e.g. `pe.export_table`, `elf.symtab`, `elf.entry_point`, `macho.symbol_table`. |
| `confidence` | `high` for exports/function symbols, `medium` for the entry point and for Mach-O symbol-table entries. |
| `aliases` | Other names resolving to the same address. |

`to_dict()` emits `address`, `source`, `confidence`, `evidence` and `name`, and
only adds `size` / `aliases` when they are known.

## `codevanta.core.strings`: string extraction

```python
from codevanta.core.strings import StringExtractor, StringResult

extractor = StringExtractor(min_length: int = 4)      # raises ValueError if < 1
extractor.extract(path: str | Path, info: BinaryInfo | None = None,
                  limit: int = 0) -> list[StringResult]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `min_length` | `4` | Shortest run of printable characters kept. |
| `limit` | `0` | `0` means "no limit"; otherwise the scan stops after `limit` results. |
| `info` | `None` | Supplies `endianness` for the UTF-16 pass and the VA mapping. |

`StringResult(offset: int, address: int | None, text: str, encoding: str,
length: int, evidence: Evidence)`; `encoding` is `"ascii"`, `"utf-16le"` or
`"utf-16be"`.

**Byte-order rule.** UTF-16 follows `info.endianness`: little-endian targets are
scanned as UTF-16LE, big-endian targets as UTF-16BE. With no metadata the scan
stays UTF-16LE and never guesses a byte swap, so a shifted cross-byte-order
match is never fabricated. `to_dict()` emits `offset`, `text`, `encoding`,
`length`, and `address` only when mapped.


## `codevanta.core.disassembler`: disassembly

> There is no `codevanta.analysis.disasm` module. The disassembler lives in
> `codevanta.core.disassembler`; the file-backed convenience call is
> `codevanta.core.report.disassemble_region`.

```python
from codevanta.core.disassembler import Disassembler, DisassemblyResult, DisassemblyError

engine = Disassembler(architecture: str, bitness: int, endianness: str = "little")
engine.disassemble(data: bytes, base_address: int,
                   max_instructions: int = 0, max_bytes: int = 0) -> DisassemblyResult
```

| Option | Default | Meaning |
| --- | --- | --- |
| `architecture` | — | Capstone architecture name (`x86`, `arm`, `aarch64`, `ppc`...). |
| `bitness` | — | `32` or `64`. |
| `endianness` | `"little"` | `"little"` or `"big"`. |
| `max_instructions` | `0` | `0` means "no instruction cap". |
| `max_bytes` | `0` | `0` means "decode to the end of `data`". |

`disassemble` raises `DisassemblyError` for an unsupported architecture or
undecodable input.

```python
DisassemblyResult(instructions: list[IRInstruction], base_address: int,
                  consumed_bytes: int, evidence: Evidence, truncated: bool = False)
```

`IRInstruction(address: int, size: int, mnemonic: str, operands: str,
raw_bytes: bytes, section: str | None = None, ir_ops: tuple[dict, ...] = ())` is
the backend-neutral IR record (`codevanta.ir.instruction`). The result's evidence
is a single record at `certain` confidence for the decoded bytes; `truncated` is
set when an explicit cap cut the sweep.

## `codevanta.analysis.xrefs`: cross references

```python
from codevanta.analysis.xrefs import find_xrefs, Xref, XrefResult, DEFAULT_MAX_BYTES

find_xrefs(path: str | Path, info: BinaryInfo,
           functions: list[FunctionCandidate] | None = None,
           max_bytes: int = 4_000_000) -> XrefResult
```

Recovers `call`, `jump`, `branch`, `call_import` and `call_indirect` references
from direct branch operands in executable sections. Indirect targets are skipped
rather than guessed. **It never raises for undecodable input**: degraded coverage
is reported through `XrefResult.warnings`.

```python
Xref(from_address: int, to_address: int, kind: str, instruction: str,
     source: str, evidence: Evidence,
     function: str | None = None, target_name: str | None = None)

XrefResult(xrefs: list[Xref], scanned_sections: list[str], scanned_bytes: int,
           truncated: bool, evidence: Evidence,
           warnings: tuple[str, ...] = (), indirect_skipped: int = 0)
```

- `kind` is one of `call`, `jump`, `branch`, `call_import`, `call_indirect`.
- For `call_import` / `call_indirect`, `to_address` is the **pointer slot**, not
  the callee (the callee is only known at run time).
- `source` is `capstone.direct_call`, `capstone.direct_jump`,
  `capstone.conditional_branch`, or the import-slot equivalent; confidence is
  `certain` for direct operands and `medium` for slots.
- `truncated` means the `max_bytes` budget cut the scan; `scanned_bytes` and
  `scanned_sections` say exactly what was covered.
- `indirect_skipped` counts register/memory targets deliberately not resolved.


## `codevanta.analysis.cfg`: control-flow graphs

```python
from codevanta.analysis.cfg import (
    build_cfg, build_recursive_cfg, FunctionCFG, BasicBlock,
)

build_cfg(path: str | Path, info: BinaryInfo, start: int,
          max_instructions: int = 2000, max_blocks: int = 500) -> FunctionCFG

build_recursive_cfg(path: str | Path, info: BinaryInfo, start: int,
                    max_instructions: int = 2000, max_blocks: int = 500,
                    resolve_indirect: bool = False,
                    max_jump_tables: int = 8,
                    max_table_entries: int = 256) -> FunctionCFG
```

`build_cfg` is a linear sweep of one region; block boundaries come from leader
and terminator rules. `build_recursive_cfg` is the same sweep plus optional
indirect-branch resolution through
`codevanta.analysis.jump_tables.resolve_jump_table`.

```python
FunctionCFG(function_address: int, function_name: str | None,
            blocks: list[BasicBlock], instruction_count: int,
            truncated: bool, evidence: Evidence,
            warnings: tuple[str, ...] = ())

BasicBlock(start: int, end: int, instructions: list[dict[str, Any]],
           successors: tuple[int, ...], terminator: str | None,
           evidence: Evidence)
```

Successors are sorted and deduplicated. Indirect branches stay unresolved. The
graph is `medium` confidence: **block boundaries are heuristic, not proven.**

## `codevanta.analysis.callgraph`: call graphs

```python
from codevanta.analysis.callgraph import build_call_graph, CallGraph

build_call_graph(path: str | Path, info: BinaryInfo,
                 functions: list[FunctionCandidate] | None = None,
                 max_functions: int = 2000,
                 max_edges: int = 20000) -> CallGraph
```

Edges come from direct `call` references, plus calls through a pointer slot that
resolves to a known import (the target node is labelled with the import name).
Jumps, conditional branches and unresolved indirect calls produce no edges.

```python
CallGraph(nodes: list[CallGraphNode], edges: list[CallGraphEdge],
          truncated: bool, evidence: Evidence,
          warnings: tuple[str, ...] = ())

CallGraphNode(address: int | None, label: str, kind: str, confidence: str)
CallGraphEdge(source: int | None, target: int | None, from_address: int,
              label: str = "call")
```

`CallGraph.to_dict()` returns the CODEVANTA payload; `CallGraph.to_graph_model()`
returns the generic `{nodes, edges}` model consumed by the exporters. Every call
target that is not a known candidate becomes an `external` node.

**Caller attribution is heuristic** — the nearest function candidate at or below
the call site inside the same section — so the graph is `medium` confidence, uses
the call address as the source for unattributable sites, and states so in
`warnings`. Check `truncated` and `warnings` before assuming completeness.
Defaults: `DEFAULT_MAX_FUNCTIONS = 2000`, `DEFAULT_MAX_EDGES = 20000`,
`MAX_LIMIT = 200000`.

## Graph export formats

All three exporters take the graph **model** (`CallGraph.to_graph_model()`) and
share the same bounds (`DEFAULT_MAX_NODES = 5000`, `DEFAULT_MAX_EDGES = 20000`,
`DEFAULT_TITLE = "CODEVANTA graph"`).

```python
# DOT and GraphML — codevanta.analysis.graph_export
to_dot(graph: dict[str, Any], title: str = "CODEVANTA graph",
       max_nodes: int = 5000, max_edges: int = 20000) -> str
to_graphml(graph: dict[str, Any], title: str = "CODEVANTA graph",
           max_nodes: int = 5000, max_edges: int = 20000) -> str
validate_graph(graph: Any, max_nodes: int = 5000, max_edges: int = 20000) -> dict[str, Any]
sanitize_text(value: str) -> str

# Self-contained HTML viewer — codevanta.analysis.html_view
to_html(graph: Any, title: str = "CODEVANTA graph",
        max_nodes: int = 5000, max_edges: int = 20000) -> str
```

Exporters are dependency-free, order their output deterministically, escape and
sanitize text strictly, and raise `GraphExportError` for a structurally invalid
model or one exceeding the node/edge caps. `to_html` produces one offline file
with no external assets. The CLI entry point is `codevanta callgraph`.


## `codevanta.analysis.binary_diff`: binary diff

```python
from codevanta.analysis.binary_diff import diff_infos, diff_binaries, BinaryDiff, FunctionDelta

diff_binaries(left_path: str | Path, right_path: str | Path,
              max_functions: int = 5000, deep: bool = False,
              semantic: bool = False, threshold: float = 0.9) -> BinaryDiff

diff_infos(left_info: BinaryInfo, right_info: BinaryInfo,
           left_functions: Sequence[FunctionCandidate],
           right_functions: Sequence[FunctionCandidate],
           max_functions: int = 5000, deep: bool = False,
           semantic: bool = False, threshold: float = 0.9) -> BinaryDiff
```

`diff_binaries` loads and diffs; `diff_infos` diffs already-loaded metadata (use
it when you already have the `BinaryInfo` and `FunctionCandidate` lists).

```python
BinaryDiff(left_path: str, right_path: str, identical: bool,
           functions_added: tuple[FunctionDelta, ...],
           functions_removed: tuple[FunctionDelta, ...],
           functions_changed: tuple[FunctionDelta, ...],
           sections_added: tuple[str, ...], sections_removed: tuple[str, ...],
           imports_added: tuple[str, ...], imports_removed: tuple[str, ...],
           exports_added: tuple[str, ...], exports_removed: tuple[str, ...],
           evidence: Evidence, warnings: tuple[str, ...] = ())

FunctionDelta(address: int, name: str | None, change: ChangeKind,
              left: dict[str, Any] | None, right: dict[str, Any] | None,
              evidence: Evidence, left_digest: str | None = None,
              right_digest: str | None = None, similarity: float | None = None)
```

Functions are matched by address first, then by name after moving — that is what
a `functions_changed` entry with differing `left`/`right` records expresses.

`deep=True` adds a normalized-instruction fingerprint to address-matched
functions (`left_digest` / `right_digest`). **Equal digests are shape equality,
not byte equality**, and different digests are not a semantic difference.

`semantic=True` scores the pairs left over by address and name matching and
reports the best pairs reaching `threshold` as a single `changed` entry carrying
`FunctionDelta.similarity` (a `float` in `0.0 .. 1.0`, otherwise `None`). So a
moved function stops being a removal plus an addition. **The score is shape
evidence, not proof of equivalence.**

`threshold` is validated even when `semantic` is `False`. Check `warnings`
before assuming the comparison is complete.

### Semantic threshold constants

| Constant | Value | Meaning |
| --- | --- | --- |
| `DEFAULT_SEMANTIC_THRESHOLD` | `0.9` | Default `threshold`. |
| `MIN_SEMANTIC_THRESHOLD` | `0.0` | Lower bound (inclusive). |
| `MAX_SEMANTIC_THRESHOLD` | `1.0` | Upper bound (inclusive). |
| `MAX_SEMANTIC_PAIRS` | `4096` | Cap on leftover pairs scored. |
| `MAX_DEEP_FINGERPRINTS` | `1000` | Cap on address-matched pairs fingerprinted per side. |
| `SEMANTIC_MAX_INSTRUCTIONS` | `2000` | Instructions decoded per function for scoring. |
| `DEFAULT_MAX_INSTRUCTIONS` / `DEEP_MAX_INSTRUCTIONS` | `2000` | Per-function decode budget. |
| `DEFAULT_MAX_FUNCTIONS` | `5000` | Function-table cap. |
| `MIN_MAX_FUNCTIONS` / `MAX_MAX_FUNCTIONS` | `1` / `20000` | `max_functions` range. |

## `codevanta.analysis.function_hash`: fingerprints and similarity

```python
from codevanta.analysis.function_hash import (
    function_fingerprint, normalized_tokens, function_similarity,
    normalize_instruction, FunctionFingerprint, SimilarityResult,
)

function_fingerprint(path: str | Path, info: BinaryInfo, address: int,
                     max_instructions: int = 2000) -> FunctionFingerprint

normalized_tokens(path: str | Path, info: BinaryInfo, address: int,
                  max_instructions: int = 2000) -> tuple[str, ...]

function_similarity(path_a: str | Path, info_a: BinaryInfo, address_a: int,
                    path_b: str | Path, info_b: BinaryInfo, address_b: int,
                    max_instructions: int = 2000) -> SimilarityResult

normalize_instruction(instruction: IRInstruction) -> str
```

| Function | Returns |
| --- | --- |
| `function_fingerprint` | `FunctionFingerprint(address, digest, instruction_count, truncated, evidence)` — a SHA-256 (`DIGEST_ALGORITHM = "sha256"`) over the normalized instruction shapes. |
| `normalized_tokens` | The token tuple the digest is built from, for inspection. |
| `function_similarity` | `SimilarityResult(score, shared, left_total, right_total, evidence, warnings)` — multiset overlap (`shared` token occurrences over the union) in `0.0 .. 1.0`. |
| `normalize_instruction` | One instruction reduced to its shape: numeric literals, frame offsets and branch targets masked, whitespace normalized. |

Because operands are masked, **equal digests mean equal mnemonic/operand
structure, not byte equality.** `truncated` means the digest covers only a
prefix. `SimilarityResult.warnings` names a side truncated to the budget, so only
prefixes were compared. The score is shape evidence at `medium` confidence — a
relocated or recompiled copy usually scores `1.0`, while two structurally similar
functions can score `1.0` without sharing meaning.
Bounds: `DEFAULT_MAX_INSTRUCTIONS = 2000`, `MIN_MAX_INSTRUCTIONS = 1`,
`MAX_MAX_INSTRUCTIONS = 100000`.


## `codevanta.analysis.type_recovery`: struct suggestions

```python
from codevanta.analysis.type_recovery import (
    suggest_struct, suggest_structs, StructSuggestion, SuggestedField,
    ArrayGroup, FieldAccess, parse_memory_operands,
    WidthConflictWarning, SignednessConflictWarning, WindowOverlapWarning,
)

suggest_struct(path: str | Path, info: BinaryInfo, start: int,
               max_instructions: int = 2000, max_fields: int = 64,
               include_stack: bool = False) -> StructSuggestion

suggest_structs(path: str | Path, info: BinaryInfo, addresses: Collection[int],
                max_instructions: int = 2000, include_stack: bool = False,
                max_windows: int = 16) -> StructSuggestion
```

`suggest_struct` decodes one bounded window and aggregates the memory operands
into suggested fields. `suggest_structs` decodes each address once and folds the
windows into **one** merged suggestion: one field per offset, counters summed,
earliest `first_access` kept, widest width winning on conflict, and `alignment` /
`array_groups` / `truncated` recomputed from the merged field set. At most
`max_windows` addresses are accepted (`MAX_MERGED_WINDOWS = 16`); duplicate or
non-executable addresses are rejected.

Only `[reg]`, `[reg + 0xNN]` and `[reg - 0xNN]` operands are read; index, scale
and segment forms are skipped. `lea`, `nop` and `prefetch*` are skipped too,
because they do not access memory. Width comes from the Intel size keyword;
direction from the operand position (`cmp`, `test`, `call`, `jmp`, `push` are
always reads).

```python
StructSuggestion(
    address: int, fields: tuple[SuggestedField, ...], instruction_count: int,
    max_fields: int, truncated: bool, include_stack: bool,
    evidence: Evidence, alignment: int | None = None,
    array_groups: tuple[ArrayGroup, ...] = (), memory_access_count: int = 0,
)

SuggestedField(offset: int, width: int, read_count: int, write_count: int,
               first_access: int | None, evidence: Evidence,
               signed: bool | None = None)

ArrayGroup(offset: int, stride: int, count: int, width: int, evidence: Evidence)
FieldAccess(offset: int, width: int, direction: str, base_register: str,
            address: int, instruction: str)
```

| `StructSuggestion` field | Notes |
| --- | --- |
| `fields` | One entry per offset, ascending. |
| `alignment` | gcd of the absolute non-zero offsets, or `None` when fewer than two exist. |
| `array_groups` | Maximal runs of ≥ 3 equally wide, equally spaced fields. |
| `memory_access_count` | How many memory operands fed the suggestion. |
| `truncated` | `max_fields` dropped further offsets. |
| `include_stack` | Whether `[rsp]`/`[rbp]`-relative accesses were included. |

### `SuggestedField.signed`

`True` when every signedness hint at that offset came from a sign-extending
operation (`movsx`, `movsxd`, `sar`, `idiv`, `imul`, and the sign-extending
`cwd`/`cbw`); `False` when every hint came from a zero-extending or unsigned one
(`movzx`, `shr`, `div`, `mul`); `None` when there was no hint **or** the hints
contradicted each other. `None` means "no signedness evidence" — never "safe".

When `signed` is `None` the key is omitted from `to_dict()` entirely, so an
unclassified field's JSON stays byte-identical to the pre-signedness output.

### The three warning classes

All three subclass `UserWarning` and are emitted through `warnings.warn`, so a
caller that does not care can filter them.

| Class | Raised when | Effect |
| --- | --- | --- |
| `WidthConflictWarning` | Merged windows disagree about one offset's dominant width. | The widest width wins; the warning names the offset and both widths. A window that only saw a `dword` is not evidence against the `qword` another window saw. |
| `SignednessConflictWarning` | One offset is accessed as both signed and unsigned. | The field is reported with `signed=None`, exactly like an offset with no evidence at all. |
| `WindowOverlapWarning` | Two merged windows decode the same instruction bytes. | The overlap is reported so double-counted accesses are not read as independent evidence. |

Everything here is a heuristic at `medium` confidence: a recovered field is a
hypothesis about how a function treats memory around one base register, not a
verified type, and it says nothing about a field's purpose or lifetime.
Bounds: `DEFAULT_MAX_FIELDS = 64`, `MIN_MAX_FIELDS = 1`, `MAX_MAX_FIELDS = 512`,
`DEFAULT_MAX_INSTRUCTIONS = 2000`, `MIN_MAX_INSTRUCTIONS = 1`,
`MAX_MAX_INSTRUCTIONS = 100000`, `MIN_MERGED_WINDOWS = 1`,
`MAX_MERGED_WINDOWS = 16`. `parse_memory_operands(instruction,
include_stack=False, pointer_width=8)` exposes the per-instruction access reader,
with `READ` / `WRITE` as the `direction` values.


## `codevanta.analysis.decompile`: pseudo-C rendering

```python
from codevanta.analysis.decompile import (
    CallSite, PseudoFunction, decompile_function,
    DEFAULT_MAX_INSTRUCTIONS, DEFAULT_MAX_BLOCKS,
    MAX_MAX_INSTRUCTIONS, MAX_MAX_BLOCKS,
)

decompile_function(path, info, address,
                   max_instructions=DEFAULT_MAX_INSTRUCTIONS,   # 2000
                   max_blocks=DEFAULT_MAX_BLOCKS) -> PseudoFunction
```

Renders one function as readable pseudo-C from the blocks of
`build_recursive_cfg`, with names from `discover_functions`. Nothing is decoded
twice and nothing is executed. `PseudoFunction` is `address`, `name`, `lines`
(body lines without the header and braces), `body` (header comment + signature +
braces + body), `call_sites`, `block_count`, `instruction_count`, `truncated`,
`evidence`, and a JSON-safe `to_dict()`; each `CallSite` is `address`, `target`
(`None` for an indirect transfer), `name` and `kind` (`"call"`, `"jump"` for a
tail call, `"unknown"` for an unresolved indirect jump).

**What the text can mean.** The argument count is the ABI argument registers
read before the first `call` (`rdi`/`rsi`/`rdx`/`rcx`/`r8`/`r9` plus aliases on
x86-64, `ecx`/`edx` on x86), capped at six; argument registers are renamed
`a0`..`a5`, frame slots become `local_0x8`/`arg_0x8`, other memory operands
`*(u64*)(...)` (`u32` for 32-bit files). Statements are emitted only where the
mnemonic alone justifies them (`mov`/`lea`, compound and unary assignments), and
each keeps its raw instruction text as a trailing comment; every other
instruction keeps only the comment. Control flow is structured as `if`/`else`,
`while (1)` with `continue;`/`break`, or `goto LABEL_<addr>;`, and conditions
come from `cmp`/`test` plus the branch mnemonic (`(unsigned)` for `jb`..`ja`).

```python
from codevanta.analysis.decompile import decompile_function
from codevanta.core.loader import BinaryLoader

path = "samples/pe64_text.bin"
info = BinaryLoader().load(path)
function = decompile_function(path, info, info.entry_point)
print(function.name, function.instruction_count, function.truncated)
print(function.evidence.confidence.value, function.evidence.source)
print(function.lines[0])
```

```text
codevanta_sample_main 8 False
low decompile.pseudo_c
rsp -= 0x28;  /* sub rsp, 0x28 */
```

**Evidence.** Always `Confidence.LOW`, `source="decompile.pseudo_c"`,
`method="mnemonic_heuristic"`, with a detail string naming the instruction and
block counts and the "nothing is executed" caveat — and the same facts repeated
in the header comment inside the text. CFG warnings are appended there as
` * warning: ...` lines (at most six plus `(+N more)`).

**Bounds.** `DEFAULT_MAX_INSTRUCTIONS = 2000`,
`DEFAULT_MAX_BLOCKS = 500`, `MAX_MAX_INSTRUCTIONS = MAX_MAX_BLOCKS =
MAX_DISASSEMBLY_COUNT = 100000`. A cut-short rendering sets `truncated` and
warns; `AnalysisError` is raised for an address outside an executable section, a
budget outside `1..MAX`, or a region that decodes to no instruction.


## `codevanta.analysis.decompilers`: decompiler providers

```python
from codevanta.analysis.decompilers import (
    AUTO, LANGUAGE,
    AngrBackend, GhidraBackend, NativeBackend,
    BackendAvailability, BackendResult, DecompilerBackend,
    available_backends, get_backend, decompile_function, supported_backends,
)

available_backends() -> tuple[BackendAvailability, ...]     # ghidra, angr, native
get_backend(name) -> DecompilerBackend                      # AnalysisError if unknown
decompile_function(path, info, address, backend=AUTO,       # "auto"
                   max_instructions=2000, max_blocks=500) -> BackendResult
```

`BackendAvailability` is `name`, `available`, a non-empty `reason` (what was
detected, or what is missing plus an install hint) and `requires`. Probes never
raise and never install: a missing package is `available=False`, never an
`ImportError`. `BackendResult` is `text` (never empty), `backend` (the provider
that actually rendered it), `language` (`LANGUAGE = "c"`), `warnings` and
`evidence`; `to_dict()` is JSON-safe.

| Backend | `requires` | Runs when |
| --- | --- | --- |
| `ghidra` | `("pyghidra", "ghidra")` | `pyghidra` imports **and** `GHIDRA_INSTALL_DIR` holds `support/`, `ghidraRun` or `ghidraRun.bat` |
| `angr` | `("angr",)` | `angr` imports |
| `native` | `()` | always |

`backend="auto"` prefers `ghidra`, then `angr`, then `native`, and records one
warning per skipped backend; `"angr"`/`"ghidra"` are strict and raise
`AnalysisError` naming the backend and its probe reason instead of substituting
another provider. Budgets are validated once (`require_budget`) before any
backend runs.

```python
from codevanta.analysis.decompilers import available_backends, decompile_function
from codevanta.core.loader import BinaryLoader

path = "samples/pe64_text.bin"
info = BinaryLoader().load(path)
print([(probe.name, probe.available) for probe in available_backends()])
result = decompile_function(path, info, info.entry_point, backend="native")
print(result.backend, result.language, len(result.warnings))
print(result.evidence.extra)
```

```text
[('ghidra', False), ('angr', False), ('native', True)]
native c 0
{'backend': 'native', 'max_instructions': 2000, 'max_blocks': 500}
```

Those three lines are this machine's answer (no `pyghidra`, no `angr`); see
[`docs/phase3.md`](phase3.md#how-to-unlock-real-c-output) for installing them.


## `codevanta.analysis.emulate`: bounded offline emulation

```python
from codevanta.analysis.emulate import (
    EMULATOR_AVAILABLE, emulator_status, emulate_function, resolve_indirect_target,
    xor_bytes, decrypt_string_loop, DECRYPT_OPS,
    EmulationResult, StopReason,
    DEFAULT_MAX_INSTRUCTIONS, MAX_MAX_INSTRUCTIONS,
    DEFAULT_STACK_SIZE, MAX_STACK_SIZE, PAGE_SIZE,
    MAX_SECTION_BYTES, MAX_TOTAL_MAPPED,
    MAX_INITIAL_BLOCKS, MAX_INITIAL_BLOCK_BYTES, MAX_MEMORY_WRITES,
    STACK_BASE_64, STACK_BASE_32,
)

emulate_function(path, info, address, initial_registers=None, initial_memory=None,
                 max_instructions=DEFAULT_MAX_INSTRUCTIONS,   # 2000
                 stack_size=DEFAULT_STACK_SIZE) -> EmulationResult   # 0x10000

resolve_indirect_target(path, info, address, initial_registers=None,
                        max_instructions=DEFAULT_MAX_INSTRUCTIONS, *,
                        initial_memory=None) -> int | None
```

The file's bytes are copied into a **private unicorn CPU**; nothing runs on the
host, no host syscall or library is invoked, and a call into an import simply
leaves the mapped image. Only ABI entry state is seeded (`rip`/`eip` at
`address`, `rsp`/`rbp` (`esp`/`ebp`) near the top of a stack mapped at
`STACK_BASE_64` (`0x7fff00000000`) or `STACK_BASE_32` (`0x7e000000`)); argument
registers are never guessed. `EMULATOR_AVAILABLE` says whether a unicorn build
is importable, and `emulator_status()` returns the empty string when it is (the
reason otherwise).

**Stop reasons** (`StopReason`): `return` (a `ret` left the section region —
`return_value` is set), `budget` (`instructions == max_instructions`, no
`return_value`), `unmapped` (faulting address in `warnings`), `unsupported` (not
x86/x86-64, undecodable, or unicorn missing — `instructions=0`,
`Confidence.UNKNOWN`), `error` (unicorn raised because of the emulated code).

**`EmulationResult`**: `address`, `stopped_reason`, `instructions`,
`return_value`, `registers`, `memory_writes` (`(address, bytes)` in store order),
`indirect_targets`, `warnings`, `evidence` (`source="emulate.unicorn"`,
`method="bounded_cpu_emulation"`, `Confidence.MEDIUM`, mapped `regions` and the
budget in `extra`).

**Bounds**: `MAX_MAX_INSTRUCTIONS = 100000`, `PAGE_SIZE = 0x1000`,
`MAX_STACK_SIZE = 0x1000000`, `MAX_SECTION_BYTES = 0x1000000`,
`MAX_TOTAL_MAPPED = 0x4000000`, `MAX_INITIAL_BLOCKS = 32`,
`MAX_INITIAL_BLOCK_BYTES = 0x100000`, `MAX_MEMORY_WRITES = 256`.
`AnalysisError` is only raised for an invalid request (address not executable or
without file bytes, budget/stack size out of range, unknown register name, a
value that does not fit the machine word, an `initial_memory` block over the
limits); limitations are reported, never raised.

```python
from codevanta.analysis.emulate import emulate_function, resolve_indirect_target
from codevanta.core.loader import BinaryLoader

path = "samples/pe64_text.bin"
info = BinaryLoader().load(path)
result = emulate_function(path, info, info.entry_point)
print(result.stopped_reason, result.instructions, hex(result.return_value))
print(result.evidence.confidence.value, result.evidence.extra["stack_base"])
print(resolve_indirect_target(path, info, info.entry_point))
```

```text
return 9 0x2a
medium 0x7fff00000000
None
```

`resolve_indirect_target` returns the target of the first indirect jump/call, and
`None` means "not resolved" — never "no target". `xor_bytes(data, key)` and
`decrypt_string_loop(data, key, *, key_step=0, op="xor", terminators=(0,))` are
pure byte functions (`DECRYPT_OPS = ("xor", "add", "sub")`) that apply a
recovered key without executing anything; see
[`docs/phase3.md`](phase3.md#the-xorstring-helpers).


## `codevanta.analysis.symbolic`: branch-decision path exploration

```python
from codevanta.analysis.symbolic import (
    EMULATOR_AVAILABLE, ANGR_AVAILABLE, angr_available,
    explore_paths, explore_with_angr,
    PathExploration, Entry, Branch,
    DEFAULT_MAX_PATHS, MAX_MAX_PATHS,          # 64 / 4096
    DEFAULT_MAX_STEPS, MAX_MAX_STEPS,          # 2000 / 200_000
)

explore_paths(path, info, address, max_paths=DEFAULT_MAX_PATHS,
              max_steps=DEFAULT_MAX_STEPS, initial_registers=None, *,
              stack_size=emulate.DEFAULT_STACK_SIZE) -> PathExploration

explore_with_angr(path, info, address, max_paths=64,
                  initial_registers=None) -> PathExploration   # ceiling 4096
```

`explore_paths` walks the decision tree of one function breadth-first on a
private unicorn CPU — the file's bytes are copied onto it, exactly like
`emulate_function`, and nothing is executed on the host. The direction real
emulation produced is recorded as `"observed"`; the opposite direction is
enqueued with its guarding flags or loop counter rewritten and recorded as
`"seeded"` — an assumption about feasibility, never a solved constraint. There
are no symbolic variables, no path predicates, no constraint solving anywhere
in the module.

**`Branch`**: `address`, `mnemonic`, `taken`, `target`, `basis`
(`"observed"`/`"seeded"`), `note` (the exact seed description; empty when
observed). **`Entry`**: `index`, `decisions`, `taken_targets`, `registers`
(end-of-path snapshot), `return_value` (`rax`/`eax` only when the path reached
a `ret` that left the section — otherwise `None`, even if `rax` holds a value),
`stopped_reason` (`"return"`, `"budget"`, `"blocked"` or `"unmapped"`),
`instructions` (replays included), `warnings`, and a `seeded` property counting
forced directions. **`PathExploration`**: `address`, `explorer`
(`"unicorn"`/`"angr"`), `architecture`, `bitness`, `max_paths`, `max_steps`
(`0` for the angr bridge), `steps`, `complete`, `entries`, `warnings`,
`evidence`, and the `paths` / `unresolved` / `return_values` properties.
`complete` is `True` only when nothing was left unexplored **and** every
reported path reached a `ret`; `unresolved` counts the paths that ended
`blocked` or `unmapped`. All three dataclasses have JSON-safe `to_dict()`
methods (hex addresses).

Only x86 and x86-64 are supported (the register and stack vocabulary is
x86-specific); anything else raises `AnalysisError`. So do a missing unicorn
build, an unusable address, an unknown seed register, a value that does not fit
the machine word and an out-of-range limit — validation happens before anything
runs. Register names follow the emulator's vocabulary (`{"edi": 0}` seeds both
paths).

```python
from codevanta.analysis.symbolic import angr_available, explore_paths
from codevanta.core.loader import BinaryLoader

path = "samples/pe64_text.bin"
info = BinaryLoader().load(path)
exploration = explore_paths(path, info, info.entry_point)
print(exploration.explorer, exploration.complete, exploration.paths,
      exploration.return_values)
print(angr_available())
```

```text
unicorn True 1 (42,)
False
```

`angr_available()` / `ANGR_AVAILABLE` probe for a module named `angr` without
importing it; `explore_with_angr` imports lazily and raises `AnalysisError`
naming the extra (`pip install -e ".[decompilers]"`) when it is missing. The
bridge explores to the `ret` addresses a bounded linear sweep found and reports
`max_steps=0` because angr owns the stopping; states still active or errored
when it stops are counted in a warning, never silently dropped.


## `codevanta.analysis.dataflow`: def-use and constant folding

```python
from codevanta.analysis.dataflow import (
    analyze_dataflow, DataFlowSummary, Definition, Use,
    DEFAULT_MAX_INSTRUCTIONS, MAX_MAX_INSTRUCTIONS,   # 2000 / 8192
    DEFAULT_MAX_BLOCKS, MAX_MAX_BLOCKS,               # 500 / 4096
    KIND_CONST, KIND_COPY, KIND_ARITHMETIC, KIND_UNKNOWN,
    READ, WRITE,
)

analyze_dataflow(path, info, address,
                 max_instructions=DEFAULT_MAX_INSTRUCTIONS,
                 max_blocks=DEFAULT_MAX_BLOCKS) -> DataFlowSummary
```

The CFG is built with `build_recursive_cfg` from `address` and walked once,
forward: every read is resolved against the definitions seen so far (and
recorded in `reaching_definition`), every write replaces what the register held.
Only provable shapes fold into constants — `mov` immediates, register copies,
`add`/`sub`/`xor` of two known values, rip-relative loads — and a folded value
is masked to the written register's width; only full-width writes carry values.
Register aliases are normalised (`eax` → `rax` on a 64-bit binary; `eax` stays
canonical on a 32-bit one), and a `call` clobbers the caller-saved registers.

**`Definition`**: `address`, `register` (canonical), `kind` (`const`, `copy`,
`arithmetic` or `unknown`), `value` (`None` when unknown), `source_register`
(for copies). **`Use`**: `address`, `register`, `read_or_write`. Within one
instruction the reads come before the write it makes.
**`DataFlowSummary`**: `address`, `definitions` and `uses` in ascending address
order, `constant_registers` (only what is still provably known after the pass),
`reaching_definition` (`(register, use address) -> definition address`; reads
with no definition in the region are absent and warned about instead),
`warnings` (each stated once, capped at `MAX_UNDEFINED_WARNINGS = 8`),
`evidence`. `to_dict()` is JSON-safe; `reaching_definition` keys render as
`"register@0x<use>"`.

The pass is a linearization, not a fixpoint: a join takes the
highest-addressed predecessor. What is reported stays sound one definition at a
time — a value is only folded from instructions the summary itself proves, and
only the last definition of a register survives, so no two conflicting origins
are ever claimed. 32-bit and 64-bit binaries only; a bad address, an
out-of-range budget or a non-executable address raise `AnalysisError`.

```python
from codevanta.analysis.dataflow import analyze_dataflow
from codevanta.core.loader import BinaryLoader

path = "samples/elf64_text.bin"
info = BinaryLoader().load(path)
summary = analyze_dataflow(path, info, info.entry_point)
print(len(summary.definitions), len(summary.uses), dict(summary.constant_registers))
print(summary.definitions[0].to_dict())
```

```text
1 3 {}
{'address': '0x401001', 'register': 'rbp', 'kind': 'copy', 'value': None, 'source_register': 'rsp'}
```


## `codevanta.analysis.evidence_bundle`: tamper-evident bundles

```python
from codevanta.analysis.evidence_bundle import (
    build_bundle, verify_bundle, read_bundle, write_bundle, dumps_bundle,
    hash_subject, entries_digest, canonical_json,
    Bundle, BundleManifest, BundleVerification,
    DEFAULT_ALGORITHM, SUPPORTED_ALGORITHMS,      # "sha256" / {"sha256"}
    MAX_ENTRIES, MAX_PAYLOAD_BYTES,               # 256 / 16 MiB
    MEDIA_TYPE_JSON, SUBJECT_CHUNK_BYTES, TOOL_VERSION,
)

build_bundle(subject_path, payloads, *, label=None) -> Bundle
verify_bundle(bundle_or_dict, *, subject_path=None) -> BundleVerification
read_bundle(path) -> Bundle
write_bundle(bundle, path) -> Path
dumps_bundle(bundle) -> str
hash_subject(subject_path) -> str
entries_digest(entries) -> str
canonical_json(payload) -> str
```

`build_bundle` streams the subject binary through SHA-256 in 1 MiB chunks and
reduces every payload to canonical JSON (`sort_keys`, no spaces, ASCII,
NaN-free) before hashing it, so both digests are recomputable from the document
alone. Entries are sorted by name, so two builds from the same inputs serialise
to identical bytes regardless of insertion order.

**`BundleManifest`**: `created_at` (ISO-8601 UTC), `tool_version`,
`subject` (the file name, or the caller's `label`), `subject_sha256`,
`entry_count`, `entries_sha256` (the combined table digest), `algorithm`
(`"sha256"` only). **`Bundle`**: `manifest`, `entries` (read-only mapping of
name to `{"sha256", "bytes", "media_type"}`), `names` and `payload(name)`
(decoded from the exact canonical text that was hashed) — the dataclass is
frozen and the mappings are proxies, so a built bundle cannot be mutated behind
the verifier's back. **`BundleVerification`**: `passed`, `problems`,
`manifest`.

`verify_bundle` runs two independent checks: per entry (re-canonicalise,
re-hash, re-measure against the recorded `sha256`/`bytes`) and per table
(`entries_digest` over the recorded table against
`manifest.entries_sha256` — this catches added, removed or renamed entries,
including an edited `sha256` whose payload was left alone). `entry_count` and
`algorithm` are checked too. Structurally damaged input is reported as a
problem rather than raised; `read_bundle` is the strict counterpart, and
deliberately does *not* verify digests, so a caller can round-trip and then
re-verify.

```python
import json

from codevanta.analysis.evidence_bundle import build_bundle, dumps_bundle, verify_bundle

bundle = build_bundle("samples/elf64_text.bin", {"report": {"format": "ELF"}})
text = dumps_bundle(bundle)
print(verify_bundle(bundle, subject_path="samples/elf64_text.bin").passed)

tampered = json.loads(text)
tampered["entries"]["report"]["payload"]["format"] = "PE"
verdict = verify_bundle(tampered)
print(verdict.passed, verdict.problems[0][:60])
```

```text
True
False entry 'report': payload sha256 mismatch (expected 9d2a96643a3699d65c1a
```

`build_bundle` raises `AnalysisError` for a missing/unreadable subject, a
non-mapping payload set, a blank entry name, more than `MAX_ENTRIES` entries,
or a payload that is not JSON-serialisable or exceeds `MAX_PAYLOAD_BYTES`.
`write_bundle` refuses nothing about the path — the CLI's rule that the output
must not overwrite the subject lives in `codevanta evidence-bundle` and
`scripts/report_bundle.py`, which also verify what they wrote.


## `codevanta.analysis.trace`: trace replay and attribution

```python
from codevanta.analysis.trace import (
    parse_gdb_trace, parse_frida_trace, TraceHit, TraceReport,
    MAX_TRACE_LINES, MAX_TRACE_HITS,   # 100_000 each
    MAX_BACKTRACE_FRAMES,              # 64
    MAX_WARNINGS,                      # 50
)

parse_gdb_trace(text, *, info=None, functions=(),
                max_lines=MAX_TRACE_LINES, max_hits=None) -> TraceReport

parse_frida_trace(text, *, info=None, functions=(),
                  max_lines=MAX_TRACE_LINES, max_hits=None) -> TraceReport
```

Nothing here launches anything: the input is what a generated session script
already printed. `parse_gdb_trace` reads the `HIT <address> <reg>=<value> …`
lines, the `BACKTRACE` marker plus `#N 0x…` frames after each hit, and skips
gdb's own noise; a `LIMIT` line marks the report `truncated`.
`parse_frida_trace` reads JSON-lines messages (`{"hit", "address", "tid",
"args"}`); a malformed line becomes a warning, `{"event": "limit"}` truncates
and `{"event": "error"}` warns. The only exception raised is `AnalysisError`,
for an out-of-range `max_lines`/`max_hits`.

**`TraceHit`**: `index`, `kind` (`"breakpoint"`/`"message"`), `address`,
`function`, `function_name`, `registers` (gdb's register snapshot; Frida's
`tid` plus up to four `arg0..arg3`), `backtrace` (innermost first; empty for
Frida). **`TraceReport`**: `provider`, `hits` (kept, in session order),
`total_hits` (exceeds `len(hits)` only when a bound cut the tail),
`truncated`, `unique_addresses`, `function_coverage` (hits per attributed
function start), `warnings` (capped at `MAX_WARNINGS`), `evidence`. `to_dict()`
is JSON-safe with hex addresses.

**Attribution** — a hit is attributed to the candidate with the greatest start
`<= address` that either contains the address within its known `size` or, when
the size is unknown, still starts before the next candidate; a candidate's
extent comes from its symbol size, else from the enclosing executable section,
and an address outside every candidate stays **unattributed** rather than being
guessed onto the nearest symbol. (Before the phase 6 fix, an unknown size was
treated as unbounded, so a hit above the last function was attributed to it.)

```python
from codevanta.analysis.trace import parse_gdb_trace
from codevanta.core.functions import discover_functions
from codevanta.core.loader import BinaryLoader

path = "samples/elf64_text.bin"
info = BinaryLoader().load(path)
with open("samples/gdb_trace.log", encoding="utf-8") as handle:
    report = parse_gdb_trace(handle.read(), info=info,
                             functions=discover_functions(info))
print(report.provider, report.total_hits, len(report.unique_addresses),
      report.function_coverage)
```

```text
gdb 3 2 {4198400: 3}
```

(`4198400` is `0x401000`: the single unnamed entry-point candidate absorbed all
three hits.) The committed `samples/gdb_trace.log` and
`samples/frida_trace.jsonl` replay through both parsers.


## `codevanta.analysis.dynamic`: provider probes and session scripts

```python
from codevanta.analysis.dynamic import (
    available_backends, provider_status,
    build_gdb_script, build_frida_script,
    script_file_name, attach_command,
    DynamicAvailability, DynamicScript,
    PROVIDERS, SCRIPT_FILE_NAMES,             # ("gdb", "frida")
    DEFAULT_MAX_HITS, MAX_MAX_HITS,           # 64 / 100_000
    BACKTRACE_DEPTH, MAX_FRIDA_ARGS,          # 8 / 4
)

available_backends() -> tuple[DynamicAvailability, ...]
provider_status(provider: str) -> DynamicAvailability

build_gdb_script(path, info, addresses, *, max_hits=DEFAULT_MAX_HITS,
                 follow_forks=False) -> DynamicScript
attach_command(provider, path, script, pid=None) -> tuple[str, ...]
```

Dynamic analysis needs a debugger, and a debugger needs a host, so this module
does the one part that is always safe: decide whether a provider can run here,
and write the script that provider should execute. Nothing imports gdb or
Frida, nothing starts a process. Probes never raise: an absent debugger is
`available=False` with a non-empty `reason` (`version` stays `None` on purpose
— probing a version would mean executing the provider).

**`DynamicAvailability`**: `name`, `available`, `reason`, `requires`,
`version`. **`DynamicScript`**: `provider`, `text` (deterministic — the same
inputs give byte-identical scripts), `entry_commands` (the `set`/`break` lines,
or the per-address `Interceptor.attach` expressions), `notes` (address
semantics, hit/backtrace bounds, what the script does not do). The gdb script
disables pagination, confirmation prompts and ASLR, prints
`HIT <address> <reg>=<value> …` per hit, `BACKTRACE` +
`BACKTRACE_DEPTH` `bt` frames, exits after `max_hits` with a `LIMIT` line and
quits with `DONE <n> hits`; the Frida hook snapshots `MAX_FRIDA_ARGS` argument
registers and detaches its listeners at the limit. Addresses are validated
(positive, deduplicated, inside an executable section when `info` is given) and
`max_hits` against `MAX_MAX_HITS`; violations raise `AnalysisError`.

`attach_command` returns the exact `argv` — ready for
`subprocess.run(..., shell=False)` — and never a shell string:
`("gdb", "-q", "-batch", "-x", <script>, "--args", <path>)` or
`("frida", "-l", <script>, "-f", <path>)` (`"-p", <pid>` when attaching; a pid
with gdb is refused, because the gdb script ends with `run`). The script's
provider must match, so a gdb script can never be handed to Frida.

```python
from codevanta.analysis.dynamic import attach_command, available_backends, build_gdb_script
from codevanta.core.loader import BinaryLoader

path = "samples/elf64_text.bin"
info = BinaryLoader().load(path)
print([(probe.name, probe.available) for probe in available_backends()])
script = build_gdb_script(path, info, [info.entry_point], max_hits=4)
print(attach_command("gdb", path, script))
print(script.entry_commands[:2])
```

```text
[('gdb', False), ('frida', False)]
('gdb', '-q', '-batch', '-x', 'codevanta-session.gdb', '--args', 'D:\\…\\samples\\elf64_text.bin')
('set pagination off', 'set confirm off')
```

(Probe results are this Windows machine's answer.) The CLI surface is
`codevanta attach`; replaying what such a session printed is
[`codevanta.analysis.trace`](#codevantaanalysistrace-trace-replay-and-attribution).


## `codevanta.storage.session`: persisted sessions

```python
from codevanta.storage.session import (
    SessionStore, SessionRecord, Annotation, SessionError,
)

store = SessionStore(db_path: str | Path)   # missing parent directories are created
```

`":memory:"` gives an ephemeral store. The store is also a context manager
(`with SessionStore(...) as store:`) and has `close()`.

| Method | Returns |
| --- | --- |
| `save(info: BinaryInfo, functions_count: int, strings_count: int, notes: str \| None = None, session_id: str \| None = None)` | `SessionRecord` — a generated 12-character id is used when `session_id` is `None`. |
| `get(session_id: str)` | `SessionRecord \| None` |
| `list(limit: int = 50)` | `list[SessionRecord]`, newest first (clamped to `MAX_LIMIT`). |
| `delete(session_id: str)` | `bool` — `True` when a row was removed. |
| `annotate(session_id: str, address: int, note: str)` | `Annotation` |
| `annotations(session_id: str)` | `_AnnotationList` (a list of `Annotation`, ordered by address). |
| `remove_annotation(session_id: str, address: int)` | `bool` |

```python
SessionRecord(session_id: str, created_at: str, binary_path: str, sha256: str,
              format: str, architecture: str, bitness: int,
              entry_point: int | None, functions: int, strings: int,
              notes: str | None = None)

Annotation(session_id: str, address: int, note: str, created_at: str)
```

Storage is additive: it records a fingerprint and counts, never analysis
verdicts. SQLite via the standard library, parameterized SQL, bounded queries —
no schema migrations yet. Invalid input (an empty or directory database path, a
negative address, a note over `MAX_NOTE_LENGTH = 4000`) raises `SessionError`.
`DEFAULT_LIMIT = 50`, `MAX_LIMIT = 10000`, `SESSION_ID_LENGTH = 12`.

The CLI default database is `$CODEVANTA_DB` (env `SESSION_DB_ENV`), otherwise
`~/.codevanta/sessions.db`; the `codevanta session …` commands and the `--db`
option use the same store.

## `codevanta.plugins`: the plugin SDK

```python
from codevanta.plugins import (
    register, unregister, registry_snapshot, builtin_plugins,
    discover, discovery_warnings, load,
    run_plugin, build_context, canonical_json,
    PluginInfo, AnalysisContext, PluginResult, AnalyzerPlugin,
    MetricsAnalyzer, METRICS_PLUGIN,
    DEFAULT_ENTRY_POINT_GROUP,   # "codevanta.analyzers"
    PLUGIN_KINDS,                # {"analyzer", "exporter", "provider"}
    DEFAULT_MAX_SECONDS,         # 30.0
    DEFAULT_MAX_BYTES,           # 4 MiB
    DEFAULT_MAX_STRINGS,         # 5000
)

register(plugin) -> PluginInfo
unregister(name: str) -> bool
registry_snapshot() -> dict[str, AnalyzerPlugin]
builtin_plugins() -> tuple[PluginInfo, ...]
discover(entry_point_group=DEFAULT_ENTRY_POINT_GROUP) -> tuple[PluginInfo, ...]
discovery_warnings() -> tuple[str, ...]
load(entry_point_group=DEFAULT_ENTRY_POINT_GROUP, name="") -> AnalyzerPlugin

build_context(path, *, address=None, functions=None, budget=None) -> AnalysisContext
run_plugin(plugin, context, max_seconds=DEFAULT_MAX_SECONDS,
           max_bytes=DEFAULT_MAX_BYTES) -> PluginResult
canonical_json(payload) -> bytes
```

An analyser that ships outside the package must not require an edit inside it.
The contract is deliberately tiny — one dataclass in, one mapping out: an
object with `name`, `version`, `description` and an
`analyze(context) -> Mapping` satisfies `AnalyzerPlugin` structurally (a
`Protocol`; it does not have to import CODEVANTA or subclass anything).

**`AnalysisContext`**: `path` (the raw file), `info` (loaded `BinaryInfo`),
`address` (focus; `build_context` defaults it to the entry point),
`functions` (pre-discovered candidates, so a plugin does not repeat core
work), `budget` (read-only mapping of plugin-specific integer limits).
**`PluginInfo`**: `name`, `version` (`"unknown"` when the declaring
distribution has none), `kind`, `entry_point` (`module:attribute`),
`description`. **`PluginResult`**: `plugin`, `payload` (shallow copy),
`elapsed_ms`, `warnings` (lifted out of `payload["warnings"]`), `evidence`
(source `plugin.<name>`, method `plugin.analyze`, `Confidence.MEDIUM` — the
harness vouches for the run, not for the plugin's method). All have JSON-safe
`to_dict()` methods.

Discovery reads distribution entry points without importing them — broken
metadata degrades to a warning (via `discovery_warnings()`), never an
exception — while `load(name=...)` consults the built-in registry first and
imports exactly one entry point lazily; a class where an instance is expected,
a failed import and an unknown name are all `AnalysisError` naming the plugin.
`run_plugin` bounds the call: the canonical-JSON byte cap is enforced *before*
the time budget (an oversized payload is never masked by a slow run), the
elapsed time is measured with `perf_counter` **after** the call returns — the
call is not interruptible, so a hung plugin still hangs the caller, and the
error says so. `register`/`unregister` manage the process-local, lock-guarded
registry (`builtin_plugins()` is the live registry, not a static list, which is
what makes the built-in path testable end to end).

`MetricsAnalyzer` (`METRICS_PLUGIN`, `name="metrics"`, `version="1.0"`) is the
wired-in built-in: function/string counts through the public API, honouring a
`max_strings` budget and warning when the budget makes `string_count` a lower
bound. `canonical_json` is the shared serialisation (sorted keys, compact
separators, ASCII, NaN-free) that the byte cap measures.

```python
from codevanta.plugins import builtin_plugins, build_context, load, run_plugin
from codevanta.core.loader import BinaryLoader

path = "samples/elf64_text.bin"
print([(p.name, p.version, p.kind) for p in builtin_plugins()])
result = run_plugin(load(name="metrics"), build_context(path))
print(result.plugin.name, result.payload["function_count"],
      result.payload["string_count"], result.warnings)
```

```text
[('metrics', '1.0', 'analyzer')]
metrics 1 2 []
```

## `codevanta.gui`: local web dashboard

```python
from codevanta.gui import (
    render_dashboard_html, create_server, create_handler, serve,
    normalize_host, ROUTES, VERSION, MAX_RESPONSE_BYTES,
)

render_dashboard_html(title: str = "CODEVANTA") -> str
create_handler(paths_allowed: bool = True) -> type[BaseHTTPRequestHandler]
create_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer
serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None
normalize_host(host: str) -> str
```

`render_dashboard_html()` returns the single self-contained page (no external
assets). `create_server` returns a **bound but unstarted** server, so tests and
scripts can call `.serve_forever()` / `.shutdown()` themselves; `serve()` binds,
prints the URL, optionally opens a browser, and blocks until `Ctrl+C`. The CLI
equivalent is `codevanta gui` (`--host`, `--port`, `--no-browser`).

**Loopback only.** `create_server` and `serve` refuse any host that is not
`localhost`, `::1` or inside `127.0.0.0/8`, raising `ValueError`. `port=0` picks a
free port. `create_handler(paths_allowed=False)` makes the file-taking routes
reject their `path` parameter, so the handler can be embedded without granting
local file reads.

**`Host` header checked on every request.** Binding to loopback does not stop DNS
rebinding, so the handler validates the `Host` header before it routes anything:
the name must be `127.0.0.1`, `localhost` or `[::1]` and, when the header carries
a port, that port must be the one the request arrived on. A missing header, a
foreign name and a port mismatch are all answered `421` with `{"error": ...}`;
the check runs before `404`/`405` as well, so a rejected request learns nothing
about the route table. `codevanta.gui.server.is_allowed_host(value, port)` is the
predicate behind it.

**Bounded responses.** Every body is capped at `MAX_RESPONSE_BYTES` (`4194304`,
4 MiB) and the cap is hard, not advisory. An oversized payload is shrunk in
stages and flagged `"response_truncated": true`: top-level lists are halved (up
to 16 rounds), then every over-long string and nested list is replaced by a
placeholder, and if the document still does not fit it becomes a minimal
`{"error": "response too large", "limit": 4194304}`. `_encode_payload` therefore
never returns more than `MAX_RESPONSE_BYTES`, whatever the payload shape. Every
numeric query parameter is validated against the ceiling of the engine that
consumes it.

### The fourteen `/api` routes

All routes are `GET` and return `application/json`; `/` returns the HTML page.
The builders are thin adapters — no analysis is reimplemented here.

| Route | Query parameters (default) | Engine |
| --- | --- | --- |
| `/api/health` | — | static: `status`, `version`, `routes`, `paths_allowed` |
| `/api/info` | `path`, `max_functions` (50) | `build_report(path, string_limit=0, xref_limit=0)` |
| `/api/functions` | `path`, `limit` (200) | `discover_functions` |
| `/api/strings` | `path`, `min_length` (4), `limit` (200) | `StringExtractor` |
| `/api/xrefs` | `path`, `limit` (2000) | `find_xrefs` (4 MB budget) |
| `/api/cfg` | `path`, `address`, `traversal` (`linear`\|`recursive`), `max_instructions` (2000), `max_blocks` (500) | `build_cfg` / `build_recursive_cfg` |
| `/api/struct` | `path`, `address`, `max_fields` (64), `include_stack` (0) | `suggest_struct` |
| `/api/callgraph` | `path`, `limit_functions` (2000), `limit_edges` (20000) | `build_call_graph` |
| `/api/diff` | `left`, `right`, `semantic` (0), `threshold` (0.9) | `diff_binaries` |
| `/api/decompile` | `path`, `address` (entry point), `backend` (`auto`), `max_instructions` (2000), `max_blocks` (500) | `codevanta.analysis.decompilers.decompile_function` |
| `/api/emulate` | `path`, `address`, `set` (repeatable `REG=VAL`), `max_instructions` (2000) | `emulate_function` |
| `/api/symbolic` | `path`, `address`, `max_paths` (64), `max_steps` (2000) | `explore_paths` |
| `/api/session_save` | `path`, `notes` | `SessionStore.save` (the one route that writes; the database comes from `SESSION_DB_ENV`) |
| `/api/session_list` | `limit` (50) | `SessionStore.list` |

Flags are integer `0`/`1`; addresses accept decimal or `0x` hex. Status codes:
`421` with `{"error": ...}` for a foreign, missing or port-mismatched `Host`
header; `400` with `{"error": ...}` for bad input, a missing file or a rejected
analysis request; `404` for an unknown route; `405` for a non-`GET` method; `500`
with `{"error": ...}` for an unexpected failure. The dashboard is read-only: it
parses bytes, never executes or writes the target.

`/api/decompile` answers `400` — naming the backend — when `backend=angr` or
`backend=ghidra` is requested and unavailable, and takes the entry point when
`address` is omitted (failing with `400` when the binary has none). Its payload
is `BackendResult.to_dict()` plus `path`, `address` and `blocks`.


## `codevanta.mcp_server`: MCP server

```python
from codevanta.mcp_server.server import build_server, run, is_loopback_host

build_server() -> MCPServer
run(transport: str = "stdio", host: str = "127.0.0.1", port: int = 8000,
    *, allow_remote: bool = False) -> None
is_loopback_host(host: str) -> bool
```

`build_server()` creates the MCP server (`name="CODEVANTA"`,
`version="0.1.0"`) and registers the twenty-two tools below.

`run(transport=...)` accepts
`SUPPORTED_TRANSPORTS = ("stdio", "sse", "streamable-http")`:

| Transport | Behaviour |
| --- | --- |
| `"stdio"` | Default. JSON-RPC over stdin/stdout; `host`/`port` are unused. This is exactly what `codevanta mcp serve` runs. |
| `"sse"` | Binds `host:port` and serves Server-Sent Events. |
| `"streamable-http"` | Binds `host:port` and serves streamable HTTP. |

The HTTP transports are network-exposed and these tools read arbitrary local
files, so a non-loopback `host` is refused unless `allow_remote=True`
(`DEFAULT_HOST = "127.0.0.1"`, `DEFAULT_PORT = 8000`; `port=0` picks a free
port). `run` raises `AnalysisError` for an unknown transport, a malformed
host/port, or a remote host without `allow_remote`. The MCP SDK only auto-enables
DNS-rebinding protection for loopback hosts — front a remote bind with your own
authentication and `Host`/`Origin` validation.

> The HTTP transports are reachable both from Python
> (`codevanta.mcp_server.server.run`) and from the CLI, which forwards its
> options verbatim: `codevanta mcp serve --transport sse --host 127.0.0.1
> --port 8000`. `--allow-remote` is the CLI spelling of `allow_remote=True`, and
> a rejected transport or bind exits `2`.

### The twenty-two tools

Registered tool names, with their input properties. Verified by listing the
tools of a built server (`asyncio.run(build_server().list_tools())`, which
returns 22 names):

| Tool | Inputs (defaults) | Returns |
| --- | --- | --- |
| `codevanta_info` | `path` | format, architecture, sections, imports, exports, symbols |
| `codevanta_functions` | `path`, `limit` (200) | function candidates with source and confidence |
| `codevanta_strings` | `path`, `min_length` (4), `limit` (200) | ASCII/UTF-16 strings with offset and VA |
| `codevanta_disasm` | `path`, `address`, `function`, `count` (50) | disassembly of the entry point, an address or a named function |
| `codevanta_analyze` | `path`, `string_limit` (5000) | the phase-1 report with provenance and evidence |
| `codevanta_xrefs` | `path`, `limit` (200), `max_bytes` (4000000) | direct call/jump/branch references |
| `codevanta_cfg` | `path`, `address`, `function`, `max_instructions` (2000), `max_blocks` (500) | heuristic basic-block CFG |
| `codevanta_decompile` | `path`, `address`, `backend` (`auto`), `max_instructions` (2000), `max_blocks` (500) | `BackendResult` payload + `path`, `address`, `blocks` |
| `codevanta_callgraph` | `path`, `limit_functions` (1000), `limit_edges` (5000) | inter-function direct-call graph |
| `codevanta_diff` | `left`, `right`, `max_functions` (5000), `deep` (false), `semantic` (false), `threshold` (0.9) | structural / deep / semantic diff |
| `codevanta_jump_table` | `path`, `address`, `mode` ("absolute"), `base`, `entries` (256), `executable_only` (true) | decoded jump-table entries |
| `codevanta_function_hash` | `path`, `address`, `max_instructions` (2000) | SHA-256 fingerprint of normalized instruction shape |
| `codevanta_similarity` | `path_a`, `address_a`, `path_b`, `address_b`, `max_instructions` (2000) | shape-overlap `score` in 0..1 |
| `codevanta_struct` | `path`, `address`, `function`, `max_instructions` (2000), `max_fields` (64), `include_stack` (false) | struct-field suggestion |
| `codevanta_session_save` | `path`, `db`, `notes` | newly persisted session record |
| `codevanta_session_list` | `db`, `limit` (20) | sessions, newest first |
| `codevanta_entropy` | `path`, `threshold` (7.2), `max_sample_bytes` | per-section entropy with packing triage |
| `codevanta_dwarf` | `path`, `limit` (500) | DWARF functions and type layouts (ELF, optional extra) |
| `codevanta_vtable` | `path`, `address`, `scan` (false), `min_slots` (3), `max_slots` (256), `max_tables` (64), `resolve_thunks` (true) | vtable candidates and thunk chains |
| `codevanta_trace` | `path`, `trace_path`, `provider` (`auto`), `max_hits` | replayed trace mapped onto candidates |
| `codevanta_symbolic` | `path`, `address`, `max_paths` (64), `max_steps` (2000) | `PathExploration` payload |
| `codevanta_dataflow` | `path`, `address`, `max_instructions` (2000), `max_blocks` (500) | `DataFlowSummary` payload |

`codevanta_decompile` matches `backend` case-insensitively (blank means `auto`)
and rejects an unknown name with the supported set in the message; an
unavailable strict backend raises the tool's `ToolError` carrying the probe's
reason, so a model sees which backend is missing instead of a generic failure.

**Argument strictness.** `codevanta_diff` forwards `deep`, `semantic` and
`threshold` untouched: they must be real booleans and a real number, so
`deep=1`, `semantic=1`, `threshold=true` and `threshold="0.9"` are rejected and
the error names the offending argument.

The server's `INSTRUCTIONS` string gives a model the same contract this document
states: check `source`, `method` and `confidence` before relying on a finding;
exports and function symbols are high confidence; the entry point is a
medium-confidence code candidate, not a proven function boundary; all addresses
are absolute VAs.


## Quick recipes

Every snippet below was executed against this checkout from the repository root,
with `codevanta` installed in editable mode (`pip install -e .`). The `text`
block after each one is the real output, not an illustration. The sample binaries
are described in [`docs/samples.md`](samples.md).

### 1. Load a sample and translate addresses

```python
from codevanta.core.loader import BinaryLoader

info = BinaryLoader().load("samples/pe64_text.bin")
print(info.format, info.architecture, hex(info.entry_point))
offset = info.va_to_offset(info.entry_point)
print("entry file offset:", hex(offset))
print("section:", info.section_for_va(info.entry_point).name)
```

```text
PE x86_64 0x140001000
entry file offset: 0x200
section: .text
```

### 2. Build a full report with all three phase-2 sections

```python
from codevanta.core.report import build_report

report = build_report(
    "samples/elf64_text.bin",
    string_limit=5,
    include_xrefs=True,
    include_cfg=True,
    include_callgraph=True,
)
print(sorted(report))
print("steps:", report["provenance"]["steps"])
print("function sources:", [f["source"] for f in report["functions"]])
print("cfg blocks:", report["cfg"]["block_count"])
print("callgraph:", len(report["callgraph"]["nodes"]), "nodes",
      len(report["callgraph"]["edges"]), "edges")
```

```text
['binary', 'callgraph', 'cfg', 'disassembly', 'functions', 'provenance', 'strings', 'xrefs']
steps: ['load_binary', 'discover_functions', 'extract_strings', 'find_xrefs', 'build_cfg']
function sources: ['binary.entry_point']
cfg blocks: 1
callgraph: 1 nodes 0 edges
```

Note the honest gaps in that output: `provenance["steps"]` lists the steps whose
engine records one, and the call-graph step is not among them; the only function
candidate comes from the entry point at `medium` confidence, and it carries no
`name` key at all because the sample has no symbol table.

### 3. Disassemble and collect cross references

```python
from codevanta.analysis.xrefs import find_xrefs
from codevanta.core.report import disassemble_region, load_binary

info = load_binary("samples/macho64_text.bin")
result = disassemble_region("samples/macho64_text.bin", info, info.entry_point, count=10)
for insn in result.instructions[:3]:
    print(f"0x{insn.address:x}", insn.mnemonic, insn.operands)

scan = find_xrefs("samples/macho64_text.bin", info)
print("xrefs:", len(scan.xrefs), "scanned:", scan.scanned_sections, scan.scanned_bytes)
for xref in scan.xrefs:
    print(xref.kind, hex(xref.from_address), "->", hex(xref.to_address),
          xref.evidence.confidence)
```

```text
0x100000180 sub rsp, 0x28
0x100000184 xor eax, eax
0x100000186 mov r9, rax
xrefs: 5 scanned: ['__text'] 56
call 0x100000195 -> 0x10000019f certain
branch 0x1000001a8 -> 0x10000020c certain
branch 0x1000001ac -> 0x10000020f certain
branch 0x1000001b3 -> 0x100000216 certain
branch 0x1000001b6 -> 0x100000224 certain
```

The last four references are what a linear sweep of that section *is*: the bytes
after the real code body decode as branches, and the scanner reports them as
`certain` operand facts rather than pretending they are code. That is exactly why
the coverage (`scanned_bytes`) is reported next to the count.


### 4. Suggest struct fields, then compare two functions by shape

```python
from codevanta.analysis.function_hash import function_fingerprint, function_similarity
from codevanta.analysis.type_recovery import suggest_struct
from codevanta.core.loader import BinaryLoader

pe = BinaryLoader().load("samples/pe64_text.bin")
suggestion = suggest_struct("samples/pe64_text.bin", pe, pe.entry_point,
                            max_instructions=16)
print("fields:", [(hex(f.offset), f.width) for f in suggestion.fields])
print("alignment:", suggestion.alignment, "accesses:", suggestion.memory_access_count)

mo = BinaryLoader().load("samples/macho64_text.bin")
fp = function_fingerprint("samples/pe64_text.bin", pe, pe.entry_point,
                          max_instructions=10)
print("digest:", fp.digest[:16], "instructions:", fp.instruction_count)
sim = function_similarity(
    "samples/pe64_text.bin", pe, pe.entry_point,
    "samples/macho64_text.bin", mo, mo.entry_point,
    max_instructions=10,
)
print("score:", round(sim.score, 4), "shared:", sim.shared,
      "totals:", sim.left_total, sim.right_total)
```

```text
fields: [('0x0', 1), ('0x36', 1), ('0x64', 4)]
alignment: 2 accesses: 3
digest: a9a99ce347279f1a instructions: 10
score: 1.0 shared: 10 totals: 10 10
```

Both samples run the same ten-instruction code body, so the shape comparison
scores `1.0` — and that is all it means: the two functions have the same
normalized instruction shapes, not the same semantics. The field offsets are the
raw displacements of the memory operands in the window, which is why the
suggestion is `medium` confidence.

### 5. Persist a session and annotate it

```python
from codevanta.core.functions import discover_functions
from codevanta.core.loader import BinaryLoader
from codevanta.core.strings import StringExtractor
from codevanta.storage.session import SessionStore

info = BinaryLoader().load("samples/pe64_text.bin")
functions = discover_functions(info)
strings = StringExtractor().extract("samples/pe64_text.bin", info=info)

with SessionStore(":memory:") as store:
    record = store.save(info, len(functions), len(strings), notes="pe64 smoke test")
    store.annotate(record.session_id, info.entry_point, "exported entry")
    print(record.session_id, record.format, record.functions, record.strings)
    print("annotations:",
          [(hex(a.address), a.note) for a in store.annotations(record.session_id)])
    print("listed:", [r.session_id for r in store.list(limit=5)])
    print("deleted:", store.delete(record.session_id), store.get(record.session_id))
```

```text
c7bb6cef8cc9 PE 1 4
annotations: [('0x140001000', 'exported entry')]
listed: ['c7bb6cef8cc9']
deleted: True None
```

The session id is generated per save, so yours will differ; everything else is
deterministic. Substitute a real path for `":memory:"` (or set `CODEVANTA_DB`) to
keep the record.

### 6. Drive the dashboard's JSON API in-process

```python
import json
import threading
import urllib.request

from codevanta.gui import create_server

server = create_server(port=0)
host, port = server.server_address[:2]
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    base = f"http://{host}:{port}"
    health = json.loads(urllib.request.urlopen(base + "/api/health").read())
    print(health["status"], health["version"])
    print(len(health["routes"]), "api routes")
    data = json.loads(urllib.request.urlopen(
        base + "/api/functions?path=samples/pe64_text.bin").read())
    print(data["format"], data["count"], [f["name"] for f in data["functions"]])
finally:
    server.shutdown()
    server.server_close()
```

```text
ok 0.1.0
10 api routes
PE 1 ['codevanta_sample_main']
```

`port=0` asks the OS for a free port, and `create_server` only ever binds a
loopback address. For the same data interactively, run `codevanta gui` and open
`http://127.0.0.1:8765/`; for the command line, see `codevanta info`,
`codevanta disasm`, `codevanta analyze` and the other commands documented in the
[README](../README.md#usage).

### 7. Read a function: render it, then run it

```python
from codevanta.analysis.decompilers import decompile_function
from codevanta.analysis.emulate import emulate_function
from codevanta.core.loader import BinaryLoader

path = "samples/pe64_text.bin"
info = BinaryLoader().load(path)

rendered = decompile_function(path, info, info.entry_point, backend="native")
print(rendered.text.splitlines()[-4])   # a body line, with its instruction comment

run = emulate_function(path, info, info.entry_point)
print(run.stopped_reason, run.instructions, run.return_value)
```

```text
    call_14000101f();  /* call 0x14000101f */
return 9 42
```

The rendering is heuristic text (`low` confidence), the run is a fact
(`medium`): the same function, two different kinds of evidence. Both are bounded
by the budgets documented in
[`codevanta.analysis.decompile`](#codevantaanalysisdecompile-pseudo-c-rendering)
and
[`codevanta.analysis.emulate`](#codevantaanalysisemulate-bounded-offline-emulation).

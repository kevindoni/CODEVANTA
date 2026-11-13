# Phase 6 — Closing the roadmap gaps in one wave

Wave 6 (PR `#40`, commit `7427972`) closed the ten remaining roadmap gaps in a
single merge: dynamic trace replay surfaced on the CLI and over MCP, path
exploration and dataflow arrived as engines, the parser fuzzer and the
benchmark gate landed as scripts, the GUI learned to persist sessions, evidence
bundles and the plugin SDK shipped, and one real attribution defect found by the
new tests was fixed on the way. The branch you are reading this on
(`feat/phase7-wiring`) carries the follow-up **wave 7 wiring** that connects
those engines to the remaining user-facing surfaces — the CLI, two more MCP
tools, and one more GUI route — which this document also covers, with the
caveat that those wiring changes were uncommitted in the working tree when
checked.

Everything below was verified by running the CLI, a Python probe, and a live
HTTP request against the dashboard on this working tree. Sample outputs are
this machine's answers, not restated help text.

## What shipped

| Workstream | Where it lives |
| --- | --- |
| Trace replay + session script CLI | `codevanta trace`, `codevanta attach` (`cli/main.py`), `analysis/trace.py`, `analysis/dynamic.py` |
| MCP trace tool | `codevanta_trace` (`mcp_server/server.py`, `mcp_server/tools.py`) |
| Path exploration (unicorn) + angr bridge | `analysis/symbolic.py` |
| Dataflow: def-use, constant folding, reaching definitions | `analysis/dataflow.py` |
| Parser fuzz harness | `scripts/fuzz_parsers.py`, `tests/test_fuzz_parsers.py` |
| Benchmark regression gate | `scripts/bench_gate.py`, `bench/baseline.*.json`, `tests/test_bench_gate.py` |
| GUI session persistence | `/api/session_save`, `/api/session_list`, Sessions panel (`gui/server.py`, `gui/layout.py`) |
| Evidence bundles | `analysis/evidence_bundle.py`, `codevanta evidence-bundle` (wave 7), `scripts/report_bundle.py` (wave 7) |
| Plugin SDK + metrics analyzer | `plugins/__init__.py`, `codevanta plugins list/run` (wave 7) |
| Trace-attribution fix | `analysis/trace.py` (`_FunctionIndex`) |

## 1. `codevanta trace` and `codevanta attach`

The dynamic layer stays honest about what it does: **nothing here starts a
debugger**. `codevanta attach` writes a provider script (gdb or Frida) and
prints the exact `argv` that runs it; `codevanta trace` re-reads what such a
session already printed and maps the hits onto function candidates.

```powershell
codevanta trace samples\elf64_text.bin --input samples\gdb_trace.log
```

```text
  Trace hits by function (1)
+----------------------------+
| Function |  Address | Hits |
|----------+----------+------|
| -        | 0x401000 |    3 |
+----------------------------+
provider: gdb (auto-detected) · hits: 3 · kept: 3 · unique addresses: 2 ·
functions hit: 1 · unattributed: 0 · truncated: no
```

`--provider auto` detects the format from the file shape (a JSON object line is
Frida, a `HIT`/`BACKTRACE`/`LIMIT`/`DONE` line is gdb) and states the choice; a
capture it cannot place exits `2` instead of being guessed onto a provider.
`--json` prints `TraceReport.to_dict()` unchanged. Two saved traces ship as
samples since wave 7: `samples/gdb_trace.log` and `samples/frida_trace.jsonl`
(both replay against any binary that maps `0x401000` executable; the Frida
render adds the caveat that Frida addresses are runtime addresses, so
attribution assumes the image was not relocated).

```powershell
codevanta attach samples\elf64_text.bin 0x401000 --provider gdb --max-hits 4 --write out
```

prints the written script path (fixed name from
`codevanta.analysis.dynamic.SCRIPT_FILE_NAMES`), then the exact command —
for gdb `("gdb", "-q", "-batch", "-x", "codevanta-session.gdb", "--args", <path>)`,
for Frida `("frida", "-l", <script>, "-f", <path>)` — and a dim line saying what
must happen before it is run. When the provider cannot run on this machine
(`available_backends()` probes without executing anything) the command exits `2`
with the probe's `reason`; on the machine this was written on, both gdb and
Frida report `available=False`.


## 2. MCP: `codevanta_trace`

`codevanta_trace` (`path`, `trace_path`, `provider="auto"`, `max_hits=None`)
wraps the same parser. A missing/unreadable capture, an unresolvable provider,
a provider mismatch or a bad `max_hits` is raised as the tool's `ToolError`
carrying the real reason instead of the framework's generic message. Verified
by listing the tools of a built server: the registry now has **22 tools**.

## 3. `codevanta.analysis.symbolic` — branch-decision path exploration

`explore_paths` walks the decision tree of one function breadth-first on a
private unicorn CPU. The distinction the module exists to make: the direction
real emulation produced is **observed**; the opposite direction is enqueued by
rewriting the guarding flags or loop counter, and that side is **seeded** — an
assumption about feasibility, never a solved constraint. No symbolic variables,
no path predicate, no SMT. Every seeded branch is flagged per path, and a
summary whose paths include seeds drops to low confidence.

```python
from codevanta.analysis.symbolic import angr_available, explore_paths
from codevanta.core.loader import BinaryLoader

path = "samples/pe64_text.bin"
info = BinaryLoader().load(path)
exploration = explore_paths(path, info, info.entry_point)
print(exploration.explorer, exploration.complete, exploration.paths,
      exploration.return_values)
```

```text
unicorn True 1 (42,)
```

The same run on the command line (`codevanta symbolic samples\pe64_text.bin
--max-paths 4`) renders one row per path (`#`, decisions as `mnemonic+`/`mnemonic-`
with a `seeded` count, the `rax`/`eax` value at a leaving `ret`, why it stopped,
steps executed) over a dim line: `explorer: unicorn · arch: x86_64 (64-bit) ·
paths: 1 · unresolved: 0 · steps: 9 · complete: yes`. `complete` is `True` only
when nothing was left unexplored *and* every reported path reached a `ret`;
paths that ended `blocked` or `unmapped` are counted in `unresolved` and
explained in warnings. `--set REG=VALUE` (repeatable) seeds registers; budgets
(`--max-paths` 64, `--max-steps` 2000, ceilings 4096 and 200000) are validated
before anything runs; a missing unicorn build, a bad address or a non-x86
binary all exit `2` as `AnalysisError`, never as an `ImportError`.

The optional **angr bridge** (`explore_with_angr`, `ANGR_AVAILABLE`,
`angr_available()`) reports the same `PathExploration` shape with
`explorer: "angr"` when angr is installed (`pip install -e ".[decompilers]"`).
It explores to the `ret` addresses found by a bounded linear sweep and reports
`max_steps=0` (angr owns the stopping). `angr_available()` is `False` on this
machine; the bridge is never imported at module import time.

## 4. `codevanta.analysis.dataflow` — def-use and constant folding

`analyze_dataflow` builds the recursive CFG and walks it once, forward, block
by block in ascending address order: reads resolve against definitions seen so
far, writes kill what the register held. Only provable shapes fold — `mov`
immediates, register copies, `add`/`sub`/`xor` of two known values, rip-relative
loads — everything else keeps the register unknown.

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

`codevanta dataflow samples\elf64_text.bin` renders the same data as a table
(address, canonical register — aliases normalised, shape `const`/`copy`/
`arithmetic`/`unknown`, provable value, copy source) plus a dim line with the
constants still known (`constant registers: none` here) and one `warning:` per
undefined read. The pass is a linearization, not a fixpoint: a join takes the
highest-addressed predecessor, so the summary is sound one definition at a time
and never claims two conflicting origins for one value. Budgets:
`--max-instructions` 2000 (ceiling 8192), `--max-blocks` 500 (ceiling 4096);
out-of-range budgets, a bad address or a non-executable address exit `2`. The
target is only ever read.

## 5. The parser fuzz harness

`scripts/fuzz_parsers.py` runs the real public entry points over mutated copies
of the committed samples (plus ELFs it packs in memory) and treats any exception
the API does not document as a finding. Mutations are seeded and replayable —
`byteflip`, `truncate`, `length-field`, `section-table`, `huge-counts`,
`zero-sizes`, `splice` — and every finding names the seed, iteration, source
file, exact edit and the mutant's SHA-256. The CI `fuzz-smoke` job runs 30
seeded iterations (`--iterations 30 --seed 3`) plus `tests/test_fuzz_parsers.py`
on every PR.

## 6. The benchmark regression gate

`scripts/bench_gate.py` imports the measurement helpers of `scripts/bench.py`
and compares every `best_ms` against a committed baseline
(`bench/baseline.windows.json` and `bench/baseline.linux.json` since wave 7 —
per-platform, because the gate refuses to compare a Windows run against a
Linux baseline). Default tolerance `0.5` (a benchmark may be 50 % slower before
it counts), a missing baseline row fails too, `--repeat` can raise precision but
never drop below the baseline's repeat, and a row beyond tolerance is remeasured
once with the better result kept. `--update-baseline` accepts new numbers.
CI runs it as the `benchmark` job with `continue-on-error: true` and a wide
tolerance (`--repeat 1 --tolerance 3.0`) — timings are machine-dependent, so the
job reports drift, it does not gate.

## 7. GUI session persistence

`/api/session_save` and `/api/session_list` are the only routes that write
anything: a session row in the same SQLite store `codevanta session save` uses
(`$CODEVANTA_DB` or `~/.codevanta/sessions.db`). The dashboard layout gained a
Sessions panel for both. They are part of the **fourteen** `/api` routes the
server registers (was ten before wave 6; wave 7 added `/api/symbolic`).

## 8. Evidence bundles

`codevanta.analysis.evidence_bundle` pins an analysis to the bytes it describes:
the subject binary is streamed through SHA-256 and every payload is reduced to
canonical JSON before it is hashed, so a verifier can recompute both digests
from the document alone.

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

`verify_bundle` runs two independent checks — per-entry (re-canonicalise,
re-hash, re-measure) and per-table (`entries_digest` over the entry table
against `manifest.entries_sha256`, which catches edited digests whose payload
was left alone). A `Bundle` is frozen and its mappings are proxies, so a built
bundle cannot be mutated behind the verifier's back. Limits: 256 entries
(`MAX_ENTRIES`), 16 MiB per payload (`MAX_PAYLOAD_BYTES`), `sha256` only.

Wave 7 added `scripts/report_bundle.py`, which ties the static report (plus an
optional saved trace) into one bundle and verifies it again on load:
`python scripts/report_bundle.py BIN --output OUT.json [--trace FILE]
[--notes TEXT]`, `--verify OUT.json` re-checks; exit `1` is a failed
verification, `2` is usage error — including an output path that would
overwrite the subject.

## 9. The plugin SDK and the metrics analyzer

`codevanta.plugins` keeps outside analysers outside the package: the contract is
one dataclass in (`AnalysisContext`: path, loaded `BinaryInfo`, focus address,
pre-discovered candidates, read-only `budget` mapping) and one JSON mapping out.
An object satisfies `AnalyzerPlugin` structurally — no import of CODEVANTA and
no base class required. Discovery reads distribution entry points
(`DEFAULT_ENTRY_POINT_GROUP = "codevanta.analyzers"`, kinds
`analyzer`/`exporter`/`provider`) without importing them; `load()` imports one
plugin lazily and consults the built-in registry first. `run_plugin` bounds the
call — canonical-JSON byte cap (default 4 MiB) checked before the wall-clock
budget (default 30 s, measured after return because the call is not
interruptible) — and lifts `payload["warnings"]` into the result.

The built-in `MetricsAnalyzer` (`name="metrics"`, `version="1.0"`) counts
functions and strings through the public API and honours a `max_strings`
budget; it exists to prove the path end to end. Verified:

```text
$ codevanta plugins list
Analysis plugins (1)
| metrics | 1.0 | analyzer | codevanta.plugins:Me… | Function and string counts … |

$ codevanta plugins run metrics samples\elf64_text.bin
architecture = x86_64  bitness = 64  function_count = 1  string_count = 2  …
plugin: metrics · version: 1.0 · kind: analyzer · 0.3 ms
```

A payload over either budget, a non-mapping return or a malformed plugin exits
`2` with the plugin named.

## 10. The trace-attribution fix

The new trace tests exposed a real defect: a hit above the last known function
was attributed to it, because an unknown candidate size was treated as
unbounded. `_FunctionIndex` now takes a candidate's extent from its symbol size
when the loader knows it, otherwise from the enclosing executable section — a
function cannot run past the end of its own section — and when neither is
available an address above the start is reported **unattributed** instead of
guessed onto the nearest symbol. `function_coverage` counts hits per attributed
function, so the table shows where a session actually went and nothing else.


## Wave 7 — wiring the engines to the surfaces

Wave 6 shipped the engines; the `feat/phase7-wiring` branch connects them to
the surfaces an analyst actually touches. **These changes were uncommitted in
the working tree when this document was written** (committed work ends at
`9e8f47b`); everything below was verified against that working tree.

| Surface | Wave 7 addition | Verified |
| --- | --- | --- |
| CLI | `codevanta symbolic`, `codevanta dataflow`, `codevanta evidence-bundle`, `codevanta plugins list/run` | `--help` and live runs on the committed samples |
| MCP | `codevanta_symbolic` (`path`, `address`, `max_paths` 64, `max_steps` 2000), `codevanta_dataflow` (`path`, `address`, `max_instructions` 2000, `max_blocks` 500) | `build_server().list_tools()` returns 22 names |
| GUI | `/api/symbolic` (`path`, `address`, `max_paths` 64, `max_steps` 2000) over `explore_paths`, plus the panel that drives it | live request: HTTP 200, `explorer: unicorn`, `complete: true`, 1 path returning `0x2a`; `/api/health` reports 14 routes |
| CI | `fuzz-smoke` (30 seeded iterations, every PR), `benchmark` (informational, `continue-on-error`), `test-platform` (py3.13 on windows-latest + macos-latest, non-blocking) | `.github/workflows/ci.yml` |
| Benchmarks | per-platform baselines: `bench/baseline.windows.json`, `bench/baseline.linux.json` | `bench_gate.py --platform` |
| Samples | `samples/gdb_trace.log`, `samples/frida_trace.jsonl` + `samples/README.md` section | both replay through `codevanta trace` |
| Scripts | `scripts/report_bundle.py` (build + verify a bundle from a report and an optional trace) | module docstring + `--help` contract |
| Tests | `tests/test_cli_phase7.py`, `test_report_bundle.py`, `test_symbolic_parity.py`, `test_trace_samples.py` | all green together with the wave 6 suites |

The evidence-bundle CLI is the wave 7 wiring of the wave 6 module:

```powershell
codevanta analyze samples\elf64_text.bin -o report.json
codevanta evidence-bundle samples\elf64_text.bin --entry report=report.json --output bundle.json
```

```text
bundle written: bundle.json · entries: 1 · subject sha256:
90484368acda3d151338987a32f89239863f589e1483256ac265c772129f6cc1
```

Every `--entry NAME=FILEPATH` names one JSON payload; the subject digest and the
per-entry digests are recomputable from the document, `--output` must never
name (or live under) the analysed path, and failures exit `2` without writing a
partial bundle. `--json` additionally prints the exact document.

## Where things live

```text
src/codevanta/analysis/symbolic.py        # explore_paths / explore_with_angr (unicorn + angr bridge)
src/codevanta/analysis/dataflow.py        # analyze_dataflow
src/codevanta/analysis/evidence_bundle.py # build/verify/read/write bundles
src/codevanta/analysis/trace.py           # parse_gdb_trace / parse_frida_trace
src/codevanta/analysis/dynamic.py         # provider probes, script builders, attach_command
src/codevanta/plugins/__init__.py         # SDK: registry, discovery, run_plugin, MetricsAnalyzer
src/codevanta/cli/main.py                 # trace, attach, symbolic, dataflow, evidence-bundle, plugins
src/codevanta/mcp_server/                 # codevanta_trace, codevanta_symbolic, codevanta_dataflow
src/codevanta/gui/                        # /api/session_save, /api/session_list, /api/symbolic + panels
scripts/fuzz_parsers.py                   # seeded mutational fuzzer
scripts/bench_gate.py                     # benchmark regression gate
scripts/report_bundle.py                  # report + trace -> verified bundle
bench/baseline.windows.json               # committed Windows baseline (best-of-15)
bench/baseline.linux.json                 # committed Linux baseline (best-of-15)
samples/gdb_trace.log                     # saved gdb session trace
samples/frida_trace.jsonl                 # saved Frida session trace
```

## Verification notes

Every command output in this document was produced on the
`feat/phase7-wiring` working tree from the committed samples: `codevanta
symbolic`, `codevanta dataflow`, `codevanta trace` (both sample traces),
`codevanta attach`, `codevanta evidence-bundle`, `codevanta plugins list`,
`codevanta plugins run metrics`, the Python examples of sections 3, 4, 8 and 9,
`build_server().list_tools()` (22 names), and a live `/api/symbolic` request
against `create_server(port=0)`. The wave 6 and wave 7 test suites
(`test_cli_trace.py`, `test_symbolic.py`, `test_dataflow.py`,
`test_evidence_bundle.py`, `test_plugins.py`, `test_cli_phase7.py`,
`test_trace_samples.py`, `test_symbolic_parity.py`, `test_report_bundle.py`)
run green together. See [`docs/api.md`](api.md) for the Python signatures of
every module named here.


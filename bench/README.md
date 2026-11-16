# CODEVANTA sample benchmark

A reproducible, provider-free harness that measures what one CODEVANTA tool call
costs to answer a question about a committed sample, and what it returns. It runs
in-process through `codevanta.mcp_server.tools` (no server, no subprocess, no
model), so the numbers cover tool execution only.

## The 12 tasks

Three samples x four evidence types. `bench/tasks.json` holds the definitions;
`{sample_dir}` is replaced with the sample directory at run time.

| Sample | Info | Functions | Relationships | Decompile |
| --- | --- | --- | --- | --- |
| `pe64_text.bin` (PE32+ x86_64) | `pe64-info` | `pe64-functions` | `pe64-xrefs` | `pe64-decompile` |
| `elf64_text.bin` (ELF64 x86_64) | `elf64-info` | `elf64-functions` | `elf64-cfg` | `elf64-decompile` |
| `macho64_text.bin` (Mach-O x86_64) | `macho64-info` | `macho64-functions` | `macho64-xrefs` | `macho64-decompile` |

Each binary gets the same four questions:

1. **Metadata** (`binary_info`) - format, architecture, entry point, sections,
   hashes. Required keys: `format`, `architecture`, `entry_point`, `sha256`,
   `sections`.
2. **Functions** (`functions`, `limit=20`) - recovered candidates. Success needs
   at least one item.
3. **Relationships** (`xrefs` or `cfg`) - direct calls/branches for PE and Mach-O;
   `cfg` from the entry point for ELF64 because that stripped sample has no
   cross-references to find (0 xrefs), while it does have a control-flow graph.
   Success needs at least one xref or block.
4. **Decompile** (`decompile`) - C-like pseudocode for the entry point. Success
   needs non-empty `text`, `backend`, and `language`.

Entry-point addresses (`bench/tasks.json`, integer `address` arguments):
`0x140001000` PE, `0x401000` ELF, `0x100000180` Mach-O. The addresses are stored
as integers because `decompile` and `cfg` currently accept only `int` addresses;
the harness is written against that contract.

## Run it

From the repository root (works on Windows, macOS, and Linux):

```bash
python bench/run_codevanta.py              # writes bench/results/{codevanta.json,report.md}
python bench/run_codevanta.py --check      # same, exits 1 if any task fails
```

Options:

| Option | Meaning |
| --- | --- |
| `--tasks PATH` | Benchmark definition (default `bench/tasks.json`). |
| `--out-dir PATH` | Output directory (default `bench/results/`). |
| `--sample-dir PATH` | Sample directory; overrides `sample_dir` in the definition. |
| `--rea PATH` | Merge external REA numbers into the report and JSON. |
| `--check` | Exit non-zero when a task raises or misses its success criteria. |

Every task is attempted even when an earlier one raises; a tool exception is
recorded as `"ok": false` with the exception type and message. Exit code `2`
means the definition or REA file was invalid, not that an analysis failed.

`bench/results/codevanta.json` is sorted by task id and contains the success
flags, wall time, output size, token estimate, and SHA-256 per task, plus totals
and the environment. `bench/results/report.md` is the human-readable table.

## The four headline metrics

| Metric | How it is measured |
| --- | --- |
| **Success rate** | Tasks whose output has every required key non-empty and every `min_list` length satisfied, over all tasks. |
| **Tokens/task** | `ceil(output_chars / 4)` averaged over tasks. `output_chars` is the length of the canonical JSON (`sort_keys=True`, compact separators) of the tool result. |
| **Wall-clock** | Per-task `time.perf_counter()` around the single tool call, summed and also reported per task. The tools module is imported before the first timer starts. |
| **Reproducibility** | SHA-256 of that same canonical JSON after sample paths are normalized to `{sample_dir}`. Repeat the run and diff `codevanta.json`: timings change, hashes must not. |

Caveats: token counts estimate what an agent would ingest, not a tokenizer's
count, and CODEVANTA's wall-clock excludes LLM latency. Decompilation uses
`backend="auto"`, so `*-decompile` hashes depend on which optional decompilers
(Ghidra/angr) are installed; the native backend is the fallback used on a clean
checkout.

## Filling the REA column

An external agent (for example an REA session driven over MCP) is asked the same
12 questions against the same samples. For each task, record the provider's
**usage for that task** - input plus output tokens - and the wall-clock time of
the turn. Provider dashboards, API responses (`usage.input_tokens` +
`usage.output_tokens`), or the agent runtime's session metrics are the source of
truth; do not estimate tokens from prompt length.

Write the numbers to `bench/results/rea.json` using exactly this schema:

```json
{
  "pe64-info": {"ok": true, "tokens": 1234, "ms": 8100},
  "pe64-functions": {"ok": true, "tokens": 2345, "ms": 12400}
}
```

Only tasks present in the file get REA cells; the rest render as `-`. Unknown
task ids are ignored with a warning. Then merge:

```bash
python bench/run_codevanta.py --rea bench/results/rea.json
```

The report gains `REA ok`, `REA tokens`, and `REA ms` columns, totals, and an
"External REA comparison" table. Treat the comparison as directional: REA tokens
include the agent's system prompt, reasoning, and retries, while CODEVANTA tokens
count only the tool result, and REA wall-clock includes model latency that the
harness never pays. Compare the same task id on both sides rather than treating
the summed totals as a pure implementation speedup.

No REA sample file is committed: `bench/results/` is generated output, and made-up
numbers would defeat the purpose of the comparison.

## Tests

```bash
python -m pytest tests/test_bench_harness.py -q
python -m ruff check bench/run_codevanta.py tests/test_bench_harness.py
```

The smoke test runs the two cheapest PE64 tasks (`info` and `functions`) through
the same module functions the CLI uses and asserts `ok` plus a positive token
estimate.

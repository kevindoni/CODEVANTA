# Phase 2e — Recursive CFG Traversal

Phase 2e adds a second way to build a control-flow graph. `build_recursive_cfg`
follows control flow outward from a start address with a worklist of block starts
and a visited set, instead of decoding a fixed window of instructions. The result
is the same `FunctionCFG` type, so tables, JSON output, and downstream consumers
are unchanged — but blocks come from following actual branch targets, and bytes
that no edge reaches are never decoded.

The linear sweep stays the default. `build_cfg` is untouched and
`codevanta cfg` behaves exactly as before unless you ask for the new traversal,
so existing scripts, reports, and tests keep their current results.

| Module | What changed |
|--------|--------------|
| `src/codevanta/analysis/cfg.py` | New `build_recursive_cfg(path, info, start, max_instructions=2000, max_blocks=500)` returning `FunctionCFG`, built by worklist traversal from `start` |
| `src/codevanta/cli/main.py` | `codevanta cfg --traversal linear\|recursive` (default `linear`) |

Only decoded instructions and direct branch operands are used. Code is read from
the file, never executed, and no memory is inspected at run time.

**Status:** in progress. Direct targets only — indirect jumps are not resolved,
calls are not followed, and there is no cross-function analysis. See
[Limitations](#limitations).

## Usage

```powershell
# Default: the phase 2 linear sweep, unchanged
codevanta cfg C:\Windows\System32\notepad.exe --address 0x140001000

# Follow control flow from the start address
codevanta cfg C:\Windows\System32\notepad.exe --address 0x140001000 --traversal recursive

# Recursive traversal with JSON output
codevanta cfg C:\Windows\System32\notepad.exe --function main --traversal recursive --json
```

| Option | Default | Effect |
|--------|---------|--------|
| `--address` / `-a` | entry point | Virtual address of the first instruction |
| `--function` / `-f` | — | Function name to graph (resolved to an address first) |
| `--traversal` | `linear` | `linear` (phase 2 sweep) or `recursive` (worklist traversal) |
| `--max-instructions` | 2000 | Instruction budget for either traversal |
| `--max-blocks` | 500 | Maximum basic blocks reported |
| `--json` | off | Emit `FunctionCFG.to_dict()` instead of the block table |

The two traversals print the same table and the same JSON keys; the difference is
which blocks exist and what `evidence` says about them. When neither `--address`
nor `--function` is given, both start at the entry point.

## API

```python
from pathlib import Path

from codevanta.analysis.cfg import build_recursive_cfg
from codevanta.core.loader import BinaryLoader

path = Path("samples/elf64_text.bin")
info = BinaryLoader().load(path)

# Any executable address works, e.g. the entry point or a section start.
start = next(
    section.virtual_address for section in info.sections if section.is_executable
)
graph = build_recursive_cfg(path, info, start)

print(graph.evidence.source)          # cfg.recursive_traversal
print(graph.evidence.confidence)      # Confidence.MEDIUM
for block in graph.blocks:
    print(f"0x{block.start:x}-0x{block.end:x}", block.successors)
```

`build_recursive_cfg` takes the same arguments as `build_cfg` and returns the same
`FunctionCFG`:

| Field | Meaning |
|-------|---------|
| `function_address` | The requested start address |
| `function_name` | Discovered name when a candidate starts at `function_address`, else `None` |
| `blocks` | `BasicBlock` list in ascending address order |
| `instruction_count` | Number of decoded instructions |
| `truncated` | `True` when `max_instructions` or `max_blocks` cut the work short |
| `evidence` | `source="cfg.recursive_traversal"`, confidence `medium` |
| `warnings` | Caveats, including budget exhaustion and dropped targets |

Each `BasicBlock` keeps its `start`, exclusive `end`, decoded `instructions`,
sorted `successors`, `terminator`, and per-block `evidence` (`source`
`cfg.recursive_traversal`, method `basic_block`, confidence `medium`).

`build_recursive_cfg` is exported from `codevanta.analysis.cfg` alongside
`build_cfg`, `FunctionCFG`, and `BasicBlock`. It raises `AnalysisError` when
`start` is not inside an executable section, when `max_instructions` or
`max_blocks` is outside `1 .. MAX_DISASSEMBLY_COUNT`, or when the architecture
cannot be disassembled.

## How the traversal works

The algorithm is a worklist over *block starts*, with a visited set so no address
is decoded twice:

1. Seed the worklist with `start`; seed the visited set with nothing.
2. Pop a block start. If it has already been visited, skip it.
3. Decode forward from that address, one instruction at a time, until the
   instruction ends the block (a `ret`, a `jmp`, or a conditional jump), until an
   already-visited leader is reached (the block ends just before it), until the
   instruction budget runs out, or at the end of the executable section.
4. Record the block, then queue every successor address that resolves inside an
   executable, file-backed section and has not been visited yet.
5. Repeat until the worklist is empty or a budget is exhausted.

The visited set is also what makes loops terminate: a back edge points at a
leader that is already visited, so it produces an edge but no second block.
Because successors are queued rather than assumed to be "the next bytes", the
order in which blocks are discovered has no effect on the result: blocks and
successor lists are sorted before they are returned, so two runs over the same
input produce identical output.

### Successor rules

| Final instruction | Successors |
|-------------------|------------|
| Conditional jump (`jne`, `jl`, `jrcxz`, `b.eq`, `cbz`, …) | fallthrough **and** the direct target |
| Unconditional jump (`jmp`, `b`, `br`, …) | the direct target only — no fallthrough |
| `ret` / `iret` family | none |
| Anything else (ordinary instruction, `call`, `nop`, …) | fallthrough only |

Two consequences of those rules matter in practice:

- **`call` does not end a block and is not followed.** A `call` behaves like any
  other non-branching instruction: execution continues at the next instruction,
  so the callee's body is not pulled into this graph. Following calls would merge
  unrelated functions into one graph, which this phase deliberately avoids.
- **Unreachable bytes are never decoded.** Bytes that follow a `ret` or an
  unconditional `jmp` and that no edge points at are padding or data as far as
  this traversal is concerned, so they produce no block. The linear sweep would
  have decoded them.

Targets are only accepted when they land inside an executable, file-backed
section; a direct target outside the code map is dropped rather than turned into a
synthetic block. Two situations are reported in `warnings` instead of being
silently hidden:

- indirect branch targets, which have no decoded address and therefore produce no
  edge (`"N indirect branch target(s) were not resolved ..."`), and
- an edge whose target block is not among the reported blocks — which happens when
  `max_blocks` truncates the graph — where the edge is kept and the gap is named.

## How it differs from the linear sweep

| | Linear sweep (`build_cfg`) | Recursive traversal (`build_recursive_cfg`) |
|---|---|---|
| Driving question | "What are the next N instruction slots?" | "What does control flow reach from here?" |
| Work list | One contiguous decode window | Worklist of block starts plus a visited set |
| Block leaders | Instruction after any terminator, plus in-window branch targets | Block starts that an edge actually points at |
| Unreachable bytes | Decoded and given blocks | Never decoded |
| `call` mid-block | Falls through (block continues) | Falls through (block continues), callee not followed |
| Evidence `source` | `cfg.linear_sweep` | `cfg.recursive_traversal` |
| Confidence | `medium` | `medium` |
| CLI default | Yes | No (`--traversal recursive`) |

The practical difference is visible in a function that ends with `ret` followed by
alignment padding or a jump table:

```text
linear:     ... ret | 00 00 00 ... decoded as instructions -> extra "blocks"
recursive:  ... ret | nothing queued -> no blocks for the padding
```

Confidence does not rise with the new traversal. Both labels are `medium`,
because neither resolves indirect transfers: the difference is *where blocks come
from* — queued branch targets instead of a fixed decode window — not proof that
the recovered control flow is complete.

## Evidence and confidence

| Result | `evidence.source` | Confidence | Why |
|--------|-------------------|------------|-----|
| Recursive graph as a whole | `cfg.recursive_traversal` | `medium` | Blocks are queued from decoded direct targets, but indirect targets stay unresolved, so reachability can be incomplete |
| Recursive block | `cfg.recursive_traversal` | `medium` | Block boundaries depend on the same mnemonic terminator rules as the linear sweep |

`medium` is the ceiling here on purpose. A graph built this way is *more precise
about what it includes* and *not at all more complete*: an indirect `jmp`, a
jump-table dispatch, or a transfer out of the region means the set of reachable
blocks is a subset of the true one. Read `truncated` and `warnings` before
treating any result as complete, and treat a missing block as "not proven
reachable", not "unreachable in fact".

## Bounds on the work

Both budgets apply to the traversal itself:

- `max_instructions` bounds decoded instructions; the traversal stops when the
  budget is spent.
- `max_blocks` bounds reported blocks; reached block starts beyond the cap are
  never decoded.
- `FunctionCFG.truncated` is `True` when either budget cut the work short, and a
  warning names the budget that was hit plus how many blocks were still queued.

Raise the budgets for dense functions, and keep in mind that a `truncated` graph
is not a smaller function — it is an incomplete view of one.

## Limitations

- **Indirect jumps are not resolved.** `jmp rax`, `jmp qword ptr [rip + 0x20]`,
  and jump-table dispatches have no decoded target, so they contribute no
  successor edge and the blocks behind them are never discovered. The same
  applies to indirect conditional branches.
- **Calls are not followed.** The callee body is not traversed. There is no
  interprocedural graph, no function-extent recovery, and no tail-call analysis;
  a graph covers the region reachable from the address you asked for.
- **Confidence stays `medium`.** Unresolved indirect targets mean reachability
  can be incomplete even when nothing was truncated.
- **Targets outside executable sections are dropped.** A direct target that does
  not land in executable, file-backed code is omitted from `successors` and named
  in a warning; no synthetic block is created.
- **A block start that cannot be decoded is skipped.** The traversal records a
  warning for that address and does not guess a block boundary to recover from it.
- **Data in code sections is still ambiguous.** The traversal decodes whatever an
  edge points at, so a direct branch into an embedded data table is still
  disassembled as instructions.
- **Not exposed over MCP.** `codevanta_cfg` takes no traversal argument; the
  recursive traversal is library and CLI only for now.
- **No debugger.** Static analysis only: the target is read, never executed, and
  no run-time memory is inspected.

## Next steps

1. Resolve indirect jump targets — jump tables and typed pointer slots — so
   dispatch blocks stop terminating the traversal.
2. Follow `call` targets into callees and join per-function graphs, which needs
   real function extents instead of the nearest-candidate heuristic.
3. Raise confidence for blocks proven reachable by at least one decoded edge, and
   keep a lower band for the rest.
4. Hand the traversal a starting set (entry point plus candidates) instead of one
   address, to recover whole-binary reachability.
5. Thread `--traversal` through `codevanta_cfg` so MCP clients can request it.
6. Code/data disambiguation and a debugger backend — later-phase work, not part
   of what is delivered here.

## Verification

```powershell
python -m pytest
ruff check src tests
```

Recursive traversal is covered by `tests/test_cfg_recursive.py` (branch and join
blocks, self-loops, unreachable tails, `call` staying flat, unresolved indirect
jumps, both budgets, invalid start/limits, evidence) alongside the shared CFG
tests in `tests/test_cfg.py`; CLI options live in `tests/test_cli_phase2.py`.

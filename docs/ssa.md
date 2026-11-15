# SSA IR view (decompiler v2, increment 1)

`codevanta_ssa` builds a typed SSA (static single assignment) view of
one function region: the same bounded recursive CFG the decompile tool
uses, converted into versioned register values, def-use chains and
honest loop markers. Read-only — the file is only read, nothing is
executed. This is the decompiler v2 foundation: the IR later passes
(phi insertion, rewriting) will consume this view.

## What it reports

* **Versioned SSA values** — every register write becomes a new value
  (`rax.3`); each read binds to the latest definition in walked order.
  Registers never defined in-region read as honest `undef`, and
  function-entry reads bind to `arg` references.
* **Call records** — a call records its Win64/Win32 argument registers
  as `call_args` and clobbers the ABI-volatile registers (`rbx` and
  the other callee-saved registers survive).
* **FLAGS** — tracked as a pseudo-register so compare-and-branch pairs
  stay connected.
* **Loop boundaries** — a back-edge marks the target block with
  `loop_boundary=true` and a `phi_required` live-in set. **No phi
  functions are constructed in this increment** — the marker records
  where they will be needed.
* **Optional type hints** from the type-propagation module, where the
  constant/pointer analysis has an opinion.
* Bounded results with `truncated` flags and warnings, at `medium`
  confidence throughout — walked-order resolution is a *linear*
  reading of code the CPU may loop over.

## Usage

```json
{"path": "sample.exe", "address": 4198400, "max_blocks": 512, "max_instructions": 2000}
```

`address` is the function start in the file virtual-address space; it
must be a positive integer pointing at decodable executable code.
Python surface:

```python
from pathlib import Path
from codevanta.analysis.ir_ssa import build_ssa
from codevanta.core.loader import BinaryLoader

info = BinaryLoader().load(Path("sample.exe"))
report = build_ssa(Path("sample.exe"), info, 0x401000, max_instructions=2000)
for block in report.blocks:
    print(block.block_id, block.loop_boundary, block.phi_required)
payload = report.to_dict()   # JSON-safe
```

Typed errors: a non-integer (or boolean) `address`, a non-positive
address, an out-of-range budget, a missing file, and an address that is
not decodable executable code.

## Bounds and confidence

| Bound | Default | Ceiling | Effect |
|-------|---------|---------|--------|
| Blocks (`max_blocks`) | 512 | 512 | out-of-range values are typed errors |
| Instructions (`max_instructions`) | 2000 | 20 000 | out-of-range values are typed errors |
| SSA values kept | 4 096 | — | counting continues; `truncated` flag |
| Uses per value | 64 | — | further uses dropped with a warning |

| Finding | Confidence | Why |
|---------|------------|-----|
| A versioned value / def-use edge | `medium` | resolved in walked order — correct on the walked path, not yet loop-aware (no phis) |
| A `loop_boundary` marker | `high` | the back-edge target is a fact of the CFG |
| A type hint | `medium` | derived by the type-propagation module, when it has one |

## Limitations

* **The loop limitation, stated plainly:** without phi functions,
  values inside a loop body still resolve to the single straight-line
  version, and forward joins read the walked-order value. A register
  modified across iterations will not yet fan out into per-iteration
  versions — the `phi_required` live-in set marks exactly the blocks
  where the future pass will insert phis.
* One function region per call; cross-function dataflow (arguments
  beyond the `arg` markers, return-value propagation) is out of scope
  in this increment.
* The ABI assumption is Win64/Win32: argument-register and clobber
  sets follow those conventions.
* Budgets are hard: a function past `max_instructions` truncates with
  an honest flag rather than inventing a completed IR.

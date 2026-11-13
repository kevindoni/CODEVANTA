"""Solver-based symbolic execution for one function: concrete inputs per path.

The unicorn explorer (:mod:`codevanta.analysis.symbolic`) enumerates branch
decisions and replays them on a virtual CPU, deliberately solving nothing. This
module is the complement: it hands the function to `angr <https://angr.io/>`_,
which runs the code on *symbolic* states, forks at every conditional branch,
and accumulates one constraint per fork. Each reported path therefore carries
the *condition* that reaches it plus a concrete assignment of the six integer
argument registers that satisfies it (claripy solves the entry register
variables under the path's constraints). Nothing is executed on the host: angr
loads only the file bytes into its own simulation (``auto_load_libs`` is always
false), and hard caps bound the work.

Guarantees
----------
* **Lazy.** angr is *optional* and imported inside :func:`explore_symbolic`,
  never at module import time. :data:`SOLVER_AVAILABLE` only records whether a
  module called ``angr`` is findable -- the same probe
  :mod:`codevanta.analysis.symbolic` uses -- and :func:`solver_status` returns
  the reason when it is absent. Without angr the function raises
  :class:`~codevanta.core.report.AnalysisError` naming angr and the extra that
  installs it. Only x86_64 is supported: the register vocabulary, the ABI seed
  list and the capstone sweep are all 64-bit x86.
* **Bounded.** At most ``max_paths`` states stay active at any tick (extras are
  dropped and the result says so), the run stops once ``max_steps`` executed
  instructions are accounted for -- the simulation manager is stepped one
  *instruction* per state per tick and every tick's instruction executions are
  charged to the budget -- and at most ``max_paths`` paths are reported.
  :attr:`SymbolicResult.truncated` is true exactly when a cap cut the
  exploration short.
* **Honest.** Every path ends with one of three ``stopped_reason`` values:
  ``return`` (a ``ret`` was reached), ``budget`` (the step budget ran out while
  the state was still going) or ``error`` (the state faulted under angr). A
  ``budget``/``error`` path reports ``return_value=None`` because it never
  reached a ``ret`` -- a register snapshot would be dressed up as a return
  value. And the evidence states the real limit of the method: the paths angr
  found are real, but *finding every* path is not guaranteed.

Path semantics
--------------
The simulation manager is stepped tick by tick with ``find`` semantics, but the
ticks are applied here rather than delegated, so the instruction budget is
exact and the active-state cap is enforced between ticks. One tick executes one
instruction in every active state; afterwards every state whose instruction
pointer is (possibly, under its own constraints) a ``ret`` address is harvested
as a ``return`` path -- the same thing ``SimulationManager.explore`` does with
``find``, with ``avoid`` being nothing. States that fault move to angr's
errored records and become ``error`` paths; states that land on a symbolic jump
or return target become *unconstrained*, cannot be enumerated this way, and are
counted in a warning. What remains stays active until a cap or the budget ends
it as a ``budget`` path.

The ``find`` set is the ``ret`` instructions of a bounded linear sweep from the
start address (the same sweep the angr bridge in ``symbolic`` uses), so a
``ret`` the sweep cannot see is never treated as found and the sweep's limits
are written into the evidence.

Constraint and input extraction
-------------------------------
Every state starts from :meth:`angr.project.Project.factory.entry_state` with
each of the six SysV x86-64 integer argument registers seeded: concretely when
the caller passed ``initial_registers``, otherwise as a named symbolic variable
(``codevanta_initial_<register>``). At each stopped state the path's
``constraints`` are ``state.solver.constraints`` stringified (capped at
:data:`_MAX_CONSTRAINTS` entries), and ``input_registers`` solves each entry
variable under *that state's* constraints -- so the values are concrete inputs
that genuinely reach the path (a path constrained to ``rdi == 0`` reports a
zero ``rdi``). ``return_value`` is one concrete solution for ``rax`` at the
``ret``, not every value ``rax`` can take; the evidence says so.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import capstone

from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError, read_code
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_PATHS",
    "DEFAULT_MAX_STEPS",
    "MAX_MAX_PATHS",
    "MAX_MAX_STEPS",
    "SOLVER_AVAILABLE",
    "SolverPath",
    "SymbolicResult",
    "explore_symbolic",
    "solver_status",
]

# ---- limits ---------------------------------------------------------------

#: Paths reported when the caller does not pass ``max_paths``.
DEFAULT_MAX_PATHS = 8

#: Hard ceiling on ``max_paths`` (bounded work, whatever the caller asks).
MAX_MAX_PATHS = 4096

#: Instruction budget used when the caller does not pass ``max_steps``.
DEFAULT_MAX_STEPS = 2000

#: Hard ceiling on ``max_steps``.
MAX_MAX_STEPS = 200_000

#: Instructions a linear sweep reads at most when collecting a function's
#: ``ret`` sites for the find set.
MAX_SCAN_INSTRUCTIONS = 4096

#: Solver constraints stringified per path before the rest are dropped.
_MAX_CONSTRAINTS = 32

#: Bytes read per disassembly step in the ``ret`` sweep.
_MAX_INSTRUCTION_BYTES = 16

#: Cap on the raw section copy angr falls back to when it cannot load the file.
_MAX_BLOB_BYTES = 1 << 20

#: Errored states described individually in warnings; the rest stay counted.
_MAX_ERROR_NOTES = 4

#: The six SysV x86-64 integer argument registers -- the only seed names this
#: module accepts, and the registers solved concretely for every path.
_ARG_REGISTERS_64 = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")

#: ``BinaryInfo.architecture`` spellings accepted as 64-bit x86.
_X86_64_NAMES = frozenset({"x86_64", "x86-64", "amd64", "em_amd64"})

#: Instruction mnemonics that leave the explored function (Capstone's naming).
_RET_MNEMONICS = frozenset({"ret", "retf", "retn", "iret", "iretd", "iretq"})

# ---- evidence identity ------------------------------------------------------

#: Evidence identity for the solver-based explorer.
_EVIDENCE_SOURCE = "solver.angr"
_EVIDENCE_METHOD = "solver_symbolic_execution"

#: The constraint solver behind claripy on every angr this module supports.
_SOLVER_NAME = "z3"

#: What a caller needs to install angr.
_ANGR_HINT = "pip install 'codevanta[decompilers]'"

#: Every AnalysisError from this module names angr and the way to install it.
_ANGR_SUFFIX = f"angr is required for solver-based exploration: {_ANGR_HINT}"

#: What solver-based exploration proved versus what it only reports.
_ASSUMPTIONS: tuple[str, ...] = (
    "solver-based exploration; concrete inputs extracted per path; no proof all paths were found",
    "each path carries the constraints angr accumulated up to its end, stringified and capped at "
    f"{_MAX_CONSTRAINTS} entries",
    "return_value is one concrete solution for rax, not every value rax can take on that path",
    "the find set is the ret instructions of a bounded linear sweep; a ret the sweep cannot see is "
    "never treated as found, so a path can end as 'budget' although a ret exists ahead of it",
    "input_registers solve the entry values of the six integer argument registers under the "
    "path's constraints; the code may overwrite them before it returns",
)

# ---- stop reasons -----------------------------------------------------------

#: Why one path ended. ``return``: the state reached a ``ret``; ``budget``: the
#: step budget ran out while the state was still going; ``error``: the state
#: faulted under angr.
_STOP_RETURN = "return"
_STOP_BUDGET = "budget"
_STOP_ERROR = "error"

# ---- availability -----------------------------------------------------------


def _probe_angr() -> bool:
    """True when a module called ``angr`` is findable; never imports angr."""
    try:
        return importlib.util.find_spec("angr") is not None
    except Exception:  # pragma: no cover - depends on the installation
        return False


#: True when a module named ``angr`` is findable. This is a *probe*, not an
#: import: angr is imported only inside :func:`explore_symbolic`, so importing
#: this module stays cheap and keeps working on a machine without angr
#: (mirrors :data:`codevanta.analysis.symbolic.ANGR_AVAILABLE`).
SOLVER_AVAILABLE = _probe_angr()


def solver_status() -> str:
    """Return why solver-based exploration is (un)available on this machine.

    A sentence either way: with angr installed it says so; without, it is the
    exact reason, naming angr and the extra that installs it.
    """
    if SOLVER_AVAILABLE:
        return (
            "ok: 'angr' is findable, so explore_symbolic can run solver-based "
            f"symbolic execution (claripy/{_SOLVER_NAME})"
        )
    return (
        "'angr' is not installed, so explore_symbolic cannot run: solver-based exploration is "
        "optional in CODEVANTA and angr is never imported at module import time; install it "
        f"with {_ANGR_HINT}"
    )


def _import_angr() -> Any:
    """Import angr lazily, or raise :class:`AnalysisError` naming it and the extra."""
    if not SOLVER_AVAILABLE:
        raise AnalysisError(
            "'angr' is not installed, so explore_symbolic cannot run: solver-based exploration "
            "is optional in CODEVANTA and angr is never imported at module import time; "
            f"install it with {_ANGR_HINT}"
        )
    try:
        import angr
    except Exception as exc:
        raise AnalysisError(
            f"importing 'angr' failed ({type(exc).__name__}: {exc}); reinstall it with {_ANGR_HINT}"
        ) from exc
    return angr


# ---- results ---------------------------------------------------------------


@dataclass(frozen=True)
class SolverPath:
    """One path the solver explored, with the concrete inputs that reach it.

    Attributes:
        return_value: One concrete solution for ``rax`` at the ``ret`` -- or
            ``None`` when the path never reached a ``ret``, because a register
            snapshot must not be dressed up as a return value.
        constraints: The solver constraints angr accumulated up to the path's
            end, stringified, capped at :data:`_MAX_CONSTRAINTS` entries.
        input_registers: Concrete entry values of the six integer argument
            registers, solved under *this path's* constraints, so the values
            genuinely reach the path.
        stopped_reason: ``"return"``, ``"budget"`` or ``"error"``.
        steps: Instructions executed along this path: one per tick angr stepped
            it, the ``ret`` itself never executed.
    """

    return_value: int | None
    constraints: tuple[str, ...]
    input_registers: Mapping[str, int]
    stopped_reason: str
    steps: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict (hex values, lists, no solver objects)."""
        return {
            "return_value": (
                f"0x{self.return_value:x}" if self.return_value is not None else None
            ),
            "constraints": list(self.constraints),
            "input_registers": {
                name: f"0x{value:x}" for name, value in sorted(self.input_registers.items())
            },
            "stopped_reason": self.stopped_reason,
            "steps": self.steps,
        }


@dataclass(frozen=True)
class SymbolicResult:
    """Every path one solver-based exploration produced, plus its limits.

    Attributes:
        address: Virtual address the exploration started at.
        paths: The paths, in the order angr's solver stopped on them.
        solver: Which constraint solver produced the concrete models (``z3``).
        truncated: ``True`` exactly when a cap -- the path cap, the
            active-state cap or the step budget -- cut the exploration short.
        warnings: What was left unexplored, dropped or unconstrained.
        evidence: Provenance for the whole exploration, including what the
            solver proved and what it only reports.
    """

    address: int
    paths: tuple[SolverPath, ...]
    solver: str
    truncated: bool
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict (hex address, lists, no enums)."""
        return {
            "address": f"0x{self.address:x}",
            "solver": self.solver,
            "truncated": self.truncated,
            "path_count": len(self.paths),
            "paths": [entry.to_dict() for entry in self.paths],
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


# ---- small helpers ---------------------------------------------------------


def _validated_address(address: int) -> int:
    """Reject a negative start address; everything else is the loader's job."""
    if address < 0:
        raise AnalysisError(f"address must be non-negative, got {address}; {_ANGR_SUFFIX}")
    return address


def _validated_limit(name: str, value: int, ceiling: int) -> int:
    """Validate one caller-supplied budget: at least 1, at most ``ceiling``."""
    if value < 1:
        raise AnalysisError(f"{name} must be at least 1, got {value}; {_ANGR_SUFFIX}")
    if value > ceiling:
        raise AnalysisError(f"{name} too large ({value}); limit is {ceiling}; {_ANGR_SUFFIX}")
    return value


def _validated_registers(initial_registers: Mapping[str, int] | None) -> dict[str, int]:
    """Validate concrete seeds: only the six ABI registers, ints in [0, 2**64)."""
    if initial_registers is None:
        return {}
    seeds: dict[str, int] = {}
    for name, value in initial_registers.items():
        if name not in _ARG_REGISTERS_64:
            raise AnalysisError(
                f"unknown seed register {name!r}: explore_symbolic seeds only the six x86-64 "
                f"integer argument registers {list(_ARG_REGISTERS_64)}; {_ANGR_SUFFIX}"
            )
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << 64):
            raise AnalysisError(
                f"seed value for {name!r} must be an int in [0, 2**64), got {value!r}; "
                f"{_ANGR_SUFFIX}"
            )
        seeds[name] = value
    return seeds


def _is_x86_64(info: BinaryInfo) -> bool:
    """True when the binary is 64-bit x86, the only architecture this module runs."""
    return info.bitness == 64 and str(info.architecture).lower() in _X86_64_NAMES


def _ret_addresses(target: Path, info: BinaryInfo, start: int, section: Any) -> tuple[int, ...]:
    """Collect ``ret`` addresses in ``section`` by a bounded linear sweep.

    The sweep only builds the find set, so a byte that cannot be decoded costs
    one resynchronisation step rather than a wrong target -- the same approach
    the angr bridge in :mod:`codevanta.analysis.symbolic` takes.
    """
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    found: list[int] = []
    end = int(section.virtual_address) + int(section.size)
    pc = start
    for _ in range(MAX_SCAN_INSTRUCTIONS):
        if pc >= end:
            break
        try:
            data = read_code(target, info, pc, _MAX_INSTRUCTION_BYTES)
        except AnalysisError:
            break
        insn = next(iter(decoder.disasm(bytes(data), pc)), None)
        if insn is None:
            pc += 1
            continue
        if str(insn.mnemonic).lower() in _RET_MNEMONICS:
            found.append(pc)
        pc += int(insn.size)
    return tuple(found)


def _build_project(module: Any, target: Path, info: BinaryInfo, section: Any) -> tuple[Any, list[str]]:
    """Create the angr project, falling back to a raw section copy if needed.

    The file is loaded as an executable first (full fidelity, ``auto_load_libs``
    always false). Hand-written ELFs without program headers can defeat angr's
    loader, so on failure the module retries with the section's bytes mapped as
    a raw blob at the section's virtual address -- and says so in a warning.
    """
    warnings: list[str] = []
    try:
        return module.Project(str(target), auto_load_libs=False), warnings
    except Exception as exc:
        warnings.append(
            f"angr could not load {target.name} as an executable ({type(exc).__name__}: {exc}); "
            f"exploring a raw copy of section {section.name!r} instead"
        )
    base = int(section.virtual_address)
    size = min(int(section.size), _MAX_BLOB_BYTES)
    if size <= 0:
        raise AnalysisError(f"section {section.name!r} has no bytes to map for angr; {_ANGR_SUFFIX}")
    try:
        blob = read_code(target, info, base, size)
    except AnalysisError as exc:
        raise AnalysisError(
            f"could not read the bytes of section {section.name!r} for the angr blob fallback "
            f"({exc}); {_ANGR_SUFFIX}"
        ) from exc
    try:
        project = module.Project(
            blob,
            main_kwargs={"backend": "blob", "arch": "AMD64", "base_addr": base},
            auto_load_libs=False,
        )
    except Exception as exc:
        raise AnalysisError(
            f"creating the angr project for {target.name} failed ({type(exc).__name__}: {exc}); "
            f"{_ANGR_SUFFIX}"
        ) from exc
    if size < int(section.size):
        warnings.append(
            f"only the first {size} byte(s) of section {section.name!r} were mapped for angr"
        )
    return project, warnings


def _seed_registers(module: Any, state: Any, seeds: Mapping[str, int]) -> dict[str, Any]:
    """Seed the entry state; return, per register, what to solve per path.

    Registers the caller seeded concretely keep their int; the rest get a named
    symbolic variable (``codevanta_initial_<register>``) so every stopped state
    can solve for a concrete entry value under its own constraints.
    """
    entry_values: dict[str, Any] = {}
    for name in _ARG_REGISTERS_64:
        if name in seeds:
            entry_values[name] = int(seeds[name])
            setattr(state.regs, name, entry_values[name])
        else:
            entry_values[name] = module.claripy.BVS(f"codevanta_initial_{name}", 64)
            setattr(state.regs, name, entry_values[name])
    return entry_values


def _at_ret(state: Any, find_set: frozenset[int]) -> bool:
    """True when reaching a ``ret`` is possible for ``state`` (find semantics).

    Concrete instruction pointers are compared directly; a symbolic pointer
    counts when one of its first two solutions is a ``ret`` address, which is
    how ``SimulationManager.explore`` treats a find set.
    """
    try:
        values = state.solver.eval_upto(state.ip, 2)
    except Exception:  # pragma: no cover - angr owns the solver vocabulary
        return False
    return any(int(value) in find_set for value in values)


def _path_from_state(
    state: Any, stopped_reason: str, steps: int, entry_values: Mapping[str, Any]
) -> SolverPath:
    """Extract one :class:`SolverPath` from a state angr stopped on.

    ``constraints`` stringifies ``state.solver.constraints`` (capped);
    ``input_registers`` solves each entry register under this state's solver, so
    the concrete values satisfy the path's constraints; ``return_value`` is one
    concrete solution for ``rax``, and only for ``return`` paths.
    """
    constraints = tuple(str(item) for item in tuple(state.solver.constraints)[:_MAX_CONSTRAINTS])
    inputs: dict[str, int] = {}
    for name, entry in entry_values.items():
        if isinstance(entry, int):
            inputs[name] = entry
            continue
        try:
            inputs[name] = int(state.solver.eval(entry))
        except Exception:  # pragma: no cover - angr owns the solver vocabulary
            continue
    return_value: int | None = None
    if stopped_reason == _STOP_RETURN:
        try:
            return_value = int(state.solver.eval(state.regs.rax))
        except Exception:  # pragma: no cover - angr owns the solver vocabulary
            return_value = None
    return SolverPath(
        return_value=return_value,
        constraints=constraints,
        input_registers=inputs,
        stopped_reason=stopped_reason,
        steps=steps,
    )


def _result_evidence(
    *, start: int, paths: list[SolverPath], truncated: bool, max_paths: int, max_steps: int
) -> Evidence:
    """Describe what the solver explored versus what it only reports."""
    stopped: dict[str, int] = {}
    for entry in paths:
        stopped[entry.stopped_reason] = stopped.get(entry.stopped_reason, 0) + 1
    return Evidence(
        source=_EVIDENCE_SOURCE,
        method=_EVIDENCE_METHOD,
        confidence=Confidence.MEDIUM,
        address=start,
        detail=(
            "solver-based exploration; concrete inputs extracted per path; no proof all paths "
            "were found"
        ),
        extra={
            "engine": f"angr/claripy with the {_SOLVER_NAME} solver",
            "paths": len(paths),
            "truncated": truncated,
            "max_paths": max_paths,
            "max_steps": max_steps,
            "stopped_reasons": stopped,
            "seed_registers": list(_ARG_REGISTERS_64),
            "assumptions": list(_ASSUMPTIONS),
        },
    )


# ---- the explorer ----------------------------------------------------------


def explore_symbolic(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    max_paths: int = DEFAULT_MAX_PATHS,
    max_steps: int = DEFAULT_MAX_STEPS,
    initial_registers: Mapping[str, int] | None = None,
) -> SymbolicResult:
    """Explore one function with solver-based symbolic execution (angr).

    angr is imported here, never at module import time, and only x86_64 is
    supported. The simulation manager is stepped one instruction per state per
    tick with ``find`` semantics -- a state whose instruction pointer is
    (possibly) a ``ret`` address becomes a path -- and ``avoid`` is nothing.
    At most ``max_paths`` states stay active at any tick, the instruction
    executions of every tick are charged against ``max_steps``, and every path
    carries its solver constraints plus concrete argument-register values that
    reach it.

    Args:
        path: Binary file.
        info: Loader metadata for that file.
        address: Start address of the function.
        max_paths: Cap on reported paths *and* on concurrently active states.
        max_steps: Instruction budget, charged per executed instruction.
        initial_registers: Concrete seeds for up to six ABI argument registers
            (``rdi``, ``rsi``, ``rdx``, ``rcx``, ``r8``, ``r9``), each an int
            in ``[0, 2**64)``. Unseeded registers become symbolic variables.

    Returns:
        A :class:`SymbolicResult`; ``truncated`` is true when a cap cut the
        exploration short.

    Raises:
        AnalysisError: When angr is not installed (the message names angr and
            the extra that installs it), when angr fails to load or explore the
            file, when the machine is not x86_64, on a bad address, seed or
            limit, or when the address is not in an executable section.
    """
    target = Path(path)
    start = _validated_address(address)
    path_limit = _validated_limit("max_paths", max_paths, MAX_MAX_PATHS)
    step_budget = _validated_limit("max_steps", max_steps, MAX_MAX_STEPS)
    if not _is_x86_64(info):
        raise AnalysisError(
            "solver-based symbolic execution supports x86_64 only: "
            f"{info.architecture!r} (bitness {info.bitness}) is not supported, so nothing was "
            f"explored; {_ANGR_SUFFIX}"
        )
    seeds = _validated_registers(initial_registers)
    module = _import_angr()
    section = info.section_for_va(start)
    if section is None:
        raise AnalysisError(
            f"address 0x{start:x} is not mapped by any section, so angr has nothing to explore; "
            f"{_ANGR_SUFFIX}"
        )
    if not section.is_executable:
        raise AnalysisError(
            f"address 0x{start:x} is inside section {section.name!r}, which is not executable, "
            f"so angr cannot execute it; {_ANGR_SUFFIX}"
        )
    find_set = frozenset(_ret_addresses(target, info, start, section))
    if not find_set:
        raise AnalysisError(
            f"no ret instruction was found scanning section {section.name!r} from 0x{start:x}, "
            f"so explore_symbolic has nothing to use as find; {_ANGR_SUFFIX}"
        )
    project, notes = _build_project(module, target, info, section)
    try:
        state = project.factory.entry_state(addr=start)
        entry_values = _seed_registers(module, state, seeds)
        simgr = project.factory.simgr(state)
    except AnalysisError:  # pragma: no cover - nothing above raises this
        raise
    except Exception as exc:
        raise AnalysisError(
            f"angr could not prepare an entry state at 0x{start:x} in {target.name} "
            f"({type(exc).__name__}: {exc}); {_ANGR_SUFFIX}"
        ) from exc

    paths: list[SolverPath] = []
    truncated = False
    steps_used = 0
    tick = 0
    error_cursor = 0
    dropped_found = 0
    dropped_errors = 0
    error_notes: list[str] = []
    unconstrained_before = len(simgr.stashes.get("unconstrained", ()))
    try:
        while simgr.active:
            if len(paths) >= path_limit:
                truncated = True
                notes.append(
                    f"path cap reached (max_paths={path_limit}) with {len(simgr.active)} "
                    "state(s) still unexplored; those paths are not reported"
                )
                break
            if steps_used >= step_budget:
                truncated = True
                take = min(len(simgr.active), path_limit - len(paths))
                for stopped_state in simgr.active[:take]:
                    paths.append(
                        _path_from_state(stopped_state, _STOP_BUDGET, tick, entry_values)
                    )
                notes.append(
                    f"step budget ran out (max_steps={step_budget}) after {tick} tick(s) with "
                    f"{len(simgr.active)} state(s) still active; they are reported as "
                    "'budget' paths and never reached a ret"
                )
                if len(simgr.active) > take:
                    notes.append(
                        f"{len(simgr.active) - take} budget-stopped state(s) were not reported "
                        f"because the path cap ({path_limit}) was hit"
                    )
                break
            if len(simgr.active) > path_limit:
                dropped = len(simgr.active) - path_limit
                truncated = True
                simgr.stashes["active"] = simgr.stashes["active"][:path_limit]
                notes.append(
                    f"the active-state cap (max_paths={path_limit}) dropped {dropped} state(s) "
                    "to bound memory; those paths were not explored"
                )
            running = len(simgr.active)
            tick += 1
            try:
                simgr.step(num_inst=1)
            except TypeError:  # pragma: no cover - angr version drift
                simgr.step()  # one basic block per tick; the budget still bounds the run
            steps_used += running
            still_active: list[Any] = []
            for found_state in simgr.active:
                if _at_ret(found_state, find_set):
                    if len(paths) < path_limit:
                        paths.append(
                            _path_from_state(found_state, _STOP_RETURN, tick, entry_values)
                        )
                    else:
                        dropped_found += 1
                        truncated = True
                else:
                    still_active.append(found_state)
            simgr.stashes["active"] = still_active
            new_errors = simgr.errored[error_cursor:]
            error_cursor = len(simgr.errored)
            for record in new_errors:
                if len(paths) < path_limit:
                    paths.append(_path_from_state(record.state, _STOP_ERROR, tick, entry_values))
                else:
                    dropped_errors += 1
                    truncated = True
                if len(error_notes) < _MAX_ERROR_NOTES:
                    error_notes.append(f"{type(record.error).__name__}: {record.error}")
    except AnalysisError:  # pragma: no cover - nothing above raises this
        raise
    except Exception as exc:
        raise AnalysisError(
            f"angr exploration of 0x{start:x} in {target.name} failed after {steps_used} "
            f"executed instruction(s) ({type(exc).__name__}: {exc}); {_ANGR_SUFFIX}"
        ) from exc

    unconstrained_delta = len(simgr.stashes.get("unconstrained", ())) - unconstrained_before
    if unconstrained_delta > 0:
        notes.append(
            f"{unconstrained_delta} state(s) became unconstrained (a symbolic jump or return "
            "target angr cannot enumerate here) and are not reported"
        )
    if dropped_found:
        notes.append(
            f"{dropped_found} found path(s) were dropped because the path cap "
            f"(max_paths={path_limit}) was reached"
        )
    if dropped_errors:
        notes.append(
            f"{dropped_errors} errored state(s) were not reported because the path cap "
            f"(max_paths={path_limit}) was reached"
        )
    for note in error_notes[:_MAX_ERROR_NOTES]:
        notes.append(f"a state errored ({note}); that path is reported with stopped_reason 'error'")
    if not paths and not truncated and not notes:
        notes.append(
            "angr stopped without finding a ret, an error or an active state; nothing to report"
        )
    return SymbolicResult(
        address=start,
        paths=tuple(paths),
        solver=_SOLVER_NAME,
        truncated=truncated,
        warnings=tuple(notes),
        evidence=_result_evidence(
            start=start, paths=paths, truncated=truncated, max_paths=path_limit, max_steps=step_budget
        ),
    )

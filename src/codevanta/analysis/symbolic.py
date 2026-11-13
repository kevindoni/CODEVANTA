"""Path exploration for one function, without installing a solver.

Two questions motivate this module: *which distinct routes through this function
exist*, and *what does each route return*. It answers them by **enumerating
branch decisions**, replaying each decision sequence on a private unicorn CPU
(the same bounded, offline emulator :mod:`codevanta.analysis.emulate` uses), and
reporting one :class:`Entry` per path. Nothing is executed on the host, no
symbolic variable is created, and no constraint is ever solved -- angr/Z3 are
*optional* here and only used by :func:`explore_with_angr`.

Path semantics
--------------
A path is a tuple of decisions, one per *conditional* branch met on the way.
Exploration is breadth first over that decision tree:

1. Replay the decision tuple from the entry point on a freshly initialised CPU.
2. At the ``k``-th conditional branch, if a decision is recorded use it, else
   follow the **observed** direction -- the one the real flags produced -- and
   enqueue ``walked + (not observed,)`` as a child.
3. A ``ret`` whose popped address lies outside the explored section completes
   the path (``stopped_reason="return"``, ``return_value`` = ``rax``/``eax`` at
   that ``ret``). An intra-section ``ret`` -- the return of a callee this path
   called -- is executed and exploration continues, exactly as in ``emulate``.
4. Paths stop for one of four reasons: ``return``, ``budget`` (the shared
   ``max_steps`` instruction budget ran out), ``blocked`` (this module cannot
   justify a successor) or ``unmapped`` (the emulated code touched an address
   that is not mapped).

Explored versus assumed
-----------------------
That distinction is the whole point of the module, so every branch carries a
:data:`Basis`:

``observed``
    The direction was produced by real emulation: the flags (or the counter
    register) were computed by the instructions that ran before the branch, and
    the branch instruction itself executed on the CPU. Nothing was forced.
``seeded``
    The *opposite* direction of a conditional branch. The flags are rewritten to
    the nearest assignment that satisfies that condition (``rflags`` bits are
    searched exhaustively -- 64 combinations -- and the minimum Hamming distance
    from the observed value is chosen), or -- for ``jrcxz``/``jecxz``/``jcxz`` --
    the counter register is written. The branch instruction then executes, and
    the explorer checks that it really landed on the intended successor. **This
    is an assumption about feasibility, not a solved constraint**: no path
    predicate is built, no model is checked, and a ``seeded`` side may well be
    unreachable for the real program.

Unconditional ``jmp``/``call`` transfers carry no decision, so they are neither
``observed`` nor ``seeded``: they are *executed*, and the address the CPU landed
on is recorded in :attr:`Entry.taken_targets`. An indirect transfer contributes
only the target its operand held at that point -- other targets it could hold
are not explored, and the entry says so in a warning.

A branch this module cannot decide is **never** guessed: ``loop``/``loope``/
``loopne`` (they decrement ``rcx`` before testing it), an unknown ``j*``
mnemonic, an indirect transfer leaving the section, an undecodable instruction,
or a seed that failed to steer the branch all end the path with
``stopped_reason="blocked"`` and a note saying exactly what was not resolved.
If a seed fails to steer the branch, the path is discarded rather than reported
as if it had reached the intended successor.

What is *not* explored: memory state is shared within one replay only, and every
path starts from the same ABI-seeded state (``initial_registers`` plus the
``rsp``/``rbp`` defaults from ``emulate``), so a path is not a proof of
reachability for arbitrary inputs -- it is the set of routes this explorer could
walk with the given seeds, with the ``seeded`` sides flagged. Two paths that
rejoin are reported separately: exploration is path-sensitive over decisions,
not a state merge.

Cost and caps
-------------
``max_paths`` (default :data:`DEFAULT_MAX_PATHS`) caps emitted paths and
``max_steps`` (default :data:`DEFAULT_MAX_STEPS`) caps emulator instructions
*including replays*, so the work is bounded no matter how branchy the function
is. Because each path is replayed from the entry point, real cost is
``O(paths x path length)``; the emulator instance and its mappings are created
once and re-initialised between replays.

Supported machines
------------------
x86 and x86-64 only, like ``emulate``: the return-value, stack and register
vocabulary here is x86-specific. Anything else raises
:class:`~codevanta.core.report.AnalysisError` instead of guessing, as does a
missing unicorn build, a bad address, or an out-of-range limit.

The angr bridge
---------------
:func:`explore_with_angr` is **optional** and never imported at module import
time: :data:`ANGR_AVAILABLE` only records whether a module called ``angr`` is
findable, and the import happens inside the call. Without angr the function
raises :class:`~codevanta.core.report.AnalysisError` naming angr and the extra
that installs it. When angr *is* present the paths come from angr's symbolic
execution, so the evidence says so and no ``observed``/``seeded`` basis is
claimed for them -- that distinction belongs to the unicorn explorer.
"""


from __future__ import annotations

import faulthandler as _faulthandler
import importlib.util as _importlib_util
from collections import deque
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import capstone

from codevanta.analysis import emulate
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError, read_code
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "ANGR_AVAILABLE",
    "DEFAULT_MAX_PATHS",
    "DEFAULT_MAX_STEPS",
    "EMULATOR_AVAILABLE",
    "MAX_BLOCK_INSTRUCTIONS",
    "MAX_MAX_PATHS",
    "MAX_MAX_STEPS",
    "Basis",
    "Branch",
    "Entry",
    "PathExploration",
    "StopReason",
    "angr_available",
    "explore_paths",
    "explore_with_angr",
]

_unicorn: Any = None
_x86_const: Any = None

try:  # optional: the unicorn explorer needs it, the module must import without it
    import unicorn as _unicorn
    import unicorn.x86_const as _x86_const
except Exception:  # pragma: no cover - depends on the environment
    pass


# ---- limits ---------------------------------------------------------------

#: Paths reported when the caller does not pass ``max_paths``.
DEFAULT_MAX_PATHS = 64

#: Hard ceiling on ``max_paths`` (bounded work, whatever the caller asks).
MAX_MAX_PATHS = 4096

#: Instruction budget used when the caller does not pass ``max_steps``.
DEFAULT_MAX_STEPS = 2000

#: Hard ceiling on ``max_steps``.
MAX_MAX_STEPS = 200_000

#: A single basic block is scanned for at most this many instructions before the
#: explorer re-scans from the next address (a long straight-line tail still runs).
MAX_BLOCK_INSTRUCTIONS = 64

#: Instructions a linear scan reads when collecting a function's ``ret`` sites
#: for the angr bridge.
MAX_SCAN_INSTRUCTIONS = 4096

#: True when a unicorn build is importable; the unicorn explorer is refused
#: otherwise. Mirrors :data:`codevanta.analysis.emulate.EMULATOR_AVAILABLE`.
EMULATOR_AVAILABLE = emulate.EMULATOR_AVAILABLE

#: Evidence identity for the unicorn explorer.
_EVIDENCE_SOURCE = "symbolic.unicorn"
_EVIDENCE_METHOD = "branch_decision_replay"

#: Evidence identity for the angr bridge.
_ANGR_SOURCE = "symbolic.angr"
_ANGR_METHOD = "symbolic_execution"

#: What a caller needs to install angr.
_ANGR_HINT = "pip install 'codevanta[decompilers]'"

# ---- stop reasons and bases -----------------------------------------------

#: Why one path ended (see the module docstring).
StopReason = Literal["return", "budget", "blocked", "unmapped"]

#: How one conditional branch direction was justified (see the module docstring).
Basis = Literal["observed", "seeded"]

_STOP_RETURN: StopReason = "return"
_STOP_BUDGET: StopReason = "budget"
_STOP_BLOCKED: StopReason = "blocked"
_STOP_UNMAPPED: StopReason = "unmapped"

_BASIS_OBSERVED: Basis = "observed"
_BASIS_SEEDED: Basis = "seeded"

#: Instruction mnemonics that leave the explored function (Capstone's naming).
_RET_MNEMONICS = frozenset({"ret", "retf", "retn", "retq", "iret", "iretd", "iretq"})

#: ``BinaryInfo.architecture`` spellings accepted as 64-bit x86.
_X86_64_NAMES = frozenset({"x86_64", "x86-64", "amd64", "em_amd64"})

#: ``BinaryInfo.architecture`` spellings accepted as 32-bit x86.
_X86_32_NAMES = frozenset({"x86", "i386", "i686", "em_386"})

#: Registers snapshotted per bitness (the same vocabulary as ``emulate``).
_REGISTERS_64 = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "rflags",
)
_REGISTERS_32 = (
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags",
)

#: Room left between the initial stack pointer and the top of the stack region,
#: so a prologue can push without leaving the mapping (mirrors ``emulate``).
_STACK_HEADROOM = 0x100

#: Bytes a linear scan may read per block (the widest x86 instruction is 15).
_MAX_INSTRUCTION_BYTES = 15

#: ``loop``/``loope``/``loopne`` decrement the counter before testing it, which
#: this explorer does not model; they end the path as ``blocked``.
_LOOP_MNEMONICS = frozenset({"loop", "loope", "loopz", "loopne", "loopnz"})


# ---- results --------------------------------------------------------------


@dataclass(frozen=True)
class Branch:
    """One conditional branch a path met, and how its direction was justified.

    Attributes:
        address: Address of the branch instruction.
        mnemonic: Capstone mnemonic (``"jz"``, ``"jle"``, ``"jrcxz"``, ...).
        taken: ``True`` when the path took the branch target, ``False`` when it
            fell through.
        target: Address the path actually continued at (the branch target, or
            the fall-through address when ``taken`` is ``False``).
        basis: ``"observed"`` when real emulation produced this direction,
            ``"seeded"`` when the flags/counter were rewritten to force it.
        note: Exact description of the seed, empty for an observed direction.
    """

    address: int
    mnemonic: str
    taken: bool
    target: int
    basis: Basis
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "address": f"0x{self.address:x}",
            "mnemonic": self.mnemonic,
            "taken": self.taken,
            "target": f"0x{self.target:x}",
            "basis": self.basis,
            "note": self.note,
        }


@dataclass(frozen=True)
class Entry:
    """One explored path: where it went, how it ended, what it left behind.

    Attributes:
        index: Position in :attr:`PathExploration.entries` (deterministic).
        decisions: The conditional branches on this path, in the order met.
        taken_targets: Addresses control transferred to, in order: taken
            conditional targets and every unconditional ``jmp``/``call`` target.
        registers: Register snapshot taken at the end of the path.
        return_value: ``rax``/``eax`` when the path reached a ``ret`` that left
            the section, otherwise ``None`` -- a value left in ``rax`` by a path
            stopped for any other reason is not a return value.
        stopped_reason: Why the path ended (see the module docstring).
        instructions: Instructions this path executed, replayed instructions
            included (the explorer's work unit, not a property of the code).
        warnings: Notes explaining every degradation, including the seed used to
            force a direction and anything that could not be resolved.
    """

    index: int
    decisions: tuple[Branch, ...]
    taken_targets: tuple[int, ...]
    registers: Mapping[str, int]
    return_value: int | None
    stopped_reason: StopReason
    instructions: int
    warnings: tuple[str, ...]

    @property
    def seeded(self) -> int:
        """Number of branches on this path whose direction was forced."""
        return sum(1 for branch in self.decisions if branch.basis == _BASIS_SEEDED)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict (addresses and values become hex)."""
        return {
            "index": self.index,
            "decisions": [branch.to_dict() for branch in self.decisions],
            "taken_targets": [f"0x{target:x}" for target in self.taken_targets],
            "registers": {
                name: f"0x{value:x}" for name, value in sorted(self.registers.items())
            },
            "return_value": (
                f"0x{self.return_value:x}" if self.return_value is not None else None
            ),
            "stopped_reason": self.stopped_reason,
            "instructions": self.instructions,
            "seeded_branches": self.seeded,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class PathExploration:
    """Every path one exploration produced, plus what it did and did not prove.

    Attributes:
        address: Virtual address the exploration started at.
        explorer: ``"unicorn"`` or ``"angr"`` -- which engine produced the paths.
        architecture: ``BinaryInfo.architecture`` of the analysed binary.
        bitness: 32 or 64.
        max_paths: Path cap the caller asked for.
        max_steps: Instruction budget the caller asked for (``0`` for the angr
            bridge, which explores until its own state manager stops).
        steps: Emulator instructions actually executed, replays included.
        complete: ``True`` only when nothing was left unexplored *and* every
            reported path reached a ``ret``. ``False`` means something is
            missing -- paths, returns, or both -- and ``warnings`` says what.
        entries: The paths, in deterministic breadth-first order.
        warnings: Exploration-level notes (truncation, limits, engine caveats).
        evidence: Provenance for the whole exploration, including what was
            explored and what was only assumed.
    """

    address: int
    explorer: str
    architecture: str
    bitness: int
    max_paths: int
    max_steps: int
    steps: int
    complete: bool
    entries: tuple[Entry, ...]
    warnings: tuple[str, ...]
    evidence: Evidence

    @property
    def paths(self) -> int:
        """Number of paths reported."""
        return len(self.entries)

    @property
    def unresolved(self) -> int:
        """Paths that ended without a return or a budget stop."""
        return sum(
            1
            for entry in self.entries
            if entry.stopped_reason in (_STOP_BLOCKED, _STOP_UNMAPPED)
        )

    @property
    def return_values(self) -> tuple[int, ...]:
        """Return values of the paths that reached a ``ret``, in path order."""
        return tuple(
            entry.return_value
            for entry in self.entries
            if entry.return_value is not None and entry.stopped_reason == _STOP_RETURN
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict (hex addresses, lists, no enums)."""
        return {
            "address": f"0x{self.address:x}",
            "explorer": self.explorer,
            "architecture": self.architecture,
            "bitness": self.bitness,
            "max_paths": self.max_paths,
            "max_steps": self.max_steps,
            "steps": self.steps,
            "complete": self.complete,
            "paths": self.paths,
            "unresolved": self.unresolved,
            "return_values": [f"0x{value:x}" for value in self.return_values],
            "entries": [entry.to_dict() for entry in self.entries],
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


# ---- small helpers --------------------------------------------------------


def _align_up(value: int) -> int:
    """Round ``value`` up to the next page boundary (mirrors ``emulate``)."""
    if value <= 0:
        return 0
    page = emulate.PAGE_SIZE
    return (value + page - 1) & ~(page - 1)


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping/adjacent page spans so each page is mapped once."""
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return merged


def _machine_bits(info: BinaryInfo) -> int | None:
    """Return 32 or 64 when this module can explore ``info``, else ``None``.

    Mirrors ``emulate._machine_bits`` (a private helper there, so it is restated
    here rather than imported): only x86 modes are accepted, because the return
    register, stack and register vocabulary of this module is x86-specific.
    """
    name = (info.architecture or "").strip().lower()
    if name in _X86_64_NAMES:
        bits = 64
    elif name in _X86_32_NAMES:
        bits = 32
    else:
        return None
    if int(info.bitness) in (32, 64):
        bits = int(info.bitness)
    if (info.endianness or "little").strip().lower() == "big":
        return None  # x86 is little-endian only
    return bits


def _reg_const(name: str) -> int | None:
    """Map a unicorn register name (``"rax"``, ``"rflags"``) to its constant."""
    if _x86_const is None:
        return None
    value = getattr(_x86_const, f"UC_X86_REG_{name.upper()}", None)
    return int(value) if isinstance(value, int) else None


def _validated_address(address: int) -> int:
    """Validate a start address (positive int) and return it."""
    if isinstance(address, bool) or not isinstance(address, int):
        raise AnalysisError(f"address must be an int, not {type(address).__name__}")
    if address <= 0:
        raise AnalysisError(f"address must be positive, got 0x{address:x}")
    return address


def _validated_limit(name: str, value: int, ceiling: int) -> int:
    """Validate one exploration cap against its ceiling."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError(f"{name} must be an int")
    if value < 1:
        raise AnalysisError(f"{name} must be >= 1")
    if value > ceiling:
        raise AnalysisError(f"{name} too large ({value}); limit is {ceiling}")
    return value


def _validated_registers(
    initial_registers: Mapping[str, int] | None, bits: int
) -> dict[str, int]:
    """Normalize and validate caller-supplied register seeds.

    Raises:
        AnalysisError: On an unknown register name, a non-int value, or a value
            that does not fit the machine word.
    """
    seeds: dict[str, int] = {}
    if not initial_registers:
        return seeds
    limit = 1 << bits
    for name, value in initial_registers.items():
        key = str(name).strip().lower()
        if _reg_const(key) is None:
            raise AnalysisError(f"unknown {bits}-bit register name {name!r}")
        if isinstance(value, bool) or not isinstance(value, int):
            raise AnalysisError(f"register {key!r} must be seeded with an int")
        if value < 0 or value >= limit:
            raise AnalysisError(f"value for register {key!r} does not fit in {bits} bits")
        seeds[key] = int(value)
    return seeds


# ---- flags and branch conditions ------------------------------------------

#: The six x86 condition flags, with their ``rflags`` bit positions. Only these
#: bits are ever rewritten (``IF``, ``DF`` and the reserved bit are preserved).
_FLAG_BITS: tuple[tuple[str, int], ...] = (
    ("cf", 0x0001),
    ("pf", 0x0004),
    ("af", 0x0010),
    ("zf", 0x0040),
    ("sf", 0x0080),
    ("of", 0x0800),
)

#: Mask covering exactly :data:`_FLAG_BITS`.
_FLAG_MASK = 0x0001 | 0x0004 | 0x0010 | 0x0040 | 0x0080 | 0x0800

#: ``rflags`` value a fresh x86 CPU has (bit 1 is always set).
_DEFAULT_EFLAGS = 0x2


@dataclass(frozen=True)
class _Flags:
    """The six condition flags, decoded from ``rflags``."""

    cf: bool
    pf: bool
    af: bool
    zf: bool
    sf: bool
    of: bool

    @classmethod
    def from_eflags(cls, value: int) -> _Flags:
        """Decode the condition flags out of an ``rflags`` value."""
        return cls(
            cf=bool(value & 0x0001),
            pf=bool(value & 0x0004),
            af=bool(value & 0x0010),
            zf=bool(value & 0x0040),
            sf=bool(value & 0x0080),
            of=bool(value & 0x0800),
        )

    def to_bits(self) -> int:
        """Encode these flags as ``rflags`` bits."""
        return (
            (0x0001 if self.cf else 0)
            | (0x0004 if self.pf else 0)
            | (0x0010 if self.af else 0)
            | (0x0040 if self.zf else 0)
            | (0x0080 if self.sf else 0)
            | (0x0800 if self.of else 0)
        )

    def distance(self, other: _Flags) -> int:
        """Number of condition flags that differ from ``other``."""
        return sum(
            1 for name, _bit in _FLAG_BITS if getattr(self, name) != getattr(other, name)
        )


#: Canonical condition predicates, named after the ``jcc`` that tests them.
#: Aliases are folded onto these by :data:`_CONDITION_ALIASES`.
_CONDITIONS: dict[str, Callable[[_Flags], bool]] = {
    "jz": lambda f: f.zf,
    "jnz": lambda f: not f.zf,
    "jc": lambda f: f.cf,
    "jnc": lambda f: not f.cf,
    "jbe": lambda f: f.cf or f.zf,
    "ja": lambda f: not f.cf and not f.zf,
    "js": lambda f: f.sf,
    "jns": lambda f: not f.sf,
    "jo": lambda f: f.of,
    "jno": lambda f: not f.of,
    "jp": lambda f: f.pf,
    "jnp": lambda f: not f.pf,
    "jl": lambda f: f.sf != f.of,
    "jge": lambda f: f.sf == f.of,
    "jle": lambda f: f.zf or (f.sf != f.of),
    "jg": lambda f: not f.zf and f.sf == f.of,
}

#: Every ``jcc`` spelling Capstone produces, folded onto :data:`_CONDITIONS`.
_CONDITION_ALIASES: dict[str, str] = {
    "jz": "jz", "je": "jz",
    "jnz": "jnz", "jne": "jnz",
    "jc": "jc", "jb": "jc", "jnae": "jc",
    "jnc": "jnc", "jae": "jnc", "jnb": "jnc",
    "jbe": "jbe", "jna": "jbe",
    "ja": "ja", "jnbe": "ja",
    "js": "js", "jns": "jns",
    "jo": "jo", "jno": "jno",
    "jp": "jp", "jpe": "jp",
    "jnp": "jnp", "jpo": "jnp",
    "jl": "jl", "jnge": "jl",
    "jge": "jge", "jnl": "jge",
    "jle": "jle", "jng": "jle",
    "jg": "jg", "jnle": "jg",
}

#: ``jcc`` forms that test a counter register instead of a flag. Seeding them
#: means writing the counter, which is exact for these three: unlike ``loop``
#: they do not decrement it.
_COUNTER_JUMPS: dict[str, str] = {"jrcxz": "rcx", "jecxz": "ecx", "jcxz": "cx"}


def _condition_holds(mnemonic: str, flags: _Flags) -> bool | None:
    """Evaluate a ``jcc`` against ``flags``.

    Returns:
        The condition's value, or ``None`` when this module does not know the
        mnemonic (the caller then blocks the path instead of guessing).
    """
    canonical = _CONDITION_ALIASES.get(mnemonic)
    if canonical is None:
        return None
    return bool(_CONDITIONS[canonical](flags))


def _flags_from_combination(combination: int) -> _Flags:
    """Build a flag set from the six bits of ``combination`` (:data:`_FLAG_BITS` order)."""
    return _Flags(
        cf=bool(combination & 0b000001),
        pf=bool(combination & 0b000010),
        af=bool(combination & 0b000100),
        zf=bool(combination & 0b001000),
        sf=bool(combination & 0b010000),
        of=bool(combination & 0b100000),
    )


def _seeded_flag_bits(canonical: str, desired: bool, observed: int) -> tuple[int, str]:
    """Pick the ``rflags`` bits that satisfy ``canonical == desired``.

    The six condition flags are enumerated exhaustively (64 combinations) and the
    assignment closest to the observed value wins, ties broken by the lowest bit
    pattern, so the result is deterministic. This is a *seed*: it says nothing
    about whether real inputs can produce these flags.

    Returns:
        ``(rflags_bits, description)``. The bits keep every non-flag bit of
        ``observed``; the description names exactly which flags changed.
    """
    predicate = _CONDITIONS[canonical]
    current = _Flags.from_eflags(observed)
    best: tuple[int, int] | None = None
    for combination in range(1 << len(_FLAG_BITS)):
        candidate = _flags_from_combination(combination)
        if bool(predicate(candidate)) != desired:
            continue
        distance = candidate.distance(current)
        if best is None or distance < best[0]:
            best = (distance, combination)
    if best is None:  # pragma: no cover - every predicate here is satisfiable
        return observed, "no flag assignment satisfies the condition"
    chosen = _flags_from_combination(best[1])
    changed = ", ".join(
        f"{name.upper()} {int(getattr(current, name))}->{int(getattr(chosen, name))}"
        for name, _bit in _FLAG_BITS
        if getattr(chosen, name) != getattr(current, name)
    )
    return (observed & ~_FLAG_MASK) | chosen.to_bits(), changed or "no flag changed"


# ---- decoding -------------------------------------------------------------


class _Decoder:
    """One-instruction Capstone decoder for the supported x86 modes."""

    def __init__(self, mode64: bool) -> None:
        mode = capstone.CS_MODE_64 if mode64 else capstone.CS_MODE_32
        self._cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
        self._cs.detail = True

    def decode(self, code: bytes, address: int) -> Any:
        """Decode one instruction from ``code``; ``None`` when it cannot be decoded."""
        if not code:
            return None
        for insn in self._cs.disasm(code, address, 1):
            return insn
        return None


@dataclass(frozen=True)
class _Scan:
    """A linearly scanned block: the instructions, and how the block ends.

    Attributes:
        instructions: Decoded instructions in address order, the terminator
            included when :attr:`terminator` is set.
        terminator: The final instruction when it transfers control, else ``None``.
        error: Why scanning stopped early (undecodable bytes, end of section),
            or ``None`` when the block ended on a terminator or a full scan.
    """

    instructions: tuple[Any, ...]
    terminator: Any | None
    error: str | None

    @property
    def body(self) -> tuple[Any, ...]:
        """Instructions before the terminator (the part that always runs)."""
        return self.instructions[:-1] if self.terminator is not None else self.instructions

    @property
    def end(self) -> int:
        """Address right after the last instruction of the scan."""
        if not self.instructions:
            return 0
        last = self.instructions[-1]
        return int(last.address) + int(last.size)


def _ends_block(insn: Any) -> bool:
    """True when ``insn`` transfers control, so the linear scan must stop there."""
    mnemonic = str(insn.mnemonic).lower()
    if mnemonic in _RET_MNEMONICS or mnemonic in _LOOP_MNEMONICS:
        return True
    if insn.group(capstone.CS_GRP_RET) or insn.group(capstone.CS_GRP_IRET):
        return True
    return bool(insn.group(capstone.CS_GRP_JUMP) or insn.group(capstone.CS_GRP_CALL))


class _Scanner:
    """Reads a block of code from the file and decodes it up to a control transfer."""

    def __init__(self, path: Path, info: BinaryInfo, decoder: _Decoder) -> None:
        self.path = path
        self.info = info
        self.decoder = decoder

    def scan(self, pc: int) -> _Scan:
        """Scan the block starting at ``pc``; never raises."""
        section = self.info.section_for_va(pc)
        if section is None:
            return _Scan((), None, f"address 0x{pc:x} is not mapped by any section")
        available = (section.virtual_address + section.size) - pc
        if available <= 0:
            return _Scan((), None, f"address 0x{pc:x} is past the end of {section.name!r}")
        if not section.is_executable:
            return _Scan(
                (),
                None,
                f"address 0x{pc:x} is inside {section.name!r}, which is not executable",
            )
        want = min(available, MAX_BLOCK_INSTRUCTIONS * _MAX_INSTRUCTION_BYTES)
        try:
            data = read_code(self.path, self.info, pc, want)
        except AnalysisError as exc:
            return _Scan((), None, f"no code bytes at 0x{pc:x}: {exc}")
        instructions: list[Any] = []
        offset = 0
        while offset < len(data) and len(instructions) < MAX_BLOCK_INSTRUCTIONS:
            insn = self.decoder.decode(bytes(data[offset:]), pc + offset)
            if insn is None:
                break
            instructions.append(insn)
            offset += int(insn.size)
            if _ends_block(insn):
                return _Scan(tuple(instructions), insn, None)
        if not instructions:
            return _Scan((), None, f"address 0x{pc:x} does not decode as an x86 instruction")
        if len(instructions) >= MAX_BLOCK_INSTRUCTIONS:
            # The scan cap, not the code: the caller continues from ``end``.
            return _Scan(tuple(instructions), None, None)
        if offset >= len(data) and offset >= available:
            return _Scan(
                tuple(instructions),
                None,
                f"the block at 0x{pc:x} runs past the readable bytes of {section.name!r}",
            )
        return _Scan(tuple(instructions), None, None)


# ---- the emulated machine -------------------------------------------------


@contextmanager
def _quiet_faulthandler() -> Iterator[None]:
    """Silence CPython's faulthandler around unicorn's guest-fault machinery.

    Unicorn resolves guest faults (``UC_ERR_READ_UNMAPPED`` and friends) with its
    own handler. On Windows CPython's ``faulthandler`` prints a first-chance
    "Windows fatal exception" line before that handler runs, which looks like a
    crash in the log even though nothing failed. Mirrors ``emulate._Runner.run``.
    """
    was_enabled = _faulthandler.is_enabled()
    if was_enabled:
        _faulthandler.disable()
    try:
        yield
    finally:
        if was_enabled:
            _faulthandler.enable()


class _Machine:
    """One unicorn CPU for one function, re-initialised between path replays.

    The emulator and its mappings are created once (:meth:`open`) and every path
    starts from the same state because :meth:`reset` rewrites the image bytes,
    zeroes the stack and re-seeds the registers. That is what makes a replay
    deterministic and the paths independent of each other.
    """

    def __init__(
        self,
        path: Path,
        info: BinaryInfo,
        address: int,
        *,
        bits: int,
        stack_size: int,
    ) -> None:
        self.path = path
        self.info = info
        self.address = address
        self.bits = bits
        self.stack_size = stack_size
        self.mode64 = bits == 64
        self.uc: Any = None
        self.ip = "rip" if self.mode64 else "eip"
        self.sp = "rsp" if self.mode64 else "esp"
        self.flags = "rflags" if self.mode64 else "eflags"
        self.return_register = "rax" if self.mode64 else "eax"
        self.names = _REGISTERS_64 if self.mode64 else _REGISTERS_32
        self._images: list[tuple[int, bytes]] = []
        self._mapped_pages: set[int] = set()
        self._mapped_bytes = 0
        self.regions: list[tuple[str, int, int]] = []
        self.stack_base = 0
        self.stack_top = 0
        section = info.section_for_va(address)
        if section is not None:
            self.region = (section.virtual_address, section.virtual_address + section.size)
            self.section_name = section.name
        else:  # pragma: no cover - the public API rejects this first
            self.region = (address, address + 1)
            self.section_name = "?"

    # ---- setup ------------------------------------------------------------

    def open(self) -> None:
        """Create the CPU and map the image and the stack."""
        uni = _unicorn
        arch = uni.UC_ARCH_X86
        mode = uni.UC_MODE_64 if self.mode64 else uni.UC_MODE_32
        with _quiet_faulthandler():
            self.uc = uni.Uc(arch, mode)
        self._map_image()
        self._map_stack()

    def _map_image(self) -> None:
        """Map every allocated section (page aligned, bounded), then copy its bytes."""
        spans: list[tuple[int, int]] = []
        sections: list[Any] = []
        for section in self.info.sections:
            if section.size <= 0 or section.virtual_address <= 0:
                continue
            if section.size > emulate.MAX_SECTION_BYTES:
                continue
            start = section.virtual_address & ~(emulate.PAGE_SIZE - 1)
            end = _align_up(section.virtual_address + section.size)
            if self._mapped_bytes + (end - start) > emulate.MAX_TOTAL_MAPPED:
                break
            self._mapped_bytes += end - start
            spans.append((start, end))
            sections.append(section)
        for start, end in _merge_spans(spans):
            self._map_pages(start, end, "image")
        for section in sections:
            size = section.raw_size or section.size
            try:
                data = read_code(self.path, self.info, section.virtual_address, size)
            except AnalysisError:
                continue
            if not data:
                continue
            self._images.append((section.virtual_address, bytes(data)))
            self.uc.mem_write(section.virtual_address, data)

    def _map_stack(self) -> None:
        """Map the stack region where ``emulate`` puts it."""
        base = emulate.STACK_BASE_64 if self.mode64 else emulate.STACK_BASE_32
        start = base & ~(emulate.PAGE_SIZE - 1)
        end = _align_up(base + self.stack_size)
        self._mapped_bytes += end - start
        self.stack_base, self.stack_top = start, end
        self._map_pages(start, end, "stack")

    def _map_pages(self, start: int, end: int, kind: str) -> None:
        """Map the page range ``[start, end)``, skipping pages already mapped."""
        run_start: int | None = None
        page = start
        while page < end:
            if page in self._mapped_pages:
                if run_start is not None:
                    self._commit(run_start, page, kind)
                    run_start = None
            else:
                self._mapped_pages.add(page)
                if run_start is None:
                    run_start = page
            page += emulate.PAGE_SIZE
        if run_start is not None:
            self._commit(run_start, end, kind)

    def _commit(self, start: int, end: int, kind: str) -> None:
        """Ask unicorn for one contiguous page run and record it."""
        self.uc.mem_map(start, end - start)
        self.regions.append((kind, start, end))

    def reset(self, seeds: Mapping[str, int]) -> None:
        """Restore the pristine state: image bytes, zeroed stack, seeded registers."""
        for address, data in self._images:
            self.uc.mem_write(address, data)
        with _quiet_faulthandler():
            self.uc.mem_write(self.stack_base, bytes(self.stack_top - self.stack_base))
        for name in self.names:
            self.write_register(name, 0)
        stack_pointer = self.stack_top - _STACK_HEADROOM
        self.write_register(self.ip, self.address)
        self.write_register(self.sp, stack_pointer)
        self.write_register("rbp" if self.mode64 else "ebp", stack_pointer)
        self.write_register(self.flags, _DEFAULT_EFLAGS)
        for name, value in seeds.items():
            self.write_register(name, value)

    # ---- state access -----------------------------------------------------

    def read_register(self, name: str) -> int | None:
        """Read one register, or ``None`` when the name is unknown here."""
        constant = _reg_const(name)
        if constant is None:
            return None
        try:
            return int(self.uc.reg_read(constant))
        except Exception:  # pragma: no cover - a writable register reads back fine
            return None

    def write_register(self, name: str, value: int) -> None:
        """Write one register, ignoring names this mode does not expose."""
        constant = _reg_const(name)
        if constant is None:
            return
        self.uc.reg_write(constant, int(value))

    def snapshot(self) -> dict[str, int]:
        """Snapshot the general-purpose registers of this mode."""
        state: dict[str, int] = {}
        for name in self.names:
            value = self.read_register(name)
            if value is not None:
                state[name] = value
        return state

    def read_pointer(self, name: str) -> int | None:
        """Read the machine word ``name`` points at, or ``None`` when unreadable."""
        address = self.read_register(name)
        if address is None:
            return None
        try:
            raw = bytes(self.uc.mem_read(address, self.bits // 8))
        except Exception:
            return None
        return int.from_bytes(raw, "little")

    def eflags(self) -> int:
        """Read ``rflags``/``eflags`` (the default value when it cannot be read)."""
        value = self.read_register(self.flags)
        return _DEFAULT_EFLAGS if value is None else value

    def in_region(self, address: int) -> bool:
        """True when ``address`` is inside the section being explored."""
        low, high = self.region
        return low <= address < high

    # ---- execution --------------------------------------------------------

    def run_to(self, begin: int, until: int, count: int) -> None:
        """Emulate ``begin`` until ``until`` (exclusive) or ``count`` instructions."""
        with _quiet_faulthandler():
            self.uc.emu_start(begin, until, 0, count)

    def step(self, address: int) -> int:
        """Execute exactly one instruction at ``address`` and return the new ``ip``."""
        with _quiet_faulthandler():
            self.uc.emu_start(address, 0, 0, 1)
        current = self.read_register(self.ip)
        return -1 if current is None else current

    def close(self) -> None:
        """Drop the emulator so unicorn can free its native handle.

        ``Uc`` registers a ``weakref.finalize`` that closes the handle when the
        instance is collected, so dropping the reference is all this has to do
        (calling ``release_handle`` could close the same handle twice).
        """
        self.uc = None


def _classify_fault(exc: Any, pc: int | None) -> tuple[StopReason, str]:
    """Turn one unicorn exception into a stop reason plus an exact note."""
    uni = _unicorn
    errno = getattr(exc, "errno", None)
    at = f" at 0x{pc:x}" if pc is not None else ""
    unmapped = {
        getattr(uni, "UC_ERR_READ_UNMAPPED", -6),
        getattr(uni, "UC_ERR_WRITE_UNMAPPED", -7),
        getattr(uni, "UC_ERR_FETCH_UNMAPPED", -8),
    }
    if errno in unmapped:
        return (
            _STOP_UNMAPPED,
            f"the path touched an address that is not mapped{at}: emulation stopped "
            f"there, so this path is incomplete (not a return)",
        )
    protection = {
        getattr(uni, "UC_ERR_READ_PROT", -9),
        getattr(uni, "UC_ERR_WRITE_PROT", -10),
        getattr(uni, "UC_ERR_FETCH_PROT", -11),
        getattr(uni, "UC_ERR_READ_UNALIGNED", -12),
        getattr(uni, "UC_ERR_WRITE_UNALIGNED", -13),
        getattr(uni, "UC_ERR_FETCH_UNALIGNED", -14),
    }
    if errno in protection:
        return (_STOP_UNMAPPED, f"memory protection violation{at}: {exc}")
    if errno == getattr(uni, "UC_ERR_INSN_INVALID", -15):
        return (
            _STOP_BLOCKED,
            f"unicorn could not decode the instruction{at}: {exc}; the path is unresolved",
        )
    return (_STOP_BLOCKED, f"emulation failed{at}: {exc}; the path is unresolved")


def _direct_target(insn: Any) -> int | None:
    """Return the constant operand of an instruction (its branch target), if any."""
    for operand in getattr(insn, "operands", ()):
        value = getattr(operand, "imm", None)
        if isinstance(value, int):
            return value
    return None


# ---- the explorer ---------------------------------------------------------


class _Explorer:
    """Breadth-first enumeration of branch decisions, one replay per path."""

    def __init__(
        self,
        machine: _Machine,
        scanner: _Scanner,
        *,
        max_paths: int,
        max_steps: int,
        seeds: Mapping[str, int],
    ) -> None:
        self.machine = machine
        self.scanner = scanner
        self.max_paths = max_paths
        self.max_steps = max_steps
        self.seeds = seeds
        self.entries: list[Entry] = []
        self.steps = 0
        self.warnings: list[str] = []

    # ---- driver -----------------------------------------------------------

    def run(self) -> None:
        """Enumerate paths until the tree, the path cap or the budget ends."""
        queue: deque[tuple[bool, ...]] = deque([()])
        truncated = False
        budget_stop = False
        while queue:
            if len(self.entries) >= self.max_paths:
                truncated = True
                break
            if self.steps >= self.max_steps:
                budget_stop = True
                break
            entry, children, used = self._walk(queue.popleft())
            self.steps += used
            self.entries.append(entry)
            queue.extend(children)
        if truncated:
            self.warnings.append(
                f"path limit reached: {self.max_paths} path(s) were reported and the branch "
                "tree is not exhausted; raise max_paths to explore further"
            )
        if budget_stop:
            self.warnings.append(
                f"step budget exhausted after {self.steps} emulated instruction(s); the "
                "remaining paths were not explored"
            )
        if truncated or budget_stop:
            self.warnings.append(f"{len(queue)} path(s) were left unexplored")
        incomplete = sum(
            1 for entry in self.entries if entry.stopped_reason != _STOP_RETURN
        )
        if incomplete and not truncated and not budget_stop:
            self.warnings.append(
                f"{incomplete} path(s) ended without a return (blocked, unmapped or budget); "
                "the branch tree is not fully resolved"
            )

    @property
    def complete(self) -> bool:
        """True when nothing was left unexplored and every path reached a ``ret``."""
        return not self.warnings and all(
            entry.stopped_reason == _STOP_RETURN for entry in self.entries
        )

    # ---- one path ---------------------------------------------------------

    def _walk(self, plan: tuple[bool, ...]) -> tuple[Entry, list[tuple[bool, ...]], int]:
        """Replay one decision plan and report exactly where it ended.

        Returns:
            ``(entry, children, instructions)``: the path's entry, the decision
            tuples still to explore, and the instructions this replay executed.
        """
        machine = self.machine
        machine.reset(self.seeds)
        pc = machine.address
        walked: list[bool] = []
        taken: list[int] = []
        branches: list[Branch] = []
        notes: list[str] = []
        children: list[tuple[bool, ...]] = []
        used = 0

        def finish(
            reason: StopReason, value: int | None
        ) -> tuple[Entry, list[tuple[bool, ...]], int]:
            return (
                self._entry(branches, taken, reason, value, notes, used),
                children,
                used,
            )

        while True:
            if self.steps + used >= self.max_steps:
                notes.append(
                    f"step budget exhausted after {self.max_steps} instruction(s); the path "
                    f"is truncated at 0x{pc:x} and has no return value"
                )
                return finish(_STOP_BUDGET, None)
            scan = self.scanner.scan(pc)
            if not scan.instructions:
                notes.append(scan.error or f"nothing to emulate at 0x{pc:x}")
                return finish(_STOP_BLOCKED, None)
            body = scan.body
            terminator = scan.terminator
            until = int(terminator.address) if terminator is not None else scan.end
            if body:
                try:
                    machine.run_to(pc, until, len(body))
                except Exception as exc:  # a unicorn fault, classified by errno
                    return finish(*self._fault(exc, notes))
                used += len(body)
            if terminator is None:
                if scan.error is not None:
                    notes.append(scan.error)
                    return finish(_STOP_BLOCKED, None)
                pc = scan.end
                continue
            address = int(terminator.address)
            mnemonic = str(terminator.mnemonic).lower()
            if (
                mnemonic in _RET_MNEMONICS
                or terminator.group(capstone.CS_GRP_RET)
                or terminator.group(capstone.CS_GRP_IRET)
            ):
                target = machine.read_pointer(machine.sp)
                if target is not None and machine.in_region(target):
                    try:
                        landed = machine.step(address)
                    except Exception as exc:  # pragma: no cover - a mapped stack
                        return finish(*self._fault(exc, notes))
                    used += 1
                    taken.append(landed)
                    pc = landed
                    continue
                if target is None:
                    notes.append(
                        f"the return address at {machine.sp} could not be read at "
                        f"0x{address:x}; the value in {machine.return_register} is reported "
                        "as this path's return value"
                    )
                return finish(_STOP_RETURN, machine.read_register(machine.return_register))
            if mnemonic in _LOOP_MNEMONICS:
                counter = "rcx" if machine.mode64 else "ecx"
                notes.append(
                    f"the {mnemonic!r} instruction at 0x{address:x} decrements {counter} "
                    "before testing it, which this explorer does not model; the path is "
                    "unresolved"
                )
                return finish(_STOP_BLOCKED, None)
            canonical = _CONDITION_ALIASES.get(mnemonic)
            counter_name = _COUNTER_JUMPS.get(mnemonic)
            if canonical is not None or counter_name is not None:
                observed: bool | None = None
                if canonical is not None:
                    observed = _condition_holds(
                        canonical, _Flags.from_eflags(machine.eflags())
                    )
                else:
                    counter_value = machine.read_register(str(counter_name))
                    if counter_value is not None:
                        observed = counter_value == 0
                if observed is None:
                    notes.append(
                        f"the {mnemonic!r} instruction at 0x{address:x} cannot be evaluated by "
                        "this explorer; the path is unresolved"
                    )
                    return finish(_STOP_BLOCKED, None)
                index = len(walked)
                if index < len(plan):
                    chosen = plan[index]
                else:
                    chosen = observed
                    children.append(tuple(walked) + (not observed,))
                basis: Basis = _BASIS_OBSERVED
                note = ""
                if chosen != observed:
                    basis = _BASIS_SEEDED
                    note = self._seed_branch(
                        mnemonic, canonical, counter_name, chosen, machine.eflags()
                    )
                    notes.append(f"0x{address:x}: {note}")
                short = "taken" if chosen else "fall-through"
                expected = (
                    _direct_target(terminator)
                    if chosen
                    else address + int(terminator.size)
                )
                try:
                    landed = machine.step(address)
                except Exception as exc:
                    return finish(*self._fault(exc, notes))
                used += 1
                if expected is not None and landed != expected:
                    notes.append(
                        f"{mnemonic!r} at 0x{address:x} continued at 0x{landed:x} but "
                        f"0x{expected:x} was expected for the {short} side, so the seed did not "
                        "steer it and the path is unresolved"
                    )
                    return finish(_STOP_BLOCKED, None)
                walked.append(chosen)
                if chosen:
                    taken.append(landed)
                branches.append(Branch(address, mnemonic, chosen, landed, basis, note))
                if not machine.in_region(landed):
                    notes.append(
                        f"control left section {machine.section_name!r} at 0x{address:x} for "
                        f"0x{landed:x}; the path is unresolved"
                    )
                    return finish(_STOP_BLOCKED, None)
                pc = landed
                continue
            # -- unconditional jmp/call: executed by the CPU, never assumed
            is_call = bool(terminator.group(capstone.CS_GRP_CALL))
            indirect = _direct_target(terminator) is None
            try:
                landed = machine.step(address)
            except Exception as exc:
                return finish(*self._fault(exc, notes))
            used += 1
            taken.append(landed)
            if indirect:
                notes.append(
                    f"the {'call' if is_call else 'jump'} at 0x{address:x} is indirect: only "
                    f"0x{landed:x}, the target of the register/memory value at that point, was "
                    "explored; any other target it could hold was not"
                )
            if not machine.in_region(landed):
                notes.append(
                    f"the {'call' if is_call else 'jump'} at 0x{address:x} left section "
                    f"{machine.section_name!r} for 0x{landed:x} (a tail call or an import "
                    "thunk); the path is unresolved"
                )
                return finish(_STOP_BLOCKED, None)
            pc = landed
            continue

    # ---- helpers ----------------------------------------------------------

    def _seed_branch(
        self,
        mnemonic: str,
        canonical: str | None,
        counter_name: str | None,
        chosen: bool,
        observed_bits: int,
    ) -> str:
        """Force one ``jcc`` direction, and describe the seed in a note."""
        machine = self.machine
        short = "taken" if chosen else "falls through"
        if canonical is not None:
            seeded, changed = _seeded_flag_bits(canonical, chosen, observed_bits)
            machine.write_register(machine.flags, seeded)
            return (
                f"{machine.flags} 0x{observed_bits:x} -> 0x{seeded:x} ({changed}) so "
                f"{mnemonic!r} {short}; that direction is assumed feasible, not proven "
                "(no constraint was solved)"
            )
        name = str(counter_name)
        previous = machine.read_register(name)
        machine.write_register(name, 0 if chosen else 1)
        return (
            f"{name} {previous} -> {0 if chosen else 1} so {mnemonic!r} {short}; that "
            "direction is assumed feasible, not proven (no constraint was solved)"
        )

    def _fault(self, exc: Any, notes: list[str]) -> tuple[StopReason, None]:
        """Classify a unicorn fault, note it, and make it the path's stop reason."""
        pc = self.machine.read_register(self.machine.ip)
        reason, note = _classify_fault(exc, pc)
        notes.append(note)
        return reason, None

    def _entry(
        self,
        branches: list[Branch],
        taken: list[int],
        reason: StopReason,
        value: int | None,
        notes: list[str],
        used: int,
    ) -> Entry:
        """Build the immutable entry for the path that just stopped."""
        return Entry(
            index=len(self.entries),
            decisions=tuple(branches),
            taken_targets=tuple(taken),
            registers=self.machine.snapshot(),
            return_value=value if reason == _STOP_RETURN else None,
            stopped_reason=reason,
            instructions=used,
            warnings=tuple(notes),
        )


# ---- public API: the unicorn explorer -------------------------------------

#: What the unicorn explorer explored versus what it merely assumed. Kept in the
#: evidence so no caller can read the paths as something stronger.
_UNICORN_ASSUMPTIONS: tuple[str, ...] = (
    "every path is a sequence of branch decisions replayed on a fresh unicorn CPU, "
    "and each replay starts from the same seeded state",
    "the observed side of a conditional branch is the real emulation result: no flag "
    "or register was touched before it ran",
    "the seeded side is a flag/counter rewrite that satisfies the branch condition; it "
    "is assumed feasible, never proven -- no path predicate was built, no constraint "
    "was solved, no symbolic variable exists",
    "unconditional jumps and calls are executed, so their targets come from the CPU; an "
    "indirect transfer contributes only the target seen at that point",
    "register and memory values are concrete, so a path is not a proof of reachability "
    "for arbitrary inputs",
)

#: What the angr bridge explored versus what the unicorn explorer would report.
_ANGR_ASSUMPTIONS: tuple[str, ...] = (
    "paths come from angr exploring the function until a ret was found; angr owns the "
    "constraint solver, this module does not",
    "the observed/seeded distinction of the unicorn explorer does not apply here: every "
    "path angr reported is feasible under the constraints it solved",
    "taken_targets lists angr's basic-block destinations; the branch kinds behind them "
    "are not reconstructed by this bridge",
)


def _branch_counts(entries: Sequence[Entry]) -> dict[str, Any]:
    """Count stopped reasons and observed/seeded branch decisions."""
    reasons: dict[str, int] = {}
    observed = 0
    seeded = 0
    for entry in entries:
        reasons[entry.stopped_reason] = reasons.get(entry.stopped_reason, 0) + 1
        for branch in entry.decisions:
            if branch.basis == _BASIS_SEEDED:
                seeded += 1
            else:
                observed += 1
    return {
        "stopped_reasons": dict(sorted(reasons.items())),
        "observed_branches": observed,
        "seeded_branches": seeded,
    }


def _exploration_evidence(
    *,
    explorer: str,
    address: int,
    info: BinaryInfo,
    bitness: int,
    entries: Sequence[Entry],
    steps: int,
    complete: bool,
    max_paths: int,
    max_steps: int,
    assumptions: Sequence[str],
    regions: Sequence[tuple[str, int, int]] = (),
) -> Evidence:
    """Build the provenance record for one exploration."""
    counts = _branch_counts(entries)
    unresolved = sum(
        1 for entry in entries if entry.stopped_reason in (_STOP_BLOCKED, _STOP_UNMAPPED)
    )
    trusted = complete and not counts["seeded_branches"] and not unresolved
    extra: dict[str, Any] = {
        "explorer": explorer,
        "paths": len(entries),
        "complete": complete,
        "unresolved_paths": unresolved,
        "steps": steps,
        "max_paths": max_paths,
        "max_steps": max_steps,
        "architecture": info.architecture,
        "bitness": bitness,
        "assumptions": list(assumptions),
        **counts,
    }
    if regions:
        extra["regions"] = [
            {"kind": kind, "start": f"0x{start:x}", "end": f"0x{end:x}"}
            for kind, start, end in regions
        ]
    counted = (
        f"{steps} emulated instruction(s)"
        if explorer == "unicorn"
        else f"{steps} instruction(s) counted from the blocks angr visited"
    )
    return Evidence(
        source=_EVIDENCE_SOURCE if explorer == "unicorn" else _ANGR_SOURCE,
        method=_EVIDENCE_METHOD if explorer == "unicorn" else _ANGR_METHOD,
        confidence=Confidence.MEDIUM if trusted else Confidence.LOW,
        address=address,
        detail=(
            f"{len(entries)} path(s) from {counted}; "
            f"{counts['observed_branches']} observed and {counts['seeded_branches']} "
            f"seeded branch decision(s)"
        ),
        extra=extra,
    )


def explore_paths(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    max_paths: int = DEFAULT_MAX_PATHS,
    max_steps: int = DEFAULT_MAX_STEPS,
    initial_registers: Mapping[str, int] | None = None,
    *,
    stack_size: int = emulate.DEFAULT_STACK_SIZE,
) -> PathExploration:
    """Explore the paths through one function with the unicorn explorer.

    This is the default explorer and needs nothing beyond the optional unicorn
    build the emulator already uses. Every path is a sequence of branch
    decisions replayed on a freshly initialised CPU; see the module docstring
    for the guarantees and for exactly what is *observed* versus *seeded*.

    Args:
        path: Binary file (only its bytes are read; nothing is executed on the host).
        info: Loader metadata for that file.
        address: Start address, inside an executable section with file bytes.
        max_paths: Maximum number of paths to report.
        max_steps: Instruction budget for the whole exploration, replays included.
        initial_registers: Register seeds for every path (``{"edi": 0}``).
        stack_size: Size of the emulated stack region.

    Returns:
        A :class:`PathExploration` with up to ``max_paths`` entries in
        deterministic breadth-first order.

    Raises:
        AnalysisError: On an unusable address, an out-of-range limit, an unknown
            register name, a missing unicorn build, or an architecture this
            module does not emulate (x86 and x86-64 only).
    """
    target = Path(path)
    start = _validated_address(address)
    path_limit = _validated_limit("max_paths", max_paths, MAX_MAX_PATHS)
    step_limit = _validated_limit("max_steps", max_steps, MAX_MAX_STEPS)
    if isinstance(stack_size, bool) or not isinstance(stack_size, int):
        raise AnalysisError("stack_size must be an int")
    if not emulate.PAGE_SIZE <= stack_size <= emulate.MAX_STACK_SIZE:
        raise AnalysisError(
            f"stack_size must be between {emulate.PAGE_SIZE} and "
            f"{emulate.MAX_STACK_SIZE} byte(s)"
        )
    if not EMULATOR_AVAILABLE:
        raise AnalysisError(
            "path exploration needs the optional unicorn engine: "
            f"{emulate.emulator_status()}; install it with "
            "'pip install codevanta[emulation]'"
        )
    bits = _machine_bits(info)
    if bits is None:
        raise AnalysisError(
            f"path exploration supports x86 and x86-64 only, not "
            f"{info.architecture!r} ({info.bitness}-bit, {info.endianness}); no code was run"
        )
    seeds = _validated_registers(initial_registers, bits)
    section = info.section_for_va(start)
    if section is None:
        raise AnalysisError(f"address 0x{start:x} is not mapped by any section")
    if not section.is_executable:
        raise AnalysisError(
            f"address 0x{start:x} is inside section {section.name!r}, which is not executable"
        )
    if info.va_to_offset(start) is None:
        raise AnalysisError(f"address 0x{start:x} has no file bytes to execute")
    machine = _Machine(target, info, start, bits=bits, stack_size=stack_size)
    try:
        machine.open()
    except AnalysisError:
        machine.close()
        raise
    except Exception as exc:  # pragma: no cover - depends on the unicorn build
        machine.close()
        raise AnalysisError(f"the emulator could not be initialised: {exc}") from exc
    explorer = _Explorer(
        machine,
        _Scanner(target, info, _Decoder(bits == 64)),
        max_paths=path_limit,
        max_steps=step_limit,
        seeds=seeds,
    )
    try:
        explorer.run()
        entries = tuple(explorer.entries)
        complete = explorer.complete
        evidence = _exploration_evidence(
            explorer="unicorn",
            address=start,
            info=info,
            bitness=bits,
            entries=entries,
            steps=explorer.steps,
            complete=complete,
            max_paths=path_limit,
            max_steps=step_limit,
            assumptions=_UNICORN_ASSUMPTIONS,
            regions=tuple(machine.regions),
        )
        return PathExploration(
            address=start,
            explorer="unicorn",
            architecture=info.architecture,
            bitness=bits,
            max_paths=path_limit,
            max_steps=step_limit,
            steps=explorer.steps,
            complete=complete,
            entries=entries,
            warnings=tuple(explorer.warnings),
            evidence=evidence,
        )
    finally:
        machine.close()


# ---- optional angr bridge -------------------------------------------------


def _probe_angr() -> bool:
    """True when a module called ``angr`` is findable; never imports angr."""
    try:
        return _importlib_util.find_spec("angr") is not None
    except Exception:  # pragma: no cover - depends on the installation
        return False


#: True when a module named ``angr`` is findable. This is a *probe*, not an
#: import: angr is imported only inside :func:`explore_with_angr`, so importing
#: this module stays cheap and keeps working on a machine without angr.
ANGR_AVAILABLE = _probe_angr()


def angr_available() -> bool:
    """Return whether the optional angr bridge can be used on this machine."""
    return ANGR_AVAILABLE


def _import_angr() -> Any:
    """Import angr lazily, or raise :class:`AnalysisError` naming it and the extra."""
    if not ANGR_AVAILABLE:
        raise AnalysisError(
            "'angr' is not installed, so explore_with_angr cannot run: the angr bridge is "
            "optional in CODEVANTA and angr is never imported at module import time; "
            f"install it with '{_ANGR_HINT}' (angr is large, which is why "
            "explore_paths needs only unicorn)"
        )
    try:
        import angr
    except Exception as exc:
        raise AnalysisError(
            f"importing 'angr' failed ({type(exc).__name__}: {exc}); reinstall it with "
            f"'{_ANGR_HINT}', or use explore_paths, which needs only unicorn"
        ) from exc
    return angr


def _ret_addresses(
    path: Path, info: BinaryInfo, address: int, decoder: _Decoder, section: Any
) -> tuple[int, ...]:
    """Collect the ``ret`` addresses in ``section`` by a bounded linear sweep.

    The sweep is only used to build angr's ``find`` set, so a byte that cannot be
    decoded costs one resynchronisation step rather than a wrong target.
    """
    found: list[int] = []
    end = section.virtual_address + section.size
    pc = address
    for _ in range(MAX_SCAN_INSTRUCTIONS):
        if pc >= end:
            break
        try:
            data = read_code(path, info, pc, _MAX_INSTRUCTION_BYTES)
        except AnalysisError:
            break
        insn = decoder.decode(bytes(data), pc)
        if insn is None:
            pc += 1
            continue
        if str(insn.mnemonic).lower() in _RET_MNEMONICS:
            found.append(pc)
        pc += int(insn.size)
    return tuple(found)


def _count_path_instructions(
    path: Path, info: BinaryInfo, decoder: _Decoder, blocks: Sequence[int]
) -> int:
    """Count the instructions of an angr path from the block addresses it visited."""
    total = 0
    for block in blocks:
        pc = block
        for _ in range(MAX_BLOCK_INSTRUCTIONS):
            try:
                data = read_code(path, info, pc, _MAX_INSTRUCTION_BYTES)
            except AnalysisError:
                break
            insn = decoder.decode(bytes(data), pc)
            if insn is None:
                break
            total += 1
            if _ends_block(insn):
                break
            pc += int(insn.size)
    return total


def _angr_entry(
    index: int,
    state: Any,
    *,
    names: Sequence[str],
    return_register: str,
    path: Path,
    info: BinaryInfo,
    decoder: _Decoder,
) -> Entry:
    """Build one :class:`Entry` from an angr found state."""
    registers: dict[str, int] = {}
    for name in names:
        try:
            registers[name] = int(getattr(state.regs, name))
        except Exception:  # pragma: no cover - angr owns the register vocabulary
            continue
    blocks = tuple(int(block) for block in getattr(state.history, "bbl_addrs", ()))
    return Entry(
        index=index,
        decisions=(),
        taken_targets=blocks[1:],
        registers=registers,
        return_value=registers.get(return_register),
        stopped_reason=_STOP_RETURN,
        instructions=_count_path_instructions(path, info, decoder, blocks),
        warnings=(
            "this path comes from angr's symbolic execution; the branch decisions the "
            "unicorn explorer would record were not reconstructed, so decisions is empty "
            "and taken_targets lists angr's basic-block destinations",
        ),
    )


def explore_with_angr(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    max_paths: int = DEFAULT_MAX_PATHS,
    initial_registers: Mapping[str, int] | None = None,
) -> PathExploration:
    """Explore the same paths with angr, when angr is installed.

    angr is **optional** and imported here, never at module import time. Explore
    the function symbolically until a ``ret`` (``find=ret``), and report up to
    ``max_paths`` found paths. The ``observed``/``seeded`` distinction of the
    unicorn explorer does not apply: these paths are whatever angr's simulation
    manager could solve, and the evidence says so.

    Args:
        path: Binary file.
        info: Loader metadata for that file.
        address: Start address of the function.
        max_paths: Maximum number of paths to report.
        initial_registers: Concrete register seeds applied to the entry state.

    Returns:
        A :class:`PathExploration` whose ``explorer`` is ``"angr"``.

    Raises:
        AnalysisError: When angr is not installed (the message names angr and the
            extra that installs it), when angr fails to explore, when the machine
            is not x86/x86-64, or on a bad address or limit.
    """
    target = Path(path)
    start = _validated_address(address)
    path_limit = _validated_limit("max_paths", max_paths, MAX_MAX_PATHS)
    bits = _machine_bits(info)
    if bits is None:
        raise AnalysisError(
            "the angr bridge reports x86 register names, so it supports x86 and x86-64 "
            f"only, not {info.architecture!r}; nothing was explored"
        )
    seeds = _validated_registers(initial_registers, bits)
    module = _import_angr()
    section = info.section_for_va(start)
    if section is None:
        raise AnalysisError(f"address 0x{start:x} is not mapped by any section")
    if not section.is_executable:
        raise AnalysisError(
            f"address 0x{start:x} is inside section {section.name!r}, which is not executable"
        )
    decoder = _Decoder(bits == 64)
    rets = _ret_addresses(target, info, start, decoder, section)
    if not rets:
        raise AnalysisError(
            f"no ret instruction was found scanning {section.name!r} from 0x{start:x}, so "
            "the angr bridge has nothing to use as find; nothing was explored"
        )
    try:
        project = module.Project(str(target), auto_load_libs=False)
        state = project.factory.entry_state(addr=start)
        for name, value in seeds.items():
            setattr(state.regs, name, value)
        simgr = project.factory.simgr(state)
        simgr.explore(find=rets, num_find=path_limit)
        found = list(simgr.found)[:path_limit]
        remaining = len(simgr.active) + len(simgr.errored)
    except AnalysisError:  # pragma: no cover - nothing above raises this
        raise
    except Exception as exc:
        raise AnalysisError(
            f"angr exploration of 0x{start:x} in {target.name} failed: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    names = _REGISTERS_64 if bits == 64 else _REGISTERS_32
    entries = tuple(
        _angr_entry(
            index,
            found_state,
            names=names,
            return_register="rax" if bits == 64 else "eax",
            path=target,
            info=info,
            decoder=decoder,
        )
        for index, found_state in enumerate(found)
    )
    warnings: list[str] = []
    if remaining:
        warnings.append(
            f"{remaining} state(s) were still active or errored when angr stopped; those "
            "paths are not reported"
        )
    if len(found) >= path_limit:
        warnings.append(
            f"path limit reached: {path_limit} path(s) were reported, so more may exist"
        )
    steps = sum(entry.instructions for entry in entries)
    complete = not warnings and not remaining
    evidence = _exploration_evidence(
        explorer="angr",
        address=start,
        info=info,
        bitness=bits,
        entries=entries,
        steps=steps,
        complete=complete,
        max_paths=path_limit,
        max_steps=0,
        assumptions=_ANGR_ASSUMPTIONS,
    )
    return PathExploration(
        address=start,
        explorer="angr",
        architecture=info.architecture,
        bitness=bits,
        max_paths=path_limit,
        max_steps=0,
        steps=steps,
        complete=complete,
        entries=entries,
        warnings=tuple(warnings),
        evidence=evidence,
    )

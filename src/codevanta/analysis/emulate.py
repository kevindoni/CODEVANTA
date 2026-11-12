"""Bounded, offline CPU emulation for questions static analysis cannot answer.

Three questions motivate this module: *what does this function return for these
inputs*, *where does this indirect jump land*, and *what does this XOR/ADD
string loop decode to*. Static decoders answer none of them: they cannot
propagate values, cannot follow a register-indirect branch, and cannot run a
decode loop. This module answers them by emulating the target code inside
`unicorn <https://www.unicorn-engine.org/>`_ -- the bytes are copied into an
emulator that runs on its own virtual CPU, so **nothing is ever executed on the
host** and a hard instruction budget bounds the work.

Guarantees
----------
* **Offline.** Only file bytes are read (through
  :func:`codevanta.core.report.read_code`) and written into emulator memory.
  No host process, syscall, or library is ever invoked, and an instruction that
  would call into an import simply runs off the mapped image (see the stop
  reasons below) instead of importing anything.
* **Bounded.** ``max_instructions`` (default
  :data:`DEFAULT_MAX_INSTRUCTIONS`, ceiling :data:`MAX_MAX_INSTRUCTIONS`) is
  enforced in the per-instruction hook, and every mapping is capped
  (:data:`MAX_SECTION_BYTES`, :data:`MAX_TOTAL_MAPPED`,
  :data:`MAX_INITIAL_BLOCKS`, :data:`MAX_INITIAL_BLOCK_BYTES`).
* **Honest.** Every run ends with one of the
  :data:`StopReason` values and a warning that says *why*. A partial answer is
  never dressed up as a complete one: a value read from ``rax`` after a budget
  stop is reported as a register, not as the function's return value.

Stop reasons
------------
``return``
    Execution reached a ``ret`` whose popped address lies outside the region of
    the section holding ``address``; the return register (``rax``/``eax``) is
    reported as :attr:`EmulationResult.return_value`. A ``ret`` that pops an
    address *inside* the same region is an ordinary intra-region return and
    emulation continues (tail calls, callbacks pushed by the code itself).
``budget``
    ``max_instructions`` instructions completed and the next one was stopped
    before it ran, so :attr:`EmulationResult.instructions` equals the budget.
``unmapped``
    The emulated code touched an address that is not mapped. The exact faulting
    address comes from unicorn's unmapped-access hook and is written into
    ``warnings``. Memory-protection faults are reported here too, because from
    the caller's point of view they are the same class of failure.
``unsupported``
    The architecture/mode is not one this module emulates (x86 and x86-64 only,
    see :func:`emulator_status`), unicorn cannot decode the instruction, or the
    emulator is unavailable. No emulation happened.
``error``
    unicorn raised an exception the emulated code caused (for example
    ``UC_ERR_EXCEPTION`` from a division by zero) or the emulator failed
    internally. The run is over.

Nothing else escapes: the only exception this module raises is
:class:`~codevanta.core.report.AnalysisError`, and only for caller mistakes
(address outside an executable section, no file bytes at the address,
``max_instructions``/``stack_size`` out of range, an unknown register name, or
an ``initial_memory`` block that breaks the documented limits).

ABI defaults
------------
Registers are seeded only with what the ABI says a function may assume at
entry: the instruction pointer (``rip``/``eip``) at ``address`` and the stack
pointer/base (``rsp``/``rbp``, or ``esp``/``ebp``) near the top of a stack
region mapped at :data:`STACK_BASE_64` / :data:`STACK_BASE_32` (recorded in the
evidence ``extra``). Argument registers are *not* guessed -- pass
``initial_registers``.

Architecture support
--------------------
x86 (32-bit) and x86-64 are supported; those are the modes whose behaviour was
verified against the installed unicorn. ARM/AArch64/MIPS binaries get
``stopped_reason="unsupported"`` and a warning instead of a guess, because the
return-value, stack and register conventions here are x86-specific.

The string-decoding helpers (:func:`xor_bytes`, :func:`decrypt_string_loop`)
are pure functions over bytes: they reinterpret a key recovered from the
emulator (or from static analysis) and never execute anything.
"""

from __future__ import annotations

import faulthandler as _faulthandler
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import capstone

from codevanta.core.loader import BinaryInfo, SectionInfo
from codevanta.core.report import AnalysisError, read_code
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_INSTRUCTIONS",
    "DEFAULT_STACK_SIZE",
    "EMULATOR_AVAILABLE",
    "MAX_INITIAL_BLOCKS",
    "MAX_INITIAL_BLOCK_BYTES",
    "MAX_MAX_INSTRUCTIONS",
    "MAX_MEMORY_WRITES",
    "MAX_SECTION_BYTES",
    "MAX_STACK_SIZE",
    "MAX_TOTAL_MAPPED",
    "STACK_BASE_32",
    "STACK_BASE_64",
    "EmulationResult",
    "StopReason",
    "DECRYPT_OPS",
    "decrypt_string_loop",
    "emulate_function",
    "emulator_status",
    "resolve_indirect_target",
    "xor_bytes",
]


# ---- limits ---------------------------------------------------------------

#: Instruction budget used when the caller does not pass one.
DEFAULT_MAX_INSTRUCTIONS = 2000

#: Hard ceiling on ``max_instructions`` (bounded work, whatever the caller asks).
MAX_MAX_INSTRUCTIONS = 100_000

#: Stack region size in bytes used when the caller does not pass one.
DEFAULT_STACK_SIZE = 0x10000

#: Hard ceiling on ``stack_size`` (16 MiB of emulator memory).
MAX_STACK_SIZE = 0x100_0000

#: A single ``initial_memory`` block may not be larger than 1 MiB.
MAX_INITIAL_BLOCK_BYTES = 0x100000

#: At most this many ``initial_memory`` blocks are accepted.
MAX_INITIAL_BLOCKS = 32

#: At most this many memory writes are recorded in
#: :attr:`EmulationResult.memory_writes`; the rest are only counted and
#: reported through a warning.
MAX_MEMORY_WRITES = 256

#: A section larger than this is not mapped into the emulator (16 MiB). The
#: code and data a function-level emulation needs are far smaller; an outlier
#: of this size is a file-layout artefact, not something to copy per call.
MAX_SECTION_BYTES = 0x100_0000

#: Total emulator memory this module will ever map (64 MiB: image + stack +
#: ``initial_memory``).
MAX_TOTAL_MAPPED = 0x400_0000

#: Emulator page size; unicorn requires page-aligned addresses *and* sizes.
PAGE_SIZE = 0x1000

#: Where the stack region is mapped for 64-bit code (page aligned, chosen far
#: away from any image VA so a mapping collision is practically impossible).
STACK_BASE_64 = 0x7FFF_0000_0000

#: Where the stack region is mapped for 32-bit code (below the 4 GiB limit and
#: above the conventional 0x0804_8000 image base).
STACK_BASE_32 = 0x7E00_0000

#: Room left between the initial stack pointer and the top of the stack region
#: so a prologue can push without immediately leaving the mapping.
_STACK_HEADROOM = 0x100

#: Widest x86 instruction, in bytes.
_MAX_INSTRUCTION_BYTES = 15

#: Byte order used for every register/memory value read back out of the
#: emulator; x86 has no big-endian mode.
_ENDIANNESS_LITTLE = "little"

# ---- evidence -------------------------------------------------------------

_EVIDENCE_SOURCE = "emulate.unicorn"
_EVIDENCE_METHOD = "bounded_cpu_emulation"

# ---- stop reasons ---------------------------------------------------------

StopReason = Literal["return", "budget", "unmapped", "unsupported", "error"]

_STOP_RETURN: StopReason = "return"
_STOP_BUDGET: StopReason = "budget"
_STOP_UNMAPPED: StopReason = "unmapped"
_STOP_UNSUPPORTED: StopReason = "unsupported"
_STOP_ERROR: StopReason = "error"
#: Internal only: :func:`resolve_indirect_target` stopped at an indirect
#: branch. Never surfaces through :class:`EmulationResult`.
_STOP_INDIRECT = "indirect"

#: The reasons :class:`EmulationResult` may report (the public ``StopReason`` set).
_PUBLIC_REASONS = frozenset(
    {_STOP_RETURN, _STOP_BUDGET, _STOP_UNMAPPED, _STOP_UNSUPPORTED, _STOP_ERROR}
)

#: Instruction mnemonics that leave the current function (Capstone's naming).
_RET_MNEMONICS = frozenset({"ret", "retf", "retn", "retq", "iret", "iretd", "iretq"})

#: ``BinaryInfo.architecture`` spellings accepted as 64-bit x86.
_X86_64_NAMES = frozenset({"x86_64", "x86-64", "amd64", "em_amd64"})

#: ``BinaryInfo.architecture`` spellings accepted as 32-bit x86.
_X86_32_NAMES = frozenset({"x86", "i386", "i686", "em_386"})

#: General-purpose registers snapshotted after a run, per bitness.
_REGISTERS_64 = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "rflags",
)
_REGISTERS_32 = (
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags",
)


# ---- optional unicorn -----------------------------------------------------


def _probe_unicorn() -> tuple[Any, Any, str]:
    """Import unicorn lazily and report why it is unavailable.

    Returns:
        ``(unicorn_module, x86_const_module, error)``. The modules are ``None``
        when the import failed, and ``error`` then explains why.
    """
    try:
        import unicorn as uni
        import unicorn.x86_const as x86_const
    except Exception as exc:  # pragma: no cover - depends on the environment
        return None, None, f"unicorn is not importable: {exc}"
    return uni, x86_const, ""


_unicorn, _x86_const, _UNICORN_ERROR = _probe_unicorn()

#: True when a unicorn build is importable; emulation is refused otherwise.
EMULATOR_AVAILABLE = _unicorn is not None


def emulator_status() -> str:
    """Return why emulation is unavailable, or ``""`` when it is available.

    Callers should check this (or :data:`EMULATOR_AVAILABLE`) before offering
    emulation in a UI. The text is one human-readable sentence naming the
    missing dependency, and it is empty when unicorn imported cleanly.
    """
    return _UNICORN_ERROR


# ---- result ---------------------------------------------------------------


@dataclass(frozen=True)
class EmulationResult:
    """Everything one bounded emulation run produced.

    Attributes:
        address: Virtual address the run started at.
        stopped_reason: Why emulation ended (see the module docstring).
        instructions: Instructions that *completed*. The instruction that ended
            the run (the ``ret`` that left the region, or the one stopped by the
            budget) is not counted, so a ``budget`` stop reports exactly
            ``max_instructions``.
        return_value: Value of the return register (``rax``/``eax``) when
            ``stopped_reason`` is ``"return"``, otherwise ``None`` -- a value
            left in ``rax`` by an interrupted run is not a return value.
        registers: Register snapshot taken after the run (names as used by
            unicorn's x86 constants: ``rax``, ``rip``, ...).
        memory_writes: ``(address, bytes)`` for each recorded store, in the order
            the stores happened. Bounded by :data:`MAX_MEMORY_WRITES`; stores to
            the stack are included.
        indirect_targets: Targets of the indirect jumps/calls that were seen, in
            order. A target is only recorded when the operand could be
            evaluated; unresolvable ones produce a warning instead.
        warnings: Human-readable notes explaining every degradation: the budget,
            the faulting address, unresolved indirect branches, dropped writes,
            skipped sections.
        evidence: Provenance for the run, including the mapped regions and the
            instruction budget in ``extra``.
    """

    address: int
    stopped_reason: StopReason
    instructions: int
    return_value: int | None
    registers: Mapping[str, int]
    memory_writes: tuple[tuple[int, bytes], ...]
    indirect_targets: tuple[int, ...]
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict (bytes become hex, ints become hex strings)."""
        return {
            "address": f"0x{self.address:x}",
            "stopped_reason": self.stopped_reason,
            "instructions": self.instructions,
            "return_value": (
                f"0x{self.return_value:x}" if self.return_value is not None else None
            ),
            "registers": {
                name: f"0x{value:x}" for name, value in sorted(self.registers.items())
            },
            "memory_writes": [
                {"address": f"0x{address:x}", "size": len(data), "hex": data.hex()}
                for address, data in self.memory_writes
            ],
            "indirect_targets": [f"0x{target:x}" for target in self.indirect_targets],
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


# ---- small helpers --------------------------------------------------------


def _align_up(value: int) -> int:
    """Round ``value`` up to the next :data:`PAGE_SIZE` boundary."""
    if value <= 0:
        return 0
    return (value + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)


def _byteorder(info: BinaryInfo) -> Literal["little", "big"]:
    """Return the byte order used to read values back, validating the binary."""
    endianness = (info.endianness or _ENDIANNESS_LITTLE).strip().lower()
    return "big" if endianness == "big" else "little"


def _reg_const(name: str) -> int | None:
    """Map a unicorn register name (``"rax"``, ``"eip"``) to its constant."""
    if _x86_const is None:
        return None
    value = getattr(_x86_const, f"UC_X86_REG_{name.upper()}", None)
    return int(value) if isinstance(value, int) else None


def _machine_bits(info: BinaryInfo) -> int | None:
    """Return 32 or 64 when this module can emulate ``info``, else ``None``.

    Only x86 modes are accepted: the return-value, stack and register handling
    in this module is x86-specific, so an ARM/MIPS binary gets
    ``stopped_reason="unsupported"`` rather than an emulation of unknown
    fidelity.
    """
    if not EMULATOR_AVAILABLE:
        return None
    name = (info.architecture or "").strip().lower()
    if name in _X86_64_NAMES:
        bits = 64
    elif name in _X86_32_NAMES:
        bits = 32
    else:
        return None
    if int(info.bitness) in (32, 64):
        bits = int(info.bitness)
    if _byteorder(info) == "big":  # x86 is little-endian only
        return None
    return bits


def _merge_spans(spans: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping/adjacent page spans so each page is mapped once."""
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return merged


# ---- instruction decoding -------------------------------------------------


class _Decoder:
    """Single-instruction decoder used to recognise ``ret`` and indirect branches.

    Unicorn tells us *where* control is, not *what* the instruction is, so the
    bytes are also decoded with Capstone (detail enabled) inside the code hook.
    Decoding only ever informs the stop decision; it never decides what executes.
    """

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


# ---- input validation -----------------------------------------------------


def _validated_address(address: int) -> int:
    """Validate a start address (non-negative int) and return it."""
    if isinstance(address, bool) or not isinstance(address, int):
        raise AnalysisError(f"address must be an int, not {type(address).__name__}")
    if address <= 0:
        raise AnalysisError(f"address must be positive, got 0x{address:x}")
    return address


def _validated_budget(max_instructions: int) -> int:
    """Validate the instruction budget against the documented limits."""
    if isinstance(max_instructions, bool) or not isinstance(max_instructions, int):
        raise AnalysisError("max_instructions must be an int")
    if max_instructions < 1:
        raise AnalysisError("max_instructions must be >= 1")
    if max_instructions > MAX_MAX_INSTRUCTIONS:
        raise AnalysisError(
            f"max_instructions too large ({max_instructions}); limit is {MAX_MAX_INSTRUCTIONS}"
        )
    return max_instructions


def _validated_stack_size(stack_size: int) -> int:
    """Validate the stack size against the documented limits."""
    if isinstance(stack_size, bool) or not isinstance(stack_size, int):
        raise AnalysisError("stack_size must be an int")
    if stack_size < PAGE_SIZE:
        raise AnalysisError(f"stack_size must be >= {PAGE_SIZE} byte(s)")
    if stack_size > MAX_STACK_SIZE:
        raise AnalysisError(f"stack_size too large ({stack_size}); limit is {MAX_STACK_SIZE}")
    return stack_size


def _validated_registers(
    initial_registers: Mapping[str, int] | None,
    bits: int,
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


def _validated_memory(initial_memory: Mapping[int, bytes] | None) -> dict[int, bytes]:
    """Normalize and validate caller-supplied memory blocks.

    Raises:
        AnalysisError: On too many blocks, an oversized block, a negative
            address, or a non-bytes payload.
    """
    blocks: dict[int, bytes] = {}
    if not initial_memory:
        return blocks
    if len(initial_memory) > MAX_INITIAL_BLOCKS:
        raise AnalysisError(
            f"initial_memory has {len(initial_memory)} blocks; limit is {MAX_INITIAL_BLOCKS}"
        )
    for address, data in initial_memory.items():
        if isinstance(address, bool) or not isinstance(address, int) or address < 0:
            raise AnalysisError(f"initial_memory address {address!r} is not a non-negative int")
        if not isinstance(data, (bytes, bytearray)):
            raise AnalysisError(
                f"initial_memory block at 0x{address:x} must be bytes"
            )
        payload = bytes(data)
        if len(payload) > MAX_INITIAL_BLOCK_BYTES:
            raise AnalysisError(
                f"initial_memory block at 0x{address:x} is {len(payload)} byte(s); "
                f"limit is {MAX_INITIAL_BLOCK_BYTES}"
            )
        blocks[address] = payload
    return blocks



# ---- the emulation session ------------------------------------------------


class _Runner:
    """One bounded emulation session on a private unicorn CPU.

    The runner owns the emulator, the mapped regions and the per-instruction
    state machine that decides when to stop. It never raises anything other
    than :class:`AnalysisError`; every emulator exception is classified into a
    :data:`StopReason` and a warning.
    """

    def __init__(
        self,
        path: str | Path,
        info: BinaryInfo,
        address: int,
        *,
        bits: int,
        max_instructions: int,
        stack_size: int,
        stop_at_indirect: bool,
    ) -> None:
        self.path = Path(path)
        self.info = info
        self.address = address
        self.bits = bits
        self.max_instructions = max_instructions
        self.stack_size = stack_size
        self.stop_at_indirect = stop_at_indirect
        self.mode64 = bits == 64
        self.word_size = bits // 8
        self.byteorder = _byteorder(info)
        self.uc: Any = None
        self.decoder = _Decoder(self.mode64)
        self.attempted = 0
        self.completed = 0
        self.reason: str | None = None
        self.warnings: list[str] = []
        self.writes: list[tuple[int, bytes]] = []
        self.dropped_writes = 0
        self.indirect: list[int] = []
        self.pending_indirect: int | None = None
        self.fault: tuple[str, int, int] | None = None
        self.mapped_pages: set[int] = set()
        self.regions: list[tuple[str, int, int]] = []
        self.mapped_bytes = 0
        self.stack_base = 0
        self.stack_top = 0
        self._wide_write_warned = False
        section = info.section_for_va(address)
        if section is not None:
            self.region = (section.virtual_address, section.virtual_address + section.size)
        else:  # pragma: no cover - the public API rejects this first
            self.region = (address, address + 1)

    # ---- setup ------------------------------------------------------------

    def setup(
        self,
        initial_registers: Mapping[str, int],
        initial_memory: Mapping[int, bytes],
    ) -> None:
        """Create the CPU, map the image and the stack, then seed state."""
        uni = _unicorn
        arch = uni.UC_ARCH_X86
        mode = uni.UC_MODE_64 if self.mode64 else uni.UC_MODE_32
        self.uc = uni.Uc(arch, mode)
        self._map_image()
        self._map_stack()
        self._map_initial_memory(initial_memory)
        self._seed_registers(initial_registers)
        self._install_hooks()

    def _map_image(self) -> None:
        """Map every section of the image (page aligned, bounded), then copy its bytes."""
        spans: list[tuple[int, int]] = []
        mapped: list[SectionInfo] = []
        for section in self.info.sections:
            span = self._section_span(section)
            if span is not None:
                spans.append(span)
                mapped.append(section)
        for start, end in _merge_spans(spans):
            self._map_pages(start, end, "image")
        for section in mapped:
            data = self._section_bytes(section)
            if not data:
                continue
            try:
                self.uc.mem_write(section.virtual_address, data)
            except Exception as exc:  # pragma: no cover - mapped just above
                self.warnings.append(
                    f"section {section.name!r} could not be written at "
                    f"0x{section.virtual_address:x}: {exc}"
                )

    def _section_span(self, section: SectionInfo) -> tuple[int, int] | None:
        """Page span to map for ``section``, or ``None`` when it is skipped."""
        if section.size <= 0 or section.virtual_address <= 0:
            return None  # not allocated (e.g. .symtab, .shstrtab) or empty
        if section.size > MAX_SECTION_BYTES:
            self.warnings.append(
                f"section {section.name!r} is {section.size} byte(s); sections larger than "
                f"{MAX_SECTION_BYTES} byte(s) are not mapped into the emulator"
            )
            return None
        start = section.virtual_address & ~(PAGE_SIZE - 1)
        end = _align_up(section.virtual_address + section.size)
        if self.mapped_bytes + (end - start) > MAX_TOTAL_MAPPED:
            self.warnings.append(
                f"section {section.name!r} is not mapped: the "
                f"{MAX_TOTAL_MAPPED} byte(s) emulator mapping budget is spent"
            )
            return None
        self.mapped_bytes += end - start
        return start, end

    def _section_bytes(self, section: SectionInfo) -> bytes:
        """File bytes backing ``section`` (empty for bss-like sections)."""
        want = min(section.size, MAX_SECTION_BYTES)
        if want <= 0:
            return b""
        try:
            return read_code(self.path, self.info, section.virtual_address, want)
        except (AnalysisError, OSError):
            return b""

    def _map_stack(self) -> None:
        """Map the stack region and remember where it lives."""
        base = STACK_BASE_64 if self.mode64 else STACK_BASE_32
        start = base & ~(PAGE_SIZE - 1)
        end = _align_up(base + self.stack_size)
        span = end - start
        if self.mapped_bytes + span > MAX_TOTAL_MAPPED:  # pragma: no cover - defensive
            raise AnalysisError("stack does not fit in the emulator mapping budget")
        self.mapped_bytes += span
        self.stack_base, self.stack_top = start, end
        self._map_pages(start, end, "stack")

    def _map_pages(self, start: int, end: int, kind: str) -> None:
        """Map the page range ``[start, end)``, skipping pages already mapped."""
        run_start: int | None = None
        page = start
        while page < end:
            if page in self.mapped_pages:
                if run_start is not None:
                    self._commit(run_start, page, kind)
                    run_start = None
            else:
                self.mapped_pages.add(page)
                if run_start is None:
                    run_start = page
            page += PAGE_SIZE
        if run_start is not None:
            self._commit(run_start, end, kind)

    def _commit(self, start: int, end: int, kind: str) -> None:
        """Ask unicorn for one contiguous page run and record it."""
        self.uc.mem_map(start, end - start)
        self.regions.append((kind, start, end))

    def _map_initial_memory(self, initial_memory: Mapping[int, bytes]) -> None:
        """Map (as needed) and write every caller-supplied memory block."""
        for address, data in initial_memory.items():
            if not data:
                continue
            start = address & ~(PAGE_SIZE - 1)
            end = _align_up(address + len(data))
            span = end - start
            if self.mapped_bytes + span > MAX_TOTAL_MAPPED:
                raise AnalysisError(
                    f"initial_memory block at 0x{address:x} does not fit in the "
                    f"{MAX_TOTAL_MAPPED} byte(s) emulator mapping budget"
                )
            self.mapped_bytes += span
            self._map_pages(start, end, "initial_memory")
            try:
                self.uc.mem_write(address, data)
            except Exception as exc:  # pragma: no cover - defensive
                raise AnalysisError(
                    f"initial_memory block at 0x{address:x} could not be written: {exc}"
                ) from exc

    def _seed_registers(self, initial_registers: Mapping[str, int]) -> None:
        """Seed the ABI defaults (rip/rsp/rbp) plus the caller's registers."""
        sp = self.stack_top - _STACK_HEADROOM
        seeds: dict[str, int] = (
            {"rip": self.address, "rsp": sp, "rbp": sp}
            if self.mode64
            else {"eip": self.address, "esp": sp, "ebp": sp}
        )
        seeds.update(initial_registers)
        for name, value in seeds.items():
            constant = _reg_const(name)
            if constant is None:  # pragma: no cover - validated by the public API
                continue
            self.uc.reg_write(constant, value)


    # ---- hooks ------------------------------------------------------------

    def _install_hooks(self) -> None:
        """Register the instruction, write and unmapped-access hooks."""
        uni = _unicorn
        self.uc.hook_add(uni.UC_HOOK_CODE, self._on_code)
        self.uc.hook_add(uni.UC_HOOK_MEM_WRITE, self._on_write)
        for hook_name in (
            "UC_HOOK_MEM_READ_UNMAPPED",
            "UC_HOOK_MEM_WRITE_UNMAPPED",
            "UC_HOOK_MEM_FETCH_UNMAPPED",
        ):
            hook = getattr(uni, hook_name, None)
            if hook is not None:
                self.uc.hook_add(hook, self._on_unmapped)

    def _on_code(self, uc: Any, address: int, size: int, user_data: Any) -> None:
        """Count instructions and decide whether to stop *before* each one runs."""
        self.attempted += 1
        self.completed = self.attempted - 1
        if self.attempted > self.max_instructions:
            self.reason = _STOP_BUDGET
            uc.emu_stop()
            return
        insn = self.decoder.decode(self._read_code_bytes(address), address)
        if insn is None:
            return  # nothing to classify: unicorn stops us if it cannot run it
        if insn.mnemonic in _RET_MNEMONICS or insn.group(capstone.CS_GRP_RET):
            if self._ret_leaves_region(insn, address):
                self.reason = _STOP_RETURN
                uc.emu_stop()
            return
        if not (insn.group(capstone.CS_GRP_JUMP) or insn.group(capstone.CS_GRP_CALL)):
            return
        if not self._is_indirect(insn):
            return
        target = self._indirect_target(insn)
        if target is None:
            self.warnings.append(
                f"indirect branch at 0x{address:x} ({insn.mnemonic} {insn.op_str}) "
                "could not be resolved; its target is unknown"
            )
            return
        if target not in self.indirect:
            self.indirect.append(target)
        if self.stop_at_indirect:
            self.pending_indirect = target
            self.reason = _STOP_INDIRECT
            uc.emu_stop()

    def _on_write(
        self,
        uc: Any,
        access: int,
        address: int,
        size: int,
        value: int,
        user_data: Any,
    ) -> None:
        """Record (bounded) the bytes of every store the code performs."""
        if len(self.writes) >= MAX_MEMORY_WRITES:
            self.dropped_writes += 1
            return
        if size <= 0:
            return
        if size > 8:
            if not self._wide_write_warned:
                self._wide_write_warned = True
                self.warnings.append(
                    f"store of {size} byte(s) at 0x{address:x} is recorded as its low 8 "
                    "byte(s); wide stores are truncated in memory_writes"
                )
            payload = (int(value) & 0xFFFF_FFFF_FFFF_FFFF).to_bytes(8, self.byteorder)
        else:
            mask = (1 << (8 * size)) - 1
            payload = (int(value) & mask).to_bytes(size, self.byteorder)
        self.writes.append((address, payload))

    def _on_unmapped(
        self,
        uc: Any,
        access: int,
        address: int,
        size: int,
        value: int,
        user_data: Any,
    ) -> bool:
        """Remember the exact faulting address; never map it to paper a bug over."""
        uni = _unicorn
        kinds = {
            getattr(uni, "UC_MEM_READ_UNMAPPED", -1): "read",
            getattr(uni, "UC_MEM_WRITE_UNMAPPED", -2): "write",
            getattr(uni, "UC_MEM_FETCH_UNMAPPED", -3): "fetch",
        }
        self.fault = (kinds.get(access, "memory"), address, size)
        return False


    # ---- instruction helpers ---------------------------------------------

    def _read_code_bytes(self, address: int) -> bytes:
        """Read up to one instruction's bytes, tolerating a page edge."""
        for want in (_MAX_INSTRUCTION_BYTES, 8, 4, 1):
            try:
                return bytes(self.uc.mem_read(address, want))
            except Exception:
                continue
        return b""

    def _read_register(self, name: str) -> int | None:
        """Read one register, or ``None`` when this mode has no such register."""
        constant = _reg_const(name)
        if constant is None:
            return None
        try:
            return int(self.uc.reg_read(constant))
        except Exception:  # pragma: no cover - defensive
            return None

    def _read_pointer(self, address: int) -> int | None:
        """Read one machine word from emulator memory."""
        try:
            raw = bytes(self.uc.mem_read(address, self.word_size))
        except Exception:
            return None
        if len(raw) != self.word_size:  # pragma: no cover - unicorn is exact
            return None
        return int.from_bytes(raw, self.byteorder)

    @staticmethod
    def _is_indirect(insn: Any) -> bool:
        """True when a branch target is a register or memory operand."""
        operands = insn.operands
        if not operands:
            return False
        return operands[0].type in (capstone.x86.X86_OP_REG, capstone.x86.X86_OP_MEM)

    def _indirect_target(self, insn: Any) -> int | None:
        """Evaluate the target of a register/memory indirect branch."""
        operands = insn.operands
        if not operands:
            return None
        operand = operands[0]
        if operand.type == capstone.x86.X86_OP_REG:
            return self._read_register(insn.reg_name(operand.reg).lower())
        if operand.type != capstone.x86.X86_OP_MEM:
            return None
        address = self._memory_address(insn, operand.mem)
        if address is None:
            return None
        return self._read_pointer(address)

    def _memory_address(self, insn: Any, mem: Any) -> int | None:
        """Compute the effective address of ``[base + index*scale + disp]``."""
        if mem.index != 0 and mem.scale not in (1, 2, 4, 8):
            return None
        address = int(mem.disp)
        if mem.base != 0:
            name = insn.reg_name(mem.base).lower()
            if name in ("rip", "eip"):  # x86: relative to the *next* instruction
                address += insn.address + insn.size
            else:
                base = self._read_register(name)
                if base is None:
                    return None
                address += base
        if mem.index != 0:
            index = self._read_register(insn.reg_name(mem.index).lower())
            if index is None:
                return None
            address += index * int(mem.scale or 1)
        if address < 0 or address >= (1 << self.bits):
            return None
        return address

    def _ret_leaves_region(self, insn: Any, address: int) -> bool:
        """True when the ``ret`` at ``address`` returns outside the current section."""
        sp_name = "rsp" if self.mode64 else "esp"
        sp = self._read_register(sp_name)
        if sp is None:  # pragma: no cover - the register always exists here
            return False
        target = self._read_pointer(sp)
        low, high = self.region
        if target is None:
            self.warnings.append(
                f"return at 0x{address:x} ({insn.mnemonic} {insn.op_str}) could not be "
                f"resolved: the return address at {sp_name}=0x{sp:x} is not readable"
            )
            return False
        if low <= target < high:
            return False  # ordinary intra-region return: keep emulating
        return True

    # ---- run and report ---------------------------------------------------

    def run(self) -> None:
        """Emulate until a stop reason is recorded; never re-raises ``UcError``."""
        try:
            # ``until=0`` means "run until something stops us"; the instruction
            # budget is enforced by the code hook, not by unicorn's count, so the
            # reported instruction count and the stop reason can never disagree.
            #
            # Unicorn resolves guest faults (``UC_ERR_READ_UNMAPPED`` and friends)
            # with its own signal/SEH handler. CPython's faulthandler prints a
            # "Windows fatal exception: access violation" line before Unicorn's
            # handler runs, which looks like a crash in the test log even though the
            # emulation is fine. Suppress it for the duration of the run and restore
            # whatever state the caller had.
            was_enabled = _faulthandler.is_enabled()
            if was_enabled:
                _faulthandler.disable()
            try:
                self.uc.emu_start(self.address, 0, 0, 0)
            finally:
                if was_enabled:
                    _faulthandler.enable()
        except _unicorn.UcError as exc:
            self._classify_error(exc)
        if self.reason is None:  # pragma: no cover - defensive
            self.reason = _STOP_ERROR
            self.warnings.append(
                "emulation stopped without reaching a return, the budget, or a fault"
            )
        if self.reason == _STOP_BUDGET:
            self.warnings.append(
                f"instruction budget exhausted after {self.max_instructions} "
                "instruction(s); the emulation result is truncated"
            )
        if self.dropped_writes:
            self.warnings.append(
                f"{self.dropped_writes} memory write(s) beyond the first "
                f"{MAX_MEMORY_WRITES} were not recorded"
            )

    def _classify_error(self, exc: Any) -> None:
        """Turn one unicorn exception into a stop reason plus an exact warning."""
        uni = _unicorn
        errno = getattr(exc, "errno", None)
        pc = self._read_register("rip" if self.mode64 else "eip")
        at = f" at 0x{pc:x}" if pc is not None else ""
        unmapped = {
            getattr(uni, "UC_ERR_READ_UNMAPPED", -6),
            getattr(uni, "UC_ERR_WRITE_UNMAPPED", -7),
            getattr(uni, "UC_ERR_FETCH_UNMAPPED", -8),
        }
        protection = {
            getattr(uni, "UC_ERR_READ_PROT", -9),
            getattr(uni, "UC_ERR_WRITE_PROT", -10),
            getattr(uni, "UC_ERR_FETCH_PROT", -11),
            getattr(uni, "UC_ERR_READ_UNALIGNED", -12),
            getattr(uni, "UC_ERR_WRITE_UNALIGNED", -13),
            getattr(uni, "UC_ERR_FETCH_UNALIGNED", -14),
        }
        if errno in unmapped:
            self.reason = _STOP_UNMAPPED
            self.warnings.append(
                f"invalid {self._fault_text()}{at}; emulation stopped because the "
                "address is not mapped"
            )
        elif errno in protection:
            self.reason = _STOP_UNMAPPED
            self.warnings.append(
                f"memory protection violation ({self._fault_text()}){at}: {exc}"
            )
        elif errno == getattr(uni, "UC_ERR_INSN_INVALID", -15):
            self.reason = _STOP_UNSUPPORTED
            self.warnings.append(
                f"unicorn could not decode the instruction{at}: {exc}; the emulation "
                "result stops there"
            )
        else:
            self.reason = _STOP_ERROR
            self.warnings.append(f"emulation failed{at}: {exc}")

    def _fault_text(self) -> str:
        """Describe the recorded unmapped fault (exact address and width)."""
        if self.fault is None:
            return "memory access"
        kind, address, size = self.fault
        return f"{kind} access to unmapped address 0x{address:x} ({size} byte(s))"

    def _read_registers(self) -> dict[str, int]:
        """Snapshot the general-purpose registers that this mode exposes."""
        names = _REGISTERS_64 if self.mode64 else _REGISTERS_32
        snapshot: dict[str, int] = {}
        for name in names:
            value = self._read_register(name)
            if value is not None:
                snapshot[name] = value
        return snapshot

    def result(self) -> EmulationResult:
        """Build the immutable result for this run."""
        reason: str = self.reason or _STOP_ERROR
        stopped_reason = reason if reason in _PUBLIC_REASONS else _STOP_ERROR
        registers = self._read_registers()
        return_value = None
        if stopped_reason == _STOP_RETURN:
            return_value = registers.get("rax" if self.mode64 else "eax")
        return EmulationResult(
            address=self.address,
            stopped_reason=stopped_reason,
            instructions=self.completed,
            return_value=return_value,
            registers=registers,
            memory_writes=tuple(self.writes),
            indirect_targets=tuple(self.indirect),
            warnings=tuple(self.warnings),
            evidence=self._evidence(stopped_reason, registers),
        )

    def _evidence(self, reason: str, registers: Mapping[str, int]) -> Evidence:
        """Describe how this result was produced, including every mapped region."""
        return Evidence(
            source=_EVIDENCE_SOURCE,
            method=_EVIDENCE_METHOD,
            confidence=Confidence.MEDIUM,
            address=self.address,
            detail=(
                f"{self.completed} instruction(s) emulated on a private "
                f"{self.bits}-bit unicorn CPU; stopped_reason={reason}"
            ),
            extra={
                "stopped_reason": reason,
                "instructions": self.completed,
                "max_instructions": self.max_instructions,
                "instruction_pointer": (
                    f"0x{registers['rip']:x}" if "rip" in registers else (
                        f"0x{registers['eip']:x}" if "eip" in registers else None
                    )
                ),
                "stack_base": f"0x{self.stack_base:x}",
                "stack_size": self.stack_top - self.stack_base,
                "architecture": self.info.architecture,
                "bitness": self.bits,
                "regions": [
                    {"kind": kind, "start": f"0x{start:x}", "end": f"0x{end:x}"}
                    for kind, start, end in self.regions
                ],
                "recorded_memory_writes": len(self.writes),
                "dropped_memory_writes": self.dropped_writes,
                "indirect_targets": len(self.indirect),
            },
        )

    def close(self) -> None:
        """Drop the emulator so unicorn can free its native handle.

        ``Uc`` registers a ``weakref.finalize`` that closes the native engine
        handle when the instance is collected, so dropping the last reference is
        all this has to do; calling ``Uc.release_handle`` here would risk closing
        the same handle twice, because the finalizer still refers to it.
        """
        self.uc = None


# ---- public API -----------------------------------------------------------


def _start_runner(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    initial_registers: Mapping[str, int] | None,
    initial_memory: Mapping[int, bytes] | None,
    max_instructions: int,
    stack_size: int,
    *,
    stop_at_indirect: bool,
) -> _Runner | None:
    """Validate the request and return a ready-to-run session.

    Returns:
        A configured :class:`_Runner`, or ``None`` when this binary or this
        machine cannot be emulated (reported as ``"unsupported"`` by callers).

    Raises:
        AnalysisError: When the request itself is invalid (bad address, missing
            file bytes, out-of-range budget/stack size, bad register or memory
            seed).
    """
    start = _validated_address(address)
    budget = _validated_budget(max_instructions)
    stack = _validated_stack_size(stack_size)
    bits = _machine_bits(info)
    if bits is None or not EMULATOR_AVAILABLE:
        return None
    seeds = _validated_registers(initial_registers, bits)
    memory = _validated_memory(initial_memory)
    section = info.section_for_va(start)
    if section is None:
        raise AnalysisError(f"address 0x{start:x} is not mapped by any section")
    if not section.is_executable:
        raise AnalysisError(
            f"address 0x{start:x} is inside section {section.name!r}, which is not executable"
        )
    if info.va_to_offset(start) is None:
        raise AnalysisError(f"address 0x{start:x} has no file bytes to execute")
    runner = _Runner(
        path,
        info,
        start,
        bits=bits,
        max_instructions=budget,
        stack_size=stack,
        stop_at_indirect=stop_at_indirect,
    )
    try:
        runner.setup(seeds, memory)
    except _unicorn.UcError as exc:
        runner.warnings.append(f"the emulator could not be prepared: {exc}")
        runner.reason = _STOP_ERROR
    return runner


def _unsupported_result(
    address: int,
    info: BinaryInfo,
    max_instructions: int,
    detail: str,
) -> EmulationResult:
    """Build the ``"unsupported"`` result used when no emulation is possible."""
    if EMULATOR_AVAILABLE:
        support = "emulation supports 32-bit and 64-bit x86 only"
    else:
        support = emulator_status() or "the emulator is unavailable"
    warning = f"{detail}; {support}, so no code was run"
    return EmulationResult(
        address=address,
        stopped_reason=_STOP_UNSUPPORTED,
        instructions=0,
        return_value=None,
        registers={},
        memory_writes=(),
        indirect_targets=(),
        warnings=(warning,),
        evidence=Evidence(
            source=_EVIDENCE_SOURCE,
            method=_EVIDENCE_METHOD,
            confidence=Confidence.UNKNOWN,
            address=address,
            detail=detail,
            extra={
                "stopped_reason": _STOP_UNSUPPORTED,
                "instructions": 0,
                "max_instructions": max_instructions,
                "architecture": info.architecture,
                "bitness": info.bitness,
                "emulator_status": emulator_status(),
            },
        ),
    )


def emulate_function(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    initial_registers: Mapping[str, int] | None = None,
    initial_memory: Mapping[int, bytes] | None = None,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    stack_size: int = DEFAULT_STACK_SIZE,
) -> EmulationResult:
    """Emulate the function at ``address`` for the given initial state.

    The image sections are mapped at their virtual addresses, a stack region is
    mapped at :data:`STACK_BASE_64`/:data:`STACK_BASE_32`, and registers start at
    the ABI defaults (``rip`` at ``address``, ``rsp``/``rbp`` near the top of the
    stack) plus ``initial_registers``. Emulation then runs with a private unicorn
    CPU until one of the :data:`StopReason` conditions is met.

    Args:
        path: Binary the metadata came from (only its bytes are read).
        info: Loaded :class:`~codevanta.core.loader.BinaryInfo`.
        address: Virtual address to start at; must be inside an executable
            section that has file bytes.
        initial_registers: Extra register seeds (``{"rdi": 2}``). Names use
            unicorn's x86 spelling for the binary's bitness; unknown names or
            values that do not fit the machine word raise
            :class:`~codevanta.core.report.AnalysisError`.
        initial_memory: ``{address: bytes}`` blocks to place in emulator memory
            before the run (at most :data:`MAX_INITIAL_BLOCKS` blocks of at most
            :data:`MAX_INITIAL_BLOCK_BYTES` bytes each). Blocks that overlap the
            image are written over it.
        max_instructions: Instruction budget, at most
            :data:`MAX_MAX_INSTRUCTIONS`.
        stack_size: Size of the mapped stack region, at most
            :data:`MAX_STACK_SIZE`; rounded up to a page.

    Returns:
        An :class:`EmulationResult`. Limitations are never raised: they are
        reported through ``stopped_reason`` and ``warnings``.

    Raises:
        AnalysisError: Only for an invalid request (see :func:`_start_runner`).
    """
    start = _validated_address(address)
    budget = _validated_budget(max_instructions)
    runner = _start_runner(
        path,
        info,
        start,
        initial_registers,
        initial_memory,
        budget,
        stack_size,
        stop_at_indirect=False,
    )
    if runner is None:
        if not EMULATOR_AVAILABLE:
            detail = "the emulator is unavailable"
        else:
            detail = f"cannot emulate {info.architecture or 'unknown'} ({info.bitness}-bit)"
        return _unsupported_result(start, info, budget, detail)
    try:
        runner.run()
        return runner.result()
    finally:
        runner.close()


def resolve_indirect_target(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    initial_registers: Mapping[str, int] | None = None,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    *,
    initial_memory: Mapping[int, bytes] | None = None,
) -> int | None:
    """Emulate until the first indirect jump/call and return its target.

    This is the static-analysis bridge: a ``jmp rax`` or ``call qword ptr
    [rip+0x10]`` cannot be resolved by decoding alone, but seeding the registers
    it depends on and running up to it can answer it in a few instructions.

    Args:
        path: Binary the metadata came from.
        info: Loaded :class:`~codevanta.core.loader.BinaryInfo`.
        address: Virtual address to start at.
        initial_registers: Register seeds (see :func:`emulate_function`).
        max_instructions: Instruction budget, at most
            :data:`MAX_MAX_INSTRUCTIONS`.
        initial_memory: Memory blocks to place before the run.

    Returns:
        The target of the first indirect branch reached, or ``None`` when no
        indirect branch was reached before the run stopped (budget, fault,
        return), when the operand could not be evaluated, or when the binary is
        not emulatable. ``None`` therefore means "not resolved", never "no
        target".

    Raises:
        AnalysisError: Only for an invalid request.
    """
    start = _validated_address(address)
    budget = _validated_budget(max_instructions)
    runner = _start_runner(
        path,
        info,
        start,
        initial_registers,
        initial_memory,
        budget,
        DEFAULT_STACK_SIZE,
        stop_at_indirect=True,
    )
    if runner is None:
        return None
    if runner.reason == _STOP_ERROR:
        runner.close()
        return None
    try:
        runner.run()
        return runner.pending_indirect
    finally:
        runner.close()


# ---- string-decoding primitives -------------------------------------------

#: Operations understood by :func:`decrypt_string_loop`, named after what the
#: *encoder* did to each byte.
DECRYPT_OPS = ("xor", "add", "sub")


def xor_bytes(data: bytes, key: int) -> bytes:
    """XOR every byte of ``data`` with the low 8 bits of ``key``.

    The primitive behind the classic ``xor byte ptr [reg], imm8`` loop. It is a
    pure function over bytes -- nothing is emulated or executed -- so it can
    document a decoded blob once the key has been recovered by
    :func:`emulate_function` (read the key from a register or ``memory_writes``).

    Args:
        data: Ciphertext bytes.
        key: XOR key; only the low 8 bits take part in the operation.

    Returns:
        ``data`` with each byte XORed against ``key``. Applying it twice with the
        same key returns the original bytes.
    """
    mask = int(key) & 0xFF
    return bytes(byte ^ mask for byte in bytes(data))


def decrypt_string_loop(
    data: bytes,
    key: int,
    *,
    key_step: int = 0,
    op: str = "xor",
    terminators: Sequence[int] = (0,),
) -> bytes:
    """Decode a string blob the way an inline decode loop would, without executing it.

    Models the loops compilers and packers emit over a byte buffer: each byte is
    transformed with the key (optionally advanced per byte) and decoding stops at
    the first terminator, C-string style.

    Args:
        data: Ciphertext bytes, already read by the caller (``read_code`` or an
            ``initial_memory`` block).
        key: Initial key. Only the low 8 bits of each per-byte key are used.
        key_step: Amount added to the key after every byte (``1`` for the
            "increment the key each iteration" variant, ``0`` for a fixed key).
        op: The operation the *encoder* applied: ``"xor"`` (``c = p ^ k``),
            ``"add"`` (``c = p + k``) or ``"sub"`` (``c = p - k``). Decoding
            inverts it.
        terminators: Byte values that end the string; the terminator itself is not
            part of the result. Pass ``()`` to decode the whole blob.

    Returns:
        The decoded bytes, up to (not including) the first terminator.

    Raises:
        AnalysisError: When ``op`` is not one of :data:`DECRYPT_OPS`.
    """
    if op not in DECRYPT_OPS:
        raise AnalysisError(f"op must be one of {DECRYPT_OPS}, not {op!r}")
    stops = frozenset(int(value) & 0xFF for value in terminators)
    decoded = bytearray()
    for index, byte in enumerate(bytes(data)):
        current = (int(key) + index * int(key_step)) & 0xFF
        if op == "xor":
            value = byte ^ current
        elif op == "add":
            value = (byte - current) & 0xFF
        else:
            value = (byte + current) & 0xFF
        if value in stops:
            break
        decoded.append(value)
    return bytes(decoded)

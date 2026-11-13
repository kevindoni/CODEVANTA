"""Parse Linux ELF core dumps into a bounded, attributable summary.

A core dump is the kernel's photograph of a crashed process: an ELF file whose
``ET_CORE`` type carries no sections, only program headers -- ``PT_NOTE``
segments with per-thread and process metadata, and ``PT_LOAD`` segments for the
memory image. This module reads the notes and nothing else; it never executes or
maps anything, so it is deterministic and replayable offline.

Notes understood
----------------
``NT_PRSTATUS``
    One per thread: the signal that stopped it (``pr_cursig``), its ``pid``, and
    the general-purpose register set. For x86_64 the ``rip``/``rsp``/``rbp``
    triplet is decoded, for i386 ``eip``/``esp``/``ebp``, and for aarch64
    ``pc``/``sp``; other machines keep the thread but report no registers rather
    than guessing a layout.
``NT_SIGINFO``
    The ``siginfo_t`` of the killing signal: signal number, ``si_code`` and the
    faulting address when the descriptor is long enough to hold one.
``NT_PRPSINFO``
    Process identity: ``pid``, the 16-byte ``pr_fname`` command name and the
    ``pr_psargs`` command line (its first token is reported as ``exe``).
``NT_FPREGSET``
    Only noted as present; the floating-point state is not decoded.
``NT_FILE``
    The mapped-file table: one ``start``/``end``/``page-offset`` triple plus a
    path per mapping. When the core has no ``NT_FILE`` note, the ``PT_LOAD``
    segments are reported as anonymous module entries instead, so a caller can
    always place a faulting address.

Bounds and errors
-----------------
A parse reads at most :data:`MAX_CORE_BYTES` bytes (cores larger than that are
refused, not slurped), keeps at most :data:`MAX_NOTES` notes,
:data:`MAX_THREADS` threads and :data:`MAX_MODULES` mappings; a cut sets
``truncated`` and a warning instead of growing without limit. The only exception
raised is :class:`~codevanta.core.report.AnalysisError`: a file that is not an
ELF core dump, a big-endian image, or a structure that runs off the end of the
buffer is a typed error, never a traceback.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_METHOD",
    "EVIDENCE_SOURCE",
    "MAX_CORE_BYTES",
    "MAX_MODULES",
    "MAX_NOTES",
    "MAX_THREADS",
    "MAX_WARNINGS",
    "CoreDumpSummary",
    "ModuleMapping",
    "ThreadInfo",
    "parse_core_dump",
]

#: Hard ceiling on the bytes one parse will read (cores are refused above this).
MAX_CORE_BYTES = 256 * 1024 * 1024

#: Hard ceiling on the notes one parse will keep.
MAX_NOTES = 64

#: Threads kept per report, whatever the core carries.
MAX_THREADS = 32

#: Mappings kept per report (``NT_FILE`` entries, or ``PT_LOAD`` fallback).
MAX_MODULES = 64

#: Warnings kept per report before the rest are summarised away.
MAX_WARNINGS = 32

#: Evidence ``source`` for every finding extracted from an ELF core.
EVIDENCE_SOURCE = "crash.elfcore"

#: Evidence ``method`` for findings read out of the ``PT_NOTE`` segments.
EVIDENCE_METHOD = "elf_pt_note"

_ELF_MAGIC = b"\x7fELF"

#: ``e_type == ET_CORE``: the only ELF type this module parses.
_ET_CORE = 4

#: e_machine values this module can name (registers are decoded for all three).
_EM_386 = 3
_EM_X86_64 = 62
_EM_AARCH64 = 183

#: ``p_type`` values used here: mapped-file table fallback and note carrier.
_PT_LOAD = 1
_PT_NOTE = 4

#: Note types (``NT_`` constants from ``elf.h``).
_NT_PRSTATUS = 1
_NT_FPREGSET = 2
_NT_PRPSINFO = 3
_NT_SIGINFO = 0x53494749  # "SIGI"
_NT_FILE = 0x46494C45  # "FILE"

_ARCH_NAMES: dict[int, str] = {
    _EM_386: "i386",
    _EM_X86_64: "x86_64",
    _EM_AARCH64: "aarch64",
}

#: ``struct elf_prstatus`` field offsets inside the note descriptor. The layout
#: is shared by every 64-bit machine (``long`` is 8 bytes): ``pr_cursig`` at 16,
#: ``pr_pid`` at 24, ``pr_reg`` at 104. The 32-bit variant shifts ``pr_reg`` to
#: 68 because ``timeval`` shrinks to 8 bytes.
_CURSIG_OFFSET = 16
_PID_OFFSET = 24
_REGS_OFFSET_64 = 104
_REGS_OFFSET_32 = 68

#: Index of each register inside the ``pr_reg`` array (``user_regs_struct``
#: order for x86; ``user_pt_regs`` order for aarch64, where ``sp`` is 31 and
#: ``pc`` is 32 after the 31 general registers).
_REG_LAYOUTS: dict[str, dict[str, int]] = {
    "x86_64": {"rbp": 4, "rip": 16, "rsp": 19},
    "i386": {"ebp": 5, "eip": 12, "esp": 15},
    "aarch64": {"pc": 32, "sp": 31},
}

#: Longest ``pr_fname``/``pr_psargs`` slice decoded from ``NT_PRPSINFO``.
_FNAME_LEN = 16
_PSARGS_LEN = 80

#: ``NT_PRPSINFO`` field offsets; ``pr_flag`` is 8 bytes on 64-bit hosts, which
#: pushes ``pid`` to 24 and the name fields to 40/56.
_PRPSINFO_64: dict[str, int] = {"pid": 24, "fname": 40, "psargs": 56}
_PRPSINFO_32: dict[str, int] = {"pid": 16, "fname": 32, "psargs": 48}


@dataclass(frozen=True)
class ModuleMapping:
    """One mapped file (from ``NT_FILE``) or ``PT_LOAD`` segment fallback."""

    start: int
    end: int
    name: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": f"0x{self.start:x}",
            "end": f"0x{self.end:x}",
            "name": self.name,
        }


@dataclass(frozen=True)
class ThreadInfo:
    """One ``NT_PRSTATUS`` note: a thread's tid, stop signal and registers."""

    tid: int
    signal: int | None
    registers: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tid": self.tid,
            "signal": self.signal,
            "registers": {name: f"0x{value:x}" for name, value in self.registers.items()},
        }


@dataclass(frozen=True)
class CoreDumpSummary:
    """Bounded, evidence-backed summary of one ELF core dump."""

    arch: str
    signal: int | None
    signal_code: int | None
    fault_addr: int | None
    pid: int | None
    comm: str | None
    exe: str | None
    faulting_thread: int | None
    registers: dict[str, int]
    threads: int
    mapped_modules: tuple[ModuleMapping, ...]
    fpregset_present: bool
    notes_seen: int
    truncated: bool
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method=EVIDENCE_METHOD,
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view: addresses and registers as hex strings."""
        return {
            "arch": self.arch,
            "signal": self.signal,
            "signal_code": self.signal_code,
            "fault_addr": None if self.fault_addr is None else f"0x{self.fault_addr:x}",
            "pid": self.pid,
            "comm": self.comm,
            "exe": self.exe,
            "faulting_thread": self.faulting_thread,
            "registers": {
                name: f"0x{value:x}" for name, value in self.registers.items()
            },
            "threads": self.threads,
            "notes_seen": self.notes_seen,
            "fpregset_present": self.fpregset_present,
            "mapped_modules": [module.to_dict() for module in self.mapped_modules],
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _read_file(path: Path) -> bytes:
    """Read ``path`` whole, refusing files above :data:`MAX_CORE_BYTES`."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise AnalysisError(f"cannot stat {str(path)!r}: {exc}") from exc
    if size > MAX_CORE_BYTES:
        raise AnalysisError(
            f"core dump {str(path)!r} is {size} bytes; the parse budget is "
            f"{MAX_CORE_BYTES} bytes"
        )
    try:
        return path.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"cannot read {str(path)!r}: {exc}") from exc


def _align4(value: int) -> int:
    """Round ``value`` up to the 4-byte alignment ELF notes use."""
    return (value + 3) & ~3


def _c_string(raw: bytes, offset: int, limit: int) -> str:
    """Decode the NUL-terminated string at ``offset`` (at most ``limit`` bytes)."""
    if offset >= len(raw):
        return ""
    chunk = raw[offset : offset + limit]
    head = chunk.split(b"\x00", 1)[0]
    return head.decode("utf-8", errors="replace")


def _parse_elf_header(data: bytes) -> tuple[bool, int]:
    """Return ``(is_64, e_machine)`` for a little-endian ELF core header."""
    if len(data) < 16 or data[:4] != _ELF_MAGIC:
        raise AnalysisError("not an ELF core dump: missing \\x7fELF magic")
    ei_class, ei_data = data[4], data[5]
    if ei_data != 1:
        raise AnalysisError("unsupported core dump: only little-endian ELF is parsed")
    if ei_class == 2:
        if len(data) < 16 + 48:
            raise AnalysisError("truncated ELF header: file ends inside the header")
        fields = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    elif ei_class == 1:
        if len(data) < 16 + 36:
            raise AnalysisError("truncated ELF header: file ends inside the header")
        fields = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
    else:
        raise AnalysisError(f"invalid ELF class {ei_class}; expected 1 (ELF32) or 2 (ELF64)")
    e_type = fields[0]
    e_machine = fields[1]
    if e_type != _ET_CORE:
        raise AnalysisError(
            f"not a core dump: e_type={e_type}, expected ET_CORE ({_ET_CORE})"
        )
    return ei_class == 2, e_machine


def _read_header_fields(data: bytes, is_64: bool) -> tuple[int, int, int, int]:
    """Return ``(e_phoff, e_phentsize, e_phnum, e_machine)`` from the ELF header."""
    fmt = "<HHIQQQIHHHHHH" if is_64 else "<HHIIIIIHHHHHH"
    fields = struct.unpack_from(fmt, data, 16)
    return fields[4], fields[8], fields[9], fields[1]


def _parse_program_headers(
    data: bytes, is_64: bool, e_phoff: int, e_phentsize: int, e_phnum: int
) -> list[tuple[int, int, int, int]]:
    """Return ``(p_type, p_offset, p_vaddr, p_filesz)`` for every program header.

    The 32-bit and 64-bit ``Elf_Phdr`` differ in field widths and order but
    share the ``type``/``offset``/``vaddr``/``filesz`` roles this parser needs.
    """
    if is_64:
        if e_phentsize < 56:
            raise AnalysisError(f"invalid e_phentsize {e_phentsize} for ELF64")
        # Elf64_Phdr: type, flags, offset, vaddr, paddr, filesz, memsz, align.
        entry_fmt = "<IIQQQQQQ"
    else:
        if e_phentsize < 32:
            raise AnalysisError(f"invalid e_phentsize {e_phentsize} for ELF32")
        entry_fmt = "<IIIIIIII"
    table_end = e_phoff + e_phnum * e_phentsize
    if table_end > len(data):
        raise AnalysisError(
            f"truncated program header table: needs {table_end} bytes, "
            f"file has {len(data)}"
        )
    headers: list[tuple[int, int, int, int]] = []
    for index in range(e_phnum):
        base = e_phoff + index * e_phentsize
        fields = struct.unpack_from(entry_fmt, data, base)
        if is_64:
            headers.append((fields[0], fields[2], fields[3], fields[5]))
        else:
            headers.append((fields[0], fields[1], fields[2], fields[4]))
    return headers


def _parse_note_segment(
    data: bytes,
    offset: int,
    size: int,
    warnings: list[str],
) -> tuple[list[tuple[str, int, bytes]], bool, int]:
    """Parse one ``PT_NOTE`` segment into ``(name, type, descriptor)`` triples.

    Returns the notes (descriptors bounded to what the segment holds), a
    truncated flag, and the total number of notes seen. A note whose descriptor
    runs past the end of the segment ends the walk with a warning: the core is
    cut short, and inventing descriptors beyond that point would only lie.
    """
    notes: list[tuple[str, int, bytes]] = []
    seen = 0
    end = min(offset + size, len(data))
    truncated = offset + size > len(data)
    pos = offset
    while pos + 12 <= end:
        namesz, descsz, note_type = struct.unpack_from("<III", data, pos)
        name_start = pos + 12
        desc_start = name_start + _align4(namesz)
        desc_end = desc_start + descsz
        seen += 1
        if desc_end > end:
            truncated = True
            warnings.append(
                f"note {seen} (type 0x{note_type:x}) is truncated: descriptor "
                f"needs {descsz} bytes at offset {desc_start}"
            )
            break
        name = _c_string(data, name_start, max(namesz, 1))
        notes.append((name, note_type, bytes(data[desc_start:desc_end])))
        pos = desc_start + _align4(descsz)
    return notes, truncated, seen


def _registers_from_prstatus(descriptor: bytes, arch: str, is_64: bool) -> dict[str, int]:
    """Decode the crash-relevant registers out of an ``NT_PRSTATUS`` note."""
    layout = _REG_LAYOUTS.get(arch)
    if layout is None:
        return {}
    base = _REGS_OFFSET_64 if is_64 else _REGS_OFFSET_32
    width = 8 if is_64 else 4
    fmt = "<Q" if is_64 else "<I"
    registers: dict[str, int] = {}
    for name, index in layout.items():
        offset = base + index * width
        if offset + width <= len(descriptor):
            registers[name] = struct.unpack_from(fmt, descriptor, offset)[0]
    return registers


def _parse_siginfo(
    descriptor: bytes, is_64: bool
) -> tuple[int | None, int | None, int | None]:
    """Return ``(signal, si_code, fault_addr)`` from an ``NT_SIGINFO`` note.

    The descriptor is a kernel ``siginfo_t``: ``si_signo`` at 0, ``si_errno``
    at 4 and ``si_code`` at 8; the ``_sifields`` union (holding ``si_addr`` for
    fault signals) starts at 16 on 64-bit hosts and at 12 on 32-bit.
    """
    if len(descriptor) < 12:
        return None, None, None
    signal = struct.unpack_from("<I", descriptor, 0)[0]
    code = struct.unpack_from("<I", descriptor, 8)[0]
    addr_width = 8 if is_64 else 4
    addr_offset = 16 if is_64 else 12
    fault_addr: int | None = None
    if addr_offset + addr_width <= len(descriptor):
        fault_addr = struct.unpack_from(
            "<Q" if is_64 else "<I", descriptor, addr_offset
        )[0]
    return signal, code, fault_addr


def _parse_prpsinfo(descriptor: bytes, is_64: bool) -> tuple[int | None, str, str]:
    """Return ``(pid, comm, exe)`` from an ``NT_PRPSINFO`` note."""
    layout = _PRPSINFO_64 if is_64 else _PRPSINFO_32
    pid: int | None = None
    if len(descriptor) >= layout["pid"] + 4:
        pid = struct.unpack_from("<I", descriptor, layout["pid"])[0]
    comm = _c_string(descriptor, layout["fname"], _FNAME_LEN)
    psargs = _c_string(descriptor, layout["psargs"], _PSARGS_LEN)
    exe = psargs.split(" ", 1)[0] if psargs else ""
    return pid, comm, exe


def _parse_nt_file(descriptor: bytes, is_64: bool) -> tuple[list[ModuleMapping], bool]:
    """Decode the mapped-file table of an ``NT_FILE`` note.

    Returns up to :data:`MAX_MODULES` mappings and whether entries were dropped
    because the count exceeded the ceiling. Names live after the fixed-size
    table, NUL-separated; an entry without a matching name keeps a placeholder
    name instead of being guessed.
    """
    width = 8 if is_64 else 4
    header_size = 2 * width
    if len(descriptor) < header_size:
        return [], False
    count, page_size = struct.unpack_from(
        "<QQ" if is_64 else "<II", descriptor, 0
    )
    table_size = count * 3 * width
    if header_size + table_size > len(descriptor):
        return [], False
    names_region = descriptor[header_size + table_size :]
    names = [
        part.decode("utf-8", errors="replace")
        for part in names_region.split(b"\x00")
        if part
    ]
    modules: list[ModuleMapping] = []
    dropped = False
    for index in range(count):
        if len(modules) >= MAX_MODULES:
            dropped = True
            break
        entry_base = header_size + index * 3 * width
        entry_fmt = "<QQQ" if is_64 else "<III"
        start, end, _page_offset = struct.unpack_from(entry_fmt, descriptor, entry_base)
        name = names[index] if index < len(names) else f"mapping {index} (unnamed)"
        modules.append(ModuleMapping(start=start, end=end, name=name))
    del page_size
    return modules, dropped


def _evidence_for(
    thread_count: int,
    signal: int | None,
    registers: dict[str, int],
    notes_seen: int,
) -> Evidence:
    """Build the report-level evidence record from what was actually decoded."""
    if thread_count and registers and signal is not None:
        confidence = Confidence.HIGH
        detail = (
            f"{thread_count} thread(s), {notes_seen} note(s); faulting registers "
            "and signal read from PT_NOTE"
        )
    elif thread_count:
        confidence = Confidence.MEDIUM
        detail = f"{thread_count} thread(s), {notes_seen} note(s); partial note set"
    else:
        confidence = Confidence.LOW
        detail = f"{notes_seen} note(s); no thread state decoded"
    return Evidence(
        source=EVIDENCE_SOURCE,
        method=EVIDENCE_METHOD,
        confidence=confidence,
        detail=detail,
    )


def _pt_load_modules(
    data: bytes,
    is_64: bool,
    e_phoff: int,
    e_phentsize: int,
    program_headers: list[tuple[int, int, int, int]],
) -> list[ModuleMapping]:
    """Build anonymous module entries from ``PT_LOAD`` segments (NT_FILE fallback)."""
    modules: list[ModuleMapping] = []
    for index, (p_type, _p_offset, p_vaddr, p_filesz) in enumerate(program_headers):
        if p_type != _PT_LOAD or len(modules) >= MAX_MODULES:
            continue
        memsz = p_filesz
        if e_phoff + index * e_phentsize + (56 if is_64 else 32) <= len(data):
            fmt = "<IIQQQQQQ" if is_64 else "<IIIIIIII"
            fields = struct.unpack_from(fmt, data, e_phoff + index * e_phentsize)
            memsz = fields[6] if is_64 else fields[5]
        modules.append(
            ModuleMapping(
                start=p_vaddr,
                end=p_vaddr + (memsz or p_filesz),
                name=f"PT_LOAD segment {len(modules)}",
            )
        )
    return modules


def parse_core_dump(path: str | Path) -> CoreDumpSummary:
    """Parse an ELF core dump at ``path`` into a :class:`CoreDumpSummary`.

    Only little-endian ELF32/ELF64 files with ``e_type == ET_CORE`` are
    accepted; anything else is a typed :class:`AnalysisError` that names the
    file and the reason. The summary keeps the faulting thread's registers
    (``rip``/``rsp``/``rbp`` on x86_64, ``eip``/``esp``/``ebp`` on i386,
    ``pc``/``sp`` on aarch64), the killing signal, ``si_code`` and fault
    address from ``NT_SIGINFO``, process identity from ``NT_PRPSINFO``, and
    mapped modules from ``NT_FILE`` (falling back to ``PT_LOAD`` segments when
    the core has no file table).

    Args:
        path: Path to the core dump file.

    Returns:
        The bounded summary with its evidence record; ``truncated`` plus
        ``warnings`` describe every cut or surprise instead of failing the call.

    Raises:
        AnalysisError: If the file is missing, unreadable, larger than
            :data:`MAX_CORE_BYTES`, not an ELF file, not ``ET_CORE``, big-endian,
            or structurally truncated.
    """
    target = Path(path)
    warnings: list[str] = []
    truncated = False
    data = _read_file(target)

    is_64, e_machine = _parse_elf_header(data)
    arch = _ARCH_NAMES.get(e_machine, f"unknown (e_machine={e_machine})")
    if e_machine not in _ARCH_NAMES:
        warnings.append(
            f"register layout for e_machine={e_machine} is unknown; "
            "threads are listed without registers"
        )
    e_phoff, e_phentsize, e_phnum, _e_machine_hdr = _read_header_fields(data, is_64)
    program_headers = _parse_program_headers(
        data, is_64, e_phoff, e_phentsize, e_phnum
    )

    notes: list[tuple[str, int, bytes]] = []
    notes_seen = 0
    note_limit_reported = False
    for p_type, p_offset, _p_vaddr, p_filesz in program_headers:
        if p_type != _PT_NOTE:
            continue
        segment_notes, segment_truncated, segment_seen = _parse_note_segment(
            data, p_offset, p_filesz, warnings
        )
        notes_seen += segment_seen
        truncated = truncated or segment_truncated
        for note in segment_notes:
            if len(notes) < MAX_NOTES:
                notes.append(note)
            elif not note_limit_reported:
                truncated = True
                note_limit_reported = True
                warnings.append(
                    f"note limit {MAX_NOTES} reached; further notes are "
                    "counted but not decoded"
                )

    threads: list[ThreadInfo] = []
    signal: int | None = None
    signal_code: int | None = None
    fault_addr: int | None = None
    pid: int | None = None
    comm: str | None = None
    exe: str | None = None
    fpregset_present = False
    mapped_modules: list[ModuleMapping] = []
    modules_from_file_note = False

    for _name, note_type, descriptor in notes:
        if note_type == _NT_PRSTATUS:
            cursig: int | None = None
            if len(descriptor) >= _CURSIG_OFFSET + 2:
                cursig = struct.unpack_from("<H", descriptor, _CURSIG_OFFSET)[0]
            tid = 0
            if len(descriptor) >= _PID_OFFSET + 4:
                tid = struct.unpack_from("<I", descriptor, _PID_OFFSET)[0]
            if len(threads) < MAX_THREADS:
                threads.append(
                    ThreadInfo(
                        tid=tid,
                        signal=cursig or None,
                        registers=_registers_from_prstatus(descriptor, arch, is_64),
                    )
                )
            else:
                truncated = True
                if not any("thread limit" in warning for warning in warnings):
                    warnings.append(
                        f"thread limit {MAX_THREADS} reached; further "
                        "NT_PRSTATUS notes are counted but not kept"
                    )
        elif note_type == _NT_SIGINFO:
            parsed_signal, parsed_code, parsed_addr = _parse_siginfo(descriptor, is_64)
            if parsed_signal is not None:
                signal = parsed_signal
            if parsed_code is not None:
                signal_code = parsed_code
            if parsed_addr is not None:
                fault_addr = parsed_addr
        elif note_type == _NT_PRPSINFO:
            note_pid, note_comm, note_exe = _parse_prpsinfo(descriptor, is_64)
            if note_pid is not None:
                pid = note_pid
            if note_comm:
                comm = note_comm
            if note_exe:
                exe = note_exe
        elif note_type == _NT_FPREGSET:
            fpregset_present = True
        elif note_type == _NT_FILE:
            file_modules, dropped = _parse_nt_file(descriptor, is_64)
            if dropped:
                truncated = True
                warnings.append(
                    f"module limit {MAX_MODULES} reached; further NT_FILE "
                    "entries are dropped"
                )
            if file_modules:
                mapped_modules = file_modules
                modules_from_file_note = True

    if not modules_from_file_note:
        mapped_modules = _pt_load_modules(
            data, is_64, e_phoff, e_phentsize, program_headers
        )
        if mapped_modules:
            warnings.append(
                "no NT_FILE note: mapped modules fall back to PT_LOAD segments"
            )

    faulting = next((thread for thread in threads if thread.signal), None)
    if faulting is None and threads:
        faulting = threads[0]
    faulting_thread: int | None = None
    registers: dict[str, int] = {}
    if faulting is not None:
        if signal is None and faulting.signal is not None:
            signal = faulting.signal
        registers = dict(faulting.registers)
        faulting_thread = faulting.tid

    if len(warnings) > MAX_WARNINGS:
        truncated = True
        dropped_warnings = len(warnings) - MAX_WARNINGS
        warnings = warnings[:MAX_WARNINGS]
        warnings.append(f"warning limit reached; {dropped_warnings} further dropped")

    evidence = _evidence_for(len(threads), signal, registers, notes_seen)
    return CoreDumpSummary(
        arch=arch,
        signal=signal,
        signal_code=signal_code,
        fault_addr=fault_addr,
        pid=pid,
        comm=comm or None,
        exe=exe or None,
        faulting_thread=faulting_thread,
        registers=registers,
        threads=len(threads),
        mapped_modules=tuple(mapped_modules),
        fpregset_present=fpregset_present,
        notes_seen=notes_seen,
        truncated=truncated,
        warnings=warnings,
        evidence=evidence,
    )

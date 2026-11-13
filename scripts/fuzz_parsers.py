#!/usr/bin/env python3
"""Deterministic mutation fuzzer for the parsers that read untrusted binaries.

Every byte the analysis pipeline reads comes from a sample nobody has vetted. A
parser that raises ``KeyError`` on the 40th entry of a crafted section table is
a crash the analyst meets as a traceback in the middle of an investigation -- or
worse, inside the MCP server that wraps it. This script turns that surprise into
a failing test: it runs the real public entry points over mutated copies of
known-good binaries and treats any exception the API does not document as a
finding.

Seeds
-----
The committed ``samples/*.bin`` files (PE, ELF32/64, Mach-O), plus ELF images
this script builds in memory with ``struct.pack`` alone: a 64-bit and a 32-bit
executable carrying a ``.text`` section and a section-name table, and a bare
header-only ELF with no tables at all. Nothing but this checkout and the
standard library is needed -- no external tools, no downloaded corpora.

Mutation strategies
-------------------
``byteflip``       1-4 random bytes XORed with a random non-zero mask.
``truncate``       cut at a random length, including 0, 2 and ``len - 1``.
``length-field``   a random 2/4/8-byte integer replaced with an edge value
                   (0, 1, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF, ``len + 1``).
``section-table``  the section/program-header pointer, count or entry-size field
                   -- or an actual section-header entry -- overwritten with an
                   edge value.
``huge-counts``    a declared count (``e_shnum``, ``e_phnum``,
                   ``NumberOfSections``, ``ncmds``, DEX ``*_ids_size``) set to
                   0xFFFF..0xFFFFFFFF: the "N sections follow" lie.
``zero-sizes``     a size or count field zeroed: "0 sections", "0 bytes".
``splice``         a random window duplicated to grow the file, so an offset that
                   was inside the payload is no longer inside it.

The generator is ``random.Random(seed)`` and nothing else, so a seed and an
iteration count replay the same mutants. Every finding names the seed, the
iteration index, the seed file, the strategy, a human description of the exact
edit made, and the mutant's SHA-256; re-running with
``--seed <seed> --iterations <iterations>`` regenerates that mutant as the last
one of the run.

The contract being fuzzed
-------------------------
The public API documents exactly four exceptions for unusable input:
``BinaryLoadError``, ``AnalysisError``, ``DisassemblyError`` and ``OSError``.
Those are the parser *answering* "this is not a usable binary" and are swallowed
here. Anything else -- ``KeyError``, ``IndexError``, ``ValueError``,
``AttributeError``, ``struct.error``, ``RecursionError`` -- is a defect in the
parser: it is recorded as a finding and makes the script exit 1.

Targets
-------
``loader``     ``BinaryLoader.load`` plus every normalized view it builds
               (sections, imports, exports, symbols, ``to_dict``,
               ``offset_to_va``).
``strings``    ``StringExtractor.extract`` with and without ``BinaryInfo``.
``disasm``     ``Disassembler`` over each executable section's file bytes.
``decompile``  ``decompile_function`` on discovered candidates and the entry.
``emulate``    ``emulate_function`` on the same addresses; reported as skipped,
               with the reason, when unicorn is not installed.

Everything runs in-process, one mutant at a time -- no subprocess, so a finding
carries a Python traceback instead of an exit status. Work is bounded by the
analysis layer's own budgets (instruction and block caps, byte caps, string
limits) so a single mutant cannot hang the run, and ``--time-budget`` stops the
loop between mutants. Mutants are written to one file inside a fresh temporary
directory that is removed on exit, so a run leaves the tree -- and the temp
directory -- exactly as it found it; only killing the process mid-run can leave
that directory behind.

Usage::

    python scripts/fuzz_parsers.py                          # 200 mutants, seed 0
    python scripts/fuzz_parsers.py --iterations 50 --seed 7
    python scripts/fuzz_parsers.py --target emulate --json

Exit status is 0 when every invocation was handled by the documented contract
and 1 when at least one finding was recorded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import struct
import sys
import tempfile
import time
import traceback
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

REPO_ROOT = Path(__file__).resolve().parents[1]
#: Let ``python scripts/fuzz_parsers.py`` run from a checkout without an
#: install. An existing install wins, so the script fuzzes the code the user
#: imports.
_SRC_DIR = REPO_ROOT / "src"
if _SRC_DIR.is_dir() and str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from codevanta.analysis.decompile import decompile_function  # noqa: E402
from codevanta.analysis.emulate import emulate_function, emulator_status  # noqa: E402
from codevanta.core.disassembler import Disassembler, DisassemblyError  # noqa: E402
from codevanta.core.functions import discover_functions  # noqa: E402
from codevanta.core.loader import BinaryInfo, BinaryLoader, BinaryLoadError  # noqa: E402
from codevanta.core.report import AnalysisError, read_code  # noqa: E402
from codevanta.core.strings import StringExtractor  # noqa: E402

SAMPLES_DIR = REPO_ROOT / "samples"

#: The exceptions the public parser API documents for input it cannot use.
#: Anything else that escapes a target is a finding, not a bad sample.
HANDLED_EXCEPTIONS: tuple[type[BaseException], ...] = (
    BinaryLoadError,
    AnalysisError,
    DisassemblyError,
    OSError,
)

#: Per-target work budgets. Small on purpose: the point is to reach every branch
#: of the parser quickly, not to finish an analysis of the mutant.
DISASM_MAX_BYTES = 4096
DISASM_MAX_INSTRUCTIONS = 512
DECOMPILE_MAX_INSTRUCTIONS = 200
DECOMPILE_MAX_BLOCKS = 50
EMULATE_MAX_INSTRUCTIONS = 200
STRING_LIMIT = 200
MAX_SECTIONS = 3

#: A spliced mutant could double a seed; keep the corpus small.
MAX_MUTANT_BYTES = 64 * 1024


# ---- seeds -----------------------------------------------------------------


def _build_elf(bitness: int) -> bytes:
    """Build a minimal ELF executable from scratch, with a ``.text`` section.

    The image has an ELF header, one ``.text`` section holding a real function,
    a ``.shstrtab`` string table and a three-entry section header table, all laid
    out from computed offsets rather than copied from a file. ``bitness`` is 32
    or 64. Returning bytes instead of a path keeps the seed corpus
    independent of disk.
    """
    if bitness == 64:
        ehdr_size, shdr_size, phdr_size = 64, 64, 56
        base, machine = 0x401000, 0x3E
        # push rbp; mov rbp, rsp; mov eax, 1; pop rbp; ret; nops
        code = bytes.fromhex("554889e5b8010000005dc3") + b"\x90" * 5
        ehdr_fmt, shdr_fmt = "<16sHHIQQQIHHHHHH", "<IIQQQQIIQQ"
    elif bitness == 32:
        ehdr_size, shdr_size, phdr_size = 52, 40, 32
        base, machine = 0x8048000, 0x03
        # push ebp; mov ebp, esp; mov eax, 1; pop ebp; ret; nops
        code = bytes.fromhex("5589e5b8010000005dc3") + b"\x90" * 6
        ehdr_fmt, shdr_fmt = "<16sHHIIIIIHHHHHH", "<IIIIIIIIII"
    else:  # pragma: no cover - programmer error, not fuzz input
        raise ValueError("bitness must be 32 or 64")

    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_off = ehdr_size
    shstr_off = text_off + len(code)
    shoff = shstr_off + len(shstrtab)

    ident = b"\x7fELF" + bytes([2 if bitness == 64 else 1, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack(
        ehdr_fmt,
        ident,
        2,  # e_type = ET_EXEC
        machine,
        1,  # e_version
        base + text_off,  # e_entry: first byte of .text
        0,  # e_phoff
        shoff,
        0,  # e_flags
        ehdr_size,
        phdr_size,
        0,  # e_phnum
        shdr_size,
        3,  # e_shnum: null, .text, .shstrtab
        2,  # e_shstrndx
    )

    def shdr(name: int, sh_type: int, flags: int, addr: int, off: int, size: int) -> bytes:
        return struct.pack(shdr_fmt, name, sh_type, flags, addr, off, size, 0, 0, 16, 0)

    shdrs = (
        shdr(0, 0, 0, 0, 0, 0)  # SHT_NULL
        + shdr(1, 1, 0x6, base + text_off, text_off, len(code))  # .text: ALLOC|EXEC
        + shdr(7, 3, 0, 0, shstr_off, len(shstrtab))  # .shstrtab: STRTAB
    )
    return ehdr + code + shstrtab + shdrs


def _elf_header_only(bitness: int) -> bytes:
    """Build an ELF header declaring no sections and no segments.

    This is the shape an analyst meets when a sample was truncated right after
    its header: valid magic, zero tables.
    """
    if bitness == 64:
        return struct.pack(
            "<16sHHIQQQIHHHHHH",
            b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8,
            2,
            0x3E,
            1,
            0x401000,
            0,
            0,
            0,
            64,
            56,
            0,
            64,
            0,
            0,
        )
    return struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8,
        2,
        0x03,
        1,
        0x8048000,
        0,
        0,
        0,
        52,
        32,
        0,
        40,
        0,
        0,
    )


def _seed_inputs() -> list[tuple[str, bytes]]:
    """Return the ``(name, bytes)`` corpus: committed samples, then synthetic ELFs."""
    seeds = [(path.name, path.read_bytes()) for path in sorted(SAMPLES_DIR.glob("*.bin"))]
    seeds.append(("synthetic-elf64", _build_elf(64)))
    seeds.append(("synthetic-elf32", _build_elf(32)))
    seeds.append(("synthetic-elf64-header-only", _elf_header_only(64)))
    seeds.append(("synthetic-elf32-header-only", _elf_header_only(32)))
    return seeds


# ---- mutant ----------------------------------------------------------------


@dataclass(frozen=True)
class _Field:
    """One header field the mutator knows how to attack."""

    name: str
    offset: int
    size: int
    endian: str  # "<" little-endian, ">" big-endian
    kind: str  # "count" | "pointer" | "size" | "flag"


@dataclass(frozen=True)
class Mutant:
    """One mutated payload plus everything needed to reproduce and report it."""

    seed_name: str
    strategy: str
    description: str
    data: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed_file": self.seed_name,
            "strategy": self.strategy,
            "description": self.description,
            "sha256": self.sha256,
            "size": len(self.data),
        }


#: ``(name, offset, size, kind)`` for the ELF header fields worth attacking. The
#: offsets are fixed by the format, so they are written out rather than parsed.
_ELF32_LAYOUT: tuple[tuple[str, int, int, str], ...] = (
    ("e_type", 0x10, 2, "flag"),
    ("e_machine", 0x12, 2, "flag"),
    ("e_version", 0x14, 4, "flag"),
    ("e_entry", 0x18, 4, "pointer"),
    ("e_phoff", 0x1C, 4, "pointer"),
    ("e_shoff", 0x20, 4, "pointer"),
    ("e_flags", 0x24, 4, "flag"),
    ("e_ehsize", 0x28, 2, "size"),
    ("e_phentsize", 0x2A, 2, "size"),
    ("e_phnum", 0x2C, 2, "count"),
    ("e_shentsize", 0x2E, 2, "size"),
    ("e_shnum", 0x30, 2, "count"),
    ("e_shstrndx", 0x32, 2, "count"),
)

_ELF64_LAYOUT: tuple[tuple[str, int, int, str], ...] = (
    ("e_type", 0x10, 2, "flag"),
    ("e_machine", 0x12, 2, "flag"),
    ("e_version", 0x14, 4, "flag"),
    ("e_entry", 0x18, 8, "pointer"),
    ("e_phoff", 0x20, 8, "pointer"),
    ("e_shoff", 0x28, 8, "pointer"),
    ("e_flags", 0x30, 4, "flag"),
    ("e_ehsize", 0x34, 2, "size"),
    ("e_phentsize", 0x36, 2, "size"),
    ("e_phnum", 0x38, 2, "count"),
    ("e_shentsize", 0x3A, 2, "size"),
    ("e_shnum", 0x3C, 2, "count"),
    ("e_shstrndx", 0x3E, 2, "count"),
)

#: DEX header fields (all 32-bit little-endian) -- the loader has a dedicated
#: DEX path, so its declared sizes belong in the corpus even though ``*.bin``
#: seeds rarely carry the magic.
_DEX_LAYOUT: tuple[tuple[str, int, int, str], ...] = (
    ("file_size", 0x20, 4, "size"),
    ("header_size", 0x24, 4, "size"),
    ("map_off", 0x34, 4, "pointer"),
    ("string_ids_size", 0x38, 4, "count"),
    ("string_ids_off", 0x3C, 4, "pointer"),
    ("type_ids_size", 0x40, 4, "count"),
    ("proto_ids_size", 0x48, 4, "count"),
    ("field_ids_size", 0x50, 4, "count"),
    ("method_ids_size", 0x58, 4, "count"),
    ("class_defs_size", 0x60, 4, "count"),
    ("data_size", 0x68, 4, "size"),
    ("data_off", 0x6C, 4, "pointer"),
)

#: Mach-O magic -> (endianness, bitness). The 32/64-bit variants differ only in
#: the size of the fields after ``sizeofcmds``, which this mutator does not use.
_MACHO_MAGICS: dict[int, str] = {
    0xFEEDFACE: "<",
    0xFEEDFACF: "<",
    0xCEFAEDFE: ">",
    0xCFFAEDFE: ">",
}

_MACHO_LAYOUT: tuple[tuple[str, int, int, str], ...] = (
    ("cputype", 0x04, 4, "flag"),
    ("cpusubtype", 0x08, 4, "flag"),
    ("filetype", 0x0C, 4, "flag"),
    ("ncmds", 0x10, 4, "count"),
    ("sizeofcmds", 0x14, 4, "size"),
    ("flags", 0x18, 4, "flag"),
)

#: Field names that make up a section/program-header table pointer or count.
_TABLE_FIELD_NAMES = frozenset(
    {
        "e_shoff",
        "e_shnum",
        "e_shentsize",
        "e_phoff",
        "e_phnum",
        "e_phentsize",
        "e_shstrndx",
        "NumberOfSections",
        "SizeOfOptionalHeader",
        "PointerToSymbolTable",
        "ncmds",
        "sizeofcmds",
    }
)

#: Edge values per field kind. The widest ones are truncated to the field width
#: by :func:`_write_field`, so a 2-byte count can still be asked for 0xFFFFFFFF.
_COUNT_VALUES = (0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)
_SIZE_VALUES = (0, 1, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF)
_POINTER_VALUES = (0, 1, 0x1000, 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)


def _elf_fields(data: bytes) -> list[_Field]:
    """Return the ELF header fields, or ``[]`` when the header is too short."""
    if len(data) < 0x34:
        return []
    endian = {1: "<", 2: ">"}.get(data[5], "")
    if not endian:
        return []
    layout = {1: _ELF32_LAYOUT, 2: _ELF64_LAYOUT}.get(data[4])
    if layout is None:
        return []
    return [_Field(name, offset, size, endian, kind) for name, offset, size, kind in layout]


def _pe_fields(data: bytes) -> list[_Field]:
    """Return the PE fields, following ``e_lfanew`` to the COFF/optional header."""
    if len(data) < 0x40:
        return []
    fields = [_Field("e_lfanew", 0x3C, 4, "<", "pointer")]
    lfanew = _read_field(data, fields[0])
    if not 0x40 <= lfanew <= len(data) - 24:
        return fields
    optional = lfanew + 24
    fields.extend(
        _Field(name, offset, size, "<", kind)
        for name, offset, size, kind in (
            ("NumberOfSections", lfanew + 6, 2, "count"),
            ("PointerToSymbolTable", lfanew + 12, 4, "pointer"),
            ("NumberOfSymbols", lfanew + 16, 4, "count"),
            ("SizeOfOptionalHeader", lfanew + 20, 2, "size"),
            ("AddressOfEntryPoint", optional + 16, 4, "pointer"),
            ("ImageBase", optional + 28, 4, "pointer"),
            ("SectionAlignment", optional + 32, 4, "size"),
            ("FileAlignment", optional + 36, 4, "size"),
            ("SizeOfImage", optional + 56, 4, "size"),
        )
    )
    return [f for f in fields if f.offset + f.size <= len(data)]


def _macho_fields(data: bytes) -> list[_Field]:
    """Return the Mach-O header fields, or ``[]`` for another format."""
    if len(data) < 0x1C:
        return []
    endian = _MACHO_MAGICS.get(int.from_bytes(data[:4], "big"))
    if endian is None:
        return []
    return [_Field(name, offset, size, endian, kind) for name, offset, size, kind in _MACHO_LAYOUT]


def _dex_fields(data: bytes) -> list[_Field]:
    """Return the DEX header fields, or ``[]`` when the header is truncated."""
    if len(data) < 0x70:
        return []
    return [_Field(name, offset, size, "<", kind) for name, offset, size, kind in _DEX_LAYOUT]


def _header_fields(data: bytes) -> list[_Field]:
    """Dispatch on the magic and return the header fields a mutant may attack."""
    if data[:4] == b"\x7fELF":
        return _elf_fields(data)
    if data[:4] == b"dex\n":
        return _dex_fields(data)
    if data[:2] == b"MZ":
        return _pe_fields(data)
    return _macho_fields(data)


def _read_field(data: bytes, target: _Field) -> int:
    """Read ``target`` from ``data``; a field past the end reads as 0."""
    chunk = data[target.offset : target.offset + target.size]
    if len(chunk) != target.size:
        return 0
    return int.from_bytes(chunk, "big" if target.endian == ">" else "little")


def _write_field(buffer: bytearray, target: _Field, value: int) -> int:
    """Write ``value`` into ``target``, truncated to the field's width; return it."""
    written = value & ((1 << (8 * target.size)) - 1)
    order: Literal["little", "big"] = "big" if target.endian == ">" else "little"
    buffer[target.offset : target.offset + target.size] = written.to_bytes(target.size, order)
    return written


def _scribble(rng: random.Random, data: bytes, values: Sequence[int]) -> tuple[bytearray, str]:
    """Fallback: write an edge value into a random 2/4/8-byte slot.

    Used when the payload's magic is unknown (or too truncated to locate a
    header), so every iteration still mutates something real.
    """
    if not data:
        return bytearray(), "empty payload: no word to write"
    width = rng.choice([w for w in (2, 4, 8) if w <= len(data)] or [1])
    offset = rng.randrange(0, len(data) - width + 1)
    buffer = bytearray(data)
    written = _write_field(buffer, _Field("word", offset, width, "<", "size"), rng.choice(values))
    return buffer, f"word @0x{offset:x} (u{width * 8}) = 0x{written:x}"


def _elf_section_entry(
    rng: random.Random, data: bytes
) -> tuple[int, bytearray, _Field] | None:
    """Locate one section-header entry and pick a field inside it to corrupt.

    Returns ``(index, buffer, field)`` where ``field.offset`` is absolute, or
    ``None`` when the table cannot be reached (no table, past EOF, or not ELF).
    """
    fields = {f.name: f for f in _elf_fields(data)}
    shoff_field = fields.get("e_shoff")
    count_field = fields.get("e_shnum")
    entsize_field = fields.get("e_shentsize")
    if shoff_field is None or count_field is None or entsize_field is None:
        return None
    shoff = _read_field(data, shoff_field)
    count = _read_field(data, count_field)
    entsize = _read_field(data, entsize_field)
    if not shoff or not entsize or count < 1:
        return None
    index = rng.randrange(min(count, 8))
    start = shoff + index * entsize
    if start + entsize > len(data):
        return None
    if entsize >= 64:  # ELF64 shdr: 8-byte sh_offset / sh_size
        candidates = (("sh_name", 0, 4), ("sh_offset", 24, 8), ("sh_size", 32, 8))
    else:  # ELF32 shdr
        candidates = (("sh_name", 0, 4), ("sh_offset", 16, 4), ("sh_size", 20, 4))
    name, relative, size = rng.choice(candidates)
    buffer = bytearray(data)
    return index, buffer, _Field(name, start + relative, size, shoff_field.endian, "pointer")


# ---- strategies ------------------------------------------------------------

#: A strategy takes the shared generator, the seed's name and its bytes, and
#: returns the mutant. Every one of them is a pure function of ``rng`` and its
#: arguments, which is what makes a seed replayable.
Strategy = Callable[[random.Random, str, bytes], Mutant]


def _strategy_byteflip(rng: random.Random, seed_name: str, data: bytes) -> Mutant:
    """XOR one to four random bytes with a random non-zero mask."""
    if not data:
        return Mutant(seed_name, "byteflip", "empty payload: no byte to flip", data)
    mask = rng.randint(1, 0xFF)
    buffer = bytearray(data)
    offsets = sorted(rng.sample(range(len(data)), min(rng.randint(1, 4), len(data))))
    for offset in offsets:
        buffer[offset] ^= mask
    where = ", ".join(f"0x{offset:x}" for offset in offsets)
    return Mutant(seed_name, "byteflip", f"xor 0x{mask:02x} into {where}", bytes(buffer))


def _strategy_truncate(rng: random.Random, seed_name: str, data: bytes) -> Mutant:
    """Cut the payload short -- including to zero bytes and to ``len - 1``."""
    size = len(data)
    choices = [0, 1, 2, 4, 8, 16, size // 4, size // 2, size - 2, size - 1]
    new_size = min(size, max(0, rng.choice(choices)))
    return Mutant(seed_name, "truncate", f"truncate {size} -> {new_size} bytes", data[:new_size])


def _strategy_length_field(rng: random.Random, seed_name: str, data: bytes) -> Mutant:
    """Overwrite a random 2/4/8-byte integer with a length-like edge value."""
    if len(data) < 2:
        return Mutant(seed_name, "length-field", "payload shorter than any integer", data)
    width = rng.choice([w for w in (2, 4, 8) if w <= len(data)])
    offset = rng.randrange(0, len(data) - width + 1)
    value = rng.choice((*_SIZE_VALUES, len(data) + 1, len(data) * 16, len(data) - 1))
    buffer = bytearray(data)
    written = _write_field(buffer, _Field("word", offset, width, rng.choice("<>"), "size"), value)
    return Mutant(
        seed_name,
        "length-field",
        f"u{width * 8} @0x{offset:x} = 0x{written:x}",
        bytes(buffer),
    )


def _strategy_section_table(rng: random.Random, seed_name: str, data: bytes) -> Mutant:
    """Corrupt the section table: a pointer/count field, or a real entry."""
    tables = [f for f in _header_fields(data) if f.name in _TABLE_FIELD_NAMES]
    entry = _elf_section_entry(rng, data)
    if entry is not None and (not tables or rng.random() < 0.5):
        index, buffer, target = entry
        written = _write_field(buffer, target, rng.choice(_POINTER_VALUES + _COUNT_VALUES))
        return Mutant(
            seed_name,
            "section-table",
            f"shdr[{index}].{target.name} @0x{target.offset:x} = 0x{written:x}",
            bytes(buffer),
        )
    if not tables:
        buffer, where = _scribble(rng, data, _POINTER_VALUES)
        return Mutant(seed_name, "section-table", f"no table header; {where}", bytes(buffer))
    target = rng.choice(tables)
    buffer = bytearray(data)
    written = _write_field(buffer, target, rng.choice(_POINTER_VALUES + _COUNT_VALUES))
    return Mutant(
        seed_name,
        "section-table",
        f"{target.name}@0x{target.offset:x} = 0x{written:x}",
        bytes(buffer),
    )


def _strategy_huge_counts(rng: random.Random, seed_name: str, data: bytes) -> Mutant:
    """Claim more sections/entries than the file can possibly hold."""
    counts = [f for f in _header_fields(data) if f.kind == "count"]
    if not counts:
        buffer, where = _scribble(rng, data, _COUNT_VALUES)
        return Mutant(seed_name, "huge-counts", f"no declared count; {where}", bytes(buffer))
    target = rng.choice(counts)
    buffer = bytearray(data)
    written = _write_field(buffer, target, rng.choice(_COUNT_VALUES))
    return Mutant(
        seed_name,
        "huge-counts",
        f"{target.name}@0x{target.offset:x} = 0x{written:x}",
        bytes(buffer),
    )


def _strategy_zero_sizes(rng: random.Random, seed_name: str, data: bytes) -> Mutant:
    """Zero a size or count field: "0 sections", "0 bytes", "empty table"."""
    sizes = [f for f in _header_fields(data) if f.kind in ("size", "count")]
    if not sizes:
        buffer, where = _scribble(rng, data, (0,))
        return Mutant(seed_name, "zero-sizes", f"no declared size; {where}", bytes(buffer))
    target = rng.choice(sizes)
    buffer = bytearray(data)
    _write_field(buffer, target, 0)
    return Mutant(seed_name, "zero-sizes", f"{target.name}@0x{target.offset:x} = 0x0", bytes(buffer))


def _strategy_splice(rng: random.Random, seed_name: str, data: bytes) -> Mutant:
    """Duplicate a random window so offsets inside the payload move out of it."""
    if len(data) < 2 or len(data) >= MAX_MUTANT_BYTES:
        return Mutant(seed_name, "splice", "payload too small or too large to splice", data)
    start = rng.randrange(len(data))
    length = rng.randint(1, min(len(data) - start, 256))
    insert_at = rng.randrange(len(data) + 1)
    grown = (data[:insert_at] + data[start : start + length] + data[insert_at:])[:MAX_MUTANT_BYTES]
    return Mutant(
        seed_name,
        "splice",
        f"duplicate 0x{start:x}-0x{start + length:x} at 0x{insert_at:x} "
        f"({len(data)} -> {len(grown)} bytes)",
        grown,
    )


#: The mutation portfolio. ``rng.choice`` over this tuple spreads iterations
#: across all seven strategies without a fixed schedule.
STRATEGIES: tuple[tuple[str, Strategy], ...] = (
    ("byteflip", _strategy_byteflip),
    ("truncate", _strategy_truncate),
    ("length-field", _strategy_length_field),
    ("section-table", _strategy_section_table),
    ("huge-counts", _strategy_huge_counts),
    ("zero-sizes", _strategy_zero_sizes),
    ("splice", _strategy_splice),
)


def _mutate(rng: random.Random, seeds: list[tuple[str, bytes]]) -> Mutant:
    """Pick a seed and a strategy from ``rng`` and produce one mutant."""
    seed_name, data = rng.choice(seeds)
    return rng.choice(STRATEGIES)[1](rng, seed_name, data)


# ---- targets ---------------------------------------------------------------


def _touch_info(info: BinaryInfo) -> None:
    """Walk every normalized view the loader built.

    ``load`` can succeed and still leave a lazily-wrong structure behind (a
    section whose ``offset + raw_size`` runs past EOF, an import with no name).
    Serializing and address-mapping the whole thing is what makes those show up.
    """
    info.to_dict()
    for section in info.sections:
        info.offset_to_va(section.offset)
        info.offset_to_va(section.offset + section.raw_size)
        section.to_dict()
    for imported in info.imports:
        imported.to_dict()
    for exported in info.exports:
        exported.to_dict()
    for symbol in info.symbols:
        symbol.to_dict()


def _raw_prefix(path: Path, limit: int = DISASM_MAX_BYTES) -> bytes:
    """Read at most ``limit`` bytes: the code window for table-less samples."""
    with path.open("rb") as handle:
        return handle.read(limit)


def _candidate_addresses(info: BinaryInfo, limit: int) -> list[int]:
    """Entry point first, then discovery order, de-duplicated and capped.

    ``BinaryInfo.entry_point`` is documented ``int | None``: the loader reports
    ``None`` for a header whose entry field cannot be read or is zero. Only real
    integers are handed on -- a fuzzer that passed ``None`` into ``disassemble``
    would be testing its own bug, not the parser's.
    """
    addresses: list[int] = [] if info.entry_point is None else [info.entry_point]
    addresses.extend(candidate.address for candidate in discover_functions(info))
    return list(dict.fromkeys(addresses))[:limit]


def _target_loader(path: Path) -> None:
    """Load the mutant and walk every normalized view the loader built."""
    _touch_info(BinaryLoader().load(path))


def _target_strings(path: Path) -> None:
    """Extract strings with binary metadata and, again, without it.

    The no-metadata call is the documented UTF-16LE default path, so it is worth
    fuzzing on its own: it decides the encoding from the header when ``info`` is
    present and never guesses when it is absent.
    """
    info: BinaryInfo | None = None
    try:
        info = BinaryLoader().load(path)
    except BinaryLoadError:
        pass  # an unloadable mutant is still a string-extraction input
    if info is not None:
        for result in StringExtractor().extract(path, info, limit=STRING_LIMIT)[:50]:
            result.to_dict()
    for result in StringExtractor(min_length=1).extract(path, limit=10):
        result.to_dict()


def _target_disasm(path: Path) -> None:
    """Disassemble every executable section, falling back to the raw header."""
    info = BinaryLoader().load(path)
    disassembler = Disassembler(info.architecture, info.bitness, info.endianness)
    regions = [section for section in info.sections if section.is_executable][:MAX_SECTIONS]
    if not regions:
        # ``entry_point`` is ``int | None``; VA 0 is the documented "no entry"
        # stand-in and keeps the raw window fuzzed either way.
        disassembler.disassemble(
            _raw_prefix(path),
            info.entry_point or 0,
            max_instructions=DISASM_MAX_INSTRUCTIONS,
            max_bytes=DISASM_MAX_BYTES,
        )
        return
    for section in regions:
        window = min(section.raw_size or DISASM_MAX_BYTES, DISASM_MAX_BYTES)
        code = read_code(path, info, section.virtual_address, window)
        disassembler.disassemble(
            code,
            section.virtual_address,
            max_instructions=DISASM_MAX_INSTRUCTIONS,
            max_bytes=DISASM_MAX_BYTES,
        )


def _target_decompile(path: Path) -> None:
    """Decompile the entry point and the first discovered candidates."""
    info = BinaryLoader().load(path)
    for address in _candidate_addresses(info, limit=2):
        try:
            pseudo = decompile_function(
                path,
                info,
                address,
                max_instructions=DECOMPILE_MAX_INSTRUCTIONS,
                max_blocks=DECOMPILE_MAX_BLOCKS,
            )
        except AnalysisError:
            continue  # documented: not executable code, or nothing decodable
        pseudo.to_dict()


def _target_emulate(path: Path) -> None:
    """Emulate the entry point and the first discovered candidates, bounded."""
    info = BinaryLoader().load(path)
    for address in _candidate_addresses(info, limit=2):
        try:
            result = emulate_function(
                path, info, address, max_instructions=EMULATE_MAX_INSTRUCTIONS
            )
        except AnalysisError:
            continue  # documented: unmapped, not executable, bad budget
        result.to_dict()


#: Target name -> the work to run against one mutant file. Each target takes the
#: path of the mutant and returns nothing; anything it raises is judged by the
#: caller against :data:`HANDLED_EXCEPTIONS`.
TARGETS: dict[str, Callable[[Path], None]] = {
    "loader": _target_loader,
    "strings": _target_strings,
    "disasm": _target_disasm,
    "decompile": _target_decompile,
    "emulate": _target_emulate,
}

#: The order targets run in, so output is stable across runs.
TARGET_ORDER: tuple[str, ...] = ("loader", "strings", "disasm", "decompile", "emulate")

#: Wall-clock ceiling for one run. The loop is interrupted *between* mutants, so
#: the honest promise is "a little over this", not "exactly this".
DEFAULT_TIME_BUDGET = 120.0


# ---- reporting -------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One undocumented exception, with everything needed to reproduce it."""

    iteration: int
    target: str
    mutant: Mutant
    exception: str
    location: str
    traceback: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "iteration": self.iteration,
            "target": self.target,
            "exception": self.exception,
            "location": self.location,
            "mutant": self.mutant.to_dict(),
            "traceback": self.traceback.splitlines()[-20:],
        }


@dataclass
class Report:
    """The outcome of one fuzz run."""

    seed: int
    iterations: int
    targets: tuple[str, ...]
    mutants: int
    runs: int
    runs_per_target: dict[str, int]
    elapsed: float
    time_budget: float
    stopped_early: bool = False
    skipped: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        """1 when anything escaped the documented contract, else 0."""
        return 1 if self.findings else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "iterations": self.iterations,
            "mutants": self.mutants,
            "targets": list(self.targets),
            "runs": self.runs,
            "runs_per_target": dict(self.runs_per_target),
            "elapsed_seconds": round(self.elapsed, 3),
            "time_budget_seconds": self.time_budget,
            "stopped_early": self.stopped_early,
            "skipped": dict(self.skipped),
            "findings": [finding.to_dict() for finding in self.findings],
            "status": "findings" if self.findings else "ok",
            "exit_code": self.exit_code,
        }


def _display_path(filename: str) -> str:
    """Render a traceback filename relative to the checkout when possible."""
    path = Path(filename)
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except (ValueError, OSError):
        return path.name


def _finding(iteration: int, target: str, mutant: Mutant, exc: BaseException) -> Finding:
    """Turn an exception that escaped a target into a reportable finding."""
    frames = traceback.extract_tb(exc.__traceback__)
    location = ""
    if frames:
        deepest = frames[-1]
        location = f"{_display_path(deepest.filename)}:{deepest.lineno} in {deepest.name}"
    return Finding(
        iteration=iteration,
        target=target,
        mutant=mutant,
        exception=f"{type(exc).__name__}: {exc}",
        location=location,
        traceback="".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
    )


def _target_unavailable_reason(name: str) -> str:
    """Return why ``name`` cannot run here, or ``""`` when it can."""
    if name == "emulate":
        return emulator_status()
    return ""


def fuzz(
    *,
    iterations: int,
    seed: int,
    targets: Sequence[str],
    time_budget: float = DEFAULT_TIME_BUDGET,
) -> Report:
    """Run ``iterations`` mutants through every available target.

    Mutants are written to one file inside a temporary directory that is removed
    when the run ends, so no crash artefact is left behind; the finding carries
    the mutant's description and SHA-256 instead.
    """
    rng = random.Random(seed)
    seeds = _seed_inputs()
    selected = tuple(targets)
    skipped: dict[str, str] = {}
    active: list[str] = []
    for name in selected:
        reason = _target_unavailable_reason(name)
        if reason:
            skipped[name] = reason
        else:
            active.append(name)

    runs_per_target = dict.fromkeys(active, 0)
    findings: list[Finding] = []
    produced = 0
    stopped_early = False
    started = time.perf_counter()

    with tempfile.TemporaryDirectory(prefix="codevanta-fuzz-") as scratch:
        payload = Path(scratch) / "mutant.bin"
        for iteration in range(iterations):
            mutant = _mutate(rng, seeds)
            payload.write_bytes(mutant.data)
            produced += 1
            for name in active:
                if time.perf_counter() - started > time_budget:
                    stopped_early = True
                    break
                runs_per_target[name] += 1
                try:
                    TARGETS[name](payload)
                except HANDLED_EXCEPTIONS:
                    continue  # the parser answered "unusable input", as documented
                except Exception as exc:  # noqa: BLE001 - any other escape is a defect
                    findings.append(_finding(iteration, name, mutant, exc))
            if stopped_early:
                break

    return Report(
        seed=seed,
        iterations=iterations,
        targets=selected,
        mutants=produced,
        runs=sum(runs_per_target.values()),
        runs_per_target=runs_per_target,
        elapsed=time.perf_counter() - started,
        time_budget=time_budget,
        stopped_early=stopped_early,
        skipped=skipped,
        findings=findings,
    )


# ---- cli -------------------------------------------------------------------


def _render(report: Report) -> str:
    """Render the human-readable summary: one row per target, then findings."""
    failures: dict[str, int] = {}
    for finding in report.findings:
        failures[finding.target] = failures.get(finding.target, 0) + 1

    lines = [
        f"fuzz-parsers  seed={report.seed}  mutants={report.mutants}/{report.iterations}"
        f"  runs={report.runs}  elapsed={report.elapsed:.2f}s"
        f"  budget={report.time_budget:g}s",
        "",
        f"{'target':<12}{'runs':>6}{'findings':>10}",
    ]
    for name in report.targets:
        if name in report.skipped:
            lines.append(f"{name:<12}{'-':>6}{'skipped':>10}")
            continue
        runs = report.runs_per_target.get(name, 0)
        lines.append(f"{name:<12}{runs:>6}{failures.get(name, 0):>10}")

    lines.append("")
    if not report.findings:
        lines.append(
            f"no findings: {report.runs} parser invocation(s) answered the mutants "
            "with a documented exception or a result"
        )
        return "\n".join(lines)

    lines.append(f"findings ({len(report.findings)}):")
    for index, finding in enumerate(report.findings, start=1):
        mutant = finding.mutant
        lines.extend(
            [
                f"  [{index}] target={finding.target} iteration={finding.iteration}"
                f" seed_file={mutant.seed_name}",
                f"      strategy={mutant.strategy}: {mutant.description}",
                f"      sha256={mutant.sha256} size={len(mutant.data)}",
                f"      {finding.exception}",
                f"      at {finding.location}",
            ]
        )
    lines.extend(
        [
            "",
            f"{len(report.findings)} finding(s): undocumented exception(s), exiting 1",
            "reproduce with: python scripts/fuzz_parsers.py"
            f" --seed {report.seed} --target <target> --iterations <iteration + 1>",
        ]
    )
    return "\n".join(lines)


def _non_negative_int(text: str) -> int:
    """argparse type: an integer that is not negative."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {text!r}") from None
    if value < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0: {text!r}")
    return value


def _positive_float(text: str) -> float:
    """argparse type: a float greater than zero."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if value <= 0:
        raise argparse.ArgumentTypeError(f"must be > 0: {text!r}")
    return value


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser (kept separate so tests can reuse it)."""
    parser = argparse.ArgumentParser(
        prog="fuzz_parsers.py",
        description=(
            "Mutation-fuzz the CODEVANTA parsers with a reproducible seed. Any exception "
            "the public API does not document is a finding and makes the script exit 1."
        ),
    )
    parser.add_argument(
        "--iterations",
        type=_non_negative_int,
        default=200,
        metavar="N",
        help="mutants to generate and run (default: 200)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=0,
        metavar="N",
        help="generator seed; the same seed replays the same mutants (default: 0)",
    )
    parser.add_argument(
        "--target",
        choices=[*TARGET_ORDER, "all"],
        default="all",
        help="parser surface to fuzz (default: all)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a machine-readable summary instead of the table",
    )
    parser.add_argument(
        "--time-budget",
        type=_positive_float,
        default=DEFAULT_TIME_BUDGET,
        metavar="SECONDS",
        help=f"stop starting new work after this long (default: {DEFAULT_TIME_BUDGET:g})",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fuzzer and return the process exit status."""
    args = _build_parser().parse_args(argv)
    targets = TARGET_ORDER if args.target == "all" else (args.target,)
    report = fuzz(
        iterations=args.iterations,
        seed=args.seed,
        targets=targets,
        time_budget=args.time_budget,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_render(report))
    for name, reason in report.skipped.items():
        print(f"warning: target {name!r} skipped: {reason}", file=sys.stderr)
    if report.stopped_early:
        print(
            f"warning: stopped at the {report.time_budget:g}s budget after "
            f"{report.mutants}/{report.iterations} mutants",
            file=sys.stderr,
        )
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())








"""Shared test fixtures for CODEVANTA."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest


def make_minimal_elf64(path: Path, *, entry: int = 0x401000) -> Path:
    """Write a header-only ELF64 file (no sections, no segments)."""
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,        # e_type = ET_EXEC
        62,       # e_machine = EM_X86_64
        1,        # e_version
        entry,    # e_entry
        0,        # e_phoff
        0,        # e_shoff
        0,        # e_flags
        64,       # e_ehsize
        56,       # e_phentsize
        0,        # e_phnum
        64,       # e_shentsize
        0,        # e_shnum
        0,        # e_shstrndx
    )
    path.write_bytes(ident + header)
    return path


@pytest.fixture
def elf64_path(tmp_path: Path) -> Path:
    return make_minimal_elf64(tmp_path / "sample_elf64.bin")


def make_elf64_with_text(path: Path, *, entry: int = 0x401000) -> Path:
    """Write an ELF64 file with one executable .text section."""
    text = bytes.fromhex("554889e5c3")  # push rbp; mov rbp, rsp; ret
    shstr = b"\x00.text\x00.shstrtab\x00"
    off_text = 0x40
    off_shstr = off_text + len(text)
    off_sh = 0x58
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, entry, 0, off_sh, 0, 64, 56, 0, 64, 3, 2
    )
    null_section = bytes(64)
    text_section = struct.pack(
        "<IIQQQQIIQQ", 1, 1, 6, entry, off_text, len(text), 0, 0, 16, 0
    )
    str_section = struct.pack(
        "<IIQQQQIIQQ", 7, 3, 0, 0, off_shstr, len(shstr), 0, 0, 1, 0
    )
    blob = bytearray(off_sh)
    blob[0:64] = header
    blob[off_text:off_text + len(text)] = text
    blob[off_shstr:off_shstr + len(shstr)] = shstr
    blob += null_section + text_section + str_section
    path.write_bytes(blob)
    return path


@pytest.fixture
def elf64_text_path(tmp_path: Path) -> Path:
    return make_elf64_with_text(tmp_path / "sample_elf64_text.bin")



@pytest.fixture
def pe_path() -> Path:
    """Use the running Python interpreter as a real PE sample on Windows."""
    if not sys.platform.startswith("win"):
        pytest.skip("PE sample tests require Windows")
    executable = Path(sys.executable)
    if executable.suffix.lower() != ".exe" or not executable.exists():
        pytest.skip("Python interpreter is not a PE executable")
    return executable


def make_macho64_with_text(
    path: Path,
    *,
    base: int = 0x100000000,
    symbol_name: str = "_sample_main",
) -> Path:
    """Write a minimal Mach-O 64 x86_64 executable.

    The file has one ``__TEXT`` segment with an executable ``__text`` section
    (``push rbp; mov rbp, rsp; ret``), an ``LC_MAIN`` entry point, and a symbol
    table exporting ``symbol_name`` at the section address. Load commands are
    contiguous after the header as the format requires.
    """
    text = bytes.fromhex("554889e5c3")  # push rbp; mov rbp, rsp; ret

    segment_command_size = 72 + 80  # segment_command_64 + one section_64
    main_size, symtab_size, dysymtab_size = 24, 24, 80
    text_offset = 32 + segment_command_size + main_size + symtab_size + dysymtab_size
    symbol_offset = text_offset + len(text)
    string_table = b"\x00" + symbol_name.encode() + b"\x00"
    string_offset = symbol_offset + 16
    total_size = string_offset + len(string_table)
    section_address = base + text_offset

    def section_64(name: bytes, segment: bytes, addr: int, size: int, offset: int) -> bytes:
        flags = 0x80000400  # S_REGULAR | PURE_INSTRUCTIONS | SOME_INSTRUCTIONS
        return struct.pack(
            "<16s16sQQIIIIIIII",
            name.ljust(16, b"\x00"),
            segment.ljust(16, b"\x00"),
            addr,
            size,
            offset,
            4,  # align
            0,  # reloff
            0,  # nreloc
            flags,
            0, 0, 0,  # reserved1..3
        )

    segment = struct.pack(
        "<II16sQQQQIIII",
        0x19,  # LC_SEGMENT_64
        segment_command_size,
        b"__TEXT".ljust(16, b"\x00"),
        base,  # vmaddr; fileoff is 0, so VA = base + file offset
        total_size,  # vmsize
        0,  # fileoff
        total_size,  # filesize
        5,  # initprot = read | execute
        5,  # maxprot
        1,  # nsects
        0,  # flags
    ) + section_64(b"__text", b"__TEXT", section_address, len(text), text_offset)

    main_command = struct.pack(
        "<IIQQ",
        0x80000028,  # LC_MAIN | LC_REQ_DYLD
        main_size,
        text_offset,  # entryoff (file offset)
        0,  # stacksize
    )

    # One nlist_64 entry: external symbol defined in section 1.
    symbol_entry = struct.pack(
        "<IBBHQ",
        1,  # strx -> "_sample_main" right after the leading NUL
        0x0F,  # n_type = N_SECT | N_EXT
        1,  # n_sect
        0,  # n_desc
        section_address,
    )
    symtab_command = struct.pack(
        "<IIIIII",
        0x02,  # LC_SYMTAB
        symtab_size,
        symbol_offset,
        1,  # nsyms
        string_offset,
        len(string_table),
    )
    dysymtab_command = struct.pack(
        "<II" + "I" * 18,
        0x0B,  # LC_DYSYMTAB
        dysymtab_size,
        0, 0,  # local symbols
        0, 1,  # defined external symbols: index 0, count 1
        1, 0,  # undefined symbols: index 1, count 0
        0, 0,  # tocoff, ntoc
        0, 0,  # modtaboff, nmodtab
        0, 0,  # extrefsymoff, nextrefsyms
        0, 0,  # indirectsymoff, nindirectsyms
        0, 0,  # extreloff, nextrel
        0, 0,  # locreloff, nlocrel
    )

    commands = segment + main_command + symtab_command + dysymtab_command
    header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,  # MH_MAGIC_64
        0x01000007,  # CPU_TYPE_X86_64
        3,  # cpusubtype
        2,  # MH_EXECUTE
        4,  # ncmds
        len(commands),
        0,  # flags
        0,  # reserved
    )
    blob = header + commands + text + symbol_entry + string_table
    assert len(blob) == total_size
    path.write_bytes(blob)
    return path


@pytest.fixture
def macho64_text_path(tmp_path: Path) -> Path:
    return make_macho64_with_text(tmp_path / "sample_macho64.bin")

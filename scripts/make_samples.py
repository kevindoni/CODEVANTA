#!/usr/bin/env python3
"""Generate the committed sample binaries under ``samples/``.

The samples exist so every command in the documentation can be run on any
platform without pointing at ``C:\\Windows\\System32`` or at a system binary.
They are intentionally tiny, self-contained, and reproducible:

* standard library only -- no LIEF, no Capstone, no external assembler;
* fully deterministic -- timestamps are zeroed and padding is fixed, so
  running this script twice produces byte-identical files;
* small -- each file is well under 4 KiB.

Usage::

    python scripts/make_samples.py                 # regenerate samples/
    python scripts/make_samples.py --output-dir X  # write somewhere else
    python scripts/make_samples.py --check         # verify committed bytes
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = REPO_ROOT / "samples"

#: ASCII string embedded in the code of both samples (NUL terminated, the way
#: a C string literal would end up in .text). Kept short so the files stay tiny.
TEXT_MESSAGE = b"codevanta x64 sample\x00"

# ---------------------------------------------------------------------------
# Shared x86_64 code body
# ---------------------------------------------------------------------------

#: Instruction sequence placed at the entry point of both samples. Offsets are
#: relative to the entry point. The payload follows the tenth instruction, so
#: ``codevanta disasm --count 10`` shows exactly the real code and nothing else.
#:
#:   0x00  sub  rsp, 0x28          ; 48 83 ec 28
#:   0x04  xor  eax, eax           ; 31 c0
#:   0x06  mov  r9, rax            ; 49 89 c1
#:   0x09  lea  rcx, [rip+disp]    ; 48 8d 0d xx xx xx xx  -> TEXT_MESSAGE
#:   0x10  mov  edx, 0x1           ; ba 01 00 00 00
#:   0x15  call helper             ; e8 xx xx xx xx
#:   0x1a  add  rsp, 0x28          ; 48 83 c4 28
#:   0x1e  ret                     ; c3
#:   0x1f  mov  eax, 0x2a          ; b8 2a 00 00 00  (helper)
#:   0x24  ret                     ; c3
#:   0x25  TEXT_MESSAGE            ; ASCII payload
CODE_LAYOUT: tuple[tuple[int, str], ...] = (
    (0x00, "sub rsp, 0x28"),
    (0x04, "xor eax, eax"),
    (0x06, "mov r9, rax"),
    (0x09, "lea rcx, [rip + message]"),
    (0x10, "mov edx, 0x1"),
    (0x15, "call helper"),
    (0x1A, "add rsp, 0x28"),
    (0x1E, "ret"),
    (0x1F, "mov eax, 0x2a"),
    (0x24, "ret"),
    (0x25, "ASCII payload"),
)

#: Offset of the helper function (the ``call`` target) inside the code body.
HELPER_OFFSET = 0x1F
#: Offset of the ASCII payload inside the code body.
MESSAGE_OFFSET = 0x25


def text_code() -> bytes:
    """Return the x86_64 code body followed by :data:`TEXT_MESSAGE`.

    Relative displacements are patched from the real offsets, so the payload
    can be edited without hand-recomputing instruction bytes.
    """
    code = bytearray()
    code += b"\x48\x83\xec\x28"  # sub rsp, 0x28
    code += b"\x31\xc0"  # xor eax, eax
    code += b"\x49\x89\xc1"  # mov r9, rax
    lea_offset = len(code)
    code += b"\x48\x8d\x0d\x00\x00\x00\x00"  # lea rcx, [rip + disp32]
    code += b"\xba\x01\x00\x00\x00"  # mov edx, 0x1
    call_offset = len(code)
    code += b"\xe8\x00\x00\x00\x00"  # call rel32
    code += b"\x48\x83\xc4\x28"  # add rsp, 0x28
    code += b"\xc3"  # ret

    assert len(code) == HELPER_OFFSET, "helper offset drifted from CODE_LAYOUT"
    code += b"\xb8\x2a\x00\x00\x00"  # mov eax, 0x2a
    code += b"\xc3"  # ret

    assert len(code) == MESSAGE_OFFSET, "message offset drifted from CODE_LAYOUT"
    code += TEXT_MESSAGE

    # lea: RIP after the instruction -> payload.
    lea_disp = MESSAGE_OFFSET - (lea_offset + 7)
    code[lea_offset + 3:lea_offset + 7] = struct.pack("<i", lea_disp)
    # call: RIP after the instruction -> helper.
    call_disp = HELPER_OFFSET - (call_offset + 5)
    code[call_offset + 1:call_offset + 5] = struct.pack("<i", call_disp)
    return bytes(code)


# ---------------------------------------------------------------------------
# PE32+ (x86_64) sample
# ---------------------------------------------------------------------------

PE_IMAGE_BASE = 0x140000000
PE_SECTION_RVA = 0x1000
PE_FILE_ALIGN = 0x200
PE_SECTION_ALIGN = 0x1000
PE_SECTION_SIZE = 0x200
PE_DLL_NAME = b"codevanta_pe64_sample.dll\x00"
PE_EXPORT_NAME = b"codevanta_sample_main\x00"

# Offsets inside the single .text section. All metadata lives inside the one
# executable section, so the sample needs exactly one section header.
PE_EXPORT_DIR_OFF = 0x40
PE_EXPORT_FUNCS_OFF = PE_EXPORT_DIR_OFF + 40  # 0x68
PE_EXPORT_NAMES_OFF = PE_EXPORT_FUNCS_OFF + 4  # 0x6c
PE_EXPORT_ORDS_OFF = PE_EXPORT_NAMES_OFF + 4  # 0x70
PE_DLL_NAME_OFF = PE_EXPORT_ORDS_OFF + 2  # 0x72
PE_EXPORT_NAME_OFF = PE_DLL_NAME_OFF + len(PE_DLL_NAME)  # 0x8c


def build_pe64_text() -> bytes:
    """Return a valid PE32+ x86_64 image with one executable ``.text`` section.

    The section holds the shared code body, the ASCII payload, and a one-entry
    export directory (``codevanta_sample_main``), so ``codevanta info`` and
    ``codevanta functions`` both have real structure to report.
    """
    code = text_code()

    section = bytearray(PE_SECTION_SIZE)
    section[0:len(code)] = code
    section[PE_EXPORT_FUNCS_OFF:PE_EXPORT_FUNCS_OFF + 4] = struct.pack(
        "<I", PE_SECTION_RVA
    )
    section[PE_EXPORT_NAMES_OFF:PE_EXPORT_NAMES_OFF + 4] = struct.pack(
        "<I", PE_SECTION_RVA + PE_EXPORT_NAME_OFF
    )
    section[PE_EXPORT_ORDS_OFF:PE_EXPORT_ORDS_OFF + 2] = struct.pack("<H", 0)
    section[PE_DLL_NAME_OFF:PE_DLL_NAME_OFF + len(PE_DLL_NAME)] = PE_DLL_NAME
    section[PE_EXPORT_NAME_OFF:PE_EXPORT_NAME_OFF + len(PE_EXPORT_NAME)] = PE_EXPORT_NAME
    export_directory = struct.pack(
        "<IIHHIIIIIII",
        0,  # Characteristics
        0,  # TimeDateStamp (zeroed: reproducible output)
        0,  # MajorVersion
        0,  # MinorVersion
        PE_SECTION_RVA + PE_DLL_NAME_OFF,  # Name: RVA of the DLL name
        1,  # Base: ordinal of the first export
        1,  # NumberOfFunctions
        1,  # NumberOfNames
        PE_SECTION_RVA + PE_EXPORT_FUNCS_OFF,  # AddressOfFunctions
        PE_SECTION_RVA + PE_EXPORT_NAMES_OFF,  # AddressOfNames
        PE_SECTION_RVA + PE_EXPORT_ORDS_OFF,  # AddressOfNameOrdinals
    )
    assert len(export_directory) == 40
    section[PE_EXPORT_DIR_OFF:PE_EXPORT_DIR_OFF + 40] = export_directory

    # DOS header: magic plus e_lfanew pointing at the PE signature.
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[0x3C:0x40] = struct.pack("<I", 64)
    pe_signature = b"PE\x00\x00"

    # COFF file header: machine, section count, zeroed timestamp, no COFF syms.
    coff_header = struct.pack(
        "<HHIIIHH",
        0x8664,  # IMAGE_FILE_MACHINE_AMD64
        1,  # NumberOfSections
        0,  # TimeDateStamp (zeroed: reproducible output)
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        0xF0,  # SizeOfOptionalHeader (PE32+)
        0x0022,  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    optional_header = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,  # Magic: PE32+ (64-bit)
        14,  # MajorLinkerVersion
        0,  # MinorLinkerVersion
        PE_SECTION_SIZE,  # SizeOfCode
        0,  # SizeOfInitializedData
        0,  # SizeOfUninitializedData
        PE_SECTION_RVA,  # AddressOfEntryPoint
        PE_SECTION_RVA,  # BaseOfCode
        PE_IMAGE_BASE,  # ImageBase
        PE_SECTION_ALIGN,  # SectionAlignment
        PE_FILE_ALIGN,  # FileAlignment
        6,  # MajorOperatingSystemVersion
        0,  # MinorOperatingSystemVersion
        0,  # MajorImageVersion
        0,  # MinorImageVersion
        6,  # MajorSubsystemVersion
        0,  # MinorSubsystemVersion
        0,  # Win32VersionValue
        PE_SECTION_ALIGN + PE_SECTION_SIZE,  # SizeOfImage
        PE_FILE_ALIGN,  # SizeOfHeaders
        0,  # CheckSum (zeroed: reproducible output)
        3,  # Subsystem: IMAGE_SUBSYSTEM_WINDOWS_CUI
        0,  # DllCharacteristics
        0x100000,  # SizeOfStackReserve
        0x1000,  # SizeOfStackCommit
        0x100000,  # SizeOfHeapReserve
        0x1000,  # SizeOfHeapCommit
        0,  # LoaderFlags
        16,  # NumberOfRvaAndSizes
    )
    assert len(optional_header) == 112

    data_directories = bytearray(16 * 8)
    data_directories[0:8] = struct.pack("<II", PE_SECTION_RVA + PE_EXPORT_DIR_OFF, 40)

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text",
        PE_SECTION_SIZE,  # VirtualSize
        PE_SECTION_RVA,  # VirtualAddress
        PE_SECTION_SIZE,  # SizeOfRawData
        PE_FILE_ALIGN,  # PointerToRawData
        0,  # PointerToRelocations
        0,  # PointerToLinenumbers
        0,  # NumberOfRelocations
        0,  # NumberOfLinenumbers
        0x60000020,  # CODE | EXECUTE | READ
    )

    headers = (
        bytes(dos_header)
        + pe_signature
        + coff_header
        + optional_header
        + bytes(data_directories)
        + section_header
    )
    assert len(headers) <= PE_FILE_ALIGN, "PE headers no longer fit in SizeOfHeaders"
    return headers.ljust(PE_FILE_ALIGN, b"\x00") + bytes(section)


# ---------------------------------------------------------------------------
# Mach-O 64 (x86_64) sample
# ---------------------------------------------------------------------------

MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 2
MACHO_CPU_TYPE_X86_64 = 0x01000007
MACHO_CPU_SUBTYPE_X86_64_ALL = 3
MACHO_BASE = 0x100000000
MACHO_SYMBOL_NAME = b"_codevanta_sample_main"

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B
LC_MAIN = 0x80000028  # LC_MAIN | LC_REQ_DYLD
S_REGULAR_PURE_INSTRUCTIONS = 0x80000400  # S_REGULAR | PURE | SOME_INSTRUCTIONS


def section_64(
    name: bytes,
    segment: bytes,
    address: int,
    size: int,
    offset: int,
    flags: int,
) -> bytes:
    """Return one ``section_64`` record."""
    return struct.pack(
        "<16s16sQQIIIIIIII",
        name.ljust(16, b"\x00"),
        segment.ljust(16, b"\x00"),
        address,
        size,
        offset,
        4,  # align (2**4)
        0,  # reloff
        0,  # nreloc
        flags,
        0,  # reserved1
        0,  # reserved2
        0,  # reserved3
    )


def build_macho64_text() -> bytes:
    """Return a thin MH_EXECUTE x86_64 Mach-O with ``__TEXT,__text``.

    A ``__TEXT`` segment holds the executable ``__text`` section (shared code
    body plus ASCII payload) and a ``__LINKEDIT`` segment holds the symbol
    table, which exports ``_codevanta_sample_main`` at the entry point.
    """
    code = text_code()
    text_size = len(code)

    segment_command_size = 72 + 80  # segment_command_64 + one section_64
    linkedit_command_size = 72  # segment_command_64, no sections
    main_command_size = 24
    symtab_command_size = 24
    dysymtab_command_size = 80
    commands_size = (
        segment_command_size
        + linkedit_command_size
        + main_command_size
        + symtab_command_size
        + dysymtab_command_size
    )
    header_size = 32
    text_offset = header_size + commands_size
    symbol_offset = text_offset + text_size
    string_table = b"\x00" + MACHO_SYMBOL_NAME + b"\x00"
    string_offset = symbol_offset + 16  # one nlist_64
    linkedit_size = 16 + len(string_table)
    total_size = string_offset + len(string_table)
    section_address = MACHO_BASE + text_offset

    text_segment = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        segment_command_size,
        b"__TEXT".ljust(16, b"\x00"),
        MACHO_BASE,  # vmaddr
        text_offset + text_size,  # vmsize
        0,  # fileoff
        text_offset + text_size,  # filesize
        5,  # initprot: VM_PROT_READ | VM_PROT_EXECUTE
        5,  # maxprot
        1,  # nsects
        0,  # flags
    ) + section_64(
        b"__text",
        b"__TEXT",
        section_address,
        text_size,
        text_offset,
        S_REGULAR_PURE_INSTRUCTIONS,
    )

    linkedit_segment = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        linkedit_command_size,
        b"__LINKEDIT".ljust(16, b"\x00"),
        MACHO_BASE + symbol_offset,  # vmaddr
        linkedit_size,  # vmsize
        symbol_offset,  # fileoff
        linkedit_size,  # filesize
        1,  # initprot: VM_PROT_READ
        1,  # maxprot
        0,  # nsects
        0,  # flags
    )

    main_command = struct.pack(
        "<IIQQ",
        LC_MAIN,
        main_command_size,
        text_offset,  # entryoff: file offset of the entry point
        0,  # stacksize
    )

    # One nlist_64 entry: an external symbol defined in section 1 (__text).
    symbol_entry = struct.pack(
        "<IBBHQ",
        1,  # n_strx: symbol name right after the leading NUL
        0x0F,  # n_type = N_SECT | N_EXT
        1,  # n_sect
        0,  # n_desc
        section_address,  # n_value
    )
    symtab_command = struct.pack(
        "<IIIIII",
        LC_SYMTAB,
        symtab_command_size,
        symbol_offset,  # symoff
        1,  # nsyms
        string_offset,  # stroff
        len(string_table),  # strsize
    )
    dysymtab_command = struct.pack(
        "<II" + "I" * 18,
        LC_DYSYMTAB,
        dysymtab_command_size,
        0, 0,  # ilocalsym, nlocalsym
        0, 1,  # iextdefsym, nextdefsym
        1, 0,  # iundefsym, nundefsym
        0, 0,  # tocoff, ntoc
        0, 0,  # modtaboff, nmodtab
        0, 0,  # extrefsymoff, nextrefsyms
        0, 0,  # indirectsymoff, nindirectsyms
        0, 0,  # extreloff, nextrel
        0, 0,  # locreloff, nlocrel
    )

    commands = (
        text_segment
        + linkedit_segment
        + main_command
        + symtab_command
        + dysymtab_command
    )
    assert len(commands) == commands_size, "Mach-O load-command sizes drifted"

    header = struct.pack(
        "<IIIIIIII",
        MH_MAGIC_64,
        MACHO_CPU_TYPE_X86_64,
        MACHO_CPU_SUBTYPE_X86_64_ALL,
        MH_EXECUTE,
        5,  # ncmds
        commands_size,  # sizeofcmds
        0,  # flags
        0,  # reserved
    )

    blob = header + commands + code + symbol_entry + string_table
    assert len(blob) == total_size, "Mach-O layout arithmetic drifted"
    return blob


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

#: Sample file name -> builder. The order is the write/report order.
SAMPLE_BUILDERS: dict[str, Callable[[], bytes]] = {
    "pe64_text.bin": build_pe64_text,
    "macho64_text.bin": build_macho64_text,
}


def build_samples() -> dict[str, bytes]:
    """Return ``{file name: bytes}`` for every sample."""
    return {name: builder() for name, builder in SAMPLE_BUILDERS.items()}


def write_samples(output_dir: Path) -> list[tuple[str, int, str]]:
    """Write every sample into ``output_dir``; return ``(name, size, sha256)``."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[tuple[str, int, str]] = []
    for name, data in build_samples().items():
        (output_dir / name).write_bytes(data)
        written.append((name, len(data), hashlib.sha256(data).hexdigest()))
    return written


def check_samples(output_dir: Path) -> list[str]:
    """Return the names of samples whose committed bytes are stale or missing."""
    output_dir = Path(output_dir)
    stale: list[str] = []
    for name, data in build_samples().items():
        path = output_dir / name
        if not path.is_file() or path.read_bytes() != data:
            stale.append(name)
    return stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the committed CODEVANTA sample binaries."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"directory to write samples into (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit non-zero if the committed samples are stale",
    )
    args = parser.parse_args(argv)
    output_dir = Path(args.output_dir)

    if args.check:
        stale = check_samples(output_dir)
        if stale:
            print(f"stale samples in {output_dir}: {', '.join(stale)}", file=sys.stderr)
            return 1
        print(f"samples in {output_dir} are up to date")
        return 0

    written = write_samples(output_dir)
    print(f"wrote {len(written)} sample(s) to {output_dir}")
    for name, size, digest in written:
        print(f"  {name:<18} {size:>5} bytes  sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""ELF dynamic, Mach-O dylib and .pyc deep inspector tests (lane-depth2).

All fixtures are hand-built bytes written to ``tmp_path``: a synthetic
ELF64 with a ``PT_DYNAMIC`` segment, an ELF32 big-endian image that falls
back to the ``.dynamic`` section, a thin Mach-O with dylib load commands
(LE 64 + BE 32), and hand-encoded marshal bodies for 3.12/3.9 layouts.
No real binaries, no network; malformed cases prove the typed
:class:`~codevanta.core.report.AnalysisError`.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis import binmeta, elf_dynamic, macho_dylibs, pyc_inspect
from codevanta.analysis.macho_dylibs import unpack_dylib_version
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools

SECTION_VA = 0x1000

DT = {"NEEDED": 1, "STRTAB": 5, "INIT": 12, "FINI": 13, "SONAME": 14,
      "RPATH": 15, "INIT_ARRAY": 25, "FINI_ARRAY": 26,
      "INIT_ARRAYSZ": 27, "FINI_ARRAYSZ": 28, "RUNPATH": 29}


# ---- ELF builders ---------------------------------------------------------------


def _elf_header(
    *,
    is64: bool = True,
    little: bool = True,
    phnum: int,
    phoff: int,
    shnum: int = 0,
    shoff: int = 0,
    phentsize: int | None = None,
    shentsize: int | None = None,
) -> bytes:
    order = "<" if little else ">"
    ident = b"\x7fELF" + bytes([2 if is64 else 1, 1 if little else 2, 1, 0]) + bytes(8)
    if is64:
        return ident + struct.pack(
            f"{order}HHIQQQIHHHHHH",
            3, 62, 1, 0, phoff, shoff, 0,
            64, phentsize if phentsize is not None else 56, phnum,
            shentsize if shentsize is not None else 64, shnum, 0,
        )
    return ident + struct.pack(
        f"{order}HHIIIIIHHHHHH",
        3, 62, 1, 0, phoff, shoff, 0,
        52, phentsize if phentsize is not None else 32, phnum,
        shentsize if shentsize is not None else 40, shnum, 0,
    )


def _phdr64(p_type: int, offset: int, vaddr: int, filesz: int) -> bytes:
    return struct.pack("<IIQQQQQQ", p_type, 5, offset, vaddr, vaddr, filesz, filesz, 8)


def _phdr32be(p_type: int, offset: int, vaddr: int, filesz: int) -> bytes:
    # Elf32_Phdr has no flags word: type, offset, vaddr, paddr, filesz, memsz, flags, align.
    return struct.pack(">IIIIIIII", p_type, offset, vaddr, vaddr, filesz, filesz, 5, 4)


def _shdr32be(sh_type: int, offset: int, size: int, link: int, addr: int) -> bytes:
    return struct.pack(">IIIIIIIIII", 0, sh_type, 0, addr, offset, size, link, 0, 4, 0)


def _dyn_entry64(tag: int, value: int) -> bytes:
    return struct.pack("<QQ", tag, value)


def _dyn_entry32be(tag: int, value: int) -> bytes:
    return struct.pack(">II", tag, value)


def build_elf64_dynamic(path: Path, *, needed_count: int = 3) -> Path:
    """ELF64 little-endian: PT_LOAD + PT_DYNAMIC with a full tag set."""
    dynstr = bytearray(b"\x00")
    offsets: dict[str, int] = {}
    for name in ["libc.so.6", "libm.so.6", "libpthread.so.0", "libdemo.so.1"]:
        while len(dynstr) % 8:
            dynstr.append(0)
        offsets[name] = len(dynstr)
        dynstr += name.encode() + b"\x00"
    dynstr_bytes = bytes(dynstr)
    data_off = 64 + 56 * 2
    strtab_off = data_off
    array_off = strtab_off + len(dynstr_bytes)
    array_va = SECTION_VA + array_off
    init_array = [0x401000 + i * 0x20 for i in range(12)]
    fini_array = [0x402000]
    entries = b"".join(
        _dyn_entry64(DT["NEEDED"], offsets[name])
        for name in ["libc.so.6", "libm.so.6", "libpthread.so.0"][:needed_count]
    )
    entries += _dyn_entry64(DT["STRTAB"], SECTION_VA + strtab_off)
    entries += _dyn_entry64(DT["SONAME"], offsets["libdemo.so.1"])
    entries += _dyn_entry64(DT["RPATH"], offsets["libm.so.6"])
    entries += _dyn_entry64(DT["RUNPATH"], offsets["libpthread.so.0"])
    entries += _dyn_entry64(DT["INIT"], 0x401000)
    entries += _dyn_entry64(DT["FINI"], 0x402000)
    entries += _dyn_entry64(DT["INIT_ARRAY"], array_va)
    entries += _dyn_entry64(DT["INIT_ARRAYSZ"], 10)  # >8 -> honest truncation
    entries += _dyn_entry64(DT["FINI_ARRAY"], array_va + 8 * 12)
    entries += _dyn_entry64(DT["FINI_ARRAYSZ"], 1)
    entries += _dyn_entry64(0, 0)
    dynamic = entries
    arrays = b"".join(struct.pack("<Q", va) for va in init_array + fini_array)
    payload = dynstr_bytes + arrays
    dynamic_off = data_off + len(payload)
    phdrs = (
        _phdr64(1, data_off, SECTION_VA + data_off, len(payload))
        + _phdr64(2, dynamic_off, SECTION_VA + dynamic_off, len(dynamic))
    )
    out = _elf_header(is64=True, phnum=2, phoff=64)
    out += phdrs + payload + dynamic
    path.write_bytes(out)
    return path


def build_elf32be_section_dynamic(path: Path) -> Path:
    """ELF32 big-endian: no PT_DYNAMIC, only ``.dynamic`` + ``.dynstr`` sections."""
    data_off = 52 + 32 * 1 + 40 * 2  # ehdr (52) + one phdr (32) + two shdrs (40 each)
    dynstr = b"\x00libsimple.so\x00libother.so\x00"
    entries = (
        _dyn_entry32be(DT["NEEDED"], 1)
        + _dyn_entry32be(DT["STRTAB"], SECTION_VA + data_off)
        + _dyn_entry32be(DT["SONAME"], 14)
        + _dyn_entry32be(DT["INIT"], 0x1000)
        + _dyn_entry32be(DT["INIT_ARRAY"], SECTION_VA + 0x100)  # unmapped -> warning
        + _dyn_entry32be(DT["INIT_ARRAYSZ"], 2)
        + _dyn_entry32be(0, 0)
    )
    arrays = struct.pack(">II", 0x1000, 0x1004)
    dynstr_off = data_off
    dynamic_off = dynstr_off + len(dynstr)
    dynamic_off + len(entries)
    shoff = 52 + 32  # ehdr + one program header: section headers live here
    phdrs = _phdr32be(1, data_off, SECTION_VA + data_off, len(dynstr) + len(entries) + len(arrays))
    shdrs = (
        _shdr32be(6, dynamic_off, len(entries), 2, 0)  # SHT_DYNAMIC (.dynamic)
        + _shdr32be(3, dynstr_off, len(dynstr), 0, SECTION_VA)  # SHT_STRTAB
    )
    out = _elf_header(
        is64=False, little=False, phnum=1, phoff=52, shnum=2, shoff=shoff, shentsize=40
    )
    out += phdrs + shdrs + dynstr + entries + arrays
    path.write_bytes(out)
    return path


# ---- Mach-O builders ------------------------------------------------------------


def _dylib_command_le(cmd: int, name: str, *, current: int = 0x00010002, compat: int = 0x00010000) -> bytes:
    name_bytes = name.encode() + b"\x00"
    cmdsize = (24 + len(name_bytes) + 3) & ~3
    blob = struct.pack("<II", cmd, cmdsize)
    blob += struct.pack("<IIII", 24, 2, current, compat)
    blob += name_bytes
    blob += bytes(cmdsize - len(blob))
    return blob


def _dylib_command_be32(cmd: int, name: str) -> bytes:
    name_bytes = name.encode() + b"\x00"
    cmdsize = (24 + len(name_bytes) + 3) & ~3
    blob = struct.pack(">II", cmd, cmdsize)
    blob += struct.pack(">IIII", 24, 2, 0x00010002, 0x00010000)
    blob += name_bytes
    blob += bytes(cmdsize - len(blob))
    return blob


def build_macho64_dylibs(
    path: Path,
    *,
    dylibs: list[bytes],
    with_id: bool = True,
    ncmds: int | None = None,
    sizeofcmds: int | None = None,
) -> Path:
    commands = b""
    if with_id:
        commands += _dylib_command_le(0x0D, "@rpath/libself.dylib")
    commands += b"".join(dylibs)
    commands += struct.pack("<II", 0x19, 72) + bytes(68)  # LC_SEGMENT: skipped
    header = struct.pack(
        "<IIIIIIIi",
        0xFEEDFACF, 0x01000007, 0x00000003, 2,  # magic, cputype, cpusubtype, filetype
        ncmds if ncmds is not None else len(dylibs) + (1 if with_id else 0) + 1,
        sizeofcmds if sizeofcmds is not None else len(commands),
        0, 0,
    )
    path.write_bytes(header + commands)
    return path


def build_macho32be_dylib(path: Path) -> Path:
    command = _dylib_command_be32(0x0C, "@executable_path/libbe.dylib")
    # A big-endian file stores MH_MAGIC (0xFEEDFACE) big-endian, so the
    # parser's little-endian magic read yields 0xCEFAEDFE (the CIGAM form).
    # The 32-bit header is 28 bytes (no reserved word).
    header = struct.pack(">IIIIIII", 0xFEEDFACE, 7, 3, 6, 1, len(command), 0)
    path.write_bytes(header + command)
    return path


# ---- marshal builders (.pyc) ----------------------------------------------------


def _m_bytes(data: bytes) -> bytes:
    return b"s" + struct.pack("<I", len(data)) + data


def _m_ascii(text: str, *, interned: bool = False, ref: bool = False) -> bytes:
    if interned:
        base = 0x41  # 'A': u32 length
        length = struct.pack("<I", len(text.encode()))
    else:
        base = 0x7A  # 'z': one-byte length
        length = bytes([len(text.encode())])
    flag = 0x80 if ref else 0x00
    return bytes([base | flag]) + length + text.encode()


def _m_int(value: int) -> bytes:
    return b"i" + struct.pack("<i", value)


def _m_int64(value: int) -> bytes:
    return b"I" + struct.pack("<q", value)


def _m_binary_float(value: float) -> bytes:
    return b"g" + struct.pack("<d", value)


def _m_float_text(text: str) -> bytes:
    return b"f" + struct.pack("<I", len(text)) + text.encode()


def _m_binary_complex() -> bytes:
    return b"y" + struct.pack("<dd", 1.5, -2.5)


def _m_long(digits: int) -> bytes:
    return b"l" + struct.pack("<i", digits) + bytes(abs(digits) * 2)


def _m_none() -> bytes:
    return b"N"


def _m_small_tuple(items: list[bytes]) -> bytes:
    return b")" + bytes([len(items)]) + b"".join(items)


def _m_list(items: list[bytes]) -> bytes:
    return b"[" + struct.pack("<I", len(items)) + b"".join(items)


def _m_set(items: list[bytes]) -> bytes:
    return b"<" + struct.pack("<I", len(items)) + b"".join(items)


def _m_dict(pairs: list[tuple[bytes, bytes]]) -> bytes:
    body = b"".join(key + value for key, value in pairs)
    return b"{" + struct.pack("<I", len(pairs)) + body


def _m_ref(index: int) -> bytes:
    return b"r" + struct.pack("<I", index)


def _m_code(
    *,
    version: str,
    argcount: int = 2,
    kwonly: int = 1,
    nlocals: int = 2,
    stacksize: int = 4,
    flags: int = 64,
    code: bytes,
    consts: bytes,
    names: bytes,
    localsplus: bytes,
    filename: str,
    name: str,
    qualname: str = "",
) -> bytes:
    """One code object in the 3.11+ or 3.8-3.10 marshal layout."""
    fields = struct.pack("<I", argcount)
    if version not in ("3.7",):
        fields += struct.pack("<I", 0)  # posonlyargcount
    fields += struct.pack("<I", kwonly) + struct.pack("<I", nlocals)
    fields += struct.pack("<I", stacksize) + struct.pack("<I", flags)
    tail = (
        _m_bytes(code)
        + consts
        + names
    )
    if version in ("3.7", "3.8", "3.9", "3.10"):
        tail += localsplus * 3  # varnames, freevars, cellvars
        tail += _m_ascii(filename)
        tail += _m_ascii(name)
        tail += struct.pack("<I", 1)
        tail += _m_bytes(b"\x01")  # lnotab
    else:  # 3.11+ localsplus layout
        tail += localsplus
        tail += _m_bytes(b"\x01" * 2)  # localspluskinds
        tail += _m_ascii(filename)
        tail += _m_ascii(name)
        tail += _m_ascii(qualname or name)
        tail += struct.pack("<I", 1)  # firstlineno
        tail += _m_bytes(b"\x00")  # linetable
        tail += _m_bytes(b"")  # exceptiontable
    return b"c" + fields + tail


def _pyc_header(magic: int, flags: int = 0) -> bytes:
    return struct.pack("<H", magic) + b"\r\n" + struct.pack("<III", flags, 1700000000, 64)


# ---- ELF dynamic ----------------------------------------------------------------


def test_elf64_dynamic_summary(tmp_path: Path) -> None:
    target = build_elf64_dynamic(tmp_path / "libdemo.so")
    summary = elf_dynamic.inspect_elf_dynamic(target)
    assert summary.elf_class == "64"
    assert summary.endian == "little"
    assert summary.dynamic_source == "pt_dynamic"
    assert list(summary.needed) == ["libc.so.6", "libm.so.6", "libpthread.so.0"]
    assert summary.needed_count == 3
    assert summary.soname == "libdemo.so.1"
    assert summary.rpath == "libm.so.6"
    assert summary.runpath == "libpthread.so.0"
    assert summary.init_address == 0x401000
    assert summary.fini_address == 0x402000
    assert summary.init_array_count == 10
    assert len(summary.init_array) == 8
    assert summary.init_array_truncated is True
    assert summary.fini_array == (0x402000,)
    assert summary.fini_array_truncated is False
    assert any("DT_INIT_ARRAY" in warning for warning in summary.warnings)
    assert json.dumps(summary.to_dict())
    assert summary.evidence.confidence.value == "high"


def test_elf_needed_truncation_keeps_honest_total(tmp_path: Path) -> None:
    target = tmp_path / "many.so"
    dynstr = b"\x00libx.so\x00"
    entries = b"".join(_dyn_entry64(DT["NEEDED"], 1) for _ in range(40))
    entries += _dyn_entry64(DT["STRTAB"], SECTION_VA + 64 + 112)
    entries += _dyn_entry64(0, 0)
    data_off = 64 + 56 * 2
    dynamic_off = data_off + len(dynstr)
    phdrs = (
        _phdr64(1, data_off, SECTION_VA + data_off, len(dynstr))
        + _phdr64(2, dynamic_off, SECTION_VA + dynamic_off, len(entries))
    )
    target.write_bytes(_elf_header(is64=True, phnum=2, phoff=64) + phdrs + dynstr + entries)
    summary = elf_dynamic.inspect_elf_dynamic(target)
    assert summary.needed_count == 40
    assert len(summary.needed) == 32
    assert summary.needed_truncated is True


def test_elf32be_section_fallback(tmp_path: Path) -> None:
    target = build_elf32be_section_dynamic(tmp_path / "libbe32.so")
    summary = elf_dynamic.inspect_elf_dynamic(target)
    assert summary.elf_class == "32"
    assert summary.endian == "big"
    assert summary.dynamic_source == "sht_dynamic"
    assert list(summary.needed) == ["libsimple.so"]
    assert summary.soname == "libother.so"
    assert summary.init_address == 0x1000
    assert summary.init_array == ()  # VA unmapped -> warning, empty list
    assert any("DT_INIT_ARRAY" in warning for warning in summary.warnings)


def test_elf_malformed(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="file not found"):
        elf_dynamic.inspect_elf_dynamic(tmp_path / "ghost.so")
    plain = tmp_path / "plain.so"
    plain.write_bytes(b"MZELFnotreally" * 4)
    with pytest.raises(AnalysisError, match="missing ELF magic"):
        elf_dynamic.inspect_elf_dynamic(plain)
    head = tmp_path / "headless.so"
    head.write_bytes(_elf_header(is64=True, phnum=0, phoff=64))
    with pytest.raises(AnalysisError, match="no PT_DYNAMIC"):
        elf_dynamic.inspect_elf_dynamic(head)
    # NEEDED without STRTAB.
    nostrtab = tmp_path / "nostrtab.so"
    entries = _dyn_entry64(DT["NEEDED"], 1) + _dyn_entry64(0, 0)
    # The entries physically sit right after ehdr (64) + one phdr (56) = 120.
    phdrs = _phdr64(2, 120, SECTION_VA + 120, len(entries))
    nostrtab.write_bytes(_elf_header(is64=True, phnum=1, phoff=64) + phdrs + entries)
    with pytest.raises(AnalysisError, match="DT_NEEDED present without DT_STRTAB"):
        elf_dynamic.inspect_elf_dynamic(nostrtab)
    # STRTAB mapped nowhere: no PT_LOAD covers 0x900000, so the VA->offset
    # walk finds nothing and the read is refused before any bytes are touched.
    badstrtab = tmp_path / "badstrtab.so"
    entries2 = (
        _dyn_entry64(DT["NEEDED"], 1)
        + _dyn_entry64(DT["STRTAB"], 0x900000)
        + _dyn_entry64(0, 0)
    )
    phdrs2 = _phdr64(2, 120, SECTION_VA + 120, len(entries2))
    badstrtab.write_bytes(_elf_header(is64=True, phnum=1, phoff=64) + phdrs2 + entries2)
    with pytest.raises(AnalysisError, match="DT_STRTAB VA"):
        elf_dynamic.inspect_elf_dynamic(badstrtab)
    # Unterminated dynamic string: the PT_LOAD covers a 300-byte run with no
    # NUL byte inside the bounded scan window, so the read is refused as
    # unterminated rather than silently decoding past the table.
    unterminated = tmp_path / "unterminated.so"
    dynstr = b"A" * 300
    entries3 = (
        _dyn_entry64(DT["NEEDED"], 0)
        + _dyn_entry64(DT["STRTAB"], SECTION_VA + 176)
        + _dyn_entry64(0, 0)
    )
    blob = dynstr + entries3
    phdrs3 = (
        _phdr64(1, 176, SECTION_VA + 176, len(dynstr))
        + _phdr64(2, 176 + len(dynstr), SECTION_VA + 176 + len(dynstr), len(entries3))
    )
    unterminated.write_bytes(_elf_header(is64=True, phnum=2, phoff=64) + phdrs3 + blob)
    with pytest.raises(AnalysisError, match="unterminated dynamic string"):
        elf_dynamic.inspect_elf_dynamic(unterminated)
    # Dynamic blob that holds zero entries before DT_NULL.
    nullonly = tmp_path / "nullonly.so"
    entries4 = _dyn_entry64(0, 0)
    phdrs4 = _phdr64(2, 120, SECTION_VA + 120, len(entries4))
    nullonly.write_bytes(_elf_header(is64=True, phnum=1, phoff=64) + phdrs4 + entries4)
    with pytest.raises(AnalysisError, match="no entries before DT_NULL"):
        elf_dynamic.inspect_elf_dynamic(nullonly)
    # Truncated program header table (e_phnum=3 with room for 2).
    badph = tmp_path / "badph.so"
    badph.write_bytes(
        _elf_header(is64=True, phnum=3, phoff=64, phentsize=56) + _phdr64(1, 0, 0, 0) * 2
    )
    with pytest.raises(AnalysisError, match="truncated program header 2"):
        elf_dynamic.inspect_elf_dynamic(badph)


def test_elf_detector_and_registry(tmp_path: Path) -> None:
    target = build_elf64_dynamic(tmp_path / "det.so")
    summary = binmeta.detect_elf_dynamic(target)
    assert summary is not None and summary.needed_count == 3
    assert binmeta.detect_elf_dynamic(tmp_path) is None
    notelf = tmp_path / "notelf.bin"
    notelf.write_bytes(b"PE\x00\x00-nope" * 4)
    assert binmeta.detect_elf_dynamic(notelf) is None
    report = binmeta.inspect_metadata(target)
    assert "elf-dynamic" in report.details


# ---- Mach-O dylibs ----------------------------------------------------------------


def test_macho64_dylibs_summary(tmp_path: Path) -> None:
    target = build_macho64_dylibs(
        tmp_path / "app.bin",
        dylibs=[
            _dylib_command_le(0x0C, "/usr/lib/libSystem.B.dylib"),
            _dylib_command_le(0x18, "/usr/lib/libweak.dylib"),
            _dylib_command_le(0x1F, "@rpath/libreexport.dylib"),
        ],
    )
    summary = macho_dylibs.inspect_macho_dylibs(target)
    assert summary.is64 is True
    assert summary.endian == "little"
    assert summary.file_type == 2
    assert summary.file_type_name == "executable"
    assert summary.load_command_count == 5  # id + 3 dylibs + skipped segment
    assert summary.dylib_count == 3
    assert summary.id_dylib is not None
    assert summary.id_dylib["name"] == "@rpath/libself.dylib"
    kinds = [entry["kind"] for entry in summary.dylibs]
    assert kinds == ["load", "weak", "reexport"]
    assert summary.dylibs[0]["name"] == "/usr/lib/libSystem.B.dylib"
    assert summary.dylibs[0]["current_version"] == "1.0.2"
    assert summary.dylibs[0]["compatibility_version"] == "1.0.0"
    assert summary.dylibs_truncated is False
    assert json.dumps(summary.to_dict())
    assert unpack_dylib_version((6 << 16) | (7 << 8) | 8) == "6.7.8"


def test_macho32be_dylib(tmp_path: Path) -> None:
    target = build_macho32be_dylib(tmp_path / "be.bin")
    summary = macho_dylibs.inspect_macho_dylibs(target)
    assert summary.is64 is False
    assert summary.endian == "big"
    assert summary.dylib_count == 1
    assert summary.dylibs[0]["name"] == "@executable_path/libbe.dylib"


def test_macho_dylibs_truncation_and_errors(tmp_path: Path) -> None:
    many = [_dylib_command_le(0x0C, f"@rpath/lib{i}.dylib") for i in range(40)]
    target = build_macho64_dylibs(tmp_path / "many.bin", dylibs=many, with_id=False)
    summary = macho_dylibs.inspect_macho_dylibs(target)
    assert summary.dylib_count == 40
    assert len(summary.dylibs) == 32
    assert summary.dylibs_truncated is True
    # Malformed cases.
    with pytest.raises(AnalysisError, match="file not found"):
        macho_dylibs.inspect_macho_dylibs(tmp_path / "ghost.bin")
    with pytest.raises(AnalysisError, match="Mach-O header truncated"):
        macho_dylibs.inspect_macho_dylibs(_write(tmp_path / "tiny.bin", b"\xcf\xfa\xed\xfe"))
    fat = tmp_path / "fat.bin"
    fat.write_bytes(struct.pack("<I", 0xCAFEBABE) + bytes(64))
    with pytest.raises(AnalysisError, match="not a thin Mach-O"):
        macho_dylibs.inspect_macho_dylibs(fat)
    # cmdsize < 8.
    badsize = tmp_path / "badsize.bin"
    header = struct.pack("<IIIIIIIi", 0xFEEDFACF, 7, 3, 2, 1, 8, 0, 0)
    badsize.write_bytes(header + struct.pack("<II", 0x0C, 4))
    with pytest.raises(AnalysisError, match="impossible cmdsize"):
        macho_dylibs.inspect_macho_dylibs(badsize)
    # Command running past the declared command list.
    over = build_macho64_dylibs(
        tmp_path / "over.bin", dylibs=[_dylib_command_le(0x0C, "@rpath/a.dylib")], sizeofcmds=8
    )
    with pytest.raises(AnalysisError, match="runs past the command list"):
        macho_dylibs.inspect_macho_dylibs(over)
    # ncmds claims more commands than the list holds.
    short = build_macho64_dylibs(
        tmp_path / "short.bin", dylibs=[_dylib_command_le(0x0C, "@rpath/a.dylib")], ncmds=9
    )
    with pytest.raises(AnalysisError, match="truncated after"):
        macho_dylibs.inspect_macho_dylibs(short)
    # Name offset outside the command.
    badname = bytearray(_dylib_command_le(0x0C, "@rpath/a.dylib"))
    struct.pack_into("<I", badname, 8, 2)  # lc_str offset < 8
    bad = build_macho64_dylibs(tmp_path / "badname.bin", dylibs=[bytes(badname)], with_id=False)
    with pytest.raises(AnalysisError, match="name offset 2 outside"):
        macho_dylibs.inspect_macho_dylibs(bad)
    # Duplicate LC_ID_DYLIB.
    dup = build_macho64_dylibs(
        tmp_path / "dup.bin",
        dylibs=[_dylib_command_le(0x0D, "@rpath/a.dylib"), _dylib_command_le(0x0D, "@rpath/b.dylib")],
        with_id=False,
    )
    with pytest.raises(AnalysisError, match="duplicate LC_ID_DYLIB"):
        macho_dylibs.inspect_macho_dylibs(dup)


def _write(path: Path, blob: bytes) -> Path:
    path.write_bytes(blob)
    return path


def test_macho_detector_and_registry(tmp_path: Path) -> None:
    target = build_macho64_dylibs(
        tmp_path / "det.bin", dylibs=[_dylib_command_le(0x0C, "@rpath/x.dylib")]
    )
    summary = binmeta.detect_macho_dylibs(target)
    assert summary is not None and summary.dylib_count == 1
    assert binmeta.detect_macho_dylibs(tmp_path) is None
    notmacho = tmp_path / "notmacho.bin"
    notmacho.write_bytes(b"\x7fELF-nope" * 4)
    assert binmeta.detect_macho_dylibs(notmacho) is None
    report = binmeta.inspect_metadata(target)
    assert "macho-dylibs" in report.details


# ---- .pyc deep walk ----------------------------------------------------------------


def _build_nested_code(version: str) -> bytes:
    return _m_code(
        version=version,
        argcount=1,
        kwonly=0,
        nlocals=1,
        stacksize=2,
        flags=67,
        code=b"\x64\x00",
        consts=_m_small_tuple([]),
        names=_m_small_tuple([]),
        localsplus=_m_small_tuple([_m_ascii("x")]),
        filename="helper.py",
        name="helper",
    )


def _build_top_body(version: str) -> bytes:
    consts = _m_small_tuple(
        [
            _m_int(42),
            _m_none(),
            _m_ascii("hi"),
            _m_bytes(b"\xca\xfe"),
            _m_small_tuple([_m_ascii("in"), _m_int(7)]),
            _m_list([_m_int(1)]),
            _m_set([_m_int(2)]),
            _m_dict([(_m_ascii("k"), _m_int(3))]),
            _m_int64(1 << 40),
            _m_binary_float(2.5),
            _m_float_text("3.25"),
            _m_long(2),
            _m_binary_complex(),
            _build_nested_code(version),
            _m_ascii("dup", interned=True, ref=True),
            _m_ref(0),  # resolves to the "dup" reference slot
        ]
    )
    names = _m_small_tuple([_m_ascii("print"), _m_ascii("value"), _m_ascii("helper")])
    return _m_code(
        version=version,
        code=b"\x64\x00\x53\x00",
        consts=consts,
        names=names,
        localsplus=_m_small_tuple(
            [_m_ascii("value"), _m_ascii("helper"), _m_ascii("x")]
        ),
        filename="mod.py",
        name="<module>",
        qualname="<module>",
    )


def _write_pyc(path: Path, magic: int, body: bytes, flags: int = 0) -> Path:
    path.write_bytes(_pyc_header(magic, flags) + body)
    return path


def test_pyc_312_modern_layout(tmp_path: Path) -> None:
    target = _write_pyc(tmp_path / "mod312.pyc", 3531, _build_top_body("3.12"))
    summary = pyc_inspect.inspect_pyc_code(target)
    assert summary.magic == 3531
    assert summary.python_version == "3.12"
    assert summary.argcount == 2
    assert summary.kwonlyargcount == 1
    assert summary.nlocals == 2
    assert summary.stacksize == 4
    assert summary.code_flags == 64
    assert summary.bytecode_size == 4
    assert summary.constant_count == 16
    kinds = [entry["kind"] for entry in summary.constants]
    assert kinds == [
        "int", "none", "str", "bytes", "tuple", "list", "set", "dict",
        "int", "float", "float", "long", "complex", "code", "str", "str",
    ]
    assert summary.constants[4]["kind"] == "tuple"
    assert summary.constants[13] == {"kind": "code", "name": "helper"}
    assert list(summary.names) == ["print", "value", "helper"]
    assert summary.name_count == 3
    assert summary.nested_code_count == 1
    assert summary.nested_code[0]["name"] == "helper"
    assert summary.nested_code[0]["filename"] == "helper.py"
    assert summary.nested_depth_max >= 1
    assert summary.hash_based is False
    assert summary.evidence.extra == {"bytecode_skipped": True}
    assert json.dumps(summary.to_dict())


def test_pyc_39_layout_and_hash_flags(tmp_path: Path) -> None:
    target = _write_pyc(tmp_path / "mod39.pyc", 3425, _build_top_body("3.9"), flags=0b11)
    summary = pyc_inspect.inspect_pyc_code(target)
    assert summary.python_version == "3.9"
    assert summary.hash_based is True
    assert summary.check_source is True
    assert summary.nested_code_count == 1
    assert summary.nested_code[0]["name"] == "helper"
    assert summary.nested_code[0]["filename"] is None  # pre-3.11 record has no filename
    assert list(summary.names) == ["print", "value", "helper"]


def test_pyc_malformed(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="file not found"):
        pyc_inspect.inspect_pyc_code(tmp_path / "ghost.pyc")
    short = tmp_path / "short.pyc"
    short.write_bytes(b"\xcb\x0d\r\n\x00")
    with pytest.raises(AnalysisError, match="truncated .pyc header"):
        pyc_inspect.inspect_pyc_code(short)
    badmagic = tmp_path / "badmagic.pyc"
    badmagic.write_bytes(b"\xcb\x0dXX" + bytes(24))
    with pytest.raises(AnalysisError, match="bad .pyc magic"):
        pyc_inspect.inspect_pyc_code(badmagic)
    notcode = tmp_path / "notcode.pyc"
    notcode.write_bytes(_pyc_header(3531) + b"N")
    with pytest.raises(AnalysisError, match="not a code object"):
        pyc_inspect.inspect_pyc_code(notcode)
    badtype = tmp_path / "badtype.pyc"
    body = _m_code(
        version="3.12",
        code=b"\x00",
        consts=b"w\x00\x00\x00\x00",
        names=_m_small_tuple([]),
        localsplus=_m_small_tuple([]),
        filename="f.py",
        name="<module>",
    )
    badtype.write_bytes(_pyc_header(3531) + body)
    with pytest.raises(AnalysisError, match="unsupported marshal type 0x77"):
        pyc_inspect.inspect_pyc_code(badtype)
    truncated = tmp_path / "truncated.pyc"
    truncated.write_bytes(_pyc_header(3531) + b"c" + b"\x00" * 6)
    with pytest.raises(AnalysisError, match="truncated marshal body"):
        pyc_inspect.inspect_pyc_code(truncated)
    badref = tmp_path / "badref.pyc"
    body2 = _m_code(
        version="3.12",
        code=b"\x00",
        consts=_m_small_tuple([_m_ref(9)]),
        names=_m_small_tuple([]),
        localsplus=_m_small_tuple([]),
        filename="f.py",
        name="<module>",
    )
    badref.write_bytes(_pyc_header(3531) + body2)
    with pytest.raises(AnalysisError, match="ref index 9 out of range"):
        pyc_inspect.inspect_pyc_code(badref)
    # Constants field that is not a tuple.
    badconsts = tmp_path / "badconsts.pyc"
    body3 = _m_code(
        version="3.12",
        code=b"\x00",
        consts=_m_int(5),
        names=_m_small_tuple([]),
        localsplus=_m_small_tuple([]),
        filename="f.py",
        name="<module>",
    )
    badconsts.write_bytes(_pyc_header(3531) + body3)
    with pytest.raises(AnalysisError, match="constants field is not a tuple"):
        pyc_inspect.inspect_pyc_code(badconsts)


def test_pyc_detector_and_registry_kind_priority(tmp_path: Path) -> None:
    target = _write_pyc(tmp_path / "det.pyc", 3531, _build_top_body("3.12"))
    summary = binmeta.detect_pyc_deep(target)
    assert summary is not None and summary.nested_code_count == 1
    assert binmeta.detect_pyc_deep(tmp_path) is None
    report = binmeta.inspect_metadata(target)
    # The header-only detector keeps kind precedence; the deep walk joins details.
    assert report.kind == "python-pyc"
    assert "pyc-deep" in report.details
    assert report.details["pyc-deep"]["nested_code_count"] == 1


def test_mcp_elf_macho_tool(tmp_path: Path) -> None:
    elf = build_elf64_dynamic(tmp_path / "mcp.so")
    payload = tools.codevanta_elf_macho(str(elf))
    assert payload["format"] == "elf"
    assert payload["dynamic"]["needed_count"] == 3
    macho = build_macho64_dylibs(
        tmp_path / "mcp.bin", dylibs=[_dylib_command_le(0x0C, "@rpath/x.dylib")]
    )
    payload = tools.codevanta_elf_macho(str(macho))
    assert payload["format"] == "macho"
    assert payload["dylibs"]["dylib_count"] == 1

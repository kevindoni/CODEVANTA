"""Cross-reference extraction tests over tiny synthetic ELF64 samples.

Every sample is assembled byte-by-byte with :mod:`struct` inside this module so
the tests stay self-contained and never touch shared fixtures.
"""

from __future__ import annotations

import struct
from dataclasses import replace
from pathlib import Path

import pytest

from codevanta.analysis.xrefs import Xref, XrefResult, find_xrefs
from codevanta.core.functions import FunctionCandidate
from codevanta.core.loader import BinaryInfo, BinaryLoader, ImportInfo
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

TEXT_VA = 0x401000
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4


def _write_elf64(
    path: Path,
    code: bytes,
    *,
    text_va: int = TEXT_VA,
    entry: int | None = None,
    text_flags: int = SHF_ALLOC | SHF_EXECINSTR,
) -> Path:
    """Write an ELF64 file with a single ``.text`` section holding ``code``."""
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_offset = 0x100
    shstrtab_offset = text_offset + len(code)
    section_headers_offset = (shstrtab_offset + len(shstrtab) + 7) & ~7
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,                            # e_type = ET_EXEC
        62,                           # e_machine = EM_X86_64
        1,                            # e_version
        text_va if entry is None else entry,
        0,                            # e_phoff
        section_headers_offset,       # e_shoff
        0,                            # e_flags
        64,                           # e_ehsize
        56,                           # e_phentsize
        0,                            # e_phnum
        64,                           # e_shentsize
        3,                            # e_shnum (null, .text, .shstrtab)
        2,                            # e_shstrndx
    )
    blob = bytearray(section_headers_offset)
    blob[0:64] = header
    blob[text_offset:text_offset + len(code)] = code
    blob[shstrtab_offset:shstrtab_offset + len(shstrtab)] = shstrtab
    blob += bytes(64)  # SHT_NULL section header
    blob += struct.pack(
        "<IIQQQQIIQQ",
        1,                 # sh_name -> ".text"
        1,                 # sh_type = SHT_PROGBITS
        text_flags,        # sh_flags
        text_va,           # sh_addr
        text_offset,       # sh_offset
        len(code),         # sh_size
        0,                 # sh_link
        0,                 # sh_info
        16,                # sh_addralign
        0,                 # sh_entsize
    )
    blob += struct.pack(
        "<IIQQQQIIQQ",
        7,                 # sh_name -> ".shstrtab"
        3,                 # sh_type = SHT_STRTAB
        0,                 # sh_flags
        0,                 # sh_addr
        shstrtab_offset,   # sh_offset
        len(shstrtab),     # sh_size
        0,                 # sh_link
        0,                 # sh_info
        1,                 # sh_addralign
        0,                 # sh_entsize
    )
    path.write_bytes(bytes(blob))
    return path


def _write_header_only_elf64(path: Path, *, entry: int = TEXT_VA) -> Path:
    """Write an ELF64 file with no section headers at all."""
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, entry, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    path.write_bytes(ident + header)
    return path


def _load(path: Path) -> BinaryInfo:
    """Load synthetic metadata for ``path`` through the real loader."""
    return BinaryLoader().load(path)


def _function(address: int, name: str) -> FunctionCandidate:
    """Build a hand-made function candidate for naming tests."""
    return FunctionCandidate(
        address=address,
        name=name,
        size=None,
        source="test.hand_built",
        confidence=Confidence.HIGH,
        evidence=Evidence(
            source="test.hand_built",
            method="unit_test",
            confidence=Confidence.HIGH,
            address=address,
        ),
    )


def test_direct_call_produces_call_xref(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "call.bin", bytes.fromhex("e80b000000c3"))
    info = _load(path)

    result = find_xrefs(path, info)

    assert [(x.from_address, x.to_address, x.kind) for x in result.xrefs] == [
        (TEXT_VA, 0x401010, "call")
    ]
    xref = result.xrefs[0]
    assert xref.instruction == "call 0x401010"
    assert xref.source == "capstone.direct_call"
    assert xref.function is None
    assert xref.evidence.source == "capstone.direct_call"
    assert xref.evidence.method == "linear_disassembly"
    assert xref.evidence.confidence is Confidence.CERTAIN
    assert xref.evidence.address == TEXT_VA
    assert xref.evidence.detail == "call 0x401010"

    assert result.scanned_sections == [".text"]
    assert result.scanned_bytes == 6
    assert result.truncated is False
    assert result.warnings == ()
    assert result.evidence.source == "capstone.xref_scan"
    assert result.evidence.method == "linear_disassembly"
    assert result.evidence.confidence is Confidence.CERTAIN
    assert result.evidence.detail == "1 xrefs"


def test_unconditional_jump_produces_jump_xref(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "jmp.bin", bytes.fromhex("eb059090909090"))
    info = _load(path)

    result = find_xrefs(path, info)

    assert len(result.xrefs) == 1
    xref = result.xrefs[0]
    assert (xref.from_address, xref.to_address) == (TEXT_VA, 0x401007)
    assert xref.kind == "jump"
    assert xref.source == "capstone.direct_jump"
    assert xref.evidence.source == "capstone.direct_jump"
    assert xref.instruction == "jmp 0x401007"
    assert result.scanned_bytes == 7


def test_conditional_jump_produces_branch_xref(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "branch.bin", bytes.fromhex("740290c3"))
    info = _load(path)

    result = find_xrefs(path, info)

    assert len(result.xrefs) == 1
    xref = result.xrefs[0]
    assert (xref.from_address, xref.to_address) == (TEXT_VA, 0x401004)
    assert xref.kind == "branch"
    assert xref.source == "capstone.conditional_branch"
    assert xref.evidence.source == "capstone.conditional_branch"
    assert xref.instruction == "je 0x401004"


def test_register_and_memory_operands_are_ignored(tmp_path: Path) -> None:
    # call rax ; jmp qword ptr [rax] ; ret
    path = _write_elf64(tmp_path / "indirect.bin", bytes.fromhex("ffd0ff20c3"))
    info = _load(path)

    result = find_xrefs(path, info)

    assert result.xrefs == []
    assert result.scanned_sections == [".text"]
    assert result.scanned_bytes == 5
    assert result.truncated is False


def test_max_bytes_below_section_size_truncates(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "cut.bin", bytes.fromhex("e80b000000c3"))
    info = _load(path)

    result = find_xrefs(path, info, max_bytes=2)

    assert result.truncated is True
    assert result.xrefs == []
    assert result.scanned_bytes == 0  # 2 bytes are not a complete instruction


def test_budget_equal_to_section_size_is_not_truncated(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "exact.bin", bytes.fromhex("e80b000000c3"))
    info = _load(path)

    result = find_xrefs(path, info, max_bytes=6)

    assert result.truncated is False
    assert [(x.from_address, x.to_address) for x in result.xrefs] == [(TEXT_VA, 0x401010)]



def test_no_executable_sections_yields_empty_result(tmp_path: Path) -> None:
    path = _write_elf64(
        tmp_path / "data.bin", bytes.fromhex("740290"), text_flags=SHF_ALLOC | SHF_WRITE
    )
    info = _load(path)
    assert not any(section.is_executable for section in info.sections)

    result = find_xrefs(path, info)

    assert result.xrefs == []
    assert result.scanned_sections == []
    assert result.scanned_bytes == 0
    assert result.truncated is False
    assert any("no executable sections" in warning for warning in result.warnings)


def test_header_only_elf_has_no_xrefs(tmp_path: Path) -> None:
    path = _write_header_only_elf64(tmp_path / "bare.bin")
    info = _load(path)

    result = find_xrefs(path, info)

    assert result.xrefs == []
    assert result.scanned_sections == []
    assert result.evidence.source == "capstone.xref_scan"


def test_target_is_named_from_supplied_candidates(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "named.bin", bytes.fromhex("e80b000000c3"))
    info = _load(path)

    result = find_xrefs(path, info, functions=[_function(0x401010, "callee")])

    assert result.xrefs[0].function == "callee"


def test_function_is_none_without_matching_candidate(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "unnamed.bin", bytes.fromhex("e80b000000c3"))
    info = _load(path)

    result = find_xrefs(path, info, functions=[_function(0x401100, "elsewhere")])

    assert result.xrefs[0].function is None


def test_xrefs_are_sorted_by_from_address(tmp_path: Path) -> None:
    # jmp 0x40100a ; nop x8 ; call 0x40100f ; ret
    code = bytes.fromhex("eb08" + "90" * 8 + "e800000000" + "c3")
    path = _write_elf64(tmp_path / "sorted.bin", code)
    info = _load(path)

    result = find_xrefs(path, info)

    addresses = [x.from_address for x in result.xrefs]
    assert addresses == [0x401000, 0x40100A]
    assert addresses == sorted(addresses)
    assert [x.kind for x in result.xrefs] == ["jump", "call"]


def test_to_dict_serializes_hex_addresses(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "dict.bin", bytes.fromhex("e80b000000c3"))
    info = _load(path)

    result = find_xrefs(path, info, functions=[_function(0x401010, "callee")])
    data = result.to_dict()

    assert data["xref_count"] == 1
    assert data["xrefs"][0]["from_address"] == "0x401000"
    assert data["xrefs"][0]["to_address"] == "0x401010"
    assert data["xrefs"][0]["kind"] == "call"
    assert data["xrefs"][0]["function"] == "callee"
    assert data["xrefs"][0]["evidence"]["address"] == "0x401000"
    assert data["scanned_sections"] == [".text"]
    assert data["truncated"] is False
    assert data["warnings"] == []
    assert data["evidence"]["source"] == "capstone.xref_scan"


def test_xref_to_dict_omits_absent_function(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "plaindict.bin", bytes.fromhex("e80b000000c3"))
    info = _load(path)

    xref = find_xrefs(path, info).xrefs[0]

    assert isinstance(xref, Xref)
    assert "function" not in xref.to_dict()


def test_zero_max_bytes_is_rejected(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "reject.bin", bytes.fromhex("c3"))
    info = _load(path)

    with pytest.raises(AnalysisError):
        find_xrefs(path, info, max_bytes=0)


def test_unsupported_architecture_returns_warning(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "arch.bin", bytes.fromhex("e80b000000c3"))
    info = replace(_load(path), architecture="unknown", bitness=0)

    result = find_xrefs(path, info)

    assert isinstance(result, XrefResult)
    assert result.xrefs == []
    assert result.scanned_bytes == 0
    assert any("disassembly unavailable" in warning for warning in result.warnings)



# --- indirect (pointer-slot) calls -------------------------------------------
#
# The samples below cover the two statically resolvable indirect call shapes:
# absolute ``call qword ptr [0x...]`` and RIP-relative
# ``call qword ptr [rip +/- 0x...]``. Import entries are appended to
# ``info.imports`` after loading because the synthetic ELF has no dynamic
# symbol table to derive them from.


def _import(name: str, address: int | None) -> ImportInfo:
    """Build a hand-made import entry for indirect-call naming tests."""
    return ImportInfo(name=name, address=address)


def test_rip_relative_call_through_import_slot_is_call_import(tmp_path: Path) -> None:
    # call qword ptr [rip + 0xa] ; ret  ->  slot at 0x401000 + 6 + 0xa
    path = _write_elf64(tmp_path / "rip_import.bin", bytes.fromhex("ff150a000000c3"))
    info = _load(path)
    info.imports.append(_import("Sleep", 0x401010))

    result = find_xrefs(path, info)

    assert len(result.xrefs) == 1
    xref = result.xrefs[0]
    assert (xref.from_address, xref.to_address) == (0x401000, 0x401010)
    assert xref.kind == "call_import"
    assert xref.target_name == "Sleep"
    assert xref.source == "capstone.import_call"
    assert xref.instruction == "call qword ptr [rip + 0xa]"
    assert xref.evidence.source == "capstone.import_call"
    assert xref.evidence.address == 0x401000
    assert xref.evidence.confidence is Confidence.CERTAIN
    assert result.indirect_skipped == 0


def test_absolute_call_through_import_slot_is_call_import(tmp_path: Path) -> None:
    # call qword ptr [0x401000] ; ret
    path = _write_elf64(tmp_path / "abs_import.bin", bytes.fromhex("ff142500104000c3"))
    info = _load(path)
    info.imports.append(_import("Sleep", 0x401000))

    result = find_xrefs(path, info)

    assert len(result.xrefs) == 1
    xref = result.xrefs[0]
    assert (xref.from_address, xref.to_address) == (0x401000, 0x401000)
    assert xref.kind == "call_import"
    assert xref.target_name == "Sleep"
    assert xref.source == "capstone.import_call"
    assert xref.instruction == "call qword ptr [0x401000]"
    assert result.indirect_skipped == 0


def test_rip_relative_negative_displacement_resolves_backwards(tmp_path: Path) -> None:
    # call qword ptr [rip - 0xa] ; ret  ->  slot at 0x401006 - 0xa
    path = _write_elf64(tmp_path / "rip_back.bin", bytes.fromhex("ff15f6ffffffc3"))
    info = _load(path)

    result = find_xrefs(path, info)

    assert len(result.xrefs) == 1
    xref = result.xrefs[0]
    assert xref.to_address == 0x400FFC
    assert xref.kind == "call_indirect"
    assert xref.instruction == "call qword ptr [rip - 0xa]"


def test_unmapped_absolute_slot_is_call_indirect(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "abs_indirect.bin", bytes.fromhex("ff150a000000c3"))
    info = _load(path)
    info.imports.append(_import("Sleep", 0x4010F0))  # different address on purpose

    result = find_xrefs(path, info)

    assert len(result.xrefs) == 1
    xref = result.xrefs[0]
    assert (xref.from_address, xref.to_address) == (0x401000, 0x401010)
    assert xref.kind == "call_indirect"
    assert xref.target_name is None
    assert xref.source == "capstone.indirect_call"
    assert xref.evidence.source == "capstone.indirect_call"
    # The slot address is certain, the callee it points at is not.
    assert xref.evidence.confidence is Confidence.HIGH
    assert result.indirect_skipped == 0


def test_import_without_address_is_not_matched(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "no_addr.bin", bytes.fromhex("ff150a000000c3"))
    info = _load(path)
    info.imports.append(_import("Unresolved", None))

    result = find_xrefs(path, info)

    assert result.xrefs[0].kind == "call_indirect"
    assert result.xrefs[0].target_name is None


def test_register_call_is_skipped_and_counted(tmp_path: Path) -> None:
    # call rax ; ret
    path = _write_elf64(tmp_path / "call_rax.bin", bytes.fromhex("ffd0c3"))
    info = _load(path)

    result = find_xrefs(path, info)

    assert result.xrefs == []
    assert result.indirect_skipped == 1
    assert result.scanned_sections == [".text"]
    assert result.scanned_bytes == 3


def test_indexed_memory_call_is_skipped_and_counted(tmp_path: Path) -> None:
    # call qword ptr [rax + 8] ; call qword ptr [rax] ; ret
    path = _write_elf64(tmp_path / "call_rax8.bin", bytes.fromhex("ff5008ff10c3"))
    info = _load(path)

    result = find_xrefs(path, info)

    assert result.xrefs == []
    assert result.indirect_skipped == 2


def test_multiple_skipped_indirect_calls_are_counted(tmp_path: Path) -> None:
    # call rax x3 ; ret
    path = _write_elf64(tmp_path / "call_rax3.bin", bytes.fromhex("ffd0ffd0ffd0c3"))
    info = _load(path)

    result = find_xrefs(path, info)

    assert result.xrefs == []
    assert result.indirect_skipped == 3


def test_indirect_jump_is_not_counted_as_skipped_call(tmp_path: Path) -> None:
    # jmp qword ptr [rax] ; jmp qword ptr [0x401000] ; jmp rax ; ret
    path = _write_elf64(tmp_path / "jmp_indirect.bin", bytes.fromhex("ff20ff2500104000ffe0c3"))
    info = _load(path)

    result = find_xrefs(path, info)

    assert result.xrefs == []
    assert result.indirect_skipped == 0  # only *calls* are counted


def test_direct_call_is_preferred_over_import_matching(tmp_path: Path) -> None:
    # call 0x401010 with an import registered at the very same address
    path = _write_elf64(tmp_path / "direct_wins.bin", bytes.fromhex("e80b000000c3"))
    info = _load(path)
    info.imports.append(_import("Sleep", 0x401010))

    result = find_xrefs(path, info)

    assert result.xrefs[0].kind == "call"
    assert result.xrefs[0].target_name is None
    assert result.indirect_skipped == 0


def test_to_dict_includes_indirect_skipped_and_target_name(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "dict_indirect.bin", bytes.fromhex("ff150a000000ffd0c3"))
    info = _load(path)
    info.imports.append(_import("Sleep", 0x401010))

    data = find_xrefs(path, info).to_dict()

    assert data["indirect_skipped"] == 1
    assert data["xref_count"] == 1
    assert data["xrefs"][0]["kind"] == "call_import"
    assert data["xrefs"][0]["to_address"] == "0x401010"
    assert data["xrefs"][0]["target_name"] == "Sleep"
    assert data["xrefs"][0]["source"] == "capstone.import_call"


def test_to_dict_omits_absent_target_name(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "dict_notarget.bin", bytes.fromhex("ff150a000000c3"))
    info = _load(path)

    data = find_xrefs(path, info).to_dict()

    assert data["indirect_skipped"] == 0
    assert "target_name" not in data["xrefs"][0]


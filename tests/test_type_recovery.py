"""Struct-field suggestion tests over tiny synthetic ELF64 samples.

Every sample is assembled byte-by-byte with :mod:`struct` inside this module, so
the tests stay self-contained and never depend on a compiler, a linker or a
fixture shared with another module.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis.type_recovery import (
    DEFAULT_MAX_FIELDS,
    MAX_MAX_FIELDS,
    MAX_MAX_INSTRUCTIONS,
    READ,
    STACK_REGISTERS,
    WRITE,
    FieldAccess,
    StructSuggestion,
    parse_memory_operands,
    suggest_struct,
)
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.ir.instruction import IRInstruction

TEXT_VA = 0x401000
DATA_VA = 0x402000

#: ``mov rax, qword ptr [rdi + 0x10]`` -- read of field 0x10 (8 bytes wide).
MOV_RAX_RDI_10 = bytes.fromhex("488b4710")

#: ``mov qword ptr [rdi + 0x18], rbx`` -- write of field 0x18 (8 bytes wide).
MOV_RDI_18_RBX = bytes.fromhex("48895f18")

#: ``mov ecx, dword ptr [rdi + 0x20]`` -- read of field 0x20 (4 bytes wide).
MOV_ECX_RDI_20 = bytes.fromhex("8b4f20")

#: ``mov eax, dword ptr [rdi]`` -- read of field 0 (4 bytes wide).
MOV_EAX_RDI = bytes.fromhex("8b07")

#: ``ret``
RET = bytes.fromhex("c3")

#: The three-field fixture from the task contract.
THREE_FIELDS = MOV_RAX_RDI_10 + MOV_RDI_18_RBX + MOV_ECX_RDI_20 + RET

#: ``mov rax, qword ptr [rbp + 8]`` -- a stack slot, not a struct field.
MOV_RAX_RBP_8 = bytes.fromhex("488b4508")

#: ``mov rax, qword ptr [rsp + 8]`` -- a stack slot, not a struct field.
MOV_RAX_RSP_8 = bytes.fromhex("488b442408")


def _make_elf64(path: Path, code: bytes, data: bytes = b"", entry: int = TEXT_VA) -> Path:
    """Write an ELF64 file with an executable ``.text`` and a ``.data`` section."""
    if not code:
        raise ValueError("code must not be empty")
    shstr = b"\x00.text\x00.data\x00.shstrtab\x00"
    off_text = 0x40
    off_data = off_text + len(code)
    off_shstr = off_data + len(data)
    shoff = off_shstr + len(shstr)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # e_type = ET_EXEC
        62,  # e_machine = EM_X86_64
        1,  # e_version
        entry,  # e_entry
        0,  # e_phoff
        shoff,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        0,  # e_phnum
        64,  # e_shentsize
        4,  # e_shnum: null, .text, .data, .shstrtab
        3,  # e_shstrndx
    )
    null_section = bytes(64)
    text_section = struct.pack("<IIQQQQIIQQ", 1, 1, 6, entry, off_text, len(code), 0, 0, 16, 0)
    data_section = struct.pack("<IIQQQQIIQQ", 7, 1, 3, DATA_VA, off_data, len(data), 0, 0, 8, 0)
    str_section = struct.pack("<IIQQQQIIQQ", 13, 3, 0, 0, off_shstr, len(shstr), 0, 0, 1, 0)
    blob = bytearray(shoff)
    blob[0:64] = header
    blob[off_text:off_text + len(code)] = code
    blob[off_data:off_data + len(data)] = data
    blob[off_shstr:off_shstr + len(shstr)] = shstr
    blob += null_section + text_section + data_section + str_section
    path.write_bytes(bytes(blob))
    return path


def _load(path: Path) -> BinaryInfo:
    """Load a fixture binary with the production loader."""
    return BinaryLoader().load(path)


def _suggest(path: Path, code: bytes, **kwargs: object) -> StructSuggestion:
    """Build a fixture with ``code`` at :data:`TEXT_VA` and inspect it."""
    binary = _make_elf64(path, code)
    info = _load(binary)
    return suggest_struct(binary, info, TEXT_VA, **kwargs)  # type: ignore[arg-type]


def _instruction(mnemonic: str, operands: str, address: int = TEXT_VA) -> IRInstruction:
    """Build an :class:`IRInstruction` carrying only the fields the parser uses."""
    return IRInstruction(
        address=address,
        size=4,
        mnemonic=mnemonic,
        operands=operands,
        raw_bytes=b"\x90" * 4,
        section=".text",
    )


def test_three_fields_recover_offsets_widths_and_directions(tmp_path: Path) -> None:
    result = _suggest(tmp_path / "three.bin", THREE_FIELDS)

    assert isinstance(result, StructSuggestion)
    assert result.address == TEXT_VA
    assert [(f.offset, f.width, f.read_count, f.write_count) for f in result.fields] == [
        (0x10, 8, 1, 0),
        (0x18, 8, 0, 1),
        (0x20, 4, 1, 0),
    ]
    assert result.truncated is False
    assert result.max_fields == DEFAULT_MAX_FIELDS
    assert result.field_count == 3


def test_evidence_is_medium_and_calls_the_fields_heuristic(tmp_path: Path) -> None:
    result = _suggest(tmp_path / "evidence.bin", THREE_FIELDS)

    assert result.evidence.source == "type_recovery.suggestion"
    assert result.evidence.confidence is Confidence.MEDIUM
    assert result.evidence.address == TEXT_VA
    assert "heuristic" in (result.evidence.detail or "")
    for field in result.fields:
        assert field.evidence.source == "type_recovery.memory_operand"
        assert field.evidence.confidence is Confidence.MEDIUM
        assert "heuristic" in (field.evidence.detail or "")


def test_stack_operands_are_excluded_by_default(tmp_path: Path) -> None:
    result = _suggest(tmp_path / "stack_default.bin", MOV_RAX_RDI_10 + MOV_RAX_RBP_8)

    assert [f.offset for f in result.fields] == [0x10]


def test_stack_operands_are_kept_when_requested(tmp_path: Path) -> None:
    result = _suggest(
        tmp_path / "stack_included.bin",
        MOV_RAX_RDI_10 + MOV_RAX_RBP_8 + MOV_RAX_RSP_8,
        include_stack=True,
    )

    assert [f.offset for f in result.fields] == [0x8, 0x10]
    assert result.include_stack is True
    stack_field = result.fields[0]
    assert (stack_field.width, stack_field.read_count, stack_field.write_count) == (8, 2, 0)


def test_zero_offset_operand_is_a_field(tmp_path: Path) -> None:
    result = _suggest(tmp_path / "zero.bin", MOV_EAX_RDI + RET)

    assert [(f.offset, f.width, f.read_count, f.write_count) for f in result.fields] == [
        (0, 4, 1, 0)
    ]


def test_max_fields_caps_and_truncates(tmp_path: Path) -> None:
    result = _suggest(tmp_path / "capped.bin", THREE_FIELDS, max_fields=1)

    assert [(f.offset, f.width) for f in result.fields] == [(0x10, 8)]
    assert result.truncated is True
    assert result.max_fields == 1
    assert result.evidence.extra["field_count"] == 1


def test_invalid_start_address_raises(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "invalid_start.bin", THREE_FIELDS)
    info = _load(binary)

    with pytest.raises(AnalysisError):
        suggest_struct(binary, info, 0x900000)
    with pytest.raises(AnalysisError):
        suggest_struct(binary, info, DATA_VA)  # mapped, but not executable
    with pytest.raises(AnalysisError):
        suggest_struct(binary, info, -1)


def test_out_of_range_budgets_raise(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "budgets.bin", THREE_FIELDS)
    info = _load(binary)

    with pytest.raises(AnalysisError):
        suggest_struct(binary, info, TEXT_VA, max_instructions=0)
    with pytest.raises(AnalysisError):
        suggest_struct(binary, info, TEXT_VA, max_instructions=MAX_MAX_INSTRUCTIONS + 1)
    with pytest.raises(AnalysisError):
        suggest_struct(binary, info, TEXT_VA, max_fields=0)
    with pytest.raises(AnalysisError):
        suggest_struct(binary, info, TEXT_VA, max_fields=MAX_MAX_FIELDS + 1)


def test_parse_memory_operands_reads_a_second_operand() -> None:
    accesses = parse_memory_operands(_instruction("mov", "rax, qword ptr [rdi + 0x10]"))

    assert accesses == (
        FieldAccess(
            offset=0x10,
            width=8,
            direction=READ,
            base_register="rdi",
            address=TEXT_VA,
            instruction="mov rax, qword ptr [rdi + 0x10]",
        ),
    )
    assert accesses[0].to_dict()["offset"] == "0x10"


def test_parse_memory_operands_writes_a_first_operand() -> None:
    accesses = parse_memory_operands(_instruction("mov", "qword ptr [rdi + 0x18], rbx"))

    assert [(a.offset, a.width, a.direction) for a in accesses] == [(0x18, 8, WRITE)]


def test_parse_memory_operands_treats_compare_and_test_as_reads() -> None:
    compare = parse_memory_operands(_instruction("cmp", "dword ptr [rdi], eax"))
    test = parse_memory_operands(_instruction("test", "dword ptr [rdi + 4], eax"))

    assert [(a.offset, a.direction) for a in compare] == [(0, READ)]
    assert [(a.offset, a.direction) for a in test] == [(4, READ)]


def test_parse_memory_operands_skips_indexed_and_lea_operands() -> None:
    assert parse_memory_operands(_instruction("mov", "rcx, qword ptr [rdi + rcx*4]")) == ()
    assert parse_memory_operands(_instruction("lea", "rax, [rdi + 0x10]")) == ()
    assert parse_memory_operands(_instruction("ret", "")) == ()


def test_parse_memory_operands_handles_negative_displacement_and_stack() -> None:
    stack = _instruction("mov", "rax, qword ptr [rbp - 8]")

    assert parse_memory_operands(stack) == ()
    assert [a.offset for a in parse_memory_operands(stack, include_stack=True)] == [-8]


def test_parse_memory_operands_falls_back_to_pointer_width() -> None:
    accesses = parse_memory_operands(_instruction("add", "[rdi + 8], eax"), pointer_width=4)

    assert [(a.offset, a.width) for a in accesses] == [(8, 4)]


def test_stack_register_set_covers_frame_pointers() -> None:
    assert {"rsp", "rbp", "esp", "ebp"} <= STACK_REGISTERS


def test_dominant_width_prefers_the_wider_access_on_a_tie(tmp_path: Path) -> None:
    result = _suggest(
        tmp_path / "tie.bin",
        bytes.fromhex("488b07")  # mov rax, qword ptr [rdi]
        + bytes.fromhex("8b07"),  # mov eax, dword ptr [rdi]
    )

    assert [(f.offset, f.width, f.read_count, f.write_count) for f in result.fields] == [
        (0, 8, 2, 0)
    ]


def test_dominant_width_follows_the_most_frequent_access(tmp_path: Path) -> None:
    result = _suggest(
        tmp_path / "dominant.bin",
        bytes.fromhex("488b07") + bytes.fromhex("8b07") + bytes.fromhex("8b07"),
    )

    assert [(f.offset, f.width, f.read_count) for f in result.fields] == [(0, 4, 3)]


def test_result_is_deterministic_and_json_serializable(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "deterministic.bin", THREE_FIELDS)
    info = _load(binary)
    first = suggest_struct(binary, info, TEXT_VA)
    second = suggest_struct(binary, info, TEXT_VA)

    assert first == second
    payload = first.to_dict()
    assert json.loads(json.dumps(payload))["field_count"] == 3
    assert [field["offset"] for field in payload["fields"]] == ["0x10", "0x18", "0x20"]
    assert payload["evidence"]["confidence"] == Confidence.MEDIUM.value

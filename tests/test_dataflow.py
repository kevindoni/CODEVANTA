"""Definition-use, constant folding and reaching-definition tests.

Every fixture is a tiny ELF64 assembled inside this module and decoded by the
production recursive CFG, so the analysis runs on the same instruction text the
rest of the engine sees. The byte comments next to each fixture spell out the
disassembly, because the expected definition address of a later test is derived
from the length of the previous opcodes.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

import pytest

from codevanta.analysis.dataflow import (
    KIND_ARITHMETIC,
    KIND_CONST,
    KIND_COPY,
    MAX_MAX_INSTRUCTIONS,
    READ,
    WRITE,
    DataFlowSummary,
    Definition,
    Use,
    analyze_dataflow,
)
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError

TEXT_VA = 0x401000
DATA_VA = 0x402000

#: ``mov rax, 5``
MOV_RAX_5 = bytes.fromhex("48c7c005000000")

#: ``mov rax, 7``
MOV_RAX_7 = bytes.fromhex("48c7c007000000")

#: ``mov rdi, 7``
MOV_RDI_7 = bytes.fromhex("48c7c707000000")

#: ``mov rax, rdi``
MOV_RAX_RDI = bytes.fromhex("4889f8")

#: ``mov rbx, rax``
MOV_RBX_RAX = bytes.fromhex("4889c3")

#: ``add rax, 3``
ADD_RAX_3 = bytes.fromhex("4883c003")

#: ``xor rax, rax``
XOR_RAX_RAX = bytes.fromhex("4831c0")

#: ``lea rax, [rip + 0x10]``
LEA_RAX_RIP = bytes.fromhex("488d0510000000")

#: ``mov eax, 5`` -- a 32-bit write that zero-extends into ``rax``.
MOV_EAX_5 = bytes.fromhex("b805000000")

#: ``mov al, 1`` -- a partial write that leaves the upper bytes untouched.
MOV_AL_1 = bytes.fromhex("b001")

#: ``mov qword ptr [rdi], rax`` -- a memory destination, not a register one.
STORE_RDI_RAX = bytes.fromhex("488907")

#: ``call 0x40100c`` -- relative call to the next instruction.
CALL_REL32 = bytes.fromhex("e800000000")

#: ``ret``
RET = bytes.fromhex("c3")


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
    blob[off_text : off_text + len(code)] = code
    blob[off_data : off_data + len(data)] = data
    blob[off_shstr : off_shstr + len(shstr)] = shstr
    blob += null_section + text_section + data_section + str_section
    path.write_bytes(bytes(blob))
    return path


def _binary(path: Path, code: bytes) -> tuple[Path, BinaryInfo]:
    """Write and load one fixture binary."""
    binary = _make_elf64(path, code)
    return binary, BinaryLoader().load(binary)


def _analyze(path: Path, code: bytes, **kwargs: Any) -> DataFlowSummary:
    """Run the analysis on a fixture written for this test."""
    binary, info = _binary(path, code)
    return analyze_dataflow(binary, info, TEXT_VA, **kwargs)


def _definitions_at(summary: DataFlowSummary, address: int) -> list[Definition]:
    """Return the definitions one instruction address produced."""
    return [item for item in summary.definitions if item.address == address]


# ---------------------------------------------------------------------------
# constant definitions
# ---------------------------------------------------------------------------


def test_mov_immediate_is_a_const_definition(tmp_path: Path) -> None:
    summary = _analyze(tmp_path / "mov.bin", MOV_RAX_5 + RET)

    assert len(summary.definitions) == 1
    definition = summary.definitions[0]
    assert definition == Definition(
        address=TEXT_VA, register="rax", kind=KIND_CONST, value=5, source_register=None
    )
    assert summary.constant_registers == {"rax": 5}
    assert summary.address == TEXT_VA
    assert summary.evidence.source == "dataflow.def_use"


def test_a_32bit_write_is_reported_under_the_canonical_register(tmp_path: Path) -> None:
    summary = _analyze(tmp_path / "eax.bin", MOV_EAX_5 + RET)

    assert [(item.register, item.kind, item.value) for item in summary.definitions] == [
        ("rax", KIND_CONST, 5)
    ]
    assert summary.constant_registers == {"rax": 5}


def test_lea_of_a_rip_relative_address_is_a_const(tmp_path: Path) -> None:
    summary = _analyze(tmp_path / "lea.bin", LEA_RAX_RIP + RET)

    definition = summary.definitions[0]
    assert definition.kind == KIND_CONST
    assert definition.value == TEXT_VA + len(LEA_RAX_RIP) + 0x10


def test_a_copy_of_an_unknown_register_carries_no_value(tmp_path: Path) -> None:
    summary = _analyze(tmp_path / "copy.bin", MOV_RAX_RDI + RET)

    definition = summary.definitions[0]
    assert definition.kind == KIND_COPY
    assert definition.source_register == "rdi"
    assert definition.value is None
    assert summary.constant_registers == {}


def test_a_copy_of_a_known_constant_propagates_it(tmp_path: Path) -> None:
    code = MOV_RDI_7 + MOV_RAX_RDI + RET
    summary = _analyze(tmp_path / "copy_known.bin", code)

    assert [item.kind for item in summary.definitions] == [KIND_CONST, KIND_COPY]
    assert summary.definitions[1].source_register == "rdi"
    assert summary.definitions[1].value == 7
    assert summary.reaching_definition[("rdi", TEXT_VA + len(MOV_RDI_7))] == TEXT_VA


# ---------------------------------------------------------------------------
# arithmetic folding
# ---------------------------------------------------------------------------


def test_add_of_a_constant_folds_the_previous_value(tmp_path: Path) -> None:
    code = MOV_RAX_5 + ADD_RAX_3 + RET
    summary = _analyze(tmp_path / "add.bin", code)

    add_address = TEXT_VA + len(MOV_RAX_5)
    folded = _definitions_at(summary, add_address)
    assert len(folded) == 1
    assert folded[0].kind == KIND_ARITHMETIC
    assert folded[0].value == 8
    assert summary.constant_registers == {"rax": 8}
    assert summary.reaching_definition[("rax", add_address)] == TEXT_VA


def test_an_arithmetic_write_without_a_known_value_stays_unknown(tmp_path: Path) -> None:
    summary = _analyze(tmp_path / "add_unknown.bin", ADD_RAX_3 + RET)

    definition = summary.definitions[0]
    assert definition.kind == KIND_ARITHMETIC
    assert definition.value is None
    assert summary.constant_registers == {}


def test_xor_of_a_register_with_itself_is_zero(tmp_path: Path) -> None:
    code = MOV_RAX_5 + XOR_RAX_RAX + RET
    summary = _analyze(tmp_path / "xor.bin", code)

    assert summary.definitions[-1].kind == KIND_ARITHMETIC
    assert summary.definitions[-1].value == 0
    assert summary.constant_registers == {"rax": 0}


def test_a_partial_write_drops_the_constant_but_keeps_the_kind(tmp_path: Path) -> None:
    code = MOV_RAX_5 + MOV_AL_1 + RET
    summary = _analyze(tmp_path / "partial.bin", code)

    partial = _definitions_at(summary, TEXT_VA + len(MOV_RAX_5))
    assert len(partial) == 1
    assert partial[0].register == "rax"
    assert partial[0].kind == KIND_CONST
    assert partial[0].value is None
    assert summary.constant_registers == {}


# ---------------------------------------------------------------------------
# reaching definitions
# ---------------------------------------------------------------------------


def test_a_register_written_twice_keeps_the_later_definition_as_reaching(
    tmp_path: Path,
) -> None:
    code = MOV_RAX_5 + MOV_RAX_7 + MOV_RBX_RAX + RET
    summary = _analyze(tmp_path / "twice.bin", code)

    second = TEXT_VA + len(MOV_RAX_5)
    use = second + len(MOV_RAX_7)
    assert [item.address for item in summary.definitions] == [TEXT_VA, second, use]
    assert summary.reaching_definition[("rax", use)] == second
    assert summary.constant_registers["rax"] == 7


def test_a_use_before_any_definition_has_no_reaching_definition(tmp_path: Path) -> None:
    summary = _analyze(tmp_path / "undefined.bin", MOV_RBX_RAX + RET)

    assert ("rax", TEXT_VA) not in summary.reaching_definition
    assert len(summary.warnings) == 1
    assert "rax" in summary.warnings[0]
    assert f"0x{TEXT_VA:x}" in summary.warnings[0]
    assert Use(TEXT_VA, "rax", READ) in summary.uses
    assert Use(TEXT_VA, "rbx", WRITE) in summary.uses


def test_undefined_reads_are_reported_once_and_bounded(tmp_path: Path) -> None:
    code = (MOV_RBX_RAX * 12) + RET
    summary = _analyze(tmp_path / "many_undefined.bin", code)

    assert len(summary.uses) == 24
    assert len(summary.warnings) == 9
    assert summary.warnings[-1].startswith("4 further read(s)")


def test_a_memory_destination_defines_no_register(tmp_path: Path) -> None:
    summary = _analyze(tmp_path / "store.bin", STORE_RDI_RAX + RET)

    assert summary.definitions == ()
    assert [use.register for use in summary.uses] == ["rax", "rdi"]
    assert all(use.read_or_write == READ for use in summary.uses)
    assert len(summary.warnings) == 2


def test_a_call_invalidates_the_caller_saved_registers(tmp_path: Path) -> None:
    code = MOV_RAX_5 + CALL_REL32 + MOV_RBX_RAX + RET
    summary = _analyze(tmp_path / "call.bin", code)

    use = TEXT_VA + len(MOV_RAX_5) + len(CALL_REL32)
    assert ("rax", use) not in summary.reaching_definition
    assert any("rax" in warning for warning in summary.warnings)
    assert summary.constant_registers == {}


def test_definitions_and_uses_are_in_address_order(tmp_path: Path) -> None:
    code = MOV_RDI_7 + MOV_RAX_RDI + MOV_RBX_RAX + ADD_RAX_3 + RET
    summary = _analyze(tmp_path / "ordered.bin", code)

    assert [item.address for item in summary.definitions] == sorted(
        item.address for item in summary.definitions
    )
    assert [item.address for item in summary.uses] == sorted(
        item.address for item in summary.uses
    )
    assert all(use.read_or_write in {READ, WRITE} for use in summary.uses)


# ---------------------------------------------------------------------------
# serialization, determinism and input validation
# ---------------------------------------------------------------------------


def test_to_dict_is_json_safe(tmp_path: Path) -> None:
    code = MOV_RAX_5 + ADD_RAX_3 + MOV_RBX_RAX + RET
    summary = _analyze(tmp_path / "json.bin", code)

    payload = summary.to_dict()
    text = json.dumps(payload)

    assert json.loads(text) == payload
    assert payload["address"] == f"0x{TEXT_VA:x}"
    assert payload["definition_count"] == len(summary.definitions)
    assert payload["use_count"] == len(summary.uses)
    assert payload["definitions"][0] == {
        "address": f"0x{TEXT_VA:x}",
        "register": "rax",
        "kind": KIND_CONST,
        "value": 5,
        "source_register": None,
    }
    assert payload["constant_registers"] == {"rax": 8, "rbx": 8}
    add_address = TEXT_VA + len(MOV_RAX_5)
    assert payload["reaching_definition"][f"rax@0x{add_address:x}"] == f"0x{TEXT_VA:x}"
    assert isinstance(payload["warnings"], list)
    assert payload["evidence"]["source"] == "dataflow.def_use"


def test_definition_and_use_to_dict_are_json_safe() -> None:
    definition = Definition(
        address=TEXT_VA, register="rax", kind=KIND_CONST, value=5, source_register=None
    )
    use = Use(TEXT_VA, "rax", WRITE)

    payload = {"definition": definition.to_dict(), "use": use.to_dict()}

    assert json.loads(json.dumps(payload)) == payload
    assert payload["definition"]["address"] == f"0x{TEXT_VA:x}"
    assert payload["use"]["read_or_write"] == WRITE


def test_the_same_input_always_produces_the_same_summary(tmp_path: Path) -> None:
    code = MOV_RAX_5 + MOV_RAX_7 + MOV_RBX_RAX + ADD_RAX_3 + RET
    first = _analyze(tmp_path / "first.bin", code)
    second = _analyze(tmp_path / "second.bin", code)

    assert first == second
    assert first.to_dict() == second.to_dict()


def test_an_address_outside_an_executable_section_raises(tmp_path: Path) -> None:
    binary, info = _binary(tmp_path / "bad.bin", MOV_RAX_5 + RET)

    with pytest.raises(AnalysisError):
        analyze_dataflow(binary, info, 0x10)


@pytest.mark.parametrize("address", [-1, "0x401000", 1.5, None, True])
def test_a_bad_address_raises(tmp_path: Path, address: object) -> None:
    binary, info = _binary(tmp_path / "bad_address.bin", MOV_RAX_5 + RET)

    with pytest.raises(AnalysisError):
        analyze_dataflow(binary, info, address)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "options",
    [
        {"max_instructions": 0},
        {"max_instructions": MAX_MAX_INSTRUCTIONS + 1},
        {"max_instructions": "100"},
        {"max_blocks": 0},
        {"max_blocks": True},
    ],
)
def test_a_bad_budget_raises(tmp_path: Path, options: dict[str, object]) -> None:
    binary, info = _binary(tmp_path / "bad_budget.bin", MOV_RAX_5 + RET)

    with pytest.raises(AnalysisError):
        analyze_dataflow(binary, info, TEXT_VA, **options)  # type: ignore[arg-type]


def test_a_small_budget_truncates_and_warns(tmp_path: Path) -> None:
    code = MOV_RAX_5 + ADD_RAX_3 + ADD_RAX_3 + RET
    summary = _analyze(tmp_path / "budget.bin", code, max_instructions=1)

    assert len(summary.definitions) == 1
    assert any("truncated" in warning for warning in summary.warnings)
    assert summary.evidence.extra["truncated"] is True




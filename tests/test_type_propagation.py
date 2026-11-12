"""Argument and return type propagation tests over tiny synthetic samples.

The byte fixtures are assembled inside this module with :mod:`struct` and then
decoded by the production recursive CFG/disassembler, so the inference is tested
against the same instruction text the pseudo-C renderer sees. A handful of tests
pass hand-written ``{"mnemonic", "operands"}`` payloads instead, because that is
the documented input shape and it keeps the 32-bit and MS-x64 ABI cases short.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis.cfg import build_recursive_cfg
from codevanta.analysis.decompile import decompile_function
from codevanta.analysis.type_propagation import (
    C_TYPE_INT32,
    C_TYPE_POINTER_32,
    C_TYPE_POINTER_64,
    C_TYPE_SIZE_T,
    C_TYPE_UINT8,
    C_TYPE_UINT16,
    C_TYPE_UINT32,
    C_TYPE_UINT64,
    C_TYPE_UNKNOWN_32,
    C_TYPE_UNKNOWN_64,
    C_TYPE_VOID,
    C_TYPE_VOID_POINTER,
    INTEGER_C_TYPES,
    POINTER_C_TYPES,
    RULE_RANKS,
    UNKNOWN_C_TYPES,
    ArgumentType,
    ReturnType,
    infer_argument_types,
    infer_return_type,
)
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.ir.instruction import IRInstruction

TEXT_VA = 0x401000
DATA_VA = 0x402000

#: ``mov rax, qword ptr [rdi + 0x10]`` -- a pointer-width load through a0.
LOAD_QWORD = bytes.fromhex("488b4710") + bytes.fromhex("c3")

#: ``mov eax, dword ptr [rdi]`` -- a sub-width load through a0.
LOAD_DWORD = bytes.fromhex("8b07") + bytes.fromhex("c3")

#: ``movzx eax, byte ptr [rdi]`` -- a one-byte load through a0.
LOAD_BYTE = bytes.fromhex("0fb607") + bytes.fromhex("c3")

#: ``add rdi, 1`` -- arithmetic on a0 only.
ARITHMETIC = bytes.fromhex("4883c701") + bytes.fromhex("c3")

#: ``test rdi, rdi; je +5; ret`` then padding and a second ``ret``: a
#: zero-comparison feeding a conditional branch.
ZERO_COMPARE = (
    bytes.fromhex("4885ff")  # 0x401000: test rdi, rdi
    + bytes.fromhex("7405")  # 0x401003: je 0x40100a
    + bytes.fromhex("c3")  # 0x401005: ret
    + bytes.fromhex("90909090")  # 0x401006: padding, never reached
    + bytes.fromhex("c3")  # 0x40100a: ret
)

#: ``mov rax, rsi; ret`` -- rsi is read, rdi (a0) never is.
UNUSED_ARGUMENT = bytes.fromhex("4889f0") + bytes.fromhex("c3")

#: ``mov eax, 1; ret`` -- a 32-bit write to the return register.
MOV_EAX_ONE = bytes.fromhex("b801000000") + bytes.fromhex("c3")

#: ``test rdi, rdi; ret`` -- flags only, the return register is never written.
NO_RETURN_WRITE = bytes.fromhex("4885ff") + bytes.fromhex("c3")

#: ``cmp rdi, rsi; sete al; ret`` -- a boolean left in the return register.
SET_BOOLEAN = bytes.fromhex("4839f7") + bytes.fromhex("0f94c0") + bytes.fromhex("c3")

#: ``add rdi, 1; mov rax, qword ptr [rdi]; ret`` -- two rules for one register.
CONFLICT = bytes.fromhex("4883c701") + bytes.fromhex("488b07") + bytes.fromhex("c3")

#: ``lea rax, [rdi + rsi*4 + 0x10]; ret`` -- an index, never a dereference.
LEA_INDEXED = bytes.fromhex("488d44b710") + bytes.fromhex("c3")

#: ``mov rax, rdi; add rax, rsi; ret`` -- the straight-line two-argument fixture.
STRAIGHT_LINE = bytes.fromhex("4889f8") + bytes.fromhex("4801f0") + bytes.fromhex("c3")


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


def _decode(path: Path, code: bytes) -> list[dict[str, object]]:
    """Decode a fixture with the production recursive CFG."""
    binary, info = _binary(path, code)
    cfg = build_recursive_cfg(binary, info, TEXT_VA)
    return [instruction for block in cfg.blocks for instruction in block.instructions]


# ---------------------------------------------------------------------------
# argument rules
# ---------------------------------------------------------------------------


def test_pointer_dereference_becomes_a_pointer(tmp_path: Path) -> None:
    arguments = infer_argument_types(_decode(tmp_path / "qword.bin", LOAD_QWORD), 8)

    assert len(arguments) == 1
    argument = arguments[0]
    assert argument.register == "rdi"
    assert argument.name == "a0"
    assert argument.c_type == C_TYPE_POINTER_64
    assert argument.confidence is Confidence.MEDIUM
    assert "pointer width" in argument.evidence_note
    assert "qword ptr [rdi + 0x10]" in argument.evidence_note


@pytest.mark.parametrize(
    "code",
    [LOAD_DWORD, LOAD_BYTE],
    ids=["dword-load", "byte-load"],
)
def test_sub_width_load_becomes_a_void_pointer(tmp_path: Path, code: bytes) -> None:
    arguments = infer_argument_types(_decode(tmp_path / "narrow.bin", code), 8)

    assert len(arguments) == 1
    argument = arguments[0]
    assert argument.c_type == C_TYPE_VOID_POINTER
    assert argument.confidence is Confidence.MEDIUM
    assert "narrower than the 8-byte pointer" in argument.evidence_note


def test_pure_arithmetic_becomes_uint64(tmp_path: Path) -> None:
    arguments = infer_argument_types(_decode(tmp_path / "arith.bin", ARITHMETIC), 8)

    assert len(arguments) == 1
    argument = arguments[0]
    assert argument.register == "rdi"
    assert argument.c_type == C_TYPE_UINT64
    assert argument.confidence is Confidence.MEDIUM
    assert "arithmetic" in argument.evidence_note
    assert "add rdi, 1" in argument.evidence_note


def test_comparison_with_zero_becomes_int32(tmp_path: Path) -> None:
    instructions = _decode(tmp_path / "zero.bin", ZERO_COMPARE)

    arguments = infer_argument_types(instructions, 8)

    assert len(arguments) == 1
    argument = arguments[0]
    assert argument.c_type == C_TYPE_INT32
    assert argument.confidence is Confidence.LOW
    assert "compared with zero" in argument.evidence_note
    # The note repeats both halves of the observation, not just the type.
    assert "test rdi, rdi" in argument.evidence_note
    assert "then je" in argument.evidence_note


def test_unused_argument_is_unknown_with_low_confidence(tmp_path: Path) -> None:
    arguments = infer_argument_types(_decode(tmp_path / "unused.bin", UNUSED_ARGUMENT), 8)

    assert [argument.name for argument in arguments] == ["a0", "a1"]
    unused, used = arguments
    assert unused.register == "rdi"
    assert unused.c_type == C_TYPE_UNKNOWN_64
    assert unused.confidence is Confidence.LOW
    assert "never read" in unused.evidence_note
    assert used.register == "rsi"
    assert used.c_type == C_TYPE_UINT64
    assert used.confidence is Confidence.LOW


def test_scaled_index_becomes_size_t(tmp_path: Path) -> None:
    arguments = infer_argument_types(_decode(tmp_path / "lea.bin", LEA_INDEXED), 8)

    assert [argument.c_type for argument in arguments] == [C_TYPE_UINT64, C_TYPE_SIZE_T]
    assert "address arithmetic" in arguments[0].evidence_note
    assert "scaled address index (x4)" in arguments[1].evidence_note


def test_conflicting_evidence_keeps_the_strongest_type(tmp_path: Path) -> None:
    arguments = infer_argument_types(_decode(tmp_path / "conflict.bin", CONFLICT), 8)

    assert len(arguments) == 1
    argument = arguments[0]
    # A pointer use outranks plain arithmetic ...
    assert argument.c_type == C_TYPE_POINTER_64
    # ... and the loser is still named, together with the type it would give.
    assert "pointer width" in argument.evidence_note
    assert "also observed" in argument.evidence_note
    assert "add rdi, 1" in argument.evidence_note
    assert f"-> {C_TYPE_UINT64}" in argument.evidence_note


def test_argument_count_stops_at_the_first_call() -> None:
    instructions = [
        {"mnemonic": "mov", "operands": "rax, rdi"},
        {"mnemonic": "call", "operands": "0x402000"},
        {"mnemonic": "mov", "operands": "rbx, rsi"},
        {"mnemonic": "ret", "operands": ""},
    ]

    arguments = infer_argument_types(instructions, 8)

    assert [argument.name for argument in arguments] == ["a0"]


def test_lower_argument_registers_are_reported_even_when_unread() -> None:
    instructions = [
        {"mnemonic": "mov", "operands": "rax, rdx"},
        {"mnemonic": "ret", "operands": ""},
    ]

    arguments = infer_argument_types(instructions, 8)

    assert [argument.name for argument in arguments] == ["a0", "a1", "a2"]
    assert [argument.register for argument in arguments] == ["rdi", "rsi", "rdx"]
    assert arguments[0].c_type == C_TYPE_UNKNOWN_64
    assert arguments[1].c_type == C_TYPE_UNKNOWN_64
    assert arguments[2].c_type == C_TYPE_UINT64


# ---------------------------------------------------------------------------
# return rules
# ---------------------------------------------------------------------------


def test_return_of_mov_eax_is_uint32(tmp_path: Path) -> None:
    instructions = _decode(tmp_path / "eax.bin", MOV_EAX_ONE)

    result = infer_return_type(instructions, 8)

    assert isinstance(result, ReturnType)
    assert result.c_type == C_TYPE_UINT32
    assert result.confidence is Confidence.MEDIUM
    assert "eax" in result.evidence_note
    assert "mov eax, 1" in result.evidence_note


def test_return_of_mov_rax_is_uint64(tmp_path: Path) -> None:
    result = infer_return_type(_decode(tmp_path / "rax.bin", LOAD_QWORD), 8)

    assert result.c_type == C_TYPE_UINT64
    assert "64-bit" in result.evidence_note


def test_return_without_a_write_to_the_return_register_is_void(tmp_path: Path) -> None:
    result = infer_return_type(_decode(tmp_path / "void.bin", NO_RETURN_WRITE), 8)

    assert result.c_type == C_TYPE_VOID
    assert result.confidence is Confidence.LOW
    assert "no instruction writes rax" in result.evidence_note


def test_return_of_a_direct_call_is_void_and_names_the_callee(tmp_path: Path) -> None:
    instructions = [
        {"mnemonic": "call", "operands": "0x401005"},
        {"mnemonic": "ret", "operands": ""},
    ]

    result = infer_return_type(instructions, 8)

    assert result.c_type == C_TYPE_VOID
    assert "call 0x401005" in result.evidence_note
    assert "callee" in result.evidence_note


def test_return_of_a_setcc_is_int32(tmp_path: Path) -> None:
    result = infer_return_type(_decode(tmp_path / "bool.bin", SET_BOOLEAN), 8)

    assert result.c_type == C_TYPE_INT32
    assert result.confidence is Confidence.MEDIUM
    assert "boolean" in result.evidence_note
    assert "sete al" in result.evidence_note


def test_last_write_before_the_ret_wins() -> None:
    instructions = [
        "mov eax, 1",
        "mov rax, rbx",
        "ret",
        "mov ebx, 2",
    ]

    result = infer_return_type(instructions, 8)

    assert result.c_type == C_TYPE_UINT64
    assert "mov rax, rbx" in result.evidence_note


def test_32bit_binary_uses_the_32bit_return_register() -> None:
    instructions = ["mov eax, 7", "ret"]

    result = infer_return_type(instructions, 4)

    assert result.c_type == C_TYPE_UINT32
    assert "eax" in result.evidence_note


# ---------------------------------------------------------------------------
# ABIs, widths and the public type table
# ---------------------------------------------------------------------------


def test_32bit_binary_emits_32bit_pointer_types() -> None:
    instructions = [
        {"mnemonic": "mov", "operands": "eax, dword ptr [ecx]"},
        {"mnemonic": "ret", "operands": ""},
    ]

    arguments = infer_argument_types(instructions, 4)

    assert len(arguments) == 1
    assert arguments[0].register == "ecx"
    assert arguments[0].c_type == C_TYPE_POINTER_32
    assert "pointer width" in arguments[0].evidence_note
    assert "dword ptr [ecx]" in arguments[0].evidence_note


def test_32bit_binary_uses_the_unknown32_placeholder() -> None:
    instructions = [
        {"mnemonic": "mov", "operands": "eax, edx"},
        {"mnemonic": "ret", "operands": ""},
    ]

    arguments = infer_argument_types(instructions, 4)

    assert [argument.name for argument in arguments] == ["a0", "a1"]
    assert arguments[0].c_type == C_TYPE_UNKNOWN_32


def test_win64_abi_uses_its_own_argument_registers() -> None:
    instructions = [
        {"mnemonic": "mov", "operands": "rax, qword ptr [rcx]"},
        {"mnemonic": "ret", "operands": ""},
    ]

    arguments = infer_argument_types(instructions, 8, abi="win64")

    assert len(arguments) == 1
    assert arguments[0].register == "rcx"
    assert arguments[0].name == "a0"
    assert arguments[0].c_type == C_TYPE_POINTER_64


def test_unknown_abi_raises() -> None:
    with pytest.raises(AnalysisError):
        infer_argument_types(["ret"], 8, abi="pascal")


@pytest.mark.parametrize("width", [0, 3, 16, -8, True])
def test_bad_pointer_width_raises(width: object) -> None:
    with pytest.raises(AnalysisError):
        infer_argument_types(["ret"], width)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError):
        infer_return_type(["ret"], width)  # type: ignore[arg-type]


def test_a_bare_string_is_not_an_instruction_list() -> None:
    with pytest.raises(AnalysisError):
        infer_argument_types("mov rax, rdi", 8)  # type: ignore[arg-type]


def test_ir_instruction_objects_are_accepted() -> None:
    instructions = [
        IRInstruction(0x401000, 4, "mov", "rax, qword ptr [rdi + 8]", b"\x48\x8b\x47\x08"),
        IRInstruction(0x401004, 1, "ret", "", b"\xc3"),
    ]

    arguments = infer_argument_types(instructions, 8)

    assert [argument.c_type for argument in arguments] == [C_TYPE_POINTER_64]
    assert infer_return_type(instructions, 8).c_type == C_TYPE_UINT64


def test_rule_ranking_and_type_tables_are_public() -> None:
    assert RULE_RANKS["pointer_deref"] > RULE_RANKS["narrow_deref"]
    assert RULE_RANKS["narrow_deref"] > RULE_RANKS["index"]
    assert RULE_RANKS["index"] > RULE_RANKS["arithmetic"]
    assert RULE_RANKS["arithmetic"] > RULE_RANKS["copy"]
    assert RULE_RANKS["copy"] > RULE_RANKS["compare"]
    assert INTEGER_C_TYPES[1] == C_TYPE_UINT8
    assert INTEGER_C_TYPES[2] == C_TYPE_UINT16
    assert INTEGER_C_TYPES[4] == C_TYPE_UINT32
    assert INTEGER_C_TYPES[8] == C_TYPE_UINT64
    assert POINTER_C_TYPES[8] == C_TYPE_POINTER_64
    assert POINTER_C_TYPES[4] == C_TYPE_POINTER_32
    assert UNKNOWN_C_TYPES[8] == C_TYPE_UNKNOWN_64
    assert UNKNOWN_C_TYPES[4] == C_TYPE_UNKNOWN_32
    assert C_TYPE_VOID == "void"
    assert C_TYPE_VOID_POINTER == "void *"
    assert C_TYPE_INT32 == "int32_t"
    assert C_TYPE_SIZE_T == "size_t"


# ---------------------------------------------------------------------------
# serialization, determinism and the decompiler integration
# ---------------------------------------------------------------------------


def test_argument_type_to_dict_is_json_safe(tmp_path: Path) -> None:
    argument = infer_argument_types(_decode(tmp_path / "dict.bin", LOAD_QWORD), 8)[0]

    data = argument.to_dict()

    assert set(data) == {"register", "name", "c_type", "evidence_note", "confidence"}
    assert data["confidence"] == "medium"
    assert json.loads(json.dumps(data)) == data


def test_return_type_to_dict_is_json_safe(tmp_path: Path) -> None:
    result = infer_return_type(_decode(tmp_path / "dict_ret.bin", MOV_EAX_ONE), 8)

    data = result.to_dict()

    assert set(data) == {"c_type", "evidence_note", "confidence"}
    assert data["c_type"] == C_TYPE_UINT32
    assert json.loads(json.dumps(data)) == data


def test_results_are_frozen(tmp_path: Path) -> None:
    argument = infer_argument_types(_decode(tmp_path / "frozen.bin", LOAD_QWORD), 8)[0]

    with pytest.raises(AttributeError):
        argument.c_type = "void"  # type: ignore[misc]


def test_inference_is_deterministic(tmp_path: Path) -> None:
    first = _decode(tmp_path / "det_a.bin", CONFLICT)
    second = _decode(tmp_path / "det_b.bin", CONFLICT)

    assert infer_argument_types(first, 8) == infer_argument_types(second, 8)
    assert infer_return_type(first, 8) == infer_return_type(second, 8)
    assert isinstance(infer_argument_types(first, 8)[0], ArgumentType)


def test_decompile_renders_the_inferred_types_in_the_signature(tmp_path: Path) -> None:
    binary, info = _binary(tmp_path / "signature.bin", LOAD_QWORD)

    result = decompile_function(binary, info, TEXT_VA)

    assert f"{C_TYPE_UINT64} sub_401000({C_TYPE_POINTER_64} a0)" in result.body
    # The pointer type is explained in the header, one line per argument.
    assert " * argument a0 (rdi): uint64_t * [medium] - dereferenced at pointer width" in (
        result.body
    )
    assert " * return: uint64_t [medium] - last write to rax" in result.body
    # The rendered statement still uses the a0 name from the operand renderer.
    assert result.lines[0] == "rax = *(u64*)(a0 + 0x10);  /* mov rax, qword ptr [rdi + 0x10] */"


def test_decompile_puts_the_inferred_types_in_evidence_extra(tmp_path: Path) -> None:
    binary, info = _binary(tmp_path / "extra.bin", STRAIGHT_LINE)

    result = decompile_function(binary, info, TEXT_VA)

    extra = result.evidence.extra
    assert [argument["name"] for argument in extra["argument_types"]] == ["a0", "a1"]
    assert {argument["c_type"] for argument in extra["argument_types"]} == {C_TYPE_UINT64}
    assert extra["return_type"]["c_type"] == C_TYPE_UINT64
    assert extra["return_type"]["confidence"] == "medium"
    # JSON carries the same data, so nothing has to parse the pseudo-C.
    payload = json.loads(json.dumps(result.to_dict()))
    assert payload["evidence"]["extra"]["argument_types"][0]["register"] == "rdi"
    assert payload["evidence"]["extra"]["return_type"]["c_type"] == C_TYPE_UINT64


def test_decompile_marks_an_unproven_argument_as_unknown(tmp_path: Path) -> None:
    binary, info = _binary(tmp_path / "unknown.bin", UNUSED_ARGUMENT)

    result = decompile_function(binary, info, TEXT_VA)

    assert f"{C_TYPE_UINT64} sub_401000(unknown64 a0, uint64_t a1)" in result.body
    first = result.evidence.extra["argument_types"][0]
    assert first["c_type"] == C_TYPE_UNKNOWN_64
    assert first["confidence"] == "low"
    assert "never read" in first["evidence_note"]


def test_decompile_renders_void_for_a_function_without_a_return_value(tmp_path: Path) -> None:
    binary, info = _binary(tmp_path / "no_return.bin", ZERO_COMPARE)

    result = decompile_function(binary, info, TEXT_VA)

    assert f"{C_TYPE_VOID} sub_401000({C_TYPE_INT32} a0)" in result.body
    assert result.evidence.extra["return_type"]["c_type"] == C_TYPE_VOID
    assert result.evidence.extra["return_type"]["confidence"] == "low"
    assert result.evidence.extra["argument_types"][0]["c_type"] == C_TYPE_INT32

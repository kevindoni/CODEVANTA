"""Struct-field suggestion tests over tiny synthetic ELF64 samples.

Every sample is assembled byte-by-byte with :mod:`struct` inside this module, so
the tests stay self-contained and never depend on a compiler, a linker or a
fixture shared with another module.
"""

from __future__ import annotations

import json
import struct
import warnings
from collections.abc import Sequence
from pathlib import Path

import pytest

from codevanta.analysis.type_recovery import (
    DEFAULT_MAX_FIELDS,
    MAX_MAX_FIELDS,
    MAX_MAX_INSTRUCTIONS,
    MAX_MERGED_WINDOWS,
    READ,
    STACK_REGISTERS,
    WRITE,
    ArrayGroup,
    FieldAccess,
    SignednessConflictWarning,
    StructSuggestion,
    WidthConflictWarning,
    WindowOverlapWarning,
    parse_memory_operands,
    suggest_struct,
    suggest_structs,
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

#: ``mov rcx, qword ptr [rdi + 0x8]`` -- read of field 8 (8 bytes wide).
MOV_RCX_RDI_8 = bytes.fromhex("488b4f08")

#: ``mov rcx, qword ptr [rdi + 0x18]`` -- read of field 0x18 (8 bytes wide).
MOV_RCX_RDI_18 = bytes.fromhex("488b4f18")

#: ``mov rcx, qword ptr [rdi + 0x20]`` -- read of field 0x20 (8 bytes wide).
MOV_RCX_RDI_20 = bytes.fromhex("488b4f20")

#: ``mov eax, dword ptr [rdi + 0x14]`` -- read of field 0x14 (4 bytes wide).
MOV_EAX_RDI_14 = bytes.fromhex("8b4714")

#: ``mov ecx, dword ptr [rdi + 0x30]`` -- read of field 0x30 (4 bytes wide).
MOV_ECX_RDI_30 = bytes.fromhex("8b4f30")

#: ``mov ecx, dword ptr [rdi + 0x38]`` -- read of field 0x38 (4 bytes wide).
MOV_ECX_RDI_38 = bytes.fromhex("8b4f38")

#: ``mov ecx, dword ptr [rdi + 0x40]`` -- read of field 0x40 (4 bytes wide).
MOV_ECX_RDI_40 = bytes.fromhex("8b4f40")

#: Three 8-byte fields at 0x10/0x18/0x20: one evenly spaced run of length 3.
ARRAY_THREE_QWORDS = MOV_RAX_RDI_10 + MOV_RDI_18_RBX + MOV_RCX_RDI_20 + RET

#: Two 8-byte fields 4 bytes apart: enough for an alignment, never for a run.
TWO_FIELDS_0X10_0X14 = MOV_RAX_RDI_10 + MOV_EAX_RDI_14 + RET

#: A qword run at 0x8/0x10/0x18, a gap, then a dword run at 0x30/0x38/0x40.
TWO_ARRAY_RUNS = (
    MOV_RCX_RDI_8
    + MOV_RAX_RDI_10
    + MOV_RCX_RDI_18
    + MOV_ECX_RDI_30
    + MOV_ECX_RDI_38
    + MOV_ECX_RDI_40
    + RET
)

#: ``movsx rax, word ptr [rdi + 0x10]`` -- sign-extending read of field 0x10.
MOVSX_RAX_RDI_10 = bytes.fromhex("480fbf4710")

#: ``movsxd rax, dword ptr [rdi + 0x10]`` -- sign-extending read of field 0x10.
MOVSXD_RAX_RDI_10 = bytes.fromhex("48634710")

#: ``movzx eax, word ptr [rdi + 0x10]`` -- zero-extending read of field 0x10.
MOVZX_EAX_RDI_10 = bytes.fromhex("0fb74710")

#: ``movzx eax, word ptr [rdi + 0x18]`` -- zero-extending read of field 0x18.
MOVZX_EAX_RDI_18 = bytes.fromhex("0fb74718")

#: ``sar dword ptr [rdi + 4], 1`` -- signed read-modify-write of field 4.
SAR_RDI_4 = bytes.fromhex("c17f0401")

#: ``shr dword ptr [rdi + 8], 1`` -- unsigned read-modify-write of field 8.
SHR_RDI_8 = bytes.fromhex("d16f08")

#: ``idiv qword ptr [rdi + 0x10]`` -- signed division by field 0x10.
IDIV_RDI_10 = bytes.fromhex("48f77f10")

#: ``mul qword ptr [rdi + 0x18]`` -- unsigned multiplication by field 0x18.
MUL_RDI_18 = bytes.fromhex("48f76718")

#: ``cqo`` -- a signedness mnemonic with only implicit operands, no memory access.
CQO = bytes.fromhex("4899")

#: ``mov ecx, dword ptr [rdi + 0x10]`` -- read of field 0x10 (4 bytes wide).
MOV_ECX_RDI_10 = bytes.fromhex("8b4f10")

#: One offset read as a signed *and* as an unsigned value: a contradiction.
MIXED_SIGNEDNESS = MOVSX_RAX_RDI_10 + MOVZX_EAX_RDI_10 + RET


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


#: Instruction budget used for merged-window fixtures. Every window is one memory
#: access plus ``ret``, i.e. exactly two instructions, so a two-instruction sweep
#: can never decode into the next window's bytes.
WINDOW_INSTRUCTIONS = 2


def _suggest_windows(
    path: Path, windows: Sequence[bytes], **kwargs: object
) -> StructSuggestion:
    """Place ``windows`` back to back in ``.text`` and merge one suggestion each.

    Each window is one memory access followed by ``ret``; the default budget of
    :data:`WINDOW_INSTRUCTIONS` keeps every sweep inside its own window.
    """
    binary = _make_elf64(path, b"".join(windows))
    info = _load(binary)
    addresses: list[int] = []
    cursor = TEXT_VA
    for window in windows:
        addresses.append(cursor)
        cursor += len(window)
    kwargs.setdefault("max_instructions", WINDOW_INSTRUCTIONS)
    return suggest_structs(binary, info, addresses, **kwargs)  # type: ignore[arg-type]


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


def test_three_evenly_spaced_qwords_yield_alignment_and_one_array_group(
    tmp_path: Path,
) -> None:
    result = _suggest(tmp_path / "array.bin", ARRAY_THREE_QWORDS)

    assert [f.offset for f in result.fields] == [0x10, 0x18, 0x20]
    assert result.alignment == 8
    assert len(result.array_groups) == 1
    group = result.array_groups[0]
    assert isinstance(group, ArrayGroup)
    assert (group.offset, group.stride, group.count, group.width) == (0x10, 8, 3, 8)
    assert group.span == 0x18
    assert group.evidence.confidence is Confidence.MEDIUM
    assert group.evidence.source == "type_recovery.array_run"
    assert "heuristic" in (group.evidence.detail or "")
    assert group.evidence.extra["stride"] == 8


def test_two_fields_give_an_alignment_but_no_array_group(tmp_path: Path) -> None:
    result = _suggest(tmp_path / "two_fields.bin", TWO_FIELDS_0X10_0X14)

    assert [f.offset for f in result.fields] == [0x10, 0x14]
    assert result.alignment == 4
    assert result.array_groups == ()


def test_a_single_offset_has_no_alignment(tmp_path: Path) -> None:
    non_zero = _suggest(tmp_path / "single_non_zero.bin", MOV_RAX_RDI_10 + RET)
    only_zero = _suggest(tmp_path / "single_zero.bin", MOV_EAX_RDI + RET)

    assert [f.offset for f in non_zero.fields] == [0x10]
    assert non_zero.alignment is None
    assert [f.offset for f in only_zero.fields] == [0]
    assert only_zero.alignment is None
    assert non_zero.array_groups == ()
    assert only_zero.array_groups == ()


def test_alignment_ignores_offset_zero(tmp_path: Path) -> None:
    result = _suggest(
        tmp_path / "zero_ignored.bin",
        MOV_EAX_RDI + MOV_RAX_RDI_10 + MOV_RCX_RDI_20 + RET,
    )

    assert [f.offset for f in result.fields] == [0, 0x10, 0x20]
    assert result.alignment == 16
    # The two remaining qwords are 0x10 apart, i.e. only a run of two.
    assert result.array_groups == ()


def test_array_groups_are_maximal_and_split_on_width(tmp_path: Path) -> None:
    result = _suggest(tmp_path / "two_runs.bin", TWO_ARRAY_RUNS)

    assert [f.offset for f in result.fields] == [0x8, 0x10, 0x18, 0x30, 0x38, 0x40]
    assert [
        (group.offset, group.stride, group.count, group.width)
        for group in result.array_groups
    ] == [(0x8, 8, 3, 8), (0x30, 8, 3, 4)]
    assert result.alignment == 8


def test_to_dict_reports_alignment_and_array_groups(tmp_path: Path) -> None:
    arrays = _suggest(tmp_path / "array_json.bin", ARRAY_THREE_QWORDS).to_dict()
    mixed = _suggest(tmp_path / "mixed_json.bin", THREE_FIELDS).to_dict()

    assert {"alignment", "array_groups"} <= set(arrays)
    assert arrays["alignment"] == 8
    assert arrays["array_groups"][0]["offset"] == "0x10"
    assert arrays["array_groups"][0]["stride"] == 8
    assert arrays["array_groups"][0]["count"] == 3
    assert arrays["array_groups"][0]["width"] == 8
    assert arrays["array_groups"][0]["evidence"]["confidence"] == Confidence.MEDIUM.value
    # 0x10/0x18/0x20 mix 8- and 4-byte widths, so no run is claimed.
    assert mixed["alignment"] == 8
    assert mixed["array_groups"] == []
    assert json.loads(json.dumps(arrays))["array_groups"][0]["count"] == 3


def test_alignment_and_array_groups_are_deterministic(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "layout_deterministic.bin", TWO_ARRAY_RUNS)
    info = _load(binary)

    first = suggest_struct(binary, info, TEXT_VA)
    second = suggest_struct(binary, info, TEXT_VA)

    assert first == second
    assert first.alignment == second.alignment == 8
    assert first.array_groups == second.array_groups


# ---- Signedness classification ---------------------------------------------


def test_sign_extending_read_marks_the_field_signed(tmp_path: Path) -> None:
    result = _suggest(tmp_path / "movsx.bin", MOVSX_RAX_RDI_10 + RET)

    assert [(f.offset, f.width, f.signed) for f in result.fields] == [(0x10, 2, True)]
    assert result.fields[0].evidence.extra["signed"] is True


def test_zero_extending_read_marks_the_field_unsigned(tmp_path: Path) -> None:
    result = _suggest(tmp_path / "movzx.bin", MOVZX_EAX_RDI_18 + RET)

    assert [(f.offset, f.width, f.signed) for f in result.fields] == [(0x18, 2, False)]
    assert result.fields[0].evidence.extra["signed"] is False


def test_a_plain_move_carries_no_signedness_hint(tmp_path: Path) -> None:
    result = _suggest(tmp_path / "plain_move.bin", MOV_RCX_RDI_20 + RET)

    assert [(f.offset, f.width, f.signed) for f in result.fields] == [(0x20, 8, None)]


def test_signed_and_unsigned_arithmetic_classify_their_operands(tmp_path: Path) -> None:
    result = _suggest(
        tmp_path / "arithmetic.bin",
        MOVSXD_RAX_RDI_10
        + SAR_RDI_4
        + IDIV_RDI_10
        + SHR_RDI_8
        + MUL_RDI_18
        + RET,
    )

    assert [(f.offset, f.signed) for f in result.fields] == [
        (4, True),
        (8, False),
        (0x10, True),
        (0x18, False),
    ]


def test_implicit_operand_mnemonics_never_add_a_field(tmp_path: Path) -> None:
    # ``cqo`` is a signedness mnemonic, but it only widens a register, so it must
    # not turn the unrelated ``mov`` access at offset 0 into a signed field.
    result = _suggest(tmp_path / "cqo.bin", CQO + MOV_EAX_RDI + RET)

    assert [(f.offset, f.signed) for f in result.fields] == [(0, None)]


def test_mixed_signedness_at_one_offset_warns_and_reports_unknown(
    tmp_path: Path,
) -> None:
    binary = _make_elf64(tmp_path / "mixed_signedness.bin", MIXED_SIGNEDNESS)
    info = _load(binary)

    with pytest.warns(SignednessConflictWarning, match="0x10"):
        result = suggest_struct(binary, info, TEXT_VA)

    assert [(f.offset, f.width, f.signed) for f in result.fields] == [(0x10, 2, None)]


def test_consistent_and_absent_hints_do_not_warn(
    tmp_path: Path, recwarn: pytest.WarningsRecorder
) -> None:
    # A plain field (no hint) and a field with two agreeing hints: neither is a
    # contradiction, so nothing may be reported.
    result = _suggest(
        tmp_path / "quiet.bin",
        MOVSX_RAX_RDI_10 + MOVSXD_RAX_RDI_10 + MOV_RCX_RDI_20 + RET,
    )

    assert [(f.offset, f.signed) for f in result.fields] == [(0x10, True), (0x20, None)]
    assert [w for w in recwarn.list if isinstance(w.message, SignednessConflictWarning)] == []


def test_to_dict_reports_signedness_only_when_it_is_known(tmp_path: Path) -> None:
    signed = _suggest(tmp_path / "signed_json.bin", MOVSX_RAX_RDI_10 + RET).to_dict()
    unsigned = _suggest(tmp_path / "unsigned_json.bin", MOVZX_EAX_RDI_18 + RET).to_dict()
    unknown = _suggest(tmp_path / "unknown_json.bin", THREE_FIELDS).to_dict()

    assert signed["fields"][0]["signed"] is True
    assert unsigned["fields"][0]["signed"] is False
    # An unknown hint is an absent key, never ``"signed": null``.
    assert all("signed" not in field for field in unknown["fields"])
    assert json.loads(json.dumps(signed))["fields"][0]["signed"] is True


def test_to_dict_omits_signed_when_the_hints_contradict(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "contradiction_json.bin", MIXED_SIGNEDNESS)
    info = _load(binary)

    with pytest.warns(SignednessConflictWarning):
        payload = suggest_struct(binary, info, TEXT_VA).to_dict()

    assert "signed" not in payload["fields"][0]


def test_field_evidence_names_the_signedness_hint(tmp_path: Path) -> None:
    result = _suggest(
        tmp_path / "signedness_evidence.bin", MOVSX_RAX_RDI_10 + MOV_RCX_RDI_20 + RET
    )

    assert "signedness signed" in (result.fields[0].evidence.detail or "")
    assert "signedness unknown" in (result.fields[1].evidence.detail or "")
    assert "heuristic" in (result.fields[0].evidence.detail or "")


def test_signedness_is_deterministic(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "signedness_deterministic.bin", MIXED_SIGNEDNESS)
    info = _load(binary)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SignednessConflictWarning)
        first = suggest_struct(binary, info, TEXT_VA)
        second = suggest_struct(binary, info, TEXT_VA)

    assert first == second
    assert first.fields[0].signed is None


def test_signed_hint_covers_imul(tmp_path: Path) -> None:
    # imul rax, qword ptr [rdi + 0x20]: signed multiplication of field 0x20.
    result = _suggest(tmp_path / "imul.bin", bytes.fromhex("480faf4720") + RET)

    assert [(f.offset, f.signed) for f in result.fields] == [(0x20, True)]



# ---- Merged window suggestions ----------------------------------------------


def test_merged_widths_keep_the_widest_and_warn(tmp_path: Path) -> None:
    with pytest.warns(WidthConflictWarning) as record:
        result = _suggest_windows(
            tmp_path / "merged_widths.bin",
            [MOV_ECX_RDI_10 + RET, MOV_RAX_RDI_10 + RET],
        )

    assert [(f.offset, f.width, f.read_count) for f in result.fields] == [(0x10, 8, 2)]
    assert len(record) == 1
    message = str(record[0].message)
    assert "0x10" in message
    assert "4-byte" in message and "8-byte" in message


def test_same_width_windows_merge_silently(
    tmp_path: Path, recwarn: pytest.WarningsRecorder
) -> None:
    result = _suggest_windows(
        tmp_path / "merged_same_width.bin",
        [MOV_RAX_RDI_10 + RET, MOV_RAX_RDI_10 + RET],
    )

    assert [(f.offset, f.width, f.read_count, f.write_count) for f in result.fields] == [
        (0x10, 8, 2, 0)
    ]
    conflicts = [
        warning
        for warning in recwarn.list
        if isinstance(warning.message, (SignednessConflictWarning, WidthConflictWarning))
    ]
    assert conflicts == []


def test_signed_and_unsigned_windows_conflict(tmp_path: Path) -> None:
    with pytest.warns(SignednessConflictWarning) as record:
        result = _suggest_windows(
            tmp_path / "merged_signedness.bin",
            [MOVSX_RAX_RDI_10 + RET, MOVZX_EAX_RDI_10 + RET],
        )

    # Both windows agree on 2 bytes, so only the hint is in dispute.
    assert [(f.offset, f.width, f.signed) for f in result.fields] == [(0x10, 2, None)]
    assert len(record) == 1
    assert "0x10" in str(record[0].message)


def test_alignment_is_recomputed_from_the_merged_offsets(tmp_path: Path) -> None:
    single = _suggest(tmp_path / "merged_alignment_window.bin", MOV_RAX_RDI_10 + RET)
    merged = _suggest_windows(
        tmp_path / "merged_alignment.bin",
        [MOV_RAX_RDI_10 + RET, MOV_EAX_RDI_14 + RET],
    )

    # Neither window sees two offsets, but the merge does.
    assert single.alignment is None
    assert [f.offset for f in merged.fields] == [0x10, 0x14]
    assert merged.alignment == 4


def test_array_groups_are_recomputed_from_the_merged_fields(tmp_path: Path) -> None:
    merged = _suggest_windows(
        tmp_path / "merged_array.bin",
        [MOV_RAX_RDI_10 + RET, MOV_RDI_18_RBX + RET, MOV_RCX_RDI_20 + RET],
    )

    assert [f.offset for f in merged.fields] == [0x10, 0x18, 0x20]
    assert [
        (group.offset, group.stride, group.count, group.width)
        for group in merged.array_groups
    ] == [(0x10, 8, 3, 8)]
    assert merged.alignment == 8




def test_merged_evidence_lists_every_window(tmp_path: Path) -> None:
    first_code = MOV_RAX_RDI_10 + RET
    binary = _make_elf64(tmp_path / "merged_evidence.bin", first_code + MOV_EAX_RDI_14 + RET)
    info = _load(binary)
    second = TEXT_VA + len(first_code)

    result = suggest_structs(
        binary, info, [second, TEXT_VA], max_instructions=WINDOW_INSTRUCTIONS
    )
    extra = result.evidence.extra

    assert result.evidence.source == "type_recovery.merged_suggestion"
    assert result.evidence.confidence is Confidence.MEDIUM
    assert "heuristic" in (result.evidence.detail or "")
    # The lowest address is the identity of the merge, whatever the caller order.
    assert result.address == TEXT_VA
    assert result.evidence.address == TEXT_VA
    assert extra["window_count"] == 2
    assert extra["windows"] == [f"0x{TEXT_VA:x}", f"0x{second:x}"]
    assert extra["instruction_count"] == result.instruction_count == 4
    assert extra["memory_access_count"] == 2
    assert extra["max_windows"] == MAX_MERGED_WINDOWS
    assert extra["max_fields"] == result.max_fields == DEFAULT_MAX_FIELDS
    assert extra["alignment"] == result.alignment


def test_merged_suggestion_is_order_independent_and_json_serializable(
    tmp_path: Path,
) -> None:
    first_code = MOV_RAX_RDI_10 + RET
    binary = _make_elf64(tmp_path / "merged_order.bin", first_code + MOV_EAX_RDI_14 + RET)
    info = _load(binary)
    second = TEXT_VA + len(first_code)

    forward = suggest_structs(binary, info, [TEXT_VA, second], max_instructions=2)
    backward = suggest_structs(binary, info, [second, TEXT_VA], max_instructions=2)

    assert forward == backward
    payload = forward.to_dict()
    assert payload["address"] == f"0x{TEXT_VA:x}"
    assert json.loads(json.dumps(payload))["evidence"]["extra"]["window_count"] == 2
    assert [field["offset"] for field in payload["fields"]] == ["0x10", "0x14"]


def test_single_window_merge_keeps_the_per_window_fields(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "merged_single.bin", THREE_FIELDS)
    info = _load(binary)

    merged = suggest_structs(binary, info, [TEXT_VA])
    single = suggest_struct(binary, info, TEXT_VA)

    assert [
        (f.offset, f.width, f.read_count, f.write_count, f.signed) for f in merged.fields
    ] == [(f.offset, f.width, f.read_count, f.write_count, f.signed) for f in single.fields]
    assert merged.alignment == single.alignment
    assert merged.array_groups == single.array_groups
    assert merged.evidence.extra["window_count"] == 1


def test_merged_field_evidence_names_the_merge(tmp_path: Path) -> None:
    with pytest.warns(WidthConflictWarning):
        result = _suggest_windows(
            tmp_path / "merged_field_evidence.bin",
            [MOV_ECX_RDI_10 + RET, MOV_RAX_RDI_10 + RET],
        )

    field = result.fields[0]
    assert field.evidence.source == "type_recovery.merged_field"
    assert field.evidence.confidence is Confidence.MEDIUM
    assert field.evidence.extra["window_count"] == 2
    assert field.evidence.extra["widths"] == [4, 8]
    assert "heuristic" in (field.evidence.detail or "")
    assert field.first_access == TEXT_VA


def test_duplicate_window_addresses_raise(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "merged_duplicate.bin", MOV_RAX_RDI_10 + RET)
    info = _load(binary)

    with pytest.raises(AnalysisError, match="more than once"):
        suggest_structs(binary, info, [TEXT_VA, TEXT_VA])


def test_empty_window_addresses_raise(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "merged_empty.bin", MOV_RAX_RDI_10 + RET)
    info = _load(binary)

    with pytest.raises(AnalysisError, match="at least one"):
        suggest_structs(binary, info, [])


def test_invalid_window_address_entry_raises(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "merged_bad_entry.bin", MOV_RAX_RDI_10 + RET)
    info = _load(binary)

    with pytest.raises(AnalysisError, match="address must be an integer"):
        suggest_structs(binary, info, [TEXT_VA, "0x401004"])  # type: ignore[list-item]
    with pytest.raises(AnalysisError, match="non-negative"):
        suggest_structs(binary, info, [-1])


def test_window_count_is_bounded(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "merged_bounds.bin", MOV_RAX_RDI_10 + RET)
    info = _load(binary)
    too_many = list(range(TEXT_VA, TEXT_VA + MAX_MERGED_WINDOWS + 1))

    with pytest.raises(AnalysisError, match="too many window addresses"):
        suggest_structs(binary, info, too_many)
    with pytest.raises(AnalysisError, match="too many window addresses"):
        suggest_structs(binary, info, [TEXT_VA, TEXT_VA + 5], max_windows=1)
    with pytest.raises(AnalysisError, match="max_windows must be"):
        suggest_structs(binary, info, [TEXT_VA], max_windows=0)
    with pytest.raises(AnalysisError, match="max_windows too large"):
        suggest_structs(binary, info, [TEXT_VA], max_windows=MAX_MERGED_WINDOWS + 1)


def test_merged_signedness_conflict_inside_one_window_survives_the_merge(
    tmp_path: Path,
) -> None:
    # Window A contradicts itself at 0x10; window B only hints signed. The merge
    # must not let B's single hint hide A's contradiction.
    with pytest.warns(SignednessConflictWarning):
        result = _suggest_windows(
            tmp_path / "conflict.bin",
            [MOVSX_RAX_RDI_10 + MOVZX_EAX_RDI_10 + RET, MOVSX_RAX_RDI_10 + RET],
            max_instructions=3,
        )

    field = next(field for field in result.fields if field.offset == 0x10)
    assert field.signed is None
    assert field.evidence.extra["signed_conflict"] is True


def test_merged_truncated_reports_a_window_that_hit_its_cap(tmp_path: Path) -> None:
    # 70 distinct offsets exceed the 64-offset cap, so the window drops six of them
    # and the merged suggestion must say so instead of reporting a lossless merge.
    code = bytearray()
    for index in range(1, 71):
        offset = 0x10 * index
        if offset <= 0x7F:
            code += bytes.fromhex("488b47") + bytes([offset])
        else:
            code += bytes.fromhex("488b87") + offset.to_bytes(4, "little")
    code += RET
    binary = _make_elf64(tmp_path / "capped.bin", bytes(code))
    info = _load(binary)

    with pytest.warns(WindowOverlapWarning):
        merged = suggest_structs(binary, info, [TEXT_VA, TEXT_VA + len(code) - 1])

    assert merged.truncated is True
    assert merged.evidence.extra["window_truncated"] == [hex(TEXT_VA)]


def test_merged_windows_warn_when_their_decodes_overlap(tmp_path: Path) -> None:
    code = MOV_RCX_RDI_20 + MOV_RCX_RDI_20 + RET
    binary = _make_elf64(tmp_path / "overlap.bin", code)
    info = _load(binary)

    with pytest.warns(WindowOverlapWarning):
        result = suggest_structs(binary, info, [TEXT_VA, TEXT_VA + 4])

    assert result.field_count >= 1


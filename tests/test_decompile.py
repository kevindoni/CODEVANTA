"""Pseudo-C decompiler tests over tiny synthetic ELF64 samples.

Every sample is assembled byte-by-byte with :mod:`struct` inside this module, so
the tests stay self-contained and never depend on a compiler, a linker or a
fixture shared with another module.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis.decompile import (
    DEFAULT_MAX_BLOCKS,
    DEFAULT_MAX_INSTRUCTIONS,
    MAX_MAX_BLOCKS,
    MAX_MAX_INSTRUCTIONS,
    CallSite,
    PseudoFunction,
    decompile_function,
)
from codevanta.core.loader import BinaryInfo, BinaryLoader, ImportInfo, SymbolInfo
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence

TEXT_VA = 0x401000
DATA_VA = 0x402000

#: ``mov rax, rdi`` -- reads argument register 0.
MOV_RAX_RDI = bytes.fromhex("4889f8")

#: ``add rax, rsi`` -- reads argument register 1.
ADD_RAX_RSI = bytes.fromhex("4801f0")

#: ``mov rax, qword ptr [rdi + 0x10]`` -- an argument-relative load.
MOV_RAX_RDI_10 = bytes.fromhex("488b4710")

#: ``mov rax, qword ptr [rbp - 8]`` -- a frame slot, not an argument.
MOV_RAX_RBP_8 = bytes.fromhex("488b45f8")

#: ``ret``
RET = bytes.fromhex("c3")

#: ``mov rax, rdi; add rax, rsi; ret`` -- three straight-line instructions.
STRAIGHT_LINE = MOV_RAX_RDI + ADD_RAX_RSI + RET

#: ``cmp rdi, rsi; je +0xb; mov eax, 1; jmp +9`` then four pad bytes, the else
#: body and the join point: a classic diamond.
DIAMOND = (
    bytes.fromhex("4839f7")  # 0x401000: cmp rdi, rsi
    + bytes.fromhex("740b")  # 0x401003: je 0x401010
    + bytes.fromhex("b801000000")  # 0x401005: mov eax, 1
    + bytes.fromhex("eb09")  # 0x40100a: jmp 0x401015
    + bytes.fromhex("90909090")  # 0x40100c: padding, never reached
    + bytes.fromhex("b802000000")  # 0x401010: mov eax, 2
    + RET  # 0x401015: ret
)

#: ``mov eax, 0; add rax, 1; cmp rax, 0xa; jl -0xa; ret`` -- a counted loop.
LOOP = (
    bytes.fromhex("b800000000")  # 0x401000: mov eax, 0
    + bytes.fromhex("4883c001")  # 0x401005: add rax, 1
    + bytes.fromhex("4883f80a")  # 0x401009: cmp rax, 0xa
    + bytes.fromhex("7cf6")  # 0x40100d: jl 0x401005
    + RET  # 0x40100f: ret
)

#: ``call rax; ret`` -- an indirect call through a register.
INDIRECT_CALL = bytes.fromhex("ffd0") + RET

#: ``call 0x401005; ret`` -- a direct call to the following instruction.
DIRECT_CALL = bytes.fromhex("e800000000") + RET

#: ``add rax, 1`` repeated: a function with no terminator for a long way.
LONG_FUNCTION = bytes.fromhex("4883c001") * 20 + RET

#: ``lea rax, [rdi + rsi*4 + 0x10]`` -- an indexed address, no dereference.
LEA_INDEXED = bytes.fromhex("488d44b710") + RET

#: ``mov rax, qword ptr [rip + 0x100]`` -- a RIP-relative load of a global.
RIP_RELATIVE = bytes.fromhex("488b0500010000") + RET

#: ``mov rax, qword ptr fs:[0x30]`` -- an operand shape the renderer does not model.
SEGMENT_OPERAND = bytes.fromhex("64488b042530000000") + RET

#: One of every statement shape the renderer emits.
STATEMENT_SHAPES = (
    bytes.fromhex("31c0")  # 0x401000: xor eax, eax
    + bytes.fromhex("48ffc0")  # 0x401002: inc rax
    + bytes.fromhex("48f7d8")  # 0x401005: neg rax
    + bytes.fromhex("486bc604")  # 0x401008: imul rax, rsi, 4
    + bytes.fromhex("48c1e002")  # 0x40100c: shl rax, 2
    + bytes.fromhex("48897718")  # 0x401010: mov qword ptr [rdi + 0x18], rsi
    + RET  # 0x401013: ret
)

#: ``test rdi, rdi; je 0x402000`` -- a branch into a non-executable section.
BRANCH_OUT_OF_CODE = bytes.fromhex("4885ff") + bytes.fromhex("0f84f70f0000") + RET

#: ``je +5; ret; ...; ret`` -- a branch whose flags were set before the sweep.
NO_COMPARISON = (
    bytes.fromhex("7405")  # 0x401000: je 0x401007
    + RET  # 0x401002: ret
    + bytes.fromhex("90") * 4  # 0x401003: padding
    + RET  # 0x401007: ret
)

#: ``cmp rdi, rsi; jb +5; ret; ...; ret`` -- an unsigned comparison.
UNSIGNED_COMPARISON = (
    bytes.fromhex("4839f7")  # 0x401000: cmp rdi, rsi
    + bytes.fromhex("7205")  # 0x401003: jb 0x40100a
    + RET  # 0x401005: ret
    + bytes.fromhex("90") * 4  # 0x401006: padding
    + RET  # 0x40100a: ret
)

#: ``inc rax; cmp rax, rdi; jne -8; ret`` -- a loop whose latch tests the exit.
BACKWARD_BRANCH_LOOP = (
    bytes.fromhex("48ffc0") + bytes.fromhex("4839f8") + bytes.fromhex("75f8") + RET
)

#: ``inc rax; jmp -5`` -- an endless loop closed by an unconditional back edge.
ENDLESS_LOOP = bytes.fromhex("48ffc0") + bytes.fromhex("ebfb")

#: Two nested tests where the inner branch leaves the enclosing region: the only
#: honest rendering is ``goto``.
CROSSING_BRANCH = (
    bytes.fromhex("4885ff")  # 0x401000: test rdi, rdi
    + bytes.fromhex("740c")  # 0x401003: je 0x401011
    + bytes.fromhex("4885f6")  # 0x401005: test rsi, rsi
    + bytes.fromhex("740c")  # 0x401008: je 0x401016
    + RET  # 0x40100a: ret
    + bytes.fromhex("90") * 6  # 0x40100b: padding
    + RET  # 0x401011: ret
    + bytes.fromhex("90") * 4  # 0x401012: padding
    + RET  # 0x401016: ret
)


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


def _load(path: Path) -> BinaryInfo:
    """Load a fixture binary with the production loader."""
    return BinaryLoader().load(path)


def _decompile(path: Path, code: bytes, **kwargs: object) -> PseudoFunction:
    """Build a fixture with ``code`` at :data:`TEXT_VA` and decompile it."""
    binary = _make_elf64(path, code)
    info = _load(binary)
    return decompile_function(binary, info, TEXT_VA, **kwargs)  # type: ignore[arg-type]


def test_straight_line_renders_signature_and_three_lines(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "straight.bin", STRAIGHT_LINE)

    assert isinstance(result, PseudoFunction)
    assert result.address == TEXT_VA
    assert result.name is None
    assert result.block_count == 1
    assert result.instruction_count == 3
    assert result.truncated is False
    assert result.call_sites == ()
    assert result.lines == (
        "rax = a0;  /* mov rax, rdi */",
        "rax += a1;  /* add rax, rsi */",
        "return;  /* ret */",
    )


def test_signature_infers_two_arguments_from_register_reads(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "signature.bin", STRAIGHT_LINE)

    # Both registers are read before the ret, so the signature names two
    # parameters; the types come from the use (a copy and an add).
    assert "uint64_t sub_401000(uint64_t a0, uint64_t a1)" in result.body
    assert "confidence: low" in result.body
    assert "0x401000" in result.body
    assert "goto" not in result.body
    assert "LABEL_" not in result.body


def test_diamond_emits_if_else_with_both_branch_bodies(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "diamond.bin", DIAMOND)

    assert result.block_count == 4
    assert result.instruction_count == 6
    assert result.truncated is False
    body = result.body
    assert "if (a0 != a1) {" in body
    assert "} else {" in body
    assert "eax = 1;" in body
    assert "eax = 2;" in body
    assert "goto" not in body


def test_diamond_condition_comes_from_the_preceding_cmp(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "diamond_cmp.bin", DIAMOND)

    lines = result.lines
    assert lines[0] == "/* cmp rdi, rsi */"
    assert lines[1] == "if (a0 != a1) {  /* je 0x401010 */"
    assert "eax = 1;" in lines[2]
    assert lines[4] == "} else {"


def test_loop_emits_while_and_break(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "loop.bin", LOOP)

    assert result.truncated is False
    assert result.lines == (
        "eax = 0;  /* mov eax, 0 */",
        "while (1) {",
        "    rax += 1;  /* add rax, 1 */",
        "    /* cmp rax, 0xa */",
        "    if (rax >= 0xa) {  /* jl 0x401005 */",
        "        break;",
        "    }",
        "}",
        "return;  /* ret */",
    )


def test_indirect_call_records_an_unresolved_call_site(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "indirect.bin", INDIRECT_CALL)

    assert result.call_sites == (CallSite(0x401000, None, None, "call"),)
    assert "(*ptr)();" in result.body
    assert "call_rax" not in result.body


def test_backward_branch_loop_breaks_on_the_exit_condition(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "backward.bin", BACKWARD_BRANCH_LOOP)

    assert result.lines == (
        "while (1) {",
        "    rax++;  /* inc rax */",
        "    /* cmp rax, rdi */",
        "    if (rax == a0) {  /* jne 0x401000 */",
        "        break;",
        "    }",
        "}",
        "return;  /* ret */",
    )


def test_unconditional_back_edge_renders_continue(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "endless.bin", ENDLESS_LOOP)

    assert result.lines == (
        "while (1) {",
        "    rax++;  /* inc rax */",
        "    continue;  /* jmp 0x401000 */",
        "}",
    )


def test_branch_crossing_an_enclosing_region_falls_back_to_goto(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "crossing.bin", CROSSING_BRANCH)

    assert "if ((a0 & a0) != 0) {  /* je 0x401011 */" in result.body
    assert "goto LABEL_401016;" in result.body
    assert "LABEL_401016:" in result.body
    assert result.truncated is False


def test_indirect_call_site_serializes_with_a_null_target(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "indirect_dict.bin", INDIRECT_CALL)

    site = result.call_sites[0].to_dict()
    assert site == {"address": "0x401000", "target": None, "name": None, "kind": "call"}


def test_direct_call_is_named_after_its_target(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "direct.bin", DIRECT_CALL)

    assert result.call_sites == (CallSite(0x401000, 0x401005, None, "call"),)
    assert "call_401005();" in result.body
    # Nothing writes rax before the ret: the function is rendered as void.
    assert "void sub_401000(void)" in result.body


def test_memory_operand_uses_the_pointer_width(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "memory.bin", MOV_RAX_RDI_10 + RET)

    assert result.lines[0] == ("rax = *(u64*)(a0 + 0x10);  /* mov rax, qword ptr [rdi + 0x10] */")


def test_stack_operand_becomes_a_frame_slot(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "stack.bin", MOV_RAX_RBP_8 + RET)

    assert result.lines[0] == "rax = local_0x8;  /* mov rax, qword ptr [rbp - 8] */"
    # A frame slot is not an argument register, but the load into rax is a
    # 64-bit write, so the return type is uint64_t and there is no parameter.
    assert "uint64_t sub_401000(void)" in result.body


def test_lea_renders_an_indexed_address_without_dereferencing(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "lea.bin", LEA_INDEXED)

    assert result.lines[0] == "rax = a0 + a1 * 4 + 0x10;  /* lea rax, [rdi + rsi*4 + 0x10] */"


def test_rip_relative_operand_resolves_to_a_global_address(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "rip.bin", RIP_RELATIVE)

    # The load is 7 bytes long, so the global sits at 0x401000 + 7 + 0x100.
    assert result.lines[0] == ("rax = *(u64*)(0x401107);  /* mov rax, qword ptr [rip + 0x100] */")


def test_unmodelled_operand_keeps_its_raw_text(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "segment.bin", SEGMENT_OPERAND)

    assert result.lines[0].startswith("rax = qword ptr fs:[0x30];")


def test_statement_shapes_cover_every_supported_mnemonic(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "statements.bin", STATEMENT_SHAPES)

    assert result.lines == (
        "eax ^= eax;  /* xor eax, eax */",
        "rax++;  /* inc rax */",
        "rax = -rax;  /* neg rax */",
        "rax = a1 * 4;  /* imul rax, rsi, 4 */",
        "rax <<= 2;  /* shl rax, 2 */",
        "*(u64*)(a0 + 0x18) = a1;  /* mov qword ptr [rdi + 0x18], rsi */",
        "return;  /* ret */",
    )


def test_branch_into_a_non_executable_section_becomes_a_raw_goto(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "out_of_code.bin", BRANCH_OUT_OF_CODE, data=bytes(16))
    info = _load(binary)
    result = decompile_function(binary, info, TEXT_VA)

    assert "if ((a0 & a0) == 0) {  /* je 0x402000 */" in result.body
    assert "goto 0x402000;" in result.body


def test_branch_without_a_comparison_falls_back_to_a_named_flag(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "no_compare.bin", NO_COMPARISON)

    assert "if (flag_from_jne) {  /* je 0x401007 */" in result.body


def test_unsigned_branch_uses_an_unsigned_comparison(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "unsigned.bin", UNSIGNED_COMPARISON)

    assert "if ((unsigned) a0 >= a1) {  /* jb 0x40100a */" in result.body


def test_import_target_is_called_by_name(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "import.bin", DIRECT_CALL)
    info = _load(binary)
    info.imports.append(ImportInfo(name="puts", address=0x401005))

    result = decompile_function(binary, info, TEXT_VA)

    assert "puts();" in result.body
    assert result.call_sites == (CallSite(0x401000, 0x401005, "puts", "call"),)


def test_discovered_symbol_names_the_function(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "symbol.bin", STRAIGHT_LINE)
    info = _load(binary)
    info.symbols.append(
        SymbolInfo(name="add_two", address=TEXT_VA, size=6, kind="function", is_function=True)
    )

    result = decompile_function(binary, info, TEXT_VA)

    assert result.name == "add_two"
    assert "uint64_t add_two(uint64_t a0, uint64_t a1)" in result.body


def test_long_function_truncates_by_max_instructions(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "long.bin", LONG_FUNCTION, max_instructions=4)

    assert result.truncated is True
    assert result.instruction_count == 4
    assert result.block_count == 1
    assert len(result.lines) == 4
    assert " * warning:" in result.body
    assert "truncated: true" in result.body


def test_result_evidence_is_low_confidence_and_mentions_the_heuristic(
    tmp_path: Path,
) -> None:
    result = _decompile(tmp_path / "evidence.bin", STRAIGHT_LINE)

    assert result.evidence.confidence is Confidence.LOW
    assert result.evidence.source == "decompile.pseudo_c"
    assert result.evidence.method == "mnemonic_heuristic"
    assert result.evidence.address == TEXT_VA
    assert "instruction(s)" in (result.evidence.detail or "")


def test_body_is_ascii_only(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "ascii.bin", DIAMOND)

    result.body.encode("ascii")
    for line in result.lines:
        line.encode("ascii")


def test_to_dict_is_json_safe_and_stable(tmp_path: Path) -> None:
    result = _decompile(tmp_path / "dict.bin", DIAMOND)

    first = result.to_dict()
    second = result.to_dict()
    assert first == second
    assert json.loads(json.dumps(first)) == first
    assert first["address"] == "0x401000"
    assert first["block_count"] == 4
    assert first["instruction_count"] == 6
    assert first["truncated"] is False
    assert isinstance(first["lines"], list)
    assert isinstance(first["body"], str)
    assert first["evidence"]["confidence"] == "low"


def test_rendering_is_deterministic(tmp_path: Path) -> None:
    first = _decompile(tmp_path / "deterministic_a.bin", DIAMOND)
    second = _decompile(tmp_path / "deterministic_b.bin", DIAMOND)

    assert first.lines == second.lines
    assert first.body == second.body
    assert first.call_sites == second.call_sites


def test_bad_address_raises(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "bad_address.bin", STRAIGHT_LINE)
    info = _load(binary)

    with pytest.raises(AnalysisError):
        decompile_function(binary, info, 0x999000)


def test_non_executable_address_raises(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "non_executable.bin", STRAIGHT_LINE, data=b"\x01\x02")
    info = _load(binary)

    with pytest.raises(AnalysisError):
        decompile_function(binary, info, DATA_VA)


def test_undecodable_region_raises(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "undecodable.bin", b"\xf0\xf0\xf0\xf0")
    info = _load(binary)

    with pytest.raises(AnalysisError):
        decompile_function(binary, info, TEXT_VA)


def test_out_of_range_budgets_raise(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "budgets.bin", STRAIGHT_LINE)
    info = _load(binary)

    with pytest.raises(AnalysisError):
        decompile_function(binary, info, TEXT_VA, max_instructions=0)
    with pytest.raises(AnalysisError):
        decompile_function(binary, info, TEXT_VA, max_instructions=MAX_MAX_INSTRUCTIONS + 1)
    with pytest.raises(AnalysisError):
        decompile_function(binary, info, TEXT_VA, max_blocks=0)
    with pytest.raises(AnalysisError):
        decompile_function(binary, info, TEXT_VA, max_blocks=MAX_MAX_BLOCKS + 1)


def test_defaults_are_within_the_hard_limits() -> None:
    assert 1 <= DEFAULT_MAX_INSTRUCTIONS <= MAX_MAX_INSTRUCTIONS
    assert 1 <= DEFAULT_MAX_BLOCKS <= MAX_MAX_BLOCKS

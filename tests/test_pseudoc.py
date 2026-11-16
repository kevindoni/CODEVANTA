"""Pseudo-C emitter (decompiler v2 increment 3) tests over synthetic ELF64 files.

Fixtures are built here with :mod:`struct` exactly like ``test_ssa.py`` does,
so the tests stay self-contained and never touch shared fixtures or real
binaries. The emitter itself is pure: it takes the SSA object and returns
deterministic text, so every assertion below pins exact emitted lines.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis.ir_ssa import build_ssa
from codevanta.analysis.pseudo_c import emit_pseudo_c
from codevanta.core.loader import BinaryLoader
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import ext_pseudoc

TEXT_ADDRESS = 0x401000

#: `mov rax, rax; add rax, rbx; mov rbx, rax` -- straight-line assignments.
STRAIGHT_LINE = bytes.fromhex("4889c04801d84889c3")

#: `add rax, 0x10; xor rcx, rcx` -- immediate fold and self-clear fold.
IMMEDIATE_SELF_CLEAR = bytes.fromhex("4883c0104831c9")

#: `cmp rax, rbx; je +2; nop; nop` -- recovered condition renders as an if.
CONDITION = bytes.fromhex("4839d874029090")

#: `mov eax, 1; dec rax; jne 0x401000; ret` -- one back-edge loop.
LOOP = bytes.fromhex("b801000000") + bytes.fromhex("48ffc8") + bytes.fromhex("75f6") + b"\xc3"

#: `mov rbx, rax; mov ecx, 1; call +1; nop; mov rax, rbx; ret` -- clobbers.
CALL_CLOBBER = bytes.fromhex("4889c3b901000000e801000000904889d8c3")


def _align(value: int, alignment: int) -> int:
    """Round ``value`` up to a multiple of ``alignment``."""
    return (value + alignment - 1) // alignment * alignment


def _write_elf64(path: Path, code: bytes, *, text_address: int = TEXT_ADDRESS) -> Path:
    """Write a minimal ELF64 executable with one executable ``.text`` section."""
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_offset = 0x40
    shstrtab_offset = _align(text_offset + len(code), 8)
    shoff = _align(shstrtab_offset + len(shstrtab), 8)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,              # e_type = ET_EXEC
        62,             # e_machine = EM_X86_64
        1,              # e_version
        text_address,   # e_entry
        0,              # e_phoff
        shoff,          # e_shoff
        0,              # e_flags
        64,             # e_ehsize
        56,             # e_phentsize
        0,              # e_phnum
        64,             # e_shentsize
        3,              # e_shnum
        2,              # e_shstrndx
    )
    null_section = bytes(64)
    text_section = struct.pack(
        "<IIQQQQIIQQ",
        1,              # sh_name -> ".text"
        1,              # sh_type = SHT_PROGBITS
        6,              # sh_flags = SHF_ALLOC | SHF_EXECINSTR
        text_address,   # sh_addr
        text_offset,    # sh_offset
        len(code),      # sh_size
        0,              # sh_link
        0,              # sh_info
        16,             # sh_addralign
        0,              # sh_entsize
    )
    shstrtab_section = struct.pack(
        "<IIQQQQIIQQ",
        7,                  # sh_name -> ".shstrtab"
        3,                  # sh_type = SHT_STRTAB
        0,                  # sh_flags
        0,                  # sh_addr
        shstrtab_offset,    # sh_offset
        len(shstrtab),      # sh_size
        0,
        0,
        1,
        0,
    )
    blob = bytearray(shoff + 3 * 64)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob[shoff : shoff + 64] = null_section
    blob[shoff + 64 : shoff + 128] = text_section
    blob[shoff + 128 : shoff + 192] = shstrtab_section
    path.write_bytes(bytes(blob))
    return path


def _emit(path: Path, code: bytes, **kwargs: int):
    """Build the SSA for ``code`` and lower it to pseudo-C."""
    sample = _write_elf64(path, code)
    info = BinaryLoader().load(sample)
    return emit_pseudo_c(build_ssa(sample, info, TEXT_ADDRESS, **kwargs))


def test_assignments_reuse_folded_expressions(tmp_path: Path) -> None:
    """mov/add/mov emits one '<id> = <expr>;' line per definition, verbatim."""
    result = _emit(tmp_path / "assign.bin", STRAIGHT_LINE)
    assert "rax.1 = rax.0;" in result.text
    assert "rax.2 = rax.1 + rbx.0;" in result.text
    assert "rbx.1 = rax.2;" in result.text
    # A FLAGS-writer with a GP definition keeps its raw mnemonic visible.
    assert "rax.2 = rax.1 + rbx.0; /* add rax, rbx */" in result.text
    assert "FLAGS" not in result.text


def test_immediate_fold_and_self_clear(tmp_path: Path) -> None:
    """`add rax, 0x10` folds the constant; `xor rcx, rcx` clears to 0."""
    result = _emit(tmp_path / "fold.bin", IMMEDIATE_SELF_CLEAR)
    assert "rax.1 = rax.0 + 0x10;" in result.text
    assert "rcx.1 = 0;" in result.text


def test_condition_renders_as_if_line(tmp_path: Path) -> None:
    """cmp rax, rbx; je -> a bounded if-line; the cmp stays a comment."""
    result = _emit(tmp_path / "cond.bin", CONDITION)
    assert "if (rax.0 == rbx.0) { /* taken */ }" in result.text
    assert result.condition_count == 1
    assert "/* cmp rax, rbx */" in result.text


def test_signed_and_unsigned_jcc_annotated(tmp_path: Path) -> None:
    """jg renders 'taken: signed', ja renders 'taken: unsigned' -- same op."""
    signed = _emit(tmp_path / "signed.bin", bytes.fromhex("4839d87f029090"))
    assert "if (rax.0 > rbx.0) { /* taken: signed */ }" in signed.text
    assert signed.condition_count == 1
    unsigned = _emit(tmp_path / "unsigned.bin", bytes.fromhex("4839d877029090"))
    assert "if (rax.0 > rbx.0) { /* taken: unsigned */ }" in unsigned.text
    assert unsigned.condition_count == 1


def test_loop_boundary_marker(tmp_path: Path) -> None:
    """The one-back-edge loop sample marks its loop-boundary block."""
    result = _emit(tmp_path / "loop.bin", LOOP)
    assert len(result.loop_markers) >= 1
    assert "LOOP BOUNDARY" in result.text


def test_call_line_with_clobber_note(tmp_path: Path) -> None:
    """A call prints its SSA argument registers and a clobber note."""
    result = _emit(tmp_path / "call.bin", CALL_CLOBBER)
    assert "call(rcx.1, rdx.0, r8.0, r9.0);" in result.text
    assert "/* clobbers:" in result.text
    assert result.call_count == 1


def test_undef_markers_are_collected(tmp_path: Path) -> None:
    """Reads before any definition are reported as sorted markers."""
    result = _emit(tmp_path / "undef.bin", STRAIGHT_LINE)
    assert result.undef_markers == ("rax.0", "rbx.0")


def test_deterministic_and_json_safe(tmp_path: Path) -> None:
    """Same input, byte-identical result; the dict survives JSON."""
    first = _emit(tmp_path / "d1.bin", STRAIGHT_LINE)
    second = _emit(tmp_path / "d2.bin", STRAIGHT_LINE)
    assert first.to_dict() == second.to_dict()
    payload = json.dumps(first.to_dict())
    assert "rax.2 = rax.1 + rbx.0;" in payload


def test_instruction_budget_sets_truncated(tmp_path: Path) -> None:
    """A tiny max_instructions budget propagates the honest truncation."""
    result = _emit(tmp_path / "bound.bin", STRAIGHT_LINE, max_instructions=2)
    assert result.truncated is True
    assert result.line_count >= 1


def test_mcp_wrapper_typed_errors(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "tool_err.bin", STRAIGHT_LINE)

    with pytest.raises(AnalysisError, match="file not found"):
        ext_pseudoc.codevanta_pseudo_c(str(tmp_path / "missing.bin"), TEXT_ADDRESS)
    with pytest.raises(AnalysisError, match="address must be an int"):
        ext_pseudoc.codevanta_pseudo_c(str(sample), "0x401000")
    with pytest.raises(AnalysisError, match="address must be positive"):
        ext_pseudoc.codevanta_pseudo_c(str(sample), 0)
    with pytest.raises(AnalysisError, match="max_blocks must be between"):
        ext_pseudoc.codevanta_pseudo_c(str(sample), TEXT_ADDRESS, max_blocks=0)
    with pytest.raises(AnalysisError, match="max_instructions must be between"):
        ext_pseudoc.codevanta_pseudo_c(str(sample), TEXT_ADDRESS, max_instructions=10**6)


def test_mcp_wrapper_returns_payload(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "tool_ok.bin", STRAIGHT_LINE)
    payload = ext_pseudoc.codevanta_pseudo_c(str(sample), TEXT_ADDRESS)
    assert payload["function_address"] == "0x401000"
    assert "rax.2 = rax.1 + rbx.0;" in payload["text"]
    assert payload["evidence"]["source"] == "pseudo_c.emit"
    json.dumps(payload)


def test_tool_is_reexported_through_tools_module() -> None:
    from codevanta.mcp_server import tools

    assert callable(tools.codevanta_pseudo_c)
    assert tools.DEFAULT_PSEUDO_C_MAX_BLOCKS == 512
    assert tools.DEFAULT_PSEUDO_C_MAX_INSTRUCTIONS == 2_000

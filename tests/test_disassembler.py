"""Disassembler tests for known instruction sequences."""

from __future__ import annotations

import pytest

from codevanta.core.disassembler import Disassembler, DisassemblyError


def test_disassemble_x64_nops() -> None:
    result = Disassembler("x86_64", 64).disassemble(b"\x90\x90\x90", base_address=0x1000)
    assert [i.mnemonic for i in result.instructions] == ["nop", "nop", "nop"]
    assert [i.address for i in result.instructions] == [0x1000, 0x1001, 0x1002]
    assert result.instructions[0].raw_bytes == b"\x90"


def test_disassemble_x64_prologue() -> None:
    result = Disassembler("x86_64", 64).disassemble(
        b"\x55\x48\x89\xe5\xc3", base_address=0x0
    )
    assert [i.mnemonic for i in result.instructions] == ["push", "mov", "ret"]
    assert result.instructions[1].text.startswith("mov")


def test_disassemble_x86() -> None:
    result = Disassembler("x86", 32).disassemble(b"\x90\xc3", base_address=0)
    assert [i.mnemonic for i in result.instructions] == ["nop", "ret"]


def test_instruction_limit_sets_truncated() -> None:
    result = Disassembler("x86_64", 64).disassemble(
        b"\x90" * 10, base_address=0, max_instructions=3
    )
    assert len(result.instructions) == 3
    assert result.truncated is True


def test_rejects_empty_input() -> None:
    with pytest.raises(DisassemblyError):
        Disassembler("x86_64", 64).disassemble(b"", base_address=0)


def test_rejects_unsupported_architecture() -> None:
    with pytest.raises(DisassemblyError):
        Disassembler("sparc", 32)


def test_rejects_big_endian_x86() -> None:
    with pytest.raises(DisassemblyError):
        Disassembler("x86", 32, endianness="big")

"""Recursive-descent CFG tests (boundaries, edges, unresolved, budgets)."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from codevanta.analysis.recursive_cfg import build_recursive_cfg
from codevanta.core.loader import BinaryLoader
from codevanta.core.report import AnalysisError

ENTRY = 0x401000

#: push rbp; mov rbp, rsp; call +2; pop rbp; ret — then the callee:
#: push rbp; mov rbp, rsp; pop rbp; ret. The call at 0x401004 targets
#: 0x40100b (rel32 = 2), so one walk from the entry point discovers it.
TWO_FUNCTION_CODE = bytes.fromhex("554889e5e8020000005dc3") + bytes.fromhex("554889e55dc3")

#: push rbp; jmp +5; nops; pop rbp; ret — the jump skips the nops into the
#: pop/ret tail, so the entry block has one jump edge instead of falling
#: through into dead bytes.
JUMPY_CODE = bytes.fromhex("55eb05909090905dc3")

#: push rbp; mov rbp, rsp; call rax; pop rbp; ret — the indirect call target
#: is not statically known and must stay unresolved.
INDIRECT_CODE = bytes.fromhex("554889e5ffd05dc3")


def _write_elf64_with_code(path: Path, code: bytes, *, entry: int = ENTRY) -> Path:
    """Write an ELF64 with one executable .text section at ``entry``.

    Local helper (no conftest change) because the recursive walk needs
    arbitrary multi-function code layouts the existing fixtures don't cover.
    """
    shstr = b"\x00.text\x00.shstrtab\x00"
    off_text = 0x40
    off_shstr = off_text + len(code)
    off_sh = (off_shstr + len(shstr) + 7) & ~7  # section headers are 8-aligned
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, entry, 0, off_sh, 0, 64, 56, 0, 64, 3, 2
    )
    null_section = bytes(64)
    text_section = struct.pack(
        "<IIQQQQIIQQ", 1, 1, 6, entry, off_text, len(code), 0, 0, 16, 0
    )
    str_section = struct.pack(
        "<IIQQQQIIQQ", 7, 3, 0, 0, off_shstr, len(shstr), 0, 0, 1, 0
    )
    blob = bytearray(off_sh)
    blob[0:64] = header
    blob[off_text : off_text + len(code)] = code
    blob[off_shstr : off_shstr + len(shstr)] = shstr
    blob += null_section + text_section + str_section
    path.write_bytes(blob)
    return path


def _build(path: Path, **kwargs: int) -> object:
    info = BinaryLoader().load(path)
    return build_recursive_cfg(path, info, ENTRY, **kwargs)


def test_discovers_callee_boundary_from_direct_call(tmp_path: Path) -> None:
    sample = _write_elf64_with_code(tmp_path / "two_fn.bin", TWO_FUNCTION_CODE)
    result = _build(sample)
    assert len(result.functions) == 2
    assert result.functions[0].function_address == ENTRY
    assert result.functions[1].function_address == 0x40100B
    assert len(result.discovered) == 1
    boundary = result.discovered[0]
    assert boundary.address == 0x40100B
    assert boundary.source == "cfg.recursive_descent"
    assert boundary.confidence.value == "medium"
    assert boundary.evidence.method == "direct_call_target"
    assert "direct call from" in boundary.evidence.detail
    assert result.truncated is False
    assert result.unresolved == []


def test_jump_target_becomes_block_edge(tmp_path: Path) -> None:
    sample = _write_elf64_with_code(tmp_path / "jumpy.bin", JUMPY_CODE)
    result = _build(sample)
    assert len(result.functions) == 1
    blocks = result.functions[0].blocks
    starts = [block.start for block in blocks]
    assert starts == [ENTRY, 0x401008]
    entry_block = blocks[0]
    assert entry_block.terminator == "jmp"
    assert entry_block.successors == (0x401008,)
    tail_block = blocks[1]
    assert tail_block.terminator == "ret"
    assert tail_block.successors == ()
    assert result.unresolved == []


def test_indirect_call_stays_unresolved(tmp_path: Path) -> None:
    sample = _write_elf64_with_code(tmp_path / "indirect.bin", INDIRECT_CODE)
    result = _build(sample)
    assert len(result.functions) == 1  # no invented function for call rax
    assert len(result.unresolved) == 1
    transfer = result.unresolved[0]
    assert transfer.address == ENTRY + 4
    assert transfer.kind == "call"
    assert transfer.mnemonic == "call"
    assert transfer.text == "call rax"
    assert transfer.reason == "indirect operand"
    assert transfer.evidence.source == "cfg.recursive_descent"


def test_function_budget_truncates_honestly(tmp_path: Path) -> None:
    sample = _write_elf64_with_code(tmp_path / "budget.bin", TWO_FUNCTION_CODE)
    result = _build(sample, max_functions=1)
    assert len(result.functions) == 1
    assert result.truncated is True
    assert any("function limit" in warning for warning in result.warnings)
    # The un-walked seed was still discovered as a call-target boundary.
    assert [c.address for c in result.discovered] == [0x40100B]


def test_instruction_budget_cuts_walk(tmp_path: Path) -> None:
    sample = _write_elf64_with_code(tmp_path / "instr_budget.bin", TWO_FUNCTION_CODE)
    result = _build(sample, max_instructions=3)
    assert result.truncated is True
    assert any("budget" in warning for warning in result.warnings)


@pytest.mark.parametrize(
    ("param", "value"),
    [
        ("max_instructions", 0),
        ("max_blocks", 0),
        ("max_functions", 0),
        ("max_bytes", 0),
    ],
)
def test_invalid_limits_raise(tmp_path: Path, param: str, value: int) -> None:
    sample = _write_elf64_with_code(tmp_path / "invalid.bin", TWO_FUNCTION_CODE)
    info = BinaryLoader().load(sample)
    with pytest.raises(AnalysisError):
        build_recursive_cfg(sample, info, ENTRY, **{param: value})


def test_non_executable_start_raises(tmp_path: Path) -> None:
    sample = _write_elf64_with_code(tmp_path / "nx.bin", TWO_FUNCTION_CODE)
    info = BinaryLoader().load(sample)
    with pytest.raises(AnalysisError):
        build_recursive_cfg(sample, info, 0x10)  # inside the ELF header, not code

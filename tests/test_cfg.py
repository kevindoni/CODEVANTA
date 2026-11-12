"""CFG (linear-sweep, phase 2) tests over synthetic ELF64 files.

The samples are built here with :mod:`struct` so the tests stay self-contained
and never touch fixtures shared with other modules.
"""

from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from codevanta.analysis import cfg as cfg_module
from codevanta.analysis.cfg import BasicBlock, FunctionCFG, build_cfg
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import MAX_DISASSEMBLY_COUNT, AnalysisError

TEXT_ADDRESS = 0x401000
#: `test eax, eax; je 0x401006; nop; nop; ret`
BRANCHY_CODE = bytes.fromhex("85c074029090c3")


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


@pytest.fixture
def branchy_path(tmp_path: Path) -> Path:
    """ELF64 sample whose `.text` contains a conditional branch into a return."""
    return _write_elf64(tmp_path / "branchy.bin", BRANCHY_CODE)


@pytest.fixture
def branchy_info(branchy_path: Path) -> BinaryInfo:
    return BinaryLoader().load(branchy_path)


def test_blocks_starting_at_expected_addresses(
    branchy_path: Path, branchy_info: BinaryInfo
) -> None:
    graph = build_cfg(branchy_path, branchy_info, TEXT_ADDRESS)

    assert [block.start for block in graph.blocks] == [0x401000, 0x401004, 0x401006]
    assert [block.end for block in graph.blocks] == [0x401004, 0x401006, 0x401007]
    assert all(isinstance(block, BasicBlock) for block in graph.blocks)
    assert graph.function_address == TEXT_ADDRESS
    assert graph.instruction_count == 5
    assert graph.truncated is False


def test_first_block_successors_are_sorted_and_deduplicated(
    branchy_path: Path, branchy_info: BinaryInfo
) -> None:
    graph = build_cfg(branchy_path, branchy_info, TEXT_ADDRESS)
    first, middle, last = graph.blocks

    assert first.terminator == "je"
    assert first.successors == (0x401004, 0x401006)
    assert middle.terminator is None
    assert middle.successors == (0x401006,)
    assert last.terminator == "ret"
    assert last.successors == ()


def test_block_instructions_are_instruction_dicts(
    branchy_path: Path, branchy_info: BinaryInfo
) -> None:
    graph = build_cfg(branchy_path, branchy_info, TEXT_ADDRESS)
    first = graph.blocks[0]

    assert [entry["address"] for entry in first.instructions] == ["0x401000", "0x401002"]
    assert [entry["mnemonic"] for entry in first.instructions] == ["test", "je"]
    assert first.instructions[0]["text"] == "test eax, eax"


def test_instruction_limit_marks_graph_truncated(
    branchy_path: Path, branchy_info: BinaryInfo
) -> None:
    graph = build_cfg(branchy_path, branchy_info, TEXT_ADDRESS, max_instructions=2)

    assert graph.truncated is True
    assert graph.instruction_count == 2
    assert [block.start for block in graph.blocks] == [0x401000]
    assert graph.blocks[0].successors == ()  # both edges leave the decoded range
    assert any("may be incomplete" in warning for warning in graph.warnings)


def test_block_limit_truncates_and_warns(tmp_path: Path) -> None:
    code = bytes.fromhex("7400" * 4 + "c3")  # four self-targeting je + ret -> 5 blocks
    path = _write_elf64(tmp_path / "many_blocks.bin", code)
    info = BinaryLoader().load(path)

    graph = build_cfg(path, info, TEXT_ADDRESS, max_blocks=2)

    assert len(graph.blocks) == 2
    assert graph.truncated is True
    assert any("max_blocks" in warning for warning in graph.warnings)


def test_conditional_branch_deduplicates_fallthrough_and_target(tmp_path: Path) -> None:
    code = bytes.fromhex("7400c3")  # je +0 (target == fallthrough); ret
    path = _write_elf64(tmp_path / "dedupe.bin", code)
    info = BinaryLoader().load(path)

    graph = build_cfg(path, info, TEXT_ADDRESS)

    assert graph.blocks[0].terminator == "je"
    assert graph.blocks[0].successors == (0x401002,)
    assert graph.blocks[1].terminator == "ret"


def test_unconditional_jump_has_no_fallthrough(tmp_path: Path) -> None:
    # jmp 0x401004 skips the nops at 0x401002..0x401003
    code = bytes.fromhex("eb029090c3")
    path = _write_elf64(tmp_path / "jump.bin", code)
    info = BinaryLoader().load(path)

    graph = build_cfg(path, info, TEXT_ADDRESS)

    assert [block.start for block in graph.blocks] == [0x401000, 0x401002, 0x401004]
    assert graph.blocks[0].terminator == "jmp"
    assert graph.blocks[0].successors == (0x401004,)
    assert graph.blocks[-1].terminator == "ret"
    assert graph.blocks[-1].successors == ()


@pytest.mark.parametrize("start", [0x0, 0x402000])
def test_start_outside_executable_section_raises(
    branchy_path: Path, branchy_info: BinaryInfo, start: int
) -> None:
    # 0x0 is mapped but inside the non-executable .shstrtab; 0x402000 is unmapped.
    with pytest.raises(AnalysisError):
        build_cfg(branchy_path, branchy_info, start)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"max_instructions": 0}, "max_instructions"),
        ({"max_instructions": MAX_DISASSEMBLY_COUNT + 1}, "max_instructions"),
        ({"max_blocks": 0}, "max_blocks"),
    ],
)
def test_invalid_limits_raise(
    branchy_path: Path,
    branchy_info: BinaryInfo,
    kwargs: dict[str, int],
    match: str,
) -> None:
    with pytest.raises(AnalysisError, match=match):
        build_cfg(branchy_path, branchy_info, TEXT_ADDRESS, **kwargs)



def test_block_evidence_shape(branchy_path: Path, branchy_info: BinaryInfo) -> None:
    graph = build_cfg(branchy_path, branchy_info, TEXT_ADDRESS)
    block = graph.blocks[1]  # two nops

    assert block.evidence.source == "cfg.linear_sweep"
    assert block.evidence.method == "basic_block"
    assert block.evidence.confidence.value == "medium"
    assert block.evidence.address == 0x401004
    assert block.evidence.detail == "2 instructions"
    assert block.evidence.to_dict()["address"] == "0x401004"


def test_function_evidence_states_heuristic_boundaries(
    branchy_path: Path, branchy_info: BinaryInfo
) -> None:
    graph = build_cfg(branchy_path, branchy_info, TEXT_ADDRESS)

    assert isinstance(graph, FunctionCFG)
    assert graph.evidence.source == "cfg.linear_sweep"
    assert graph.evidence.confidence.value == "medium"
    assert graph.evidence.address == TEXT_ADDRESS
    assert "heuristic" in (graph.evidence.detail or "").lower()


def test_to_dict_is_json_ready(branchy_path: Path, branchy_info: BinaryInfo) -> None:
    data = build_cfg(branchy_path, branchy_info, TEXT_ADDRESS).to_dict()

    assert data["function_address"] == "0x401000"
    assert data["function_name"] is None
    assert data["block_count"] == 3
    assert data["instruction_count"] == 5
    assert data["truncated"] is False
    assert data["warnings"] == []
    assert data["evidence"]["source"] == "cfg.linear_sweep"
    first = data["blocks"][0]
    assert first["start"] == "0x401000"
    assert first["end"] == "0x401004"
    assert first["successors"] == ["0x401004", "0x401006"]
    assert first["terminator"] == "je"
    assert first["instruction_count"] == 2
    assert first["instructions"][1]["mnemonic"] == "je"
    assert first["evidence"]["method"] == "basic_block"


def test_function_name_uses_discovery_candidate(
    branchy_path: Path, branchy_info: BinaryInfo, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = SimpleNamespace(address=TEXT_ADDRESS, name="main")
    monkeypatch.setattr(cfg_module, "discover_functions", lambda _info: [candidate])

    graph = build_cfg(branchy_path, branchy_info, TEXT_ADDRESS)

    assert graph.function_name == "main"


def test_function_name_ignored_for_other_addresses(
    branchy_path: Path, branchy_info: BinaryInfo, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = SimpleNamespace(address=TEXT_ADDRESS + 0x100, name="other")
    monkeypatch.setattr(cfg_module, "discover_functions", lambda _info: [candidate])

    graph = build_cfg(branchy_path, branchy_info, TEXT_ADDRESS)

    assert graph.function_name is None


def test_single_fallthrough_instruction_region(tmp_path: Path) -> None:
    # One `nop` at the very end of .text: no terminator, no successor in range.
    path = _write_elf64(tmp_path / "tiny.bin", b"\x90")
    info = BinaryLoader().load(path)

    graph = build_cfg(path, info, TEXT_ADDRESS)

    assert graph.instruction_count == 1
    assert graph.blocks[0].terminator is None
    assert graph.blocks[0].successors == ()
    assert graph.truncated is False


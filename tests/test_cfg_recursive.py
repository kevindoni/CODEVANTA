"""Recursive-traversal CFG tests over synthetic ELF64 files.

The recursive builder follows control flow from the entry address instead of
sweeping a window, so these tests assert *reachability* behaviour that the
linear-sweep tests in ``test_cfg.py`` deliberately do not: unreachable bytes
must not become blocks, loops must terminate, and call targets must not be
followed. They also assert that reported block ranges are disjoint, because a
block decoded from the worklist can reach past a leader discovered later.
Samples are assembled by hand with :mod:`struct` so the module stays
self-contained.
"""

from __future__ import annotations

import struct
from itertools import pairwise
from pathlib import Path

import pytest

from codevanta.analysis.cfg import (
    BasicBlock,
    FunctionCFG,
    build_cfg,
    build_recursive_cfg,
)
from codevanta.analysis.jump_tables import MAX_ENTRIES as JUMP_TABLE_MAX_ENTRIES
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import MAX_DISASSEMBLY_COUNT, AnalysisError

TEXT_ADDRESS = 0x401000
RODATA_ADDRESS = 0x402000
#: `test eax, eax; je 0x401006; nop; nop; ret` -> branch plus join.
BRANCH_CODE = bytes.fromhex("85c074029090c3")
#: `nop; jmp 0x401000` -> a single block that points at itself.
LOOP_CODE = bytes.fromhex("90ebfd")
#: `ret; nop; nop` -> the two nops are unreachable.
TAIL_CODE = bytes.fromhex("c39090")
#: `call 0x401005; ret` -> the call target is the fallthrough, never a new block.
CALL_CODE = bytes.fromhex("e800000000c3")
#: `jmp rax; ret` -> indirect jump, so the block keeps no successor.
INDIRECT_CODE = bytes.fromhex("ffe0c3")
#: `je 0x401010; nop x13; ret; jmp 0x401005` -> a backward jump into the middle
#: of a run the `je` fallthrough already covered, so the traversal's block
#: hypotheses overlap and the split pass has to make them disjoint (task_0028).
BACKWARD_JUMP_CODE = b"\x74\x0e" + b"\x90" * 13 + b"\xc3\xeb\xf3"

#: `jmp qword ptr [rip + 0xffa]` (-> 0x402000); `ret` at 0x401006; and `ret` at
#: 0x401010 / 0x401020, the addresses the pointer table below dispatches to.
DISPATCH_CODE = (
    bytes.fromhex("ff25fa0f0000")  # 0x401000: jmp qword ptr [rip + 0xffa]
    + b"\xc3"  # 0x401006: ret (never reached through the jump)
    + b"\x90" * 9  # padding up to 0x401010
    + b"\xc3"  # 0x401010: ret
    + b"\x90" * 15  # padding up to 0x401020
    + b"\xc3"  # 0x401020: ret
)
#: Two absolute pointers plus the conventional zero terminator (0x402000).
DISPATCH_TABLE = struct.pack("<QQQ", 0x401010, 0x401020, 0)
#: Two chained dispatchers: 0x401000 -> table A (0x402000) -> 0x401010 ->
#: table B (0x402010) -> 0x401020, each table terminated by a zero pointer.
CHAINED_DISPATCH_CODE = (
    bytes.fromhex("ff25fa0f0000")  # 0x401000: jmp qword ptr [rip + 0xffa] -> 0x402000
    + b"\xc3"  # 0x401006: ret
    + b"\x90" * 9  # padding up to 0x401010
    + bytes.fromhex("ff25fa0f0000")  # 0x401010: jmp qword ptr [rip + 0xffa] -> 0x402010
    + b"\xc3"  # 0x401016: ret
    + b"\x90" * 9  # padding up to 0x401020
    + b"\xc3"  # 0x401020: ret
)
CHAINED_TABLE = struct.pack("<QQ", 0x401010, 0) + struct.pack("<QQ", 0x401020, 0)
#: `jmp qword ptr [rax]` then `ret` -> pointer-sized read, yet not a table address.
INDEXED_CODE = bytes.fromhex("ff20c3")
#: `jmp qword ptr [0x500000]` -> absolute operand pointing at unmapped memory.
UNMAPPED_TABLE_CODE = bytes.fromhex("ff24250000500090")


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
    text_section = struct.pack(
        "<IIQQQQIIQQ",
        1,              # sh_name -> ".text"
        1,              # sh_type = SHT_PROGBITS
        6,              # sh_flags = SHF_ALLOC | SHF_EXECINSTR
        text_address,   # sh_addr
        text_offset,    # sh_offset
        len(code),      # sh_size
        0,
        0,
        16,             # sh_addralign
        0,
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
    blob[shoff : shoff + 64] = bytes(64)
    blob[shoff + 64 : shoff + 128] = text_section
    blob[shoff + 128 : shoff + 192] = shstrtab_section
    path.write_bytes(bytes(blob))
    return path


def _write_elf64_rodata(
    path: Path,
    code: bytes,
    table: bytes,
    *,
    text_address: int = TEXT_ADDRESS,
    rodata_address: int = RODATA_ADDRESS,
) -> Path:
    """Write a minimal ELF64 executable with an executable ``.text`` and ``.rodata``.

    Args:
        path: Destination file.
        code: Bytes of the executable ``.text`` section, mapped at ``text_address``.
        table: Bytes of the read-only ``.rodata`` section. Pointer arrays are
            placed at its start, so the first table sits at ``rodata_address``.
        text_address: Virtual address of ``.text``.
        rodata_address: Virtual address of ``.rodata``.

    Returns:
        ``path``, written to disk.
    """
    shstrtab = b"\x00.text\x00.rodata\x00.shstrtab\x00"
    text_offset = 0x40
    rodata_offset = _align(text_offset + len(code), 8)
    rodata = table.ljust(_align(len(table), 8), b"\x00")
    shstrtab_offset = rodata_offset + len(rodata)
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
        4,              # e_shnum: null, .text, .rodata, .shstrtab
        3,              # e_shstrndx
    )
    sections = [
        bytes(64),  # SHT_NULL
        struct.pack(  # .text: SHF_ALLOC | SHF_EXECINSTR
            "<IIQQQQIIQQ",
            1, 1, 6, text_address, text_offset, len(code), 0, 0, 16, 0,
        ),
        struct.pack(  # .rodata: SHF_ALLOC only
            "<IIQQQQIIQQ",
            7, 1, 2, rodata_address, rodata_offset, len(rodata), 0, 0, 8, 0,
        ),
        struct.pack(  # .shstrtab: SHT_STRTAB
            "<IIQQQQIIQQ",
            15, 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0,
        ),
    ]
    blob = bytearray(shoff)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[rodata_offset : rodata_offset + len(rodata)] = rodata
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob += b"".join(sections)
    path.write_bytes(bytes(blob))
    return path


def _build_table_cfg(
    tmp_path: Path,
    code: bytes,
    table: bytes,
    name: str = "table.bin",
    **kwargs: int,
) -> FunctionCFG:
    """Write ``code`` plus a pointer ``table`` and build the recursive CFG."""
    path = _write_elf64_rodata(tmp_path / name, code, table)
    info = BinaryLoader().load(path)
    return build_recursive_cfg(path, info, TEXT_ADDRESS, **kwargs)


def _build(
    tmp_path: Path,
    code: bytes,
    name: str = "sample.bin",
    **kwargs: int,
) -> FunctionCFG:
    """Write ``code`` into a fresh ELF64 sample and build its recursive CFG."""
    path = _write_elf64(tmp_path / name, code)
    info = BinaryLoader().load(path)
    return build_recursive_cfg(path, info, TEXT_ADDRESS, **kwargs)


def _load(tmp_path: Path, code: bytes, name: str = "sample.bin") -> tuple[Path, BinaryInfo]:
    """Return a sample path and its loaded metadata."""
    path = _write_elf64(tmp_path / name, code)
    return path, BinaryLoader().load(path)


def _assert_disjoint(blocks: list[BasicBlock]) -> None:
    """Assert the blocks are ordered and no address is reported twice."""
    for previous, current in pairwise(blocks):
        assert previous.end <= current.start, (
            f"0x{previous.start:x}-0x{previous.end:x} overlaps 0x{current.start:x}"
        )
    addresses = [int(entry["address"], 16) for block in blocks for entry in block.instructions]
    assert addresses == sorted(addresses), "instructions must be reported in address order"
    assert len(set(addresses)) == len(addresses), "an instruction must not be reported twice"


def test_branch_and_join_yields_three_blocks(tmp_path: Path) -> None:
    graph = _build(tmp_path, BRANCH_CODE)

    assert isinstance(graph, FunctionCFG)
    assert [block.start for block in graph.blocks] == [0x401000, 0x401004, 0x401006]
    assert [block.end for block in graph.blocks] == [0x401004, 0x401006, 0x401007]
    assert all(isinstance(block, BasicBlock) for block in graph.blocks)
    _assert_disjoint(graph.blocks)
    assert graph.function_address == TEXT_ADDRESS
    assert graph.instruction_count == 5
    assert graph.truncated is False
    assert graph.warnings == ()


def test_branch_successors_cover_fallthrough_and_target(tmp_path: Path) -> None:
    first, middle, last = _build(tmp_path, BRANCH_CODE).blocks

    assert first.terminator == "je"
    assert first.successors == (0x401004, 0x401006)  # fallthrough + direct target
    assert [entry["mnemonic"] for entry in first.instructions] == ["test", "je"]
    assert middle.terminator is None  # ordinary run stops at an already-known leader
    assert middle.successors == (0x401006,)
    assert last.terminator == "ret"
    assert last.successors == ()


def test_self_loop_is_one_block_pointing_at_itself(tmp_path: Path) -> None:
    graph = _build(tmp_path, LOOP_CODE)

    assert len(graph.blocks) == 1
    block = graph.blocks[0]
    assert block.start == 0x401000
    assert block.terminator == "jmp"
    assert block.successors == (0x401000,)  # the visited set stops the traversal
    _assert_disjoint(graph.blocks)
    assert graph.instruction_count == 2
    assert graph.truncated is False


def test_backward_jump_is_split_into_disjoint_blocks(tmp_path: Path) -> None:
    graph = _build(tmp_path, BACKWARD_JUMP_CODE, "disjoint.bin")

    # The `je` fallthrough decodes 13 nops and the ret, but the trailing
    # `jmp 0x401005` reaches back into that run: the split pass must cut it.
    assert [(block.start, block.end) for block in graph.blocks] == [
        (0x401000, 0x401002),
        (0x401002, 0x401005),
        (0x401005, 0x401010),
        (0x401010, 0x401012),
    ]
    _assert_disjoint(graph.blocks)

    branch, first_run, second_run, back_jump = graph.blocks

    assert branch.terminator == "je"
    assert branch.successors == (0x401002, 0x401010)  # fallthrough + taken target
    assert [entry["mnemonic"] for entry in branch.instructions] == ["je"]

    # The leading piece of the cut run falls through to the split address only.
    assert first_run.terminator is None
    assert first_run.successors == (0x401005,)
    assert [entry["mnemonic"] for entry in first_run.instructions] == ["nop"] * 3

    # The trailing piece keeps the original terminator and has no successor.
    assert second_run.terminator == "ret"
    assert second_run.successors == ()
    assert [entry["mnemonic"] for entry in second_run.instructions] == ["nop"] * 10 + ["ret"]
    assert second_run.instructions[-1]["address"] == "0x40100f"

    assert back_jump.terminator == "jmp"
    assert back_jump.successors == (0x401005,)

    # Unique instruction addresses: 27 instructions were decoded, 16 are reported.
    assert graph.instruction_count == 16
    assert graph.instruction_count == sum(len(block.instructions) for block in graph.blocks)
    assert graph.truncated is False
    assert graph.warnings == ()


def test_unreachable_tail_is_not_reported(tmp_path: Path) -> None:
    path, info = _load(tmp_path, TAIL_CODE, "tail.bin")

    graph = build_recursive_cfg(path, info, TEXT_ADDRESS)
    sweep = build_cfg(path, info, TEXT_ADDRESS)

    assert len(graph.blocks) == 1  # only the ret; the two nops are unreachable
    assert graph.blocks[0].start == 0x401000
    assert graph.blocks[0].end == 0x401001
    assert graph.blocks[0].successors == ()
    assert graph.instruction_count == 1
    assert len(sweep.blocks) == 2  # linear sweep cannot tell padding from code


def test_call_is_an_ordinary_instruction(tmp_path: Path) -> None:
    graph = _build(tmp_path, CALL_CODE)

    assert [block.start for block in graph.blocks] == [0x401000]
    assert graph.instruction_count == 2
    assert [entry["mnemonic"] for entry in graph.blocks[0].instructions] == ["call", "ret"]
    # `call 0x401005` is not followed: no separate callee block appears and the
    # block simply runs into the ret through the fallthrough.
    assert graph.blocks[0].terminator == "ret"
    assert graph.blocks[0].successors == ()


def test_indirect_jump_leaves_no_successor_and_warns(tmp_path: Path) -> None:
    graph = _build(tmp_path, INDIRECT_CODE, "indirect.bin")

    assert len(graph.blocks) == 1
    assert graph.blocks[0].terminator == "jmp"
    assert graph.blocks[0].successors == ()  # `jmp rax` cannot be resolved
    assert any("indirect branch target" in warning for warning in graph.warnings)


def test_max_blocks_truncates_traversal(tmp_path: Path) -> None:
    graph = _build(tmp_path, BRANCH_CODE, "trunc.bin", max_blocks=1)

    assert len(graph.blocks) == 1
    assert graph.blocks[0].start == 0x401000
    assert graph.truncated is True
    assert any("max_blocks" in warning for warning in graph.warnings)


def test_max_instructions_truncates_traversal(tmp_path: Path) -> None:
    graph = _build(tmp_path, BRANCH_CODE, "budget.bin", max_instructions=2)

    assert graph.truncated is True
    assert graph.instruction_count <= 2
    assert any("max_instructions" in warning for warning in graph.warnings)


@pytest.mark.parametrize("start", [0x0, 0x402000, 0x402001])
def test_invalid_start_raises(tmp_path: Path, start: int) -> None:
    # 0x0 is mapped but inside the non-executable .shstrtab; 0x402000+ is unmapped.
    path, info = _load(tmp_path, BRANCH_CODE, "invalid.bin")

    with pytest.raises(AnalysisError, match="executable"):
        build_recursive_cfg(path, info, start)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"max_instructions": 0}, "max_instructions"),
        ({"max_instructions": MAX_DISASSEMBLY_COUNT + 1}, "max_instructions"),
        ({"max_blocks": 0}, "max_blocks"),
        ({"max_blocks": MAX_DISASSEMBLY_COUNT + 1}, "max_blocks"),
    ],
)
def test_invalid_limits_raise(tmp_path: Path, kwargs: dict[str, int], match: str) -> None:
    path, info = _load(tmp_path, BRANCH_CODE, "limits.bin")

    with pytest.raises(AnalysisError, match=match):
        build_recursive_cfg(path, info, TEXT_ADDRESS, **kwargs)


def test_evidence_records_traversal_bounds_and_gaps(tmp_path: Path) -> None:
    graph = _build(tmp_path, BRANCH_CODE, "evidence.bin")

    assert graph.evidence.source == "cfg.recursive_traversal"
    assert graph.evidence.method == "recursive_traversal"
    assert graph.evidence.confidence.value == "medium"
    assert graph.evidence.address == TEXT_ADDRESS
    detail = graph.evidence.detail or ""
    assert "max_instructions=2000" in detail
    assert "max_blocks=500" in detail
    assert "indirect" in detail
    assert "not followed" in detail

    block = graph.blocks[0]
    assert block.evidence.source == "cfg.recursive_traversal"
    assert block.evidence.method == "basic_block"
    assert block.evidence.confidence.value == "medium"
    assert block.evidence.address == 0x401000


def test_to_dict_is_json_ready(tmp_path: Path) -> None:
    data = _build(tmp_path, BRANCH_CODE, "dict.bin").to_dict()

    assert data["function_address"] == "0x401000"
    assert data["block_count"] == 3
    assert data["instruction_count"] == 5
    assert data["truncated"] is False
    assert data["evidence"]["source"] == "cfg.recursive_traversal"
    assert data["blocks"][0]["successors"] == ["0x401004", "0x401006"]
    assert data["blocks"][2]["terminator"] == "ret"


def test_indirect_jump_is_unresolved_by_default(tmp_path: Path) -> None:
    # resolve_indirect defaults to False, so the dispatcher keeps no successor
    # and the table is never read: the pre-task behaviour, byte for byte.
    graph = _build_table_cfg(tmp_path, DISPATCH_CODE, DISPATCH_TABLE, "default.bin")

    assert [block.start for block in graph.blocks] == [TEXT_ADDRESS]
    block = graph.blocks[0]
    assert block.terminator == "jmp"
    assert block.successors == ()
    assert any("indirect branch target" in warning for warning in graph.warnings)
    assert "jump table" not in (graph.evidence.detail or "")


def test_jump_table_targets_become_successors(tmp_path: Path) -> None:
    graph = _build_table_cfg(
        tmp_path, DISPATCH_CODE, DISPATCH_TABLE, "resolved.bin", resolve_indirect=True
    )

    assert [block.start for block in graph.blocks] == [0x401000, 0x401010, 0x401020]
    assert graph.blocks[0].successors == (0x401010, 0x401020)
    assert [block.terminator for block in graph.blocks] == ["jmp", "ret", "ret"]
    assert all(block.successors == () for block in graph.blocks[1:])
    assert graph.instruction_count == 3
    assert graph.truncated is False
    # The table's zero terminator is surfaced too, prefixed with the block start.
    assert len(graph.warnings) == 1
    assert graph.warnings[0].startswith("block 0x401000")
    assert "zero pointer" in graph.warnings[0]
    _assert_disjoint(graph.blocks)


def test_jump_table_evidence_reports_what_was_resolved(tmp_path: Path) -> None:
    graph = _build_table_cfg(
        tmp_path, DISPATCH_CODE, DISPATCH_TABLE, "table-evidence.bin", resolve_indirect=True
    )

    detail = graph.evidence.detail or ""
    assert "1 jump table(s) resolved" in detail
    assert "max_jump_tables=8" in detail
    assert "max_table_entries=256" in detail


def test_jump_table_targets_are_deduplicated_and_sorted(tmp_path: Path) -> None:
    table = struct.pack("<QQQQ", 0x401020, 0x401010, 0x401020, 0)
    graph = _build_table_cfg(
        tmp_path, DISPATCH_CODE, table, "dedupe.bin", resolve_indirect=True
    )

    assert graph.blocks[0].successors == (0x401010, 0x401020)


def test_truncated_table_warns_with_block_start_prefix(tmp_path: Path) -> None:
    graph = _build_table_cfg(
        tmp_path,
        DISPATCH_CODE,
        DISPATCH_TABLE,
        "table-truncated.bin",
        resolve_indirect=True,
        max_table_entries=1,
    )

    assert [block.start for block in graph.blocks] == [0x401000, 0x401010]
    assert graph.blocks[0].successors == (0x401010,)
    truncation = [warning for warning in graph.warnings if "max_table_entries=1" in warning]
    assert truncation
    assert truncation[0].startswith("block 0x401000")
    assert "truncated" in truncation[0]


def test_max_jump_tables_bounds_resolution_and_warns_once(tmp_path: Path) -> None:
    graph = _build_table_cfg(
        tmp_path,
        CHAINED_DISPATCH_CODE,
        CHAINED_TABLE,
        "table-budget.bin",
        resolve_indirect=True,
        max_jump_tables=1,
    )

    assert [block.start for block in graph.blocks] == [0x401000, 0x401010]
    assert graph.blocks[0].successors == (0x401010,)
    assert graph.blocks[1].successors == ()  # the second table was never decoded
    limit = [warning for warning in graph.warnings if "max_jump_tables=1" in warning]
    assert len(limit) == 1
    assert limit[0].startswith("block 0x401010")


def test_chained_jump_tables_are_followed(tmp_path: Path) -> None:
    graph = _build_table_cfg(
        tmp_path,
        CHAINED_DISPATCH_CODE,
        CHAINED_TABLE,
        "table-chained.bin",
        resolve_indirect=True,
        max_jump_tables=2,
    )

    assert [block.start for block in graph.blocks] == [0x401000, 0x401010, 0x401020]
    assert graph.blocks[1].successors == (0x401020,)
    # One zero-terminator note per resolved table, both prefixed with their block.
    assert len(graph.warnings) == 2
    assert all(warning.startswith("block 0x4010") for warning in graph.warnings)
    assert not any("indirect branch target" in warning for warning in graph.warnings)
    _assert_disjoint(graph.blocks)


def test_register_indirect_jump_warns_and_keeps_no_successor(tmp_path: Path) -> None:
    graph = _build_table_cfg(tmp_path, INDIRECT_CODE, bytes(8), "reg.bin", resolve_indirect=True)

    assert len(graph.blocks) == 1
    assert graph.blocks[0].successors == ()
    assert any("indirect branch target" in warning for warning in graph.warnings)
    assert not any("jump table" in warning for warning in graph.warnings)


def test_indexed_memory_jump_is_not_resolved(tmp_path: Path) -> None:
    # `jmp qword ptr [rax]` reads a pointer, but its address is register-based.
    graph = _build_table_cfg(tmp_path, INDEXED_CODE, bytes(8), "indexed.bin", resolve_indirect=True)

    assert graph.blocks[0].successors == ()
    assert any("indirect branch target" in warning for warning in graph.warnings)


def test_unmapped_table_address_warns(tmp_path: Path) -> None:
    graph = _build_table_cfg(
        tmp_path, UNMAPPED_TABLE_CODE, bytes(8), "unmapped-table.bin", resolve_indirect=True
    )

    assert graph.blocks[0].successors == ()
    unreadable = [warning for warning in graph.warnings if "0x500000" in warning]
    assert unreadable
    assert unreadable[0].startswith("block 0x401000")
    assert any("indirect branch target" in warning for warning in graph.warnings)


def test_resolution_enabled_without_indirect_jumps_is_unchanged(tmp_path: Path) -> None:
    default = _build(tmp_path, BRANCH_CODE, "plain.bin")
    enabled = _build(tmp_path, BRANCH_CODE, "plain-enabled.bin", resolve_indirect=True)

    assert enabled.blocks == default.blocks
    assert enabled.warnings == default.warnings
    assert "0 jump table(s) resolved" in (enabled.evidence.detail or "")


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"max_jump_tables": 0}, "max_jump_tables"),
        ({"max_jump_tables": MAX_DISASSEMBLY_COUNT + 1}, "max_jump_tables"),
        ({"max_table_entries": 0}, "max_table_entries"),
        ({"max_table_entries": JUMP_TABLE_MAX_ENTRIES + 1}, "max_table_entries"),
    ],
)
def test_invalid_indirect_limits_raise(
    tmp_path: Path, kwargs: dict[str, int], match: str
) -> None:
    path, info = _load(tmp_path, BRANCH_CODE, "indirect-limits.bin")

    with pytest.raises(AnalysisError, match=match):
        build_recursive_cfg(path, info, TEXT_ADDRESS, resolve_indirect=True, **kwargs)

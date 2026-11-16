"""SSA IR (decompiler v2 increment 1) tests over synthetic ELF64 files.

Fixtures are built here with :mod:`struct` exactly like ``test_cfg.py`` does,
so the tests stay self-contained and never touch shared fixtures or real
binaries.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis.ir_ssa import (
    DEFAULT_MAX_BLOCKS,
    DEFAULT_MAX_INSTRUCTIONS,
    MAX_BLOCKS,
    MAX_INSTRUCTIONS,
    MAX_USES_PER_VALUE,
    MAX_VALUES,
    SSABlock,
    SSAFunction,
    abi_name,
    abi_volatile_registers,
    build_ssa,
)
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import ext_ssa

TEXT_ADDRESS = 0x401000

#: `mov rax, rax; add rax, rbx; mov rbx, rax` -- straight-line versioning.
STRAIGHT_LINE = bytes.fromhex("4889c04801d84889c3")

#: `mov rbx, rax; mov ecx, 1; call +1; nop; mov rax, rbx; ret` -- the call
#: skips the nop and lands on `mov rax, rbx`; rbx must survive the call.
CALL_CLOBBER = bytes.fromhex("4889c3b901000000e801000000904889d8c3")

#: `mov eax, 1; dec rax; jne 0x401000; ret` -- one back-edge loop.
LOOP = bytes.fromhex("b801000000") + bytes.fromhex("48ffc8") + bytes.fromhex("75f6") + b"\xc3"

#: `lea rax, [rbx + rcx*1]; ret` -- pointer type hint at the definition.
LEA = bytes.fromhex("488d040b") + b"\xc3"


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


def _ssa(path: Path, code: bytes, **kwargs: int) -> SSAFunction:
    """Build the SSA for ``code`` written as one fresh ELF64 sample."""
    sample = _write_elf64(path, code)
    info = BinaryLoader().load(sample)
    return build_ssa(sample, info, TEXT_ADDRESS, **kwargs)


@pytest.fixture
def straight_line(tmp_path: Path) -> SSAFunction:
    """SSA of the straight-line mov/add/mov sample."""
    return _ssa(tmp_path / "straight.bin", STRAIGHT_LINE)


@pytest.fixture
def call_clobber(tmp_path: Path) -> SSAFunction:
    """SSA of the call-clobber sample."""
    return _ssa(tmp_path / "call.bin", CALL_CLOBBER)


@pytest.fixture
def loop(tmp_path: Path) -> SSAFunction:
    """SSA of the one-back-edge loop sample."""
    return _ssa(tmp_path / "loop.bin", LOOP)


def test_straight_line_versions_increment_and_def_use(straight_line: SSAFunction) -> None:
    fn = straight_line
    assert fn.instruction_count == 3
    values = {value.id: value for value in fn.values}

    # rax.1 <- mov rax, rax (insn 0); rax.2 <- add (insn 1); rbx.1 <- mov (insn 2)
    assert values["rax.1"].kind == "def"
    assert (values["rax.1"].def_block, values["rax.1"].def_insn_index) == (0, 0)
    assert values["rax.2"].kind == "def"
    assert (values["rax.2"].def_block, values["rax.2"].def_insn_index) == (0, 1)
    assert values["rbx.1"].kind == "def"
    assert values["rbx.1"].def_insn_index == 2

    # Reads bind to the correct latest version; undefined reads are honest.
    assert values["rax.0"].kind == "undef"
    assert values["rax.0"].uses == ((0, 0),)
    assert values["rax.1"].uses == ((0, 1),)
    assert values["rax.2"].uses == ((0, 2),)
    assert values["rbx.0"].kind == "undef"
    assert values["rbx.0"].uses == ((0, 1),)
    assert values["rbx.1"].uses == ()

    # add writes FLAGS (pseudo-register), mov does not.
    assert values["FLAGS.1"].kind == "def"
    assert values["FLAGS.1"].def_insn_index == 1

    stats = fn.to_dict()["stats"]
    assert stats["value_count"] == len(values)
    assert stats["def_count"] == 4  # rax.1, rax.2, rbx.1, FLAGS.1
    assert stats["undef_count"] == 2  # rax.0, rbx.0
    assert stats["use_count"] == 4
    assert stats["loop_count"] == 0


def test_type_hints_from_width_and_lea(tmp_path: Path) -> None:
    fn = _ssa(tmp_path / "lea.bin", LEA)
    values = {value.id: value for value in fn.values}
    assert values["rax.1"].type_hint == "uint64_t *"
    assert values["rbx.0"].type_hint is None  # undef stays untyped (honest)


def test_no_type_hints_when_disabled(tmp_path: Path) -> None:
    fn = _ssa(tmp_path / "lea.bin", LEA, attach_types=False)
    values = {value.id: value for value in fn.values}
    assert values["rax.1"].type_hint is None


def test_abi_tables() -> None:
    assert abi_name(64) == "win64"
    assert abi_name(32) == "win32"
    assert abi_volatile_registers(64) == ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")
    assert abi_volatile_registers(32) == ("eax", "ecx", "edx")


def test_call_clobbers_volatile_but_rbx_survives(call_clobber: SSAFunction) -> None:
    fn = call_clobber
    block = fn.blocks[0]
    call = block.instructions[2]
    assert call.mnemonic == "call"
    # Argument passing: Win64 rcx, rdx, r8, r9 recorded on the call node.
    assert call.call_args == ("rcx.1", "rdx.0", "r8.0", "r9.0")
    assert call.reads == ("rcx.1", "rdx.0", "r8.0", "r9.0")

    values = {value.id: value for value in fn.values}
    # Volatile registers got fresh "clobber" versions after the call...
    for value_id in ("rax.1", "rcx.2", "rdx.1", "r8.1", "r9.1", "r10.1", "r11.1"):
        assert values[value_id].kind == "clobber"
    assert values["FLAGS.1"].kind == "clobber"
    # ...and the read after the call sees the clobbered rax, not the old one.
    assert block.instructions[4].reads == ("rbx.1",)
    assert block.instructions[4].writes == ("rax.2",)
    assert values["rax.2"].kind == "def"

    # rbx is non-volatile under Win64: same version before and after the call.
    assert values["rbx.1"].uses == ((0, 4),)
    assert [value_id for value_id in values if value_id.startswith("rbx.")] == ["rbx.1"]


def test_arg_registers_are_incoming_values(call_clobber: SSAFunction) -> None:
    values = {value.id: value for value in call_clobber.values}
    for value_id in ("rdx.0", "r8.0", "r9.0"):
        assert values[value_id].kind == "arg"
        assert values[value_id].def_block is None
        assert values[value_id].def_insn_index is None


def test_loop_boundary_marks_phi_required(loop: SSAFunction) -> None:
    fn = loop
    assert fn.loop_count == 1
    head = fn.blocks[0]
    assert isinstance(head, SSABlock)
    assert head.loop_boundary is True
    # Live-in at the loop head: dec reads rax, the conditional jump reads FLAGS.
    assert head.phi_required == ("FLAGS", "rax")
    assert fn.blocks[1].loop_boundary is False
    assert fn.blocks[1].phi_required == ()

    # Honest limitation: reads inside the loop body resolve to the
    # straight-line versions; no phi values were invented.
    assert [insn.mnemonic for insn in head.instructions] == ["mov", "dec", "jne"]
    assert head.instructions[2].reads == ("FLAGS.1",)
    assert head.instructions[2].writes == ()

    stats = fn.to_dict()["stats"]
    assert stats["loop_count"] == 1
    assert stats["truncated_blocks"] is False
    assert stats["truncated_instructions"] is False
    assert stats["truncated_values"] is False
    assert any("increment 1 limitation" in warning for warning in fn.warnings)


def test_value_budget_truncates_with_warning(tmp_path: Path) -> None:
    # Eight `mov eax, i` writes; a 3-value budget must stop construction early.
    code = b"".join(bytes([0xB8]) + index.to_bytes(4, "little") for index in range(8))
    fn = _ssa(tmp_path / "many.bin", code, max_values=3)

    assert fn.truncated_values is True
    assert fn.instruction_count == 3
    assert [value.id for value in fn.values] == ["rax.1", "rax.2", "rax.3"]
    assert any("max_values=3" in warning for warning in fn.warnings)
    stats = fn.to_dict()["stats"]
    assert stats["truncated_values"] is True
    assert stats["value_count"] == 3


def test_instruction_budget_truncates_with_warning(tmp_path: Path) -> None:
    code = b"\x90" * 20
    fn = _ssa(tmp_path / "nops.bin", code, max_instructions=5)

    assert fn.truncated_instructions is True
    assert fn.instruction_count == 5
    assert any("max_instructions=5" in warning for warning in fn.warnings)
    assert fn.to_dict()["stats"]["truncated_instructions"] is True


def test_determinism_is_byte_identical(tmp_path: Path) -> None:
    first = _ssa(tmp_path / "det_a.bin", CALL_CLOBBER)
    second = _ssa(tmp_path / "det_b.bin", CALL_CLOBBER)

    dumped_first = json.dumps(first.to_dict(), indent=1)
    dumped_second = json.dumps(second.to_dict(), indent=1)
    assert dumped_first == json.dumps(first.to_dict(), indent=1)
    assert dumped_first == dumped_second


def test_unknown_region_raises_typed_error(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "err.bin", STRAIGHT_LINE)
    info: BinaryInfo = BinaryLoader().load(sample)

    with pytest.raises(AnalysisError, match="executable"):
        build_ssa(sample, info, 0x999000)  # outside .text

    with pytest.raises(AnalysisError, match="max_instructions"):
        build_ssa(sample, info, TEXT_ADDRESS, max_instructions=0)
    with pytest.raises(AnalysisError, match="max_blocks"):
        build_ssa(sample, info, TEXT_ADDRESS, max_blocks=MAX_BLOCKS + 1)
    with pytest.raises(AnalysisError, match="max_values"):
        build_ssa(sample, info, TEXT_ADDRESS, max_values=0)
    with pytest.raises(AnalysisError, match="max_uses_per_value"):
        build_ssa(sample, info, TEXT_ADDRESS, max_uses_per_value=MAX_USES_PER_VALUE + 1)


def test_default_budgets_are_the_module_constants(tmp_path: Path) -> None:
    fn = _ssa(tmp_path / "defs.bin", STRAIGHT_LINE)
    assert MAX_BLOCKS == 512
    assert MAX_INSTRUCTIONS == 20_000
    assert MAX_VALUES == 4_096
    assert MAX_USES_PER_VALUE == 64
    assert DEFAULT_MAX_BLOCKS == 512
    assert DEFAULT_MAX_INSTRUCTIONS == 2_000
    assert isinstance(fn, SSAFunction)
    assert fn.evidence.source == "ir.ssa"
    assert fn.evidence.method == "cfg-straight-line-ssa"
    assert fn.evidence.confidence.value == "medium"


def test_mcp_wrapper_returns_json_payload(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "tool.bin", CALL_CLOBBER)

    payload = ext_ssa.codevanta_ssa(str(sample), TEXT_ADDRESS)

    assert payload["address"] == "0x401000"
    assert payload["evidence"]["source"] == "ir.ssa"
    assert payload["evidence"]["method"] == "cfg-straight-line-ssa"
    assert payload["evidence"]["confidence"] == "medium"
    assert payload["block_count"] == len(payload["blocks"])
    assert payload["stats"]["value_count"] == len(payload["values"])
    json.dumps(payload)  # every field must be JSON-safe


def test_mcp_wrapper_typed_errors(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "tool_err.bin", STRAIGHT_LINE)

    with pytest.raises(AnalysisError, match="file not found"):
        ext_ssa.codevanta_ssa(str(tmp_path / "missing.bin"), TEXT_ADDRESS)
    with pytest.raises(AnalysisError, match="address must be an int"):
        ext_ssa.codevanta_ssa(str(sample), "0x401000")
    with pytest.raises(AnalysisError, match="address must be positive"):
        ext_ssa.codevanta_ssa(str(sample), 0)
    with pytest.raises(AnalysisError, match="max_blocks must be between"):
        ext_ssa.codevanta_ssa(str(sample), TEXT_ADDRESS, max_blocks=0)
    with pytest.raises(AnalysisError, match="max_instructions must be between"):
        ext_ssa.codevanta_ssa(str(sample), TEXT_ADDRESS, max_instructions=10 ** 6)


def test_tool_is_reexported_through_tools_module() -> None:
    from codevanta.mcp_server import tools

    assert callable(tools.codevanta_ssa)
    assert tools.DEFAULT_SSA_MAX_BLOCKS == 512
    assert tools.DEFAULT_SSA_MAX_INSTRUCTIONS == 2_000


# ---- increment 2: expression folding + condition recovery ---------------------


def test_fold_binary_with_undefined_operand(tmp_path: Path) -> None:
    """`add rax, rbx` with an undefined rbx folds honestly against rbx.0."""
    fn = _ssa(tmp_path / "fold1.bin", bytes.fromhex("4889c04801d84889c3"))
    values = {value.id: value for value in fn.values}
    assert values["rax.2"].expr == "rax.1 + rbx.0"


def test_fold_immediate_and_self_clear(tmp_path: Path) -> None:
    """`add rax, 0x10` folds the constant; `xor rcx, rcx` clears to '0'."""
    fn = _ssa(tmp_path / "fold2.bin", bytes.fromhex("4883c0104831c9"))
    values = {value.id: value for value in fn.values}
    assert values["rax.1"].expr == "rax.0 + 0x10"
    assert values["rcx.1"].expr == "0"


def test_fold_copy_chain(tmp_path: Path) -> None:
    """mov chains collapse one link per move, ending at the root value."""
    fn = _ssa(tmp_path / "fold3.bin", STRAIGHT_LINE)
    values = {value.id: value for value in fn.values}
    assert values["rax.1"].expr == "rax.0"
    assert values["rax.2"].expr == "rax.1 + rbx.0"
    assert values["rbx.1"].expr == "rax.2"


def test_condition_recovery_on_jcc(tmp_path: Path) -> None:
    """cmp rax, rbx; je -> the jump carries the recovered condition."""
    fn = _ssa(tmp_path / "cond.bin", bytes.fromhex("4839d874029090"))
    je = fn.blocks[0].instructions[-1]
    assert je.mnemonic == "je"
    assert je.condition == {
        "cond": "je",
        "left": "rax.0",
        "right": "rbx.0",
        "raw": "cmp rax, rbx",
    }


def test_condition_cleared_by_flags_writer(tmp_path: Path) -> None:
    """cmp; add (rewrites FLAGS); je -> the comparison is stale, je has none."""
    code = bytes.fromhex("4839d84883c3017402")
    fn = _ssa(tmp_path / "cond2.bin", code)
    je = fn.blocks[0].instructions[-1]
    assert je.mnemonic == "je"
    assert je.condition is None


def test_folded_expr_is_json_safe_and_deterministic(tmp_path: Path) -> None:
    """Folded expressions survive JSON round-trips deterministically."""
    first = _ssa(tmp_path / "d1.bin", bytes.fromhex("4889c04801d84889c3"))
    payload = json.dumps(first.to_dict())
    assert "rax.1 + rbx.0" in payload
    second = _ssa(tmp_path / "d2.bin", bytes.fromhex("4889c04801d84889c3"))
    assert json.dumps(second.to_dict()) == payload




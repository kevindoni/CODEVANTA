"""Tests for bounded unicorn emulation over tiny synthetic ELF samples.

Every sample is assembled byte by byte with :mod:`struct` in this module, so the
tests stay self-contained: no shared fixtures, no real binaries, and no host code
is ever executed -- the bytes only ever run inside unicorn's emulator.

The module is skipped wholesale when unicorn is not installed, so the rest of
the suite keeps passing without the optional extra.

Note for Windows runs: unicorn's ``Uc.mem_map`` raises and handles a first-chance
access violation internally, which CPython's ``faulthandler`` (enabled by pytest)
prints even though nothing failed. The tests below do not depend on it; run with
``-p no:faulthandler`` to silence that message.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis import emulate
from codevanta.analysis.emulate import (
    DEFAULT_MAX_INSTRUCTIONS,
    EMULATOR_AVAILABLE,
    MAX_INITIAL_BLOCK_BYTES,
    MAX_INITIAL_BLOCKS,
    MAX_MAX_INSTRUCTIONS,
    EmulationResult,
    decrypt_string_loop,
    emulate_function,
    emulator_status,
    resolve_indirect_target,
    xor_bytes,
)
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError

pytest.importorskip("unicorn")

#: Virtual address of .text in the ELF64 samples.
TEXT_VA = 0x401000

#: Virtual address of .text in the ELF32 samples (conventional image base).
TEXT32_VA = 0x8048000

#: Address used by the ``initial_memory`` samples; nothing maps it.
BLOB_VA = 0x600000

#: An address no sample maps, used for the unmapped-access case.
UNMAPPED_VA = 0x700000

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHT_PROGBITS = 1
SHT_STRTAB = 3

_TEXT_OFFSET = 0x40
_SHSTRTAB = b"\x00.text\x00.shstrtab\x00"
_NAME_TEXT = 1
_NAME_SHSTRTAB = 7

#: x86-64 ``mov eax, 42; ret``.
CODE_MOV_EAX_42 = bytes.fromhex("b82a000000c3")

#: x86-64 ``mov rax, rdi; add rax, rsi; ret``.
CODE_ADD_RDI_RSI = bytes.fromhex("4889f8" "4801f0" "c3")

#: x86 ``mov eax, 42; ret``.
CODE_MOV_EAX_42_32 = bytes.fromhex("b82a000000c3")

#: x86-64 ``mov rax, [rbx]; ret``: faults when ``rbx`` is not mapped.
CODE_LOAD_RBX = bytes.fromhex("488b03" "c3")

#: x86-64 ``jmp rax`` -- a register-indirect branch.
CODE_JMP_RAX = bytes.fromhex("ffe0")

#: x86-64 ``jmp $`` -- spins forever, so only the budget can stop it.
CODE_SPIN = bytes.fromhex("ebfe")

#: The inline XOR decode loop used by the string sample:
#: ``xor byte [rdi], dl; inc rdi; dec ecx; jnz $-9; ret``.
CODE_XOR_LOOP = bytes.fromhex("3017" "48ffc7" "ffc9" "75f7" "c3")

#: ``call qword ptr [rip + 6]`` followed by the pointer slot it reads
#: (at +0x0c) and a ``ret`` at +0x20, so the indirect target is inside .text.
CODE_CALL_RIP_POINTER = (
    bytes.fromhex("ff1506000000" "909090909090")
    + (TEXT_VA + 0x20).to_bytes(8, "little")
    + b"\x90" * 12
    + b"\xc3"
)

#: Plaintext the XOR loop sample decrypts to.
XOR_PLAINTEXT = b"CodeVanta!"
XOR_KEY = 0x5A

#: Ciphertext placed in emulator memory for the XOR loop sample.


def _write_elf(path: Path, code: bytes, *, bits: int, va: int) -> Path:
    """Write a tiny ELF (32- or 64-bit) whose .text holds ``code``.

    The file has three sections (null, ``.text`` at ``va``, ``.shstrtab``), no
    program headers and no other content, which is enough for
    :class:`~codevanta.core.loader.BinaryLoader` and for emulation.

    Args:
        path: Destination file.
        code: Bytes placed at the start of ``.text``.
        bits: 32 or 64, selecting the ELF class.
        va: Virtual address of ``.text``.

    Returns:
        ``path``, written to disk.
    """
    text_offset = _TEXT_OFFSET
    shstr_offset = text_offset + len(code)
    sh_offset = (shstr_offset + len(_SHSTRTAB) + 7) & ~7
    blob = bytearray(sh_offset)
    if bits == 64:
        ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
        header = ident + struct.pack(
            "<HHIQQQIHHHHHH",
            2,                  # e_type = ET_EXEC
            62,                 # e_machine = EM_X86_64
            1,                  # e_version
            va,                 # e_entry
            0,                  # e_phoff
            sh_offset,          # e_shoff
            0,                  # e_flags
            64,                 # e_ehsize
            56,                 # e_phentsize
            0,                  # e_phnum
            64,                 # e_shentsize
            3,                  # e_shnum: null, .text, .shstrtab
            2,                  # e_shstrndx
        )
        text_header = struct.pack(
            "<IIQQQQIIQQ",
            _NAME_TEXT, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
            va, text_offset, len(code), 0, 0, 16, 0,
        )
        str_header = struct.pack(
            "<IIQQQQIIQQ",
            _NAME_SHSTRTAB, SHT_STRTAB, 0, 0, shstr_offset, len(_SHSTRTAB), 0, 0, 1, 0,
        )
    else:
        ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + bytes(8)
        header = ident + struct.pack(
            "<HHIIIIIHHHHHH",
            2,                  # e_type = ET_EXEC
            3,                  # e_machine = EM_386
            1,                  # e_version
            va,                 # e_entry
            0,                  # e_phoff
            sh_offset,          # e_shoff
            0,                  # e_flags
            52,                 # e_ehsize
            40,                 # e_phentsize
            0,                  # e_phnum
            40,                 # e_shentsize
            3,                  # e_shnum
            2,                  # e_shstrndx
        )
        text_header = struct.pack(
            "<IIIIIIIIII",
            _NAME_TEXT, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
            va, text_offset, len(code), 0, 0, 16, 0,
        )
        str_header = struct.pack(
            "<IIIIIIIIII",
            _NAME_SHSTRTAB, SHT_STRTAB, 0, 0, shstr_offset, len(_SHSTRTAB), 0, 0, 1, 0,
        )
    blob[0 : len(header)] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[shstr_offset : shstr_offset + len(_SHSTRTAB)] = _SHSTRTAB
    blob += bytes(64 if bits == 64 else 40) + text_header + str_header
    path.write_bytes(bytes(blob))
    return path


def _sample(tmp_path: Path, code: bytes, *, bits: int = 64, name: str = "sample.elf") -> Path:
    """Write a sample ELF with ``code`` in ``.text`` at the matching base address."""
    va = TEXT_VA if bits == 64 else TEXT32_VA
    return _write_elf(tmp_path / name, code, bits=bits, va=va)


def _load(path: Path) -> BinaryInfo:
    """Load a sample through the real loader."""
    return BinaryLoader().load(path)



# ---- emulator availability ------------------------------------------------


def test_emulator_reports_available() -> None:
    assert EMULATOR_AVAILABLE is True
    assert emulator_status() == ""


# ---- return values --------------------------------------------------------


def test_mov_eax_42_returns_42(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="ret42.elf")
    info = _load(path)

    result = emulate_function(path, info, TEXT_VA)

    assert isinstance(result, EmulationResult)
    assert result.stopped_reason == "return"
    assert result.return_value == 42
    assert result.registers["rax"] == 42
    assert result.registers["rip"] == TEXT_VA + 5  # the ret itself never ran
    assert result.instructions == 1  # only the mov completed
    assert result.warnings == ()


def test_register_arithmetic_uses_initial_registers(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_ADD_RDI_RSI, name="add.elf")
    info = _load(path)

    result = emulate_function(
        path, info, TEXT_VA, initial_registers={"rdi": 2, "rsi": 3}
    )

    assert result.stopped_reason == "return"
    assert result.return_value == 5
    assert result.registers["rax"] == 5


def test_elf32_sample_returns_value(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42_32, bits=32, name="ret42_32.elf")
    info = _load(path)

    assert info.bitness == 32
    result = emulate_function(path, info, TEXT32_VA)

    assert result.stopped_reason == "return"
    assert result.return_value == 42
    assert result.registers["eax"] == 42
    assert result.evidence.extra["bitness"] == 32


def test_stack_pointer_points_into_the_mapped_stack(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="stack.elf")
    info = _load(path)

    result = emulate_function(path, info, TEXT_VA)

    regions = result.evidence.extra["regions"]
    stack = next(region for region in regions if region["kind"] == "stack")
    base = int(stack["start"], 16)
    top = int(stack["end"], 16)
    assert base <= result.registers["rsp"] < top
    assert result.registers["rbp"] == result.registers["rsp"]


# ---- instruction budget ---------------------------------------------------


def test_budget_exhaustion_is_reported(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_SPIN, name="spin.elf")
    info = _load(path)

    result = emulate_function(path, info, TEXT_VA, max_instructions=5)

    assert result.stopped_reason == "budget"
    assert result.instructions == 5
    assert result.return_value is None  # a partial run has no return value
    assert any("truncated" in warning for warning in result.warnings)


def test_budget_above_the_ceiling_is_rejected(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="budget.elf")
    info = _load(path)

    with pytest.raises(AnalysisError):
        emulate_function(path, info, TEXT_VA, max_instructions=MAX_MAX_INSTRUCTIONS + 1)
    with pytest.raises(AnalysisError):
        emulate_function(path, info, TEXT_VA, max_instructions=0)


def test_default_budget_is_the_documented_constant(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="default.elf")
    info = _load(path)

    result = emulate_function(path, info, TEXT_VA)

    assert result.evidence.extra["max_instructions"] == DEFAULT_MAX_INSTRUCTIONS


# ---- faults ---------------------------------------------------------------


def test_unmapped_read_is_reported_not_raised(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_LOAD_RBX, name="unmapped.elf")
    info = _load(path)

    result = emulate_function(path, info, TEXT_VA, initial_registers={"rbx": UNMAPPED_VA})

    assert result.stopped_reason == "unmapped"
    assert result.return_value is None
    detail = " ".join(result.warnings)
    assert "unmapped" in detail
    assert f"0x{UNMAPPED_VA:x}" in detail  # the exact faulting address
    assert result.instructions == 0  # the faulting load never completed


def test_unsupported_architecture_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="arm.elf")
    info = _load(path)
    monkeypatch.setattr(info, "architecture", "aarch64")

    result = emulate_function(path, info, TEXT_VA)

    assert result.stopped_reason == "unsupported"
    assert result.instructions == 0
    assert result.return_value is None
    assert result.registers == {}
    assert any("x86" in warning for warning in result.warnings)
    assert result.evidence.confidence.value == "unknown"



# ---- indirect branches ----------------------------------------------------


def test_resolve_indirect_target_returns_seeded_target(tmp_path: Path) -> None:
    # ``jmp rax`` followed by nops and a ``ret`` at +0x10.
    path = _sample(
        tmp_path, CODE_JMP_RAX + b"\x90" * 14 + b"\xc3", name="jmp_rax.elf"
    )
    info = _load(path)
    target = TEXT_VA + 0x10

    resolved = resolve_indirect_target(
        path, info, TEXT_VA, initial_registers={"rax": target}
    )

    assert resolved == target


def test_emulation_records_indirect_targets(tmp_path: Path) -> None:
    path = _sample(
        tmp_path, CODE_JMP_RAX + b"\x90" * 14 + b"\xc3", name="jmp_rax2.elf"
    )
    info = _load(path)
    target = TEXT_VA + 0x10

    result = emulate_function(path, info, TEXT_VA, initial_registers={"rax": target})

    assert result.indirect_targets == (target,)
    assert result.stopped_reason == "return"
    assert result.warnings == ()


def test_resolve_indirect_target_reads_a_pointer_slot(tmp_path: Path) -> None:
    """``call qword ptr [rip+6]`` resolves through the pointer it points at."""
    path = _sample(tmp_path, CODE_CALL_RIP_POINTER, name="call_rip.elf")
    info = _load(path)

    resolved = resolve_indirect_target(path, info, TEXT_VA)

    assert resolved == TEXT_VA + 0x20


def test_unsupported_machine_never_emulates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="nomachine.elf")
    info = _load(path)
    monkeypatch.setattr(emulate, "_machine_bits", lambda _info: None)

    result = emulate_function(path, info, TEXT_VA)

    assert result.stopped_reason == "unsupported"
    assert result.instructions == 0
    assert resolve_indirect_target(path, info, TEXT_VA) is None


def test_missing_emulator_is_reported_as_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the optional extra the API degrades instead of raising."""
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="noemulator.elf")
    info = _load(path)
    monkeypatch.setattr(emulate, "EMULATOR_AVAILABLE", False)
    monkeypatch.setattr(emulate, "_UNICORN_ERROR", "unicorn is not importable: test")

    result = emulate_function(path, info, TEXT_VA)

    assert result.stopped_reason == "unsupported"
    assert result.warnings == (
        "the emulator is unavailable; unicorn is not importable: test, so no code was run",
    )
    assert result.evidence.extra["emulator_status"] == "unicorn is not importable: test"


def test_resolve_indirect_target_returns_none_without_indirect_branch(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="noindirect.elf")
    info = _load(path)

    assert resolve_indirect_target(path, info, TEXT_VA) is None


def test_resolve_indirect_target_returns_none_on_budget(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_SPIN, name="spin2.elf")
    info = _load(path)

    assert resolve_indirect_target(path, info, TEXT_VA, max_instructions=3) is None


# ---- string-decoding primitives -------------------------------------------


def test_xor_bytes_round_trip() -> None:
    data = b"plain text bytes"

    ciphertext = xor_bytes(data, 0x5A)

    assert ciphertext != data
    assert xor_bytes(ciphertext, 0x5A) == data
    assert xor_bytes(data, 0x15A) == xor_bytes(data, 0x5A)  # only 8 bits take part


def test_decrypt_string_loop_stops_at_the_terminator() -> None:
    ciphertext = XOR_CIPHERTEXT

    assert decrypt_string_loop(ciphertext, XOR_KEY) == XOR_PLAINTEXT
    assert decrypt_string_loop(ciphertext, XOR_KEY, terminators=()) == (
        XOR_PLAINTEXT + b"\x00"
    )


def test_decrypt_string_loop_rolling_key_and_add_encoder() -> None:
    plaintext = b"rolling"
    rolling = bytes(
        (byte + (0x10 + index)) & 0xFF for index, byte in enumerate(plaintext)
    )

    assert decrypt_string_loop(rolling, 0x10, key_step=1, op="add") == plaintext
    subtractive = bytes(
        (byte - (0x20 + index)) & 0xFF for index, byte in enumerate(plaintext)
    )
    assert decrypt_string_loop(subtractive, 0x20, key_step=1, op="sub") == plaintext


def test_decrypt_string_loop_rejects_unknown_op() -> None:
    with pytest.raises(AnalysisError):
        decrypt_string_loop(b"data", 1, op="rol")


def test_xor_loop_emulation_transcript(tmp_path: Path) -> None:
    """The end-to-end case: emulate the decode loop, then describe the primitive."""
    path = _sample(tmp_path, CODE_XOR_LOOP, name="xorloop.elf")
    info = _load(path)

    result = emulate_function(
        path,
        info,
        TEXT_VA,
        initial_registers={
            "rdi": BLOB_VA,
            "rcx": len(XOR_CIPHERTEXT),
            "rdx": XOR_KEY,
        },
        initial_memory={BLOB_VA: XOR_CIPHERTEXT},
    )

    assert result.stopped_reason == "return"
    assert result.warnings == ()
    assert result.instructions == 4 * len(XOR_CIPHERTEXT)  # 11 iterations, ret not run
    assert result.registers["rdi"] == BLOB_VA + len(XOR_CIPHERTEXT)
    assert result.registers["rcx"] & 0xFFFFFFFF == 0  # ``dec ecx`` counted down to zero

    decoded = bytearray(len(XOR_CIPHERTEXT))
    for address, data in result.memory_writes:
        if BLOB_VA <= address < BLOB_VA + len(XOR_CIPHERTEXT):
            offset = address - BLOB_VA
            decoded[offset : offset + len(data)] = data
    assert bytes(decoded) == XOR_PLAINTEXT + b"\x00"

    # The key recovered from ``dl`` reinterprets the blob without executing it.
    assert decrypt_string_loop(XOR_CIPHERTEXT, result.registers["rdx"]) == XOR_PLAINTEXT
    assert xor_bytes(XOR_CIPHERTEXT, XOR_KEY).split(b"\x00")[0] == XOR_PLAINTEXT



def test_memory_writes_are_bounded(tmp_path: Path) -> None:
    """A long decode loop cannot blow the transcript up: writes are capped."""
    path = _sample(tmp_path, CODE_XOR_LOOP, name="many_writes.elf")
    info = _load(path)
    blob = bytes(index & 0xFF ^ XOR_KEY for index in range(300)) + b"\x00"

    result = emulate_function(
        path,
        info,
        TEXT_VA,
        initial_registers={"rdi": BLOB_VA, "rcx": len(blob), "rdx": XOR_KEY},
        initial_memory={BLOB_VA: blob},
    )

    assert result.stopped_reason == "return"
    assert len(result.memory_writes) == 256
    assert any("were not recorded" in warning for warning in result.warnings)
    assert result.evidence.extra["dropped_memory_writes"] == len(blob) - 256


# ---- serialization and evidence -------------------------------------------


def test_to_dict_is_json_safe(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_XOR_LOOP, name="dict.elf")
    info = _load(path)
    result = emulate_function(
        path,
        info,
        TEXT_VA,
        initial_registers={"rdi": BLOB_VA, "rcx": 2, "rdx": 0x11},
        initial_memory={BLOB_VA: b"\x01\x02\x00"},
    )

    payload = result.to_dict()
    text = json.dumps(payload)  # no bytes, no Paths, no enums
    reloaded = json.loads(text)

    assert reloaded["address"] == f"0x{TEXT_VA:x}"
    assert reloaded["stopped_reason"] == "return"
    assert isinstance(reloaded["instructions"], int)
    assert isinstance(reloaded["registers"], dict)
    assert all(isinstance(value, str) for value in reloaded["registers"].values())
    assert isinstance(reloaded["memory_writes"], list)
    assert isinstance(reloaded["warnings"], list)
    assert isinstance(reloaded["evidence"], dict)


def test_evidence_describes_the_run(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="evidence.elf")
    info = _load(path)

    result = emulate_function(path, info, TEXT_VA, max_instructions=50)

    assert result.evidence.source == "emulate.unicorn"
    assert result.evidence.address == TEXT_VA
    assert result.evidence.extra["stopped_reason"] == "return"
    assert result.evidence.extra["max_instructions"] == 50
    assert result.evidence.extra["bitness"] == 64
    assert result.evidence.extra["stack_size"] > 0
    kinds = {region["kind"] for region in result.evidence.extra["regions"]}
    assert {"image", "stack"} <= kinds


# ---- caller mistakes ------------------------------------------------------


def test_address_outside_executable_section_raises(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="badsel.elf")
    info = _load(path)
    data_section = next(s for s in info.sections if s.name == ".shstrtab")

    with pytest.raises(AnalysisError):
        emulate_function(path, info, data_section.virtual_address)
    with pytest.raises(AnalysisError):
        emulate_function(path, info, 0x900000)  # not mapped by any section


def test_unknown_register_name_raises(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="badreg.elf")
    info = _load(path)

    with pytest.raises(AnalysisError):
        emulate_function(path, info, TEXT_VA, initial_registers={"nope": 1})
    with pytest.raises(AnalysisError):
        emulate_function(path, info, TEXT_VA, initial_registers={"eax": -1})


def test_initial_memory_limits_are_enforced(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="badmem.elf")
    info = _load(path)

    too_many = {BLOB_VA + index * 0x1000: b"\x01" for index in range(MAX_INITIAL_BLOCKS + 1)}
    with pytest.raises(AnalysisError):
        emulate_function(path, info, TEXT_VA, initial_memory=too_many)
    with pytest.raises(AnalysisError):
        emulate_function(
            path, info, TEXT_VA, initial_memory={BLOB_VA: b"\x00" * (MAX_INITIAL_BLOCK_BYTES + 1)}
        )


def test_stack_size_limits_are_enforced(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="badstack.elf")
    info = _load(path)

    with pytest.raises(AnalysisError):
        emulate_function(path, info, TEXT_VA, stack_size=0)

XOR_CIPHERTEXT = bytes(byte ^ XOR_KEY for byte in XOR_PLAINTEXT + b"\x00")

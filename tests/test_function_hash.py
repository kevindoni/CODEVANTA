"""Function fingerprint tests (normalization, determinism, bounds, evidence)."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis.function_hash import (
    DEFAULT_MAX_INSTRUCTIONS,
    MAX_MAX_INSTRUCTIONS,
    FunctionFingerprint,
    function_fingerprint,
    normalize_instruction,
)
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.ir.instruction import IRInstruction

TEXT_VA = 0x401000
DATA_VA = 0x402000

#: ``mov eax, 0x2a; ret`` -- the immediate differs between fixtures, the shape does not.
MOV_RET_42 = bytes.fromhex("b82a000000c3")

#: ``mov eax, 0x63; ret``
MOV_RET_99 = bytes.fromhex("b863000000c3")

#: ``push rbp; mov rbp, rsp; ret``
PROLOGUE = bytes.fromhex("554889e5c3")

NOP = bytes.fromhex("90")
RET = bytes.fromhex("c3")


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
    text_section = struct.pack(
        "<IIQQQQIIQQ", 1, 1, 6, entry, off_text, len(code), 0, 0, 16, 0
    )
    data_section = struct.pack(
        "<IIQQQQIIQQ", 7, 1, 3, DATA_VA, off_data, len(data), 0, 0, 8, 0
    )
    str_section = struct.pack(
        "<IIQQQQIIQQ", 13, 3, 0, 0, off_shstr, len(shstr), 0, 0, 1, 0
    )
    blob = bytearray(shoff)
    blob[0:64] = header
    blob[off_text:off_text + len(code)] = code
    blob[off_data:off_data + len(data)] = data
    blob[off_shstr:off_shstr + len(shstr)] = shstr
    blob += null_section + text_section + data_section + str_section
    path.write_bytes(blob)
    return path


def _load(path: Path) -> BinaryInfo:
    """Load a fixture binary with the production loader."""
    return BinaryLoader().load(path)


def _fingerprint(path: Path, code: bytes, **kwargs: object) -> FunctionFingerprint:
    """Build a fixture with ``code`` at :data:`TEXT_VA` and fingerprint it."""
    binary = _make_elf64(path, code)
    info = _load(binary)
    return function_fingerprint(binary, info, TEXT_VA, **kwargs)  # type: ignore[arg-type]



def test_identical_code_produces_the_same_digest(tmp_path: Path) -> None:
    left = _fingerprint(tmp_path / "left.bin", PROLOGUE)
    right = _fingerprint(tmp_path / "right.bin", PROLOGUE)

    assert left.digest == right.digest
    assert len(left.digest) == 64
    assert left.instruction_count == right.instruction_count == 3
    assert left.truncated is False
    assert left.address == TEXT_VA


def test_fingerprint_is_deterministic_across_loads(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "sample.bin", PROLOGUE)
    info = _load(binary)

    first = function_fingerprint(binary, info, TEXT_VA)
    second = function_fingerprint(binary, _load(binary), TEXT_VA)

    assert first.digest == second.digest
    assert first.to_dict() == second.to_dict()


def test_digest_is_sha256_of_the_normalized_stream(tmp_path: Path) -> None:
    # "mov eax, 0x2a" and "ret" normalize to "mov eax, #" and "ret".
    expected = hashlib.sha256(b"mov eax, #\nret").hexdigest()

    fingerprint = _fingerprint(tmp_path / "immediate.bin", MOV_RET_42)

    assert fingerprint.instruction_count == 2
    assert fingerprint.digest == expected


def test_differing_immediates_normalize_to_the_same_digest(tmp_path: Path) -> None:
    left = _fingerprint(tmp_path / "left.bin", MOV_RET_42)
    right = _fingerprint(tmp_path / "right.bin", MOV_RET_99)

    assert left.digest == right.digest
    assert left.digest == hashlib.sha256(b"mov eax, #\nret").hexdigest()


def test_nop_and_ret_at_the_same_address_have_different_digests(tmp_path: Path) -> None:
    nop = _fingerprint(tmp_path / "nop.bin", NOP)
    ret = _fingerprint(tmp_path / "ret.bin", RET)

    assert nop.address == ret.address == TEXT_VA
    assert nop.digest != ret.digest
    assert nop.digest == hashlib.sha256(b"nop").hexdigest()
    assert ret.digest == hashlib.sha256(b"ret").hexdigest()


def test_instruction_count_and_truncation_are_reported(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "truncated.bin", NOP * 3 + RET)
    info = _load(binary)

    full = function_fingerprint(binary, info, TEXT_VA)
    cut = function_fingerprint(binary, info, TEXT_VA, max_instructions=2)

    assert full.instruction_count == 4
    assert full.truncated is False
    assert cut.instruction_count == 2
    assert cut.truncated is True
    assert cut.digest != full.digest
    assert "truncated" in (cut.evidence.detail or "")


def test_evidence_is_shape_based_and_medium_confidence(tmp_path: Path) -> None:
    fingerprint = _fingerprint(tmp_path / "evidence.bin", PROLOGUE)

    assert fingerprint.evidence.source == "function_hash.normalized"
    assert fingerprint.evidence.method == "normalized_linear_disassembly"
    assert fingerprint.evidence.confidence is Confidence.MEDIUM
    assert fingerprint.evidence.address == TEXT_VA
    assert "shape" in (fingerprint.evidence.detail or "")
    assert "#" in (fingerprint.evidence.detail or "")
    assert fingerprint.evidence.extra["algorithm"] == "sha256"
    assert fingerprint.evidence.extra["max_instructions"] == DEFAULT_MAX_INSTRUCTIONS
    assert fingerprint.evidence.extra["truncated"] is False


def test_to_dict_is_json_serialisable(tmp_path: Path) -> None:
    payload = _fingerprint(tmp_path / "json.bin", PROLOGUE).to_dict()

    text = json.dumps(payload)  # must not raise

    assert payload["address"] == "0x401000"
    assert payload["algorithm"] == "sha256"
    assert payload["instruction_count"] == 3
    assert payload["truncated"] is False
    assert payload["evidence"]["source"] == "function_hash.normalized"
    assert json.loads(text)["digest"] == payload["digest"]



def test_address_outside_an_executable_section_raises(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "sections.bin", PROLOGUE, data=b"\x01\x02\x03\x04")
    info = _load(binary)

    with pytest.raises(AnalysisError, match="executable"):
        function_fingerprint(binary, info, DATA_VA)
    with pytest.raises(AnalysisError, match="executable"):
        function_fingerprint(binary, info, 0)
    with pytest.raises(AnalysisError):
        function_fingerprint(binary, info, 0xDEAD0000)


def test_invalid_max_instructions_raises(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "limits.bin", PROLOGUE)
    info = _load(binary)

    for bad in (0, -1, MAX_MAX_INSTRUCTIONS + 1, "many", True):
        with pytest.raises(AnalysisError):
            function_fingerprint(binary, info, TEXT_VA, max_instructions=bad)  # type: ignore[arg-type]


def test_non_integer_address_raises(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "address.bin", PROLOGUE)
    info = _load(binary)

    for bad in ("0x401000", None, True, -0x10):
        with pytest.raises(AnalysisError):
            function_fingerprint(binary, info, bad)  # type: ignore[arg-type]


def test_normalize_instruction_masks_numbers_but_keeps_register_names() -> None:
    def insn(mnemonic: str, operands: str) -> IRInstruction:
        return IRInstruction(
            address=TEXT_VA, size=4, mnemonic=mnemonic, operands=operands, raw_bytes=b"\x90"
        )

    assert normalize_instruction(insn("mov", "eax, 0x2a")) == "mov eax, #"
    assert normalize_instruction(insn("mov", "eax, 0x63")) == "mov eax, #"
    assert normalize_instruction(insn("lea", "rax, [rbp - 0x10]")) == "lea rax, [rbp - #]"
    # Register names that merely contain digits survive untouched.
    assert normalize_instruction(insn("stp", "x29, x30, [sp, #-0x10]!")) == (
        "stp x29, x30, [sp, #]!"
    )
    # ARM writes immediates as "#0x1"; the collapsed mask matches x86's "0x1".
    assert normalize_instruction(insn("mov", "r0, #0x1")) == "mov r0, #"
    # Bare decimals are masked too, and mnemonics are lower-cased.
    assert normalize_instruction(insn("ADD", "eax, 1")) == "add eax, #"
    assert normalize_instruction(insn("Ret", "")) == "ret"

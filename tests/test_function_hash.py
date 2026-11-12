"""Function fingerprint tests (normalization, determinism, bounds, evidence, similarity)."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from codevanta.analysis import function_hash as function_hash_module
from codevanta.analysis.function_hash import (
    DEFAULT_MAX_INSTRUCTIONS,
    MAX_MAX_INSTRUCTIONS,
    FunctionFingerprint,
    SimilarityResult,
    function_fingerprint,
    function_similarity,
    normalize_instruction,
    normalized_tokens,
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


def _pair(
    tmp_path: Path, code_a: bytes, code_b: bytes
) -> tuple[Path, BinaryInfo, Path, BinaryInfo]:
    """Build two fixtures (``code_a`` as ``left.bin``, ``code_b`` as ``right.bin``)."""
    left = _make_elf64(tmp_path / "left.bin", code_a)
    right = _make_elf64(tmp_path / "right.bin", code_b)
    return left, _load(left), right, _load(right)


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


# --- normalized tokens (the reusable helper behind the digest) --------------


def test_normalized_tokens_are_the_hashed_strings(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "tokens.bin", MOV_RET_42)
    info = _load(binary)

    tokens = normalized_tokens(binary, info, TEXT_VA)
    fingerprint = function_fingerprint(binary, info, TEXT_VA)

    assert tokens == ("mov eax, #", "ret")
    assert isinstance(tokens, tuple)
    assert len(tokens) == fingerprint.instruction_count
    assert hashlib.sha256("\n".join(tokens).encode("utf-8")).hexdigest() == fingerprint.digest


def test_digest_is_unchanged_by_the_token_refactor(tmp_path: Path) -> None:
    # The pre-refactor value, re-derived from first principles: "mov eax, 0x2a"
    # normalizes to "mov eax, #", is joined with "\n" and hashed with SHA-256.
    assert function_hash_module.DIGEST_ALGORITHM == "sha256"
    expected = hashlib.sha256(b"mov eax, #\nret").hexdigest()

    fingerprint = _fingerprint(tmp_path / "unchanged.bin", MOV_RET_42)

    assert fingerprint.digest == expected
    assert fingerprint.to_dict()["digest"] == expected


def test_normalized_tokens_are_bounded_by_the_instruction_budget(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "budget.bin", NOP * 3 + RET)
    info = _load(binary)

    assert normalized_tokens(binary, info, TEXT_VA) == ("nop", "nop", "nop", "ret")
    assert normalized_tokens(binary, info, TEXT_VA, max_instructions=2) == ("nop", "nop")


def test_normalized_tokens_reject_invalid_bounds(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "bounds.bin", PROLOGUE)
    info = _load(binary)

    for bad in (0, -1, MAX_MAX_INSTRUCTIONS + 1, "many", True):
        with pytest.raises(AnalysisError):
            normalized_tokens(binary, info, TEXT_VA, max_instructions=bad)  # type: ignore[arg-type]
    for bad_address in ("0x401000", None, True, -0x10):
        with pytest.raises(AnalysisError):
            normalized_tokens(binary, info, bad_address)  # type: ignore[arg-type]


# --- multiset similarity ----------------------------------------------------


def test_identical_regions_score_one(tmp_path: Path) -> None:
    left, info_a, right, info_b = _pair(tmp_path, PROLOGUE, PROLOGUE)

    result = function_similarity(left, info_a, TEXT_VA, right, info_b, TEXT_VA)

    assert isinstance(result, SimilarityResult)
    assert result.score == 1.0
    assert result.shared == 3
    assert result.left_total == result.right_total == 3
    assert result.union == 3
    assert result.warnings == ()


def test_masked_immediates_still_score_one(tmp_path: Path) -> None:
    left, info_a, right, info_b = _pair(tmp_path, MOV_RET_42, MOV_RET_99)

    result = function_similarity(left, info_a, TEXT_VA, right, info_b, TEXT_VA)

    assert result.score == 1.0


def test_disjoint_regions_score_zero(tmp_path: Path) -> None:
    left, info_a, right, info_b = _pair(tmp_path, NOP, RET)

    result = function_similarity(left, info_a, TEXT_VA, right, info_b, TEXT_VA)

    assert result.score == 0.0
    assert result.shared == 0
    assert result.left_total == result.right_total == 1
    assert result.union == 2


def test_one_shared_token_of_two_scores_one_half(tmp_path: Path) -> None:
    # One fixture: left = "nop; ret" at TEXT_VA, right = "ret" at TEXT_VA + 1.
    binary = _make_elf64(tmp_path / "half.bin", NOP + RET)
    info = _load(binary)

    result = function_similarity(binary, info, TEXT_VA, binary, info, TEXT_VA + 1)

    assert result.shared == 1
    assert result.left_total == 2
    assert result.right_total == 1
    assert result.union == 2
    assert result.score == 0.5
    # sum(min)/sum(max) is symmetric, so swapping the sides cannot change it.
    swapped = function_similarity(binary, info, TEXT_VA + 1, binary, info, TEXT_VA)
    assert swapped.score == 0.5


def test_similarity_respects_token_multiplicity(tmp_path: Path) -> None:
    # left = "nop; nop; ret", right = "nop; ret": sum(min) = 2, sum(max) = 3.
    binary = _make_elf64(tmp_path / "multiset.bin", NOP * 2 + RET)
    info = _load(binary)

    result = function_similarity(binary, info, TEXT_VA, binary, info, TEXT_VA + 1)

    assert (result.shared, result.left_total, result.right_total) == (2, 3, 2)
    assert result.union == 3
    assert result.score == pytest.approx(2 / 3)
    assert result.to_dict()["score"] == 0.6667


def test_similarity_is_deterministic_across_loads(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "repeat.bin", NOP + RET)
    info = _load(binary)
    other = _load(binary)

    first = function_similarity(binary, info, TEXT_VA, binary, info, TEXT_VA + 1)
    second = function_similarity(binary, other, TEXT_VA, binary, other, TEXT_VA + 1)

    assert first.score == second.score
    assert first.to_dict() == second.to_dict()


def test_similarity_evidence_is_shape_based_and_medium_confidence(tmp_path: Path) -> None:
    left, info_a, right, info_b = _pair(tmp_path, PROLOGUE, RET)

    result = function_similarity(left, info_a, TEXT_VA, right, info_b, TEXT_VA)
    evidence = result.evidence

    assert evidence.source == "function_hash.similarity"
    assert evidence.method == "token_multiset"
    assert evidence.confidence is Confidence.MEDIUM
    assert evidence.address == TEXT_VA
    detail = evidence.detail or ""
    assert "shape" in detail
    assert "semantic" in detail  # the shape-not-semantics caveat
    assert "not" in detail
    assert "#" in detail
    assert evidence.extra["left_address"] == "0x401000"
    assert evidence.extra["right_address"] == "0x401000"
    assert evidence.extra["union"] == 3  # 3 left tokens + 1 right token - 1 shared
    assert evidence.extra["max_instructions"] == DEFAULT_MAX_INSTRUCTIONS
    assert evidence.extra["left_truncated"] is False
    assert evidence.extra["right_truncated"] is False


def test_similarity_to_dict_is_json_serialisable_and_rounds_the_score(tmp_path: Path) -> None:
    left, info_a, right, info_b = _pair(tmp_path, NOP * 2 + RET, RET)

    result = function_similarity(left, info_a, TEXT_VA, right, info_b, TEXT_VA)
    payload = result.to_dict()
    text = json.dumps(payload)  # must not raise

    # sum(min) = 1, sum(max) = 3 -> 0.333..., serialized with 4 decimals.
    assert payload["score"] == 0.3333
    assert payload["shared"] == 1
    assert payload["left_total"] == 3
    assert payload["right_total"] == 1
    assert payload["union"] == 3
    assert payload["warnings"] == []
    assert payload["evidence"]["source"] == "function_hash.similarity"
    assert json.loads(text)["score"] == payload["score"]


def test_similarity_warns_when_a_side_was_truncated(tmp_path: Path) -> None:
    left, info_a, right, info_b = _pair(tmp_path, NOP * 3 + RET, NOP * 3 + RET)

    full = function_similarity(left, info_a, TEXT_VA, right, info_b, TEXT_VA)
    cut = function_similarity(left, info_a, TEXT_VA, right, info_b, TEXT_VA, max_instructions=2)

    assert full.warnings == ()
    assert len(cut.warnings) == 2
    assert all("truncated" in warning for warning in cut.warnings)
    assert cut.left_total == cut.right_total == 2
    assert cut.evidence.extra["left_truncated"] is True
    assert cut.evidence.extra["right_truncated"] is True
    assert list(cut.to_dict()["warnings"]) == list(cut.warnings)


def test_similarity_rejects_invalid_addresses(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "invalid.bin", PROLOGUE, data=b"\x01\x02\x03\x04")
    info = _load(binary)

    for bad in ("0x401000", None, True, -0x10):
        with pytest.raises(AnalysisError):
            function_similarity(binary, info, bad, binary, info, TEXT_VA)  # type: ignore[arg-type]
        with pytest.raises(AnalysisError):
            function_similarity(binary, info, TEXT_VA, binary, info, bad)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="executable"):
        function_similarity(binary, info, DATA_VA, binary, info, TEXT_VA)
    with pytest.raises(AnalysisError, match="executable"):
        function_similarity(binary, info, TEXT_VA, binary, info, DATA_VA)
    with pytest.raises(AnalysisError):
        function_similarity(binary, info, TEXT_VA, binary, info, 0xDEAD0000)


def test_similarity_rejects_invalid_max_instructions(tmp_path: Path) -> None:
    binary = _make_elf64(tmp_path / "limits2.bin", PROLOGUE)
    info = _load(binary)

    for bad in (0, -1, MAX_MAX_INSTRUCTIONS + 1, "many", True):
        with pytest.raises(AnalysisError):
            function_similarity(
                binary,
                info,
                TEXT_VA,
                binary,
                info,
                TEXT_VA,
                max_instructions=bad,  # type: ignore[arg-type]
            )


def test_similarity_rejects_an_empty_token_multiset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A real sweep never yields zero tokens (an undecodable region raises), so
    # the defensive guard is exercised by stubbing the internal sweep: a score
    # against an empty multiset would be a meaningless 0.0 instead of an error.
    binary = _make_elf64(tmp_path / "empty.bin", PROLOGUE)
    info = _load(binary)
    real_sweep = function_hash_module._sweep
    calls: list[int] = []

    def stub_sweep(path: object, target: object, address: int, budget: int) -> object:
        calls.append(address)
        if len(calls) == 1:  # left side is real, the right side is empty
            return real_sweep(path, target, address, budget)  # type: ignore[arg-type]
        return SimpleNamespace(
            tokens=(),
            truncated=False,
            consumed_bytes=0,
            buffer_bytes=0,
            address=address,
            max_instructions=budget,
        )

    monkeypatch.setattr(function_hash_module, "_sweep", stub_sweep)

    with pytest.raises(AnalysisError, match="no instruction tokens"):
        function_similarity(binary, info, TEXT_VA, binary, info, TEXT_VA)
    assert len(calls) == 2

"""Tests for the solver-based symbolic explorer over tiny synthetic ELF samples.

Every sample is assembled byte by byte with :mod:`struct` in this module (the
builder is copied from :mod:`tests.test_symbolic`), so the tests stay
self-contained: no shared fixtures, no real binaries, and no host code is ever
executed -- the bytes only ever run inside angr's simulated CPU.

The module is skipped wholesale when angr is not installed (the
``decompile-parity`` CI job is where angr is real; a plain ``pip install -e
".[decompilers]"`` enables it anywhere), so the rest of the suite keeps passing
without the optional extra. What these tests pin down: a straight-line function
yields one path whose concrete inputs are the seeded registers and whose return
value is their sum; a two-way conditional yields both sides with their solved
constraints and return values; a tiny step budget truncates the exploration and
flags it; unsupported architectures and a missing angr raise
:class:`~codevanta.core.report.AnalysisError` naming angr and the install; and
the result serializes to JSON and back.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis import solver
from codevanta.analysis.solver import (
    SolverPath,
    SymbolicResult,
    explore_symbolic,
    solver_status,
)
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError

pytest.importorskip(
    "angr",
    reason="the solver explorer needs angr, which only the decompile-parity CI job installs "
    "(locally: pip install 'codevanta[decompilers]')",
)

#: Virtual address of .text in the ELF64 samples.
TEXT_VA = 0x401000

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHT_PROGBITS = 1
SHT_STRTAB = 3

_TEXT_OFFSET = 0x40
_SHSTRTAB = b"\x00.text\x00.shstrtab\x00"
_NAME_TEXT = 1
_NAME_SHSTRTAB = 7

#: x86-64 ``mov rax, rdi; add rax, rsi; ret`` -- straight line, one path.
CODE_ADD_RDI_RSI = (
    bytes.fromhex("4889f8")            # mov rax, rdi
    + bytes.fromhex("4801f0")          # add rax, rsi
    + bytes.fromhex("c3")              # ret
)

#: x86-64 ``test edi, edi; jz +6; mov eax, 1; ret; mov eax, 2; ret``.
#: Offsets: ``test`` at 0x0, ``je`` at 0x2 (target 0xa), the two mov/ret pairs
#: at 0x4/0x9 and 0xa/0xf, so the two sides return different values.
CODE_TWO_WAY = (
    bytes.fromhex("85ff")            # 0x00: test edi, edi
    + bytes.fromhex("7406")          # 0x02: je 0xa   (Capstone spells 0x74 "je")
    + bytes.fromhex("b801000000")    # 0x04: mov eax, 1
    + bytes.fromhex("c3")            # 0x09: ret
    + bytes.fromhex("b802000000")    # 0x0a: mov eax, 2
    + bytes.fromhex("c3")            # 0x0f: ret
)

#: x86-64 ``jmp $; ret`` -- spins, so only the step budget can stop it. The
#: unreachable ``ret`` exists so the find set is not empty.
CODE_SPIN = bytes.fromhex("ebfe") + bytes.fromhex("c3")


def _write_elf(path: Path, code: bytes, *, va: int) -> Path:
    """Write a tiny ELF64 whose ``.text`` holds ``code`` at ``va``.

    Three sections (null, ``.text``, ``.shstrtab``), no program headers and no
    other content: enough for :class:`~codevanta.core.loader.BinaryLoader` and
    for the explorer.

    Args:
        path: Destination file.
        code: Bytes placed at the start of ``.text``.
        va: Virtual address of ``.text``.

    Returns:
        ``path``, written to disk.
    """
    shstr_offset = _TEXT_OFFSET + len(code)
    sh_offset = (shstr_offset + len(_SHSTRTAB) + 7) & ~7
    blob = bytearray(sh_offset)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,          # e_type = ET_EXEC
        62,         # e_machine = EM_X86_64
        1,          # e_version
        va,         # e_entry
        0,          # e_phoff
        sh_offset,  # e_shoff
        0,          # e_flags
        64,         # e_ehsize
        56,         # e_phentsize
        0,          # e_phnum
        64,         # e_shentsize
        3,          # e_shnum: null, .text, .shstrtab
        2,          # e_shstrndx
    )
    text_header = struct.pack(
        "<IIQQQQIIQQ",
        _NAME_TEXT, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
        va, _TEXT_OFFSET, len(code), 0, 0, 16, 0,
    )
    str_header = struct.pack(
        "<IIQQQQIIQQ",
        _NAME_SHSTRTAB, SHT_STRTAB, 0, 0, shstr_offset, len(_SHSTRTAB), 0, 0, 1, 0,
    )
    blob[0 : len(header)] = header
    blob[_TEXT_OFFSET : _TEXT_OFFSET + len(code)] = code
    blob[shstr_offset : shstr_offset + len(_SHSTRTAB)] = _SHSTRTAB
    blob += bytes(64) + text_header + str_header
    path.write_bytes(bytes(blob))
    return path


def _sample(tmp_path: Path, code: bytes, *, name: str = "sample.elf") -> Path:
    """Write a sample ELF with ``code`` in ``.text`` at :data:`TEXT_VA`."""
    return _write_elf(tmp_path / name, code, va=TEXT_VA)


def _load(path: Path) -> BinaryInfo:
    """Load a sample through the real loader."""
    return BinaryLoader().load(path)


# ---- availability ----------------------------------------------------------


def test_availability_probe_and_status() -> None:
    """With angr installed (the only place this module runs) both say so."""
    assert solver.SOLVER_AVAILABLE is True
    assert isinstance(solver.SOLVER_AVAILABLE, bool)
    status = solver_status()
    assert isinstance(status, str)
    assert status
    assert "angr" in status  # the "not installed" reason names angr too


# ---- straight line: concrete seeds in, concrete sum out --------------------


def test_straight_line_returns_the_seeded_sum_with_its_inputs(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_ADD_RDI_RSI, name="straight.elf")
    info = _load(path)

    result = explore_symbolic(
        path, info, TEXT_VA, initial_registers={"rdi": 0x10, "rsi": 0x20}
    )

    assert isinstance(result, SymbolicResult)
    assert isinstance(result.solver, str) and result.solver
    assert result.truncated is False
    assert all(isinstance(warning, str) for warning in result.warnings)
    assert len(result.paths) == 1
    entry = result.paths[0]
    assert isinstance(entry, SolverPath)
    assert entry.stopped_reason == "return"
    assert entry.return_value == 0x30  # 0x10 + 0x20, solved from the concrete seeds
    assert entry.steps >= 2  # the mov and the add; the ret is found, not executed
    assert entry.input_registers["rdi"] == 0x10
    assert entry.input_registers["rsi"] == 0x20
    assert all(isinstance(value, int) and value >= 0 for value in entry.input_registers.values())

    evidence = result.evidence
    assert evidence.source == "solver.angr"
    assert evidence.method == "solver_symbolic_execution"
    assert evidence.confidence.value == "medium"
    assert evidence.address == TEXT_VA
    assert evidence.detail is not None
    assert "no proof all paths were found" in evidence.detail
    assert any("no proof all paths were found" in item for item in evidence.extra["assumptions"])


# ---- a two-way conditional: two paths, two constraints, two returns --------


def test_two_way_conditional_yields_both_sides_with_their_constraints(tmp_path: Path) -> None:
    """With no concrete seeds, ``rdi`` stays symbolic and angr forks at the ``je``."""
    path = _sample(tmp_path, CODE_TWO_WAY, name="twoway.elf")
    info = _load(path)

    result = explore_symbolic(path, info, TEXT_VA)

    returning = [entry for entry in result.paths if entry.stopped_reason == "return"]
    assert len(result.paths) >= 2
    assert {entry.return_value for entry in returning} == {1, 2}
    assert all(entry.constraints for entry in returning)  # each side carries its je constraint
    assert all("rdi" in entry.input_registers for entry in returning)
    assert all(
        isinstance(value, int) and value >= 0
        for entry in returning
        for value in entry.input_registers.values()
    )


# ---- the step budget is reachable and flags truncation ----------------------


def test_step_budget_truncates_and_reports_budget_paths(tmp_path: Path) -> None:
    """``jmp $`` never reaches its ret, so a small budget must cut it -- and say so."""
    path = _sample(tmp_path, CODE_SPIN, name="spin.elf")
    info = _load(path)

    result = explore_symbolic(path, info, TEXT_VA, max_steps=3)

    assert result.truncated is True
    assert result.warnings
    assert any("budget" in warning for warning in result.warnings)
    budget_paths = [entry for entry in result.paths if entry.stopped_reason == "budget"]
    assert len(budget_paths) == 1
    assert budget_paths[0].return_value is None  # never reached a ret: no return value
    assert 1 <= budget_paths[0].steps <= 3
    assert not [entry for entry in result.paths if entry.stopped_reason == "return"]


# ---- caller mistakes --------------------------------------------------------


def test_unsupported_architecture_raises_naming_angr(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_ADD_RDI_RSI, name="arch.elf")
    info = BinaryInfo(
        path=path,
        format="elf",
        architecture="arm64",
        bitness=64,
        endianness="little",
        entry_point=TEXT_VA,
        image_base=0x400000,
        sha256="0" * 64,
        file_size=path.stat().st_size,
    )

    with pytest.raises(AnalysisError) as excinfo:
        explore_symbolic(path, info, TEXT_VA)

    message = str(excinfo.value)
    assert "arm64" in message
    assert "angr" in message
    assert "pip install" in message


def test_missing_angr_raises_naming_angr_and_the_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gate, forced: what every machine without the decompilers extra sees."""
    path = _sample(tmp_path, CODE_ADD_RDI_RSI, name="noangr.elf")
    info = _load(path)
    monkeypatch.setattr(solver, "SOLVER_AVAILABLE", False)

    with pytest.raises(AnalysisError) as excinfo:
        explore_symbolic(path, info, TEXT_VA)

    message = str(excinfo.value)
    assert "angr" in message
    assert "not installed" in message
    assert "pip install" in message


# ---- serialization ----------------------------------------------------------


def test_to_dict_is_json_safe(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_TWO_WAY, name="dict.elf")
    info = _load(path)

    result = explore_symbolic(path, info, TEXT_VA, max_paths=4)

    reloaded = json.loads(json.dumps(result.to_dict()))  # no bytes, no solver objects
    assert reloaded["address"] == f"0x{TEXT_VA:x}"
    assert reloaded["solver"] == result.solver
    assert reloaded["truncated"] is False
    assert reloaded["path_count"] == len(result.paths)
    assert isinstance(reloaded["warnings"], list)
    entry = reloaded["paths"][0]
    assert set(entry) == {
        "return_value",
        "constraints",
        "input_registers",
        "stopped_reason",
        "steps",
    }
    assert entry["stopped_reason"] == "return"
    assert entry["return_value"].startswith("0x")
    assert isinstance(entry["constraints"], list)
    assert all(isinstance(constraint, str) for constraint in entry["constraints"])
    assert isinstance(entry["input_registers"], dict)
    assert all(
        isinstance(value, str) and value.startswith("0x")
        for value in entry["input_registers"].values()
    )
    assert isinstance(entry["steps"], int)
    assert reloaded["evidence"]["confidence"] == "medium"
    assert "no proof all paths were found" in reloaded["evidence"]["detail"]

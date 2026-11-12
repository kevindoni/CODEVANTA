"""Parity test: the provider layer against a **real** decompiler (angr).

Every other decompiler test in ``tests/`` runs on a machine without angr, so it
can only prove that the native fallback works and that the missing backends
explain themselves. This module is the complement: it asserts the claim that
CODEVANTA's provider layer really drives a third-party decompiler -- the
REA-class parity claim -- instead of only asserting it in prose.

The module is skipped unless angr is installed (``pip install -e
".[decompilers]"``; the ``decompile-parity`` CI job installs exactly that), and
when angr *is* present these tests fail rather than skip if the provider layer
quietly falls back to ``native``.

The fixture binary is assembled byte by byte below (the same builder as
``tests/test_decompile.py``), so the test needs no compiler, no linker and no
sample file checked into the repository. angr only ever *analyses* it; the
fixture is never executed.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis.decompilers import (
    BackendResult,
    available_backends,
    decompile_function,
    get_backend,
)
from codevanta.core.loader import BinaryInfo, BinaryLoader

#: Skip the whole module when the optional backend is absent. Kept after the
#: imports on purpose: the provider package itself imports fine without angr, so
#: the import order stays lint-clean (E402) and only the *tests* need angr.
pytest.importorskip("angr", reason="the [decompilers] extra (angr) is not installed")

TEXT_VA = 0x401000
DATA_VA = 0x402000

#: ``mov rax, rdi`` -- reads argument register 0.
MOV_RAX_RDI = bytes.fromhex("4889f8")

#: ``add rax, rsi`` -- reads argument register 1.
ADD_RAX_RSI = bytes.fromhex("4801f0")

#: ``ret``
RET = bytes.fromhex("c3")

#: ``mov rax, rdi; add rax, rsi; ret`` -- a two-argument straight line, small
#: enough that angr's CFG and decompiler finish in a second but shaped like a
#: normal function (prologue-free, one exit).
STRAIGHT_LINE = MOV_RAX_RDI + ADD_RAX_RSI + RET

#: Fragments that a real C rendering of ``STRAIGHT_LINE`` contains.
C_MARKERS = ("return", "if", "{")


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
    text_section = struct.pack("<IIQQQQIIQQ", 1, 1, 6, entry, off_text, len(code), 0, 0, 16, 0)
    data_section = struct.pack("<IIQQQQIIQQ", 7, 1, 3, DATA_VA, off_data, len(data), 0, 0, 8, 0)
    str_section = struct.pack("<IIQQQQIIQQ", 13, 3, 0, 0, off_shstr, len(shstr), 0, 0, 1, 0)
    blob = bytearray(shoff)
    blob[0:64] = header
    blob[off_text : off_text + len(code)] = code
    blob[off_data : off_data + len(data)] = data
    blob[off_shstr : off_shstr + len(shstr)] = shstr
    blob += null_section + text_section + data_section + str_section
    path.write_bytes(bytes(blob))
    return path


@pytest.fixture()
def sample(tmp_path: Path) -> tuple[Path, BinaryInfo]:
    """Build the fixture ELF64 and load it with the production loader."""
    binary = _make_elf64(tmp_path / "parity.bin", STRAIGHT_LINE)
    return binary, BinaryLoader().load(binary)


def _angr_result(sample: tuple[Path, BinaryInfo]) -> BackendResult:
    """Decompile the fixture strictly through angr."""
    path, info = sample
    return decompile_function(path, info, TEXT_VA, backend="angr")


def test_available_backends_reports_angr_available() -> None:
    probes = available_backends()

    by_name = {probe.name: probe for probe in probes}
    assert set(by_name) == {"ghidra", "angr", "native"}
    angr = by_name["angr"]
    assert angr.available is True, angr.reason
    # An available backend still explains itself, and keeps its requirement.
    assert angr.reason.strip()
    assert "angr" in angr.requires
    assert by_name["native"].available is True
    assert get_backend("angr").availability().available is True


def test_angr_backend_returns_real_c(sample: tuple[Path, BinaryInfo]) -> None:
    result = _angr_result(sample)

    assert result.backend == "angr"
    assert result.language == "c"
    assert result.text.strip()
    assert any(marker in result.text for marker in C_MARKERS), result.text


def test_payload_records_the_real_decompiler(sample: tuple[Path, BinaryInfo]) -> None:
    result = _angr_result(sample)

    payload = result.to_dict()
    assert payload["backend"] == "angr"
    assert payload["language"] == "c"
    evidence = payload["evidence"]
    assert evidence["source"] == "angr.decompiler"
    assert evidence["method"] == "analyses.Decompiler"
    assert evidence["address"] == "0x401000"
    assert evidence["extra"]["backend"] == "angr"
    # angr's own version is recorded, so a report can say *which* decompiler ran.
    assert str(evidence["extra"]["angr_version"]).strip() not in {"", "unknown"}
    assert json.loads(json.dumps(payload))["backend"] == "angr"


def test_warnings_no_longer_claim_angr_was_skipped(sample: tuple[Path, BinaryInfo]) -> None:
    result = _angr_result(sample)

    # The auto/native path warns "backend 'angr' was unavailable and skipped".
    # With angr installed and explicitly requested, no such note may survive.
    assert not any("angr" in warning and "skipped" in warning for warning in result.warnings)
    assert not any("unavailable" in warning for warning in result.warnings)


def test_auto_prefers_angr_over_the_native_fallback(sample: tuple[Path, BinaryInfo]) -> None:
    path, info = sample
    result = decompile_function(path, info, TEXT_VA)  # backend defaults to "auto"

    assert result.backend == "angr"
    assert result.backend != "native"
    assert result.language == "c"
    assert result.text.strip()
    # Ghidra may legitimately be reported as skipped here; angr may not.
    assert not any("'angr'" in warning and "unavailable" in warning for warning in result.warnings)

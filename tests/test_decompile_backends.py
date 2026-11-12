"""Tests for the pluggable decompiler provider layer.

The fixture binary is assembled byte by byte inside this module, so the tests
never need a compiler, a linker or a decompiler. angr, pyghidra and Ghidra are
*not* installed in the reference environment: every external backend must report
itself unavailable with a reason, ``auto`` must fall back to the native renderer
and nothing may raise ``ImportError``. The positive angr path is guarded by
:func:`pytest.importorskip` so it starts working the moment someone installs angr.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import codevanta
from codevanta.analysis.decompile import decompile_function as native_decompile
from codevanta.analysis.decompilers import (
    AngrBackend,
    BackendAvailability,
    BackendResult,
    DecompilerBackend,
    GhidraBackend,
    NativeBackend,
    available_backends,
    decompile_function,
    get_backend,
    supported_backends,
)
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError

TEXT_VA = 0x401000
DATA_VA = 0x402000

#: ``mov rax, rdi`` -- reads argument register 0.
MOV_RAX_RDI = bytes.fromhex("4889f8")

#: ``add rax, rsi`` -- reads argument register 1.
ADD_RAX_RSI = bytes.fromhex("4801f0")

#: ``ret``
RET = bytes.fromhex("c3")

#: ``mov rax, rdi; add rax, rsi; ret`` -- a two-argument straight line.
STRAIGHT_LINE = MOV_RAX_RDI + ADD_RAX_RSI + RET

#: ``add rax, 1`` repeated, then ``ret`` -- long enough to hit a tiny budget.
LONG_FUNCTION = bytes.fromhex("4883c001") * 20 + RET

#: Modules that must stay unimported until a backend is actually used.
LAZY_MODULES = ("angr", "pyghidra", "ghidra", "jpype")


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


def _fixture(
    tmp_path: Path,
    code: bytes = STRAIGHT_LINE,
    name: str = "tiny.bin",
) -> tuple[Path, BinaryInfo]:
    """Build a fixture binary and load it with the production loader."""
    binary = _make_elf64(tmp_path / name, code)
    return binary, BinaryLoader().load(binary)


def test_package_imports_and_probes_without_optional_dependencies() -> None:
    src_dir = Path(codevanta.__file__).resolve().parents[1]
    program = (
        "import sys\n"
        "import codevanta.analysis.decompilers as d\n"
        "probes = d.available_backends()\n"
        "assert [p.name for p in probes] == ['ghidra', 'angr', 'native'], probes\n"
        "assert isinstance(d.get_backend('native').availability().available, bool)\n"
        f"heavy = sorted({{name.split('.')[0] for name in sys.modules}} & set({LAZY_MODULES!r}))\n"
        "assert not heavy, heavy\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(src_dir)},
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_available_backends_reports_three_backends_in_report_order() -> None:
    probes = available_backends()

    assert isinstance(probes, tuple)
    assert [probe.name for probe in probes] == ["ghidra", "angr", "native"]
    assert supported_backends() == ("ghidra", "angr", "native")


def test_available_backends_always_explains_itself() -> None:
    for probe in available_backends():
        assert isinstance(probe, BackendAvailability)
        assert isinstance(probe.available, bool)
        assert probe.reason.strip(), f"{probe.name} has no reason"
        if not probe.available:
            assert probe.requires, f"{probe.name} does not say what it needs"


def test_native_backend_is_always_available_and_needs_nothing() -> None:
    probe = get_backend("native").availability()

    assert probe.name == "native"
    assert probe.available is True
    assert probe.requires == ()


def test_availability_records_are_frozen_and_json_safe() -> None:
    probe = available_backends()[0]

    with pytest.raises(FrozenInstanceError):
        probe.available = True  # type: ignore[misc]

    payload = json.loads(json.dumps([item.to_dict() for item in available_backends()]))
    assert payload[0]["name"] == "ghidra"
    assert isinstance(payload[0]["requires"], list)


def test_get_backend_by_name_is_case_and_space_insensitive() -> None:
    assert get_backend("native") is get_backend("  NaTiVe ")


def test_get_backend_returns_protocol_conforming_objects() -> None:
    for name in supported_backends():
        backend = get_backend(name)
        assert isinstance(backend, DecompilerBackend)
        assert backend.name == name
        assert isinstance(backend.requires, tuple)
        assert callable(backend.availability)
        assert callable(backend.decompile)


def test_unknown_backend_name_raises_listing_the_supported_set() -> None:
    with pytest.raises(AnalysisError) as excinfo:
        get_backend("nope")

    message = str(excinfo.value)
    assert "nope" in message
    for name in ("ghidra", "angr", "native"):
        assert name in message


# ---------------------------------------------------------------------------
# angr: unavailable here, but the positive path runs once angr is installed
# ---------------------------------------------------------------------------

ANGR_AVAILABLE = get_backend("angr").availability().available


@pytest.mark.skipif(ANGR_AVAILABLE, reason="angr is installed, so it is available")
def test_angr_backend_is_unavailable_and_says_why() -> None:
    probe = AngrBackend().availability()

    assert probe.available is False
    assert probe.name == "angr"
    assert probe.requires == ("angr",)
    assert "angr" in probe.reason
    assert probe.reason.strip()


@pytest.mark.skipif(ANGR_AVAILABLE, reason="angr is installed, so it is available")
def test_strict_angr_request_raises_analysis_error_not_importerror(tmp_path: Path) -> None:
    binary, info = _fixture(tmp_path)

    with pytest.raises(AnalysisError) as excinfo:
        decompile_function(binary, info, TEXT_VA, backend="angr")

    message = str(excinfo.value)
    assert "angr" in message
    assert "unavailable" in message
    assert "native" in message


@pytest.mark.skipif(ANGR_AVAILABLE, reason="angr is installed, so it is available")
def test_angr_backend_object_also_raises_analysis_error(tmp_path: Path) -> None:
    binary, info = _fixture(tmp_path)

    with pytest.raises(AnalysisError):
        AngrBackend().decompile(binary, info, TEXT_VA)


def test_angr_positive_path_when_installed(tmp_path: Path) -> None:
    pytest.importorskip("angr")
    binary, info = _fixture(tmp_path)

    result = decompile_function(binary, info, TEXT_VA, backend="angr")

    assert result.backend == "angr"
    assert result.text.strip()
    assert result.evidence.address == TEXT_VA


# ---------------------------------------------------------------------------
# ghidra: needs pyghidra *and* an installation; both are probed, never launched
# ---------------------------------------------------------------------------

GHIDRA_AVAILABLE = get_backend("ghidra").availability().available


@pytest.mark.skipif(GHIDRA_AVAILABLE, reason="pyghidra and a Ghidra installation are present")
def test_ghidra_backend_is_unavailable_and_names_the_missing_piece() -> None:
    probe = GhidraBackend().availability()

    assert probe.available is False
    assert probe.name == "ghidra"
    assert probe.requires == ("pyghidra", "ghidra")
    assert "pyghidra" in probe.reason or "GHIDRA_INSTALL_DIR" in probe.reason


@pytest.mark.skipif(GHIDRA_AVAILABLE, reason="pyghidra and a Ghidra installation are present")
def test_strict_ghidra_request_raises_analysis_error_naming_ghidra(tmp_path: Path) -> None:
    binary, info = _fixture(tmp_path)

    with pytest.raises(AnalysisError) as excinfo:
        decompile_function(binary, info, TEXT_VA, backend="ghidra")

    assert "ghidra" in str(excinfo.value).lower()


def test_ghidra_reason_names_the_install_variable_when_it_is_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)

    probe = GhidraBackend().availability()

    assert "GHIDRA_INSTALL_DIR" in probe.reason


def test_ghidra_rejects_a_directory_that_is_not_an_installation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    not_ghidra = tmp_path / "not-ghidra"
    not_ghidra.mkdir()
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(not_ghidra))

    probe = GhidraBackend().availability()

    assert probe.available is False
    assert "does not look like a Ghidra installation" in probe.reason


def test_ghidra_rejects_an_install_variable_pointing_at_a_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    a_file = tmp_path / "ghidra.tar.gz"
    a_file.write_bytes(b"not really")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(a_file))

    probe = GhidraBackend().availability()

    assert probe.available is False
    assert "is not a directory" in probe.reason


# ---------------------------------------------------------------------------
# native: must always run
# ---------------------------------------------------------------------------


def test_native_returns_the_renderer_body(tmp_path: Path) -> None:
    binary, info = _fixture(tmp_path)

    result = decompile_function(binary, info, TEXT_VA, backend="native")

    assert isinstance(result, BackendResult)
    assert result.backend == "native"
    assert result.language == "c"
    assert result.text.strip()
    assert result.text == native_decompile(binary, info, TEXT_VA).body
    assert "sub_401000" in result.text


def test_native_backend_object_is_callable_directly(tmp_path: Path) -> None:
    binary, info = _fixture(tmp_path)

    result = NativeBackend().decompile(binary, info, TEXT_VA, max_instructions=50, max_blocks=10)

    assert result.backend == "native"
    assert result.text.strip()


def test_native_evidence_names_the_backend_and_the_budgets(tmp_path: Path) -> None:
    binary, info = _fixture(tmp_path)

    result = decompile_function(binary, info, TEXT_VA, backend="native")

    assert result.evidence.source == "decompile.pseudo_c"
    assert result.evidence.address == TEXT_VA
    assert result.evidence.extra["backend"] == "native"
    assert result.evidence.extra["max_instructions"] == 2000
    assert result.evidence.extra["max_blocks"] == 500


def test_native_surfaces_header_warnings_for_a_truncated_rendering(tmp_path: Path) -> None:
    binary, info = _fixture(tmp_path, LONG_FUNCTION, "long.bin")

    result = decompile_function(binary, info, TEXT_VA, backend="native", max_instructions=2)

    assert result.warnings == (
        "instruction limit reached (max_instructions=2); the graph may be incomplete",
    )
    assert all(warning.strip() for warning in result.warnings)


def test_native_address_error_propagates_as_analysis_error(tmp_path: Path) -> None:
    binary, info = _fixture(tmp_path)

    with pytest.raises(AnalysisError):
        decompile_function(binary, info, DATA_VA, backend="native")


# ---------------------------------------------------------------------------
# auto: prefer an external backend, always fall back, never stay silent
# ---------------------------------------------------------------------------


def test_auto_never_raises_and_returns_a_rendering(tmp_path: Path) -> None:
    binary, info = _fixture(tmp_path)

    result = decompile_function(binary, info, TEXT_VA, backend="auto")

    assert isinstance(result, BackendResult)
    assert result.text.strip()
    assert result.backend in supported_backends()
    assert result.language == "c"


def test_auto_records_every_unavailable_backend_in_warnings(tmp_path: Path) -> None:
    binary, info = _fixture(tmp_path)
    probes = {probe.name: probe for probe in available_backends()}

    result = decompile_function(binary, info, TEXT_VA)

    for name in ("ghidra", "angr"):
        probe = probes[name]
        if probe.available:
            continue
        matching = [warning for warning in result.warnings if name in warning]
        assert matching, f"{name} was unavailable but no warning mentions it"
        assert any(probe.reason in warning for warning in matching)


def test_auto_falls_back_to_native_when_nothing_else_is_available(tmp_path: Path) -> None:
    probes = {probe.name: probe for probe in available_backends()}
    if any(probe.available for name, probe in probes.items() if name != "native"):
        pytest.skip("an external backend is available in this environment")
    binary, info = _fixture(tmp_path)

    result = decompile_function(binary, info, TEXT_VA, backend="auto")

    assert result.backend == "native"
    assert len(result.warnings) == 2
    assert "ghidra" in result.warnings[0]
    assert "angr" in result.warnings[1]


def test_auto_is_the_default_backend(tmp_path: Path) -> None:
    binary, info = _fixture(tmp_path)

    default = decompile_function(binary, info, TEXT_VA)
    explicit = decompile_function(binary, info, TEXT_VA, backend="auto")

    assert default.backend == explicit.backend
    assert default.warnings == explicit.warnings
    assert default.text == explicit.text


# ---------------------------------------------------------------------------
# result shape and shared validation
# ---------------------------------------------------------------------------


def test_result_to_dict_is_json_safe(tmp_path: Path) -> None:
    binary, info = _fixture(tmp_path)
    result = decompile_function(binary, info, TEXT_VA, backend="native")

    data = result.to_dict()

    assert set(data) == {"text", "backend", "language", "warnings", "evidence"}
    round_trip = json.loads(json.dumps(data))
    assert round_trip["backend"] == "native"
    assert round_trip["language"] == "c"
    assert round_trip["text"] == result.text
    assert isinstance(round_trip["warnings"], list)
    assert round_trip["evidence"]["source"] == "decompile.pseudo_c"
    assert round_trip["evidence"]["confidence"] == "low"
    assert round_trip["evidence"]["address"] == "0x401000"


def test_result_serializes_an_empty_warning_list(tmp_path: Path) -> None:
    binary, info = _fixture(tmp_path)
    result = decompile_function(binary, info, TEXT_VA, backend="native")

    assert result.warnings == ()
    assert result.to_dict()["warnings"] == []


def test_backend_result_is_frozen(tmp_path: Path) -> None:
    binary, info = _fixture(tmp_path)
    result = decompile_function(binary, info, TEXT_VA, backend="native")

    with pytest.raises(FrozenInstanceError):
        result.backend = "angr"  # type: ignore[misc]


@pytest.mark.parametrize(
    "budgets",
    [
        {"max_instructions": 0},
        {"max_instructions": -5},
        {"max_instructions": 10**9},
        {"max_blocks": 0},
        {"max_blocks": 10**9},
        {"max_instructions": "many"},
        {"max_blocks": 1.5},
    ],
)
def test_out_of_range_budgets_are_rejected_before_any_backend_runs(
    tmp_path: Path,
    budgets: dict[str, object],
) -> None:
    binary, info = _fixture(tmp_path)

    with pytest.raises(AnalysisError):
        decompile_function(binary, info, TEXT_VA, **budgets)  # type: ignore[arg-type]


def test_non_string_backend_is_rejected(tmp_path: Path) -> None:
    binary, info = _fixture(tmp_path)

    with pytest.raises(AnalysisError):
        decompile_function(binary, info, TEXT_VA, backend=123)  # type: ignore[arg-type]


def test_unknown_backend_through_the_entry_point_lists_the_supported_set(
    tmp_path: Path,
) -> None:
    binary, info = _fixture(tmp_path)

    with pytest.raises(AnalysisError) as excinfo:
        decompile_function(binary, info, TEXT_VA, backend="objdump")

    message = str(excinfo.value)
    assert "objdump" in message
    assert "native" in message


def test_backend_names_are_matched_case_insensitively_through_the_entry_point(
    tmp_path: Path,
) -> None:
    binary, info = _fixture(tmp_path)

    result = decompile_function(binary, info, TEXT_VA, backend="  Native ")

    assert result.backend == "native"

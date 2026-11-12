"""Tests for the committed sample binaries and their generator.

The samples in ``samples/`` are checked in as bytes, so these tests pin two
things that can silently rot:

* the committed files still parse as the formats they claim to be, and
* they are still exactly what ``scripts/make_samples.py`` produces.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
from typer.testing import CliRunner

from codevanta.cli.main import app
from codevanta.core.functions import discover_functions
from codevanta.core.loader import BinaryLoader

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = REPO_ROOT / "samples"
GENERATOR_PATH = REPO_ROOT / "scripts" / "make_samples.py"

#: Expected ``(format, architecture, bitness)`` per sample file.
EXPECTED_METADATA: dict[str, tuple[str, str, int]] = {
    "pe64_text.bin": ("PE", "x86_64", 64),
    "macho64_text.bin": ("MachO", "x86_64", 64),
}
SAMPLE_NAMES = tuple(EXPECTED_METADATA)

#: Hard ceiling from the task: every sample must stay tiny.
MAX_SAMPLE_SIZE = 4096


def load_generator_module() -> ModuleType:
    """Import ``scripts/make_samples.py`` by path (``scripts`` is not a package)."""
    assert GENERATOR_PATH.is_file(), f"missing generator script: {GENERATOR_PATH}"
    spec = importlib.util.spec_from_file_location("codevanta_make_samples", GENERATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GENERATOR = load_generator_module()


@pytest.mark.parametrize("filename", SAMPLE_NAMES)
def test_sample_file_exists_and_is_small(filename: str) -> None:
    path = SAMPLES_DIR / filename
    assert path.is_file(), f"missing committed sample: {path}"
    assert 0 < path.stat().st_size <= MAX_SAMPLE_SIZE


@pytest.mark.parametrize("filename", SAMPLE_NAMES)
def test_sample_loads_with_expected_metadata(filename: str) -> None:
    format_name, architecture, bitness = EXPECTED_METADATA[filename]
    path = SAMPLES_DIR / filename
    info = BinaryLoader().load(path)

    assert info.format, "loader reported an empty format"
    assert info.format == format_name
    assert info.architecture, "loader reported an empty architecture"
    assert info.architecture == architecture
    assert info.bitness, "loader reported empty bitness"
    assert info.bitness == bitness
    assert info.entry_point, "loader reported no entry point"
    assert info.endianness == "little"
    assert info.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert info.file_size == path.stat().st_size


@pytest.mark.parametrize("filename", SAMPLE_NAMES)
def test_sample_has_one_executable_section(filename: str) -> None:
    info = BinaryLoader().load(SAMPLES_DIR / filename)
    executable = [section for section in info.sections if section.is_executable]
    assert len(executable) == 1
    assert executable[0].raw_size > 0
    assert not executable[0].is_writable


@pytest.mark.parametrize("filename", SAMPLE_NAMES)
def test_sample_entry_point_maps_into_code(filename: str) -> None:
    info = BinaryLoader().load(SAMPLES_DIR / filename)
    assert info.entry_point is not None
    section = info.section_for_va(info.entry_point)
    assert section is not None and section.is_executable
    offset = info.va_to_offset(info.entry_point)
    assert offset is not None and offset == section.offset


@pytest.mark.parametrize("filename", SAMPLE_NAMES)
def test_sample_contains_the_ascii_payload(filename: str) -> None:
    payload = GENERATOR.TEXT_MESSAGE.rstrip(b"\x00")
    assert payload in (SAMPLES_DIR / filename).read_bytes()


@pytest.mark.parametrize("filename", SAMPLE_NAMES)
def test_committed_bytes_match_the_generator(filename: str) -> None:
    generated = GENERATOR.build_samples()
    assert filename in generated
    assert (SAMPLES_DIR / filename).read_bytes() == generated[filename], (
        f"{filename} is stale; run `python scripts/make_samples.py`"
    )


def test_generator_is_deterministic() -> None:
    first = GENERATOR.build_samples()
    second = GENERATOR.build_samples()
    assert first == second
    assert set(first) == set(SAMPLE_NAMES)


def test_generator_writes_reproducible_files(tmp_path: Path) -> None:
    written = GENERATOR.write_samples(tmp_path)
    assert {name for name, _, _ in written} == set(SAMPLE_NAMES)
    for name, size, digest in written:
        data = (tmp_path / name).read_bytes()
        assert len(data) == size
        assert hashlib.sha256(data).hexdigest() == digest
        assert data == (SAMPLES_DIR / name).read_bytes()


def test_generator_check_mode_reports_fresh_samples() -> None:
    assert GENERATOR.check_samples(SAMPLES_DIR) == []
    assert GENERATOR.main(["--check"]) == 0


@pytest.mark.parametrize("filename", SAMPLE_NAMES)
def test_discover_functions_includes_the_entry_point(filename: str) -> None:
    info = BinaryLoader().load(SAMPLES_DIR / filename)
    candidates = discover_functions(info)
    assert candidates, "function discovery returned nothing"
    assert any(candidate.address == info.entry_point for candidate in candidates)
    for candidate in candidates:
        assert candidate.source
        assert candidate.confidence is not None
        assert candidate.evidence is not None


@pytest.mark.parametrize("filename", SAMPLE_NAMES)
def test_cli_info_runs_on_sample(filename: str) -> None:
    result = CliRunner().invoke(app, ["info", str(SAMPLES_DIR / filename)])
    assert result.exit_code == 0, result.stdout
    format_name, architecture, _ = EXPECTED_METADATA[filename]
    assert format_name in result.stdout
    assert architecture in result.stdout


def test_cli_functions_runs_on_pe_sample() -> None:
    result = CliRunner().invoke(app, ["functions", str(SAMPLES_DIR / "pe64_text.bin")])
    assert result.exit_code == 0, result.stdout
    export_name = GENERATOR.PE_EXPORT_NAME.rstrip(b"\x00").decode()
    assert export_name in result.stdout


def test_cli_disasm_runs_on_macho_sample() -> None:
    result = CliRunner().invoke(
        app, ["disasm", str(SAMPLES_DIR / "macho64_text.bin"), "--count", "10"]
    )
    assert result.exit_code == 0, result.stdout
    assert "Disassembly at" in result.stdout
    assert "call" in result.stdout

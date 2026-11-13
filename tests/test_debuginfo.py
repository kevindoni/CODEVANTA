"""DWARF debug-info extraction tests (producer-grade symbols and type layouts)."""

from __future__ import annotations

from pathlib import Path

import pytest

from codevanta.analysis.debuginfo import extract_debug_info
from codevanta.core.loader import BinaryLoader
from codevanta.core.report import AnalysisError

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
HELLO_DWARF = SAMPLES / "hello-dwarf"

pytest.importorskip("elftools", reason="pyelftools optional extra not installed")


def _skip_if_no_sample() -> None:
    if not HELLO_DWARF.exists():
        pytest.skip("samples/hello-dwarf is not checked out")


@pytest.fixture
def dwarf_info() -> object:
    _skip_if_no_sample()
    return BinaryLoader().load(HELLO_DWARF)


def test_non_elf_is_rejected_with_typed_error() -> None:
    _skip_if_no_sample()
    info = BinaryLoader().load(HELLO_DWARF)
    info.format = "PE"  # type: ignore[misc]
    with pytest.raises(AnalysisError, match="ELF only"):
        extract_debug_info(HELLO_DWARF, info)


def test_invalid_limits_raise(dwarf_info: object) -> None:
    _skip_if_no_sample()
    info = BinaryLoader().load(HELLO_DWARF)
    with pytest.raises(AnalysisError, match="limit"):
        extract_debug_info(HELLO_DWARF, info, limit=0)
    with pytest.raises(AnalysisError, match="limit"):
        extract_debug_info(HELLO_DWARF, info, limit=100_001)


def test_extracts_functions_with_byte_exact_extents(dwarf_info: object) -> None:
    info = BinaryLoader().load(HELLO_DWARF)
    result = extract_debug_info(HELLO_DWARF, info)
    by_name = {f.name: f for f in result.functions}
    assert set(by_name) == {"compute", "scale_and_shift", "main"}
    compute = by_name["compute"]
    assert compute.address == 0x708
    assert compute.size == 64
    assert compute.is_external is True
    assert compute.evidence.source == "dwarf.debug_info"
    assert compute.evidence.confidence.value == "high"
    assert "64 bytes" in compute.evidence.detail


def test_extracts_named_type_layouts(dwarf_info: object) -> None:
    info = BinaryLoader().load(HELLO_DWARF)
    result = extract_debug_info(HELLO_DWARF, info)
    by_name = {t.name: t for t in result.types}
    assert by_name["point"].kind == "struct"
    assert by_name["point"].byte_size == 8
    assert by_name["point"].evidence.source == "dwarf.debug_info"


def test_limit_truncates_with_honest_flags(dwarf_info: object) -> None:
    info = BinaryLoader().load(HELLO_DWARF)
    result = extract_debug_info(HELLO_DWARF, info, limit=1)
    assert len(result.functions) == 1
    assert result.truncated_functions is True
    assert any("function limit" in w for w in result.warnings)


def test_no_dwarf_info_yields_empty_with_warning(tmp_path: Path, dwarf_info: object) -> None:
    _skip_if_no_sample()
    # The macho sample has no DWARF; but the module refuses non-ELF. Use the
    # stub-ELF route instead: exercise the no-dwarf branch through a
    # format-valid ELF without .debug_info.
    elf64_min = SAMPLES / "elf64_min.bin"
    if elf64_min.exists():
        min_info = BinaryLoader().load(elf64_min)
        result = extract_debug_info(elf64_min, min_info)
        assert result.functions == []
        assert result.types == []
        assert any("no .debug_info" in w for w in result.warnings)


def test_missing_pyelftools_raises_typed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _skip_if_no_sample()
    info = BinaryLoader().load(HELLO_DWARF)
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("elftools"):
            raise ImportError("No module named 'elftools'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(AnalysisError, match=r"\.\[dwarf\]"):
        extract_debug_info(HELLO_DWARF, info)

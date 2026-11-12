"""Function discovery tests (provenance and merging)."""

from __future__ import annotations

from pathlib import Path

from codevanta.core.functions import discover_functions
from codevanta.core.loader import BinaryInfo, ExportInfo, SymbolInfo


def _make_info(**overrides: object) -> BinaryInfo:
    defaults: dict[str, object] = {
        "path": Path("dummy"),
        "format": "ELF",
        "architecture": "x86_64",
        "bitness": 64,
        "endianness": "little",
        "entry_point": 0x401000,
        "image_base": 0x400000,
        "sha256": "0" * 64,
        "file_size": 1024,
    }
    defaults.update(overrides)
    return BinaryInfo(**defaults)  # type: ignore[arg-type]


def test_entry_point_is_medium_confidence() -> None:
    candidates = discover_functions(_make_info())
    assert len(candidates) == 1
    entry = candidates[0]
    assert entry.address == 0x401000
    assert entry.source == "binary.entry_point"
    assert entry.confidence.value == "medium"
    assert entry.evidence.source == "binary.entry_point"


def test_exports_are_high_confidence() -> None:
    info = _make_info(exports=[ExportInfo(name="start", address=0x401100)])
    candidates = discover_functions(info)
    match = next(c for c in candidates if c.address == 0x401100)
    assert match.name == "start"
    assert match.confidence.value == "high"
    assert match.source == "elf.dynsym"


def test_duplicate_address_merges_aliases() -> None:
    info = _make_info(
        exports=[ExportInfo(name="start", address=0x401100)],
        symbols=[SymbolInfo(name="sym_start", address=0x401100, is_function=True)],
    )
    candidates = discover_functions(info)
    match = next(c for c in candidates if c.address == 0x401100)
    assert match.name == "start"
    assert "sym_start" in match.aliases


def test_non_function_symbols_are_ignored() -> None:
    info = _make_info(symbols=[SymbolInfo(name="global", address=0x402000, is_function=False)])
    candidates = discover_functions(info)
    assert all(c.address != 0x402000 for c in candidates)


def test_candidates_are_sorted_by_address() -> None:
    info = _make_info(
        exports=[
            ExportInfo(name="b", address=0x402000),
            ExportInfo(name="a", address=0x401500),
        ]
    )
    addresses = [c.address for c in discover_functions(info)]
    assert addresses == sorted(addresses)


def test_macho_symbol_candidates_use_macho_sources() -> None:
    info = _make_info(
        format="MachO",
        symbols=[SymbolInfo(name="_sample_main", address=0x401100, is_function=True)],
        exports=[ExportInfo(name="_exported", address=0x401200)],
    )
    candidates = discover_functions(info)
    symbol_match = next(c for c in candidates if c.address == 0x401100)
    assert symbol_match.source == "macho.symbol_table"
    assert symbol_match.confidence.value == "medium"
    export_match = next(c for c in candidates if c.address == 0x401200)
    assert export_match.source == "macho.exported_symbols"
    assert export_match.confidence.value == "high"

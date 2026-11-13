"""Vtable discovery and thunk-chain tests (real sample + synthetic thunk ELF)."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codevanta.analysis.vtables import find_vtables, resolve_thunk
from codevanta.cli.main import app
from codevanta.core.loader import BinaryLoader
from codevanta.core.report import AnalysisError

runner = CliRunner()

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
SHAPES = SAMPLES / "shapes-vtable"

TEXT_VA = 0x401000
DATA_VA = 0x500000

#: x86_64 layout (section maps VA == file offset delta from TEXT_VA):
#: +0x00 thunk = `jmp rel32` (E9) to the real function at +0x10;
#: +0x10 real function (`ret`); +0x20 another plain function (`ret`).
_THUNK_VA = TEXT_VA
_REAL_FN_VA = TEXT_VA + 0x10
_PLAIN_FN_VA = TEXT_VA + 0x20
_SLOT_VALUES = [
    _THUNK_VA,
    _REAL_FN_VA,
    _PLAIN_FN_VA,
    _THUNK_VA,
]
_CODE = (
    bytes.fromhex("e9")            # jmp rel32 -> real function
    + struct.pack("<i", _REAL_FN_VA - (_THUNK_VA + 5))
    + b"\x90" * 11                 # pad to +0x10
    + b"\xc3"                      # real function: ret
    + b"\x90" * 15                 # pad to +0x20
    + b"\xc3"                      # plain function: ret
)


def _write_elf64(path: Path) -> Path:
    """Minimal ELF64 x86_64 with an executable .text and a pointer-table .data."""
    shstr = b"\x00.text\x00.data\x00.shstrtab\x00"
    off_text = 0x40
    off_data = off_text + len(_CODE)
    off_shstr = off_data + len(_SLOT_VALUES) * 8
    shoff = (off_shstr + len(shstr) + 7) & ~7

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # ET_EXEC
        62,  # EM_X86_64
        1,
        TEXT_VA,
        0,
        shoff,
        0,
        64,
        56,
        0,
        64,
        3,
        2,
    )
    def section(
        name_idx: int, flags: int, addr: int, offset: int, size: int
    ) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name_idx, 1, flags, addr, offset, size, 0, 0, 1, 0)

    blob = bytearray(shoff + 3 * 64)
    blob[0:64] = header
    blob[off_text : off_text + len(_CODE)] = _CODE
    for value in _SLOT_VALUES:
        blob[off_data : off_data + 8] = struct.pack("<Q", value)
        off_data += 8
    blob[shoff + 64 : shoff + 128] = section(1, 0x6, TEXT_VA, off_text, len(_CODE))
    blob[shoff + 128 : shoff + 192] = section(2, 0x3, DATA_VA, off_text + len(_CODE), len(_SLOT_VALUES) * 8)
    blob[shoff + 192 : shoff + 256] = section(3, 0, 0, off_shstr, len(shstr))
    blob[off_shstr : off_shstr + len(shstr)] = shstr
    path.write_bytes(bytes(blob))
    return path


def _skip_if_no_sample() -> None:
    if not SHAPES.exists():
        pytest.skip("samples/shapes-vtable is not checked out")


def _load(path: Path):
    return BinaryLoader().load(path)


def test_address_mode_decodes_slots_and_skips_header(tmp_path: Path) -> None:
    _skip_if_no_sample()
    info = _load(SHAPES)
    result = find_vtables(SHAPES, info, address=0xB8F0)
    assert len(result.tables) == 1
    table = result.tables[0]
    assert table.address == 0xB8F0
    assert len(table.slots) == 4
    assert table.header_slots == 0
    assert all(slot.target != 0 for slot in table.slots)
    assert all(slot.evidence.source == "vtable.slot_ref" for slot in table.slots)
    assert all(slot.evidence.confidence.value == "medium" for slot in table.slots)


def test_address_mode_skips_itanium_header_when_given_symbol_address(
    tmp_path: Path,
) -> None:
    _skip_if_no_sample()
    info = _load(SHAPES)
    # The nm-reported vtable symbol address covers offset-to-top + RTTI + fns;
    # the module skips up to two leading header slots automatically.
    result = find_vtables(SHAPES, info, address=0xB8E8)
    assert len(result.tables) == 1
    assert result.tables[0].header_slots == 1


def test_scan_mode_finds_all_three_candidate_tables() -> None:
    _skip_if_no_sample()
    info = _load(SHAPES)
    result = find_vtables(SHAPES, info)
    addresses = [table.address for table in result.tables]
    assert 0xB8F0 in addresses or 0xB8E0 in addresses
    assert len(result.tables) >= 2
    assert ".data.rel.ro" in result.scanned_sections
    assert result.scanned_bytes > 0


def test_relocation_overlay_fills_pie_slots() -> None:
    _skip_if_no_sample()
    info = _load(SHAPES)
    # PIE file: pointer slots are zero on disk. Without the relocation overlay
    # nothing would be discovered; with it, three tables appear.
    result = find_vtables(SHAPES, info)
    assert len(result.tables) >= 2
    for table in result.tables:
        for slot in table.slots:
            assert slot.target != 0


def test_thunk_resolution_on_synthetic_elf(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "thunk.bin")
    info = _load(sample)
    result = find_vtables(sample, info, address=DATA_VA, min_slots=3)
    assert len(result.tables) == 1
    slots = result.tables[0].slots
    assert slots[0].target == _THUNK_VA
    assert slots[0].resolved_target == _REAL_FN_VA  # jmp chain followed
    assert slots[1].target == _REAL_FN_VA
    assert slots[1].resolved_target is None  # real fn: first insn is not jmp
    assert "thunk chain" in slots[0].evidence.detail


def test_resolve_thunk_rejects_plain_function(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "plain.bin")
    info = _load(sample)
    assert resolve_thunk(sample, info, _REAL_FN_VA) is None
    assert resolve_thunk(sample, info, _PLAIN_FN_VA) is None


def test_invalid_bounds_raise(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "bounds.bin")
    info = _load(sample)
    with pytest.raises(AnalysisError, match="min_slots"):
        find_vtables(sample, info, min_slots=1)
    with pytest.raises(AnalysisError, match="max_slots"):
        find_vtables(sample, info, max_slots=1)
    with pytest.raises(AnalysisError, match="max_scan_bytes"):
        find_vtables(sample, info, max_scan_bytes=1)


def test_cli_vtable_address_mode(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "cli.bin")
    result = runner.invoke(app, ["vtable", str(sample), "--address", hex(DATA_VA)])
    assert result.exit_code == 0, result.stdout
    assert "Vtable candidate" in result.stdout


def test_cli_vtable_json(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "cli_json.bin")
    result = runner.invoke(app, ["vtable", str(sample), "--address", hex(DATA_VA), "--json"])
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["table_count"] == 1
    assert payload["tables"][0]["slots"][0]["resolved_target"] == hex(_REAL_FN_VA)


def test_cli_vtable_requires_address_or_scan(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "cli_missing.bin")
    result = runner.invoke(app, ["vtable", str(sample)])
    assert result.exit_code != 0

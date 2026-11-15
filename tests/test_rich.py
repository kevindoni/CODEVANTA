"""Rich header decoder tests (lane-rich).

All fixtures are hand-built minimal PE32+ images written to ``tmp_path`` --
the MZ + ``e_lfanew`` pattern from ``tests/test_meta.py``'s ``pe_with_clr``
with a Rich header block appended before the PE signature: the DanS block,
the encoded entry pairs, then ``Rich`` and the key. No real binaries, no
network, no external tools. Wrong keys, missing markers and oversize scans
prove the typed :class:`~codevanta.core.report.AnalysisError`.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from codevanta.analysis.rich_header import DANS_MARKER, MAX_ENTRIES, inspect_rich_header
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools

#: The XOR key from the classic NTCore example Rich header.
KEY = 0xB4F3D2A3


def make_rich_pe(
    path: Path,
    key: int,
    entries: list[tuple[int, int, int]],
    *,
    stored_key: int | None = None,
) -> Path:
    """Build a minimal PE32+ whose DOS region carries a Rich header.

    ``entries`` are ``(product_id, build, count)`` tuples encoded with
    ``key``; ``stored_key`` (when given) overrides the key DWORD published
    after the ``Rich`` marker, simulating a wrong key.
    """
    key &= 0xFFFFFFFF
    blob = bytearray(struct.pack("<I", DANS_MARKER ^ key))
    blob += (key & 0xFFFFFFFF).to_bytes(4, "little") * 3  # DanS padding (0 ^ key)
    for product_id, build, count in entries:
        encoded = ((product_id & 0xFFFF) << 16) | (build & 0xFFFF)
        blob += struct.pack("<II", encoded ^ key, count ^ key)
    blob += b"Rich" + struct.pack("<I", (key if stored_key is None else stored_key) & 0xFFFFFFFF)
    while len(blob) % 16:
        blob += b"\x00"

    pe_off = 0x80 + len(blob)
    dos = bytearray(b"MZ" + bytes(58) + b"\x00\x00\x00\x00")
    struct.pack_into("<I", dos, 0x3C, pe_off)
    out = bytearray(dos)
    out += bytes(0x80 - len(out))
    out += blob
    out += b"PE\0\0"
    out += struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 240, 0x22)
    opt = bytearray(240)
    opt[0:2] = struct.pack("<H", 0x20B)
    opt[108:112] = struct.pack("<I", 16)
    out += opt
    path.write_bytes(bytes(out))
    return path


def make_plain_pe(path: Path) -> Path:
    """Minimal PE32+ with no Rich header at all (pe_with_clr pattern)."""
    dos = b"MZ" + bytes(58) + struct.pack("<I", 0x80)
    out = bytearray(dos)
    out += bytes(0x80 - len(out))
    out += b"PE\0\0"
    out += struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 240, 0x22)
    opt = bytearray(240)
    opt[0:2] = struct.pack("<H", 0x20B)
    opt[108:112] = struct.pack("<I", 16)
    out += opt
    path.write_bytes(bytes(out))
    return path


# ---- decode round-trip ----------------------------------------------------------


def test_rich_roundtrip_decodes_entries_and_guess(tmp_path: Path) -> None:
    path = make_rich_pe(
        tmp_path / "rich.exe",
        KEY,
        [(0x0001, 0x0001, 11), (0x0104, 0x0E24, 1)],
    )
    summary = inspect_rich_header(path)
    assert summary.valid is True
    assert summary.xor_key == KEY
    assert [(e.product_id, e.build, e.count) for e in summary.entries] == [
        (0x0001, 0x0001, 11),
        (0x0104, 0x0E24, 1),
    ]
    assert summary.entries[0].name_guess == "Import"
    assert summary.entries[1].name_guess == "MSVC 14.x (VS2015+)"
    assert summary.compiler_guess == "MSVC 14.x link 14.36"
    assert summary.total_object_count == 12
    assert summary.entries_truncated is False
    assert summary.warnings == ()
    assert summary.evidence.source == "pe.rich"
    assert summary.evidence.confidence.value == "high"
    payload = summary.to_dict()
    assert payload["entries"][0]["product_id"] == "0x0001"
    assert payload["entries"][1]["product_id"] == "0x0104"
    assert payload["total_object_count"] == 12


def test_rich_unknown_product_id_stays_honest(tmp_path: Path) -> None:
    path = make_rich_pe(tmp_path / "unknown.exe", KEY, [(0x0123, 0x0ABC, 4)])
    summary = inspect_rich_header(path)
    assert summary.entries[0].name_guess is None
    assert summary.compiler_guess == "unknown product id"


def test_rich_capped_entries_are_truncated_with_warning(tmp_path: Path) -> None:
    entries = [(0x0001, 1 + index, 1) for index in range(260)]
    path = make_rich_pe(tmp_path / "many.exe", KEY, entries)
    summary = inspect_rich_header(path)
    assert summary.entries_total == 260
    assert summary.entries_truncated is True
    assert len(summary.entries) == MAX_ENTRIES == 256
    assert any("keeping the first 256" in warning for warning in summary.warnings)


# ---- typed errors -----------------------------------------------------------------


def test_rich_wrong_key_is_a_typed_error(tmp_path: Path) -> None:
    path = make_rich_pe(
        tmp_path / "wrong.exe",
        0x12345678,
        [(0x0001, 1, 1), (0x0104, 0x0E24, 1)],
        stored_key=0xDEADBEEF,
    )
    with pytest.raises(AnalysisError, match="key mismatch"):
        inspect_rich_header(path)


def test_rich_missing_marker_is_a_typed_error(tmp_path: Path) -> None:
    path = make_plain_pe(tmp_path / "plain.exe")
    with pytest.raises(AnalysisError, match="no Rich header"):
        inspect_rich_header(path)


def test_rich_oversize_scan_is_a_typed_error(tmp_path: Path) -> None:
    pe_off = 0x11000  # beyond the bounded DOS-stub scan region
    dos = bytearray(b"MZ" + bytes(58) + b"\x00\x00\x00\x00")
    struct.pack_into("<I", dos, 0x3C, pe_off)
    out = bytearray(dos)
    out += bytes(0x80 - len(out))
    out += bytes(pe_off - 0x80)
    out += b"PE\0\0"
    out += struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 240, 0x22)
    path = tmp_path / "oversize.exe"
    path.write_bytes(bytes(out))
    with pytest.raises(AnalysisError, match="oversize Rich header scan"):
        inspect_rich_header(path)


def test_rich_missing_file_is_a_typed_error(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="file not found"):
        inspect_rich_header(tmp_path / "ghost.exe")


# ---- determinism + MCP surface ------------------------------------------------------


def test_rich_decode_is_deterministic(tmp_path: Path) -> None:
    path = make_rich_pe(tmp_path / "stable.exe", KEY, [(0x0001, 1, 2), (0x0104, 0x0E24, 1)])
    first = inspect_rich_header(path).to_dict()
    second = inspect_rich_header(path).to_dict()
    assert first == second


def test_mcp_rich_tool(tmp_path: Path) -> None:
    path = make_rich_pe(tmp_path / "tool.exe", KEY, [(0x0001, 1, 11), (0x0104, 0x0E24, 1)])
    payload = tools.codevanta_rich(str(path))
    assert payload["valid"] is True
    assert payload["compiler_guess"] == "MSVC 14.x link 14.36"
    assert payload["total_object_count"] == 12
    assert payload["evidence"]["source"] == "pe.rich"
    assert payload["evidence"]["confidence"] == "high"
    with pytest.raises(AnalysisError, match="file not found"):
        tools.codevanta_rich(str(tmp_path / "ghost.exe"))

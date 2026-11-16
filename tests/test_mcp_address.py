"""MCP tool addresses accept both integers and ``0x``-prefixed hex text.

A virtual address is written by hand as ``"0x140001000"``, but MCP clients
send JSON integers. Both forms must reach the analysis layer as the same
value, and junk must fail with the typed analysis error instead of a
``TypeError`` from inside the tool.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = REPO_ROOT / "samples" / "pe64_text.bin"

ENTRY = 0x140001000


@pytest.fixture()
def sample() -> Path:
    assert SAMPLE.is_file(), f"missing sample: {SAMPLE}"
    return SAMPLE


def test_check_address_accepts_int_hex_and_rejects_junk() -> None:
    assert tools._check_address(ENTRY) == ENTRY
    assert tools._check_address(f"0x{ENTRY:x}") == ENTRY
    assert tools._check_address(f"0x{ENTRY:X}") == ENTRY
    with pytest.raises(AnalysisError):
        tools._check_address(-1)
    with pytest.raises(AnalysisError):
        tools._check_address("not-an-address")  # type: ignore[arg-type]
    with pytest.raises(AnalysisError):
        tools._check_address(True)  # type: ignore[arg-type]


def test_decompile_hex_string_matches_integer(sample: Path) -> None:
    from_text = tools.decompile(str(sample), address=f"0x{ENTRY:x}")
    from_int = tools.decompile(str(sample), address=ENTRY)
    assert from_text["text"] == from_int["text"]
    assert from_text["address"] == from_int["address"]


def test_disasm_hex_string_matches_integer(sample: Path) -> None:
    from_text = tools.disasm(str(sample), address=f"0x{ENTRY:x}", count=4)
    from_int = tools.disasm(str(sample), address=ENTRY, count=4)
    assert from_text == from_int

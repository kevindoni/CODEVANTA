"""MCP tool layer tests (plain functions and in-process server)."""

from __future__ import annotations

import asyncio
import json
import struct
from pathlib import Path

import pytest

from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools
from codevanta.mcp_server.server import build_server
from codevanta.storage.session import SessionError


def test_binary_info_on_elf(elf64_path: Path) -> None:
    info = tools.binary_info(str(elf64_path))
    assert info["format"] == "ELF"
    assert info["architecture"] == "x86_64"
    assert info["entry_point"] == "0x401000"


def test_binary_info_missing_file(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError):
        tools.binary_info(str(tmp_path / "missing.bin"))


def test_functions_reports_entry_point(elf64_path: Path) -> None:
    payload = tools.functions(str(elf64_path))
    assert payload["count"] == 1
    item = payload["items"][0]
    assert item["source"] == "binary.entry_point"
    assert item["confidence"] == "medium"


def test_strings_and_disasm_on_elf(elf64_text_path: Path) -> None:
    payload = tools.strings(str(elf64_text_path), min_length=3)
    assert "items" in payload
    disassembly = tools.disasm(str(elf64_text_path), count=3)
    assert [item["text"] for item in disassembly["instructions"]] == [
        "push rbp",
        "mov rbp, rsp",
        "ret",
    ]


def test_analyze_has_provenance(elf64_text_path: Path) -> None:
    report = tools.analyze(str(elf64_text_path))
    assert report["provenance"]["tool"] == "codevanta"
    assert report["binary"]["format"] == "ELF"
    assert report["disassembly"]["instruction_count"] == 3


def test_server_lists_nine_tools() -> None:
    listed = asyncio.run(build_server().list_tools())
    names = sorted(tool.name for tool in listed)
    assert names == [
        "codevanta_analyze",
        "codevanta_cfg",
        "codevanta_disasm",
        "codevanta_functions",
        "codevanta_info",
        "codevanta_session_list",
        "codevanta_session_save",
        "codevanta_strings",
        "codevanta_xrefs",
    ]


def _payload(result: object) -> dict:
    structured = getattr(result, "structuredContent", None)
    if structured:
        return structured
    for block in getattr(result, "content", []):
        text = getattr(block, "text", None)
        if text:
            return json.loads(text)
    raise AssertionError(f"no payload in {result!r}")


def test_server_call_tool_returns_payload(elf64_text_path: Path) -> None:
    result = asyncio.run(
        build_server().call_tool("codevanta_info", {"path": str(elf64_text_path)})
    )
    payload = _payload(result)
    assert payload["format"] == "ELF"
    assert payload["architecture"] == "x86_64"


TEXT_ADDRESS = 0x401000


def _write_elf64(path: Path, code: bytes, *, text_address: int = TEXT_ADDRESS) -> Path:
    """Write a minimal ELF64 executable with one executable ``.text`` section."""
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_offset = 0x40
    shstrtab_offset = (text_offset + len(code) + 7) & ~7
    shoff = (shstrtab_offset + len(shstrtab) + 7) & ~7
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,             # e_type = ET_EXEC
        62,            # e_machine = EM_X86_64
        1,             # e_version
        text_address,  # e_entry
        0,             # e_phoff
        shoff,         # e_shoff
        0,             # e_flags
        64,            # e_ehsize
        56,            # e_phentsize
        0,             # e_phnum
        64,            # e_shentsize
        3,             # e_shnum
        2,             # e_shstrndx
    )
    text_section = struct.pack(
        "<IIQQQQIIQQ",
        1,              # sh_name -> ".text"
        1,              # sh_type = SHT_PROGBITS
        6,              # sh_flags = SHF_ALLOC | SHF_EXECINSTR
        text_address,   # sh_addr
        text_offset,    # sh_offset
        len(code),      # sh_size
        0,              # sh_link
        0,              # sh_info
        16,             # sh_addralign
        0,              # sh_entsize
    )
    shstrtab_section = struct.pack(
        "<IIQQQQIIQQ",
        7,                  # sh_name -> ".shstrtab"
        3,                  # sh_type = SHT_STRTAB
        0,                  # sh_flags
        0,                  # sh_addr
        shstrtab_offset,    # sh_offset
        len(shstrtab),      # sh_size
        0,
        0,
        1,
        0,
    )
    blob = bytearray(shoff + 3 * 64)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob[shoff + 64 : shoff + 128] = text_section
    blob[shoff + 128 : shoff + 192] = shstrtab_section
    path.write_bytes(bytes(blob))
    return path


@pytest.fixture
def call_elf_path(tmp_path: Path) -> Path:
    """ELF64 sample whose ``.text`` contains ``call 0x401010; ret``."""
    return _write_elf64(tmp_path / "call.bin", bytes.fromhex("e80b000000c3"))


@pytest.fixture
def branchy_elf_path(tmp_path: Path) -> Path:
    """ELF64 sample with ``test eax, eax; je +2; nop; nop; ret``."""
    return _write_elf64(tmp_path / "branchy.bin", bytes.fromhex("85c074029090c3"))

def test_xrefs_reports_direct_call(call_elf_path: Path) -> None:
    payload = tools.xrefs(str(call_elf_path))

    assert payload["count"] >= 1
    assert payload["returned"] == len(payload["items"]) >= 1
    assert payload["truncated"] is False
    assert payload["scanned_bytes"] > 0
    item = payload["items"][0]
    assert item["kind"] == "call"
    assert item["from_address"] == "0x401000"
    assert item["to_address"] == "0x401010"
    assert item["evidence"]["source"] == "capstone.direct_call"


def test_xrefs_limit_truncates_items(call_elf_path: Path) -> None:
    payload = tools.xrefs(str(call_elf_path), limit=1)

    assert payload["count"] >= 1
    assert payload["returned"] == 1


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"limit": 0}, "limit"),
        ({"limit": tools.MAX_XREF_LIMIT + 1}, "limit"),
        ({"max_bytes": 0}, "max_bytes"),
        ({"max_bytes": tools.MAX_XREF_BYTES + 1}, "max_bytes"),
    ],
)
def test_xrefs_rejects_out_of_range_bounds(
    call_elf_path: Path, kwargs: dict[str, int], match: str
) -> None:
    with pytest.raises(AnalysisError, match=match):
        tools.xrefs(str(call_elf_path), **kwargs)


def test_cfg_splits_blocks(branchy_elf_path: Path) -> None:
    payload = tools.cfg(str(branchy_elf_path))

    assert payload["start"] == "0x401000"
    assert len(payload["blocks"]) >= 2
    assert payload["instruction_count"] >= 4
    assert payload["truncated"] is False
    assert payload["warnings"] == []
    assert payload["blocks"][0]["start"] == "0x401000"
    assert payload["blocks"][0]["terminator"] == "je"


def test_cfg_rejects_out_of_range_bounds(branchy_elf_path: Path) -> None:
    with pytest.raises(AnalysisError, match="max_instructions"):
        tools.cfg(str(branchy_elf_path), max_instructions=0)
    with pytest.raises(AnalysisError, match="max_blocks"):
        tools.cfg(str(branchy_elf_path), max_blocks=0)


def test_cfg_unknown_function_is_an_analysis_error(branchy_elf_path: Path) -> None:
    with pytest.raises(AnalysisError, match="not found"):
        tools.cfg(str(branchy_elf_path), function="no_such_function")


def test_session_save_and_list(
    elf64_text_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "sessions.db"
    monkeypatch.setenv("CODEVANTA_DB", str(db_path))

    saved = tools.session_save(str(elf64_text_path), notes="mcp test")

    session = saved["session"]
    assert saved["db"] == str(db_path)
    assert session["session_id"]
    assert session["notes"] == "mcp test"
    assert session["format"] == "ELF"
    assert session["functions"] >= 1
    assert db_path.exists()

    listed = tools.session_list()

    assert listed["db"] == str(db_path)
    assert listed["count"] == 1
    assert [item["session_id"] for item in listed["items"]] == [session["session_id"]]


def test_session_save_respects_explicit_db(
    elf64_text_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CODEVANTA_DB", raising=False)
    db_path = tmp_path / "explicit.db"

    saved = tools.session_save(str(elf64_text_path), db=str(db_path))

    assert saved["db"] == str(db_path)
    assert tools.session_list(db=str(db_path), limit=5)["count"] == 1


def test_session_list_rejects_bad_limit(tmp_path: Path) -> None:
    db_path = str(tmp_path / "empty.db")
    with pytest.raises(SessionError, match="limit"):
        tools.session_list(db=db_path, limit=0)
    with pytest.raises(SessionError, match="limit"):
        tools.session_list(db=db_path, limit=tools.MAX_SESSION_LIMIT + 1)

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

TEXT_VA = 0x401000
#: `test eax, eax; je 0x401006; nop; nop; ret` — one branch into a return.
BRANCHY_CODE = bytes.fromhex("85c074029090c3")


def _write_elf64_code(path: Path, code: bytes, *, executable: bool = True) -> Path:
    """Write an ELF64 file with one ``.text`` section at 0x401000 holding ``code``.

    Built here (not in conftest) because the phase 2 tool tests need arbitrary
    code bytes and a non-executable variant of the same layout.
    """
    shstr = b"\x00.text\x00.shstrtab\x00"
    text_offset = 0x40
    shstr_offset = text_offset + len(code)
    shoff = (shstr_offset + len(shstr) + 7) & ~7
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, TEXT_VA, 0, shoff, 0, 64, 56, 0, 64, 3, 2
    )
    # SHF_ALLOC|SHF_EXECINSTR for the code case, SHF_ALLOC|SHF_WRITE otherwise.
    flags = 0x6 if executable else 0x3
    text_section = struct.pack(
        "<IIQQQQIIQQ", 1, 1, flags, TEXT_VA, text_offset, len(code), 0, 0, 16, 0
    )
    str_section = struct.pack(
        "<IIQQQQIIQQ", 7, 3, 0, 0, shstr_offset, len(shstr), 0, 0, 1, 0
    )
    blob = bytearray(shoff)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[shstr_offset : shstr_offset + len(shstr)] = shstr
    blob += bytes(64) + text_section + str_section
    path.write_bytes(bytes(blob))
    return path


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


def test_server_lists_tools() -> None:
    listed = asyncio.run(build_server().list_tools())
    names = sorted(tool.name for tool in listed)
    assert names == [
        "codevanta_analyze",
        "codevanta_cfg",
        "codevanta_disasm",
        "codevanta_functions",
        "codevanta_info",
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


def test_xrefs_reports_call_reference(tmp_path: Path) -> None:
    path = _write_elf64_code(tmp_path / "call.bin", bytes.fromhex("e80b000000c3"))

    payload = tools.xrefs(str(path))

    assert payload["count"] == 1
    assert payload["returned"] == 1
    assert payload["truncated"] is False
    item = payload["xrefs"][0]
    assert item["from_address"] == "0x401000"
    assert item["to_address"] == "0x401010"
    assert item["kind"] == "call"
    assert item["instruction"] == "call 0x401010"
    assert item["evidence"]["source"] == "capstone.direct_call"
    assert item["evidence"]["confidence"] == "certain"
    assert payload["scanned_sections"] == [".text"]
    assert payload["scan_truncated"] is False
    assert payload["warnings"] == []
    assert payload["evidence"]["source"] == "capstone.xref_scan"


def test_xrefs_limit_truncates_result(tmp_path: Path) -> None:
    # jmp 0x40100a ; nop x8 ; call 0x40100f ; ret -> two references
    code = bytes.fromhex("eb08" + "90" * 8 + "e800000000" + "c3")
    path = _write_elf64_code(tmp_path / "two.bin", code)

    payload = tools.xrefs(str(path), limit=1)

    assert payload["count"] == 2
    assert payload["returned"] == 1
    assert payload["truncated"] is True
    assert len(payload["xrefs"]) == 1


def test_xrefs_invalid_inputs_raise(tmp_path: Path) -> None:
    path = _write_elf64_code(tmp_path / "reject.bin", bytes.fromhex("c3"))

    with pytest.raises(AnalysisError, match="limit"):
        tools.xrefs(str(path), limit=0)
    with pytest.raises(AnalysisError, match="limit"):
        tools.xrefs(str(path), limit=100_001)
    with pytest.raises(AnalysisError, match="max_bytes"):
        tools.xrefs(str(path), max_bytes=0)


def test_xrefs_without_executable_sections_returns_warnings(tmp_path: Path) -> None:
    path = _write_elf64_code(
        tmp_path / "data.bin", bytes.fromhex("740290c3"), executable=False
    )

    payload = tools.xrefs(str(path))

    assert payload["count"] == 0
    assert payload["xrefs"] == []
    assert payload["scanned_sections"] == []
    assert any("no executable sections" in warning for warning in payload["warnings"])
    assert payload["evidence"]["source"] == "capstone.xref_scan"


def test_cfg_builds_blocks_from_entry_point(tmp_path: Path) -> None:
    path = _write_elf64_code(tmp_path / "branchy.bin", BRANCHY_CODE)

    payload = tools.cfg(str(path))

    assert payload["function_address"] == "0x401000"
    assert payload["function_name"] is None
    assert payload["block_count"] == 3
    assert payload["instruction_count"] == 5
    assert payload["truncated"] is False
    assert payload["evidence"]["source"] == "cfg.linear_sweep"
    first = payload["blocks"][0]
    assert first["terminator"] == "je"
    assert first["successors"] == ["0x401004", "0x401006"]
    assert first["instructions"][1]["mnemonic"] == "je"
    assert first["evidence"]["method"] == "basic_block"


def test_cfg_accepts_address_and_rejects_unknown_function(tmp_path: Path) -> None:
    path = _write_elf64_code(tmp_path / "targeted.bin", BRANCHY_CODE)

    by_address = tools.cfg(str(path), address=0x401004)

    assert by_address["function_address"] == "0x401004"
    assert by_address["block_count"] == 1  # nop ; nop ; ret from mid-section
    with pytest.raises(AnalysisError, match="not found"):
        tools.cfg(str(path), function="missing")


def test_cfg_non_executable_address_raises(tmp_path: Path) -> None:
    path = _write_elf64_code(tmp_path / "guard.bin", BRANCHY_CODE)

    with pytest.raises(AnalysisError, match="executable"):
        tools.cfg(str(path), address=0x402000)


def test_cfg_invalid_limits_raise(tmp_path: Path) -> None:
    path = _write_elf64_code(tmp_path / "limits.bin", BRANCHY_CODE)

    with pytest.raises(AnalysisError, match="max_instructions"):
        tools.cfg(str(path), max_instructions=0)
    with pytest.raises(AnalysisError, match="max_instructions"):
        tools.cfg(str(path), max_instructions=100_001)
    with pytest.raises(AnalysisError, match="max_blocks"):
        tools.cfg(str(path), max_blocks=0)


def test_server_call_tool_xrefs(tmp_path: Path) -> None:
    path = _write_elf64_code(tmp_path / "server_xrefs.bin", bytes.fromhex("e80b000000c3"))

    result = asyncio.run(
        build_server().call_tool("codevanta_xrefs", {"path": str(path)})
    )
    payload = _payload(result)

    assert payload["count"] == 1
    assert payload["xrefs"][0]["kind"] == "call"


def test_server_call_tool_cfg(tmp_path: Path) -> None:
    path = _write_elf64_code(tmp_path / "server_cfg.bin", BRANCHY_CODE)

    result = asyncio.run(build_server().call_tool("codevanta_cfg", {"path": str(path)}))
    payload = _payload(result)

    assert payload["function_address"] == "0x401000"
    assert payload["block_count"] == 3
    assert payload["evidence"]["source"] == "cfg.linear_sweep"

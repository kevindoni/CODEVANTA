"""MCP tool layer tests (plain functions and in-process server)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from core.report import AnalysisError
from mcp_server import tools
from mcp_server.server import build_server


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


def test_server_lists_five_tools() -> None:
    listed = asyncio.run(build_server().list_tools())
    names = sorted(tool.name for tool in listed)
    assert names == [
        "codevanta_analyze",
        "codevanta_disasm",
        "codevanta_functions",
        "codevanta_info",
        "codevanta_strings",
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

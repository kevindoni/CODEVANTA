"""Tests for the token-efficient MCP gateway meta-tools."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from codevanta.mcp_server.gateway import (
    DEFAULT_MAX_TOKENS,
    RESULTS_DIR_ENV,
    build_gateway_server,
    clamp_max_tokens,
)
from codevanta.mcp_server.server import build_server

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = REPO_ROOT / "samples" / "pe64_text.bin"

GATEWAY_TOOLS = {"search", "schema", "call", "result_read", "result_grep"}


def _invoke(
    server: MCPServer,
    name: str,
    arguments: dict | None = None,
) -> dict:
    """Call one MCP tool in-process and parse its JSON reply."""
    result = asyncio.run(server.call_tool(name, arguments or {}))
    assert not result.is_error, result
    assert result.content, f"{name} returned no content"
    text = result.content[0].text
    assert isinstance(text, str)
    return json.loads(text)


def test_gateway_exposes_a_small_registry_and_leaves_the_source_alone() -> None:
    gateway = build_gateway_server()
    listed = asyncio.run(gateway.list_tools())
    names = {tool.name for tool in listed}
    assert names == GATEWAY_TOOLS
    assert len(names) < 10

    # The flat registry is untouched: clients that want all schemas still get them.
    source = asyncio.run(build_server().list_tools())
    assert len(source) == 126


def test_search_returns_compact_rows_and_honors_query_and_limit() -> None:
    gateway = build_gateway_server()

    page = _invoke(gateway, "search", {"query": "binary", "limit": 3})
    assert page["total"] >= 3
    assert page["count"] <= 3
    assert len(page["tools"]) <= 3
    for row in page["tools"]:
        assert set(row) == {"name", "required", "description"}
        assert "binary" in (row["name"] + " " + row["description"]).lower()
        assert "properties" not in row
        assert "parameters" not in row

    exact = _invoke(gateway, "search", {"query": "codevanta_info"})
    assert [row["name"] for row in exact["tools"]] == ["codevanta_info"]
    assert exact["tools"][0]["required"] == ["path"]


def test_schema_returns_one_compact_schema_with_properties() -> None:
    gateway = build_gateway_server()

    schema = _invoke(gateway, "schema", {"tool": "codevanta_info"})
    assert schema["name"] == "codevanta_info"
    assert schema["required"] == ["path"]
    assert schema["properties"]["path"]["type"] == "string"
    # Presentation metadata is dropped to keep the reply small.
    assert "title" not in schema["properties"]["path"]

    disasm = _invoke(gateway, "schema", {"tool": "codevanta_disasm"})
    assert disasm["properties"]["address"]["anyOf"][0]["type"] == "integer"

    nav = _invoke(gateway, "schema", {"tool": "codevanta_nav"})
    assert "mark" in nav["properties"]["action"]["enum"]


def test_budget_default_and_clamp() -> None:
    assert clamp_max_tokens(DEFAULT_MAX_TOKENS) == 1500
    assert clamp_max_tokens(1) == 100
    assert clamp_max_tokens(10**9) == 50_000
    assert clamp_max_tokens(True) == DEFAULT_MAX_TOKENS
    assert clamp_max_tokens("big") == DEFAULT_MAX_TOKENS


def test_unknown_tool_and_tool_crash_are_typed_errors() -> None:
    gateway = build_gateway_server()

    unknown = _invoke(gateway, "call", {"tool": "does_not_exist"})
    assert unknown["code"] == "unknown_tool"
    assert "error" in unknown
    assert _invoke(gateway, "schema", {"tool": "does_not_exist"})["code"] == "unknown_tool"

    source = MCPServer(name="synthetic-errors", version="0.0.0")

    @source.tool(description="Always fail, to prove the gateway contains crashes.")
    def synthetic_boom() -> dict:
        raise RuntimeError("kaboom")

    crashing = build_gateway_server(source)
    failure = _invoke(crashing, "call", {"tool": "synthetic_boom"})
    assert failure["code"] == "tool_error"
    assert failure["tool"] == "synthetic_boom"


def test_call_runs_the_underlying_tool_in_process() -> None:
    assert SAMPLE.is_file(), f"missing sample: {SAMPLE}"
    gateway = build_gateway_server()

    payload = _invoke(
        gateway,
        "call",
        {"tool": "codevanta_info", "arguments": {"path": str(SAMPLE)}},
    )
    assert payload["format"] == "PE"
    assert payload["architecture"] == "x86_64"
    assert payload["path"] == str(SAMPLE)


def test_oversized_call_is_stored_and_retrievable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv(RESULTS_DIR_ENV, str(tmp_path))

    source = MCPServer(name="synthetic-big", version="0.0.0")

    @source.tool(description="Return an oversized payload with a discoverable needle.")
    def synthetic_big() -> dict:
        return {
            "needle": "GATEWAY_NEEDLE_42",
            "unicode": "h\u00e9llo-\u65e5\u672c",
            "blob": "x" * 20_000,
        }

    gateway = build_gateway_server(source)
    envelope = _invoke(
        gateway,
        "call",
        {"tool": "synthetic_big", "max_tokens": 200},
    )
    assert envelope["total_tokens"] > 200
    assert envelope["preview"]
    assert "result_id" in envelope
    result_id = envelope["result_id"]
    stored = tmp_path / f"{result_id}.json"
    assert stored.is_file()
    assert "h\u00e9llo-\u65e5\u672c" in stored.read_text(encoding="utf-8")

    page = _invoke(
        gateway,
        "result_read",
        {"result_id": result_id, "max_tokens": 200},
    )
    assert page["total_tokens"] == envelope["total_tokens"]
    assert page["text"]
    assert "blob" in page["text"]
    assert page["next_offset_tokens"] is not None

    subtree = _invoke(
        gateway,
        "result_read",
        {"result_id": result_id, "path": "needle"},
    )
    assert "GATEWAY_NEEDLE_42" in subtree["text"]

    hits = _invoke(
        gateway,
        "result_grep",
        {"result_id": result_id, "pattern": "GATEWAY_NEEDLE_42"},
    )
    assert hits["match_count"] == 1
    assert "GATEWAY_NEEDLE_42" in hits["matches"][0]["text"]


def test_invalid_result_id_is_rejected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(RESULTS_DIR_ENV, str(tmp_path))
    gateway = build_gateway_server()

    for bad_id in ("../escape", "..\\escape", "a/b", r"C:\secret", "."):
        payload = _invoke(gateway, "result_read", {"result_id": bad_id})
        assert payload["code"] == "invalid_result_id"
        assert "error" in payload
        assert not (tmp_path / "escape.json").exists()

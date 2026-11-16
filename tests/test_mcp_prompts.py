"""The six guided investigations exposed as MCP prompts."""

from __future__ import annotations

import asyncio

from codevanta.mcp_server.gateway import build_gateway_server
from codevanta.mcp_server.prompts import register_prompts
from codevanta.mcp_server.server import build_server

EXPECTED = {
    "triage_binary",
    "investigate_feature",
    "diff_versions",
    "audit_electron_app",
    "trace_crash",
    "prepare_rebuild",
}


def _names(prompts) -> set[str]:
    return {prompt.name for prompt in prompts}


def test_flat_server_registers_the_six_investigations() -> None:
    prompts = asyncio.run(build_server().list_prompts())

    assert _names(prompts) == EXPECTED


def test_gateway_keeps_the_same_investigations() -> None:
    prompts = asyncio.run(build_gateway_server().list_prompts())

    assert _names(prompts) == EXPECTED


def test_triage_prompt_renders_its_arguments() -> None:
    server = build_server()

    result = asyncio.run(server.get_prompt("triage_binary", {"path": "sample.bin"}))

    text = _text(result)
    assert "sample.bin" in text
    assert "codevanta_info" in text
    assert "codevanta_triage" in text


def test_investigate_prompt_names_the_feature() -> None:
    server = build_server()

    result = asyncio.run(
        server.get_prompt("investigate_feature", {"feature": "license check", "path": "a.exe"})
    )

    text = _text(result)
    assert '"license check"' in text
    assert "a.exe" in text


def test_register_prompts_is_idempotent() -> None:
    server = build_server()

    register_prompts(server)
    register_prompts(server)

    prompts = asyncio.run(server.list_prompts())
    assert _names(prompts) == EXPECTED


def _text(result) -> str:
    message = getattr(result, "messages", None)
    if message:
        parts = []
        for item in message:
            content = getattr(item, "content", item)
            text = getattr(content, "text", None)
            parts.append(text if isinstance(text, str) else str(content))
        return "\n".join(parts)
    return str(result)

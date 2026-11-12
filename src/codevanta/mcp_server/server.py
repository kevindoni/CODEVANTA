"""CODEVANTA MCP server (Model Context Protocol, stdio transport)."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from codevanta.analysis.xrefs import DEFAULT_MAX_BYTES

from . import tools

SERVER_NAME = "CODEVANTA"
SERVER_VERSION = "0.1.0"

INSTRUCTIONS = (
    "CODEVANTA performs static analysis of PE and ELF binaries and never executes "
    "targets. Every result carries evidence: check 'source', 'method', and "
    "'confidence' before relying on a finding. Exports and function symbols are "
    "high confidence; the entry point is a medium-confidence code candidate, not a "
    "proven function boundary. All addresses are absolute virtual addresses (VA)."
)


def build_server() -> MCPServer:
    """Create the MCP server and register the phase 1 and phase 2 tools."""
    server = MCPServer(
        name=SERVER_NAME,
        version=SERVER_VERSION,
        instructions=INSTRUCTIONS,
    )

    @server.tool(
        description=(
            "Load a PE or ELF binary and return format, architecture, sections, "
            "imports, exports, and symbols."
        )
    )
    def codevanta_info(path: str) -> dict:
        return tools.binary_info(path)

    @server.tool(
        description="List function candidates with detection source and confidence."
    )
    def codevanta_functions(path: str, limit: int = 200) -> dict:
        return tools.functions(path, limit=limit)

    @server.tool(
        description=(
            "Extract ASCII and UTF-16LE strings with file offset and mapped "
            "virtual address."
        )
    )
    def codevanta_strings(path: str, min_length: int = 4, limit: int = 200) -> dict:
        return tools.strings(path, min_length=min_length, limit=limit)

    @server.tool(
        description="Disassemble the entry point, a virtual address, or a named function."
    )
    def codevanta_disasm(
        path: str,
        address: int | None = None,
        function: str | None = None,
        count: int = 50,
    ) -> dict:
        return tools.disasm(path, address=address, function=function, count=count)

    @server.tool(
        description="Produce the full phase 1 JSON report with provenance and evidence."
    )
    def codevanta_analyze(path: str, string_limit: int = 5000) -> dict:
        return tools.analyze(path, string_limit=string_limit)

    @server.tool(
        description=(
            "List direct-branch cross references (call/jump/branch) recovered from "
            "executable sections, each with evidence and an optional callee name; "
            "indirect targets are skipped rather than guessed."
        )
    )
    def codevanta_xrefs(
        path: str,
        limit: int = 100,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> dict:
        return tools.xrefs(path, limit=limit, max_bytes=max_bytes)

    @server.tool(
        description=(
            "Build a linear-sweep control-flow graph (basic blocks and successor "
            "edges) for the entry point, a virtual address, or a named function; "
            "block boundaries are heuristic and carry medium-confidence evidence."
        )
    )
    def codevanta_cfg(
        path: str,
        address: int | None = None,
        function: str | None = None,
        max_instructions: int = 2000,
        max_blocks: int = 500,
    ) -> dict:
        return tools.cfg(
            path,
            address=address,
            function=function,
            max_instructions=max_instructions,
            max_blocks=max_blocks,
        )

    return server


def run() -> None:
    """Run the MCP server over stdio."""
    build_server().run(transport="stdio")

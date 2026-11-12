"""CODEVANTA MCP server (Model Context Protocol, stdio transport)."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

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
    """Create the MCP server and register the phase 1 tools."""
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

    return server


def run() -> None:
    """Run the MCP server over stdio."""
    build_server().run(transport="stdio")

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
    """Create the MCP server and register the analysis tools."""
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
            "List direct call, jump, and conditional-branch cross references from "
            "executable sections. Each reference carries evidence; indirect "
            "transfers are not resolved."
        )
    )
    def codevanta_xrefs(
        path: str,
        limit: int = 200,
        max_bytes: int = 4_000_000,
    ) -> dict:
        return tools.xrefs(path, limit=limit, max_bytes=max_bytes)

    @server.tool(
        description=(
            "Build a heuristic linear-sweep control-flow graph (basic blocks, "
            "successors, terminators) for the entry point, an address, or a named "
            "function. Block boundaries are heuristic, not proven."
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

    @server.tool(
        description=(
            "Analyze a binary and persist its fingerprint, function count, and "
            "string count as a new session in the local SQLite session database."
        )
    )
    def codevanta_session_save(
        path: str,
        db: str | None = None,
        notes: str | None = None,
    ) -> dict:
        return tools.session_save(path, db=db, notes=notes)

    @server.tool(
        description="List persisted analysis sessions, newest first."
    )
    def codevanta_session_list(db: str | None = None, limit: int = 20) -> dict:
        return tools.session_list(db=db, limit=limit)

    return server


def run() -> None:
    """Run the MCP server over stdio."""
    build_server().run(transport="stdio")

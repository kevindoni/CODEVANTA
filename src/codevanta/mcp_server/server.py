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
            "Build an inter-function call graph. Edges come from direct calls "
            "only, plus calls through a pointer slot that resolves to a known "
            "import (the target node is labelled with the import name) or to a "
            "statically known slot whose callee is unknown. Jumps, conditional "
            "branches, and unresolved indirect calls produce no edges. The "
            "caller of a call site is attributed heuristically to the nearest "
            "function candidate at or below the call address in the same "
            "section, so caller attribution is not proven. Check 'truncated' "
            "and 'warnings' before assuming the graph is complete."
        )
    )
    def codevanta_callgraph(
        path: str,
        limit_functions: int = 1000,
        limit_edges: int = 5000,
    ) -> dict:
        return tools.callgraph(
            path,
            limit_functions=limit_functions,
            limit_edges=limit_edges,
        )

    @server.tool(
        description=(
            "Compare two binaries structurally: functions (matched by address "
            "first, then by name after moving), sections, imports and exports. "
            "Nothing is executed. With deep=true, address-matched functions are "
            "also compared by a normalized-instruction fingerprint; equal "
            "digests are shape equality, not byte equality. Check 'warnings' "
            "before assuming the comparison is complete."
        )
    )
    def codevanta_diff(
        left: str,
        right: str,
        max_functions: int = 5000,
        deep: bool = False,
    ) -> dict:
        return tools.diff(
            left,
            right,
            max_functions=max_functions,
            deep=deep,
        )

    @server.tool(
        description=(
            "Decode a jump table at an absolute virtual address. mode='absolute' "
            "reads consecutive pointer-sized virtual addresses; mode='relative' "
            "reads signed 32-bit offsets added to 'base' (required in that "
            "mode). Scanning stops at the first slot that is not a usable code "
            "target and explains why in 'warnings'; a zero pointer also ends an "
            "absolute table. Entries are shape evidence, not proof that a "
            "dispatcher indexes the table."
        )
    )
    def codevanta_jump_table(
        path: str,
        address: int,
        mode: str = "absolute",
        base: int | None = None,
        entries: int = 256,
        executable_only: bool = True,
    ) -> dict:
        return tools.jump_table(
            path,
            address,
            mode=mode,
            base=base,
            entries=entries,
            executable_only=executable_only,
        )

    @server.tool(
        description=(
            "Return a SHA-256 fingerprint of the normalized instruction shape of "
            "the function starting at an address. Numeric literals are masked, "
            "so equal digests mean equal mnemonic/operand structure, not byte "
            "equality, and different digests are not a semantic difference. "
            "'truncated' means the digest covers only a prefix of the region."
        )
    )
    def codevanta_function_hash(
        path: str,
        address: int,
        max_instructions: int = 2000,
    ) -> dict:
        return tools.function_hash(
            path,
            address,
            max_instructions=max_instructions,
        )

    @server.tool(
        description=(
            "Compare two function regions as multisets of normalized instruction "
            "shapes and return a 'score' in 0..1 (shared / union token "
            "occurrences). Numeric literals, frame offsets and branch targets are "
            "masked, so a relocated or recompiled copy usually scores 1.0, while "
            "two structurally similar functions can score 1.0 without sharing "
            "meaning. The score is shape evidence at MEDIUM confidence, not "
            "semantic equivalence: different code can score high and a rewrite can "
            "score low. 'warnings' means a side was truncated to the instruction "
            "budget, so only prefixes were compared."
        )
    )
    def codevanta_similarity(
        path_a: str,
        address_a: int,
        path_b: str,
        address_b: int,
        max_instructions: int = 2000,
    ) -> dict:
        return tools.similarity(
            path_a,
            address_a,
            path_b,
            address_b,
            max_instructions=max_instructions,
        )

    @server.tool(
        description=(
            "Suggest struct fields for the memory a function accesses around a "
            "base register, starting at an address, a named function, or the "
            "entry point. Only '[reg]', '[reg + 0xNN]' and '[reg - 0xNN]' "
            "operands are read; index/scale/segment forms are skipped. Width "
            "comes from the Intel size keyword, direction from the operand "
            "position (cmp/test/call/jmp/push are always reads). 'alignment' is "
            "the gcd of the absolute non-zero offsets and 'array_groups' lists "
            "runs of at least three "
            "equally spaced fields; 'truncated' means max_fields dropped "
            "offsets. Fields are medium-confidence heuristics from operand "
            "shapes, not verified types, and carry no signedness or purpose."
        )
    )
    def codevanta_struct(
        path: str,
        address: int | None = None,
        function: str | None = None,
        max_instructions: int = 2000,
        max_fields: int = 64,
        include_stack: bool = False,
    ) -> dict:
        return tools.struct(
            path,
            address=address,
            function=function,
            max_instructions=max_instructions,
            max_fields=max_fields,
            include_stack=include_stack,
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

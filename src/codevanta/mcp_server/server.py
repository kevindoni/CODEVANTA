"""CODEVANTA MCP server (Model Context Protocol).

``stdio`` is the default transport, so existing client configurations keep
working. ``sse`` and ``streamable-http`` are also available for clients that
speak HTTP; they bind a local TCP port and are opt-in.
"""

from __future__ import annotations

import ipaddress
from typing import Annotated, Any, Literal, cast

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from codevanta.core.report import AnalysisError

from . import tools

SERVER_NAME = "CODEVANTA"
SERVER_VERSION = "0.1.0"

#: Transports the pinned ``mcp`` SDK can serve. ``MCPServer.run`` declares
#: ``Literal["stdio", "sse", "streamable-http"]`` and raises ``ValueError`` for
#: anything else, so this tuple is the SDK's list - not a CODEVANTA invention.
#: ``stdio`` is first because it is the default.
SUPPORTED_TRANSPORTS: tuple[str, ...] = ("stdio", "sse", "streamable-http")

#: Transports that bind a TCP socket, i.e. that can be reached from off-box.
HTTP_TRANSPORTS: frozenset[str] = frozenset({"sse", "streamable-http"})

#: Default bind address for the HTTP transports; loopback keeps the tools local.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000

#: The hosts the pinned MCP SDK hardens by itself. ``MCPServer.sse_app`` and
#: ``MCPServer.streamable_http_app`` compare their ``host`` argument with exactly
#: these strings before enabling DNS-rebinding protection, so ``127.0.0.2`` used
#: to bind without protection while ``"[::1]"`` did not bind at all. CODEVANTA
#: therefore never relies on that detection: it normalises the host once and
#: passes explicit :class:`TransportSecuritySettings` for a loopback bind (see
#: :func:`transport_security`).
SDK_HARDENED_HOSTS: tuple[str, ...] = ("127.0.0.1", "localhost", "::1")

HttpTransport = Literal["sse", "streamable-http"]

INSTRUCTIONS = (
    "CODEVANTA performs static analysis of PE and ELF binaries and never executes "
    "targets. Every result carries evidence: check 'source', 'method', and "
    "'confidence' before relying on a finding. Exports and function symbols are "
    "high confidence; the entry point is a medium-confidence code candidate, not a "
    "proven function boundary. All addresses are absolute virtual addresses (VA)."
)


#: ``codevanta_diff`` flags are forwarded to :func:`codevanta.mcp_server.tools.diff`
#: exactly as the client sent them. ``Any`` stops the MCP argument model from
#: rewriting the JSON first (``deep=1`` became ``True``, ``threshold=true`` became
#: ``1.0`` and ``threshold="0.9"`` became ``0.9``), so ``_check_bool`` and
#: ``_check_threshold`` make the decision and name the offending argument, while
#: ``Annotated`` keeps the published input schema advertising the documented type.
RawBooleanFlag = Annotated[Any, Field(json_schema_extra={"type": "boolean"})]
RawNumberFlag = Annotated[Any, Field(json_schema_extra={"type": "number"})]


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
    def codevanta_analyze(
        path: str,
        string_limit: int = 5000,
        include_xrefs: bool = False,
        include_cfg: bool = False,
        include_callgraph: bool = False,
    ) -> dict:
        return tools.analyze(
            path,
            string_limit=string_limit,
            include_xrefs=include_xrefs,
            include_cfg=include_cfg,
            include_callgraph=include_callgraph,
        )

    @server.tool(
        description=(
            "Per-section Shannon entropy sampled from file bytes with a packing "
            "triage hint: sections at or above the threshold (default 7.2 bits/byte) "
            "are flagged as possibly packed — a heuristic, not proof. Sections "
            "without file bytes carry entropy null with a warning."
        )
    )
    def codevanta_entropy(
        path: str,
        threshold: float = 7.2,
        max_sample_bytes: int = 65_536,
    ) -> dict:
        return tools.entropy(path, threshold=threshold, max_sample_bytes=max_sample_bytes)

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
            "Decompile one function to C-like text with a pluggable backend. "
            "backend='auto' (default) prefers a real decompiler -- Ghidra, then "
            "angr -- when one is installed and falls back to the built-in "
            "mnemonic-level pseudo-C renderer, listing every skipped backend in "
            "'warnings'; backend='native' always works; backend='angr' and "
            "backend='ghidra' are strict and fail with a clear error naming the "
            "backend and its install hint (never an ImportError) when that "
            "backend is not available. 'backend' reports the provider that "
            "actually produced 'text', which differs from the request under "
            "'auto', and 'blocks' is how many basic blocks the text covers. "
            "Control flow, argument count and types are inferred from "
            "mnemonics, so the text is low-confidence evidence and nothing is "
            "executed. Check 'warnings' before relying on a fallback rendering."
        )
    )
    def codevanta_decompile(
        path: str,
        address: int,
        backend: str = "auto",
        max_instructions: int = 2000,
        max_blocks: int = 500,
    ) -> dict:
        try:
            return tools.decompile(
                path,
                address,
                backend=backend,
                max_instructions=max_instructions,
                max_blocks=max_blocks,
            )
        except AnalysisError as exc:
            # An unavailable backend or a bad address is caller-correctable, but
            # the framework would otherwise replace the text with a generic
            # "Error executing tool" message that hides which argument failed.
            raise ToolError(str(exc)) from exc

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
            "digests are shape equality, not byte equality. With semantic=true "
            "the functions that address and name matching left unpaired are "
            "scored by instruction-shape overlap, and the best pairs reaching "
            "threshold (0.0..1.0, default 0.9) are reported as one 'changed' "
            "entry carrying 'similarity', so a moved function is no longer a "
            "removal plus an addition; that score is shape evidence, not proof "
            "of equivalence. The threshold is validated even when semantic is "
            "false. Arguments are never coerced: deep and semantic must be real "
            "booleans and threshold a real number, so deep=1, semantic=1, "
            "threshold=true and threshold='0.9' are rejected and the error names "
            "the offending argument. Check 'warnings' before assuming the "
            "comparison is complete."
        )
    )
    def codevanta_diff(
        left: str,
        right: str,
        max_functions: int = 5000,
        deep: RawBooleanFlag = False,
        semantic: RawBooleanFlag = False,
        threshold: RawNumberFlag = 0.9,
    ) -> dict:
        try:
            return tools.diff(
                left,
                right,
                max_functions=max_functions,
                deep=deep,
                semantic=semantic,
                threshold=threshold,
            )
        except AnalysisError as exc:
            # AnalysisError is an anticipated, caller-correctable failure, but the
            # framework would collapse it into a generic "Error executing tool"
            # crash message that hides which argument is wrong. Re-raising it as a
            # ToolError keeps the text (e.g. "deep must be a boolean") in the
            # is_error result the client receives.
            raise ToolError(str(exc)) from exc

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
            "Replay a saved dynamic-session trace against a binary and map every "
            "recorded hit onto the discovered function candidates. 'trace_path' "
            "is a capture the generated gdb or Frida script already printed: "
            "nothing is launched and no target is executed. 'provider' picks the "
            "format; 'auto' detects it from the file and 'provider_resolved' "
            "reports the choice, while a capture that cannot be placed, or that "
            "contradicts an explicit provider, is an error instead of a guess. "
            "The work is bounded (8 MB and 100000 lines read, plus 'max_hits'): "
            "'truncated' means a bound or the session's own limit cut the parse, "
            "and malformed lines land in 'warnings' rather than failing the "
            "call. Hits outside every candidate stay unattributed. A hit is "
            "evidence of one run, not proof that the code always executes."
        )
    )
    def codevanta_trace(
        path: str,
        trace_path: str,
        provider: Literal["auto", "gdb", "frida"] = "auto",
        max_hits: int | None = None,
    ) -> dict:
        try:
            return tools.trace(path, trace_path, provider=provider, max_hits=max_hits)
        except AnalysisError as exc:
            # A missing capture, an unreadable one, an unresolvable provider, a
            # provider mismatch or a bad max_hits is the caller's to fix, but the
            # framework would otherwise replace the reason with a generic
            # "Error executing tool" message that hides which argument failed.
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Extract DWARF debug-info functions and named type layouts from an ELF "
            "with producer metadata (highest-grade symbol evidence). Requires the "
            "optional pyelftools extra: pip install -e \".[dwarf]\"."
        )
    )
    def codevanta_dwarf(path: str, limit: int = 500) -> dict:
        return tools.dwarf(path, limit=limit)

    @server.tool(
        description=(
            "Discover C++ vtable candidates (runs of consecutive code pointers in "
            "data sections) and resolve thunk chains from slot targets — indirect "
            "cross-references at medium confidence, clearly labelled as heuristic."
        )
    )
    def codevanta_vtable(
        path: str,
        address: int | None = None,
        scan: bool = False,
        min_slots: int = 3,
        max_slots: int = 256,
        max_tables: int = 64,
        resolve_thunks: bool = True,
    ) -> dict:
        return tools.vtable(
            path,
            address=address,
            scan=scan,
            min_slots=min_slots,
            max_slots=max_slots,
            max_tables=max_tables,
            resolve_thunks=resolve_thunks,
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


def normalise_host(host: str) -> str:
    """Return ``host`` as the bare bind address uvicorn and the SDK expect.

    The rule, applied in this order:

    1. surrounding whitespace is stripped;
    2. one pair of surrounding IPv6 brackets is dropped, because ``[::1]`` is
       ``Host``-header/URL notation rather than a bindable address - uvicorn
       refused ``--host "[::1]"`` with "invalid IP address";
    3. ``localhost`` (in any case) becomes ``127.0.0.1``, the literal the SDK
       recognises as loopback, so neither the bind nor the ``Host`` allow-list
       depends on what a resolver returns for ``localhost``.

    Anything else is returned unchanged. Normalising once means the loopback
    guard, the ``Host``/``Origin`` allow-list and the ``bind()`` call all see the
    same string. This function does not validate: a blank or remote result is
    returned as-is and rejected by :func:`run`.

    Args:
        host: Requested bind host, possibly bracketed or ``localhost``.

    Returns:
        The bare address to bind, or ``""`` when ``host`` is blank.
    """
    candidate = host.strip()
    if len(candidate) > 2 and candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if candidate.lower() == "localhost":
        return "127.0.0.1"
    return candidate


def is_loopback_host(host: str) -> bool:
    """Return True when ``host`` is an address only reachable from this machine.

    The check runs on :func:`normalise_host` output, so ``[::1]``, `` 127.0.0.1 ``
    and ``LOCALHOST`` behave like their bare lower-case forms, and ``127.0.0.2``
    is loopback because the whole of ``127.0.0.0/8`` is. Everything else -
    including the wildcards ``0.0.0.0`` and ``::``, and any hostname such as
    ``example.com`` or ``localhost.evil.com`` - is treated as remote: a wildcard
    listens on every interface and a hostname may resolve to a routable address.

    Accepting ``127.0.0.2`` is only safe because :func:`run` also passes explicit
    :class:`TransportSecuritySettings`; the SDK's own hardening knows three
    literal hosts (:data:`SDK_HARDENED_HOSTS`), not the whole loopback range.
    """
    if not isinstance(host, str):
        return False
    candidate = normalise_host(host)
    if not candidate:
        return False
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def transport_security(host: str) -> TransportSecuritySettings | None:
    """Return DNS-rebinding protection for the loopback bind ``host``.

    The SDK builds its own settings only when its ``host`` argument is literally
    one of :data:`SDK_HARDENED_HOSTS`, which left ``127.0.0.2`` - accepted by
    :func:`is_loopback_host` - serving without any ``Host``/``Origin`` check.
    Passing the settings explicitly closes that gap: ``MCPServer.sse_app`` and
    ``MCPServer.streamable_http_app`` only fall back to their own detection when
    ``transport_security is None``, and the pinned SDK's ``run`` forwards the
    keyword to both HTTP transports.

    The lists describe the *actual* bind address in the SDK's own ``:<port>``
    wildcard shape, so ``Host: 127.0.0.2:8000`` and ``Origin:
    http://127.0.0.2:8000`` pass while ``Host: attacker.example`` and ``Origin:
    http://attacker.example`` get the SDK's ``421``/``403``. Only ``http://``
    origins are listed, matching the SDK's defaults for its own three hosts, and
    a request without an ``Origin`` header - every non-browser MCP client - is
    always accepted.

    A non-loopback bind returns ``None``: the SDK then leaves protection off,
    which is exactly what ``allow_remote=True`` promises - front a remote bind
    with your own authentication and ``Host``/``Origin`` validation.

    Args:
        host: Bind host, normalised or not.

    Returns:
        Settings for :meth:`MCPServer.run`, or ``None`` for a remote bind.
    """
    if not is_loopback_host(host):
        return None
    bind_host = normalise_host(host)
    authority = f"[{bind_host}]" if ":" in bind_host else bind_host
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[authority, f"{authority}:*"],
        allowed_origins=[f"http://{authority}", f"http://{authority}:*"],
    )


def run(
    transport: str = "stdio",
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    allow_remote: bool = False,
) -> None:
    """Serve the CODEVANTA tools over MCP.

    ``transport="stdio"`` is the default and behaves exactly as before: the
    server speaks JSON-RPC over stdin/stdout and ``host``/``port`` are unused,
    so no existing client configuration changes meaning. ``"sse"`` and
    ``"streamable-http"`` bind ``host:port`` instead.

    The HTTP transports are network-exposed and these tools read arbitrary
    local files, so a non-loopback ``host`` is refused unless ``allow_remote``
    is set.

    ``host`` is normalised once through :func:`normalise_host` - whitespace
    stripped, surrounding IPv6 brackets dropped, ``localhost`` mapped to
    ``127.0.0.1`` - and that single value is used for the loopback guard, the
    ``Host``/``Origin`` allow-list and the bind. Two consequences of the SDK's
    own behaviour are worth spelling out, because the pinned SDK hardens only
    the three literal strings in :data:`SDK_HARDENED_HOSTS`:

    * ``127.0.0.2`` (and the rest of ``127.0.0.0/8``) is accepted *and* hardened:
      :func:`transport_security` passes explicit
      :class:`TransportSecuritySettings` naming the real bind address, instead
      of relying on the SDK's detection, which does not fire for it.
    * ``"[::1]"`` is un-bracketed to ``::1`` before binding, so it binds and is
      hardened; the bracketed form used to fail inside uvicorn.

    A non-loopback bind (``allow_remote=True``) gets no automatic hardening -
    front it with your own authentication and ``Host``/``Origin`` validation.

    Args:
        transport: One of :data:`SUPPORTED_TRANSPORTS`.
        host: Bind address for the HTTP transports (default loopback).
        port: Bind port for the HTTP transports; ``0`` picks a free port.
        allow_remote: Permit a non-loopback ``host``.

    Raises:
        AnalysisError: Unknown transport, malformed host/port, or a
            non-loopback host without ``allow_remote``.
    """
    if transport not in SUPPORTED_TRANSPORTS:
        supported = ", ".join(SUPPORTED_TRANSPORTS)
        raise AnalysisError(
            f"unknown MCP transport {transport!r}; supported transports: {supported}"
        )

    if transport == "stdio":
        # Identical to the previous no-argument behaviour.
        build_server().run(transport="stdio")
        return

    if not isinstance(host, str) or not host.strip():
        raise AnalysisError(f"invalid MCP bind host {host!r}; expected a hostname or IP address")
    bind_host = normalise_host(host)
    if not is_loopback_host(bind_host) and not allow_remote:
        raise AnalysisError(
            f"refusing to bind the MCP server to non-loopback host {host!r}: these tools "
            "read local files. Pass allow_remote=True to override."
        )
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise AnalysisError(f"invalid MCP port {port!r}; expected an integer in 0..65535")

    build_server().run(
        transport=cast("HttpTransport", transport),
        host=bind_host,
        port=port,
        transport_security=transport_security(bind_host),
    )


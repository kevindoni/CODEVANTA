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

from codevanta.analysis.cdp_client import DEFAULT_ENDPOINT as WEB_DEFAULT_ENDPOINT
from codevanta.analysis.cdp_client import DEFAULT_OBSERVE_MS as WEB_DEFAULT_OBSERVE_MS
from codevanta.analysis.solver import DEFAULT_TIMEOUT_MS as SOLVER_DEFAULT_TIMEOUT_MS
from codevanta.analysis.uart_decode import DEFAULT_BAUD as UART_DEFAULT_BAUD
from codevanta.analysis.uart_decode import DEFAULT_DATA_BITS as UART_DEFAULT_DATA_BITS
from codevanta.analysis.uart_decode import DEFAULT_PARITY as _UART_DEFAULT_PARITY
from codevanta.analysis.uart_decode import DEFAULT_STOP_BITS as UART_DEFAULT_STOP_BITS
from codevanta.core.report import AnalysisError

from . import tools
from .ext_assets import TOOL_DESCRIPTION_PE_ASSETS as PE_ASSETS_DESCRIPTION
from .ext_expose import TOOL_DESCRIPTION_EMULATE as EXPOSE_EMULATE_DESCRIPTION
from .ext_expose import TOOL_DESCRIPTION_TYPES as EXPOSE_TYPES_DESCRIPTION
from .ext_expose import TOOL_DESCRIPTION_WASM as EXPOSE_WASM_DESCRIPTION
from .ext_fridasession import DEFAULT_FRIDA_DURATION as FRIDA_DEFAULT_DURATION
from .ext_fridasession import TOOL_DESCRIPTION_FRIDA_CLOSE as FRIDA_CLOSE_DESCRIPTION
from .ext_fridasession import TOOL_DESCRIPTION_FRIDA_LOAD as FRIDA_LOAD_DESCRIPTION
from .ext_fridasession import TOOL_DESCRIPTION_FRIDA_SESSIONS as FRIDA_SESSIONS_DESCRIPTION
from .ext_fridasession import TOOL_DESCRIPTION_FRIDA_START as FRIDA_START_DESCRIPTION
from .ext_fridasession import TOOL_DESCRIPTION_FRIDA_STATUS as FRIDA_STATUS_DESCRIPTION
from .ext_solver import TOOL_DESCRIPTION as SYMBOLIC_SOLVE_DESCRIPTION
from .ext_uires import TOOL_DESCRIPTION_DIALOG_DECODE as UIRES_DIALOG_DESCRIPTION
from .ext_uires import TOOL_DESCRIPTION_UI_PREVIEW as UIRES_PREVIEW_DESCRIPTION
from .ext_webfw import TOOL_DESCRIPTION_SOURCEMAP as WEBFW_SOURCEMAP_DESCRIPTION
from .ext_webfw import TOOL_DESCRIPTION_UNPACK as WEBFW_UNPACK_DESCRIPTION
from .ext_wingui import TOOL_DESCRIPTION_WIN_SHOT as WINGUI_SHOT_DESCRIPTION
from .ext_wingui import TOOL_DESCRIPTION_WIN_TREE as WINGUI_TREE_DESCRIPTION
from .ext_wingui import TOOL_DESCRIPTION_WIN_WINDOWS as WINGUI_WINDOWS_DESCRIPTION

#: Upstream ``DEFAULT_PARITY`` is inferred plain ``str``; the MCP schema
#: publishes the literal union the UART decoder actually accepts.
UART_DEFAULT_PARITY = cast(Literal["none", "even", "odd"], _UART_DEFAULT_PARITY)

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
    "targets, with exactly two exceptions: the codevanta_debug tool runs a live gdb "
    "session and executes the target inside it, and the codevanta_proc_run tool "
    "executes the caller-selected command locally as an owned, bounded child "
    "process, both on the analyst's explicit request. "
    "Every result carries evidence: check 'source', 'method', and "
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
            "Run one LIVE gdb debug session: launch a target under "
            "gdb --interpreter=mi2 (this tool executes the target in a debugger "
            "it owns - the one exception to CODEVANTA's read-only rule), insert an "
            "optional breakpoint (function name or 0x address), perform one action "
            "at the stop (registers / memory at an address / backtrace / continue / "
            "step / next / quit), then shut the debugger down and verify the exit. "
            "Requires gdb on PATH; a machine without it gets a typed error naming "
            "the install step, never a traceback. Every result carries an "
            "'evidence' record naming the MI command that produced it and is "
            "evidence of one run, not a static property of the binary."
        )
    )
    def codevanta_debug(
        path: str,
        action: Literal[
            "registers", "memory", "backtrace", "continue", "step", "next", "quit"
        ] = "registers",
        break_at: str | None = None,
        address: int | None = None,
        length: int = 64,
        max_frames: int = 20,
    ) -> dict:
        try:
            return tools.debug(
                path,
                action,
                break_at=break_at,
                address=address,
                length=length,
                max_frames=max_frames,
            )
        except AnalysisError as exc:
            # A missing gdb, a bad action/argument combination or an MI refusal
            # is caller-correctable, but the framework would otherwise replace
            # the reason with a generic "Error executing tool" message that
            # hides which argument failed.
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

    @server.tool(
        description=(
            "Explore the paths through a function with the unicorn branch-decision "
            "replay. Honest limits: this is a unicorn exploration, not a symbolic "
            "executor -- the observed side of a branch is the real emulation "
            "result, the other side is forced by rewriting the guarding flag or "
            "counter ('seeded') and is assumed feasible, never proven: no path "
            "predicate, no constraint solving, no symbolic variables. Values are "
            "concrete, x86/x86-64 only, and the optional unicorn extra is "
            "required (pip install 'codevanta[emulation]'). The file is read and "
            "only ever executed inside the emulator, never on the host. Seeded "
            "directions are flagged per path and drop the summary to low "
            "confidence; a path is evidence about one concrete run, not a "
            "reachability proof."
        )
    )
    def codevanta_symbolic(
        path: str,
        address: int,
        max_paths: int = 64,
        max_steps: int = 2000,
    ) -> dict:
        return tools.symbolic(
            path,
            address,
            max_paths=max_paths,
            max_steps=max_steps,
        )

    @server.tool(
        description=(
            "Recover definition-use chains, constants and reaching definitions "
            "for the function at an address: one forward pass over the recursive "
            "CFG in which register writes become definitions that kill earlier "
            "ones and reads resolve against what is still known. Only provable "
            "shapes fold into 'constant_registers' (immediates, rip-relative "
            "loads, copies, add/sub/xor of two known values). Honest limits: "
            "the pass is a linearization, not a fixpoint -- joins take the "
            "highest-addressed predecessor -- so the summary is sound one "
            "definition at a time, not a dataflow proof. Undefined reads are "
            "reported in 'warnings'. The binary is read, never executed."
        )
    )
    def codevanta_dataflow(
        path: str,
        address: int,
        max_instructions: int = 2000,
        max_blocks: int = 500,
    ) -> dict:
        return tools.dataflow(
            path,
            address,
            max_instructions=max_instructions,
            max_blocks=max_blocks,
        )

    @server.tool(
        description=(
            "Compare two offline CODEVANTA artifacts. what='functions' or "
            "'strings' diff analyze report payloads (an evidence bundle is "
            "unwrapped to its 'report' entry automatically): functions "
            "match by name and function_hash fingerprint (shapes, not "
            "proof of identity, medium confidence), strings are exact set "
            "diffs. what='bundles' diffs evidence bundles by record kind "
            "and payload digest membership (exact, high confidence). "
            "what='reports' diffs two report payloads structurally by "
            "canonical-JSON sha256 per section plus element counts. "
            "what='metadata' diffs two binmeta MetadataReport documents by "
            "format kind and detail keys. Path-backed kinds take non-JSON "
            "files: what='wasm' (two WASM modules: section sets, bounded "
            "import/export name diffs, byte-size deltas), what='crash' "
            "(two ELF core dumps: signal, faulting module, bounded "
            "register deltas, same_crash_site verdict with confidence), "
            "what='sessions' (two session DBs: annotation count deltas, "
            "addresses only on one side), what='nav' (bookmark/comment/"
            "cursor diffs via NavStore), what='firmware' (magic-scan hits "
            "appeared/disappeared, heuristic provenance), what="
            "'screenshots' (two captured 8-bit PNG screenshots: exact "
            "pixel diff with changed-pixel ratio, per-channel mean deltas "
            "and an identical/minor/major verdict), what='har' (two HAR "
            "captures: entry-count delta, new/removed URL paths, "
            "status-code and method histogram diffs), what='sections' "
            "(two binaries' section tables: added/removed sections plus "
            "size and entropy changes), what='imports' (two binaries' "
            "import libraries: added/removed DLLs and function-count "
            "changes) and what='bridges' (two bridges_report() JSON "
            "snapshots: newly available/unavailable tools, version "
            "changes). Offline structure only; nothing is ever executed."
        )
    )
    def codevanta_compare(
        a: str,
        b: str,
        what: str = "functions",
        max_functions: int = tools.COMPARE_MAX_FUNCTIONS,
        max_strings: int = tools.COMPARE_MAX_STRINGS,
        max_changed_sections: int = tools.COMPARE_MAX_CHANGED_SECTIONS,
        max_detail_keys: int = tools.COMPARE_MAX_DETAIL_KEYS,
        max_rows: int = tools.COMPARE_MAX_ROWS,
    ) -> dict:
        return tools.compare(
            a,
            b,
            what=what,
            max_functions=max_functions,
            max_strings=max_strings,
            max_changed_sections=max_changed_sections,
            max_detail_keys=max_detail_keys,
            max_rows=max_rows,
        )

    @server.tool(
        description=(
            "Manage the residual-unknown ledger: typed records for what an "
            "analysis could not decide, with deterministic content ids, "
            "severity, open->resolved lifecycle and evidence references. "
            "action='list' returns records (optionally status-filtered), "
            "action='open' appends one (domain/summary required, ledger file "
            "created when missing), action='resolve' closes one id with an "
            "optional note. The ledger is a JSON payload that can be embedded "
            "in an evidence bundle as its 'unknowns' entry."
        )
    )
    def codevanta_unknowns(
        action: str,
        ledger: str,
        unknown_id: str | None = None,
        domain: str | None = None,
        summary: str | None = None,
        severity: str = tools.DEFAULT_UNKNOWN_SEVERITY,
        evidence_refs: list[str] | None = None,
        note: str | None = None,
        status: str | None = None,
        expected_revision: int | None = None,
    ) -> dict:
        return tools.unknowns(
            action,
            ledger,
            unknown_id=unknown_id,
            domain=domain,
            summary=summary,
            severity=severity,
            evidence_refs=evidence_refs,
            note=note,
            status=status,
            expected_revision=expected_revision,
        )

    @server.tool(
        description=(
            "Manage the obligation ledger (ledger v2): typed records for the "
            "evidence an analysis still owes, each with a required authority "
            "(parsed/computed/verified), confidence (low/medium/high), "
            "environment (host/device/network), recommended probes and "
            "evidence refs. action='list' (optionally status-filtered), "
            "'get' (one record with its immutable revision trail), 'add' "
            "(question required), 'discharge'/'waive' (close one open id, "
            "CAS via expected_revision), 'remove'. Deterministic content ids; "
            "the ledger is a JSON payload embeddable in an evidence bundle "
            "as its 'obligations' entry."
        )
    )
    def codevanta_obligations(
        action: str,
        ledger: str,
        obligation_id: str | None = None,
        question: str | None = None,
        required_authority: str = tools.DEFAULT_OBLIGATION_AUTHORITY,
        required_confidence: str = tools.DEFAULT_OBLIGATION_CONFIDENCE,
        required_environment: str = tools.DEFAULT_OBLIGATION_ENVIRONMENT,
        recommended_probes: list[str] | None = None,
        evidence_refs: list[str] | None = None,
        note: str | None = None,
        status: str | None = None,
        expected_revision: int | None = None,
    ) -> dict:
        return tools.codevanta_obligations(
            action,
            ledger,
            obligation_id=obligation_id,
            question=question,
            required_authority=required_authority,
            required_confidence=required_confidence,
            required_environment=required_environment,
            recommended_probes=recommended_probes,
            evidence_refs=evidence_refs,
            note=note,
            status=status,
            expected_revision=expected_revision,
        )

    @server.tool(
        description=(
            "Evaluate obligation coverage (ledger v2): match every "
            "obligation's evidence_refs in an obligations ledger against one "
            "evidence bundle's entry names (kinds), entry digests and payload "
            "record ids, and report a complete/partial/uncovered verdict per "
            "obligation plus overall counts. Deterministic ordering, fully "
            "offline."
        )
    )
    def codevanta_coverage(obligations_ledger: str, evidence_bundle: str) -> dict:
        return tools.codevanta_coverage(obligations_ledger, evidence_bundle)

    @server.tool(
        description=(
            "Auto-detect format metadata for a file or directory: APK signing "
            "block (v1/v2/v3), Go build info, Rust cargo-auditable, Python .pyc "
            "header, Electron fuses, ELF notes, kernel-module .modinfo, or a "
            "desktop app layout (Unity, IL2CPP, Unreal, Electron, .NET)."
        )
    )
    def codevanta_metadata(path: str) -> dict:
        return tools.codevanta_metadata(path)

    @server.tool(
        description=(
            "Summarise a crash dump file, auto-detecting the format: a Linux "
            "ELF core dump or an Apple .ips crash report (the leading magic "
            "bytes decide). Offline and read-only: the file is parsed, never "
            "executed, and the payload carries the format, the parsed summary "
            "fields and an evidence record stating how much of the finding "
            "was parse-verified."
        )
    )
    def codevanta_crash(path: str) -> dict:
        return tools.codevanta_crash(path)

    @server.tool(
        description=(
            "Auto-detect container formats in one file: WASM, EVM (a labelled "
            "heuristic verdict, evm_like), GGUF, safetensors, pcap/pcapng and "
            "firmware magics. Offline and read-only; the summary carries an "
            "evidence record with source/method/confidence."
        )
    )
    def codevanta_binmeta(path: str) -> dict:
        return tools.codevanta_binmeta(path)

    @server.tool(
        description=(
            "Summarise a Mach-O's embedded code signature (structure only, "
            "offline): the LC_CODE_SIGNATURE offset, the SuperBlob slot table "
            "(bounded), the code-directory identifier, the entitlements key "
            "list (bounded) and a certificate count from the CMS blob. No "
            "trust verification - hashes, chains and signatures are never "
            "checked. Unsigned files and malformed signatures surface as "
            "typed errors, never tracebacks."
        )
    )
    def codevanta_codesign(path: str) -> dict:
        return tools.codevanta_codesign(path)

    @server.tool(
        description=(
            "Introspect a SQLite database strictly read-only through the "
            "mode=ro&immutable=1 URI: a bounded table list with row counts, "
            "and with `table` that table's columns plus up to 10 sample rows "
            "(JSON-safe values). The tool cannot write, create journals or "
            "replay a WAL; a present -wal file is reported as ignored. "
            "Offline."
        )
    )
    def codevanta_sqlite(path: str, table: str | None = None) -> dict:
        return tools.codevanta_sqlite(path, table)

    @server.tool(
        description=(
            "Read-only Android device queries over adb: action='devices' "
            "lists attached devices/emulators; action='props'/'packages'/"
            "'processes'/'setting' inspect the device named by `device`; "
            "action='logcat' dumps recent log rows (bounded 200, optional "
            "pid/count). Device-mutating actions are limited to the app "
            "lifecycle: action='start'/'stop' launch or force-stop "
            "`package`, action='pull'/'push' move one bounded file (512 "
            "MiB) between `local_path` and `remote_path` with a host-side "
            "sha256. Requires adb on PATH - its absence surfaces as a typed "
            "error naming the platform-tools install step, never a "
            "traceback. Mutating actions (install, screencap, bugreport) "
            "are deliberately not exposed."
        )
    )
    def codevanta_adb(
        action: Literal[
            "devices",
            "props",
            "packages",
            "processes",
            "logcat",
            "pull",
            "push",
            "start",
            "stop",
            "setting",
        ],
        device: str | None = None,
        pid: int | None = None,
        count: int = 50,
        local_path: str | None = None,
        remote_path: str | None = None,
        package: str | None = None,
        namespace: str | None = None,
        key: str | None = None,
    ) -> dict:
        return tools.codevanta_adb(
            action,
            device,
            pid=pid,
            count=count,
            local_path=local_path,
            remote_path=remote_path,
            package=package,
            namespace=namespace,
            key=key,
        )

    @server.tool(
        description=(
            "Passively inspect one live Electron/Chromium page over CDP: list "
            "the debugger endpoint's targets, pick target_id (or the first "
            "page target) and return title, url, bounded resources and "
            "console traffic overheard during observe_ms. Skip-gated on "
            "endpoint reachability: an unreachable endpoint comes back as "
            "{\"available\": false, \"reason\": ...} with evidence, not an "
            "error. Read-only: only domain enables and navigation/resource "
            "queries are sent, never Runtime.evaluate."
        )
    )
    def codevanta_web_inspect(
        endpoint: str = WEB_DEFAULT_ENDPOINT,
        target_id: str | None = None,
        observe_ms: int = WEB_DEFAULT_OBSERVE_MS,
    ) -> dict:
        return tools.codevanta_web_inspect(
            endpoint,
            target_id=target_id,
            observe_ms=observe_ms,
        )

    @server.tool(
        description=(
            "List an Electron ASAR archive offline (bounded 512 file entries "
            "with honest totals), or with `extract` naming one in-archive "
            "entry read that entry (bounded 8 MiB) and report its size and "
            "SHA-256. Pure byte parsing; nothing is executed."
        )
    )
    def codevanta_asar(path: str, extract: str | None = None) -> dict:
        return tools.codevanta_asar(path, extract)

    @server.tool(
        description=(
            "Summarise a HAR (HTTP Archive) capture offline: entry count, "
            "total request time, started-time span, a content-type histogram "
            "(max 16 keys), unique hosts (max 32), the first 200 rows "
            "(method/url/status/time/content-type/grpc) and per-entry gRPC "
            "flags (content-type match or valid 5-byte frame prefix). Pure "
            "byte parsing; nothing is executed."
        )
    )
    def codevanta_web_capture(path: str) -> dict:
        return tools.codevanta_web_capture(path)

    @server.tool(
        description=(
            "Decode a protobuf wire-format body file into a structure-only "
            "field tree (field numbers, wire types, values: varint int, "
            "IEEE-754 float, nested fields or bounded hex). With grpc=true a "
            "leading 5-byte gRPC frame prefix is stripped first and "
            "reported. MEDIUM confidence: field numbers are semantic-free "
            "without the .proto schema. Warnings cover unknown wire types "
            "and truncated fields; never raises for message content."
        )
    )
    def codevanta_proto_decode(path: str, grpc: bool = False) -> dict:
        return tools.codevanta_proto_decode(path, grpc=grpc)

    @server.tool(description=SYMBOLIC_SOLVE_DESCRIPTION)
    def codevanta_symbolic_solve(
        path: str,
        address: int | None = None,
        max_paths: int = tools.DEFAULT_SYMBOLIC_MAX_PATHS,
        max_steps: int = tools.DEFAULT_SYMBOLIC_MAX_STEPS,
        solver_mode: Literal["auto", "naive"] = "auto",
        timeout_ms: int = SOLVER_DEFAULT_TIMEOUT_MS,
    ) -> dict:
        return tools.codevanta_symbolic_solve(
            path,
            address,
            max_paths=max_paths,
            max_steps=max_steps,
            solver_mode=solver_mode,
            timeout_ms=timeout_ms,
        )

    @server.tool(
        description=(
            "Summarize one sigrok .sr session archive offline: version, "
            "sample rate, device, channels, logic-file names and byte sizes, "
            "and the annotation count when the archive carries one. "
            "ZIP-bomb guarded; the logic data is stat'ed but never inflated."
        )
    )
    def codevanta_signal_sr(path: str) -> dict:
        return tools.codevanta_signal_sr(path)

    @server.tool(
        description=(
            "Decode a raw logic-0/1 capture file as UART with the pure-Python "
            "decoder-lite (medium confidence by design). One byte per sample: "
            "0 is logic low, anything else high; samplerate_hz must give at "
            "least 2 samples per baud bit. Offline; garbage captures decode "
            "to few or zero bytes with warnings."
        )
    )
    def codevanta_uart_decode(
        path: str,
        samplerate_hz: int,
        baud: int = UART_DEFAULT_BAUD,
        databits: int = UART_DEFAULT_DATA_BITS,
        parity: Literal["none", "even", "odd"] = UART_DEFAULT_PARITY,
        stopbits: int = UART_DEFAULT_STOP_BITS,
    ) -> dict:
        return tools.codevanta_uart_decode(
            path,
            samplerate_hz,
            baud=baud,
            databits=databits,
            parity=parity,
            stopbits=stopbits,
        )

    @server.tool(
        description=(
            "Parse one flattened devicetree blob (DTB) offline: a shallow, "
            "bounded walk returning the tree structure and, with `node`, the "
            "properties of that top-level node (the root's own properties "
            "when omitted). Unknown node names are typed errors."
        )
    )
    def codevanta_dtb(path: str, node: str | None = None) -> dict:
        return tools.codevanta_dtb(path, node)

    @server.tool(
        description=(
            "Read or write one session's navigation state: action='mark' "
            "pins a bookmark, 'comment' attaches a note, 'goto' moves the "
            "cursor and records the visit, 'cursor' reads it back and "
            "'bookmarks'/'comments'/'history' list the bounded state. Every "
            "action needs `session` and the session database path `db`; "
            "mark/comment/goto also need `address` (int or 0x-prefixed hex "
            "string). A missing session is a typed error with the "
            "'codevanta session save' hint. Offline."
        )
    )
    def codevanta_nav(
        action: Literal[
            "mark", "comment", "goto", "cursor", "bookmarks", "comments", "history"
        ],
        session: str | None = None,
        address: int | str | None = None,
        name: str | None = None,
        text: str | None = None,
        db: str | None = None,
    ) -> dict:
        return tools.codevanta_nav(action, session, address, name, text, db)

    @server.tool(
        description=(
            "Report which external GUI navigation providers (Hopper, Cutter, "
            "Ghidra) could attach on this machine: one capability report each "
            "with name/available/reason, plus the nav.providers evidence "
            "record. The probes never launch anything and never raise; "
            "CODEVANTA's own navigation works regardless. Offline."
        )
    )
    def codevanta_nav_providers() -> dict:
        return tools.codevanta_nav_providers()

    @server.tool(
        description=(
            "Report which external analysis tool bridges could run on this "
            "machine: binwalk, unblob, tshark, wabt (wasm-validate + "
            "wasm-objdump), objdump, sigrok-cli, adb, gdb and z3. One "
            "capability record per bridge with available/version/reason; "
            "every probe is bounded (5s version call, import probe for z3) "
            "and never raises for a missing tool. Offline."
        )
    )
    def codevanta_bridges() -> dict:
        return tools.codevanta_bridges()

    @server.tool(
        description=(
            "Extract a firmware image with binwalk (default) or unblob into "
            "out_dir: bounded 120s run, bounded transcript parse (max 64 "
            "reported entries) plus a shallow scan of the extraction tree "
            "(max 64 paths). Requires the tool on PATH - its absence "
            "surfaces as a typed error with the install hint and the "
            "offline `codevanta binmeta` magic-scan fallback."
        )
    )
    def codevanta_firmware_extract(
        path: str,
        out_dir: str,
        tool: Literal["binwalk", "unblob"] = "binwalk",
    ) -> dict:
        return tools.codevanta_firmware_extract(path, out_dir, tool)

    @server.tool(
        description=(
            "Extract protocol fields from a pcap/pcapng capture with tshark "
            "-T fields: comma-separated field names (max 16), optional -Y "
            "display filter, packet cap -c (1..100, default 50) and a "
            "bounded 100-row parse. Requires tshark on PATH - its absence "
            "surfaces as a typed error with the install hint and the "
            "offline `codevanta binmeta` structural pcap fallback."
        )
    )
    def codevanta_pcap_fields(
        path: str,
        fields: str,
        display_filter: str | None = None,
        packet_limit: int = tools.DEFAULT_TSHARK_PACKET_LIMIT,
    ) -> dict:
        return tools.codevanta_pcap_fields(
            path, fields, display_filter=display_filter, packet_limit=packet_limit
        )

    # lane-bridge-b: depth bridges (apktool / Wakaru / pure-Python PE certs).
    @server.tool(
        description=(
            "Decode an APK with apktool (--no-src, bounded 120s): decoded "
            "AndroidManifest.xml, apktool.yml, bounded res/ file count, smali "
            "absence (expected with --no-src) and a bounded shallow walk of "
            "the output tree. Requires apktool on PATH; its absence surfaces "
            "as a typed error with the install hint and a pointer to the "
            "offline 'codevanta metadata' fallback, never a traceback."
        )
    )
    def codevanta_apk_decode(apk_path: str, out_dir: str) -> dict:
        return tools.codevanta_apk_decode(apk_path, out_dir)

    @server.tool(
        description=(
            "Recover readable JavaScript from a bundled/minified file with "
            "Wakaru: mode='minify' (unminify, readable identifiers) or "
            "mode='unpack' (split webpack-style modules). Requires Node.js - "
            "install with `npm i -g @wakaru/cli`; unavailability surfaces as "
            "a typed error naming that hint. Bounded recovered-entry list; "
            "the console transcript is preserved under out_dir."
        )
    )
    def codevanta_js_recover(
        bundle_path: str, out_dir: str, mode: Literal["minify", "unpack"] = "minify"
    ) -> dict:
        return tools.codevanta_js_recover(bundle_path, out_dir, mode)

    @server.tool(
        description=(
            "Statically inventory a JavaScript/Electron application offline "
            "(pure Python, nothing executed). Give it an extracted app "
            "directory or an .asar archive and it returns bounded modules, "
            "imports (require/import/export-from/dynamic, classified "
            "relative/bare/builtin and resolved against the scanned set when "
            "possible), package.json facts (name, main, electron version), a "
            "heuristic per-file Electron process role "
            "(main/renderer/preload/mixed), and ipcMain/ipcRenderer call "
            "sites with literal channels paired across sides by exact name. "
            "Literal text matches are certain; roles and channel pairs are "
            "medium confidence and carry their own evidence. Bounds: file "
            "rows, depth, per-file bytes and a whole-scan byte budget, every "
            "cap reported through truncated flags and warnings."
        )
    )
    def codevanta_javascript(
        path: str, max_files: int = 512
    ) -> dict:
        try:
            return tools.codevanta_javascript(path, max_files=max_files)
        except AnalysisError as exc:
            # A wrong path/kind or an out-of-range max_files is
            # caller-correctable; surface the engine's typed message instead
            # of the framework's generic error text.
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Audit a JavaScript/Electron application for security "
            "anti-patterns, offline and pure Python (nothing executed, no "
            "Node.js). Runs the static app inventory first, then bounded "
            "regex rules over JS and HTML sources: nodeIntegration:true, "
            "contextIsolation:false, sandbox:false, webSecurity:false, "
            "missing or weak CSP, interpolated exec/spawn commands, "
            "caller-chosen IPC channels behind contextBridge, "
            "shell.openExternal with non-literal arguments, remote loadURL "
            "literals. Each finding carries rule id, severity, confidence, "
            "file, line, snippet, recommendation and evidence; literal "
            "misconfigurations are certain, shape-based findings are medium."
        )
    )
    def codevanta_electron_audit(
        path: str, max_files: int = 512
    ) -> dict:
        try:
            return tools.codevanta_electron_audit(path, max_files=max_files)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Aggregate CODEVANTA inventories into a deterministic CycloneDX "
            "1.6 SBOM document. Each path is a PE/ELF/Mach-O binary or a "
            "JavaScript application directory/.asar archive; components come "
            "from JS external packages (versions only when package.json pins "
            "them exactly) and binary import libraries. The serial number is "
            "derived from the input hashes, there is no timestamp, versions "
            "are never guessed, and every component carries its evidence as "
            "a property. Bounded by max_components with honest truncation. "
            "Nothing is executed."
        )
    )
    def codevanta_sbom(
        paths: list[str], max_components: int = 2000
    ) -> dict:
        try:
            return tools.codevanta_sbom(paths, max_components=max_components)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Detect file-scope capabilities in a binary via bounded rule "
            "matching over imports, strings, exports and section names: "
            "HTTP/TCP communication, process creation, registry writes, "
            "service installs, keylogging, screenshots, reverse-shell and "
            "injection candidates, packing hints and more (14 built-in "
            "rules; supply extra_rules as a JSON file to extend). Every "
            "match lists exactly which features fired and where -- the "
            "feature evidence is certain, the capability conclusion is "
            "medium confidence. File scope only: no function-level "
            "attribution, unlike full capa. Nothing is executed."
        )
    )
    def codevanta_capabilities(
        path: str, extra_rules: str | None = None, string_limit: int = 5000
    ) -> dict:
        try:
            return tools.codevanta_capabilities(
                path, extra_rules=extra_rules, string_limit=string_limit
            )
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Profile a binary against eight fixed capability domains -- "
            "network (socket/winsock/curl/reqwest markers), crypto "
            "(bcrypt/crypt32/aes/rsa/sha), file_system (fopen/CreateFile/"
            "read/write), process (CreateProcess/exec/ptrace), registry "
            "(RegOpenKey/RegQueryValue), service (OpenSCManager/"
            "StartService), gui (CreateWindow/user32/cairo) and "
            "dynamic_loading (dlopen/GetProcAddress/lazy_static). Each "
            "domain reports detected plus at most 8 evidence strings and a "
            "high/medium confidence; the report carries a deterministic "
            "0-100 overall_risk_score over dangerous domain combinations "
            "and a bounded evidence list (<=16). Case-insensitive byte "
            "scan, capped at 8 MiB with an honest truncation warning. The "
            "markers are certain; the capability conclusion is medium "
            "confidence. Nothing is executed."
        )
    )
    def codevanta_capability_profile(path: str) -> dict:
        try:
            return tools.codevanta_capability_profile(path)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Recover stack-constructed strings by bounded offline emulation "
            "(FLOSS-style). Each target function's bytes run on a private "
            "unicorn CPU -- nothing executes on the host; emulated stack "
            "writes are tracked and printable ASCII / UTF-16LE runs in the "
            "written span become stackstrings with their function, stack "
            "offset, encoding and evidence. Results are medium confidence: "
            "the string provably appeared in emulated memory, but emulation "
            "is an approximation. Needs the optional emulation extra (pip "
            "install codevanta[emulation]); its absence is a typed error."
        )
    )
    def codevanta_stackstrings(
        path: str,
        addresses: list[int] | None = None,
        max_functions: int = 16,
        max_instructions: int = 2000,
        max_strings: int = 32,
    ) -> dict:
        try:
            return tools.codevanta_stackstrings(
                path,
                addresses=addresses,
                max_functions=max_functions,
                max_instructions=max_instructions,
                max_strings=max_strings,
            )
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Normalize a HAR (HTTP Archive) recording into a bounded, "
            "deterministic replay fixture: request/response records with "
            "bodies as size + sha256 + a 128-byte preview (never inlined), "
            "and an endpoint manifest that collapses paths into templates "
            "(/api/items/42 -> /api/items/{n}) with counts and status "
            "distributions -- the surface an agent could train or test "
            "against. The offline half of a replay environment: nothing is "
            "served, nothing is executed."
        )
    )
    def codevanta_replay_fixture(
        har_path: str,
        max_entries: int = 500,
        max_body_bytes: int = 262_144,
    ) -> dict:
        try:
            return tools.codevanta_replay_fixture(
                har_path, max_entries=max_entries, max_body_bytes=max_body_bytes
            )
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Recover function names from a Go binary's embedded pclntab, "
            "offline. strip leaves the pclntab behind because the runtime "
            "needs it for stack traces; this walks the go1.2 / 1.16 / 1.18+ / "
            "1.20+ layouts (located by section name, then a bounded magic "
            "scan) and reports each function's name, address and - from 1.16 "
            "on - file and line when the tables carry them. The Go version is "
            "an evidence-backed guess; UPX-compressed and garble-obfuscated "
            "tables are out of scope. Nothing is executed."
        )
    )
    def codevanta_gosymbols(
        path: str, max_functions: int = 65_536
    ) -> dict:
        try:
            return tools.codevanta_gosymbols(path, max_functions=max_functions)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Match a bounded subset of real YARA rules against a file. "
            "Provide the rules as text or a .yar path. Supported: text "
            "strings (nocase / wide), hex strings with ?? nibble wildcards "
            "and bounded [n-m] jumps, conditions from and/or/not, $a, "
            "#a OP N, filesize OP N and all of / any of / N of; anything "
            "else is a typed error naming the rule -- never silently "
            "ignored. String hits are certain evidence (offsets recorded); "
            "a satisfied rule is a medium-confidence conclusion. Nothing is "
            "executed."
        )
    )
    def codevanta_yara(
        path: str,
        rules_text: str | None = None,
        rules_path: str | None = None,
        max_strings: int = 200_000,
        max_matches_per_string: int = 64,
    ) -> dict:
        try:
            return tools.codevanta_yara(
                path,
                rules_text=rules_text,
                rules_path=rules_path,
                max_strings=max_strings,
                max_matches_per_string=max_matches_per_string,
            )
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Compute triage hashes for one file, optionally scoring a second "
            "against it: sha256, the imphash (MD5 over the lowercase "
            "dll.function import list, the Mandiant/VirusTotal convention; "
            "refused with a warning for ELF/Mach-O where the loader has no "
            "library pairing), and an ssdeep-shaped fuzzy signature "
            "(piecewise hashing over the documented block ladder). With "
            "'compare' set, adds a 0-100 fuzzy similarity score. Nothing is "
            "executed."
        )
    )
    def codevanta_triage(path: str, compare: str | None = None) -> dict:
        try:
            return tools.codevanta_triage(path, compare=compare)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Start a rebuild project: Study → Build → Check → Ready. Studies "
            "the target with CODEVANTA's analysis engine (surface-only in "
            "clean-room mode, all tools in deep mode), writes craft.json and "
            "the capture, and returns the project id. An external coding agent "
            "then builds the recreation; use codevanta_rebuild_check to compare "
            "it against the original. Nothing is executed, nothing touches the "
            "network."
        )
    )
    def codevanta_rebuild(
        target: str,
        request: str,
        mode: str = "clean-room",
        root: str | None = None,
    ) -> dict:
        try:
            return tools.codevanta_rebuild(target, request, mode=mode, root=root)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Mark a rebuild project as ``building`` and scaffold the ``app/`` "
            "directory. Returns the project id, status, suggested stack, "
            "directory and the list of files written for the coding agent."
        )
    )
    def codevanta_rebuild_build(
        project_id: str,
        root: str | None = None,
    ) -> dict:
        try:
            return tools.codevanta_rebuild_build(project_id, root=root)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Run the automated Build → Check → Improve loop. Generates code "
            "from study entries, writes it to ``app/``, runs "
            "``codevanta_rebuild_check``, and repeats until identical or "
            "``max_attempts`` is reached. Marks the project ``ready`` on "
            "success."
        )
    )
    def codevanta_rebuild_build_auto(
        project_id: str,
        root: str | None = None,
        max_attempts: int = 5,
    ) -> dict:
        try:
            return tools.codevanta_rebuild_build_auto(
                project_id, root=root, max_attempts=max_attempts
            )
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Request an improvement pass for a rebuild project. Regenerates "
            "the code in ``app/`` using the latest study entries, then runs "
            "one check. Returns whether the build is now identical. Intended "
            "for external coding agents to iterate toward Ready."
        )
    )
    def codevanta_rebuild_improve(
        project_id: str,
        hint: str | None = None,
        root: str | None = None,
    ) -> dict:
        try:
            return tools.codevanta_rebuild_improve(project_id, hint=hint, root=root)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "List rebuild projects, most recently updated first. Returns the "
            "project id, name, status, mode, target and updated timestamp for "
            "each project under the rebuild root."
        )
    )
    def codevanta_rebuild_list(root: str | None = None) -> dict:
        try:
            return tools.codevanta_rebuild_list(root=root)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Show one rebuild project's full record: request, status, study "
            "entries, checks and inbox. Returns the complete craft.json payload."
        )
    )
    def codevanta_rebuild_show(project_id: str, root: str | None = None) -> dict:
        try:
            return tools.codevanta_rebuild_show(project_id, root=root)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Compare an agent-built recreation against the project's original "
            "target and record the check. For binary targets uses CODEVANTA's "
            "structural comparison; otherwise compares SHA-256 and size. Returns "
            "whether the build is identical and saves the result under checks/."
        )
    )
    def codevanta_rebuild_check(
        project_id: str,
        build_path: str,
        root: str | None = None,
    ) -> dict:
        try:
            return tools.codevanta_rebuild_check(project_id, build_path, root=root)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Behavior check: run the built recreation and capture its exit code "
            "and stdout/stderr. With run_original=true (explicit consent; "
            "executes the original binary on this machine) also run the original "
            "target and report exit-code match and stdout similarity. Recorded "
            "under checks/ with kind 'behavior'."
        )
    )
    def codevanta_rebuild_check_behavior(
        project_id: str,
        build_path: str,
        run_original: bool = False,
        timeout: int = 10,
        root: str | None = None,
    ) -> dict:
        try:
            return tools.codevanta_rebuild_check_behavior(
                project_id, build_path, run_original=run_original, timeout=timeout, root=root
            )
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Mark a rebuild project as ``ready``. Requires the project to be "
            "in ``checked`` status and the most recent check to report "
            "``identical: true``. Returns the updated project record."
        )
    )
    def codevanta_rebuild_ready(
        project_id: str,
        root: str | None = None,
    ) -> dict:
        try:
            return tools.codevanta_rebuild_ready(project_id, root=root)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Read PDB information offline. A .pdb input gets the bounded "
            "MSF v7 walk: streams, the info stream's GUID/age/version, "
            "named streams and the DBI module list. Any other input is "
            "treated as a PE and returns its debug directory's CodeView "
            "record -- the PDB path, GUID and age that identify the symbol "
            "file. No symbol records, no type info (TPI/IPI), no download, "
            "no network, ever. Nothing is executed."
        )
    )
    def codevanta_pdb(
        path: str, max_streams: int = 256, max_modules: int = 4096
    ) -> dict:
        try:
            return tools.codevanta_pdb(path, max_streams=max_streams, max_modules=max_modules)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Parse a PE file's certificate table offline with pure Python: "
            "WIN_CERTIFICATE entries and the PKCS#7 SignedData structure via "
            "a minimal hand-rolled DER walk - signer count, serial numbers "
            "(hex), digest/signature algorithm OID names (common SHA-1/256/"
            "384/512 RSA/ECDSA map) and signingTime when present in the "
            "authenticated attributes. Structural analysis only: no "
            "trust-chain verification; issuer names are honestly reported "
            "as not decoded. Always available."
        )
    )
    def codevanta_certs(path: str) -> dict:
        return tools.codevanta_certs(path)

    # lane-live2: live instrumentation bridges (frida / lldb / rizin).
    @server.tool(
        description=(
            "Live Frida bridge. action='devices' lists Frida devices "
            "(frida-ls-devices); action='ps' lists processes, optionally on a "
            "named device (frida-ps -D); action='script' attaches to pid and "
            "runs script_path for a bounded duration (1..60s, default 10), "
            "returning the captured send()/console messages (max 200). "
            "Skip-gated on the frida CLI tools and/or the frida Python "
            "module - absence surfaces as a typed error with the "
            "`pip install frida-tools` install hint."
        )
    )
    def codevanta_frida(
        action: Literal["devices", "ps", "script"],
        device_id: str | None = None,
        pid: int | None = None,
        script_path: str | None = None,
        duration: float = tools.DEFAULT_FRIDA_DURATION,
    ) -> dict:
        return tools.codevanta_frida(
            action,
            device_id=device_id,
            pid=pid,
            script_path=script_path,
            duration=duration,
        )

    @server.tool(
        description=(
            "Run a target under one bounded batch LLDB session (lldb -b): "
            "target create, optional breakpoint (function name or 0x "
            "address), run, register read, backtrace, quit. Returns the "
            "typed stop reason, register values (max 64), frames (max 32) "
            "and a bounded raw transcript tail. Requires lldb on PATH - its "
            "absence surfaces as a typed error with the install hint."
        )
    )
    def codevanta_lldb_run(
        target: str,
        break_at: str | None = None,
        timeout_s: float = tools.DEFAULT_LLDB_TIMEOUT,
    ) -> dict:
        return tools.codevanta_lldb_run(target, break_at=break_at, timeout_s=timeout_s)

    @server.tool(
        description=(
            "List functions of a binary with batch rizin analysis (rizin "
            "-q -c 'aaa; afl'): bounded 256-entry list of address, size and "
            "name, junk rows reported as warnings. Requires rizin on PATH - "
            "its absence surfaces as a typed error with the install hint "
            "and a pointer to the offline `codevanta functions` fallback."
        )
    )
    def codevanta_rizin_functions(path: str) -> dict:
        return tools.codevanta_rizin_functions(path)

    @server.tool(
        description=(
            "Report decompiler provider availability for this machine: native "
            "(always available), ghidra/angr (when importable/configured), jeb "
            "(commercial, dex/apk targets only) and hopper (macOS GUI probe). "
            "Read-only."
        )
    )
    def codevanta_providers() -> dict:
        return tools.codevanta_providers()

    @server.tool(
        description=(
            "Parse an IL2CPP global-metadata.dat header: version family, header "
            "tables with offset/size, and approximate row counts. Structure only; "
            "no readable-name decoding."
        )
    )
    def codevanta_il2cpp(path: str) -> dict:
        return tools.codevanta_il2cpp(path)

    @server.tool(
        description=(
            "Inspect a GPU code container: CUDA fatbin entries with sm_XX arch "
            "detection, CUBIN ELF section walk with PTX marker detection, or "
            "Clang offload bundle (COB) host/device lines."
        )
    )
    def codevanta_gpu(path: str) -> dict:
        return tools.codevanta_gpu(path)

    # lane-search: binary search and navigation tools.
    @server.tool(
        description=(
            "Search a file's raw bytes for a hex byte pattern with '??' "
            "wildcards (e.g. '8B 44 ?? 24 ?? ??'; whitespace between bytes is "
            "ignored). mask optionally overrides per pattern byte: 'x' keeps "
            "it, '?' ignores it. start/end bound the scanned window; each hit "
            "carries its offset and a hex context of up to 16 bytes on both "
            "sides. 'total' counts every match even beyond 'limit' (max 4096), "
            "and 'truncated' reports the cut. CERTAIN confidence: direct byte "
            "equality over file bytes; files above 64 MiB are rejected."
        )
    )
    def codevanta_search_bytes(
        path: str,
        pattern: str,
        mask: str | None = None,
        start: int = 0,
        end: int | None = None,
        limit: int = 64,
    ) -> dict:
        return tools.codevanta_search_bytes(
            path, pattern, mask=mask, start=start, end=end, limit=limit
        )

    @server.tool(
        description=(
            "Search the printable strings extracted from a file (ASCII and "
            "UTF-16LE runs of >= 4 chars) for a query. mode='literal' is a "
            "substring test, mode='regex' applies the query with re.search "
            "per string; case_sensitive controls both. Each match carries its "
            "file offset, text (capped at 256 chars) and honest length. "
            "'total' counts every match even beyond 'limit' (max 20000). "
            "CERTAIN confidence over the extracted strings."
        )
    )
    def codevanta_search_strings(
        path: str,
        query: str,
        mode: Literal["literal", "regex"] = "literal",
        case_sensitive: bool = True,
        limit: int = 100,
    ) -> dict:
        return tools.codevanta_search_strings(
            path, query, mode=mode, case_sensitive=case_sensitive, limit=limit
        )

    @server.tool(
        description=(
            "Search function names (symbol-table and export names plus the "
            "entry point) for a pattern: mode='literal' is a case-sensitive "
            "substring test, mode='regex' a re.search per name. Each match "
            "carries address, name and best-known size. The match over the "
            "inventory is exact, but every name is only as trustworthy as its "
            "own discovery evidence - check each binary's function sources."
        )
    )
    def codevanta_search_procs(
        path: str,
        pattern: str,
        mode: Literal["literal", "regex"] = "literal",
        limit: int = 100,
    ) -> dict:
        return tools.codevanta_search_procs(path, pattern, mode=mode, limit=limit)

    @server.tool(
        description=(
            "BFS the shortest call path between two addresses using the "
            "inter-function call graph (same direct-call / resolved-import "
            "edges as codevanta_callgraph, bounded to 1000 candidates / 5000 "
            "edges). Returns 'path' (address + name per hop), 'length' in "
            "call edges and 'found'; missing endpoints or a disconnected "
            "graph give found=false, never an error. MEDIUM confidence: "
            "caller attribution in the graph is heuristic."
        )
    )
    def codevanta_call_path(
        path: str,
        start_addr: int,
        goal_addr: int,
        max_depth: int = 8,
    ) -> dict:
        return tools.codevanta_call_path(path, start_addr, goal_addr, max_depth=max_depth)

    @server.tool(
        description=(
            "Navigate to one address: the containing function (a known size "
            "must span it; a size-less function extends to the next one), "
            "the nearest previous and next functions, the covering section's "
            "name, and a hex byte preview (default 32, max 256 bytes) mapped "
            "through the section file offset. MEDIUM confidence: the preview "
            "is direct file bytes, the function neighbourhood comes from the "
            "heuristic discovery lane."
        )
    )
    def codevanta_navigate(path: str, address: int, preview: int = 32) -> dict:
        return tools.codevanta_navigate(path, address, preview=preview)

    @server.tool(
        description=(
            "Collect the bounded call-graph neighbourhood of one address: "
            "direction='callers' walks incoming edges towards the callers, "
            "'callees' walks outgoing edges (depth 1..16, default 3). Nodes "
            "carry their BFS depth from the root (depth 0) and edges are the "
            "graph edges between collected nodes; 'truncated' reports a "
            "10000-node cut. An address without edges in the direction gives "
            "an empty subset. MEDIUM confidence, heuristic graph edges."
        )
    )
    def codevanta_graph_subset(
        path: str,
        address: int,
        direction: Literal["callers", "callees"] = "callers",
        max_depth: int = 3,
    ) -> dict:
        return tools.codevanta_graph_subset(
            path, address, direction=direction, max_depth=max_depth
        )

    # lane-depth2: TWO MCP wrappers for the deep format inspectors. Imports
    # alone register nothing; these closures bind the tools to the server.
    @server.tool(
        description=(
            "Deep-parse a PE's resource section and load config in one call, "
            "pure Python and offline (nothing executed). Resources: bounded "
            "type tree walk (type/name/language levels), entry list, "
            "icon/cursor counts, shallow VS_VERSIONINFO key/value pairs with "
            "the VS_FIXEDFILEINFO version, RT_MANIFEST preview and a hex raw "
            "preview per type. Load config: TLS callback list (bounded 16), "
            "Guard CF function-table count and flag names, DEP policy "
            "(NX_COMPAT/ASLR/GuardCF from DllCharacteristics) and SE handler "
            "count. Absent directories are reported as present:false, not "
            "errors; malformed structures raise typed errors."
        )
    )
    def codevanta_pe_deep(path: str) -> dict:
        try:
            return tools.codevanta_pe_deep(path)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Deep-parse an ELF's dynamic section or a Mach-O's dylib load "
            "commands, auto-detected by magic, pure Python and offline. ELF: "
            "DT_NEEDED libraries (bounded 32), DT_RPATH/RUNPATH/SONAME, "
            "DT_INIT/FINI addresses and the init/fini pointer arrays "
            "(bounded 8). Mach-O: LC_LOAD_DYLIB-family entries (bounded 32) "
            "with install name, timestamp, current_version and "
            "compatibility_version, plus LC_ID_DYLIB. Malformed structures "
            "raise typed errors; nothing is executed."
        )
    )
    def codevanta_elf_macho(path: str) -> dict:
        try:
            return tools.codevanta_elf_macho(path)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Auto-detect container formats in one file, offline and pure "
            "Python: WebAssembly module sections, GGUF tensor metadata, "
            "safetensors headers, pcap/pcapng capture summaries, EVM bytecode "
            "opcodes and a firmware magic sweep over the raw bytes. Formats "
            "that do not match stay out of the summary; a file matching "
            "nothing is a valid empty detection, never an error. Read-only; "
            "nothing is executed."
        )
    )
    def codevanta_containers(path: str) -> dict:
        try:
            return tools.codevanta_containers(path)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Compare two PNG screenshots pixel by pixel: changed-pixel "
            "ratio, per-channel mean absolute delta and a verdict "
            "(identical / minor / major) using documented thresholds. "
            "Different dimensions short-circuit to major with a warning "
            "because no aligned comparison exists. Pure-Python PNG decode; "
            "nothing is executed."
        )
    )
    def codevanta_png_diff(left: str, right: str) -> dict:
        try:
            return tools.codevanta_png_diff(left, right)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=EXPOSE_EMULATE_DESCRIPTION)
    def codevanta_emulate(
        path: str,
        address: int,
        initial_registers: dict[str, int] | None = None,
        max_instructions: int = tools.DEFAULT_EMULATE_INSTRUCTIONS,
        stack_size: int = tools.DEFAULT_EMULATE_STACK_SIZE,
    ) -> dict:
        try:
            return tools.codevanta_emulate(
                path,
                address=address,
                initial_registers=initial_registers,
                max_instructions=max_instructions,
                stack_size=stack_size,
            )
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=EXPOSE_WASM_DESCRIPTION)
    def codevanta_wasm(
        path: str,
        mode: Literal["validate", "objdump"] = "validate",
        timeout: float = tools.DEFAULT_WASM_TIMEOUT,
        out_dir: str | None = None,
    ) -> dict:
        try:
            return tools.codevanta_wasm(
                path, mode=mode, timeout=timeout, out_dir=out_dir
            )
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=EXPOSE_TYPES_DESCRIPTION)
    def codevanta_types(
        path: str,
        address: int,
        abi: str = "sysv",
        max_instructions: int = tools.DEFAULT_TYPES_INSTRUCTIONS,
    ) -> dict:
        try:
            return tools.codevanta_types(
                path,
                address=address,
                abi=abi,
                max_instructions=max_instructions,
            )
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        description=(
            "Auto-detect the mangling scheme of a bounded batch of symbols "
            "and decode them offline with a pure-Python bounded parser: "
            "Itanium C++ (_Z..., nested names, args, templates, "
            "substitutions), MSVC C++ (?..., free/member functions, common "
            "types), Rust legacy (_ZN...17h<hash>E), Rust v0 (_R..., RFC "
            "2603 crate/nested paths) and Swift (_$s... / __T..., "
            "best-effort identifiers + entity kind). Undecodable or exotic "
            "input is never an error: it returns scheme='unknown' or "
            "complete=false with a note naming exactly what was not "
            "decoded; results carry evidence. Pure string parsing; nothing "
            "is executed."
        )
    )
    def codevanta_demangle(symbols: list[str]) -> dict:
        try:
            return tools.codevanta_demangle(symbols)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=tools.TOOL_DESCRIPTION_START)
    def codevanta_debug_start(
        path: str,
        addresses: list[int],
        max_hits: int = tools.DEFAULT_DEBUG_MAX_HITS,
        timeout: float = tools.DEFAULT_DEBUG_TIMEOUT,
    ) -> dict:
        try:
            return tools.codevanta_debug_start(
                path, addresses, max_hits=max_hits, timeout=timeout
            )
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=tools.TOOL_DESCRIPTION_STATUS)
    def codevanta_debug_status(session_id: str) -> dict:
        try:
            return tools.codevanta_debug_status(session_id)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=tools.TOOL_DESCRIPTION_CLOSE)
    def codevanta_debug_close(session_id: str) -> dict:
        try:
            return tools.codevanta_debug_close(session_id)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=tools.TOOL_DESCRIPTION_SESSIONS)
    def codevanta_debug_sessions() -> dict:
        try:
            return tools.codevanta_debug_sessions()
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=WEBFW_SOURCEMAP_DESCRIPTION)
    def codevanta_sourcemap(
        path: str, line: int | None = None, column: int | None = None
    ) -> dict:
        try:
            return tools.codevanta_sourcemap(path, line=line, column=column)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=WEBFW_UNPACK_DESCRIPTION)
    def codevanta_unpack(path: str, hashes: bool = True) -> dict:
        try:
            return tools.codevanta_unpack(path, hashes=hashes)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=FRIDA_START_DESCRIPTION)
    def codevanta_frida_start(
        mode: str = "attach",
        target: str = "",
        pid: int | None = None,
        script: str | None = None,
        script_path: str | None = None,
        device_id: str | None = None,
        duration: float = FRIDA_DEFAULT_DURATION,
    ) -> dict:
        try:
            return tools.codevanta_frida_start(
                mode,
                target,
                pid=pid,
                script=script,
                script_path=script_path,
                device_id=device_id,
                duration=duration,
            )
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=FRIDA_LOAD_DESCRIPTION)
    def codevanta_frida_load(
        session_id: str,
        source: str | None = None,
        path: str | None = None,
        duration: float = FRIDA_DEFAULT_DURATION,
    ) -> dict:
        try:
            return tools.codevanta_frida_load(
                session_id,
                source=source,
                path=path,
                duration=duration,
            )
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=FRIDA_STATUS_DESCRIPTION)
    def codevanta_frida_status(session_id: str) -> dict:
        try:
            return tools.codevanta_frida_status(session_id)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=FRIDA_CLOSE_DESCRIPTION)
    def codevanta_frida_close(session_id: str) -> dict:
        try:
            return tools.codevanta_frida_close(session_id)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=FRIDA_SESSIONS_DESCRIPTION)
    def codevanta_frida_sessions() -> dict:
        try:
            return tools.codevanta_frida_sessions()
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=tools.TOOL_DESCRIPTION_PROC_RUN)
    def codevanta_proc_run(
        command: str,
        arguments: list[str] | None = None,
        working_directory: str | None = None,
        timeout: float = tools.DEFAULT_PROC_TIMEOUT,
        env: dict[str, str] | None = None,
        max_output_bytes: int = tools.PROC_MAX_OUTPUT_BYTES,
    ) -> dict:
        try:
            return tools.codevanta_proc_run(
                command,
                arguments,
                working_directory,
                timeout=timeout,
                env=env,
                max_output_bytes=max_output_bytes,
            )
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=tools.TOOL_DESCRIPTION_PROC_STATUS)
    def codevanta_proc_status(session_id: str) -> dict:
        try:
            return tools.codevanta_proc_status(session_id)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=tools.TOOL_DESCRIPTION_PROC_COMPARE)
    def codevanta_proc_compare(left_session_id: str, right_session_id: str) -> dict:
        try:
            return tools.codevanta_proc_compare(left_session_id, right_session_id)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=tools.TOOL_DESCRIPTION_PROC_SESSIONS)
    def codevanta_proc_sessions() -> dict:
        try:
            return tools.codevanta_proc_sessions()
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=UIRES_DIALOG_DESCRIPTION)
    def codevanta_dialog_decode(path: str) -> dict:
        try:
            return tools.codevanta_dialog_decode(path)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=UIRES_PREVIEW_DESCRIPTION)
    def codevanta_ui_preview(path: str, output_directory: str) -> dict:
        try:
            return tools.codevanta_ui_preview(path, output_directory)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=tools.TOOL_DESCRIPTION_CODEGEN)
    def codevanta_rebuild_generate(
        project_dir: str, output_directory: str, language: str = "python"
    ) -> dict:
        try:
            return tools.codevanta_rebuild_generate(
                project_dir, output_directory, language=language
            )
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=WINGUI_WINDOWS_DESCRIPTION)
    def codevanta_win_windows(pid: int | None = None) -> dict:
        try:
            return tools.codevanta_win_windows(pid)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=WINGUI_TREE_DESCRIPTION)
    def codevanta_win_tree(hwnd: int) -> dict:
        try:
            return tools.codevanta_win_tree(hwnd)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=WINGUI_SHOT_DESCRIPTION)
    def codevanta_win_shot(hwnd: int, output_directory: str) -> dict:
        try:
            return tools.codevanta_win_shot(hwnd, output_directory)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description=PE_ASSETS_DESCRIPTION)
    def codevanta_pe_assets(path: str, output_directory: str) -> dict:
        try:
            return tools.codevanta_pe_assets(path, output_directory)
        except AnalysisError as exc:
            raise ToolError(str(exc)) from exc

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


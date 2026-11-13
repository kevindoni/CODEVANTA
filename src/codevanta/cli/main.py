"""CODEVANTA command line interface."""

from __future__ import annotations

import json
import math
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any, Literal, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from codevanta.analysis import debug_session, dynamic
from codevanta.analysis import emulate as emulator
from codevanta.analysis.binary_diff import (
    DEFAULT_MAX_FUNCTIONS as DIFF_MAX_FUNCTIONS,
)
from codevanta.analysis.binary_diff import (
    DEFAULT_SEMANTIC_THRESHOLD as DIFF_SEMANTIC_THRESHOLD,
)
from codevanta.analysis.binary_diff import (
    MAX_SEMANTIC_THRESHOLD as DIFF_MAX_THRESHOLD,
)
from codevanta.analysis.binary_diff import (
    MIN_SEMANTIC_THRESHOLD as DIFF_MIN_THRESHOLD,
)
from codevanta.analysis.binary_diff import BinaryDiff, FunctionDelta, diff_binaries
from codevanta.analysis.callgraph import (
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_FUNCTIONS,
    CallGraph,
    build_call_graph,
)
from codevanta.analysis.cfg import FunctionCFG, build_cfg, build_recursive_cfg
from codevanta.analysis.compare import (
    COMPARE_WHATS,
    compare_bundles,
    compare_inventories,
    compare_strings,
    is_bundle_document,
    load_document,
    load_report_payload,
)
from codevanta.analysis.compare import (
    DEFAULT_MAX_FUNCTIONS as COMPARE_MAX_FUNCTIONS,
)
from codevanta.analysis.compare import (
    DEFAULT_MAX_STRINGS as COMPARE_MAX_STRINGS,
)
from codevanta.analysis.dataflow import (
    DEFAULT_MAX_BLOCKS as DATAFLOW_MAX_BLOCKS,
)
from codevanta.analysis.dataflow import (
    DEFAULT_MAX_INSTRUCTIONS as DATAFLOW_MAX_INSTRUCTIONS,
)
from codevanta.analysis.dataflow import DataFlowSummary, analyze_dataflow
from codevanta.analysis.debuginfo import extract_debug_info
from codevanta.analysis.decompile import (
    DEFAULT_MAX_BLOCKS as DECOMPILE_MAX_BLOCKS,
)
from codevanta.analysis.decompile import (
    DEFAULT_MAX_INSTRUCTIONS as DECOMPILE_MAX_INSTRUCTIONS,
)
from codevanta.analysis.decompilers import BackendResult, decompile_function
from codevanta.analysis.evidence_bundle import build_bundle, dumps_bundle, write_bundle
from codevanta.analysis.graph_export import (
    DEFAULT_MAX_EDGES as EXPORT_MAX_EDGES,
)
from codevanta.analysis.graph_export import (
    DEFAULT_MAX_NODES as EXPORT_MAX_NODES,
)
from codevanta.analysis.graph_export import (
    GraphExportError,
    to_dot,
    to_graphml,
)
from codevanta.analysis.html_view import to_html
from codevanta.analysis.jump_tables import (
    DEFAULT_MAX_ENTRIES as JUMP_TABLE_MAX_ENTRIES,
)
from codevanta.analysis.jump_tables import (
    MODE_ABSOLUTE,
    MODE_RELATIVE,
    MODES,
    JumpTableResult,
    resolve_jump_table,
)
from codevanta.analysis.solver import (
    DEFAULT_TIMEOUT_MS as SOLVER_DEFAULT_TIMEOUT_MS,
)
from codevanta.analysis.solver import SolverOverlay, solve_exploration
from codevanta.analysis.symbolic import (
    DEFAULT_MAX_PATHS as SYMBOLIC_MAX_PATHS,
)
from codevanta.analysis.symbolic import (
    DEFAULT_MAX_STEPS as SYMBOLIC_MAX_STEPS,
)
from codevanta.analysis.symbolic import (
    EMULATOR_AVAILABLE as SYMBOLIC_EMULATOR_AVAILABLE,
)
from codevanta.analysis.symbolic import PathExploration, explore_paths
from codevanta.analysis.trace import TraceReport, parse_frida_trace, parse_gdb_trace
from codevanta.analysis.type_recovery import (
    DEFAULT_MAX_FIELDS as STRUCT_MAX_FIELDS,
)
from codevanta.analysis.type_recovery import (
    DEFAULT_MAX_INSTRUCTIONS as STRUCT_MAX_INSTRUCTIONS,
)
from codevanta.analysis.type_recovery import (
    MAX_MERGED_WINDOWS as STRUCT_MAX_WINDOWS,
)
from codevanta.analysis.type_recovery import (
    ArrayGroup,
    StructSuggestion,
    parse_memory_operands,
    suggest_struct,
    suggest_structs,
)
from codevanta.analysis.vtables import find_vtables
from codevanta.analysis.xrefs import DEFAULT_MAX_BYTES, find_xrefs
from codevanta.cli.containers import app as containers_app
from codevanta.cli.crash import app as crash_app
from codevanta.cli.meta import meta_app
from codevanta.cli.mobile import app as mobile_app
from codevanta.cli.web import asar, web_app
from codevanta.core.disassembler import DisassemblyError
from codevanta.core.entropy import analyze_entropy
from codevanta.core.functions import discover_functions
from codevanta.core.loader import BinaryInfo, BinaryLoader, BinaryLoadError
from codevanta.core.report import (
    DEFAULT_XREF_LIMIT,
    AnalysisError,
    build_report,
    disassemble_region,
    resolve_target,
)
from codevanta.core.strings import StringExtractor
from codevanta.core.unknowns import (
    DEFAULT_UNKNOWN_SEVERITY,
    UNKNOWN_STATUSES,
    make_open_unknown,
    records_from_payload,
    records_to_payload,
    resolve_unknowns,
)
from codevanta.plugins import AnalysisContext, builtin_plugins, run_plugin
from codevanta.plugins import load as load_plugin
from codevanta.storage.session import SessionError, SessionRecord, SessionStore

app = typer.Typer(
    name="codevanta",
    help="CODEVANTA — Advanced Code Intelligence. Decode. Analyze. Understand.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def _load(path: Path) -> BinaryInfo:
    try:
        return BinaryLoader().load(path)
    except BinaryLoadError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2) from exc


def _session_db(db: Path | None) -> Path:
    """Return ``db``, else ``$CODEVANTA_DB``, else ``~/.codevanta/sessions.db``."""
    if db is not None:
        return db
    configured = os.environ.get("CODEVANTA_DB")
    if configured and configured.strip():
        return Path(configured)
    return Path.home() / ".codevanta" / "sessions.db"


def _fail(message: str, code: int) -> NoReturn:
    """Print an error and exit with ``code``."""
    console.print(f"[bold red]error:[/] {escape(message)}")
    raise typer.Exit(code=code)


def _system_exit_status(exc: SystemExit) -> int:
    """Return the status a :class:`SystemExit` asks for, as CPython would.

    ``SystemExit`` carries ``None`` (meaning success), an ``int`` or any other
    object (printed, then exit 1, which is the documented CPython behaviour).
    """
    code = exc.code
    if code is None:
        return 0
    if isinstance(code, bool) or not isinstance(code, int):
        return 1
    return code


def _print_sections(info: BinaryInfo) -> None:
    table = Table(title="Sections")
    table.add_column("Name")
    table.add_column("VA", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("Offset", justify="right")
    table.add_column("Flags")
    for section in info.sections:
        flags = ("X" if section.is_executable else "") + ("W" if section.is_writable else "")
        table.add_row(
            escape(section.name or "<unnamed>"),
            f"0x{section.virtual_address:x}",
            str(section.size),
            f"0x{section.offset:x}",
            flags or "-",
        )
    console.print(table)
@app.command()
def info(path: Annotated[Path, typer.Argument(help="Path to a PE or ELF binary")]) -> None:
    """Show binary metadata (format, arch, sections, imports, exports)."""
    loaded = _load(path)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan")
    grid.add_column()
    rows = [
        ("File", str(loaded.path)),
        ("Format", loaded.format),
        ("Architecture", loaded.architecture),
        ("Bitness", str(loaded.bitness)),
        ("Endianness", loaded.endianness),
        ("Entry point", f"0x{loaded.entry_point:x}" if loaded.entry_point is not None else "-"),
        ("Image base", f"0x{loaded.image_base:x}"),
        ("SHA-256", loaded.sha256),
        ("Stripped", "yes" if loaded.is_stripped else "no"),
        ("Sections", str(len(loaded.sections))),
        ("Imports", str(len(loaded.imports))),
        ("Exports", str(len(loaded.exports))),
        ("Symbols", str(len(loaded.symbols))),
    ]
    for key, value in rows:
        grid.add_row(key, escape(value))
    console.print(
        Panel(grid, title="CODEVANTA · binary info", subtitle="Decode. Analyze. Understand.")
    )
    _print_sections(loaded)
    for warning in loaded.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")


@app.command()
def entropy(
    path: Path,
    threshold: Annotated[
        float,
        typer.Option(
            help="Entropy (bits/byte) at or above which a section is flagged as possibly packed"
        ),
    ] = 7.2,
    max_sample_bytes: Annotated[
        int, typer.Option(help="Maximum bytes sampled per section")
    ] = 65_536,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of a table")
    ] = False,
) -> None:
    """Show per-section Shannon entropy and packing triage hints."""
    loaded = _load(path)
    try:
        report = analyze_entropy(
            path, loaded, threshold=threshold, max_sample_bytes=max_sample_bytes
        )
    except AnalysisError as exc:
        _fail(str(exc), 4)
    if json_output:
        console.print_json(json.dumps(report.to_dict()))
        return
    table = Table(title="Section entropy (bits/byte)")
    table.add_column("Section")
    table.add_column("Entropy", justify="right")
    table.add_column("Sampled", justify="right")
    table.add_column("Exec")
    table.add_column("Packed hint")
    for section in report.sections:
        entropy_text = f"{section.entropy:.3f}" if section.entropy is not None else "-"
        packed_text = "yes" if section.packed_hint else "-"
        style = "yellow" if section.packed_hint else ""
        table.add_row(
            escape(section.name),
            entropy_text,
            str(section.sampled_bytes),
            "yes" if section.is_executable else "-",
            f"[{style}]{packed_text}[/]" if style else packed_text,
        )
    console.print(table)
    for warning in report.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")
    if report.packed_candidates:
        console.print(
            "[dim]high entropy suggests packing or compression — a heuristic, "
            "not proof; check imports and entry-point stubs before concluding.[/]"
        )


@app.command()
def dwarf(
    path: Annotated[Path, typer.Argument(help="Path to an ELF binary with DWARF debug info")],
    limit: Annotated[
        int, typer.Option(help="Maximum functions and types displayed")
    ] = 500,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """Extract function names, extents and type layouts from DWARF debug info."""
    loaded = _load(path)
    try:
        result = extract_debug_info(path, loaded, limit=limit)
    except AnalysisError as exc:
        _fail(str(exc), 4)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    functions_table = Table(title="DWARF functions (producer metadata)")
    functions_table.add_column("Address", justify="right")
    functions_table.add_column("Size", justify="right")
    functions_table.add_column("Name")
    functions_table.add_column("Linkage name")
    functions_table.add_column("External")
    for function in result.functions:
        functions_table.add_row(
            f"0x{function.address:x}",
            str(function.size),
            escape(function.name),
            escape(function.linkage_name or "-"),
            "yes" if function.is_external else "-",
        )
    console.print(functions_table)
    if result.types:
        types_table = Table(title="Named types")
        types_table.add_column("Kind")
        types_table.add_column("Name")
        types_table.add_column("Byte size", justify="right")
        for debug_type in result.types:
            types_table.add_row(
                debug_type.kind,
                escape(debug_type.name),
                str(debug_type.byte_size),
            )
        console.print(types_table)
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")


@app.command()
def vtable(
    path: Annotated[Path, typer.Argument(help="Path to a PE, ELF, Mach-O or DEX binary")],
    address: Annotated[
        str | None,
        typer.Option("--address", "-a", help="Vtable address (decimal or 0x hex); header slots are skipped automatically"),
    ] = None,
    scan: Annotated[
        bool, typer.Option("--scan", help="Sweep every data section for candidate runs")
    ] = False,
    min_slots: Annotated[
        int, typer.Option("--min-slots", help="Fewest consecutive code pointers that count as a table")
    ] = 3,
    max_slots: Annotated[
        int, typer.Option("--max-slots", help="Cap on slots decoded per candidate")
    ] = 256,
    max_tables: Annotated[
        int, typer.Option("--max-tables", help="Cap on candidates in --scan mode")
    ] = 64,
    no_thunks: Annotated[
        bool, typer.Option("--no-thunks", help="Do not follow one-instruction tail-call chains")
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """Discover vtable candidates and resolve thunk chains (indirect xrefs)."""
    if address is None and not scan:
        _fail("give --address ADDR or --scan", 2)
    loaded = _load(path)
    try:
        parsed_address = None if address is None else _parse_address(address)
        result = find_vtables(
            path,
            loaded,
            address=parsed_address,
            min_slots=min_slots,
            max_slots=max_slots,
            max_tables=max_tables,
            resolve_thunks=not no_thunks,
        )
    except AnalysisError as exc:
        _fail(str(exc), 4)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    if not result.tables:
        console.print("[yellow]no vtable candidates found[/]")
        for warning in result.warnings:
            console.print(f"[yellow]warning:[/] {escape(warning)}")
        return
    for index, candidate in enumerate(result.tables):
        title = (
            f"Vtable candidate {index + 1}/{len(result.tables)} at 0x{candidate.address:x} "
            f"({candidate.section_name}, {len(candidate.slots)} slots"
            + (f", {candidate.header_slots} header skipped)" if candidate.header_slots else ")")
        )
        slots_table = Table(title=escape(title))
        slots_table.add_column("Slot", justify="right")
        slots_table.add_column("Slot address", justify="right")
        slots_table.add_column("Target", justify="right")
        slots_table.add_column("Via thunk", justify="right")
        for slot in candidate.slots:
            slots_table.add_row(
                str(slot.index),
                f"0x{slot.slot_address:x}",
                f"0x{slot.target:x}",
                f"0x{slot.resolved_target:x}" if slot.resolved_target is not None else "-",
            )
        console.print(slots_table)
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")
    console.print(
        "[dim]candidates are runs of code pointers in data — a heuristic, "
        "not proof of a vtable.[/]"
    )


@app.command()
def functions(
    path: Path,
    limit: Annotated[int, typer.Option(help="Maximum candidates to display")] = 200,
) -> None:
    """List function candidates with detection source and confidence."""
    loaded = _load(path)
    candidates = discover_functions(loaded)
    table = Table(title=f"Function candidates ({len(candidates)})")
    table.add_column("Address", justify="right")
    table.add_column("Name")
    table.add_column("Size", justify="right")
    table.add_column("Source")
    table.add_column("Confidence")
    for candidate in candidates[:limit]:
        table.add_row(
            f"0x{candidate.address:x}",
            candidate.name or "<unknown>",
            str(candidate.size) if candidate.size is not None else "-",
            escape(candidate.source),
            candidate.confidence.value,
        )
    console.print(table)
    if len(candidates) > limit:
        console.print(f"[dim]Showing {limit} of {len(candidates)}; raise --limit to see more.[/]")


@app.command()
def strings(
    path: Path,
    min_length: Annotated[int, typer.Option(help="Minimum string length")] = 4,
    limit: Annotated[int, typer.Option(help="Maximum strings to display")] = 200,
) -> None:
    """Extract ASCII and UTF-16LE strings with their locations."""
    loaded = _load(path)
    results = StringExtractor(min_length=min_length).extract(path, info=loaded, limit=limit)
    table = Table(title=f"Strings (min {min_length} chars, first {len(results)})")
    table.add_column("Offset", justify="right")
    table.add_column("VA", justify="right")
    table.add_column("Enc")
    table.add_column("Text")
    for item in results:
        text = item.text if len(item.text) <= 80 else item.text[:77] + "..."
        table.add_row(
            f"0x{item.offset:x}",
            f"0x{item.address:x}" if item.address is not None else "-",
            item.encoding,
            escape(text),
        )
    console.print(table)


@app.command()
def disasm(
    path: Path,
    address: Annotated[
        int | None, typer.Option("--address", "-a", help="Virtual address to disassemble")
    ] = None,
    count: Annotated[int, typer.Option(help="Maximum instructions to decode")] = 50,
    function: Annotated[
        str | None, typer.Option("--function", "-f", help="Function name to disassemble")
    ] = None,
) -> None:
    """Disassemble the entry point, an address, or a named function."""
    loaded = _load(path)
    try:
        start = resolve_target(loaded, address, function)
        result = disassemble_region(path, loaded, start, count=count)
    except AnalysisError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=4) from exc
    table = Table(title=f"Disassembly at 0x{start:x}")
    table.add_column("Address", justify="right")
    table.add_column("Bytes")
    table.add_column("Instruction")
    for insn in result.instructions:
        table.add_row(f"0x{insn.address:x}", insn.raw_bytes.hex(), escape(insn.text))
    console.print(table)
    if result.truncated:
        console.print("[dim]Output truncated; raise --count to decode more.[/]")


@app.command()
def analyze(
    path: Path,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the JSON report to this path")
    ] = None,
    string_limit: Annotated[int, typer.Option(help="Maximum strings kept in the report")] = 5000,
    callgraph: Annotated[
        bool,
        typer.Option("--callgraph", help="Embed the direct-call call graph in the report"),
    ] = False,
    xrefs: Annotated[
        bool,
        typer.Option("--xrefs", help="Embed the cross-reference section in the report"),
    ] = False,
    cfg: Annotated[
        bool,
        typer.Option("--cfg", help="Embed the entry-point control-flow graph in the report"),
    ] = False,
    xref_limit: Annotated[
        int, typer.Option("--xref-limit", help="Maximum cross references kept in the report")
    ] = DEFAULT_XREF_LIMIT,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Echo the JSON report on stdout (default without --output)"),
    ] = False,
) -> None:
    """Run the phase 1 analysis and emit a JSON report.

    Each phase 2 section is opt-in and maps straight to its ``build_report``
    argument: ``--xrefs`` adds ``xrefs`` (bounded by ``--xref-limit``, default
    2000, capped at 200000) and ``--cfg`` adds the entry-point ``cfg`` (bounded
    to 2000 instructions and 500 blocks), each with its own evidence and
    warnings, and the provenance step chain gains ``find_xrefs``/``build_cfg``.
    ``--callgraph`` adds the ``callgraph`` section (bounded to 1000 nodes and
    5000 edges). Without the flags the report is the phase 1 payload.

    When ``--output`` is used a dim one-line summary per embedded section
    (nodes/edges, xrefs kept, CFG blocks; counts and truncation) is printed
    after the file is written, and ``--json`` additionally echoes the payload on
    stdout.
    """
    try:
        report = build_report(
            path,
            string_limit=string_limit,
            xref_limit=xref_limit,
            include_callgraph=callgraph,
            include_xrefs=xrefs,
            include_cfg=cfg,
        )
    except (AnalysisError, BinaryLoadError) as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2) from exc
    payload = json.dumps(report, indent=2)
    if output is not None:
        output.write_text(payload, encoding="utf-8")
        console.print(f"[green]report written:[/] {output}")
        _print_report_summary(report)
        if json_output:
            console.print_json(payload)
        return
    console.print_json(payload)


def _print_report_summary(report: dict[str, Any]) -> None:
    """Print dim one-line summaries for the sections embedded in a report."""
    graph = report.get("callgraph")
    if isinstance(graph, dict):
        console.print(
            f"[dim]callgraph: {graph.get('node_count', 0)} nodes"
            f" · {graph.get('edge_count', 0)} edges"
            f" · truncated: {'yes' if graph.get('truncated') else 'no'}[/]"
        )
    refs = report.get("xrefs")
    if isinstance(refs, dict):
        console.print(
            f"[dim]xrefs: {refs.get('returned', 0)} of {refs.get('count', 0)} kept"
            f" · truncated: {'yes' if refs.get('truncated') else 'no'}[/]"
        )
    flow = report.get("cfg")
    if isinstance(flow, dict):
        console.print(
            f"[dim]cfg: {flow.get('block_count', 0)} blocks"
            f" · {flow.get('instruction_count', 0)} instructions"
            f" · truncated: {'yes' if flow.get('truncated') else 'no'}[/]"
        )


@app.command()
def xrefs(
    path: Path,
    limit: Annotated[int, typer.Option(help="Maximum cross references to display")] = 100,
    max_bytes: Annotated[
        int, typer.Option("--max-bytes", help="Ceiling on executable bytes scanned")
    ] = DEFAULT_MAX_BYTES,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of a table")
    ] = False,
) -> None:
    """List direct-branch cross references found in executable sections."""
    if limit < 1:
        _fail("--limit must be >= 1", 2)
    if max_bytes < 1:
        _fail("--max-bytes must be >= 1", 2)
    loaded = _load(path)
    try:
        result = find_xrefs(path, loaded, max_bytes=max_bytes)
    except AnalysisError as exc:
        _fail(str(exc), 2)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    table = Table(title=f"Cross references ({len(result.xrefs)})")
    table.add_column("From", justify="right")
    table.add_column("To", justify="right")
    table.add_column("Kind")
    table.add_column("Function")
    table.add_column("Instruction")
    for item in result.xrefs[:limit]:
        table.add_row(
            f"0x{item.from_address:x}",
            f"0x{item.to_address:x}",
            escape(item.kind),
            escape(item.function or "-"),
            escape(item.instruction),
        )
    console.print(table)
    if len(result.xrefs) > limit:
        console.print(f"[dim]Showing {limit} of {len(result.xrefs)}; raise --limit for more.[/]")
    shown = ", ".join(result.scanned_sections) or "-"
    console.print(
        f"[dim]scanned {result.scanned_bytes} bytes in {escape(shown)}"
        f" · truncated: {'yes' if result.truncated else 'no'}[/]"
    )
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")


def _print_cfg(graph: FunctionCFG) -> None:
    title = f"Basic blocks ({len(graph.blocks)}) at 0x{graph.function_address:x}"
    if graph.function_name:
        title += f" · {graph.function_name}"
    table = Table(title=escape(title))
    table.add_column("Start", justify="right")
    table.add_column("End", justify="right")
    table.add_column("Instructions", justify="right")
    table.add_column("Terminator")
    table.add_column("Successors")
    for block in graph.blocks:
        successors = ", ".join(f"0x{address:x}" for address in block.successors) or "-"
        table.add_row(
            f"0x{block.start:x}",
            f"0x{block.end:x}",
            str(block.instruction_count),
            escape(block.terminator or "-"),
            escape(successors),
        )
    console.print(table)
    for warning in graph.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")
    if graph.truncated:
        console.print("[dim]graph truncated; raise --max-instructions/--max-blocks for more.[/]")


#: Traversal strategies accepted by ``codevanta cfg``.
CfgTraversal = Literal["linear", "recursive"]


@app.command()
def cfg(
    path: Path,
    address: Annotated[
        int | None, typer.Option("--address", "-a", help="Virtual address of the function")
    ] = None,
    function: Annotated[
        str | None, typer.Option("--function", "-f", help="Function name to graph")
    ] = None,
    max_instructions: Annotated[
        int, typer.Option("--max-instructions", help="Instruction budget for the traversal")
    ] = 2000,
    max_blocks: Annotated[
        int, typer.Option("--max-blocks", help="Maximum basic blocks reported")
    ] = 500,
    traversal: Annotated[
        CfgTraversal,
        typer.Option(
            "--traversal",
            help=(
                "Traversal strategy: linear (contiguous linear sweep, default) or "
                "recursive (follow jump targets from the entry block only)"
            ),
        ),
    ] = "linear",
    resolve_indirect: Annotated[
        bool,
        typer.Option(
            "--resolve-indirect",
            help=(
                "Resolve indirect jumps through pointer jump tables (recursive "
                "traversal only)"
            ),
        ),
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of a table")
    ] = False,
) -> None:
    """Build a control-flow graph for the entry point, an address, or a function.

    The --traversal option selects linear (default: contiguous window sweep) or
    recursive (control-flow driven: only code reachable from the start address is
    graphed). Both return the same FunctionCFG structure (blocks, successors,
    evidence) and therefore the same table, --json payload and warnings; linear
    blocks partition the decoded window while recursive blocks are disjoint but
    limited to reachable code.

    --resolve-indirect only means something to the recursive traversal: it turns
    an indirect ``jmp`` through a pointer-sized memory operand into a jump-table
    lookup, so the dispatch targets become successors and are followed like any
    other block. The linear sweep has no notion of a dispatch edge, so asking for
    it there is rejected (exit code 2) instead of silently ignored.
    """
    if resolve_indirect and traversal != "recursive":
        _fail(
            "--resolve-indirect needs --traversal recursive: the linear sweep does not "
            "follow control flow, so indirect jumps cannot be resolved",
            2,
        )
    loaded = _load(path)
    try:
        start = resolve_target(loaded, address, function)
    except AnalysisError as exc:
        _fail(str(exc), 4)
    try:
        if traversal == "recursive":
            graph = build_recursive_cfg(
                path,
                loaded,
                start,
                max_instructions=max_instructions,
                max_blocks=max_blocks,
                resolve_indirect=resolve_indirect,
            )
        else:
            graph = build_cfg(
                path,
                loaded,
                start,
                max_instructions=max_instructions,
                max_blocks=max_blocks,
            )
    except AnalysisError as exc:
        _fail(str(exc), 5)
    if json_output:
        console.print_json(json.dumps(graph.to_dict()))
        return
    _print_cfg(graph)
    if json_output:
        console.print_json(json.dumps(graph.to_dict()))
        return
    _print_cfg(graph)


#: Number of leading hex characters of a content fingerprint shown in a table.
_DIGEST_PREVIEW = 12


def _digest_cell(delta: FunctionDelta) -> str:
    """Return the fingerprint cell for one function delta.

    Deep mode fingerprints only address-matched pairs, so ``added``/``removed``
    deltas -- and matched pairs beyond the deep-mode ceiling -- carry no digest
    and render as ``-`` rather than as an empty cell.
    """
    if delta.left_digest is None or delta.right_digest is None:
        return "-"
    return f"{delta.left_digest[:_DIGEST_PREVIEW]} -> {delta.right_digest[:_DIGEST_PREVIEW]}"


def _similarity_line(delta: FunctionDelta) -> str:
    """Render one semantic pairing as ``0x401000 -> 0x401010 ... similarity 1.0000``.

    Only deltas carrying a ``similarity`` reach this renderer, so both metadata
    snapshots are set and the two addresses are the move the score paired. The
    score keeps four decimals, matching :attr:`FunctionDelta.similarity` and the
    JSON report, so the text and the payload cannot disagree.
    """
    left = "-" if delta.left is None else str(delta.left.get("address", "-"))
    right = "-" if delta.right is None else str(delta.right.get("address", "-"))
    score = 0.0 if delta.similarity is None else delta.similarity
    return (
        f"semantic pair {left} -> {right} "
        f"({delta.name or '<unknown>'}): similarity {score:.4f}"
    )


def _print_binary_diff(result: BinaryDiff) -> None:
    """Print a :class:`BinaryDiff` as an identity panel plus two tables.

    The first table is the added/removed/changed count matrix for functions,
    sections, imports and exports; the second lists the individual name deltas.
    The function delta table then carries the address, name and change of every
    candidate the comparison could not match, plus -- when deep mode
    fingerprinted the pair -- the truncated content digests of both sides. A
    pairing made by semantic mode adds no column: its score is printed as one
    dim detail line per pair, so the table keeps its shape.
    """
    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold cyan")
    header.add_column()
    header.add_row("Left", escape(result.left_path))
    header.add_row("Right", escape(result.right_path))
    header.add_row("Identical", "yes" if result.identical else "no")
    console.print(Panel(header, title="CODEVANTA · binary diff"))

    counts = Table(title="Deltas")
    counts.add_column("Kind")
    counts.add_column("Added", justify="right")
    counts.add_column("Removed", justify="right")
    counts.add_column("Changed", justify="right")
    for kind, added, removed, changed in (
        (
            "Functions",
            result.functions_added,
            result.functions_removed,
            result.functions_changed,
        ),
        ("Sections", result.sections_added, result.sections_removed, ()),
        ("Imports", result.imports_added, result.imports_removed, ()),
        ("Exports", result.exports_added, result.exports_removed, ()),
    ):
        counts.add_row(kind, str(len(added)), str(len(removed)), str(len(changed)))
    console.print(counts)

    named = (
        [("Section", "added", name) for name in result.sections_added]
        + [("Section", "removed", name) for name in result.sections_removed]
        + [("Import", "added", name) for name in result.imports_added]
        + [("Import", "removed", name) for name in result.imports_removed]
        + [("Export", "added", name) for name in result.exports_added]
        + [("Export", "removed", name) for name in result.exports_removed]
    )
    if named:
        names = Table(title=f"Section, import and export deltas ({len(named)})")
        names.add_column("Kind")
        names.add_column("Change")
        names.add_column("Name")
        for kind, change, name in named:
            names.add_row(escape(kind), escape(change), escape(name))
        console.print(names)

    deltas = sorted(
        (*result.functions_added, *result.functions_removed, *result.functions_changed),
        key=lambda delta: (delta.address, delta.change),
    )
    if deltas:
        show_digests = any(
            delta.left_digest is not None or delta.right_digest is not None for delta in deltas
        )
        scored = [delta for delta in deltas if delta.similarity is not None]
        functions = Table(title=f"Function deltas ({len(deltas)})")
        functions.add_column("Address", justify="right")
        functions.add_column("Name")
        functions.add_column("Change")
        if show_digests:
            functions.add_column("Digest (left -> right)")
        for delta in deltas:
            row = [
                f"0x{delta.address:x}",
                escape(delta.name or "<unknown>"),
                escape(delta.change),
            ]
            if show_digests:
                row.append(escape(_digest_cell(delta)))
            functions.add_row(*row)
        console.print(functions)
        if show_digests:
            console.print(
                "[dim]digests are the first "
                f"{_DIGEST_PREVIEW} hex characters of the normalized shape SHA-256; "
                "equal digests are not byte equality[/]"
            )
        if scored:
            for delta in scored:
                console.print(f"[dim]{escape(_similarity_line(delta))}[/]")
            console.print(
                "[dim]pairs are decoded instruction-shape overlaps, "
                "not proof the functions are the same code[/]"
            )
    else:
        console.print("[dim]no function deltas[/]")
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")


def _diff_threshold(value: float) -> float:
    """Validate ``--threshold`` and return it as a float, or exit 2.

    The bound is checked before either binary is loaded, so an out-of-range
    value fails as an input error instead of after a potentially expensive
    parse -- and it is checked even when ``--semantic`` is off, because a
    silently ignored value would change behaviour the moment semantic matching
    is switched on. ``nan``/``inf`` are rejected alongside the finite range
    because the comparison would otherwise be silently always-false.
    """
    if not math.isfinite(value) or not (DIFF_MIN_THRESHOLD <= value <= DIFF_MAX_THRESHOLD):
        _fail(
            f"invalid threshold {value!r}; expected a number within "
            f"{DIFF_MIN_THRESHOLD} .. {DIFF_MAX_THRESHOLD}",
            2,
        )
    return float(value)


@app.command()
def diff(
    left: Annotated[Path, typer.Argument(help="Baseline (left-hand) binary")],
    right: Annotated[Path, typer.Argument(help="Candidate (right-hand) binary")],
    max_functions: Annotated[
        int,
        typer.Option(
            "--max-functions", help="Per-side ceiling on compared function candidates"
        ),
    ] = DIFF_MAX_FUNCTIONS,
    deep: Annotated[
        bool,
        typer.Option(
            "--deep",
            help="Also compare the normalized content of address-matched functions",
        ),
    ] = False,
    semantic: Annotated[
        bool,
        typer.Option(
            "--semantic",
            help=(
                "Also pair the functions left unpaired by address and name when "
                "their normalized instruction shapes score at least --threshold"
            ),
        ),
    ] = False,
    threshold: Annotated[
        float,
        typer.Option(
            "--threshold",
            help=(
                "Smallest shape-similarity score that may pair two leftovers "
                f"({DIFF_MIN_THRESHOLD} .. {DIFF_MAX_THRESHOLD}, "
                f"default {DIFF_SEMANTIC_THRESHOLD})"
            ),
        ),
    ] = DIFF_SEMANTIC_THRESHOLD,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """Structurally diff two binaries (sections, imports, exports, functions).

    The comparison is metadata only: no instruction bytes are read, compared or
    executed, so the identical flag means "no structural delta was observed",
    never "the machine code is equivalent". A difference is the successful
    outcome, so the command exits 0 whether or not the binaries differ; only load
    and input errors exit non-zero (2).

    ``--deep`` adds a shape fingerprint of every address-matched function: its
    bytes are read (never executed) and their normalized instructions are hashed
    with SHA-256, so immediates and branch targets are masked out. A differing
    digest turns the pair into ``changed`` and both digests are shown;
    ``added``/``removed`` pairs are not fingerprinted and keep ``-``. Equal
    digests are not byte equality and different digests are not a semantic
    difference, so the metadata verdict is never upgraded to "equivalent".

    ``--semantic`` reads the decoded instruction shapes of the functions that
    address and name matching left unpaired and pairs them when their score
    reaches ``--threshold`` (default 0.9, valid range 0.0 .. 1.0; anything else
    exits 2 before a file is loaded). A paired move becomes one ``changed``
    entry and its score is printed as a dim ``semantic pair`` detail line under
    the unchanged function table. Every unpaired candidate keeps its structural
    verdict, so semantic mode can only merge a removal with an addition, never
    hide one. An overlap is evidence of similar decoded shapes, not proof that
    two functions are the same code.
    """
    effective_threshold = _diff_threshold(threshold)
    try:
        result = diff_binaries(
            left,
            right,
            max_functions=max_functions,
            deep=deep,
            semantic=semantic,
            threshold=effective_threshold,
        )
    except BinaryLoadError as exc:
        _fail(str(exc), 2)
    except AnalysisError as exc:
        _fail(str(exc), 2)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    _print_binary_diff(result)


def _jump_table_mode(mode: str | None) -> str | None:
    """Validate ``--mode`` and return it normalised, or ``None`` when omitted.

    Case and surrounding whitespace are folded exactly like
    :func:`codevanta.analysis.jump_tables.resolve_jump_table`, so
    ``--mode Relative`` works; an unknown layout exits 2 before any file is
    loaded, and ``None`` (flag omitted) keeps the historical absolute default
    without changing the printed footer.
    """
    if mode is None:
        return None
    text = mode.strip().lower()
    if text not in MODES:
        _fail(f"invalid mode {mode!r}; expected one of {', '.join(MODES)}", 2)
    return text


def _print_jump_table(
    result: JumpTableResult,
    *,
    mode: str | None = None,
    base_address: int | None = None,
) -> None:
    """Print one :class:`JumpTableResult` as an index/target table plus a footer.

    The first footer line is identical to what earlier releases printed. When
    the caller asked for a layout explicitly, a second dim line names the mode
    and -- in relative mode -- the base: every target of such a table is
    ``base + signed offset`` and is meaningless without it. Keeping that on its
    own line also stops a narrow console from wrapping the base away from its
    label.
    """
    table = Table(title=escape(f"Jump table at 0x{result.table_address:x}"))
    table.add_column("Index", justify="right")
    table.add_column("Target", justify="right")
    for entry in result.entries:
        table.add_row(str(entry.index), f"0x{entry.target:x}")
    console.print(table)
    if not result.entries:
        console.print("[yellow]no pointer slots decoded at this address[/]")
    console.print(
        f"[dim]pointer size: {result.pointer_size} bytes"
        f" · entries: {len(result.entries)}"
        f" · truncated: {'yes' if result.truncated else 'no'}[/]"
    )
    layout: list[str] = []
    if mode is not None:
        layout.append(f"mode: {mode}")
    if base_address is not None:
        layout.append(f"base: 0x{base_address:x}")
    if layout:
        console.print(f"[dim]{' · '.join(layout)}[/]")
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")


@app.command("jump-table")
def jump_table(
    path: Path,
    address: Annotated[
        str,
        typer.Option(
            "--address",
            "-a",
            help="Virtual address of the first pointer slot (decimal or 0x hex)",
        ),
    ],
    entries: Annotated[
        int, typer.Option("--entries", help="Maximum pointer slots to decode")
    ] = JUMP_TABLE_MAX_ENTRIES,
    executable_only: Annotated[
        bool,
        typer.Option(
            "--executable-only/--no-executable-only",
            help="Stop the scan at pointers into non-executable sections",
        ),
    ] = True,
    mode: Annotated[
        str | None,
        typer.Option(
            "--mode",
            help="Table layout: 'absolute' pointer slots (default) or 'relative' "
            "signed 32-bit offsets from --base",
        ),
    ] = None,
    base: Annotated[
        str | None,
        typer.Option(
            "--base",
            help="Origin that relative offsets are added to (decimal or 0x hex); "
            "required with --mode relative",
        ),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of a table")
    ] = False,
) -> None:
    """Decode a jump table starting at ADDRESS.

    With ``--mode absolute`` (the default) each slot is a pointer-sized absolute
    virtual address; with ``--mode relative`` each slot is a signed 32-bit offset
    and the target is ``--base + offset``, which is the shape position-independent
    switch tables use. Relative mode without a usable ``--base`` exits 2 instead
    of inventing an origin, because every target would otherwise be wrong.

    Slots are read exclusively from the containing section's file bytes and
    decoded with the binary's endianness and pointer width (8 bytes for a 64-bit
    binary, 4 for a 32-bit one; always 4 in relative mode). The scan stops at the
    first slot that cannot be a target, namely an address no section maps, or a
    pointer into a non-executable section while --executable-only is in effect,
    and every such stop is reported as a warning. In absolute mode a zero pointer
    also terminates the table. Decoded pointers are evidence of a dispatch table,
    not proof that a dispatcher indexes it.
    """
    table_address = _parse_address(address)
    explicit_mode = _jump_table_mode(mode)
    resolved_mode = explicit_mode or MODE_ABSOLUTE
    base_address = None if base is None else _parse_address(base, label="base")
    if resolved_mode == MODE_RELATIVE and base_address is None:
        _fail("--mode relative requires --base (e.g. --base 0x401000)", 2)
    loaded = _load(path)
    try:
        result = resolve_jump_table(
            path,
            loaded,
            table_address,
            max_entries=entries,
            executable_only=executable_only,
            mode=resolved_mode,
            base_address=base_address if resolved_mode == MODE_RELATIVE else None,
        )
    except AnalysisError as exc:
        _fail(str(exc), 2)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    _print_jump_table(
        result,
        mode=explicit_mode,
        base_address=base_address if resolved_mode == MODE_RELATIVE else None,
    )


#: Pointer width in bytes per bitness, used when a memory operand carries no
#: Intel size keyword. Mirrors the fallback used by the type-recovery layer.
_STRUCT_POINTER_WIDTHS: dict[int, int] = {16: 2, 32: 4, 64: 8}


def _struct_offset_cell(offset: int) -> str:
    """Render a field offset in hex, keeping the sign in front (``-0x8``)."""
    return f"-0x{-offset:x}" if offset < 0 else f"0x{offset:x}"


def _struct_base_registers(
    path: Path,
    info: BinaryInfo,
    start: int,
    *,
    max_instructions: int,
    include_stack: bool,
) -> tuple[str, ...]:
    """Return the base registers a *single* struct window saw, sorted and unique.

    :func:`codevanta.analysis.type_recovery.suggest_struct` aggregates accesses
    per offset and therefore drops the base register of each access, while the
    footer still has to name the registers used as struct pointers. The same
    bounded window is decoded once more and every operand goes through the
    production parser (:func:`parse_memory_operands`), so both passes agree on
    which operands count. A failure here never fails the command: the suggestion
    is already computed, so the footer simply reports no base register.

    Only the single-window path pays for this second decode -- one extra window,
    so the single-address output stays exactly as it was. A merge must not
    multiply that cost by its window count and reads the registers out of the
    evidence instead (:func:`_struct_evidence_base_registers`).
    """
    pointer_width = _STRUCT_POINTER_WIDTHS.get(info.bitness, 8)
    try:
        region = disassemble_region(path, info, start, count=max_instructions)
    except (AnalysisError, DisassemblyError):
        return ()
    registers: set[str] = set()
    for instruction in region.instructions:
        for access in parse_memory_operands(
            instruction, include_stack=include_stack, pointer_width=pointer_width
        ):
            registers.add(access.base_register)
    return tuple(sorted(registers))


#: Evidence key a suggestion would carry the base registers it saw under.
_STRUCT_BASE_REGISTER_KEY = "base_registers"


def _struct_evidence_base_registers(result: StructSuggestion) -> tuple[str, ...]:
    """Return the base registers the sweep behind ``result`` recorded itself.

    A merge aggregates accesses per offset across windows, so the base register
    of each access is not a field of its own. Re-sweeping every window just for
    the footer would decode up to ``max_windows * max_instructions``
    instructions a second time, on top of the budget the merge is bounded by, so
    the union is read out of the evidence the merge already produced instead --
    from the merged suggestion and from every merged field, because either level
    can carry it. The values are de-duplicated and sorted, which keeps the footer
    independent of the order the windows were passed in.

    The phase 2k analysis layer records no base register in that evidence, so
    this returns none today and the footer says so rather than paying for a
    second decode. Carrying the registers out of the sweep is an analysis-layer
    change; until it lands, nothing here decodes a window again.
    """
    registers: set[str] = set()
    evidence_records = [result.evidence, *(field.evidence for field in result.fields)]
    for evidence in evidence_records:
        recorded = evidence.extra.get(_STRUCT_BASE_REGISTER_KEY)
        if not isinstance(recorded, (list, tuple, set, frozenset)):
            continue
        registers.update(name for name in recorded if isinstance(name, str))
    return tuple(sorted(registers))


def _struct_window_text(windows: tuple[int, ...]) -> str:
    """Render merged windows as ``2 (0x401000, 0x401004)``."""
    addresses = ", ".join(f"0x{start:x}" for start in windows)
    return f"{len(windows)} ({addresses})"


def _struct_warnings(result: StructSuggestion, *, merged: bool = False) -> list[str]:
    """Return the CLI-level warnings for one struct suggestion.

    ``merged`` selects the field-cap hint. A single window can keep the dropped
    offsets by raising ``--max-fields``, but the same command exits 2 on a
    non-default ``--max-fields`` next to a merge, so a merge must not be told to
    raise a flag it rejects: it is told the cap the merged sweep applies instead
    and that the windows have to be split to see the remaining offsets.
    """
    warnings: list[str] = []
    if result.truncated:
        if merged:
            warnings.append(
                f"field cap reached: the merged sweep keeps at most {STRUCT_MAX_FIELDS} "
                "offsets, so split the windows into separate runs to see the remaining "
                "offsets"
            )
        else:
            warnings.append(
                f"field cap of {result.max_fields} reached; raise --max-fields for the "
                "remaining offsets"
            )
    if not result.fields:
        hint = (
            ""
            if result.include_stack
            else "; stack-based operands are excluded unless --include-stack is given"
        )
        warnings.append(f"no field-shaped memory operand was decoded in the window{hint}")
    return warnings


def _struct_alignment_text(result: StructSuggestion) -> str:
    """Render the inferred alignment, or ``unknown`` when none could be derived."""
    return "unknown" if result.alignment is None else str(result.alignment)


def _struct_array_line(group: ArrayGroup) -> str:
    """Render one array candidate as ``array at 0x10: 3 x 8-byte, stride 8``."""
    return (
        f"array at {_struct_offset_cell(group.offset)}: "
        f"{group.count} x {group.width}-byte, stride {group.stride}"
    )


def _struct_signed_text(result: StructSuggestion) -> str:
    """Render the signedness hints of ``result`` as one footer value.

    Only fields with evidence contribute, so a field whose offset was never
    touched by a sign- or zero-extending mnemonic stays out of the line, and a
    suggestion without any hint reports ``none`` -- meaning "no signedness
    evidence", never "safe". Contradictory offsets are already collapsed to
    ``signed=None`` (with a warning) by the analysis layer, so they read as
    unknown here too. Offsets are named in hex, order preserved from the table.
    """
    hints = [
        f"{_struct_offset_cell(field.offset)} "
        f"{'signed' if field.signed else 'unsigned'}"
        for field in result.fields
        if field.signed is not None
    ]
    return ", ".join(hints) or "none"


def _print_struct_layout(result: StructSuggestion) -> None:
    """Print the alignment line and one line per array candidate.

    ``arrays: none`` stands in for the absent group lines, so the footer always
    says whether a run was found. Both texts go through :func:`escape` because
    they are assembled from analysis data. The closing ``signed:`` line follows
    the same rule: it lists the offsets that carry a signedness hint (or
    ``none``), keeping the hint out of the table columns.
    """
    console.print(f"[dim]alignment: {escape(_struct_alignment_text(result))}[/]")
    if result.array_groups:
        for group in result.array_groups:
            console.print(f"[dim]{escape(_struct_array_line(group))}[/]")
    else:
        console.print("[dim]arrays: none[/]")
    console.print(f"[dim]signed: {escape(_struct_signed_text(result))}[/]")


def _struct_register_footer(base_registers: tuple[str, ...], *, merged: bool) -> str:
    """Render the ``base registers:`` footer value of a struct run.

    A single window derives its registers from its own decode, so the only empty
    case is a window without a field-shaped operand and ``-`` states that. A
    merge reads the union from the evidence the sweep already produced; when that
    evidence carries none, ``-`` would claim the windows never used a base
    register, so the footer says the merge did not record them instead of
    decoding every window a second time to find out.
    """
    if base_registers:
        return ", ".join(base_registers)
    return "not recorded by the merge" if merged else "-"


def _print_struct_suggestion(
    result: StructSuggestion,
    *,
    base_registers: tuple[str, ...],
    windows: tuple[int, ...] | None = None,
) -> None:
    """Print one :class:`StructSuggestion` as an offset table plus a footer.

    ``windows`` is only passed by the merged (repeated ``--address``) path, where
    it adds one ``windows:`` footer line naming every merged address and selects
    the merge wording of the field-cap hint. The single-window output stays
    unchanged because both only apply when ``windows`` is given.
    """
    table = Table(title=escape(f"Struct at 0x{result.address:x}"))
    table.add_column("Offset", justify="right")
    table.add_column("Width", justify="right")
    table.add_column("Reads", justify="right")
    table.add_column("Writes", justify="right")
    for field in result.fields:
        table.add_row(
            _struct_offset_cell(field.offset),
            str(field.width),
            str(field.read_count),
            str(field.write_count),
        )
    console.print(table)
    merged = windows is not None
    registers = _struct_register_footer(base_registers, merged=merged)
    console.print(f"[dim]base registers: {escape(registers)} - fields: {result.field_count}[/]")
    console.print(
        f"[dim]instructions: {result.instruction_count}"
        f" - max fields: {result.max_fields}"
        f" - truncated: {'yes' if result.truncated else 'no'}[/]"
    )
    if windows is not None:
        console.print(f"[dim]windows: {escape(_struct_window_text(windows))}[/]")
    _print_struct_layout(result)
    for warning in _struct_warnings(result, merged=merged):
        console.print(f"[yellow]warning:[/] {escape(warning)}")


@app.command()
def struct(
    path: Path,
    address: Annotated[
        list[str] | None,
        typer.Option(
            "--address",
            "-a",
            help=(
                "Virtual address of the first instruction (decimal or 0x hex); repeat "
                f"up to {STRUCT_MAX_WINDOWS} times to merge the windows"
            ),
        ),
    ] = None,
    function: Annotated[
        str | None, typer.Option("--function", "-f", help="Function to start the sweep at")
    ] = None,
    max_instructions: Annotated[
        int,
        typer.Option("--max-instructions", help="Maximum instructions to decode"),
    ] = STRUCT_MAX_INSTRUCTIONS,
    max_fields: Annotated[
        int,
        typer.Option("--max-fields", help="Maximum distinct field offsets reported"),
    ] = STRUCT_MAX_FIELDS,
    include_stack: Annotated[
        bool,
        typer.Option(
            "--include-stack",
            help=(
                "Keep \\[rsp]/\\[rbp]-relative operands instead of treating them as "
                "stack slots"
            ),
        ),
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of a table")
    ] = False,
) -> None:
    """Suggest the struct fields a function accesses through memory operands.

    The start address comes from ``--address``, else ``--function``, else the
    entry point. A bounded window (``--max-instructions``) is disassembled and
    every ``\\[reg]`` / ``\\[reg + 0xNN]`` / ``\\[reg - 0xNN]`` operand is
    aggregated per offset: the dominant access width, the read count and the
    write count. Only file bytes are read; nothing is mapped or executed.

    ``--address`` is repeatable: one address is the single-window sweep above,
    while two or more addresses are merged by ``suggest_structs`` (type
    recovery) into one field per offset -- counters summed, widest width
    winning, earliest access kept -- and the ``alignment``/``array_groups``/
    ``truncated`` facts are recomputed across windows. A merge accepts at most
    ``MAX_MERGED_WINDOWS`` (16) windows, sorts the addresses before decoding,
    and rejects duplicated ones, so the output is the same for any order of the
    same address set. ``--function`` names one start, so it is rejected (exit 2)
    next to *any* ``--address`` -- one address would silently win over it --
    and ``--max-fields`` is rejected next to a merge, which always keeps its own
    ``DEFAULT_MAX_FIELDS`` (64) cap.

    Fields are a heuristic about how the code reaches memory through one base
    register, not verified types: signedness, purpose and lifetime stay unknown.
    ``\\[rsp]``/``\\[rbp]``-based operands usually describe stack slots, so they
    are dropped unless ``--include-stack`` is given, and ``--max-fields`` caps the
    number of offsets kept (the rest are dropped and reported as truncated).

    ``--json`` emits ``StructSuggestion.to_dict()`` unchanged, which already
    carries the derived ``alignment``, ``array_groups`` and per-field ``signed``
    hint, plus the merged ``window_count``/``windows`` in the evidence ``extra``.
    The table adds a footer naming the base registers seen, the field and
    instruction counts, the truncation flag, the inferred ``alignment``
    (``unknown`` when fewer than two distinct non-zero offsets were seen), one
    ``array at 0x..`` line per array candidate -- ``arrays: none`` when no run
    was found -- and one ``signed:`` line listing the offsets whose mnemonics
    hinted a signed or unsigned access (``none`` when nothing hinted), followed
    by one ``warning:`` line per limitation. A merged run adds one
    ``windows: N (0x.., 0x..)`` line naming the merged windows, and reads its
    base registers out of the evidence the merge already produced instead of
    decoding every window again -- that evidence records none today, so the
    footer says so. A truncated merge is told to split the windows, because the
    merged sweep always keeps at most its own field cap. Load and input
    errors -- unreadable file, bad address, unknown function, address outside an
    executable section, duplicated address, too many windows, conflicting
    options -- exit 2.
    """
    starts = tuple(_parse_address(text) for text in address or ())
    if starts and function is not None:
        _fail(
            "--function names one start; give either --function or --address, not both",
            2,
        )
    if len(starts) > 1 and max_fields != STRUCT_MAX_FIELDS:
        _fail(
            "--max-fields applies to a single --address; the merged sweep keeps "
            f"at most {STRUCT_MAX_FIELDS} fields",
            2,
        )
    loaded = _load(path)
    try:
        if len(starts) > 1:
            result = suggest_structs(
                path,
                loaded,
                starts,
                max_instructions=max_instructions,
                include_stack=include_stack,
            )
        else:
            start = resolve_target(loaded, starts[0] if starts else None, function)
            result = suggest_struct(
                path,
                loaded,
                start,
                max_instructions=max_instructions,
                max_fields=max_fields,
                include_stack=include_stack,
            )
    except AnalysisError as exc:
        _fail(str(exc), 2)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    if len(starts) > 1:
        windows = tuple(sorted(starts))
        _print_struct_suggestion(
            result,
            base_registers=_struct_evidence_base_registers(result),
            windows=windows,
        )
        return
    _print_struct_suggestion(
        result,
        base_registers=_struct_base_registers(
            path,
            loaded,
            start,
            max_instructions=max_instructions,
            include_stack=include_stack,
        ),
    )


def _header_fact(line: str, label: str) -> str | None:
    """Return the value behind ``label:`` on one header comment line.

    The native renderer states its own block/instruction counts and truncation
    flag only inside the ``* blocks: 1  instructions: 2  truncated: false`` line
    of the header comment it writes at the top of the pseudo-C, so the footer
    reads that line back instead of decoding the function a second time.
    """
    _, separator, rest = line.partition(f"{label}:")
    if not separator:
        return None
    value = rest.split()[0] if rest.split() else ""
    return value or None


def _fact_text(value: Any) -> str:
    """Render one count fact from a rendering, or ``unknown`` when it stated none."""
    return "unknown" if value is None else str(value)


def _truncation_text(value: Any) -> str:
    """Render a truncation flag as ``yes``/``no``, or ``unknown`` when unstated."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = "" if value is None else str(value).strip().lower()
    if text in {"true", "yes", "1"}:
        return "yes"
    if text in {"false", "no", "0"}:
        return "no"
    return "unknown"


def _rendering_facts(result: BackendResult) -> tuple[str, str, str]:
    """Return the ``(blocks, instructions, truncated)`` footer facts of a rendering.

    The backends report these differently: ``angr`` and ``ghidra`` record a block
    count (and the requested budgets) in the evidence ``extra`` map, while the
    native renderer only prints them in its header comment, which
    :func:`_header_fact` reads. A fact no backend stated stays ``unknown`` rather
    than guessed, and a truncated rendering is never reported as whole.
    """
    extra = result.evidence.extra
    blocks = extra.get("blocks", extra.get("block_count"))
    instructions = extra.get("instructions")
    truncated = extra.get("truncated")
    if blocks is None or instructions is None or truncated is None:
        header = next(
            (
                line
                for line in result.text.splitlines()
                if "blocks:" in line and "instructions:" in line and "truncated:" in line
            ),
            "",
        )
        if blocks is None:
            blocks = _header_fact(header, "blocks")
        if instructions is None:
            instructions = _header_fact(header, "instructions")
        if truncated is None:
            truncated = _header_fact(header, "truncated")
    return _fact_text(blocks), _fact_text(instructions), _truncation_text(truncated)


def _print_decompilation(result: BackendResult, start: int) -> None:
    """Print one rendering as a Panel, then a dim footer and one line per warning.

    The body is wrapped in a :class:`~rich.text.Text` instead of being printed as
    markup-bearing text, so the pseudo-C is shown byte for byte: a ``[`` or a
    ``/* ... */`` comment in the rendering is never interpreted by Rich. The
    footer repeats the counts the backend stated, and every warning keeps its own
    line so a fallback or an unresolved indirect branch is never hidden.
    """
    console.print(
        Panel(
            Text(result.text),
            title=escape(f"Decompilation at 0x{start:x}"),
            subtitle=escape(f"backend: {result.backend} · language: {result.language}"),
        )
    )
    blocks, instructions, truncated = _rendering_facts(result)
    console.print(
        f"[dim]blocks: {blocks} · instructions: {instructions} · truncated: {truncated}[/]"
    )
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")


@app.command()
def decompile(
    path: Path,
    address: Annotated[
        str | None,
        typer.Argument(
            help="Virtual address of the function (decimal or 0x hex); defaults to the entry point"
        ),
    ] = None,
    backend: Annotated[
        str,
        typer.Option(
            "--backend",
            help=(
                "Decompiler backend: 'auto' (default: first available external provider, "
                "else native), 'native', 'angr' or 'ghidra'"
            ),
        ),
    ] = "auto",
    function: Annotated[
        str | None, typer.Option("--function", "-f", help="Function name to decompile")
    ] = None,
    max_instructions: Annotated[
        int, typer.Option("--max-instructions", help="Maximum instructions to render")
    ] = DECOMPILE_MAX_INSTRUCTIONS,
    max_blocks: Annotated[
        int, typer.Option("--max-blocks", help="Maximum basic blocks to render")
    ] = DECOMPILE_MAX_BLOCKS,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON rendering instead of a panel")
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", "-o", help="Write the rendering here (the JSON payload with --json)"
        ),
    ] = None,
) -> None:
    """Decompile one function to readable pseudo-C.

    The function comes from ADDRESS, else ``--function``, else the entry point,
    resolved exactly like ``codevanta disasm`` does -- an address therefore wins
    over ``--function`` when both are given. The target binary is only ever read:
    the rendering is static text, and nothing is mapped or executed.

    ``--backend`` selects the provider. ``auto`` (the default) prefers the first
    available external backend (``ghidra``, then ``angr``) and falls back to the
    built-in heuristic renderer, recording one warning per skipped backend so a
    fallback is never silent. ``native`` always works; ``angr`` and ``ghidra``
    are strict and exit 2 with the probe's reason -- install hint included --
    instead of substituting another provider. A missing optional dependency never
    surfaces as ``ImportError``.

    ``--max-instructions`` and ``--max-blocks`` bound the work; an out-of-range
    budget is rejected before any backend runs.

    The panel shows the pseudo-C body verbatim (no markup is interpreted) with the
    backend that produced it and the source language, followed by a dim
    ``blocks``/``instructions``/``truncated`` footer and one ``warning:`` line per
    limitation: budget cuts, unresolved indirect branches, skipped backends.
    ``--json`` prints ``BackendResult.to_dict()`` unchanged instead, and
    ``--output`` writes the rendering -- the JSON payload when ``--json`` is given
    -- to a file. Load errors, a bad address, an unknown function, an unknown
    backend and an unavailable backend all exit 2.
    """
    requested = None if address is None else _parse_address(address)
    loaded = _load(path)
    try:
        start = resolve_target(loaded, requested, function)
        result = decompile_function(
            path,
            loaded,
            start,
            backend=backend,
            max_instructions=max_instructions,
            max_blocks=max_blocks,
        )
    except AnalysisError as exc:
        _fail(str(exc), 2)
    payload = result.to_dict()
    if output is not None:
        written = json.dumps(payload) if json_output else result.text
        output.write_text(written if written.endswith("\n") else f"{written}\n", encoding="utf-8")
        console.print(f"[green]rendering written:[/] {escape(str(output))}")
    if json_output:
        console.print_json(json.dumps(payload))
        return
    _print_decompilation(result, start)


def _parse_register_assignment(text: str) -> tuple[str, int]:
    """Parse one ``REG=VALUE`` register seed given through ``--set``.

    The name is passed through untouched -- the emulation layer owns the valid
    register set, so a typo is reported by its own message -- while the value
    accepts decimal and ``0x``-prefixed hex. A missing ``=``, an empty name or
    value, and a negative value all exit 2 rather than seeding a wrong state.
    """
    name, separator, value = text.partition("=")
    name = name.strip()
    value = value.strip()
    if not separator or not name or not value:
        _fail(f"invalid --set {text!r}; use REG=VALUE, e.g. --set rdi=2", 2)
    try:
        parsed = int(value, 0)
    except ValueError:
        _fail(f"invalid --set value {value!r}; use decimal or 0x-prefixed hex", 2)
    if parsed < 0:
        _fail(f"invalid --set value {value!r}; register values must not be negative", 2)
    return name, parsed


def _parse_memory_block(text: str) -> tuple[int, bytes]:
    """Parse one ``ADDRESS=HEXBYTES`` memory block given through ``--mem``.

    The address side accepts decimal and ``0x``-prefixed hex, the byte side an
    even number of hex digits (``--mem 0x600000=48454c4c4f``). The block is
    placed in emulator memory before the run, which is how a decrypted or
    synthetic input reaches the emulated code without touching the host.
    """
    address_text, separator, hex_text = text.partition("=")
    if not separator:
        _fail(f"invalid --mem {text!r}; use ADDRESS=HEXBYTES, e.g. --mem 0x600000=deadbeef", 2)
    block_address = _parse_address(address_text.strip(), label="--mem address")
    digits = "".join(hex_text.split())
    if not digits:
        _fail(f"invalid --mem {text!r}; the byte side is empty", 2)
    try:
        data = bytes.fromhex(digits)
    except ValueError as exc:
        _fail(f"invalid --mem bytes {digits!r}; use an even number of hex digits ({exc})", 2)
    return block_address, data


def _register_line(registers: Mapping[str, int]) -> str:
    """Render the non-zero registers as ``rax=0x2a rbp=0x7fff...``.

    Zeroed registers are dropped because the ABI defaults zero most of them, so
    the ones that survived the run are the interesting ones. ``none`` is printed
    when every register is zero, so the line never disappears.
    """
    live = [f"{name}=0x{value:x}" for name, value in sorted(registers.items()) if value]
    return " ".join(live) if live else "none"


def _value_text(value: int | None) -> str:
    """Render a machine value as ``0x2a (42)``, or ``none`` when absent."""
    return "none" if value is None else f"0x{value:x} ({value})"


def _print_emulation(result: emulator.EmulationResult) -> None:
    """Print one run as a fact table, then the live registers and the warnings.

    The table carries exactly what a caller has to read off a bounded run: why it
    stopped, how many instructions completed, the return value (``none`` unless
    the stop reason is ``return``, because a value left in ``rax`` by an
    interrupted run is not a return value) and the resolved indirect targets. The
    dim line under it lists the non-zero registers, and every warning keeps its
    own line so a budget cut or a faulting address is never hidden.
    """
    table = Table(title=escape(f"Emulation at 0x{result.address:x}"))
    table.add_column("Fact")
    table.add_column("Value")
    targets = ", ".join(f"0x{target:x}" for target in result.indirect_targets) or "none"
    rows = (
        ("stopped reason", result.stopped_reason),
        ("instructions", str(result.instructions)),
        ("return value", _value_text(result.return_value)),
        ("indirect targets", targets),
    )
    for label, value in rows:
        table.add_row(label, escape(str(value)))
    console.print(table)
    console.print(f"[dim]registers: {escape(_register_line(result.registers))}[/]")
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")


@app.command()
def emulate(
    path: Path,
    address: Annotated[
        str | None,
        typer.Argument(
            help="Virtual address to start at (decimal or 0x hex); defaults to the entry point"
        ),
    ] = None,
    max_instructions: Annotated[
        int, typer.Option("--max-instructions", help="Instruction budget for one run")
    ] = emulator.DEFAULT_MAX_INSTRUCTIONS,
    stack_size: Annotated[
        int, typer.Option("--stack-size", help="Bytes of stack to map for the run")
    ] = emulator.DEFAULT_STACK_SIZE,
    set_values: Annotated[
        list[str] | None,
        typer.Option(
            "--set", help="Seed a register, e.g. --set rdi=2 (decimal or 0x hex); repeatable"
        ),
    ] = None,
    memory: Annotated[
        list[str] | None,
        typer.Option(
            "--mem", help="Place a memory block, e.g. --mem 0x600000=deadbeef; repeatable"
        ),
    ] = None,
    stop_at_indirect: Annotated[
        bool,
        typer.Option(
            "--resolve-target",
            help="Stop at the first indirect branch and report its target instead",
        ),
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of a table")
    ] = False,
) -> None:
    """Emulate one function offline and report what it returns.

    The run starts at ADDRESS, else the entry point, on a *private* virtual CPU:
    only the file's bytes are copied into emulator memory, so nothing is ever
    executed on the host, and ``--max-instructions`` bounds the work. Registers
    start at the ABI defaults (instruction and stack pointers seeded, argument
    registers left alone), which is why inputs are seeded explicitly with
    ``--set REG=VALUE`` (repeatable, decimal or ``0x`` hex) and
    ``--mem ADDRESS=HEXBYTES`` (repeatable blocks placed before the run, which is
    how an encrypted or synthetic input reaches the emulated code).

    The table reports why the run stopped, how many instructions completed, the
    return value and the indirect targets it resolved; the dim line under it
    lists the non-zero registers, and every degradation (budget exhausted,
    unmapped access, unresolved indirect branch) keeps its own ``warning:`` line.
    A partial answer is never dressed up as a complete one: a value read from
    ``rax`` after a budget stop is reported as a register, not as a return value.
    ``--json`` prints ``EmulationResult.to_dict()`` unchanged, which swaps the
    table for the full register snapshot, the recorded memory writes and the
    evidence.

    ``--resolve-target`` answers the static-analysis question instead: it runs
    until the first indirect jump/call and reports that target, so the payload is
    ``address``/``mode``/``resolved``/``indirect_target`` plus the budget rather
    than an emulation result (there is none). ``--stack-size`` only affects a full
    emulation, so a non-default value is called out when ``--resolve-target`` is
    used.

    Emulation needs the optional ``unicorn`` engine; when it is missing this exits
    2 with :func:`codevanta.analysis.emulate.emulator_status` as the reason and
    never raises ``ImportError``. Malformed seeds, an unknown register, an address
    outside an executable section and out-of-range limits also exit 2.
    """
    if not emulator.EMULATOR_AVAILABLE:
        _fail(
            "emulation is unavailable: "
            f"{emulator.emulator_status() or 'the unicorn engine could not be imported'}; "
            "codevanta.analysis.emulate.emulator_status() reports the exact probe result -- "
            "install it with 'pip install unicorn' and retry",
            2,
        )
    registers = dict(_parse_register_assignment(text) for text in set_values or ())
    blocks: dict[int, bytes] = {}
    for text in memory or ():
        block_address, data = _parse_memory_block(text)
        blocks[block_address] = data
    requested = None if address is None else _parse_address(address)
    loaded = _load(path)
    try:
        start = resolve_target(loaded, requested, None)
        if stop_at_indirect:
            target = emulator.resolve_indirect_target(
                path,
                loaded,
                start,
                registers,
                max_instructions=max_instructions,
                initial_memory=blocks,
            )
        else:
            result = emulator.emulate_function(
                path,
                loaded,
                start,
                initial_registers=registers,
                initial_memory=blocks,
                max_instructions=max_instructions,
                stack_size=stack_size,
            )
    except AnalysisError as exc:
        _fail(str(exc), 2)
    if stop_at_indirect:
        if json_output:
            console.print_json(
                json.dumps(
                    {
                        "address": f"0x{start:x}",
                        "mode": "resolve_indirect_target",
                        "resolved": target is not None,
                        "indirect_target": None if target is None else f"0x{target:x}",
                        "max_instructions": max_instructions,
                    }
                )
            )
            return
        if target is None:
            console.print("[yellow]indirect target: unresolved[/]")
            console.print(
                "[dim]no indirect branch was reached before the run stopped, or its operand "
                "could not be evaluated; that means unresolved, never 'no target'[/]"
            )
        else:
            console.print(f"[green]indirect target:[/] {_value_text(target)}")
        if stack_size != emulator.DEFAULT_STACK_SIZE:
            console.print(
                "[dim]note: --stack-size applies to a full emulation, not to --resolve-target[/]"
            )
        return
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    _print_emulation(result)


#: Output formats accepted by ``codevanta callgraph``.
CallGraphFormat = Literal["json", "dot", "graphml", "html"]


def _render_call_graph(graph: CallGraph, output_format: CallGraphFormat, path: Path) -> str:
    """Render ``graph`` as JSON, DOT, GraphML or HTML text.

    ``json`` serializes the analysis payload itself (:meth:`CallGraph.to_dict`);
    ``dot``, ``graphml`` and ``html`` render the generic graph model so the shared
    exporters in :mod:`codevanta.analysis.graph_export` and the viewer in
    :mod:`codevanta.analysis.html_view` stay the only serializers.

    Every serializer is given size-derived caps (``max(DEFAULT, len(...))``) so a
    graph the analysis already accepted is never rejected downstream for being
    larger than the exporter default.
    """
    if output_format in ("dot", "graphml", "html"):
        model = graph.to_graph_model()
        title = f"callgraph {path.name}"
        max_nodes = max(EXPORT_MAX_NODES, len(model["nodes"]))
        max_edges = max(EXPORT_MAX_EDGES, len(model["edges"]))
        if output_format == "dot":
            return to_dot(model, title=title, max_nodes=max_nodes, max_edges=max_edges)
        if output_format == "graphml":
            return to_graphml(model, title=title, max_nodes=max_nodes, max_edges=max_edges)
        return to_html(model, title=title, max_nodes=max_nodes, max_edges=max_edges)
    return json.dumps(graph.to_dict(), indent=2)


@app.command()
def callgraph(
    path: Path,
    limit_functions: Annotated[
        int,
        typer.Option("--limit-functions", help="Maximum function candidates kept as nodes"),
    ] = DEFAULT_MAX_FUNCTIONS,
    limit_edges: Annotated[
        int, typer.Option("--limit-edges", help="Maximum call edges reported")
    ] = DEFAULT_MAX_EDGES,
    output_format: Annotated[
        CallGraphFormat,
        typer.Option(
            "--format",
            help=(
                "Output format: json (analysis payload), dot, graphml or html "
                "(self-contained SVG viewer)"
            ),
        ),
    ] = "json",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the graph to this path instead of stdout"),
    ] = None,
) -> None:
    """Build the direct-call call graph and emit it as JSON, DOT, GraphML or HTML."""
    loaded = _load(path)
    try:
        graph = build_call_graph(
            path,
            loaded,
            functions=discover_functions(loaded),
            max_functions=limit_functions,
            max_edges=limit_edges,
        )
        payload = _render_call_graph(graph, output_format, path)
    except (AnalysisError, GraphExportError) as exc:
        _fail(str(exc), 2)
    if output is not None:
        try:
            output.write_text(payload, encoding="utf-8", newline="\n")
        except (OSError, UnicodeError) as exc:
            _fail(f"cannot write {output}: {exc}", 2)
        console.print(f"[green]graph written:[/] {escape(str(output))}")
    else:
        # markup=False keeps DOT/GraphML brackets intact; soft_wrap avoids
        # inserting line breaks that would corrupt the serialized payload.
        console.print(payload, markup=False, soft_wrap=True)
    console.print(
        f"[dim]nodes: {len(graph.nodes)} · edges: {len(graph.edges)}"
        f" · truncated: {'yes' if graph.truncated else 'no'}"
        f" · format: {escape(output_format)}[/]"
    )
    for warning in graph.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")


# --------------------------------------------------------------------------- #
# Dynamic sessions: replay a saved trace, generate an attach script
# --------------------------------------------------------------------------- #

#: Providers ``codevanta trace`` accepts; ``auto`` reads the provider off the file.
TraceProvider = Literal["gdb", "frida", "auto"]

#: Providers ``codevanta attach`` generates a session script for.
AttachProvider = Literal["gdb", "frida"]

#: Lines ``--provider auto`` reads before it gives up on detecting the provider.
_DETECT_LINES = 200

#: First-line markers the generated gdb script prints, in the order they appear.
_GDB_TRACE_MARKERS = ("HIT ", "BACKTRACE", "LIMIT ", "DONE ")


def _detect_trace_provider(text: str) -> str | None:
    """Return which provider wrote ``text``, or ``None`` when nothing matches.

    Detection reads the file shape, not a flag: a line that parses as a JSON
    object is one of the messages the Frida hook sends, and a line opening with
    ``HIT``/``BACKTRACE``/``LIMIT``/``DONE`` is one the gdb script prints. Only
    the first :data:`_DETECT_LINES` non-blank lines are inspected, so a large
    trace costs no more than a small one, and an unrecognisable file returns
    ``None`` instead of being guessed onto whichever provider has more markers.
    """
    for line in text.splitlines()[:_DETECT_LINES]:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("{"):
            try:
                message = json.loads(stripped)
            except ValueError:
                continue
            if isinstance(message, dict):
                return "frida"
            continue
        if stripped.startswith(_GDB_TRACE_MARKERS):
            return "gdb"
    return None


def _print_trace_report(report: TraceReport, *, auto_detected: bool) -> None:
    """Render a parsed trace as a per-function table, its totals and its warnings."""
    names: dict[int, str] = {}
    for hit in report.hits:
        if hit.function is not None:
            names.setdefault(hit.function, hit.function_name or "-")
    unattributed = sum(1 for hit in report.hits if hit.function is None)
    provider = f"{report.provider} (auto-detected)" if auto_detected else report.provider
    if report.function_coverage:
        table = Table(title=f"Trace hits by function ({len(report.function_coverage)})")
        table.add_column("Function")
        table.add_column("Address", justify="right")
        table.add_column("Hits", justify="right")
        for address, count in sorted(report.function_coverage.items()):
            table.add_row(escape(names.get(address, "-")), f"0x{address:x}", str(count))
        console.print(table)
    else:
        console.print("[yellow]no hit landed inside a discovered function[/]")
    console.print(
        f"[dim]provider: {escape(provider)} · hits: {report.total_hits}"
        f" · kept: {len(report.hits)} · unique addresses: {len(report.unique_addresses)}"
        f" · functions hit: {len(report.function_coverage)} · unattributed: {unattributed}"
        f" · truncated: {'yes' if report.truncated else 'no'}[/]"
    )
    if report.provider == "frida":
        console.print(
            "[dim]frida reports runtime addresses, so a hit is attributed to a function "
            "only when the image was not relocated[/]"
        )
    for warning in report.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")


@app.command()
def trace(
    path: Annotated[Path, typer.Argument(help="Path to the binary the session ran against")],
    trace_file: Annotated[
        Path,
        typer.Option(
            "--input", help="Saved session trace to parse (gdb output or frida JSON lines)"
        ),
    ],
    provider: Annotated[
        TraceProvider,
        typer.Option(
            "--provider", help="Trace format: gdb, frida, or auto to detect it from the file"
        ),
    ] = "auto",
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit TraceReport.to_dict() instead of a table")
    ] = False,
) -> None:
    """Replay a saved session trace and map its hits onto function candidates.

    Nothing here starts a debugger: ``--input`` is what a generated session
    script already printed, so a run can be re-read offline as often as needed.
    ``--provider auto`` reads the provider off the file shape -- a JSON object
    line is a Frida message, a ``HIT``/``BACKTRACE``/``LIMIT``/``DONE`` line is
    gdb -- and the render states which one it used; a file it cannot place exits
    2 instead of being guessed onto a provider.

    The table has one row per function that was hit: its name (``-`` when the
    candidate is unnamed), its start address, and how many hits landed inside it.
    The dim line under the table carries the totals -- hits seen, hits kept,
    unique addresses, functions hit, hits that fell outside every candidate, and
    whether the parse was cut -- and every dropped or malformed line keeps its
    own ``warning:`` line. ``--json`` prints ``TraceReport.to_dict()`` unchanged.
    """
    try:
        text = trace_file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        _fail(f"cannot read {trace_file}: {exc}", 2)
    auto_detected = provider == "auto"
    chosen = _detect_trace_provider(text) if auto_detected else provider
    if chosen is None:
        _fail(
            f"cannot tell whether {str(trace_file)!r} is a gdb or a frida trace; "
            "pass --provider gdb or --provider frida",
            2,
        )
    loaded = _load(path)
    functions = discover_functions(loaded)
    try:
        if chosen == "gdb":
            report = parse_gdb_trace(text, info=loaded, functions=functions)
        else:
            report = parse_frida_trace(text, info=loaded, functions=functions)
    except AnalysisError as exc:
        _fail(str(exc), 2)
    if json_output:
        console.print_json(json.dumps(report.to_dict()))
        return
    _print_trace_report(report, auto_detected=auto_detected)


@app.command()
def attach(
    path: Annotated[Path, typer.Argument(help="Path to the binary to instrument")],
    addresses: Annotated[
        list[str] | None,
        typer.Argument(
            help="Breakpoint/hook addresses (decimal or 0x hex); defaults to the entry point"
        ),
    ] = None,
    provider: Annotated[
        AttachProvider,
        typer.Option("--provider", help="Provider to generate a session script for: gdb or frida"),
    ] = "gdb",
    max_hits: Annotated[
        int, typer.Option("--max-hits", help="Stop the session after this many hits")
    ] = dynamic.DEFAULT_MAX_HITS,
    write: Annotated[
        Path | None,
        typer.Option("--write", help="Write the script into this directory (created if missing)"),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the script, its path and its command as JSON")
    ] = False,
) -> None:
    """Generate a session script and the exact command that runs it -- never run it.

    The script comes from :func:`codevanta.analysis.dynamic.build_gdb_script` or
    :func:`codevanta.analysis.dynamic.build_frida_script`, and the command from
    :func:`codevanta.analysis.dynamic.attach_command`, so neither is spelled out
    a second time here. ADDRESS is repeatable and defaults to the entry point;
    ``--max-hits`` bounds the session and the script states that bound.

    ``--write DIR`` creates the directory, saves the script under its fixed name
    (:data:`codevanta.analysis.dynamic.SCRIPT_FILE_NAMES`) and prints that path;
    without it the script text goes to stdout and nothing is written. In both
    cases the exact ``argv`` follows, and the dim line under it says what has to
    happen before that command is run. ``--json`` prints the script text, its
    path (``null`` when not written), the argv as a list and the probe.

    The provider is never launched: this command writes a file and prints a
    command line. A provider that cannot run here -- :func:`available_backends`
    decides that without executing anything -- exits 2 with its ``reason``
    rather than handing over a command line that would fail.
    """
    status = dynamic.provider_status(provider)
    if not status.available:
        _fail(f"{provider} is unavailable: {status.reason}", 2)
    loaded = _load(path)
    points = [_parse_address(text) for text in addresses or ()]
    try:
        if not points:
            points = [resolve_target(loaded, None, None)]
        if provider == "gdb":
            script = dynamic.build_gdb_script(path, loaded, points, max_hits=max_hits)
        else:
            script = dynamic.build_frida_script(path, loaded, points, max_hits=max_hits)
        argv = dynamic.attach_command(provider, path, script)
    except AnalysisError as exc:
        _fail(str(exc), 2)
    script_name = dynamic.script_file_name(provider)
    script_path: Path | None = None
    if write is not None:
        script_path = write / script_name
        try:
            write.mkdir(parents=True, exist_ok=True)
            script_path.write_text(script.text, encoding="utf-8", newline="\n")
        except OSError as exc:
            _fail(f"cannot write {script_path}: {exc}", 2)
    if json_output:
        console.print_json(
            json.dumps(
                {
                    "provider": provider,
                    "availability": status.to_dict(),
                    "script": script.to_dict(),
                    "script_path": None if script_path is None else str(script_path),
                    "attach_command": list(argv),
                    "addresses": [f"0x{address:x}" for address in points],
                    "max_hits": max_hits,
                }
            )
        )
        return
    if script_path is not None:
        console.print(f"[green]script written:[/] {escape(str(script_path))}")
    else:
        console.print(script.text, markup=False, soft_wrap=True)
    console.print(f"[bold]attach:[/] {escape(' '.join(argv))}")
    console.print(
        f"[dim]provider: {escape(provider)} · targets: {len(points)} · max hits: {max_hits}"
        f" · script: {escape(script_name)} · availability: {escape(status.reason)}[/]"
    )
    if script_path is not None:
        console.print(
            f"[dim]run the command above from {escape(str(script_path.parent))}, because the "
            "argv names the script by its fixed file name[/]"
        )
    else:
        console.print(
            "[dim]nothing was written: save the text above under that file name in the "
            "working directory, or pass --write DIR, before running the command[/]"
        )


# ---- phase 8 item 1: live debug session --------------------------------------


#: Actions ``codevanta debug`` performs at the stop, mirroring
#: :data:`codevanta.analysis.debug_session.DEBUG_ACTIONS`.
DebugAction = Literal[
    "registers", "memory", "backtrace", "continue", "step", "next", "quit"
]


def _print_debug_break(break_payload: dict) -> None:
    """Render the breakpoint entry plus the stop it produced."""
    info = break_payload
    breakpoint_info = info.get("breakpoint") or info
    location = (
        breakpoint_info.get("function") or breakpoint_info.get("address") or "pending"
    )
    console.print(
        f"[green]breakpoint {breakpoint_info.get('number')}[/] at {escape(str(location))}"
        + (" [yellow](pending)[/]" if breakpoint_info.get("pending") else "")
    )
    run = info.get("run") or {}
    stop = run.get("stop") or {}
    address = stop.get("address")
    rendered = f"0x{int(address, 16):x}" if isinstance(address, str) else "-"
    console.print(
        f"[dim]stopped: {escape(str(stop.get('reason', 'unknown')))} at {rendered}"
        f" · function: {escape(str(stop.get('function') or '-'))}[/]"
    )
    for warning in run.get("warnings", []):
        console.print(f"[yellow]warning:[/] {escape(str(warning))}")


def _print_debug_result(action: str, result: dict | None) -> None:
    """Render one debug action result as a table (or a line when there is none)."""
    if result is None:
        console.print(f"[dim]action {escape(action)}: nothing to report (launch/quit only)[/]")
        return
    if action == "registers":
        table = Table(title=escape(f"Registers ({result.get('count', 0)})"))
        table.add_column("#", justify="right")
        table.add_column("Register")
        table.add_column("Value", justify="right")
        for register in result.get("registers", []):
            table.add_row(
                str(register.get("number", "-")),
                escape(str(register.get("name", "-"))),
                escape(str(register.get("value")) if register.get("value") is not None else "-"),
            )
        console.print(table)
        if result.get("truncated"):
            console.print("[yellow]register list was truncated[/]")
    elif action == "backtrace":
        frames = result.get("frames", [])
        table = Table(title=escape(f"Backtrace ({len(frames)})"))
        table.add_column("Level", justify="right")
        table.add_column("Address", justify="right")
        table.add_column("Function")
        table.add_column("Source")
        for frame in frames:
            table.add_row(
                str(frame.get("level")) if frame.get("level") is not None else "-",
                str(frame.get("address") or "-"),
                escape(str(frame.get("function") or "-")),
                escape(str(frame.get("source") or "-")),
            )
        console.print(table)
        if result.get("truncated"):
            console.print("[yellow]backtrace was truncated at the requested frame budget[/]")
    elif action == "memory":
        console.print(
            f"[bold]memory at {escape(str(result.get('address')))}[/]: "
            f"{result.get('length')} of the requested {result.get('requested_length')} byte(s)"
        )
        contents = str(result.get("contents_hex", ""))
        for offset in range(0, len(contents), 64):
            console.print(f"  {contents[offset : offset + 64]}", markup=False, soft_wrap=True)
        if result.get("short_read"):
            console.print("[yellow]short read: fewer bytes came back than requested[/]")
    else:
        stop = result.get("stop", {})
        address = stop.get("address")
        rendered = f"0x{int(address, 16):x}" if isinstance(address, str) else "-"
        console.print(
            f"[bold]stopped:[/] {escape(str(stop.get('reason', 'unknown')))} at {rendered}"
            f" · function: {escape(str(stop.get('function') or '-'))}"
        )
    for warning in result.get("warnings", []):
        console.print(f"[yellow]warning:[/] {escape(str(warning))}")
    evidence = result.get("evidence") or {}
    console.print(
        f"[dim]evidence: {escape(str(evidence.get('source')))} via "
        f"{escape(str(evidence.get('method')))} · confidence: "
        f"{escape(str(evidence.get('confidence')))}[/]"
    )


@app.command()
def debug(
    target: Annotated[Path, typer.Argument(help="Path to the program gdb will load")],
    break_at: Annotated[
        str | None,
        typer.Option(
            "--break-at",
            help="Break here first: a function name or an address (0x401000); the target is run to it",
        ),
    ] = None,
    action: Annotated[
        DebugAction, typer.Option("--action", help="What to do at the stop")
    ] = "registers",
    address: Annotated[
        str | None,
        typer.Option(
            "--address", help="Virtual address the 'memory' action reads (decimal or 0x hex)"
        ),
    ] = None,
    length: Annotated[
        int, typer.Option("--length", help="Bytes the 'memory' action reads")
    ] = 64,
    max_frames: Annotated[
        int, typer.Option("--max-frames", help="Frame budget for the 'backtrace' action")
    ] = 20,
    timeout: Annotated[
        float, typer.Option("--timeout", help="Per-command wall-clock budget in seconds")
    ] = debug_session.DEFAULT_TIMEOUT,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the session payloads instead of a table")
    ] = False,
) -> None:
    """Run one LIVE gdb debug session: launch, break, inspect, verified exit.

    Unlike every other CODEVANTA command, this one executes the target -- inside
    a gdb machine-interface session this command owns. gdb is launched on TARGET
    (``--interpreter=mi2``), an optional ``--break-at`` location is inserted and
    the target is run to it, then ``--action`` is performed at the stop:
    ``registers`` (default), ``memory`` (needs ``--address`` and ``--length``),
    ``backtrace`` (bounded by ``--max-frames``), ``continue``, ``step``, ``next``
    or ``quit`` (launch and shut down only, the session smoke test). The
    debugger is always shut down again and the exit is verified.

    Every command runs under the ``--timeout`` budget; a session that misses it
    exits 2 saying so. A machine without gdb on PATH also exits 2 with the
    install hint -- never a traceback. Each result carries an ``evidence`` line
    naming the MI command that produced it: these are observations of one run,
    not static properties of the binary. ``--json`` prints the raw payloads.
    """
    parsed_address: int | None = None
    if address is not None:
        parsed_address = _parse_address(address, label="--address")
    try:
        payload = debug_session.run_debug(
            target,
            action=action,
            break_at=break_at,
            address=parsed_address,
            length=length,
            max_frames=max_frames,
            timeout=timeout,
        )
    except AnalysisError as exc:
        _fail(str(exc), 2)
    if json_output:
        console.print_json(json.dumps(payload))
        return
    status = debug_session.gdb_status()
    if payload.get("break") is not None:
        _print_debug_break(payload["break"])
    _print_debug_result(str(payload.get("action")), payload.get("result"))
    quit_payload = payload.get("quit") or {}
    verdict = "verified" if quit_payload.get("clean") else "FORCED"
    console.print(
        f"[dim]gdb session closed ({verdict}, exit code {quit_payload.get('exit_code')}) "
        f"· availability: {escape(status['reason'])}[/]"
    )
    for warning in quit_payload.get("warnings", []):
        console.print(f"[yellow]warning:[/] {escape(str(warning))}")


# ---- phase 7: path exploration and data flow --------------------------------


def _print_symbolic_exploration(result: PathExploration, overlay: SolverOverlay | None = None) -> None:
    """Print one :class:`PathExploration` as a path table plus its warnings.

    ``overlay`` is the optional z3-backed solver verdict; when it ran, pruned
    paths are left out of the table (each pruned path has its own warning)
    and the dim line grows a ``solver`` section.
    """
    pruned = set(overlay.pruned) if overlay is not None else set()
    table = Table(title=escape(f"Paths through 0x{result.address:x} ({result.paths})"))
    table.add_column("#", justify="right")
    table.add_column("Decisions")
    table.add_column("Return", justify="right")
    table.add_column("Stopped")
    table.add_column("Steps", justify="right")
    for entry in result.entries:
        if entry.index in pruned:
            continue
        decisions = " ".join(
            f"{branch.mnemonic}{'+' if branch.taken else '-'}" for branch in entry.decisions
        )
        if entry.seeded:
            decisions = f"{decisions} ({entry.seeded} seeded)"
        table.add_row(
            str(entry.index),
            decisions or "-",
            f"0x{entry.return_value:x}" if entry.return_value is not None else "-",
            entry.stopped_reason,
            str(entry.instructions),
        )
    console.print(table)
    summary = (
        f"[dim]explorer: {escape(result.explorer)} · arch: {escape(result.architecture)} "
        f"({result.bitness}-bit) · paths: {result.paths} · unresolved: {result.unresolved} · "
        f"steps: {result.steps} · complete: {'yes' if result.complete else 'no'}[/]"
    )
    if overlay is not None and overlay.ran:
        summary = (
            f"{summary[:-3]} · solver: z3 · checked: {overlay.checked} · "
            f"pruned: {len(overlay.pruned)} · solver ms: {overlay.solver_ms}[/]"
        )
    console.print(summary)
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")
    for entry in result.entries:
        for warning in entry.warnings:
            console.print(f"[yellow]warning:[/] [path {entry.index}] {escape(warning)}")
    if overlay is not None:
        for warning in overlay.warnings:
            console.print(f"[yellow]warning:[/] {escape(warning)}")


@app.command()
def symbolic(
    path: Annotated[Path, typer.Argument(help="Path to the binary to explore")],
    address: Annotated[
        str | None,
        typer.Argument(
            help="Virtual address to start at (decimal or 0x hex); defaults to the entry point"
        ),
    ] = None,
    max_paths: Annotated[
        int, typer.Option("--max-paths", help="Maximum paths to report")
    ] = SYMBOLIC_MAX_PATHS,
    max_steps: Annotated[
        int,
        typer.Option(
            "--max-steps", help="Instruction budget for the whole exploration, replays included"
        ),
    ] = SYMBOLIC_MAX_STEPS,
    solver_mode: Annotated[
        str,
        typer.Option(
            "--solver",
            help="Path feasibility checker: 'auto' uses z3 when importable, 'naive' never does",
        ),
    ] = "auto",
    set_values: Annotated[
        list[str] | None,
        typer.Option(
            "--set", help="Seed a register for every path, e.g. --set eax=42; repeatable"
        ),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit PathExploration.to_dict() instead of a table")
    ] = False,
) -> None:
    """Enumerate the paths through one function by replaying branch decisions.

    Exploration starts at ADDRESS, else the entry point, and walks the decision
    tree breadth first: every conditional branch met on the way is followed in
    the direction the emulated flags produced (``observed``) and the opposite
    direction is enqueued with its flags rewritten (``seeded`` -- an assumption
    about feasibility, not a solved constraint, and each such branch says so in
    a ``warning:`` line). Nothing is executed on the host: the file's bytes are
    copied onto a private CPU, exactly like ``codevanta emulate``.

    The table has one row per path: its number, the decisions as
    ``mnemonic+`` (taken) or ``mnemonic-`` (fell through) with a ``seeded``
    count when directions were forced, the value in ``rax``/``eax`` when the
    path reached a ``ret`` that left the function (``-`` otherwise), why it
    stopped (``return``, ``budget``, ``blocked`` or ``unmapped``) and how many
    instructions it executed. The dim line under it carries the explorer, the
    architecture, the totals and whether the exploration was complete; every
    degradation keeps its own ``warning:`` line, per path where applicable.
    ``--json`` prints ``PathExploration.to_dict()`` unchanged instead.

    ``--set REG=VALUE`` (repeatable, decimal or ``0x`` hex) seeds a register for
    every path before it runs, which is how an input reaches the code. A
    partial answer is never dressed up as a complete one: paths that ended
    without a return are counted in the ``unresolved`` total and explained.
    ``--max-paths`` and ``--max-steps`` bound the work; an out-of-range budget
    is rejected before anything runs. Exploration needs the optional ``unicorn``
    engine; when it is missing this exits 2 and never raises ``ImportError``.
    A bad address, a bad seed and an address outside an executable section all
    exit 2 as well.

    ``--solver`` adds the optional feasibility check behind the paths:
    ``auto`` (the default) hands every path's branch decisions to the z3
    BitVec solver when ``z3-solver`` is importable (``pip install z3-solver``),
    prunes the paths whose constraints cannot hold together with a ``warning:``
    line and reports the survivors with ``feasible``/``model``/``solver_ms``
    in the JSON payload; ``naive`` never touches a solver. Without z3 the
    command behaves exactly as before, plus one ``warning:`` line naming the
    naive evaluation; every solver call is time- and memory-bounded.
    """
    if not SYMBOLIC_EMULATOR_AVAILABLE:
        _fail(
            "path exploration is unavailable: "
            f"{emulator.emulator_status() or 'the unicorn engine could not be imported'}; "
            "install it with 'pip install unicorn' and retry",
            2,
        )
    registers = dict(_parse_register_assignment(text) for text in set_values or ())
    requested = None if address is None else _parse_address(address)
    loaded = _load(path)
    try:
        start = resolve_target(loaded, requested, None)
        result = explore_paths(
            path,
            loaded,
            start,
            max_paths=max_paths,
            max_steps=max_steps,
            initial_registers=registers,
        )
        overlay = solve_exploration(
            result, mode=solver_mode, timeout_ms=SOLVER_DEFAULT_TIMEOUT_MS
        )
    except AnalysisError as exc:
        _fail(str(exc), 2)
    if json_output:
        console.print_json(json.dumps(overlay.augmented_dict(result)))
        return
    _print_symbolic_exploration(result, overlay)


def _print_dataflow_summary(result: DataFlowSummary) -> None:
    """Print one :class:`DataFlowSummary` as a definition table plus footers."""
    table = Table(title=escape(f"Data flow at 0x{result.address:x}"))
    table.add_column("Address", justify="right")
    table.add_column("Register")
    table.add_column("Kind")
    table.add_column("Value", justify="right")
    table.add_column("Source")
    for definition in result.definitions:
        table.add_row(
            f"0x{definition.address:x}",
            escape(definition.register),
            escape(definition.kind),
            f"0x{definition.value:x}" if definition.value is not None else "-",
            escape(definition.source_register or "-"),
        )
    console.print(table)
    constants = " ".join(
        f"{name}=0x{value:x}" for name, value in sorted(result.constant_registers.items())
    )
    console.print(f"[dim]constant registers: {escape(constants or 'none')}[/]")
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")


@app.command()
def dataflow(
    path: Annotated[Path, typer.Argument(help="Path to the binary to analyse")],
    address: Annotated[
        str | None,
        typer.Argument(
            help="Virtual address to start at (decimal or 0x hex); defaults to the entry point"
        ),
    ] = None,
    max_instructions: Annotated[
        int,
        typer.Option("--max-instructions", help="Maximum instructions to decode"),
    ] = DATAFLOW_MAX_INSTRUCTIONS,
    max_blocks: Annotated[
        int, typer.Option("--max-blocks", help="Maximum basic blocks to walk")
    ] = DATAFLOW_MAX_BLOCKS,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit DataFlowSummary.to_dict() instead of a table")
    ] = False,
) -> None:
    """Recover register definitions, uses and provable constants of one function.

    The region starting at ADDRESS, else the entry point, is decoded and walked
    forward once, block by block in ascending address order: every read is
    resolved against the definitions seen so far and every register write
    replaces (kills) what the register held. A few shapes are folded -- the
    values a ``mov`` immediate, a register copy or an ``add``/``sub`` of known
    values leave behind -- and anything else keeps the register unknown rather
    than guessing.

    The table has one row per definition: its address, the canonical register
    (aliases such as ``eax`` are normalised), the shape (``const``, ``copy``,
    ``arithmetic`` or ``unknown``), the provable value (``-`` when none) and
    the source register of a copy. The dim line under it lists the constants
    still known after the pass (``none`` when nothing is provable), and every
    caveat -- undefined reads, a truncated CFG -- keeps its own ``warning:``
    line. ``--json`` prints ``DataFlowSummary.to_dict()`` unchanged instead,
    which adds the uses, the reaching definitions and the evidence.

    ``--max-instructions`` and ``--max-blocks`` bound the work; an out-of-range
    budget, a bad address and an address outside an executable section all
    exit 2. The target binary is only ever read: this is a static pass.
    """
    requested = None if address is None else _parse_address(address)
    loaded = _load(path)
    try:
        start = resolve_target(loaded, requested, None)
        result = analyze_dataflow(
            path,
            loaded,
            start,
            max_instructions=max_instructions,
            max_blocks=max_blocks,
        )
    except AnalysisError as exc:
        _fail(str(exc), 2)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    _print_dataflow_summary(result)


# ---- phase 7: analysis plugins ----------------------------------------------


plugins_app = typer.Typer(help="Analysis plugin commands")
app.add_typer(plugins_app, name="plugins")
app.add_typer(containers_app)
app.add_typer(crash_app, name="crash")
app.add_typer(mobile_app, name="mobile")
app.add_typer(web_app, name="web")
app.command("asar", help="List an Electron ASAR archive; optionally extract one entry")(asar)


@plugins_app.command("list")
def plugins_list(
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the plugin descriptions as JSON")
    ] = False,
) -> None:
    """List the analysis plugins this process can run with ``plugins run``.

    The list is the live built-in registry, sorted by name. ``--json`` prints
    one ``PluginInfo.to_dict()`` per plugin instead of a table.
    """
    infos = builtin_plugins()
    if json_output:
        console.print_json(json.dumps([info.to_dict() for info in infos]))
        return
    table = Table(title=escape(f"Analysis plugins ({len(infos)})"))
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Kind")
    table.add_column("Entry point")
    table.add_column("Description")
    for info in infos:
        table.add_row(
            escape(info.name),
            escape(info.version),
            escape(info.kind),
            escape(info.entry_point or "-"),
            escape(info.description or "-"),
        )
    console.print(table)


@plugins_app.command("run")
def plugins_run(
    name: Annotated[
        str, typer.Argument(help="Plugin name, as shown by 'codevanta plugins list'")
    ],
    path: Annotated[Path, typer.Argument(help="Path to the binary to analyse")],
    address: Annotated[
        str | None,
        typer.Argument(
            help="Focus address for the run (decimal or 0x hex); defaults to the entry point"
        ),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit PluginResult.to_dict() instead of a table")
    ] = False,
) -> None:
    """Run one analysis plugin over a binary under the plugin harness budget.

    The plugin is resolved from the built-in registry first; a name no registry
    or entry point declares exits 2 with an error that names it. The run gets
    an :class:`~codevanta.plugins.AnalysisContext` built from the loaded binary
    and its discovered function candidates, focused at ADDRESS, else the entry
    point, and the harness bounds the run by wall-clock time and payload size
    -- a plugin that overruns either budget exits 2.

    The table prints the returned payload as ``key = value`` rows (nested
    values as JSON), the dim line under it names the plugin, its version, its
    kind and the measured run time, and warnings the payload declares keep
    their own ``warning:`` lines. ``--json`` prints
    ``PluginResult.to_dict()`` unchanged instead.
    """
    requested = None if address is None else _parse_address(address)
    loaded = _load(path)
    try:
        plugin = load_plugin(name=name)
        start = resolve_target(loaded, requested, None)
        context = AnalysisContext(
            path=path,
            info=loaded,
            address=start,
            functions=tuple(discover_functions(loaded)),
        )
        result = run_plugin(plugin, context)
    except AnalysisError as exc:
        _fail(str(exc), 2)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    table = Table(title=escape(f"Plugin {result.plugin.name}"))
    table.add_column("Key")
    table.add_column("Value")
    for key, value in sorted(result.payload.items()):
        text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
        table.add_row(escape(str(key)), escape(text))
    console.print(table)
    console.print(
        f"[dim]plugin: {escape(result.plugin.name)} · version: "
        f"{escape(result.plugin.version)} · kind: {escape(result.plugin.kind)} · "
        f"{result.elapsed_ms:.1f} ms[/]"
    )
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")


# ---- phase 7: evidence bundles ----------------------------------------------


def _parse_entry_assignment(text: str) -> tuple[str, str]:
    """Parse one ``NAME=FILEPATH`` payload given through ``--entry``.

    The name and the file side must both be non-empty; a missing ``=`` or a
    blank half exits with code 2 instead of bundling a wrong payload.
    """
    name, separator, file_text = text.partition("=")
    name = name.strip()
    file_text = file_text.strip()
    if not separator or not name or not file_text:
        _fail(f"invalid --entry {text!r}; use NAME=FILEPATH, e.g. --entry cfg=report.json", 2)
    return name, file_text


def _read_entry_payload(name: str, file_text: str) -> Any:
    """Read one ``--entry`` payload file and parse it as JSON."""
    payload_path = Path(file_text)
    try:
        text = payload_path.read_text(encoding="utf-8")
    except OSError as exc:
        _fail(f"cannot read entry {name!r} from {payload_path}: {exc}", 2)
    except UnicodeDecodeError as exc:
        _fail(f"entry {name!r} is not UTF-8 text ({exc})", 2)
    try:
        return json.loads(text)
    except ValueError as exc:
        _fail(f"entry {name!r} is not valid JSON ({exc})", 2)


@app.command("evidence-bundle")
def evidence_bundle(
    path: Annotated[Path, typer.Argument(help="Path to the analysed binary")],
    entries: Annotated[
        list[str],
        typer.Option(
            "--entry",
            help="Bundle one payload, NAME=FILEPATH (a JSON file); repeatable, at least once",
        ),
    ],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write the bundle document here")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Also print the bundle document to stdout")
    ] = False,
) -> None:
    """Hash one binary and its analysis payloads into a tamper-evident bundle.

    Every ``--entry`` names one payload: ``NAME`` is the entry name in the
    bundle (at least one entry is required; a repeated name is refused) and
    ``FILEPATH`` is a JSON file whose parsed document becomes the payload. The
    subject binary is streamed through SHA-256 and every payload is reduced to
    canonical JSON before it is hashed, so a verifier can recompute both
    digests from the document alone -- ``verify_bundle`` reports any later
    edit as a mismatch.

    The bundle is written to ``--output`` as canonical JSON. Writing it *into*
    the analysed path is refused: ``--output`` must not name the analysed
    binary itself (nor anything under it, when the subject is a directory),
    because a bundle that overwrites its own subject destroys the evidence it
    pins. Missing or unreadable entry files, non-JSON payloads and unwritable
    outputs all exit 2, and a bundle is never written partially.

    The success line names the written path, the entry count and the subject
    digest. ``--json`` additionally prints the exact document to stdout.
    """
    payloads: dict[str, Any] = {}
    for text in entries:
        name, file_text = _parse_entry_assignment(text)
        if name in payloads:
            _fail(f"duplicate --entry name {name!r}; entry names must be unique", 2)
        payloads[name] = _read_entry_payload(name, file_text)
    subject = path.resolve()
    target = output.resolve()
    if subject.is_dir():
        if target == subject or subject in target.parents:
            _fail(
                f"--output {str(output)!r} is inside the analysed directory {str(path)!r}; "
                "write the bundle somewhere else",
                2,
            )
    elif target == subject:
        _fail(f"--output {str(output)!r} would overwrite the analysed binary {str(path)!r}", 2)
    try:
        bundle = build_bundle(path, payloads)
        written = write_bundle(bundle, output)
    except AnalysisError as exc:
        _fail(str(exc), 2)
    console.print(
        f"[green]bundle written:[/] {escape(str(written))} · entries: {len(payloads)} "
        f"· subject sha256: {escape(bundle.manifest.subject_sha256)}"
    )
    if json_output:
        console.print(dumps_bundle(bundle), markup=False, soft_wrap=True)


mcp_app = typer.Typer(help="Model Context Protocol server commands")
app.add_typer(mcp_app, name="mcp")


@mcp_app.command("serve")
def mcp_serve(
    transport: Annotated[
        str,
        typer.Option(
            "--transport",
            help="stdio (default), sse or streamable-http",
        ),
    ] = "stdio",
    host: Annotated[
        str,
        typer.Option("--host", help="Bind address for the HTTP transports"),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", help="Bind port for the HTTP transports; 0 picks a free one"),
    ] = 8000,
    allow_remote: Annotated[
        bool,
        typer.Option("--allow-remote", help="Permit a non-loopback bind address"),
    ] = False,
) -> None:
    """Serve CODEVANTA tools to coding agents over MCP (stdio or HTTP)."""
    try:
        from codevanta.mcp_server.server import run as run_server
    except ImportError as exc:  # pragma: no cover - dependency guard
        console.print(f"[bold red]error:[/] MCP support needs the 'mcp' package: {exc}")
        raise typer.Exit(code=2) from exc
    try:
        run_server(transport=transport, host=host, port=port, allow_remote=allow_remote)
    except (AnalysisError, ValueError) as exc:
        _fail(str(exc), 2)
    except OSError as exc:
        _fail(f"could not bind {host}:{port}: {exc}", 2)
    except SystemExit as exc:
        # uvicorn reports an unusable address by calling ``sys.exit`` from inside
        # the SDK's event loop, so a taken port arrives here as ``SystemExit``
        # (verified with the pinned mcp/uvicorn: code 3) and would otherwise
        # leave the process with exit 3 and raw uvicorn output. Exit 0 is a
        # clean shutdown and is re-raised untouched.
        if _system_exit_status(exc) == 0:
            raise
        _fail(f"could not bind {host}:{port}", 2)


@app.command()
def gui(
    host: Annotated[
        str,
        typer.Option("--host", help="Loopback address to bind (127.0.0.1, localhost or ::1)"),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", help="TCP port to listen on; 0 picks a free one"),
    ] = 8765,
    no_browser: Annotated[
        bool,
        typer.Option("--no-browser", help="Do not open a browser window"),
    ] = False,
) -> None:
    """Serve the local web dashboard (read-only, loopback only)."""
    if port < 0 or port > 65535:
        _fail(f"port must be within 0 .. 65535, got {port}", 2)
    try:
        from codevanta.gui import serve as serve_gui
    except ImportError as exc:  # pragma: no cover - packaging guard
        console.print(f"[bold red]error:[/] the web dashboard is unavailable: {exc}")
        raise typer.Exit(code=2) from exc
    try:
        serve_gui(host=host, port=port, open_browser=not no_browser)
    except OSError as exc:
        # ``http.server`` raises ``OSError`` (``PermissionError`` for WSAEACCES on
        # Windows) for a taken port, never ``SystemExit``, so this is the bind
        # failure path for the dashboard; the message names the address.
        _fail(f"could not bind {host}:{port}: {exc}", 2)
    except ValueError as exc:
        _fail(str(exc), 2)


def _render_plan(plan) -> None:
    lines = list(plan.notes)
    for change in plan.changes:
        lines.append(f"{change.action}: {change.path}")
        if change.diff:
            lines.append(change.diff)
    title = f"setup plan · {plan.client} · {plan.scope}"
    console.print(Panel("\n".join(lines), title=escape(title)))


def _adapters_for(ctx, names: list[str] | None):
    from codevanta.setup.clients import SetupError, detected_clients, get_client

    try:
        if names:
            return [get_client(name) for name in names]
        return detected_clients(ctx)
    except SetupError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2) from exc


def _print_client_status(ctx) -> None:
    from codevanta.setup.clients import describe_clients

    table = Table(title="Coding agent MCP status")
    table.add_column("Client")
    table.add_column("Scope")
    table.add_column("Status")
    table.add_column("Config path")
    for row in describe_clients(ctx):
        status_style = "green" if row["status"] == "registered" else "yellow"
        table.add_row(
            escape(row["client"]),
            row["scope"],
            f"[{status_style}]{escape(row['status'])}[/]",
            escape(row["path"]),
        )
    console.print(table)


@app.command()
def setup(
    client: Annotated[
        list[str] | None,
        typer.Option("--client", "-c", help="claude, cursor, cline, vscode (default: detected)"),
    ] = None,
    scope: Annotated[str, typer.Option(help="user or project")] = "user",
    project: Annotated[
        Path | None, typer.Option(help="Project directory for project scope")
    ] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show the plan only")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Apply without confirmation")] = False,
    verify: Annotated[bool, typer.Option("--verify", help="Verify after applying")] = False,
    list_clients: Annotated[
        bool, typer.Option("--list", help="Show configuration status for every client and exit")
    ] = False,
) -> None:
    """Register CODEVANTA as an MCP server for coding agents."""
    from codevanta.setup.apply import apply_plan
    from codevanta.setup.clients import SetupContext, SetupError
    from codevanta.setup.verify import verify_entry, verify_tools

    ctx = SetupContext.from_environment(project)
    if list_clients:
        _print_client_status(ctx)
        return
    adapters = _adapters_for(ctx, client)
    if not adapters:
        console.print("[yellow]no coding agents detected[/]; pass --client claude|cursor|cline|vscode")
        raise typer.Exit(code=3)
    try:
        plans = [adapter.plan(ctx, scope) for adapter in adapters]
    except SetupError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2) from exc
    for plan in plans:
        _render_plan(plan)
    if dry_run:
        console.print("[dim]dry run: nothing was written[/]")
        return
    if any(plan.has_changes for plan in plans):
        if not yes and not typer.confirm("Apply this setup plan?", default=False):
            console.print("[yellow]cancelled[/]")
            return
        for plan in plans:
            for path in apply_plan(plan):
                console.print(f"[green]updated[/] {path}")
    else:
        console.print("[green]already configured[/]")
    if verify:
        results = [verify_entry(adapter, ctx, scope) for adapter in adapters]
        results.append(verify_tools())
        for result in results:
            marker = "[green]ok[/]" if result["ok"] else "[red]fail[/]"
            console.print(f"{marker} {escape(str(result))}")
        if not all(result["ok"] for result in results):
            raise typer.Exit(code=4)


@app.command()
def uninstall(
    client: Annotated[
        list[str] | None, typer.Option("--client", "-c", help="claude, cursor, cline, vscode")
    ] = None,
    scope: Annotated[str, typer.Option(help="user or project")] = "user",
    project: Annotated[
        Path | None, typer.Option(help="Project directory for project scope")
    ] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Apply without confirmation")] = False,
) -> None:
    """Remove CODEVANTA from coding-agent MCP settings."""
    from codevanta.setup.apply import apply_plan
    from codevanta.setup.clients import SetupContext, SetupError

    ctx = SetupContext.from_environment(project)
    adapters = _adapters_for(ctx, client)
    if not adapters:
        console.print("[yellow]no coding agents detected[/]; pass --client claude|cursor|cline|vscode")
        raise typer.Exit(code=3)
    try:
        plans = [adapter.removal_plan(ctx, scope) for adapter in adapters]
    except SetupError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2) from exc
    for plan in plans:
        _render_plan(plan)
    if not any(plan.has_changes for plan in plans):
        console.print("[green]nothing to remove[/]")
        return
    if not yes and not typer.confirm("Apply this removal plan?", default=False):
        console.print("[yellow]cancelled[/]")
        return
    for plan in plans:
        for path in apply_plan(plan):
            console.print(f"[green]updated[/] {path}")


session_app = typer.Typer(help="Persisted analysis sessions (SQLite)")
app.add_typer(session_app, name="session")
app.add_typer(meta_app, name="metadata")


@session_app.command("save")
def session_save(
    path: Path,
    db: Annotated[Path | None, typer.Option("--db", help="Session database file")] = None,
    notes: Annotated[str | None, typer.Option("--notes", help="Note stored with the session")] = None,
) -> None:
    """Analyze PATH and persist the counts as a new session."""
    loaded = _load(path)
    try:
        functions_count = len(discover_functions(loaded))
        strings_count = len(StringExtractor(min_length=4).extract(path, info=loaded))
        with SessionStore(_session_db(db)) as store:
            record = store.save(loaded, functions_count, strings_count, notes=notes)
    except SessionError as exc:
        _fail(str(exc), 2)
    console.print(f"[green]session saved:[/] {escape(record.session_id)}")
    console.print(f"[dim]{escape(str(record.binary_path))}[/]")
    console.print(
        f"[dim]functions: {record.functions} · strings: {record.strings}"
        f" · db: {escape(str(_session_db(db)))}[/]"
    )


def _print_sessions(records: list[SessionRecord]) -> None:
    table = Table(title=f"Sessions ({len(records)})")
    table.add_column("Id")
    table.add_column("Created")
    table.add_column("Format")
    table.add_column("Arch")
    table.add_column("Functions", justify="right")
    table.add_column("Strings", justify="right")
    table.add_column("Path")
    for record in records:
        table.add_row(
            escape(record.session_id),
            escape(record.created_at),
            escape(record.format),
            escape(record.architecture),
            str(record.functions),
            str(record.strings),
            escape(record.binary_path),
        )
    console.print(table)


@session_app.command("list")
def session_list(
    db: Annotated[Path | None, typer.Option("--db", help="Session database file")] = None,
    limit: Annotated[int, typer.Option(help="Maximum sessions to display")] = 20,
) -> None:
    """List stored sessions, newest first."""
    if limit < 1:
        _fail("--limit must be >= 1", 2)
    try:
        with SessionStore(_session_db(db)) as store:
            records = store.list(limit=limit)
    except SessionError as exc:
        _fail(str(exc), 2)
    if not records:
        console.print("[yellow]no sessions stored[/]")
        return
    _print_sessions(records)


@session_app.command("show")
def session_show(
    session_id: str,
    db: Annotated[Path | None, typer.Option("--db", help="Session database file")] = None,
) -> None:
    """Show one stored session as a key/value panel."""
    try:
        with SessionStore(_session_db(db)) as store:
            record = store.get(session_id)
    except SessionError as exc:
        _fail(str(exc), 2)
    if record is None:
        _fail(f"session {session_id!r} not found", 2)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan")
    grid.add_column()
    rows = [
        ("Session", record.session_id),
        ("Created", record.created_at),
        ("Path", record.binary_path),
        ("Format", record.format),
        ("Architecture", record.architecture),
        ("Bitness", str(record.bitness)),
        (
            "Entry point",
            f"0x{record.entry_point:x}" if record.entry_point is not None else "-",
        ),
        ("SHA-256", record.sha256),
        ("Functions", str(record.functions)),
        ("Strings", str(record.strings)),
        ("Notes", record.notes or "-"),
    ]
    for key, value in rows:
        grid.add_row(key, escape(value))
    console.print(Panel(grid, title="CODEVANTA · session", subtitle=escape(record.session_id)))


def _parse_address(text: str, *, label: str = "address") -> int:
    """Parse an address given on the command line.

    ``int(text, 0)`` is used so decimal (``4198400``), hexadecimal (``0x401000``),
    octal (``0o...``) and binary (``0b...``) literals are all accepted. Anything
    that does not parse, or parses to a negative value, exits with code 2.

    ``label`` only names the value in those error messages, so ``--base`` can
    report ``invalid base ...`` while every other address keeps its own wording.
    """
    try:
        address = int(text, 0)
    except ValueError:
        _fail(f"invalid {label} {text!r}; use decimal or 0x-prefixed hex", 2)
    if address < 0:
        _fail(f"invalid {label} {text!r}; addresses must not be negative", 2)
    return address


@session_app.command("annotate")
def session_annotate(
    session_id: str,
    address: str,
    note: str,
    db: Annotated[Path | None, typer.Option("--db", help="Session database file")] = None,
) -> None:
    """Attach NOTE to ADDRESS (decimal or 0x hex) inside a stored session."""
    parsed = _parse_address(address)
    try:
        with SessionStore(_session_db(db)) as store:
            annotation = store.annotate(session_id, parsed, note)
    except SessionError as exc:
        _fail(str(exc), 2)
    console.print(
        f"[green]annotation saved:[/] {escape(annotation.session_id)}"
        f" · 0x{annotation.address:x}"
    )
    console.print(f"[dim]{escape(annotation.note)} · {escape(annotation.created_at)}[/]")


@session_app.command("notes")
def session_notes(
    session_id: str,
    db: Annotated[Path | None, typer.Option("--db", help="Session database file")] = None,
) -> None:
    """List the annotations stored for one session, lowest address first."""
    try:
        with SessionStore(_session_db(db)) as store:
            annotations = store.annotations(session_id)
    except SessionError as exc:
        _fail(str(exc), 2)
    if not annotations:
        console.print(f"[yellow]no notes for session {escape(session_id)}[/]")
        return
    table = Table(title=escape(f"Notes ({len(annotations)})"))
    table.add_column("Address", justify="right")
    table.add_column("Note")
    table.add_column("Created")
    for annotation in annotations:
        table.add_row(
            f"0x{annotation.address:x}",
            escape(annotation.note),
            escape(annotation.created_at),
        )
    console.print(table)


# ---- phase 8: typed comparators and the residual-unknown ledger --------------

#: ``bundles`` is the documented extra beyond the required ``functions`` and
#: ``strings``: it reaches :func:`compare_bundles` offline as well.
CompareWhat = Literal["functions", "strings", "bundles"]
CompareFormat = Literal["text", "json"]

UnknownsAction = Literal["list", "open", "resolve"]
UnknownsStatus = Literal["open", "resolved"]
UnknownsSeverity = Literal["low", "medium", "high"]
UnknownsFormat = Literal["text", "json"]


def _print_inventory_compare(result: Any) -> None:
    """Render an :class:`InventoryCompare` result as text tables."""
    if result.matched_by_name:
        table = Table(title="Matched by name (heuristic)")
        table.add_column("Name")
        table.add_column("Left")
        table.add_column("Right")
        table.add_column("Address changed", justify="center")
        for match in result.matched_by_name:
            table.add_row(
                escape(match.name),
                escape(match.left_address or "-"),
                escape(match.right_address or "-"),
                "yes" if match.address_changed else "no",
            )
        console.print(table)
    if result.matched_by_fingerprint:
        table = Table(title="Matched by fingerprint")
        table.add_column("Digest")
        table.add_column("Left")
        table.add_column("Right")
        for match in result.matched_by_fingerprint:
            table.add_row(
                escape(f"{match.digest[:12]}..."),
                escape(f"{match.left_name or '-'} {match.left_address or ''}".strip()),
                escape(f"{match.right_name or '-'} {match.right_address or ''}".strip()),
            )
        console.print(table)
    for title, entries in (("Added", result.added), ("Removed", result.removed)):
        label = f"{title} (right-only)" if title == "Added" else f"{title} (left-only)"
        table = Table(title=label)
        table.add_column("Name")
        table.add_column("Address")
        for entry in entries:
            table.add_row(escape(entry.name or "-"), escape(entry.address or "-"))
        console.print(table)
    console.print(
        f"[dim]left functions: {result.left_functions}"
        f" · right functions: {result.right_functions}"
        f" · added: {len(result.added)}"
        f" · removed: {len(result.removed)}"
        f" · by name: {len(result.matched_by_name)}"
        f" · by fingerprint: {len(result.matched_by_fingerprint)}[/]"
    )


def _print_strings_compare(result: Any) -> None:
    """Render a :class:`StringsCompare` result as text tables."""
    for title, texts in (("Added strings", result.added), ("Removed strings", result.removed)):
        table = Table(title=title)
        table.add_column("Text")
        for text in texts:
            table.add_row(escape(text))
        console.print(table)
    console.print(
        f"[dim]left strings: {result.left_strings}"
        f" · right strings: {result.right_strings}"
        f" · added: {len(result.added)}"
        f" · removed: {len(result.removed)}"
        f" · shared: {result.shared_count}[/]"
    )


def _print_bundle_compare(result: Any) -> None:
    """Render a :class:`BundleCompare` result as text tables."""
    if result.changed:
        table = Table(title="Changed entries (digest mismatch)")
        table.add_column("Entry")
        table.add_column("Left sha256")
        table.add_column("Right sha256")
        for change in result.changed:
            table.add_row(
                escape(change.name),
                escape(change.left_sha256 or "-"),
                escape(change.right_sha256 or "-"),
            )
        console.print(table)
    console.print(
        f"[dim]left entries: {result.left_entries}"
        f" · right entries: {result.right_entries}"
        f" · added: {len(result.added_names)}"
        f" · removed: {len(result.removed_names)}"
        f" · changed: {len(result.changed)}"
        f" · unchanged: {len(result.unchanged_names)}"
        f" · shared digests: {result.shared_digest_count}[/]"
    )


def _print_compare_warnings(result: Any) -> None:
    """Print warnings and the evidence footer shared by compare results."""
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")
    evidence = result.evidence
    console.print(
        f"[dim]evidence: {escape(str(evidence.get('source', '-')))}"
        f" · {escape(str(evidence.get('method', '-')))}"
        f" · confidence: {escape(str(evidence.get('confidence', '-')))}[/]"
    )


@app.command("compare")
def compare(
    a: Annotated[
        Path,
        typer.Argument(help="Left artifact: an analyze report or evidence bundle (JSON)"),
    ],
    b: Annotated[
        Path,
        typer.Argument(help="Right artifact: an analyze report or evidence bundle (JSON)"),
    ],
    what: Annotated[
        CompareWhat,
        typer.Option("--what", help="Which sections to compare"),
    ] = "functions",
    output_format: Annotated[
        CompareFormat, typer.Option("--format", "-f", help="Output format")
    ] = "text",
    max_functions: Annotated[
        int,
        typer.Option("--max-functions", help="Per-side function inventory budget"),
    ] = COMPARE_MAX_FUNCTIONS,
    max_strings: Annotated[
        int,
        typer.Option("--max-strings", help="Unique string texts kept per delta"),
    ] = COMPARE_MAX_STRINGS,
) -> None:
    """Compare two offline JSON artifacts (never loads a binary).

    The arguments are ``codevanta analyze`` report payloads, e.g.
    ``samples/report_elf64.json`` and ``samples/report_bundle.json`` (a bundle
    is unwrapped to its ``report`` entry automatically), so the comparison is
    reproducible from the documents alone.
    """
    if what not in COMPARE_WHATS:
        _fail(f"invalid --what {what!r}; expected one of {', '.join(COMPARE_WHATS)}", 2)
    result: Any
    try:
        if what == "functions":
            result = compare_inventories(
                load_report_payload(a),
                load_report_payload(b),
                max_functions=max_functions,
            )
        elif what == "strings":
            result = compare_strings(
                load_report_payload(a),
                load_report_payload(b),
                max_strings=max_strings,
            )
        else:
            result = compare_bundles(load_document(a), load_document(b))
    except AnalysisError as exc:
        _fail(str(exc), 2)
    if output_format == "json":
        console.print_json(json.dumps(result.to_dict()))
        return
    if what == "functions":
        _print_inventory_compare(result)
    elif what == "strings":
        _print_strings_compare(result)
    else:
        _print_bundle_compare(result)
    _print_compare_warnings(result)


def _load_unknowns_ledger(path: Path) -> dict[str, Any]:
    """Load an unknowns ledger payload, unwrapping a bundle document if needed."""
    document = load_document(path)
    if is_bundle_document(document):
        entry = document["entries"].get("unknowns")
        if not isinstance(entry, dict) or not isinstance(entry.get("payload"), dict):
            raise AnalysisError(f"{path} is a bundle without an 'unknowns' entry")
        document = entry["payload"]
    return document


def _write_unknowns_ledger(path: Path, payload: dict[str, Any]) -> None:
    """Write a ledger payload as canonical JSON (sorted keys, trailing newline)."""
    try:
        path.write_text(
            json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except OSError as exc:
        _fail(f"cannot write ledger {path}: {exc}", 2)


@app.command("unknowns")
def unknowns(
    action: Annotated[
        UnknownsAction,
        typer.Argument(help="list: show records · open: add a record · resolve: close one"),
    ],
    ledger: Annotated[
        Path, typer.Argument(help="Ledger JSON file (or a bundle carrying an 'unknowns' entry)")
    ],
    unknown_id: Annotated[
        str | None, typer.Option("--id", help="Record id to resolve (resolve)")
    ] = None,
    domain: Annotated[
        str | None, typer.Option("--domain", help="Domain tag, e.g. cfg (open)")
    ] = None,
    summary: Annotated[
        str | None, typer.Option("--summary", help="One-line description (open)")
    ] = None,
    severity: Annotated[
        UnknownsSeverity, typer.Option("--severity", help="Record severity (open)")
    ] = DEFAULT_UNKNOWN_SEVERITY,
    evidence: Annotated[
        list[str] | None,
        typer.Option("--evidence", help="Evidence reference; repeatable (open)"),
    ] = None,
    note: Annotated[
        str | None, typer.Option("--note", help="Resolution note (resolve)")
    ] = None,
    status: Annotated[
        UnknownsStatus | None, typer.Option("--status", help="Filter by status (list)")
    ] = None,
    output_format: Annotated[
        UnknownsFormat, typer.Option("--format", "-f", help="Output format")
    ] = "text",
) -> None:
    """Manage the residual-unknown ledger (typed open/resolved records).

    A ledger file is the JSON payload ``{"count": N, "items": [...]}``; ids are
    deterministic content digests, so opening the same finding twice is
    reported as a duplicate instead of silently growing the ledger.
    """
    if status is not None and status not in UNKNOWN_STATUSES:
        _fail(f"invalid --status {status!r}; expected one of {', '.join(UNKNOWN_STATUSES)}", 2)

    if action == "list":
        try:
            records = records_from_payload(_load_unknowns_ledger(ledger))
        except AnalysisError as exc:
            _fail(str(exc), 2)
        if status is not None:
            records = tuple(record for record in records if record.status == status)
        if output_format == "json":
            console.print_json(json.dumps(records_to_payload(list(records))))
            return
        table = Table(title=f"Unknowns ({len(records)} records)")
        table.add_column("Id")
        table.add_column("Status")
        table.add_column("Severity", justify="center")
        table.add_column("Domain")
        table.add_column("Summary")
        table.add_column("Refs", justify="right")
        for record in records:
            table.add_row(
                escape(record.id),
                escape(record.status),
                escape(record.severity),
                escape(record.domain),
                escape(record.summary),
                str(len(record.evidence_refs)),
            )
        console.print(table)
        open_count = sum(1 for record in records if record.status == "open")
        console.print(f"[dim]records: {len(records)} · open: {open_count}[/]")
        return

    if action == "open":
        if not domain or not summary:
            _fail("opening an unknown requires --domain and --summary", 2)
        existing: list[Any] = []
        if ledger.exists():
            try:
                existing = list(records_from_payload(_load_unknowns_ledger(ledger)))
            except AnalysisError as exc:
                _fail(str(exc), 2)
        try:
            record = make_open_unknown(
                domain=domain,
                summary=summary,
                severity=severity,
                evidence_refs=tuple(evidence or ()),
            )
            payload = records_to_payload([*existing, record])
        except AnalysisError as exc:
            _fail(str(exc), 2)
        _write_unknowns_ledger(ledger, payload)
        if output_format == "json":
            console.print_json(json.dumps({"action": "open", "record": record.to_dict()}))
        else:
            console.print(
                f"[green]unknown opened:[/] {escape(record.id)} · "
                f"domain: {escape(record.domain)} · severity: {record.severity}"
            )
        return

    # action == "resolve"
    if not unknown_id:
        _fail("resolving an unknown requires --id", 2)
    try:
        payload = resolve_unknowns(
            _load_unknowns_ledger(ledger),
            [unknown_id],
            note=note or "",
        )
    except AnalysisError as exc:
        _fail(str(exc), 2)
    _write_unknowns_ledger(ledger, payload)
    if output_format == "json":
        console.print_json(json.dumps({"action": "resolve", "resolved": unknown_id}))
    else:
        console.print(f"[green]unknown resolved:[/] {escape(unknown_id)}")


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    main()

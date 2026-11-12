"""CODEVANTA command line interface."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from codevanta.analysis.cfg import FunctionCFG, build_cfg
from codevanta.analysis.xrefs import DEFAULT_MAX_BYTES, find_xrefs
from codevanta.core.functions import discover_functions
from codevanta.core.loader import BinaryInfo, BinaryLoader, BinaryLoadError
from codevanta.core.report import AnalysisError, build_report, disassemble_region, resolve_target
from codevanta.core.strings import StringExtractor
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


def _fail(message: str, code: int) -> None:
    """Print an error and exit with ``code``."""
    console.print(f"[bold red]error:[/] {escape(message)}")
    raise typer.Exit(code=code)


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
) -> None:
    """Run the phase 1 analysis and emit a JSON report."""
    try:
        report = build_report(path, string_limit=string_limit)
    except (AnalysisError, BinaryLoadError) as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2) from exc
    payload = json.dumps(report, indent=2)
    if output is not None:
        output.write_text(payload, encoding="utf-8")
        console.print(f"[green]report written:[/] {output}")
        return
    console.print_json(payload)


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
        int, typer.Option("--max-instructions", help="Instruction budget for the linear sweep")
    ] = 2000,
    max_blocks: Annotated[
        int, typer.Option("--max-blocks", help="Maximum basic blocks reported")
    ] = 500,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of a table")
    ] = False,
) -> None:
    """Build a control-flow graph for the entry point, an address, or a function."""
    loaded = _load(path)
    try:
        start = resolve_target(loaded, address, function)
    except AnalysisError as exc:
        _fail(str(exc), 4)
    try:
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


mcp_app = typer.Typer(help="Model Context Protocol server commands")
app.add_typer(mcp_app, name="mcp")


@mcp_app.command("serve")
def mcp_serve() -> None:
    """Serve CODEVANTA tools to coding agents over MCP (stdio)."""
    try:
        from codevanta.mcp_server.server import run as run_server
    except ImportError as exc:  # pragma: no cover - dependency guard
        console.print(f"[bold red]error:[/] MCP support needs the 'mcp' package: {exc}")
        raise typer.Exit(code=2) from exc
    run_server()


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


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    main()



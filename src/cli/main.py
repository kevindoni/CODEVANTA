"""CODEVANTA command line interface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from core.disassembler import Disassembler, DisassemblyError
from core.functions import discover_functions
from core.loader import BinaryInfo, BinaryLoader, BinaryLoadError
from core.strings import StringExtractor
from evidence.provenance import Provenance

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


def _read_code(path: Path, info: BinaryInfo, address: int, want_bytes: int) -> bytes | None:
    offset = info.va_to_offset(address)
    section = info.section_for_va(address)
    if offset is None or section is None:
        return None
    remaining = (section.offset + (section.raw_size or section.size)) - offset
    if remaining <= 0:
        return None
    with open(path, "rb") as handle:
        handle.seek(offset)
        return handle.read(min(want_bytes, remaining))


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
        disassembler = Disassembler(loaded.architecture, loaded.bitness, loaded.endianness)
    except DisassemblyError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=3) from exc
    start = address
    if function and start is None:
        match = next((c for c in discover_functions(loaded) if c.name == function), None)
        if match is None:
            console.print(f"[bold red]error:[/] function {function!r} not found")
            raise typer.Exit(code=4)
        start = match.address
    if start is None:
        start = loaded.entry_point
    if start is None:
        console.print("[bold red]error:[/] no address supplied and binary has no entry point")
        raise typer.Exit(code=4)
    section = loaded.section_for_va(start)
    if section is None or not section.is_executable:
        console.print(f"[bold red]error:[/] address 0x{start:x} is not inside an executable section")
        raise typer.Exit(code=5)
    code = _read_code(path, loaded, start, max(count, 1) * 16)
    if not code:
        console.print(f"[bold red]error:[/] cannot map address 0x{start:x} to file bytes")
        raise typer.Exit(code=5)
    result = disassembler.disassemble(code, base_address=start, max_instructions=count)
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
    loaded = _load(path)
    provenance = (
        Provenance()
        .add_step("load_binary")
        .add_step("discover_functions")
        .add_step("extract_strings")
    )
    candidates = discover_functions(loaded)
    all_strings = StringExtractor(min_length=4).extract(path, info=loaded)
    kept = all_strings[:string_limit]

    disassembly = None
    if loaded.entry_point is not None:
        try:
            disassembler = Disassembler(loaded.architecture, loaded.bitness, loaded.endianness)
            code = _read_code(path, loaded, loaded.entry_point, 512)
            if code:
                disassembly = disassembler.disassemble(
                    code, base_address=loaded.entry_point, max_instructions=32
                ).to_dict()
        except DisassemblyError:
            disassembly = None

    report = {
        "provenance": provenance.to_dict(),
        "binary": loaded.to_dict(),
        "functions": [c.to_dict() for c in candidates],
        "strings": {
            "count": len(all_strings),
            "returned": len(kept),
            "truncated": len(kept) < len(all_strings),
            "items": [s.to_dict() for s in kept],
        },
        "disassembly": disassembly,
    }
    payload = json.dumps(report, indent=2)
    if output is not None:
        output.write_text(payload, encoding="utf-8")
        console.print(f"[green]report written:[/] {output}")
        return
    console.print_json(payload)


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    main()



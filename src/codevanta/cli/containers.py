"""CODEVANTA container commands: ``codevanta binmeta``, ``evm`` and ``sqlite``.

Three read-only views over self-describing containers, wired to the same
contract as the rest of the CLI: a rich table of what was decoded, a dim
totals footer, every surprise as a ``warning:`` line, an ``evidence:`` footer
naming source and confidence, and ``--json`` for the unchanged ``to_dict()``
payload.

``binmeta`` auto-detects every container family
(:func:`codevanta.analysis.containers.inspect_container`): WASM, GGUF,
safetensors, pcap/pcapng, EVM bytecode and the firmware magic sweep. ``evm``
disassembles raw EVM bytecode with the strict entry point
(:func:`codevanta.analysis.containers.require_evm`). ``sqlite`` introspects a
database file read-only
(:func:`codevanta.analysis.sqlite_view.inspect_sqlite`, ``mode=ro`` +
``immutable=1``, so nothing is ever written).

None of these commands execute anything: containers are dead data and the
only thing these commands do with them is read them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from codevanta.analysis.containers import (
    BinmetaSummary,
    EvmSummary,
    inspect_container,
    require_evm,
)
from codevanta.analysis.sqlite_view import inspect_sqlite
from codevanta.core.report import AnalysisError

app = typer.Typer(help="Container inspection: WASM, EVM, GGUF, safetensors, pcap, SQLite")
console = Console()


def _fail(message: str, code: int) -> NoReturn:
    """Print an error and exit with ``code`` (mirrors the main CLI helper)."""
    console.print(f"[bold red]error:[/] {escape(message)}")
    raise typer.Exit(code=code) from None


def _run(parse, *args: Any) -> Any:
    """Call one parser, mapping every typed failure to ``exit 2``."""
    try:
        return parse(*args)
    except AnalysisError as exc:
        _fail(str(exc), 2)


def _evidence_footer(evidence: dict[str, Any]) -> None:
    """Print the shared ``evidence:`` footer line."""
    console.print(
        f"[dim]evidence: {escape(str(evidence.get('source')))}"
        f" via {escape(str(evidence.get('method')))}"
        f" · confidence: {escape(str(evidence.get('confidence')))}[/]"
    )


@app.command("binmeta")
def binmeta(
    path: Annotated[Path, typer.Argument(help="Path to the container file")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit BinmetaSummary.to_dict() instead of a table"),
    ] = False,
) -> None:
    """Auto-detect container formats: WASM, GGUF, safetensors, pcap, EVM, magics.

    Every inspector runs in turn (magic-gated formats first, EVM last because
    it has no magic), and each match contributes its own bounded summary and
    evidence. A file matching nothing is reported as such -- detection is
    honest, not force-fitted -- and the firmware magic sweep always runs as
    low/medium-confidence triage. ``--json`` prints the summary unchanged.
    """
    summary: BinmetaSummary = _run(inspect_container, path)
    if json_output:
        console.print_json(json.dumps(summary.to_dict()))
        return
    if not summary.detected:
        console.print("[yellow]no container format matched[/]")
    else:
        console.print(
            f"[bold]Container[/] · {escape(', '.join(summary.detected))}"
            f" · {summary.size_bytes} bytes"
        )
    if summary.wasm is not None:
        table = Table(title=f"WASM v{summary.wasm.version} section table")
        table.add_column("Id", justify="right")
        table.add_column("Name")
        table.add_column("Offset", justify="right")
        table.add_column("Size", justify="right")
        for section in summary.wasm.sections:
            table.add_row(
                str(section.id),
                escape(section.name),
                f"0x{section.offset:x}",
                str(section.size),
            )
        console.print(table)
        console.print(
            f"[dim]imports: {summary.wasm.import_count}"
            f" · exports: {summary.wasm.export_count}"
            f" · truncated: {'yes' if summary.wasm.truncated else 'no'}[/]"
        )
    if summary.gguf is not None:
        offset = "-" if summary.gguf.data_offset is None else f"0x{summary.gguf.data_offset:x}"
        console.print(
            f"[dim]gguf: v{summary.gguf.version} · tensors: {summary.gguf.tensor_count}"
            f" · kv: {summary.gguf.kv_count} · data offset: {offset}[/]"
        )
    if summary.safetensors is not None:
        console.print(
            f"[dim]safetensors: {summary.safetensors.tensor_count} tensors"
            f" · header: {summary.safetensors.header_bytes} B"
            f" · payload: {summary.safetensors.total_tensor_bytes} B in spans[/]"
        )
    if summary.pcap is not None:
        first = (
            "-"
            if summary.pcap.first_timestamp is None
            else f"{summary.pcap.first_timestamp:.6f}"
        )
        console.print(
            f"[dim]pcap: {summary.pcap.format} ({summary.pcap.endian})"
            f" · records: {summary.pcap.record_count}"
            f" · linktype: {summary.pcap.linktype_name} · first ts: {first}[/]"
        )
    if summary.evm is not None:
        console.print(
            f"[dim]evm: {summary.evm.op_count} ops · jumpdests: {summary.evm.jumpdest_count}"
            f" · evm_like: {'yes' if summary.evm.evm_like else 'no'}[/]"
        )
    if summary.magics is not None:
        hits = Table(title=f"Firmware magic scan ({summary.magics.hit_count} hits)")
        hits.add_column("Offset", justify="right")
        hits.add_column("Kind")
        hits.add_column("Aligned")
        hits.add_column("Confidence")
        for hit in summary.magics.hits:
            hits.add_row(
                f"0x{hit.offset:x}",
                escape(hit.kind),
                "yes" if hit.aligned else "no",
                escape(hit.confidence),
            )
        console.print(hits)
    for warning in summary.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")
    for item in summary.evidence:
        _evidence_footer(item.to_dict())


@app.command("evm")
def evm(
    path: Annotated[Path, typer.Argument(help="Path to raw EVM bytecode")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit EvmSummary.to_dict() instead of an op table"),
    ] = False,
) -> None:
    """Disassemble EVM bytecode: bounded op list, JUMPDEST landing pads, targets.

    The sweep is ``PUSH``-aware, so immediate bytes never masquerade as
    instructions and every reported ``JUMPDEST`` is a real instruction start.
    Plain ``JUMP``/``JUMPI`` targets (a preceding ``PUSH`` immediate) are
    checked against the landing-pad set. EVM bytecode has no magic: the
    ``evm_like`` verdict is a labelled heuristic, and a file with no
    decodable opcodes -- or one that decodes but has no terminator or landing
    pad -- exits 2 with a typed message. ``--json`` prints the summary
    unchanged.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        _fail(f"cannot read {str(path)!r}: {exc}", 2)
    summary: EvmSummary = _run(require_evm, data)
    if json_output:
        console.print_json(json.dumps(summary.to_dict()))
        return
    table = Table(title=f"EVM bytecode ({summary.size_bytes} bytes)")
    table.add_column("PC", justify="right")
    table.add_column("Op")
    table.add_column("Operand")
    for op in summary.ops:
        table.add_row(str(op.pc), op.op, op.operand or "-")
    console.print(table)
    console.print(
        f"[dim]ops: {summary.op_count} · jumpdests: {summary.jumpdest_count}"
        f" · jump targets: {summary.jump_targets_valid}/{summary.jump_targets_total} valid"
        f" · truncated: {'yes' if summary.truncated else 'no'}[/]"
    )
    for warning in summary.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")
    if summary.evidence is not None:
        _evidence_footer(summary.evidence.to_dict())


@app.command("sqlite")
def sqlite(
    db: Annotated[Path, typer.Argument(help="Path to the SQLite database file")],
    table: Annotated[
        str | None,
        typer.Option("--table", help="Add schema and sample rows for this table"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit SqliteSummary.to_dict() instead of tables"),
    ] = False,
) -> None:
    """Introspect a SQLite database read-only (immutable; never writes).

    The file is opened through ``file:...?mode=ro&immutable=1``: no write, no
    journal, no WAL replay -- a present ``-wal`` file is reported but
    ignored. The table list carries row counts (bounded at 32 tables);
    ``--table`` adds the column list and up to 10 sample rows for one table.
    Anything that is not a SQLite 3 database exits 2 with a typed message.
    ``--json`` prints the summary unchanged.
    """
    summary = _run(inspect_sqlite, db, table)
    if json_output:
        console.print_json(json.dumps(summary.to_dict()))
        return
    console.print(
        f"[bold]SQLite[/] · {escape(str(summary.path))} · {summary.size_bytes} bytes"
        f" · tables: {summary.table_count}"
        f" · wal: {'present (ignored)' if summary.wal_present else 'none'}"
    )
    listing = Table(title="Tables")
    listing.add_column("Name")
    listing.add_column("Rows", justify="right")
    for entry in summary.tables:
        listing.add_row(escape(entry.name), str(entry.row_count))
    console.print(listing)
    for entry in summary.tables:
        if not entry.columns:
            continue
        schema = Table(title=f"Schema: {entry.name}")
        schema.add_column("Column")
        schema.add_column("Type")
        schema.add_column("Not null", justify="center")
        schema.add_column("PK", justify="center")
        for column in entry.columns:
            schema.add_row(
                escape(column.name),
                escape(column.type or "-"),
                "yes" if column.not_null else "no",
                "yes" if column.primary_key else "no",
            )
        console.print(schema)
        if entry.sample_rows:
            rows = Table(title=f"Sample rows: {entry.name} (max 10)")
            keys = list(entry.sample_rows[0])
            for key in keys:
                rows.add_column(escape(key))
            for record in entry.sample_rows:
                cells = [escape(str(record.get(key, "-"))) for key in keys]
                rows.add_row(*cells)
            console.print(rows)
    for warning in summary.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")
    if summary.evidence is not None:
        _evidence_footer(summary.evidence.to_dict())

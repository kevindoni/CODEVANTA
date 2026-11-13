"""``codevanta metadata`` — format metadata inspector sub-app (lane-meta).

Registered in :mod:`codevanta.cli.main` with exactly one ``add_typer``
line; the sub-app itself is a single-command Typer app, so the command is
``codevanta metadata <path> [--json]``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from codevanta.analysis import binmeta
from codevanta.core.report import AnalysisError

meta_app = typer.Typer(
    invoke_without_command=True,
    # Single-command sub-app: PATH and --json may appear in any order.
    context_settings={"allow_interspersed_args": True},
    help=(
        "Format metadata inspectors: APK signing block, Go build info, "
        "cargo-auditable, .pyc header, Electron fuses, ELF notes, .modinfo, "
        "desktop app layouts."
    ),
)
console = Console()


def _fail(message: str) -> None:
    """Print an error and exit with code 2."""
    console.print(f"[bold red]error:[/] {escape(message)}")
    raise typer.Exit(code=2)


def _fmt(value: Any) -> str:
    """Compact, bounded rendering of one detail value."""
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)[:200]
    if isinstance(value, list):
        if not value:
            return "0 items"
        head = ", ".join(str(item) for item in value[:4])
        return f"{len(value)} items: {head}"[:200]
    return str(value)


def _flatten(details: dict[str, Any]) -> list[tuple[str, str]]:
    """Flatten the per-detector detail dicts into (field, value) rows."""
    rows: list[tuple[str, str]] = []
    for section, payload in details.items():
        if isinstance(payload, dict):
            for key, value in payload.items():
                rows.append((f"{section}.{key}", _fmt(value)))
        else:
            rows.append((section, _fmt(payload)))
    return rows


@meta_app.callback(invoke_without_command=True)
def metadata(
    path: Annotated[Path, typer.Argument(help="File or directory to inspect")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """Auto-detect format metadata for PATH (pure Python, offline)."""
    try:
        report = binmeta.inspect_metadata(path)
    except AnalysisError as exc:
        _fail(str(exc))
    if json_output:
        console.print_json(json.dumps(report.to_dict()))
        return
    table = Table(title=f"Metadata · {escape(str(path))}")
    table.add_column("Kind")
    table.add_column("Field")
    table.add_column("Value")
    rows = _flatten(report.details)
    for index, (field, value) in enumerate(rows):
        table.add_row(
            escape(report.kind) if index == 0 else "",
            escape(field),
            escape(value),
        )
    if not rows:
        table.add_row(escape(report.kind), "-", "-")
    console.print(table)
    evidence_table = Table(title="Evidence")
    evidence_table.add_column("Source")
    evidence_table.add_column("Method")
    evidence_table.add_column("Confidence")
    evidence_table.add_column("Detail")
    for record in report.evidence:
        data = record.to_dict()
        evidence_table.add_row(
            escape(data["source"]),
            escape(data["method"]),
            escape(data["confidence"]),
            escape(data.get("detail", "")),
        )
    console.print(evidence_table)

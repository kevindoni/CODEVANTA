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

from codevanta.analysis import (
    binmeta,
    elf_dynamic,
    macho_dylibs,
    managed_meta,
    pe_loadconfig,
    pe_resources,
    pyc_inspect,
)
from codevanta.analysis.codesign import inspect_codesign
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

# lane-depth2: one sub-app with a command per deep format inspector; the
# registration lives in cli.main.py as a single add_typer line.
deep2_app = typer.Typer(
    help=(
        "Deep format inspectors (lane-depth2): PE resources + version info, "
        "PE load config + TLS callbacks, ELF dynamic section, Mach-O dylibs, "
        ".pyc shallow marshal walk, .NET metadata members."
    ),
)


def _deep_render(title: str, payload: dict[str, Any], evidence: Any) -> None:
    """Render one deep inspector's summary dict + evidence (shared)."""
    table = Table(title=title)
    table.add_column("Field")
    table.add_column("Value")
    for field, value in _flatten({"summary": payload}):
        table.add_row(escape(field), escape(value))
    console.print(table)
    data = evidence.to_dict()
    console.print(
        f"[dim]evidence: {escape(str(data['source']))} via {escape(str(data['method']))}"
        f" · confidence: {escape(str(data['confidence']))}[/]"
    )


def _deep_entry(target: Path, json_output: bool, title: str, summary: Any) -> None:
    """Shared output path for the deep commands (JSON or rendered table)."""
    if json_output:
        console.print_json(json.dumps(summary.to_dict()))
        return
    _deep_render(f"{title} · {escape(str(target))}", summary.to_dict(), summary.evidence)


def _deep_runner(target: Path, json_output: bool, title: str, inspector: Any) -> None:
    try:
        summary = inspector(target)
    except AnalysisError as exc:
        _fail(str(exc))
    _deep_entry(target, json_output, title, summary)


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


def codesign(
    macho: Annotated[Path, typer.Argument(help="Thin Mach-O file to inspect")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the JSON result instead of a summary"),
    ] = False,
) -> None:
    """Summarise a Mach-O's embedded code signature (structure only, offline).

    Prints the LC_CODE_SIGNATURE offset, the SuperBlob slot table, the
    code-directory identifier, the entitlements keys and a certificate count.
    A file without a signature load command exits 2 with a typed message;
    nothing here verifies trust -- parse-only.
    """
    try:
        report = inspect_codesign(macho)
    except AnalysisError as exc:
        _fail(str(exc))
    if report is None:
        _fail(f"no embedded code signature found in {macho}")
    assert report is not None  # narrowed by _fail above
    if json_output:
        console.print_json(json.dumps(report.to_dict()))
        return
    console.print(
        f"[bold]Codesign[/] {escape(str(macho))} · {escape(report.macho_kind)}"
        f" ({escape(report.endian)}-endian)"
    )
    console.print(
        f"[dim]LC_CODE_SIGNATURE:[/] offset {report.signature_offset}"
        f" · size {report.signature_size} bytes · slots {report.slot_count}"
    )
    if report.identifier:
        console.print(f"[dim]identifier:[/] {escape(report.identifier)}")
    console.print(
        f"[dim]team id:[/] {escape(report.team_id if report.team_id else '-')}"
        f" · certificates: {report.certificates_count if report.certificates_count is not None else '-'}"
    )
    table = Table(title="SuperBlob slots")
    table.add_column("Type")
    table.add_column("Name")
    table.add_column("Offset", justify="right")
    table.add_column("Length", justify="right")
    for slot_type, name, offset, length in report.slots:
        table.add_row(
            f"0x{slot_type:x}",
            escape(name),
            str(offset),
            str(length),
        )
    if not report.slots:
        table.add_row("-", "-", "-", "-")
    console.print(table)
    if report.entitlements_keys:
        console.print(f"[dim]entitlements keys:[/] {len(report.entitlements_keys)}")
        for key in report.entitlements_keys[:16]:
            console.print(f"  {escape(key)}")
        if report.entitlements_truncated:
            console.print("[yellow]warning:[/] key list truncated at 32 entries")
    for warning in report.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")
    data = report.evidence.to_dict()
    console.print(
        f"[dim]evidence: {escape(str(data['source']))} via {escape(str(data['method']))}"
        f" · confidence: {escape(str(data['confidence']))}[/]"
    )


# ---- lane-depth2 deep inspector commands --------------------------------------


@deep2_app.command("pe-resources")
def deep_pe_resources(
    path: Annotated[Path, typer.Argument(help="PE file to inspect")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of a table")
    ] = False,
) -> None:
    """Deep-walk a PE's resource directory tree (bounded, offline)."""
    _deep_runner(path, json_output, "PE resources", pe_resources.inspect_pe_resources)


@deep2_app.command("pe-loadconfig")
def deep_pe_loadconfig(
    path: Annotated[Path, typer.Argument(help="PE file to inspect")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of a table")
    ] = False,
) -> None:
    """Deep-read a PE's load config, TLS callbacks and DEP policy (offline)."""
    _deep_runner(path, json_output, "PE load config", pe_loadconfig.inspect_pe_load_config)


@deep2_app.command("elf-dynamic")
def deep_elf_dynamic(
    path: Annotated[Path, typer.Argument(help="ELF file to inspect")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of a table")
    ] = False,
) -> None:
    """Deep-read an ELF's dynamic section (DT_NEEDED, arrays, offline)."""
    _deep_runner(path, json_output, "ELF dynamic", elf_dynamic.inspect_elf_dynamic)


@deep2_app.command("macho-dylibs")
def deep_macho_dylibs(
    path: Annotated[Path, typer.Argument(help="Thin Mach-O file to inspect")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of a table")
    ] = False,
) -> None:
    """Deep-read a Mach-O's dylib load commands (versions, offline)."""
    _deep_runner(path, json_output, "Mach-O dylibs", macho_dylibs.inspect_macho_dylibs)


@deep2_app.command("pyc-inspect")
def deep_pyc_inspect(
    path: Annotated[Path, typer.Argument(help=".pyc file to inspect")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of a table")
    ] = False,
) -> None:
    """Shallow-walk a .pyc's constant/name tables (bytecode never decoded)."""
    _deep_runner(path, json_output, "PYC inspect", pyc_inspect.inspect_pyc_code)


@deep2_app.command("managed-meta")
def deep_managed_meta(
    path: Annotated[Path, typer.Argument(help=".NET PE file to inspect")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of a table")
    ] = False,
) -> None:
    """Shallow-walk a .NET assembly's #~/#Strings metadata (offline)."""
    _deep_runner(path, json_output, "Managed metadata", managed_meta.inspect_managed_metadata)
